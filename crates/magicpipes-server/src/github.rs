//! Signing in with GitHub or GitHub Enterprise Server (`docs/USERS.md`, "Social login"). It's OAuth 2,
//! not OpenID Connect: there's no ID token to check, so who someone is comes from asking its API
//! over TLS with the token the code buys. What a browser carries meanwhile, and who gets in, are the
//! same as for any provider ([`crate::oidc`], `control::oidc`).
//!
//! The identity is GitHub's numeric user id. A username can change hands, and a person's address can
//! change. Only addresses GitHub says are verified count, and only one of them is used.
//!
//! When tag rules ask for them, a sign-in also asks to read organizations (`read:org`), and someone's
//! organizations and teams become the claims [`ORG`] (`acme`) and [`TEAM`] (`acme/platform`),
//! lowercased, as GitHub's names are compared without case. One that can't be read gives nothing,
//! so its rules don't match.

use anyhow::{Context, anyhow, bail};
use http::Method;
use magicpipes_core::url;
use serde::Deserialize;

use crate::oidc::{Claims, MAX_CLAIM_VALUES, Person, allowed_url, get_json, request};

/// Enough to read someone's addresses, which `/user` doesn't always show. Nothing else.
const SCOPE: &str = "user:email";
/// Also their organizations and teams, for rules that need them.
const SCOPE_WITH_ORGS: &str = "user:email read:org";
const GITHUB_COM: &str = "https://github.com";
/// The claims an organization's and a team's name are, for tag rules.
pub const ORG: &str = "github:org";
pub const TEAM: &str = "github:team";
/// Teams are read this many to a page, which keeps a page well under the client's limit, for at
/// most this many pages.
const TEAMS_PER_PAGE: usize = 50;
const TEAM_PAGES: usize = 4;

/// github.com's API has a host of its own; a GitHub Enterprise Server's is a path.
fn api_base(issuer: &str) -> String {
    let base = issuer.trim_end_matches('/');
    if base == GITHUB_COM { "https://api.github.com".to_string() } else { format!("{base}/api/v3") }
}

/// Where to send the browser. `orgs`: also ask to read organizations and teams.
pub(crate) fn authorization_url(issuer: &str, client_id: &str, redirect_uri: &str, state: &str, challenge: &str, orgs: bool) -> String {
    format!(
        "{}/login/oauth/authorize?response_type=code&scope={}&client_id={}&redirect_uri={}&state={state}&code_challenge={challenge}&code_challenge_method=S256",
        issuer.trim_end_matches('/'),
        url::encode(if orgs { SCOPE_WITH_ORGS } else { SCOPE }),
        url::encode(client_id),
        url::encode(redirect_uri),
    )
}

#[derive(Deserialize)]
struct TokenAnswer {
    access_token: Option<String>,
    /// GitHub says a code was refused with a 200 and this.
    error: Option<String>,
}

#[derive(Deserialize)]
struct User {
    id: u64,
    login: String,
    name: Option<String>,
}

#[derive(Deserialize)]
struct Email {
    email: String,
    #[serde(default)]
    primary: bool,
    #[serde(default)]
    verified: bool,
}

#[derive(Deserialize)]
struct Org {
    login: String,
}

#[derive(Deserialize)]
struct Team {
    slug: String,
    organization: Org,
}

/// The claims rules see: organizations and `organization/team` names, lowercased.
fn group_claims(orgs: Option<Vec<Org>>, teams: Option<Vec<Team>>) -> Claims {
    let mut claims = Claims::new();
    if let Some(orgs) = orgs {
        claims.insert(ORG.into(), orgs.into_iter().take(MAX_CLAIM_VALUES).map(|o| o.login.to_lowercase()).collect());
    }
    if let Some(teams) = teams {
        let names = teams.into_iter().take(MAX_CLAIM_VALUES).map(|t| format!("{}/{}", t.organization.login, t.slug).to_lowercase()).collect();
        claims.insert(TEAM.into(), names);
    }
    claims.retain(|_, v| !v.is_empty());
    claims
}

/// Someone's teams, a page at a time.
async fn teams(api: &str, auth: &str) -> anyhow::Result<Vec<Team>> {
    let mut all = Vec::new();
    for page in 1..=TEAM_PAGES {
        let some: Vec<Team> = get_json(&format!("{api}/user/teams?per_page={TEAMS_PER_PAGE}&page={page}"), Some(auth)).await?;
        let last = some.len() < TEAMS_PER_PAGE;
        all.extend(some);
        if last {
            break;
        }
    }
    Ok(all)
}

/// The address to go by: the primary one if GitHub verified it, or else the first it did.
fn verified_address(emails: &[Email]) -> Option<&str> {
    let verified = || emails.iter().filter(|e| e.verified);
    verified().find(|e| e.primary).or_else(|| verified().next()).map(|e| e.email.as_str())
}

/// Trades the code for a token, and asks who that is, and which organizations (`orgs`) and teams
/// (`teams`) they're in, if rules want those. The token isn't kept.
#[allow(clippy::too_many_arguments)] // one exchange's parts
pub(crate) async fn person(issuer: &str, client_id: &str, client_secret: &str, code: &str, redirect_uri: &str, verifier: &str, orgs: bool, with_teams: bool) -> anyhow::Result<Person> {
    let form = format!(
        "client_id={}&client_secret={}&code={}&redirect_uri={}&code_verifier={}",
        url::encode(client_id),
        url::encode(client_secret),
        url::encode(code),
        url::encode(redirect_uri),
        url::encode(verifier),
    );
    let token_url = format!("{}/login/oauth/access_token", issuer.trim_end_matches('/'));
    let bytes = request(Method::POST, &token_url, None, Some(form)).await.context("token request")?;
    let answer: TokenAnswer = serde_json::from_slice(&bytes).context("token response")?;
    let token = answer.access_token.ok_or_else(|| anyhow!("GitHub refused the code: {}", answer.error.as_deref().unwrap_or("no token")))?;

    let auth = format!("Bearer {token}");
    let api = api_base(issuer);
    let user: User = get_json(&format!("{api}/user"), Some(&auth)).await.context("user")?;
    if user.id == 0 {
        bail!("GitHub didn't say who this is");
    }
    let emails: Vec<Email> = get_json(&format!("{api}/user/emails"), Some(&auth)).await.context("email addresses")?;
    let verified_email = verified_address(&emails).map(str::to_string);
    fn unread(what: &'static str) -> impl FnOnce(anyhow::Error) {
        move |e| tracing::info!(error = %format!("{e:#}"), "couldn't read someone's GitHub {what}, so rules about them don't match")
    }
    let orgs = if orgs { get_json::<Vec<Org>>(&format!("{api}/user/orgs?per_page=100"), Some(&auth)).await.map_err(unread("organizations")).ok() } else { None };
    let teams = if with_teams { teams(&api, &auth).await.map_err(unread("teams")).ok() } else { None };
    Ok(Person {
        subject: user.id.to_string(),
        vouched_for: verified_email.is_some(),
        verified_email,
        name: user.name.filter(|n| !n.trim().is_empty()).unwrap_or(user.login),
        claims: group_claims(orgs, teams),
    })
}

/// Asks an address whether it's GitHub, before an administrator adds it. Returns it as identities
/// will name it, without a trailing slash.
pub(crate) async fn check(entered: &str) -> anyhow::Result<String> {
    #[derive(Deserialize)]
    struct Root {
        #[allow(dead_code)] // that it's there is the answer
        current_user_url: String,
    }
    let base = entered.trim().trim_end_matches('/');
    if !allowed_url(base) {
        bail!("the address must be an https:// URL");
    }
    let _: Root = get_json(&format!("{}/", api_base(base)), None).await.context("this doesn't look like GitHub")?;
    Ok(base.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn email(email: &str, primary: bool, verified: bool) -> Email {
        Email { email: email.into(), primary, verified }
    }

    #[test]
    fn only_a_verified_address_counts() {
        assert_eq!(verified_address(&[]), None);
        assert_eq!(verified_address(&[email("a@x.com", true, false)]), None, "primary, but not verified");
        assert_eq!(verified_address(&[email("a@x.com", false, true), email("b@x.com", true, true)]), Some("b@x.com"), "the primary one first");
        assert_eq!(verified_address(&[email("a@x.com", true, false), email("b@x.com", false, true)]), Some("b@x.com"), "or another that's verified");
    }

    #[test]
    fn its_answers_are_read_as_github_sends_them() {
        // From GitHub's documentation for `GET /user/emails`, and a user with no public name.
        let emails: Vec<Email> = serde_json::from_str(r#"[{"email":"a@x.com","verified":true,"primary":true,"visibility":"public"}]"#).unwrap();
        assert_eq!(verified_address(&emails), Some("a@x.com"));
        let user: User = serde_json::from_str(r#"{"login":"octocat","id":583231,"name":null,"email":null}"#).unwrap();
        assert_eq!((user.id, user.login.as_str(), user.name), (583231, "octocat", None));
        let refused: TokenAnswer = serde_json::from_str(r#"{"error":"bad_verification_code","error_description":"The code passed is incorrect or expired."}"#).unwrap();
        assert_eq!((refused.access_token, refused.error.as_deref()), (None, Some("bad_verification_code")));
    }

    #[test]
    fn organizations_and_teams_are_claims_in_lowercase() {
        // From GitHub's documentation for `GET /user/orgs` and `GET /user/teams`, cut short.
        let orgs: Vec<Org> = serde_json::from_str(r#"[{"login":"GitHub","id":1,"url":"https://api.github.com/orgs/github"}]"#).unwrap();
        let teams: Vec<Team> = serde_json::from_str(r#"[{"id":1,"name":"Justice League","slug":"justice-league","organization":{"login":"GitHub","id":1}}]"#).unwrap();
        let claims = group_claims(Some(orgs), Some(teams));
        assert_eq!(claims.get(ORG), Some(&vec!["github".to_string()]));
        assert_eq!(claims.get(TEAM), Some(&vec!["github/justice-league".to_string()]));
        assert!(group_claims(None, Some(vec![])).is_empty(), "not asked, or in none");
    }

    #[test]
    fn github_com_and_enterprise_servers_have_their_own_addresses() {
        assert_eq!(api_base("https://github.com"), "https://api.github.com");
        assert_eq!(api_base("https://github.com/"), "https://api.github.com");
        assert_eq!(api_base("https://git.example.com"), "https://git.example.com/api/v3");
        let with_orgs = authorization_url("https://github.com/", "c", "https://mp.example.com/cb", "st", "ch", true);
        assert!(with_orgs.contains("scope=user%3Aemail%20read%3Aorg"), "{with_orgs}");
        let to = authorization_url("https://github.com/", "client 1", "https://mp.example.com/auth/oidc/github/callback", "st", "ch", false);
        assert!(to.starts_with("https://github.com/login/oauth/authorize?"), "{to}");
        for part in ["scope=user%3Aemail", "client_id=client%201", "redirect_uri=https%3A%2F%2Fmp.example.com%2Fauth%2Foidc%2Fgithub%2Fcallback", "state=st", "code_challenge=ch", "code_challenge_method=S256"] {
            assert!(to.contains(part), "{part} in {to}");
        }
    }
}
