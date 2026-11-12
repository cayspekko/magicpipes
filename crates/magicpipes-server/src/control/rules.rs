//! Tag rules (`docs/USERS.md`, "Where tags come from"): tags people get from what a sign-in says
//! about them, besides those an administrator assigns. Only administrators write rules, and a rule
//! gives only an ordinary tag an administrator made, so nobody gives themselves anything.
//!
//! A rule names a sign-in source (a provider's or the proxy's issuer), a claim and a value: whoever
//! that source says has the value in that claim (equal to it, or in it if it's a list) gets the
//! tag. Matching is exact, except GitHub's organization and team names, which GitHub compares
//! without case and which are lowercased on both sides. At each single sign-on through a source,
//! what the person matched among its rules replaces what they matched before (`store::rules`); a
//! match counts for `session_max_age_secs`, so someone who stops signing in through that source,
//! or is taken out of the group, loses the tag by then at the latest. An email-domain rule, from
//! any source, gives its tag to every account whose confirmed address is at that domain, at once.

use magicpipes_core::error::ErrorCode;
use magicpipes_core::proto::ErrorBody;
use magicpipes_core::{rfc3339, secret, unix_now};
use serde::Serialize;

use super::users::denied;
use super::{ControlPlane, OrLog, err, internal};
use crate::authz::{self, Action, Principal, Resource};
use crate::config::{ProviderKind, clean_email_domain};
use crate::oidc::{Claims, MAX_CLAIM_LEN};
use crate::store::{ANY_SOURCE, EMAIL_DOMAIN, MAX_TAG_RULES, NewRule, NotAdded, TagRuleRow};

/// A claim name's longest.
const MAX_CLAIM_NAME: usize = 200;
/// Claims that rules don't look at: they say who someone is, or are about the token. An address
/// has rules of its own, which only take a confirmed one.
const NOT_FOR_RULES: &[&str] = &["sub", "iss", "aud", "exp", "iat", "nbf", "nonce", "azp", "email", "email_verified"];

/// Where a rule's claims come from.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SourceKind {
    /// Any sign-in: the account's confirmed address.
    Any,
    Oidc,
    Github,
    Proxy,
}

/// A source a rule can name.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct RuleSource {
    /// What the rule stores: the issuer, or `*`.
    pub issuer: String,
    /// What people call it: the provider's label.
    pub name: String,
    pub kind: SourceKind,
}

/// A rule, for the Tags page and the API.
#[derive(Debug, Clone, Serialize)]
pub struct TagRuleView {
    pub id: String,
    /// The source's issuer, or `*`.
    pub source: String,
    /// Its name, or a note that it's gone.
    pub source_name: String,
    pub claim: String,
    pub value: String,
    pub tag: String,
    /// People it gives the tag to now.
    pub holders: usize,
    /// Of those, people who hold the tag only through it.
    pub only_through: usize,
    pub created_at: String,
}

/// Does a sign-in's claims meet the rule?
fn meets(rule: &TagRuleRow, claims: &Claims) -> bool {
    claims.get(&rule.claim).is_some_and(|values| values.contains(&rule.value))
}

fn bad(why: &str) -> ErrorBody {
    err(ErrorCode::InvalidRequest, why)
}

/// What a rule from `source` may say, cleaned: `(claim, value)`.
fn clean_rule(source: &RuleSource, claim: &str, value: &str) -> Result<(String, String), ErrorBody> {
    let (claim, value) = (claim.trim(), value.trim());
    if value.is_empty() || value.len() > MAX_CLAIM_LEN || value.chars().any(char::is_control) {
        return Err(bad("Enter the value the claim has to have, at most 256 characters."));
    }
    match source.kind {
        SourceKind::Any => {
            if !claim.is_empty() && claim != EMAIL_DOMAIN {
                return Err(bad("A rule for any sign-in can only be about an address's domain."));
            }
            let domain = clean_email_domain(value).map_err(|_| bad("Enter a domain, like example.com."))?;
            Ok((EMAIL_DOMAIN.into(), domain))
        }
        SourceKind::Github => {
            let value = value.to_lowercase();
            match claim {
                crate::github::ORG if !value.contains('/') => Ok((claim.into(), value)),
                crate::github::TEAM if value.split_once('/').is_some_and(|(o, t)| !o.is_empty() && !t.is_empty() && !t.contains('/')) => Ok((claim.into(), value)),
                crate::github::ORG => Err(bad("An organization's name has no slash, like acme.")),
                crate::github::TEAM => Err(bad("Name a team with its organization, like acme/platform.")),
                _ => Err(bad("From GitHub, a rule is about github:org (an organization) or github:team (organization/team).")),
            }
        }
        SourceKind::Oidc | SourceKind::Proxy => {
            if claim.is_empty() || claim.len() > MAX_CLAIM_NAME || !claim.chars().all(|c| c.is_ascii_graphic()) {
                return Err(bad("Enter the claim's name, such as groups."));
            }
            if NOT_FOR_RULES.contains(&claim) || claim == EMAIL_DOMAIN || claim.starts_with("github:") {
                return Err(bad("Rules can't use that claim. For an address's domain, choose any sign-in."));
            }
            Ok((claim.into(), value.into()))
        }
    }
}

impl ControlPlane {
    /// The sources a rule can name: any sign-in, then the providers people can choose, or the
    /// authenticating proxy.
    pub fn rule_sources(&self) -> Vec<RuleSource> {
        let mut out = vec![RuleSource { issuer: ANY_SOURCE.into(), name: "Any sign-in".into(), kind: SourceKind::Any }];
        if let Some(proxy) = &self.proxy_auth {
            out.push(RuleSource { issuer: proxy.issuer.clone(), name: "The authenticating proxy".into(), kind: SourceKind::Proxy });
        }
        for p in self.oidc_providers() {
            let kind = if p.kind == ProviderKind::Github { SourceKind::Github } else { SourceKind::Oidc };
            out.push(RuleSource { issuer: p.issuer.clone(), name: p.label.clone(), kind });
        }
        out
    }

    fn rule_view(&self, st: &super::State, sources: &[RuleSource], r: &TagRuleRow) -> TagRuleView {
        let (holders, only_through) = st.dir.rule_reach(r);
        let source_name = sources.iter().find(|s| s.issuer == r.issuer).map_or_else(|| format!("{} (not a sign-in here now)", r.issuer), |s| s.name.clone());
        TagRuleView {
            id: r.id.clone(),
            source: r.issuer.clone(),
            source_name,
            claim: r.claim.clone(),
            value: r.value.clone(),
            tag: r.tag.clone(),
            holders,
            only_through,
            created_at: rfc3339(r.created_at),
        }
    }

    /// Every rule (administrators only).
    pub fn tag_rules(&self, who: &Principal) -> Result<Vec<TagRuleView>, ErrorBody> {
        if !authz::authorize(who, Action::Manage, Resource::Org) {
            return Err(denied(who));
        }
        let sources = self.rule_sources();
        let st = self.state.lock().unwrap();
        Ok(st.dir.rules().iter().map(|r| self.rule_view(&st, &sources, r)).collect())
    }

    /// Adds a rule (administrators only). One about an address's domain applies at once; one about
    /// a claim, at each person's next sign-in through its source.
    pub fn create_tag_rule(&self, who: &Principal, source: &str, claim: &str, value: &str, tag: &str) -> Result<TagRuleView, ErrorBody> {
        if !authz::authorize(who, Action::Manage, Resource::Org) {
            return Err(denied(who));
        }
        let sources = self.rule_sources();
        let from = sources.iter().find(|s| s.issuer == source.trim()).ok_or_else(|| bad("Choose where people sign in with."))?;
        let (claim, value) = clean_rule(from, claim, value)?;
        let tag = tag.trim().to_ascii_lowercase();
        let id = secret::new_token("tr");
        let created_by = matches!(who, Principal::User { .. }).then(|| who.actor());
        let rule = NewRule { id: &id, issuer: &from.issuer, claim: &claim, value: &value, tag: &tag, created_by };
        match self.store.create_tag_rule(&rule).map_err(internal)? {
            Ok(()) => {}
            Err(NotAdded::Exists) => return Err(bad("That rule exists already.")),
            Err(NotAdded::Full) => return Err(err(ErrorCode::LimitReached, format!("There are {MAX_TAG_RULES} rules already; remove some first."))),
            Err(NotAdded::NoSuchTag) => return Err(err(ErrorCode::TagUnknown, format!("'{tag}' isn't a tag a rule can give. Create it first."))),
        }
        self.audit(who, "tag_rule.create", &id, &format!("{} {claim}={value} {tag}", from.issuer));
        self.refresh();
        let st = self.state.lock().unwrap();
        let row = st.dir.rules().iter().find(|r| r.id == id).cloned().ok_or_else(|| err(ErrorCode::Internal, "the rule went missing"))?;
        Ok(self.rule_view(&st, &sources, &row))
    }

    /// `false` if it was already gone. Whoever held its tag only through it loses it at once.
    pub fn delete_tag_rule(&self, who: &Principal, id: &str) -> Result<bool, ErrorBody> {
        if !authz::authorize(who, Action::Manage, Resource::Org) {
            return Err(denied(who));
        }
        if !self.store.delete_tag_rule(id).map_err(internal)? {
            return Ok(false);
        }
        self.audit(who, "tag_rule.delete", id, "");
        self.refresh();
        Ok(true)
    }

    /// The claims the rules for a source look at, so a sign-in asks for them.
    pub(super) fn wanted_claims(&self, issuer: &str) -> Vec<String> {
        let st = self.state.lock().unwrap();
        let mut claims: Vec<String> = st.dir.rules().iter().filter(|r| r.issuer == issuer).map(|r| r.claim.clone()).collect();
        claims.sort();
        claims.dedup();
        claims
    }

    /// At a single sign-on through `issuer`: what the person matched among its rules replaces what
    /// they matched before.
    pub(super) fn match_tag_rules(&self, issuer: &str, user_id: &str, claims: &Claims) {
        let matched: Vec<String> = {
            let st = self.state.lock().unwrap();
            let rules: Vec<&TagRuleRow> = st.dir.rules().iter().filter(|r| r.issuer == issuer).collect();
            if rules.is_empty() {
                return;
            }
            rules.into_iter().filter(|r| meets(r, claims)).map(|r| r.id.clone()).collect()
        };
        if self.store.set_rule_matches(user_id, issuer, &matched).or_log() == Some(true) {
            self.refresh();
        }
    }

    /// Forgets matches older than a session lasts, and takes their tags away.
    pub(super) fn prune_rule_matches(&self) {
        let before = unix_now().saturating_sub(i64::try_from(self.cfg.users.session_max_age_secs).unwrap_or(i64::MAX));
        if self.store.prune_rule_matches(before).or_log().is_some_and(|n| n > 0) {
            self.refresh();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn source(kind: SourceKind) -> RuleSource {
        RuleSource { issuer: "https://login.example.com".into(), name: "Example".into(), kind }
    }

    fn rule(claim: &str, value: &str) -> TagRuleRow {
        TagRuleRow { id: "tr_1".into(), issuer: "i".into(), claim: claim.into(), value: value.into(), tag: "team:eng".into(), created_by: None, created_at: 0 }
    }

    #[test]
    fn a_rule_matches_a_value_or_one_in_a_list_exactly() {
        let claims: Claims = [("groups".to_string(), vec!["eng".to_string(), "ops".to_string()]), ("hd".to_string(), vec!["example.com".to_string()])].into_iter().collect();
        assert!(meets(&rule("groups", "eng"), &claims));
        assert!(meets(&rule("hd", "example.com"), &claims));
        for (claim, value) in [("groups", "Eng"), ("groups", "en"), ("groups", "eng "), ("roles", "eng"), ("hd", "Example.com")] {
            assert!(!meets(&rule(claim, value), &claims), "{claim}={value}");
        }
    }

    #[test]
    fn what_a_rule_can_say_depends_on_its_source() {
        let any = source(SourceKind::Any);
        assert_eq!(clean_rule(&any, "", " Example.COM ").unwrap(), (EMAIL_DOMAIN.into(), "example.com".into()));
        assert_eq!(clean_rule(&any, EMAIL_DOMAIN, "example.com").unwrap().0, EMAIL_DOMAIN);
        assert!(clean_rule(&any, "groups", "eng").is_err(), "any source has no claims of its own");
        assert!(clean_rule(&any, "", "ann@example.com").is_err());

        let gh = source(SourceKind::Github);
        assert_eq!(clean_rule(&gh, "github:org", "Acme").unwrap(), ("github:org".into(), "acme".into()));
        assert_eq!(clean_rule(&gh, "github:team", "Acme/Platform").unwrap(), ("github:team".into(), "acme/platform".into()));
        for (claim, value) in [("github:team", "platform"), ("github:team", "acme/"), ("github:team", "a/b/c"), ("github:org", "acme/x"), ("groups", "eng")] {
            assert!(clean_rule(&gh, claim, value).is_err(), "{claim}={value}");
        }

        let oidc = source(SourceKind::Oidc);
        assert_eq!(clean_rule(&oidc, " groups ", " eng ").unwrap(), ("groups".into(), "eng".into()));
        assert_eq!(clean_rule(&oidc, "https://example.com/roles", "admin").unwrap().0, "https://example.com/roles", "namespaced claims");
        for (claim, value) in [("", "eng"), ("groups", ""), ("my groups", "eng"), ("email", "a@example.com"), ("sub", "x"), (EMAIL_DOMAIN, "example.com"), ("github:org", "acme"), ("groups", "a\u{7}b")] {
            assert!(clean_rule(&oidc, claim, value).is_err(), "{claim}={value}");
        }
        assert!(clean_rule(&oidc, "groups", &"x".repeat(MAX_CLAIM_LEN + 1)).is_err());
    }
}
