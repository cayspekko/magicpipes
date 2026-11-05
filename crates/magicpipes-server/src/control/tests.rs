//! Registry unit tests: ownership between agents, quotas and what each principal can see.

use std::sync::Arc;
use std::time::Duration;

use magicpipes_core::error::ErrorCode;
use magicpipes_core::proto::{EnrollRequest, RegisterTunnel};
use magicpipes_core::secret;
use tokio_util::sync::CancellationToken;

use super::ControlPlane;
use crate::authz::Principal;
use crate::certs::CertManager;
use crate::config::Config;
use crate::data::{DataPlane, ProxySettings};
use crate::store::Store;

pub(crate) struct Fixture {
    pub(crate) cp: Arc<ControlPlane>,
    data: Arc<DataPlane>,
    dir: std::path::PathBuf,
}

impl Drop for Fixture {
    fn drop(&mut self) {
        if !self.dir.as_os_str().is_empty() {
            std::fs::remove_dir_all(&self.dir).ok();
        }
    }
}

impl Fixture {
    /// Stops this control plane, as a restart would, and keeps its data directory.
    fn stop(mut self) -> std::path::PathBuf {
        std::mem::take(&mut self.dir)
    }
}

pub(crate) fn fixture() -> Fixture {
    let dir = std::env::temp_dir().join(format!("mp-control-{}", secret::random_string(8)));
    std::fs::create_dir_all(&dir).unwrap();
    fixture_in(dir, "")
}

/// A control plane over the database in `dir`, with extra configuration appended.
fn fixture_in(dir: std::path::PathBuf, extra: &str) -> Fixture {
    let cfg: Config = toml::from_str(&format!(
        r#"
base_domain = "t.example.test"
data_dir = "{}"
[management]
hostname = "mgmt.example.test"
[tls]
mode = "dev-ca"
[agents]
max_tunnels_per_agent = 2
{extra}
"#,
        dir.display()
    ))
    .unwrap();
    let cfg = Arc::new(cfg);
    let store = Store::open(&dir.join("db.sqlite")).unwrap();
    let certs = CertManager::new(&cfg.tls, &cfg.data_dir, &[&cfg.base_domain, &cfg.management.hostname]).unwrap();
    let data = DataPlane::new(ProxySettings::from_config(&cfg, crate::tunnel_auth::Signer::for_tests()), CancellationToken::new());
    let cp = ControlPlane::new(cfg, store, certs, data.clone()).unwrap();
    Fixture { cp, data, dir }
}

impl Fixture {
    pub(crate) fn agent(&self, name: &str) -> String {
        let token = self.cp.create_enrollment(&Principal::AdminToken, Default::default()).unwrap();
        let req = EnrollRequest { enrollment_token: token, agent_name: name.into() };
        self.cp.enroll(&req).unwrap().agent_id
    }
}

fn http(name: &str) -> RegisterTunnel {
    RegisterTunnel {
        id: None,
        name: Some(name.into()),
        target: "http://127.0.0.1:3000".into(),
        kind: Default::default(),
        remote_port: None,
        allow: vec![],
        visibility: None,
        tags: vec![],
        hostname: None,
    }
}

#[tokio::test]
async fn agents_cannot_touch_each_others_tunnels() {
    let f = fixture();
    let (a, b) = (f.agent("a"), f.agent("b"));
    let t = f.cp.register(&a, &http("app")).unwrap();
    assert!(t.created);

    // Re-registering is idempotent for the owner and refused for anyone else.
    assert!(!f.cp.register(&a, &http("app")).unwrap().created);
    assert!(f.cp.register(&b, &http("app")).unwrap_err().is(ErrorCode::NameTaken));
    let by_id = RegisterTunnel { id: Some(t.id.clone()), ..http("app") };
    assert!(f.cp.register(&b, &by_id).unwrap_err().is(ErrorCode::NotFound));
    assert!(f.cp.check(&b, &t.id).await.unwrap_err().is(ErrorCode::NotFound));
    let cert = f.cp.cert_status(&b, &t.hostname, Duration::ZERO).await;
    assert!(cert.unwrap_err().is(ErrorCode::NotFound));

    // Another agent's unregister is a silent no-op; the owner's removes the route.
    f.cp.unregister(&b, &t.id).unwrap();
    assert!(f.data.lookup(&t.hostname).is_some());
    f.cp.unregister(&a, &t.id).unwrap();
    assert!(f.data.lookup(&t.hostname).is_none());
}

#[tokio::test]
async fn management_follows_authorize() {
    let f = fixture();
    let (a, b) = (f.agent("a"), f.agent("b"));
    let ta = f.cp.register(&a, &http("one")).unwrap();
    f.cp.register(&b, &http("two")).unwrap();
    let (pa, pb) = (Principal::Agent(a.clone()), Principal::Agent(b.clone()));

    // Each agent sees only its own tunnels and itself; an administrator sees everything.
    let names = |who: &Principal| f.cp.tunnels(who).into_iter().map(|t| t.name).collect::<Vec<_>>();
    assert_eq!(names(&pa), ["one"]);
    assert_eq!(names(&pb), ["two"]);
    assert_eq!(names(&Principal::AdminToken).len(), 2);
    assert!(names(&Principal::Anonymous).is_empty());
    assert_eq!(f.cp.agents(&pa).len(), 1);
    assert_eq!(f.cp.agents(&Principal::AdminToken).len(), 2);
    assert!(f.cp.tunnel(&pb, "one").is_none());
    assert!(f.cp.status(&Principal::Anonymous).is_none());
    assert!(f.cp.status(&Principal::AdminToken).is_some());
    assert!(f.cp.create_enrollment(&pa, Default::default()).unwrap_err().is(ErrorCode::Forbidden));

    // Deleting and revoking need Manage; refusals look like "not found".
    assert!(!f.cp.delete_tunnel(&pb, &ta.id).unwrap());
    assert!(!f.cp.revoke_agent(&pb, &a).unwrap());
    assert!(f.cp.delete_tunnel(&Principal::AdminToken, &ta.id).unwrap());
    assert!(f.data.lookup(&ta.hostname).is_none());
    assert!(f.cp.revoke_agent(&Principal::AdminToken, &b).unwrap());
    assert!(names(&Principal::AdminToken).is_empty());
}

#[tokio::test]
async fn routes_carry_their_access_policy() {
    let f = fixture();
    let a = f.agent("a");
    let t = f.cp.register(&a, &http("pub")).unwrap();
    let route = f.data.lookup(&t.hostname).unwrap();
    assert_eq!(route.access.authz.agent_id, a);
    assert!(route.access.authz.public);
    assert!(route.access.admits(&Principal::Anonymous, "203.0.113.9".parse().unwrap()));
}

#[tokio::test]
async fn per_agent_tunnel_quota() {
    let f = fixture();
    let (a, b) = (f.agent("a"), f.agent("b"));
    f.cp.register(&a, &http("q1")).unwrap();
    f.cp.register(&a, &http("q2")).unwrap();
    assert!(f.cp.register(&a, &http("q3")).unwrap_err().is(ErrorCode::LimitReached));
    // One agent's quota doesn't affect another.
    f.cp.register(&b, &http("q4")).unwrap();
}

#[tokio::test]
async fn personal_tags_and_access() {
    use magicpipes_core::proto::Visibility;

    use crate::authz::{self, Action, Resource, Role};
    use crate::control::EnrollmentOptions;
    let f = fixture();
    let admin = Principal::AdminToken;
    let s = |l: &[&str]| l.iter().map(|t| t.to_string()).collect::<Vec<_>>();
    f.cp.create_tag(&admin, "dev", "", true).unwrap();
    f.cp.create_tag(&admin, "prod", "", false).unwrap();
    assert!(f.cp.create_tag(&admin, "Not Valid!", "", true).unwrap_err().is(ErrorCode::InvalidRequest));
    assert!(f.cp.create_tag(&admin, "user:mallory", "", true).unwrap_err().is(ErrorCode::InvalidRequest), "user: is for personal tags");

    // Every account gets a personal tag that nobody else can hold, and that can't be turned off
    // or deleted. Its name says nothing about the person; the UI shows them instead.
    let (ann, _) = f.cp.create_user(&admin, "ann@example.com", "", Role::Member, Some("correct horse battery")).await.unwrap();
    let (bob, _) = f.cp.create_user(&admin, "bob@example.com", "", Role::Member, Some("correct horse battery")).await.unwrap();
    let (pa, pb) = (ann.personal_tag.clone().unwrap(), bob.personal_tag.clone().unwrap());
    assert!(pa.starts_with("user:") && !pa.contains("ann") && ann.tags.is_empty(), "{pa}");
    assert!(f.cp.tags(&admin).iter().all(|t| !t.name.starts_with("user:")), "the registry lists only ordinary tags");
    assert!(f.cp.set_user_tags(&admin, &ann.id, &s(&["team:qa"])).unwrap_err().is(ErrorCode::TagUnknown));
    assert!(f.cp.set_user_tags(&admin, &ann.id, std::slice::from_ref(&pb)).unwrap_err().is(ErrorCode::Forbidden));
    assert!(!f.cp.delete_tag(&admin, &pa).unwrap() && !f.cp.set_tag_access(&admin, &pa, false).unwrap());
    f.cp.set_user_tags(&admin, &ann.id, &s(&["dev", "prod"])).unwrap();
    let ann_now = f.cp.user(&admin, &ann.id).unwrap();
    assert_eq!((ann_now.tags, ann_now.personal_tag), (s(&["dev", "prod"]), Some(pa.clone())));
    assert_eq!(f.cp.people(&admin)[&pa], "ann@example.com");
    let ann_sees = f.cp.people(&Principal::User { id: ann.id.clone(), role: Role::Member, tags: vec![] });
    assert_eq!((ann_sees.get(&pa).map(String::as_str), ann_sees.get(&pb)), (Some("you"), None), "members don't learn others' emails");
    let who = |id: &str| Principal::User { id: id.into(), role: Role::Member, tags: f.cp.users(&admin).into_iter().find(|u| u.id == id).map(|u| {
        let mut t = u.tags;
        t.extend(u.personal_tag);
        t.sort();
        t
    }).unwrap() };
    assert!(f.cp.set_user_tags(&who(&ann.id), &ann.id, &s(&["dev"])).unwrap_err().is(ErrorCode::Forbidden), "no self-assignment");

    // Members enroll only their own machines, which publish with their tags.
    let tagged = EnrollmentOptions { tags: s(&["dev"]), ..Default::default() };
    assert!(f.cp.create_enrollment(&who(&ann.id), tagged.clone()).unwrap_err().is(ErrorCode::InvalidRequest));
    let other = EnrollmentOptions { owner_user_id: Some(bob.id.clone()), ..Default::default() };
    assert!(f.cp.create_enrollment(&who(&ann.id), other).unwrap_err().is(ErrorCode::Forbidden));
    let for_ann = EnrollmentOptions { owner_user_id: Some(ann.id.clone()), tags: s(&["dev"]), ..Default::default() };
    assert!(f.cp.create_enrollment(&admin, for_ann).unwrap_err().is(ErrorCode::InvalidRequest), "personal machines have no tags of their own");
    let token = f.cp.create_enrollment(&who(&ann.id), Default::default()).unwrap();
    let laptop = f.cp.enroll(&EnrollRequest { enrollment_token: token, agent_name: "laptop".into() }).unwrap().agent_id;
    let view = |id: &str| f.cp.agents(&admin).into_iter().find(|a| a.id == id).unwrap();
    let v = view(&laptop);
    assert_eq!((v.owner_user_id.as_deref(), v.tags.clone(), v.default_private), (Some(ann.id.as_str()), s(&["dev", "prod", &pa]), true));
    assert!(f.cp.set_agent_tags(&admin, &laptop, &s(&["dev"])).unwrap_err().is(ErrorCode::InvalidRequest));

    // A tunnel carries its owner's personal tag plus the tags asked for, from the owner's own.
    let private = |name: &str, tags: &[&str]| RegisterTunnel { visibility: Some(Visibility::Private), tags: s(tags), ..http(name) };
    let app = f.cp.register(&laptop, &private("app", &["dev"])).unwrap();
    assert_eq!((app.tags.clone(), app.owner_tag.clone()), (s(&["dev", &pa]), Some(pa.clone())));
    assert!(f.cp.register(&laptop, &private("x", &["ops"])).unwrap_err().is(ErrorCode::TagUnknown));
    f.cp.create_tag(&admin, "ops", "", true).unwrap();
    assert!(f.cp.register(&laptop, &private("x", &["ops"])).unwrap_err().is(ErrorCode::Forbidden), "ann doesn't hold ops");
    let lbl = f.cp.register(&laptop, &private("lbl", &["prod"])).unwrap();
    let access = |host: &str| f.data.lookup(host).unwrap().access.authz.access.clone();
    assert_eq!(access(&lbl.hostname), std::slice::from_ref(&pa), "a tag that doesn't grant access is only a label");
    assert_eq!(lbl.access, std::slice::from_ref(&pa));
    let may = |id: &str, host: &str| authz::authorize(&who(id), Action::Connect, Resource::Tunnel(&f.data.lookup(host).unwrap().access.authz));
    assert!(may(&ann.id, &app.hostname) && may(&ann.id, &lbl.hostname), "the owner gets in through the personal tag");
    assert!(!may(&bob.id, &app.hostname));
    f.cp.set_user_tags(&admin, &bob.id, &s(&["dev"])).unwrap();
    assert!(may(&bob.id, &app.hostname) && !may(&bob.id, &lbl.hostname));
    // Someone's personal tag on a tunnel shares it with that one person.
    let mut shared = s(&["prod", &pa, &pb]);
    shared.sort();
    assert_eq!(f.cp.register(&laptop, &private("lbl", &["prod", &pb])).unwrap().tags, shared);
    assert!(may(&bob.id, &lbl.hostname));
    // Access is the tag's setting, applied at once.
    f.cp.set_tag_access(&admin, "prod", true).unwrap();
    assert_eq!(access(&lbl.hostname), shared);
    f.cp.set_tag_access(&admin, "dev", false).unwrap();
    assert_eq!(access(&app.hostname), std::slice::from_ref(&pa));
    assert!(!may(&bob.id, &app.hostname));
    // Re-registering without a visibility keeps the tags.
    assert_eq!(f.cp.register(&laptop, &http("app")).unwrap().tags, s(&["dev", &pa]));
    // Removing a tag from the owner doesn't unshare what she published (the tunnel keeps it),
    // but every registration that names tags is checked against what she holds now.
    f.cp.set_tag_access(&admin, "dev", true).unwrap();
    f.cp.set_user_tags(&admin, &ann.id, &s(&["prod"])).unwrap();
    assert_eq!(access(&app.hostname), s(&["dev", &pa]));
    assert!(may(&bob.id, &app.hostname));
    assert!(f.cp.register(&laptop, &private("app", &["dev"])).unwrap_err().is(ErrorCode::Forbidden), "no longer hers to give");
    assert_eq!(f.cp.register(&laptop, &private("app", &[])).unwrap().tags, std::slice::from_ref(&pa), "naming tags replaces them");
    f.cp.set_user_tags(&admin, &ann.id, &s(&["dev", "prod"])).unwrap();

    // A service agent has tags of its own, set by administrators; untagged, nobody gets in.
    let service = f.agent("ci");
    assert!(f.cp.set_agent_tags(&who(&ann.id), &service, &s(&["dev"])).unwrap_err().is(ErrorCode::NotFound), "not ann's agent");
    assert!(f.cp.register(&service, &private("svc", &["dev"])).unwrap_err().is(ErrorCode::Forbidden));
    f.cp.set_agent_tags(&admin, &service, &s(&["dev"])).unwrap();
    let svc = f.cp.register(&service, &private("svc", &["dev"])).unwrap();
    assert_eq!(svc.tags, s(&["dev"]));
    let bare = f.cp.register(&service, &private("bare", &[])).unwrap();
    assert!(access(&bare.hostname).is_empty(), "no tag, no access: not even for an administrator");

    // Deleting a tag removes it everywhere.
    f.cp.delete_tag(&admin, "dev").unwrap();
    assert!(view(&service).tags.is_empty());
    assert_eq!(f.cp.tunnel(&admin, "svc").unwrap().tags, Vec::<String>::new());

    // A disabled owner's agents can't connect and serve nothing.
    assert!(f.data.lookup(&app.hostname).is_some());
    f.cp.update_user(&admin, &ann.id, None, Some(true)).unwrap();
    assert!(f.data.lookup(&app.hostname).is_none());
    let (handle, _) = magicpipes_core::mux::spawn(tokio::io::duplex(1024).0, magicpipes_core::mux::Mode::Server);
    assert!(f.cp.attach_session(&laptop, handle, "127.0.0.1:1".parse().unwrap(), 2).is_none());
}

#[tokio::test]
async fn tag_changes_keep_other_edits() {
    use magicpipes_core::proto::Visibility;

    use crate::authz::Role;
    let f = fixture();
    let admin = Principal::AdminToken;
    for t in ["team:dev", "team:ops", "env:prod"] {
        f.cp.create_tag(&admin, t, "", true).unwrap();
    }
    let (ann, _) = f.cp.create_user(&admin, "ann@example.com", "", Role::Member, Some("correct horse battery")).await.unwrap();
    let s = |l: &[&str]| l.iter().map(|t| t.to_string()).collect::<Vec<_>>();

    // Two administrators editing from the same page: each change keeps the other's.
    f.cp.set_user_tags(&admin, &ann.id, &s(&["team:dev"])).unwrap();
    f.cp.change_user_tags(&admin, &ann.id, &s(&["team:ops"]), &[]).unwrap();
    assert_eq!(f.cp.change_user_tags(&admin, &ann.id, &s(&["env:prod"]), &s(&["team:dev"])).unwrap(), s(&["env:prod", "team:ops"]));
    assert!(f.cp.change_user_tags(&admin, &ann.id, &s(&["team:qa"]), &[]).unwrap_err().is(ErrorCode::TagUnknown));
    let pa = ann.personal_tag.clone().unwrap();
    assert_eq!(f.cp.change_user_tags(&admin, &ann.id, &[], std::slice::from_ref(&pa)).unwrap(), s(&["env:prod", "team:ops"]));
    assert_eq!(f.cp.user(&admin, &ann.id).unwrap().personal_tag, Some(pa.clone()), "removing the personal tag does nothing");
    let who = Principal::User { id: ann.id.clone(), role: Role::Member, tags: s(&["team:ops", &pa]) };
    assert!(f.cp.change_user_tags(&who, &ann.id, &s(&["team:dev"]), &[]).unwrap_err().is(ErrorCode::Forbidden));

    // Service agents: administrators add and remove.
    let ci = f.agent("ci");
    f.cp.change_agent_tags(&admin, &ci, &s(&["team:dev", "team:ops"]), &[]).unwrap();
    let private = |name: &str, tags: &[&str]| RegisterTunnel { visibility: Some(Visibility::Private), tags: s(tags), ..http(name) };
    let t = f.cp.register(&ci, &private("dev", &["team:dev"])).unwrap();
    f.cp.register(&ci, &private("both", &["team:dev", "team:ops"])).unwrap();
    let web = f.agent("web");
    f.cp.change_agent_tags(&admin, &web, &s(&["team:ops"]), &[]).unwrap();
    f.cp.register(&web, &RegisterTunnel { visibility: Some(Visibility::Public), ..http("public") }).unwrap();
    let reach = f.cp.private_reach(&admin);
    assert_eq!((reach.by_tag.get("team:dev"), reach.by_tag.get("team:ops")), (Some(&2), Some(&1)), "public tunnels don't count");
    assert_eq!(reach.by_agent[&ci].get("team:dev"), Some(&2));
    assert!(f.cp.private_reach(&who).by_tag.is_empty(), "members count only their own tunnels");

    // A tunnel's tags are what was stored: removing one from the agent changes what new
    // tunnels may carry, not existing ones.
    f.cp.change_agent_tags(&admin, &ci, &[], &s(&["team:dev"])).unwrap();
    assert_eq!(f.data.lookup(&t.hostname).unwrap().access.authz.access, ["team:dev"]);
    assert!(f.cp.change_agent_tags(&who, &ci, &[], &s(&["team:ops"])).unwrap_err().is(ErrorCode::NotFound), "not ann's agent");
}

#[tokio::test]
async fn registration_respects_the_enrollment() {
    use magicpipes_core::proto::{Kind, Visibility};

    use crate::authz::Role;
    use crate::control::EnrollmentOptions;
    let f = fixture();
    let admin = Principal::AdminToken;
    // Enrolled before the server had users: its tunnels stay public by default.
    let ci = f.agent("ci");
    f.cp.create_tag(&admin, "team:dev", "", true).unwrap();
    f.cp.create_tag(&admin, "team:ops", "", true).unwrap();
    let (ann, _) = f.cp.create_user(&admin, "ann@example.com", "", Role::Member, Some("correct horse battery")).await.unwrap();
    f.cp.set_user_tags(&admin, &ann.id, &["team:dev".into()]).unwrap();
    // An administrator enrolls ann's machine: ann owns it, so its tunnels carry her tag.
    let opts = EnrollmentOptions { owner_user_id: Some(ann.id.clone()), allow_public: Some(false), ..Default::default() };
    let token = f.cp.create_enrollment(&admin, opts).unwrap();
    let laptop = f.cp.enroll(&EnrollRequest { enrollment_token: token, agent_name: "laptop".into() }).unwrap().agent_id;
    let with = |name: &str, v: Option<Visibility>, tags: &[&str]| RegisterTunnel { visibility: v, tags: tags.iter().map(|s| s.to_string()).collect(), ..http(name) };

    // An agent that sends no visibility gets its enrollment's default: private, for its owner.
    let pa = ann.personal_tag.clone().unwrap();
    let t = f.cp.register(&laptop, &http("old")).unwrap();
    assert_eq!((t.visibility, t.tags.clone()), (Some(Visibility::Private), vec![pa.clone()]));
    let route = f.data.lookup(&t.hostname).unwrap();
    assert!(!route.access.authz.public);
    assert_eq!(route.access.authz.access, std::slice::from_ref(&pa), "no tags asked for: the owner only, by their tag");
    // ...and re-registering without one keeps the tunnel as it is.
    f.cp.register(&laptop, &with("old", Some(Visibility::Private), &["team:dev"])).unwrap();
    assert_eq!(f.cp.register(&laptop, &http("old")).unwrap().tags, ["team:dev".to_string(), pa.clone()]);

    assert!(f.cp.register(&laptop, &with("pub", Some(Visibility::Public), &[])).unwrap_err().is(ErrorCode::PublicNotAllowed));
    assert!(f.cp.register(&laptop, &with("ops", Some(Visibility::Private), &["team:ops"])).unwrap_err().is(ErrorCode::Forbidden));
    assert!(f.cp.register(&laptop, &with("qa", Some(Visibility::Private), &["team:qa"])).unwrap_err().is(ErrorCode::TagUnknown));
    let tcp = RegisterTunnel { kind: Kind::Tcp, ..with("db", Some(Visibility::Private), &[]) };
    assert!(f.cp.register(&laptop, &tcp).unwrap_err().is(ErrorCode::Unsupported) || f.cp.register(&laptop, &tcp).unwrap_err().is(ErrorCode::PortsDisabled));
    let public = RegisterTunnel { visibility: Some(Visibility::Public), tags: vec!["team:dev".into()], ..http("site") };
    assert!(f.cp.register(&ci, &public).unwrap_err().is(ErrorCode::InvalidRequest), "tags apply only to private tunnels");

    // The service agent from before users keeps making public tunnels; new ones default to private.
    let t = f.cp.register(&ci, &http("site")).unwrap();
    assert_eq!(t.visibility, Some(Visibility::Public));
    assert!(f.data.lookup(&t.hostname).unwrap().access.authz.public);
    let later = f.agent("later");
    assert_eq!(f.cp.register(&later, &http("site2")).unwrap().visibility, Some(Visibility::Private));

    // An agent from before private tunnels can't check one; it is told to upgrade, and gets
    // neither a private tunnel it would time out on nor a public one.
    let old = f.agent("old");
    let (handle, _) = magicpipes_core::mux::spawn(tokio::io::duplex(1024).0, magicpipes_core::mux::Mode::Server);
    f.cp.attach_session(&old, handle, "127.0.0.1:1".parse().unwrap(), 2).unwrap();
    assert!(f.cp.register(&old, &http("legacy")).unwrap_err().is(ErrorCode::AgentOutdated));
}

#[tokio::test]
async fn deleting_a_tag_closes_tunnels_shared_with_it() {
    use magicpipes_core::proto::Visibility;

    use crate::control::EnrollmentOptions;
    let f = fixture();
    let admin = Principal::AdminToken;
    for t in ["team:dev", "team:secret"] {
        f.cp.create_tag(&admin, t, "", true).unwrap();
    }
    let opts = EnrollmentOptions { tags: vec!["team:dev".into(), "team:secret".into()], ..Default::default() };
    let token = f.cp.create_enrollment(&admin, opts).unwrap();
    let agent = f.cp.enroll(&EnrollRequest { enrollment_token: token, agent_name: "box".into() }).unwrap().agent_id;
    let req = RegisterTunnel { visibility: Some(Visibility::Private), tags: vec!["team:secret".into()], ..http("db") };
    let t = f.cp.register(&agent, &req).unwrap();
    let access = || f.data.lookup(&t.hostname).unwrap().access.authz.access.clone();
    assert_eq!(access(), ["team:secret"]);
    assert!(f.cp.delete_tag(&admin, "team:secret").unwrap());
    assert!(access().is_empty(), "nobody, not every tag of the agent");
    // A new tag with the old name grants nothing until someone puts it on the tunnel again.
    f.cp.create_tag(&admin, "team:secret", "", true).unwrap();
    assert!(access().is_empty());
}

#[tokio::test]
async fn custom_hostnames_are_assigned_by_administrators() {
    use magicpipes_core::proto::{Kind, Visibility};

    use crate::authz::Role;
    use crate::control::EnrollmentOptions;
    let f = fixture();
    let admin = Principal::AdminToken;
    let (ann, _) = f.cp.create_user(&admin, "ann@example.com", "", Role::Member, Some("correct horse battery")).await.unwrap();
    let (bob, _) = f.cp.create_user(&admin, "bob@example.com", "", Role::Member, Some("correct horse battery")).await.unwrap();
    let laptop_of = |id: &str| EnrollmentOptions { owner_user_id: Some(id.to_string()), ..Default::default() };
    let enroll = |opts| f.cp.enroll(&EnrollRequest { enrollment_token: f.cp.create_enrollment(&admin, opts).unwrap(), agent_name: "m".into() }).unwrap().agent_id;
    let (anns, bobs, ci) = (enroll(laptop_of(&ann.id)), enroll(laptop_of(&bob.id)), f.agent("ci"));
    let as_member = |u: &crate::control::UserView| Principal::User { id: u.id.clone(), role: Role::Member, tags: vec![] };

    // Only administrators register, for one user or one service agent, and only real hostnames.
    let shop = "shop.app.t.example.test";
    assert!(f.cp.create_hostname(&as_member(&ann), shop, Some(&ann.id), None).unwrap_err().is(ErrorCode::Forbidden));
    assert!(f.cp.create_hostname(&admin, "app.t.example.test", Some(&ann.id), None).unwrap_err().is(ErrorCode::InvalidRequest), "a tunnel name");
    assert!(f.cp.create_hostname(&admin, shop, None, None).unwrap_err().is(ErrorCode::InvalidRequest));
    assert!(f.cp.create_hostname(&admin, shop, None, Some(&anns)).unwrap_err().is(ErrorCode::InvalidRequest), "a personal machine: assign its owner");
    let view = f.cp.create_hostname(&admin, "Shop.App.T.Example.Test.", Some(&ann.id), None).unwrap();
    assert_eq!((view.hostname.as_str(), view.owner_email.as_deref(), view.tunnel.as_deref()), (shop, Some("ann@example.com"), None));
    assert!(f.cp.create_hostname(&admin, shop, Some(&bob.id), None).unwrap_err().is(ErrorCode::InvalidRequest), "registered already");
    f.cp.create_hostname(&admin, "api.app.t.example.test", None, Some(&ci)).unwrap();
    assert_eq!(f.cp.hostnames(&as_member(&ann)).len(), 1, "members see their own");
    assert_eq!(f.cp.hostnames(&admin).len(), 2);

    // Only the machines it is assigned to serve it; the name comes from its first label.
    let on = |host: &str| RegisterTunnel { hostname: Some(host.into()), visibility: Some(Visibility::Public), ..http("x") };
    let named = |host: &str| RegisterTunnel { name: None, ..on(host) };
    assert!(f.cp.register(&bobs, &named(shop)).unwrap_err().is(ErrorCode::NotFound), "not bob's");
    assert!(f.cp.register(&ci, &named(shop)).unwrap_err().is(ErrorCode::NotFound));
    assert!(f.cp.register(&anns, &named("other.app.t.example.test")).unwrap_err().is(ErrorCode::NotFound), "not registered");
    let t = f.cp.register(&anns, &named(shop)).unwrap();
    assert_eq!((t.hostname.as_str(), t.name.as_str(), t.created), (shop, "shop", true));
    assert_eq!(t.public_url, format!("https://{shop}"));
    assert!(f.data.lookup(shop).is_some() && f.data.lookup("shop.t.example.test").is_none(), "routed at the custom hostname only");
    assert!(!f.cp.register(&anns, &named(shop)).unwrap().created, "adding it again is idempotent");
    let moved = RegisterTunnel { id: Some(t.id.clone()), ..named("api.app.t.example.test") };
    assert!(f.cp.register(&anns, &moved).unwrap_err().is(ErrorCode::NotFound), "and it can't move to a hostname that isn't hers");
    assert!(f.cp.register(&ci, &RegisterTunnel { kind: Kind::Tcp, ..named("api.app.t.example.test") }).unwrap_err().is(ErrorCode::InvalidRequest));
    let api = f.cp.register(&ci, &named("api.app.t.example.test")).unwrap();
    assert_eq!(f.cp.hostnames(&admin).iter().find(|h| h.hostname == shop).unwrap().tunnel.as_deref(), Some("shop"));

    // Removing the registration deletes its tunnel.
    assert!(f.cp.delete_hostname(&admin, "api.app.t.example.test").unwrap());
    assert!(f.data.lookup(&api.hostname).is_none() && f.cp.tunnel(&admin, &api.id).is_none());
    assert!(!f.cp.delete_hostname(&admin, "api.app.t.example.test").unwrap());
    assert!(f.cp.delete_hostname(&as_member(&ann), shop).unwrap_err().is(ErrorCode::Forbidden));
}

#[tokio::test]
async fn ports_outside_the_range_stay_closed() {
    use magicpipes_core::proto::Kind;
    let port = std::net::TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port();
    let ports = format!("[ports]\nrange = \"{port}-{port}\"\nbind = \"127.0.0.1\"");
    let f = fixture_in(fixture().stop(), &ports);
    let agent = f.agent("db");
    f.cp.register(&agent, &RegisterTunnel { kind: Kind::Tcp, target: "tcp://127.0.0.1:5432".into(), ..http("db") }).unwrap();
    assert!(f.data.lookup_port(Kind::Tcp, port).is_some());
    // The operator turns raw ports off and restarts: the port is not opened again.
    let f = fixture_in(f.stop(), "");
    assert!(f.data.lookup_port(Kind::Tcp, port).is_none());
}

#[tokio::test]
async fn members_can_publish_applies_to_enrolled_machines() {
    use magicpipes_core::proto::Visibility;

    use crate::authz::Role;
    use crate::control::EnrollmentOptions;
    let f = fixture();
    let admin = Principal::AdminToken;
    let (ann, _) = f.cp.create_user(&admin, "ann@example.com", "", Role::Member, Some("correct horse battery")).await.unwrap();
    let opts = EnrollmentOptions { owner_user_id: Some(ann.id.clone()), allow_public: Some(true), ..Default::default() };
    let token = f.cp.create_enrollment(&admin, opts).unwrap();
    let laptop = f.cp.enroll(&EnrollRequest { enrollment_token: token, agent_name: "laptop".into() }).unwrap().agent_id;
    let public = |name: &str| RegisterTunnel { visibility: Some(Visibility::Public), ..http(name) };
    f.cp.register(&laptop, &public("before")).unwrap();
    // The administrator turns public tunnels off for members and restarts the server.
    let f = fixture_in(f.stop(), "[users]\nmembers_can_publish = false");
    assert!(f.cp.register(&laptop, &public("after")).unwrap_err().is(ErrorCode::PublicNotAllowed));
    let private = RegisterTunnel { visibility: Some(Visibility::Private), ..http("after") };
    assert_eq!(f.cp.register(&laptop, &private).unwrap().visibility, Some(Visibility::Private));
}

#[tokio::test]
async fn only_http_tunnels_ask_for_certificates() {
    use magicpipes_core::proto::Kind;

    let port = {
        let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        l.local_addr().unwrap().port()
    };
    let ports = format!("[ports]\nrange = \"{port}-{port}\"\nbind = \"127.0.0.1\"");
    let f = fixture_in(fixture().stop(), &ports);
    let agent = f.agent("a");
    let web = f.cp.register(&agent, &http("web")).unwrap();
    assert!(f.cp.cert_status(&agent, &web.hostname, Duration::ZERO).await.is_ok());
    // Asking about a port tunnel's hostname would order a certificate past the daily limit.
    let db = f.cp.register(&agent, &RegisterTunnel { kind: Kind::Tcp, target: "tcp://127.0.0.1:5432".into(), ..http("db") }).unwrap();
    assert!(f.cp.cert_status(&agent, &db.hostname, Duration::ZERO).await.unwrap_err().is(ErrorCode::NotFound));
}

#[tokio::test]
async fn a_changed_role_takes_effect_at_once() {
    use magicpipes_core::proto::Visibility;

    use crate::authz::Role;
    use crate::control::EnrollmentOptions;
    let dir = std::env::temp_dir().join(format!("mp-control-{}", secret::random_string(8)));
    std::fs::create_dir_all(&dir).unwrap();
    let f = fixture_in(dir, "[users]\nmembers_can_publish = false");
    let admin = Principal::AdminToken;
    let (ann, _) = f.cp.create_user(&admin, "ann@example.com", "", Role::Admin, Some("correct horse battery")).await.unwrap();
    let opts = EnrollmentOptions { owner_user_id: Some(ann.id.clone()), allow_public: Some(true), ..Default::default() };
    let token = f.cp.create_enrollment(&admin, opts).unwrap();
    let laptop = f.cp.enroll(&EnrollRequest { enrollment_token: token, agent_name: "laptop".into() }).unwrap().agent_id;
    let public = |name: &str| RegisterTunnel { visibility: Some(Visibility::Public), ..http(name) };
    f.cp.register(&laptop, &public("before")).unwrap();
    f.cp.update_user(&admin, &ann.id, Some(Role::Member), None).unwrap();
    assert!(f.cp.register(&laptop, &public("after")).unwrap_err().is(ErrorCode::PublicNotAllowed));
    f.cp.update_user(&admin, &ann.id, Some(Role::Admin), None).unwrap();
    assert!(f.cp.register(&laptop, &public("after")).is_ok());
}

#[tokio::test]
async fn api_tokens_end_when_an_account_is_taken_back() {
    use crate::authz::Role;
    let f = fixture();
    let admin = Principal::AdminToken;
    let (ann, _) = f.cp.create_user(&admin, "ann@example.com", "", Role::Member, Some("correct horse battery")).await.unwrap();
    let (bob, _) = f.cp.create_user(&admin, "bob@example.com", "", Role::Member, Some("correct horse battery")).await.unwrap();
    let as_ann = Principal::User { id: ann.id.clone(), role: Role::Member, tags: Vec::new() };
    let as_bob = Principal::User { id: bob.id.clone(), role: Role::Member, tags: Vec::new() };
    let works = |t: &str| f.cp.bearer(t).is_some();

    let (_, one) = f.cp.create_token(&as_ann, "one", None).unwrap();
    let (_, two) = f.cp.create_token(&as_ann, "two", None).unwrap();
    assert!(works(&one) && works(&two));

    // Someone else's account looks like one that doesn't exist.
    assert!(f.cp.revoke_tokens(&as_bob, &ann.id).unwrap_err().is(ErrorCode::NotFound));
    assert!(f.cp.revoke_tokens(&admin, "us_nobody").unwrap_err().is(ErrorCode::NotFound));
    assert!(works(&one));

    // An administrator can revoke them, and so can their owner.
    assert_eq!(f.cp.revoke_tokens(&admin, &ann.id).unwrap(), 2);
    assert!(!works(&one) && !works(&two));
    let (_, three) = f.cp.create_token(&as_ann, "three", None).unwrap();
    assert_eq!(f.cp.revoke_tokens(&as_ann, &ann.id).unwrap(), 1);
    assert!(!works(&three));

    // A password reset takes them too, and leaves other people's alone.
    let (_, four) = f.cp.create_token(&as_ann, "four", None).unwrap();
    let (_, bobs) = f.cp.create_token(&as_bob, "bobs", None).unwrap();
    f.cp.reset_password(&admin, &ann.id).await.unwrap();
    assert!(!works(&four) && works(&bobs));
}
