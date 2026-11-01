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
        std::fs::remove_dir_all(&self.dir).ok();
    }
}

pub(crate) fn fixture() -> Fixture {
    let dir = std::env::temp_dir().join(format!("mp-control-{}", secret::random_string(8)));
    std::fs::create_dir_all(&dir).unwrap();
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
        access: vec![],
        labels: vec![],
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
async fn tags_limit_enrollments_and_personal_agents() {
    use crate::authz::Role;
    use crate::control::EnrollmentOptions;
    let f = fixture();
    let admin = Principal::AdminToken;
    for t in ["team:dev", "team:ops"] {
        f.cp.create_tag(&admin, t, "").unwrap();
    }
    assert!(f.cp.create_tag(&admin, "Not Valid!", "").unwrap_err().is(ErrorCode::InvalidRequest));
    let (ann, _) = f.cp.create_user(&admin, "ann@example.com", "", Role::Member, Some("correct horse battery")).await.unwrap();
    assert!(f.cp.set_user_tags(&admin, &ann.id, &["team:qa".into()]).unwrap_err().is(ErrorCode::TagUnknown));
    f.cp.set_user_tags(&admin, &ann.id, &["team:dev".into()]).unwrap();
    let who = Principal::User { id: ann.id.clone(), role: Role::Member, tags: vec!["team:dev".into()] };
    assert!(f.cp.set_user_tags(&who, &ann.id, &["team:ops".into()]).unwrap_err().is(ErrorCode::Forbidden), "no self-assignment");

    // Members enroll only their own machines, and only with tags they hold.
    let opts = |tags: &[&str]| EnrollmentOptions { tags: tags.iter().map(|s| s.to_string()).collect(), ..Default::default() };
    assert!(f.cp.create_enrollment(&who, opts(&["team:ops"])).unwrap_err().is(ErrorCode::Forbidden));
    let other = EnrollmentOptions { owner_user_id: Some("us_someone".into()), ..Default::default() };
    assert!(f.cp.create_enrollment(&who, other).unwrap_err().is(ErrorCode::Forbidden));
    let token = f.cp.create_enrollment(&who, opts(&["team:dev"])).unwrap();
    let laptop = f.cp.enroll(&EnrollRequest { enrollment_token: token, agent_name: "laptop".into() }).unwrap().agent_id;
    let view = |id: &str| f.cp.agents(&admin).into_iter().find(|a| a.id == id).unwrap();
    let v = view(&laptop);
    assert_eq!((v.owner_user_id.as_deref(), v.tags.clone(), v.default_private), (Some(ann.id.as_str()), vec!["team:dev".to_string()], true));
    assert_eq!(f.cp.agents(&who).len(), 1, "owners see their own machines");

    // A personal agent never has more than its owner: removing the owner's tag removes it.
    f.cp.set_user_tags(&admin, &ann.id, &[]).unwrap();
    assert!(view(&laptop).tags.is_empty());
    f.cp.set_user_tags(&admin, &ann.id, &["team:dev".into()]).unwrap();
    assert_eq!(view(&laptop).tags, ["team:dev"]);

    // Owners may remove an agent's tags but not add them; administrators may.
    assert!(f.cp.update_agent(&who, &laptop, Some(&["team:dev".into(), "team:ops".into()]), None).unwrap_err().is(ErrorCode::Forbidden));
    f.cp.update_agent(&who, &laptop, Some(&[]), Some(&["env:laptop".into()])).unwrap();
    assert_eq!((view(&laptop).tags.len(), view(&laptop).labels.clone()), (0, vec!["env:laptop".to_string()]));
    let service = f.agent("ci");
    f.cp.update_agent(&admin, &service, Some(&["team:ops".into()]), None).unwrap();
    assert_eq!(view(&service).tags, ["team:ops"], "a service agent keeps what an administrator gave it");
    assert!(f.cp.update_agent(&who, &service, Some(&[]), None).unwrap_err().is(ErrorCode::NotFound), "not ann's agent");

    // A disabled owner's agents can't connect and serve nothing.
    f.cp.register(&laptop, &http("annsapp")).unwrap();
    assert!(f.data.lookup("annsapp.t.example.test").is_some());
    f.cp.update_user(&admin, &ann.id, None, Some(true)).unwrap();
    assert!(f.data.lookup("annsapp.t.example.test").is_none());
    let (handle, _) = magicpipes_core::mux::spawn(tokio::io::duplex(1024).0, magicpipes_core::mux::Mode::Server);
    assert!(f.cp.attach_session(&laptop, handle, "127.0.0.1:1".parse().unwrap(), 2).is_none());

    // Deleting a tag revokes it everywhere.
    f.cp.delete_tag(&admin, "team:ops").unwrap();
    assert!(view(&service).tags.is_empty());
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
    f.cp.create_tag(&admin, "team:dev", "").unwrap();
    f.cp.create_tag(&admin, "team:ops", "").unwrap();
    let (ann, _) = f.cp.create_user(&admin, "ann@example.com", "", Role::Member, Some("correct horse battery")).await.unwrap();
    f.cp.set_user_tags(&admin, &ann.id, &["team:dev".into()]).unwrap();
    let opts = EnrollmentOptions { owner_user_id: Some(ann.id.clone()), tags: vec!["team:dev".into()], allow_public: Some(false), ..Default::default() };
    let token = f.cp.create_enrollment(&admin, opts).unwrap();
    let laptop = f.cp.enroll(&EnrollRequest { enrollment_token: token, agent_name: "laptop".into() }).unwrap().agent_id;
    let with = |name: &str, v: Option<Visibility>, access: &[&str]| RegisterTunnel {
        visibility: v,
        access: access.iter().map(|s| s.to_string()).collect(),
        ..http(name)
    };

    // An agent that sends no visibility (protocol 2) gets its enrollment's default: private.
    let t = f.cp.register(&laptop, &http("old")).unwrap();
    assert_eq!((t.visibility, t.access.len()), (Some(Visibility::Private), 0));
    let route = f.data.lookup(&t.hostname).unwrap();
    assert!(!route.access.authz.public);
    assert_eq!(route.access.authz.access, ["team:dev"], "no tags asked for: all of the agent's");
    // ...and re-registering without one keeps the tunnel as it is.
    f.cp.register(&laptop, &with("old", Some(Visibility::Private), &["team:dev"])).unwrap();
    assert_eq!(f.cp.register(&laptop, &http("old")).unwrap().access, ["team:dev"]);

    assert!(f.cp.register(&laptop, &with("pub", Some(Visibility::Public), &[])).unwrap_err().is(ErrorCode::PublicNotAllowed));
    assert!(f.cp.register(&laptop, &with("ops", Some(Visibility::Private), &["team:ops"])).unwrap_err().is(ErrorCode::Forbidden));
    assert!(f.cp.register(&laptop, &with("qa", Some(Visibility::Private), &["team:qa"])).unwrap_err().is(ErrorCode::TagUnknown));
    let tcp = RegisterTunnel { kind: Kind::Tcp, ..with("db", Some(Visibility::Private), &[]) };
    assert!(f.cp.register(&laptop, &tcp).unwrap_err().is(ErrorCode::Unsupported) || f.cp.register(&laptop, &tcp).unwrap_err().is(ErrorCode::PortsDisabled));

    // The service agent from before users keeps making public tunnels; new ones default to private.
    let t = f.cp.register(&ci, &http("site")).unwrap();
    assert_eq!(t.visibility, Some(Visibility::Public));
    assert!(f.data.lookup(&t.hostname).unwrap().access.authz.public);
    let later = f.agent("later");
    assert_eq!(f.cp.register(&later, &http("site2")).unwrap().visibility, Some(Visibility::Private));
}
