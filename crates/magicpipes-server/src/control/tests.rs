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
    let data = DataPlane::new(ProxySettings::from_config(&cfg), CancellationToken::new());
    let cp = ControlPlane::new(cfg, store, certs, data.clone()).unwrap();
    Fixture { cp, data, dir }
}

impl Fixture {
    pub(crate) fn agent(&self, name: &str) -> String {
        let token = self.cp.create_enrollment(&Principal::AdminToken).unwrap();
        let req = EnrollRequest { enrollment_token: token, agent_name: name.into() };
        self.cp.enroll(&req).unwrap().agent_id
    }
}

fn http(name: &str) -> RegisterTunnel {
    RegisterTunnel { id: None, name: Some(name.into()), target: "http://127.0.0.1:3000".into(), kind: Default::default(), remote_port: None, allow: vec![] }
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
    assert!(f.cp.create_enrollment(&pa).unwrap_err().is(ErrorCode::Forbidden));

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
