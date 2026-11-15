//! `magicpipesd` — the MagicPipes public server.

// See "Threads and memory" in docs/ARCHITECTURE.md for why this, and why only here.
#[cfg(target_env = "musl")]
#[global_allocator]
static ALLOCATOR: mimalloc::MiMalloc = mimalloc::MiMalloc;

mod authz;
mod certs;
mod config;
mod control;
mod data;
mod forwarded;
mod gateway;
mod github;
mod handover;
mod listen;
mod mail;
mod proxy_header;
mod mgmt;
mod oidc;
mod proxy_auth;
mod store;
mod totp;
mod tunnel_auth;
mod upgrading;

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, bail};
use clap::{Parser, Subcommand};
use tokio::net::TcpListener;
use tokio_rustls::TlsAcceptor;
use tokio_util::sync::CancellationToken;
use tokio_util::task::TaskTracker;

use crate::certs::{CertManager, CertResolver, SingleHost};
use crate::config::{Config, TlsMode};
use crate::control::ControlPlane;
use crate::data::{DataPlane, ProxySettings};
use crate::store::Store;

#[derive(Parser)]
#[command(name = "magicpipesd", version, about = "MagicPipes public tunnel server")]
struct Cli {
    /// Path to the configuration file.
    #[arg(long, short, global = true, env = "MAGICPIPESD_CONFIG", default_value = "magicpipesd.toml")]
    config: PathBuf,
    /// Upgrade to the latest release without downtime: download it, check its signature, put it
    /// in place of the running server's binary, and have the server hand over to it.
    #[arg(long)]
    upgrade: bool,
    /// With --upgrade: only say whether a newer release is available.
    #[arg(long, requires = "upgrade", conflicts_with_all = ["restart", "rollback"])]
    check: bool,
    /// With --upgrade: hand over to the binary in place now, downloading nothing (after
    /// installing one another way, or to restart without downtime).
    #[arg(long, requires = "upgrade", conflicts_with = "rollback")]
    restart: bool,
    /// With --upgrade: put back the binary the last upgrade replaced, and hand over to it.
    #[arg(long, requires = "upgrade")]
    rollback: bool,
    /// With --upgrade: print the result as JSON.
    #[arg(long, requires = "upgrade")]
    json: bool,
    #[command(subcommand)]
    command: Option<Command>,
}

#[derive(Subcommand)]
enum Command {
    /// Run the server (default).
    Run,
    /// Create a single-use enrollment token for `magicpipes login`.
    Enroll,
    /// Create an additional admin token (or replace all with --rotate).
    AdminToken {
        #[arg(long)]
        rotate: bool,
    },
    /// Print an example configuration file.
    InitConfig,
    /// Read the configuration and migrate the database copy at --database: what a running
    /// server has a new version do before handing over to it.
    #[command(hide = true)]
    Rehearse {
        #[arg(long)]
        database: PathBuf,
    },
}

fn main() -> anyhow::Result<()> {
    // While this process has one thread, and before anything replaces its binary or opens a file.
    magicpipes_core::upgrade::remember_exe();
    #[cfg(unix)]
    magicpipes_core::fds::adopt_from_env();
    let joining = std::env::var_os(handover::SOCKET_ENV).map(PathBuf::from);
    if joining.is_some() {
        // SAFETY: the process has one thread so far, so nothing reads the environment meanwhile.
        unsafe { std::env::remove_var(handover::SOCKET_ENV) };
    }
    let cli = Cli::parse();
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_env("MAGICPIPESD_LOG")
                .or_else(|_| tracing_subscriber::EnvFilter::try_from_default_env())
                .unwrap_or_else(|_| "info".into()),
        )
        .with_writer(std::io::stderr)
        .with_ansi(std::io::IsTerminal::is_terminal(&std::io::stderr()))
        .init();

    if cli.upgrade {
        if cli.command.is_some() {
            bail!("--upgrade is a command of its own: `magicpipesd --config <file> --upgrade`");
        }
        let cfg = Config::load(&cli.config)?;
        let what = match (cli.check, cli.restart, cli.rollback) {
            (true, _, _) => upgrading::What::Check,
            (_, true, _) => upgrading::What::Restart,
            (_, _, true) => upgrading::What::Rollback,
            _ => upgrading::What::Upgrade,
        };
        std::process::exit(i32::from(upgrading::run(what, &cfg, cli.json)));
    }
    match cli.command.unwrap_or(Command::Run) {
        Command::Rehearse { database } => {
            Config::load(&cli.config)?;
            handover::rehearse(&database)
        }
        Command::InitConfig => {
            print!("{}", config::EXAMPLE);
            Ok(())
        }
        Command::Enroll => {
            let cfg = Config::load(&cli.config)?;
            let store = open_store(&cfg)?;
            // A service agent; its tunnels are private by default once the server has user accounts.
            let spec = store::EnrollmentSpec { default_private: store.has_users()?, ..Default::default() };
            let token = store.create_enrollment(cfg.agents.enrollment_ttl_secs, &spec)?;
            let port = cfg.management.listen.port();
            let server = match port {
                443 => format!("https://{}", cfg.management.hostname),
                p => format!("https://{}:{p}", cfg.management.hostname),
            };
            eprintln!("Single-use enrollment token (valid {} minutes). On the machine to enroll, run:\n", cfg.agents.enrollment_ttl_secs / 60);
            println!("magicpipes login --server {server} --token {token}");
            Ok(())
        }
        Command::AdminToken { rotate } => {
            let cfg = Config::load(&cli.config)?;
            let store = open_store(&cfg)?;
            println!("{}", store.create_admin_token(rotate)?);
            if rotate {
                eprintln!("All previous admin tokens were revoked.");
            }
            Ok(())
        }
        Command::Run => {
            let cfg = Config::load(&cli.config)?;
            // A new version this one hands over to reads the same file, wherever it starts.
            let config_path = std::path::absolute(&cli.config)?;
            let control = tokio::runtime::Builder::new_multi_thread()
                .worker_threads(CONTROL_THREADS)
                .thread_name("mp-control")
                .enable_all()
                .build()?;
            let traffic = tokio::runtime::Builder::new_multi_thread().thread_name("mp-traffic").enable_all().build()?;
            traffic.block_on(run(cfg, config_path, joining, control.handle().clone()))
        }
    }
}

fn open_store(cfg: &Config) -> anyhow::Result<Store> {
    let mut dir = std::fs::DirBuilder::new();
    dir.recursive(true);
    #[cfg(unix)]
    std::os::unix::fs::DirBuilderExt::mode(&mut dir, 0o700);
    dir.create(&cfg.data_dir).with_context(|| format!("creating data_dir {}", cfg.data_dir.display()))?;
    let path = cfg.data_dir.join("magicpipes.db");
    #[cfg(unix)]
    keep_private(&cfg.data_dir, &path)?;
    Store::open(&path)
}

/// Password hashes, session data and keys live here, in a directory that may have been made by
/// someone else (a Docker volume starts out 0755). SQLite gives its -wal and -shm files the
/// database's permissions, so the database must exist with the right ones before it is opened.
#[cfg(unix)]
fn keep_private(data_dir: &Path, db: &Path) -> anyhow::Result<()> {
    use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};

    let tighten = |path: &Path, mode: u32| {
        let Ok(meta) = std::fs::metadata(path) else { return };
        if meta.permissions().mode() & 0o077 != 0 {
            match std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode)) {
                Ok(()) => tracing::info!(path = %path.display(), "tightened permissions so other local users can't read it"),
                Err(e) => tracing::warn!(path = %path.display(), error = %e, "other local users may be able to read this; could not change its permissions"),
            }
        }
    };
    tighten(data_dir, 0o700);
    std::fs::OpenOptions::new().append(true).create(true).mode(0o600).open(db).with_context(|| format!("opening {}", db.display()))?;
    for suffix in ["", "-wal", "-shm"] {
        let mut name = db.as_os_str().to_owned();
        name.push(suffix);
        tighten(Path::new(&name), 0o600);
    }
    Ok(())
}

/// On first start, creates an admin token and writes it to `<data_dir>/admin-token` (mode 0600).
/// The token itself is never logged.
fn bootstrap_admin(cfg: &Config, store: &Store) -> anyhow::Result<()> {
    if store.admin_token_count()? > 0 {
        return Ok(());
    }
    let token = store.create_admin_token(false)?;
    let path = cfg.data_dir.join("admin-token");
    certs::write_private(&path, format!("{token}\n").as_bytes())?;
    tracing::warn!(path = %path.display(), "created initial admin token; read it, store it safely, then delete the file");
    Ok(())
}

async fn bind(addr: std::net::SocketAddr, what: &str) -> anyhow::Result<TcpListener> {
    TcpListener::bind(addr).await.with_context(|| format!("binding {what} listener on {addr}"))
}

/// The listener an older version handed over as `name`, if it's for `addr`; else a new one.
async fn take_or_bind(name: &str, addr: std::net::SocketAddr, what: &str) -> anyhow::Result<TcpListener> {
    #[cfg(unix)]
    if let Some(fd) = magicpipes_core::fds::take(name) {
        let std = std::net::TcpListener::from(fd);
        if std.local_addr().ok() == Some(addr) || std.local_addr().is_ok_and(|a| addr.ip().is_unspecified() && a.port() == addr.port()) {
            std.set_nonblocking(true)?;
            return Ok(TcpListener::from_std(std)?);
        }
        tracing::info!(listener = what, %addr, "the configuration moved this listener; binding the new address");
    }
    #[cfg(not(unix))]
    let _ = name;
    bind(addr, what).await
}

/// Another descriptor for a listener's socket, to hand to a new version.
#[cfg(unix)]
fn dup(name: &str, l: &TcpListener) -> Option<(String, std::os::fd::OwnedFd)> {
    std::os::fd::AsFd::as_fd(l).try_clone_to_owned().ok().map(|fd| (name.to_string(), fd))
}

/// Certificates for the management listener: its hostname only, never a tunnel's.
fn management_resolver(cfg: &Config, certs: &Arc<CertManager>) -> anyhow::Result<Arc<SingleHost>> {
    let host = &cfg.management.hostname;
    let inner = if let (Some(c), Some(k)) = (&cfg.management.cert_file, &cfg.management.key_file) {
        let loaded = certs::load_pem(&read(c)?, &read(k)?)?;
        let resolver = Arc::new(CertResolver::default());
        for n in &loaded.names {
            resolver.insert(n, loaded.key.clone());
        }
        if resolver.lookup(host).is_none() {
            bail!("management.cert_file does not cover {host}");
        }
        resolver
    } else {
        if cfg.tls.mode == TlsMode::Files {
            if certs.resolver().lookup_issued(host).is_none() {
                bail!("tls.cert_file does not cover the management hostname {host}; set management.cert_file");
            }
        } else {
            certs.ensure(host);
        }
        certs.resolver()
    };
    Ok(Arc::new(SingleHost { host: host.clone(), inner }))
}

fn read(p: &Path) -> anyhow::Result<Vec<u8>> {
    std::fs::read(p).with_context(|| format!("reading {}", p.display()))
}

/// Threads for the control plane, which blocks on SQLite and the registry lock. Its writes go one
/// at a time anyway, so more would only take processor time from traffic, which has the rest.
const CONTROL_THREADS: usize = 2;

/// Runs on the traffic threads, which carry listeners and connections. What the control plane
/// starts (handlers, certificate orders, timers) runs on `control_rt` instead. `joining`: an older
/// version started this one to hand over to it ([`handover`]).
async fn run(cfg: Config, config_path: PathBuf, joining: Option<PathBuf>, control_rt: tokio::runtime::Handle) -> anyhow::Result<()> {
    let mut joining = handover::join(joining).await?;
    let result = serve(cfg, config_path, &mut joining, control_rt).await;
    if let (Err(e), Some(j)) = (&result, joining) {
        j.failed(format!("{e:#}")).await;
    }
    result
}

async fn serve(cfg: Config, config_path: PathBuf, joining: &mut Option<handover::Joining>, control_rt: tokio::runtime::Handle) -> anyhow::Result<()> {
    let cfg = Arc::new(cfg);
    let store = open_store(&cfg)?;
    bootstrap_admin(&cfg, &store)?;

    let certs = CertManager::new(&cfg.tls, &cfg.data_dir, &[&cfg.base_domain, &cfg.management.hostname])?;
    if let Some(p) = certs.dev_ca_path() {
        tracing::warn!(ca = %p.display(), "tls.mode = dev-ca: clients must trust this CA; do not use in production");
    }
    let shutdown = CancellationToken::new();
    // Certificate renewals, sweeps, checks and the like: stopped first at a handover.
    let background = shutdown.child_token();
    let signer = tunnel_auth::Signer::load_or_create(&cfg.data_dir)?;
    let data = DataPlane::new(ProxySettings::from_config(&cfg, signer), shutdown.clone());
    if let Some(j) = joining.as_ref() {
        data.hold_for(j.agents.clone(), Duration::from_secs(cfg.upgrades.hold_secs));
    }
    let (control, mgmt_resolver) = {
        let _control_rt = control_rt.enter();
        (ControlPlane::new(cfg.clone(), store, certs.clone(), data.clone())?, management_resolver(&cfg, &certs)?)
    };
    // Ports the older version had open that no tunnel here uses any more.
    #[cfg(unix)]
    for prefix in ["tcp:", "udp:"] {
        drop(magicpipes_core::fds::take_prefixed(prefix));
    }

    let public_https = take_or_bind("https", cfg.public.https_listen, "public HTTPS").await?;
    let public_http = match cfg.public.http_listen {
        Some(a) => Some(take_or_bind("http", a, "public HTTP").await?),
        None => None,
    };
    let mgmt = take_or_bind("mgmt", cfg.management.listen, "management").await?;
    let ssh = match &cfg.ssh {
        Some(s) => {
            data.set_ssh_ca(data::ssh::load_key(&cfg.data_dir, "ssh-user-ca", "magicpipes user CA")?);
            Some((take_or_bind("ssh", s.listen, "SSH gateway").await?, data::ssh::load_key(&cfg.data_dir, "ssh-host-key", "magicpipes gateway")?, s.clone()))
        }
        None => None,
    };
    #[cfg(unix)]
    let handed: Vec<(String, std::os::fd::OwnedFd)> = [dup("https", &public_https), dup("mgmt", &mgmt)]
        .into_iter()
        .chain([public_http.as_ref().and_then(|l| dup("http", l)), ssh.as_ref().and_then(|(l, ..)| dup("ssh", l))])
        .flatten()
        .collect();

    let tracker = TaskTracker::new();

    // Taking over, the older version's background work runs until it stops accepting.
    if joining.is_none() {
        let _control_rt = control_rt.enter();
        control.start(background.clone());
        certs.spawn_renewal(background.clone());
    }

    let public_acceptor = TlsAcceptor::from(certs::server_config(certs.resolver()));
    let mgmt_acceptor = TlsAcceptor::from(certs::server_config(mgmt_resolver));

    tracing::info!(
        base_domain = %cfg.base_domain,
        https = %cfg.public.https_listen,
        http = ?cfg.public.http_listen,
        management = %cfg.management.listen,
        ports = ?cfg.ports.range,
        tls = ?cfg.tls.mode,
        "magicpipesd {} started",
        magicpipes_core::VERSION
    );

    let mut tasks = tokio::task::JoinSet::new();
    tasks.spawn(data::ingress::serve_https(
        public_https,
        public_acceptor,
        data.clone(),
        listen::ListenOpts {
            name: "public-https",
            max_connections: cfg.public.max_connections,
            max_per_client: cfg.public.max_connections_per_client.max(1),
            header_read_timeout: Duration::from_secs(cfg.public.header_read_timeout_secs),
            trusted_proxies: cfg.trusted_proxies(),
            proxy_protocol: cfg.public.proxy_protocol,
            idle_timeout: config::optional_secs(cfg.public.body_idle_timeout_secs),
        },
        shutdown.clone(),
        tracker.clone(),
    ));
    if let Some(l) = public_http {
        tasks.spawn(data::ingress::serve_http(l, certs.challenges(), cfg.url_port(), shutdown.clone(), tracker.clone()));
    }
    if let Some((listener, key, settings)) = ssh {
        tasks.spawn(data::ssh::serve(listener, key, data.clone(), settings, shutdown.clone()));
    }
    tasks.spawn(mgmt::serve_mgmt(mgmt, mgmt_acceptor, control.clone(), control_rt.clone(), shutdown.clone(), tracker.clone()));

    if let Some(mut j) = joining.take() {
        let hosts = {
            let _control_rt = control_rt.enter();
            control.ensure_certificates()
        };
        control.certificates_settled(hosts, Duration::from_secs(10)).await;
        j.ready().await;
        {
            let _control_rt = control_rt.enter();
            control.start(background.clone());
            certs.spawn_renewal(background.clone());
        }
        j.take_over();
        tracing::info!("took over from the older version");
    } else {
        handover::notify("READY=1");
    }
    handover::write_pid(&cfg.data_dir);

    let old = Arc::new(handover::Old {
        data_dir: cfg.data_dir.clone(),
        config_path,
        control: control.clone(),
        #[cfg(unix)]
        data: data.clone(),
        #[cfg(unix)]
        listeners: handed,
        busy: std::sync::atomic::AtomicBool::new(false),
    });
    let (asks_tx, mut asks) = tokio::sync::mpsc::channel::<handover::Ask>(1);
    control.set_handover(asks_tx.clone());
    #[cfg(unix)]
    {
        // `systemctl reload` and `magicpipesd --upgrade`.
        let mut usr2 = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::user_defined2())?;
        let data_dir = cfg.data_dir.clone();
        tokio::spawn(async move {
            while usr2.recv().await.is_some() {
                let _ = asks_tx.try_send(handover::Ask::from_signal(&data_dir));
            }
        });
    }
    #[cfg(not(unix))]
    drop(asks_tx);

    let mut preparing: Option<tokio::task::JoinHandle<Result<handover::Handing, String>>> = None;
    let handing = loop {
        tokio::select! {
            _ = wait_for_signal() => {
                if let Some(p) = preparing.take() {
                    p.abort();
                }
                break None;
            }
            Some(ask) = asks.recv(), if preparing.is_none() => {
                let old = old.clone();
                preparing = Some(tokio::spawn(async move { old.prepare(&ask).await }));
            }
            prepared = async { preparing.as_mut().expect("guarded").await }, if preparing.is_some() => {
                preparing = None;
                if let Ok(Ok(h)) = prepared {
                    break Some(h);
                }
            }
        }
    };

    let Some(mut handing) = handing else {
        tracing::info!("shutting down");
        handover::notify("STOPPING=1");
        shutdown.cancel();
        control.close_sessions();
        while tasks.join_next().await.is_some() {}
        tracker.close();
        if tokio::time::timeout(Duration::from_secs(15), tracker.wait()).await.is_err() {
            tracing::warn!("some connections did not finish within 15s");
        }
        handover::remove_pid(&cfg.data_dir);
        return Ok(());
    };

    // The new version is ready: this one stops accepting, and its agents move.
    tracing::info!("handing over to the new version");
    shutdown.cancel();
    data.stop_pooling();
    handing.go(&old).await;
    control.ask_to_reconnect();
    let asked = std::time::Instant::now();
    while tasks.join_next().await.is_some() {}
    tracker.close();
    handing.finishing(&old);
    old.drain(asked, &tracker, Duration::from_secs(cfg.upgrades.drain_secs)).await;
    handing.finish(&old).await;
    Ok(())
}

async fn wait_for_signal() {
    #[cfg(unix)]
    {
        let mut term = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()).expect("SIGTERM handler");
        tokio::select! {
            _ = interrupt() => {}
            _ = term.recv() => {}
        }
    }
    #[cfg(not(unix))]
    {
        interrupt().await;
    }
}

/// Ctrl+C. If no handler can be installed (no console), waits forever rather than treating the
/// error as a shutdown request.
async fn interrupt() {
    if tokio::signal::ctrl_c().await.is_err() {
        std::future::pending::<()>().await
    }
}

#[cfg(test)]
mod cli_tests {
    use clap::CommandFactory;

    use super::*;

    #[test]
    fn the_command_line_is_well_formed_and_reads_as_it_did() {
        Cli::command().debug_assert();
        for args in [&["magicpipesd", "--config", "x.toml", "run"][..], &["magicpipesd", "enroll"], &["magicpipesd", "-c", "x", "rehearse", "--database", "c.db"]] {
            assert!(Cli::try_parse_from(args).is_ok(), "{args:?}");
        }
        let up = Cli::try_parse_from(["magicpipesd", "--config", "x.toml", "--upgrade", "--check", "--json"]).unwrap();
        assert!(up.upgrade && up.check && up.json && up.command.is_none());
        assert!(Cli::try_parse_from(["magicpipesd", "--check"]).is_err(), "--check needs --upgrade");
        assert!(Cli::try_parse_from(["magicpipesd", "--upgrade", "--check", "--rollback"]).is_err());
    }
}

#[cfg(all(test, unix))]
mod tests {
    use std::os::unix::fs::PermissionsExt;

    use super::*;

    #[test]
    fn the_database_is_private_even_in_a_directory_someone_else_made() {
        let dir = std::env::temp_dir().join(format!("mp-main-{}", magicpipes_core::secret::random_string(8)));
        std::fs::create_dir_all(&dir).unwrap();
        let mode = |p: &Path| std::fs::metadata(p).unwrap().permissions().mode() & 0o777;
        let set = |p: &Path, m: u32| std::fs::set_permissions(p, std::fs::Permissions::from_mode(m)).unwrap();
        set(&dir, 0o755);
        let cfg: Config = toml::from_str(&format!(
            "base_domain = \"t.test\"\ndata_dir = \"{}\"\n[management]\nhostname = \"m.t.test\"\n[tls]\nmode = \"dev-ca\"",
            dir.display()
        ))
        .unwrap();

        // A new database.
        drop(open_store(&cfg).unwrap());
        assert_eq!(mode(&dir), 0o700);
        let db = dir.join("magicpipes.db");
        assert_eq!(mode(&db), 0o600);

        // One an older version left readable, with its journal files.
        set(&dir, 0o755);
        set(&db, 0o644);
        let wal = dir.join("magicpipes.db-wal");
        std::fs::write(&wal, b"").unwrap();
        set(&wal, 0o644);
        let store = open_store(&cfg).unwrap();
        assert_eq!((mode(&dir), mode(&db), mode(&wal)), (0o700, 0o600, 0o600));
        assert!(store.admin_token_count().is_ok(), "it still opens");
        std::fs::remove_dir_all(&dir).ok();
    }
}
