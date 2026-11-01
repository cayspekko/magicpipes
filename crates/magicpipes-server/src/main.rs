//! `magicpipesd` — the MagicPipes public server.

mod authz;
mod certs;
mod config;
mod control;
mod data;
mod forwarded;
mod gateway;
mod listen;
mod proxy_header;
mod mgmt;
mod store;
mod tunnel_auth;

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
}

fn main() -> anyhow::Result<()> {
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

    match cli.command.unwrap_or(Command::Run) {
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
            tokio::runtime::Builder::new_multi_thread().enable_all().build()?.block_on(run(cfg))
        }
    }
}

fn open_store(cfg: &Config) -> anyhow::Result<Store> {
    let mut dir = std::fs::DirBuilder::new();
    dir.recursive(true);
    #[cfg(unix)]
    std::os::unix::fs::DirBuilderExt::mode(&mut dir, 0o700);
    dir.create(&cfg.data_dir).with_context(|| format!("creating data_dir {}", cfg.data_dir.display()))?;
    Store::open(&cfg.data_dir.join("magicpipes.db"))
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
            if certs.resolver().lookup(host).is_none() {
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

async fn run(cfg: Config) -> anyhow::Result<()> {
    let cfg = Arc::new(cfg);
    let store = open_store(&cfg)?;
    bootstrap_admin(&cfg, &store)?;

    let certs = CertManager::new(&cfg.tls, &cfg.data_dir, &[&cfg.base_domain, &cfg.management.hostname])?;
    if let Some(p) = certs.dev_ca_path() {
        tracing::warn!(ca = %p.display(), "tls.mode = dev-ca: clients must trust this CA; do not use in production");
    }
    let shutdown = CancellationToken::new();
    let signer = tunnel_auth::Signer::load_or_create(&cfg.data_dir)?;
    let data = DataPlane::new(ProxySettings::from_config(&cfg, signer), shutdown.clone());
    let control = ControlPlane::new(cfg.clone(), store, certs.clone(), data.clone())?;
    let mgmt_resolver = management_resolver(&cfg, &certs)?;

    let public_https = bind(cfg.public.https_listen, "public HTTPS").await?;
    let public_http = match cfg.public.http_listen {
        Some(a) => Some(bind(a, "public HTTP").await?),
        None => None,
    };
    let mgmt = bind(cfg.management.listen, "management").await?;

    let tracker = TaskTracker::new();

    control.start(shutdown.clone());
    certs.spawn_renewal(shutdown.clone());

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
        },
        shutdown.clone(),
        tracker.clone(),
    ));
    if let Some(l) = public_http {
        tasks.spawn(data::ingress::serve_http(l, certs.challenges(), cfg.url_port(), shutdown.clone(), tracker.clone()));
    }
    tasks.spawn(mgmt::serve_mgmt(mgmt, mgmt_acceptor, control.clone(), shutdown.clone(), tracker.clone()));

    wait_for_signal().await;
    tracing::info!("shutting down");
    shutdown.cancel();
    control.close_sessions();
    while tasks.join_next().await.is_some() {}
    tracker.close();
    if tokio::time::timeout(Duration::from_secs(15), tracker.wait()).await.is_err() {
        tracing::warn!("some connections did not finish within 15s");
    }
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
