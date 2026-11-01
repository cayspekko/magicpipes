//! `magicpipes` — MagicPipes CLI and local agent.

mod agent;
mod client;
mod https;
mod ipc;
mod platform;
mod state;

use std::io::{IsTerminal, Write};
use std::path::PathBuf;
use std::process::ExitCode;
use std::time::Duration;

use clap::{Args, Parser, Subcommand};
use magicpipes_core::error::ErrorCode;
use magicpipes_core::proto::Kind;
use serde_json::{Value, json};

use crate::ipc::{AddRequest, ErrorInfo, IpcRequest, StepState};
use crate::state::AgentConfig;

#[derive(Parser)]
#[command(name = "magicpipes", version, about = "Expose local applications at public HTTPS URLs")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Args, Clone, Copy)]
struct Output {
    /// Print machine-readable JSON on stdout (progress and diagnostics go to stderr).
    #[arg(long)]
    json: bool,
    /// Suppress progress output on stderr.
    #[arg(long, short)]
    quiet: bool,
}

#[derive(Subcommand)]
enum Command {
    /// Enroll this machine with a MagicPipes server.
    Login {
        /// Management URL of the server, e.g. https://example.com:8443
        #[arg(long)]
        server: String,
        /// Single-use enrollment token (from `magicpipesd enroll` or the UI).
        #[arg(long, env = "MAGICPIPES_TOKEN", hide_env_values = true)]
        token: Option<String>,
        /// Extra CA certificate (PEM) to trust, e.g. the server's development CA.
        #[arg(long)]
        ca_cert: Option<PathBuf>,
        /// Name for this agent (defaults to the hostname).
        #[arg(long)]
        name: Option<String>,
        #[command(flatten)]
        out: Output,
    },
    /// Expose a local port, serve a directory or share a terminal; returns once the public address is verified to work.
    Add {
        /// Local port of the application (TCP; UDP with --udp).
        port: Option<u16>,
        /// Publish a raw TCP port (tcp://host:port) instead of an HTTPS hostname: databases, SSH,
        /// game servers, anything that speaks TCP.
        #[arg(long, conflicts_with_all = ["serve", "shell", "udp"])]
        tcp: bool,
        /// Publish a UDP port (udp://host:port); datagrams go to the local UDP port.
        #[arg(long, conflicts_with_all = ["serve", "shell"])]
        udp: bool,
        /// With --tcp/--udp: ask for this public port (it must be in the server's range).
        #[arg(long, value_name = "PORT")]
        remote_port: Option<u16>,
        /// With --tcp/--udp: only let clients from this network connect (CIDR or address;
        /// repeatable). Default: anyone.
        #[arg(long = "allow-cidr", value_name = "CIDR", value_parser = parse_cidr)]
        allow_cidr: Vec<String>,
        /// Serve the files in DIR with the built-in web server instead of forwarding to a port.
        #[arg(long, value_name = "DIR", conflicts_with_all = ["port", "host", "shell"])]
        serve: Option<PathBuf>,
        /// With --serve: don't list directory contents (a directory's index.html is still served).
        #[arg(long, requires = "serve")]
        no_list: bool,
        /// Share a terminal in the browser: your login shell, or the program given after `--`.
        /// Each visitor gets their own copy; read-only unless --write.
        #[arg(long, conflicts_with_all = ["port", "host"])]
        shell: bool,
        /// With --shell: let visitors type. Prints a secret link, which is required to connect.
        #[arg(long)]
        write: bool,
        /// With --shell: most sessions open at once.
        #[arg(long, value_name = "N")]
        max_clients: Option<u16>,
        /// With --shell: the program (and its arguments) to run instead of your login shell.
        #[arg(last = true, value_name = "PROGRAM")]
        command: Vec<String>,
        /// Tunnel name (first label of the public hostname). Random if omitted.
        #[arg(long)]
        name: Option<String>,
        /// Local host to connect to (default: 127.0.0.1, falling back to ::1).
        #[arg(long)]
        host: Option<String>,
        /// Path requested by the readiness probe.
        #[arg(long, default_value = "/")]
        probe_path: String,
        /// Overall timeout in seconds, including certificate issuance.
        #[arg(long, default_value_t = 120)]
        timeout: u64,
        #[command(flatten)]
        out: Output,
    },
    /// List tunnels served by this machine.
    #[command(alias = "ls")]
    List {
        #[command(flatten)]
        out: Output,
    },
    /// Show login, agent and connection status.
    Status {
        #[command(flatten)]
        out: Output,
    },
    /// Remove a tunnel (by name, id or local port).
    #[command(alias = "rm")]
    Remove {
        tunnel: String,
        /// Remove locally even if the server cannot be reached.
        #[arg(long)]
        force: bool,
        #[command(flatten)]
        out: Output,
    },
    /// Manage the background agent.
    Agent {
        #[command(subcommand)]
        command: AgentCommand,
    },
}

#[derive(Subcommand)]
enum AgentCommand {
    /// Run the agent in the foreground (for systemd, launchd, containers, debugging).
    Run {
        #[arg(long, hide = true)]
        detached: bool,
    },
    /// Start the background agent if it is not running.
    Start {
        #[command(flatten)]
        out: Output,
    },
    /// Stop the background agent. Tunnels stay registered and resume on next start.
    Stop {
        #[command(flatten)]
        out: Output,
    },
    /// Show agent status.
    Status {
        #[command(flatten)]
        out: Output,
    },
    /// Print the background agent's log.
    Logs {
        /// Number of lines.
        #[arg(short = 'n', long, default_value_t = 50)]
        lines: usize,
        /// Keep printing new lines.
        #[arg(short, long)]
        follow: bool,
    },
}

/// Exit codes (documented in the README).
fn main() -> ExitCode {
    let cli = Cli::parse();
    check_add_args(&cli.command);
    if let Command::Agent { command: AgentCommand::Run { detached } } = cli.command {
        return run_agent(detached);
    }
    let rt = tokio::runtime::Builder::new_current_thread().enable_all().build().expect("tokio runtime");
    rt.block_on(dispatch(cli.command))
}

/// Argument rules clap cannot express: a bool flag such as `--shell` always counts as present
/// (it has a default), so `requires = "shell"` would never fire.
fn check_add_args(cmd: &Command) {
    use clap::CommandFactory;
    use clap::error::ErrorKind;
    let Command::Add { port, tcp, udp, remote_port, allow_cidr, serve, shell, write, max_clients, command, .. } = cmd else {
        return;
    };
    let fail = |kind, msg: &str| Cli::command().find_subcommand_mut("add").expect("add subcommand").error(kind, msg).exit();
    if port.is_none() && serve.is_none() && !shell {
        fail(ErrorKind::MissingRequiredArgument, "give a local <PORT>, --serve <DIR> or --shell");
    }
    if !shell && (*write || max_clients.is_some() || !command.is_empty()) {
        fail(ErrorKind::ArgumentConflict, "--write, --max-clients and a `-- <PROGRAM>` can only be used with --shell");
    }
    if !tcp && !udp && (remote_port.is_some() || !allow_cidr.is_empty()) {
        fail(ErrorKind::ArgumentConflict, "--remote-port and --allow-cidr can only be used with --tcp or --udp");
    }
    if remote_port == &Some(0) {
        fail(ErrorKind::InvalidValue, "--remote-port must be between 1 and 65535");
    }
}

fn parse_cidr(s: &str) -> Result<String, String> {
    magicpipes_core::cidr::Cidr::parse(s).map(|c| c.to_string())
}

fn run_agent(detached: bool) -> ExitCode {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_env("MAGICPIPES_LOG").unwrap_or_else(|_| "info".into()),
        )
        .with_writer(std::io::stderr)
        .with_ansi(!detached && std::io::stderr().is_terminal())
        .init();
    match agent::run(detached) {
        Ok(agent::Start::Ran) => ExitCode::SUCCESS,
        Ok(agent::Start::AlreadyRunning) if detached => ExitCode::SUCCESS,
        Ok(agent::Start::AlreadyRunning) => {
            eprintln!("Error: an agent is already running (pid {})", read_pid().unwrap_or_default());
            ExitCode::from(5)
        }
        Err(e) => {
            eprintln!("Error: {e:#}");
            ExitCode::from(1)
        }
    }
}

fn read_pid() -> Option<String> {
    std::fs::read_to_string(state::pid_path()).ok().map(|s| s.trim().to_string())
}

async fn dispatch(cmd: Command) -> ExitCode {
    let (out, result) = match cmd {
        Command::Login { server, token, ca_cert, name, out } => (out, login(server, token, ca_cert, name, out).await),
        Command::Add {
            port,
            tcp,
            udp,
            remote_port,
            allow_cidr,
            serve,
            no_list,
            shell,
            write,
            max_clients,
            command,
            name,
            host,
            probe_path,
            timeout,
            out,
        } => {
            let kind = match (tcp, udp) {
                (true, _) => Kind::Tcp,
                (_, true) => Kind::Udp,
                _ => Kind::Http,
            };
            let req = AddRequest {
                port,
                kind,
                remote_port,
                allow: allow_cidr,
                serve,
                list: !no_list,
                shell: shell.then(|| if command.is_empty() { login_shell() } else { command }),
                cwd: None,
                writable: write,
                max_clients,
                host,
                name,
                probe_path,
                timeout_secs: timeout,
            };
            (out, add(req, out).await)
        }
        Command::List { out } => (out, list(out).await),
        Command::Status { out } => (out, status(out).await),
        Command::Remove { tunnel, force, out } => (out, remove(tunnel, force, out).await),
        Command::Agent { command } => match command {
            AgentCommand::Start { out } => (out, agent_start(out).await),
            AgentCommand::Stop { out } => (out, agent_stop(out).await),
            AgentCommand::Status { out } => (out, status(out).await),
            AgentCommand::Logs { lines, follow } => {
                return match logs(lines, follow).await {
                    Ok(()) => ExitCode::SUCCESS,
                    Err(e) => {
                        eprintln!("Error: {e}");
                        ExitCode::from(1)
                    }
                };
            }
            AgentCommand::Run { .. } => unreachable!("handled in main"),
        },
    };
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            if out.json {
                println!("{}", json!({ "error": e }));
            }
            if !out.json || !out.quiet {
                eprintln!("\nError: {}", e.message);
            }
            ExitCode::from(magicpipes_core::error::exit_code(&e.code))
        }
    }
}

fn print_json(v: &Value) {
    println!("{}", serde_json::to_string_pretty(v).unwrap_or_default());
}

/// The command `--shell` runs without one: the user's login shell (PowerShell on Windows).
fn login_shell() -> Vec<String> {
    if cfg!(windows) {
        return vec!["powershell.exe".into(), "-NoLogo".into()];
    }
    let shell = std::env::var("SHELL").ok().filter(|s| !s.is_empty()).unwrap_or_else(|| "/bin/sh".into());
    vec![shell, "-l".into()]
}

// ---- commands -----------------------------------------------------------------------------

async fn login(server: String, token: Option<String>, ca_cert: Option<PathBuf>, name: Option<String>, out: Output) -> Result<(), ErrorInfo> {
    let server = server.trim().trim_end_matches('/').to_string();
    https::parse_server(&server).map_err(|e| ErrorInfo::new(ErrorCode::InvalidServer, e.to_string()))?;
    let token = match token {
        Some(t) => t,
        None => {
            if !std::io::stdin().is_terminal() {
                return Err(ErrorInfo::new(ErrorCode::InvalidEnrollmentToken, "pass --token or set MAGICPIPES_TOKEN"));
            }
            eprint!("Enrollment token: ");
            let _ = std::io::stderr().flush();
            let mut line = String::new();
            std::io::stdin().read_line(&mut line).map_err(|e| ErrorInfo::new(ErrorCode::ConfigError, e.to_string()))?;
            line
        }
    };
    let ca_pem = match &ca_cert {
        Some(p) => Some(std::fs::read_to_string(p).map_err(|e| ErrorInfo::new(ErrorCode::ConfigError, format!("reading {}: {e}", p.display())))?),
        None => None,
    };
    let tls = https::tls_config(ca_pem.as_deref()).map_err(|e| ErrorInfo::new(ErrorCode::ConfigError, format!("{e:#}")))?;
    let agent_name = name.unwrap_or_else(platform::hostname);
    let body = json!({ "enrollment_token": token.trim(), "agent_name": agent_name });
    let (status, resp) = https::post_json(&server, "/api/v1/enroll", &tls, &body)
        .await
        .map_err(|e| ErrorInfo::new(ErrorCode::ServerUnreachable, format!("{e:#}")))?;
    if !status.is_success() {
        let msg = resp["error"]["message"].as_str().unwrap_or("enrollment failed").to_string();
        let code = resp["error"]["code"].as_str().unwrap_or(ErrorCode::InvalidEnrollmentToken.as_str());
        return Err(ErrorInfo::wire(code, msg));
    }
    let enrolled: magicpipes_core::proto::EnrollResponse =
        serde_json::from_value(resp).map_err(|e| ErrorInfo::new(ErrorCode::Protocol, e.to_string()))?;
    // A running agent still uses the previous identity: stop it; the next command restarts it.
    let was_running = client::connect().await.is_some();
    if was_running {
        let _ = client::request(&IpcRequest::Shutdown { if_idle: false }, |_, _| {}).await;
        client::wait_stopped(Duration::from_secs(5)).await;
    }
    let cfg = AgentConfig {
        server: server.clone(),
        agent_id: enrolled.agent_id.clone(),
        agent_token: enrolled.agent_token,
        base_domain: enrolled.base_domain.clone(),
        ca_cert_pem: ca_pem,
    };
    cfg.save().map_err(|e| ErrorInfo::new(ErrorCode::ConfigError, format!("{e:#}")))?;
    if out.json {
        print_json(&json!({ "server": server, "agent_id": enrolled.agent_id, "base_domain": enrolled.base_domain }));
    } else {
        println!("Logged in to {server}");
        println!("  Agent:       {} ({})", agent_name, enrolled.agent_id);
        println!("  Base domain: {}", enrolled.base_domain);
        if was_running {
            println!("  The running agent was stopped; it restarts with the new identity on the next command.");
        }
        println!("\nNext: magicpipes add <port>");
    }
    Ok(())
}

struct Progress {
    enabled: bool,
    /// Label for the local step when it is not a port check.
    local: Option<&'static str>,
}

impl Progress {
    fn step(&self, step: ipc::Step, state: StepState) {
        if !self.enabled {
            return;
        }
        let mut err = std::io::stderr();
        match state {
            StepState::Running => {
                let label = match self.local {
                    Some(l) if step == ipc::Step::Local => l,
                    _ => step.label(),
                };
                let _ = write!(err, "{label:<30}");
            }
            StepState::Done => {
                let _ = writeln!(err, "✓");
            }
            StepState::Failed => {
                let _ = writeln!(err, "✗");
            }
            StepState::Warned => {
                let _ = writeln!(err, "!");
            }
        }
        let _ = err.flush();
    }
}

async fn add(mut req: AddRequest, out: Output) -> Result<(), ErrorInfo> {
    client::require_login()?;
    // The agent runs elsewhere (another working directory), so it needs an absolute path.
    if let Some(dir) = &req.serve {
        let abs = std::fs::canonicalize(dir)
            .map_err(|e| ErrorInfo::new(ErrorCode::InvalidDirectory, format!("cannot serve {}: {e}", dir.display())))?;
        req.serve = Some(abs);
    }
    if req.shell.is_some() {
        let cwd = std::env::current_dir().and_then(std::fs::canonicalize);
        req.cwd = Some(cwd.map_err(|e| ErrorInfo::new(ErrorCode::InvalidCommand, format!("cannot use the current directory: {e}")))?);
    }
    let kind = req.kind;
    let open_to_anyone = req.allow.is_empty();
    let serving = req.serve.clone();
    let listing = serving.is_some() && req.list;
    let shell = req.shell.as_ref().map(|argv| (state::command_line(argv), req.writable, req.cwd.clone().unwrap_or_default()));
    let spawned = client::ensure_agent().await?;
    let local = if serving.is_some() {
        Some("Checking directory...")
    } else if shell.is_some() {
        Some("Checking program...")
    } else {
        None
    };
    let progress = Progress { enabled: !out.quiet, local };
    let result = client::request(&IpcRequest::Add(req), |s, st| progress.step(s, st)).await;
    let data = match result {
        Ok(d) => d,
        Err(e) => {
            if spawned {
                // Don't leave an agent we just started running with nothing to do.
                let _ = client::request(&IpcRequest::Shutdown { if_idle: true }, |_, _| {}).await;
            }
            return Err(e);
        }
    };
    if out.json {
        print_json(&data);
    } else {
        println!();
        println!("Tunnel ready");
        println!();
        println!("  Public: {}", data["share_url"].as_str().or(data["public_url"].as_str()).unwrap_or_default());
        match (&serving, &shell) {
            (Some(dir), _) => println!("  Serving: {}", state::display_path(dir)),
            (_, Some((cmd, writable, cwd))) => {
                println!("  Shell:  {cmd} ({})", if *writable { "read-write" } else { "read-only" });
                println!("  In:     {}", state::display_path(cwd));
            }
            _ => println!("  Local:  {}", data["target"].as_str().unwrap_or_default()),
        }
        println!("  Status: connected");
        println!();
        match &shell {
            Some((_, true, _)) => println!("Tunnel active in background. Anyone with this link can type into the terminal."),
            Some((_, false, _)) => println!("Tunnel active in background. Anyone with the URL can watch; each visitor gets their own copy."),
            None if kind.is_http() => println!("Tunnel active in background. Anyone with the URL can reach it."),
            None if open_to_anyone => println!("Tunnel active in background. Anyone who finds the port can connect."),
            None => println!("Tunnel active in background. Only the allowed networks can connect."),
        }
        println!("Stop it with: magicpipes remove {}", data["name"].as_str().unwrap_or_default());
    }
    if let Some((cmd, writable, _)) = &shell
        && !out.quiet
    {
        eprintln!();
        if *writable {
            eprintln!("The link above runs `{cmd}` on this machine as you, with full control. Share it like a password;");
            eprintln!("re-running this command prints the same link, and `magicpipes remove` revokes it.");
        } else {
            eprintln!("Visitors only watch: their keystrokes are ignored. Use --write to let people type.");
        }
    }
    if !kind.is_http() && !out.quiet {
        let url = data["public_url"].as_str().unwrap_or_default();
        if data["reachable"] == false {
            eprintln!();
            eprintln!("Warning: this machine could not connect to {url}. The tunnel works from the server");
            eprintln!("inward; check that the server's firewall or router forwards this port. (Some networks");
            eprintln!("cannot reach their own public address, so clients elsewhere may still get through.)");
        }
        if kind == Kind::Udp {
            eprintln!();
            eprintln!("UDP cannot be verified end to end: datagrams to {url} now reach the local port.");
        }
        if open_to_anyone {
            eprintln!();
            eprintln!("The port is open to the whole internet, and nothing but your service authenticates");
            eprintln!("clients. Use --allow-cidr to limit who can connect.");
        }
    }
    if listing && !out.quiet {
        eprintln!();
        eprintln!("Directory listing is on: anyone with the URL can browse every non-hidden file in this directory.");
        eprintln!("Use --no-list to serve only files by exact path (and index.html).");
    }
    Ok(())
}

async fn list(out: Output) -> Result<(), ErrorInfo> {
    let data = match client::request(&IpcRequest::List, |_, _| {}).await {
        Ok(d) => d,
        Err(e) if e.is(ErrorCode::AgentNotRunning) => {
            let tunnels: Vec<Value> = state::load_tunnels()
                .unwrap_or_default()
                .into_iter()
                .map(|t| {
                    json!({ "id": t.id, "name": t.name, "kind": t.kind, "public_url": t.public_url, "target": t.describe(),
                            "status": "stopped", "created_at": magicpipes_core::rfc3339(t.created_at) })
                })
                .collect();
            json!({ "agent_running": false, "connection": "stopped", "tunnels": tunnels })
        }
        Err(e) => return Err(e),
    };
    if out.json {
        print_json(&data);
        return Ok(());
    }
    let tunnels = data["tunnels"].as_array().cloned().unwrap_or_default();
    if tunnels.is_empty() {
        println!("No tunnels. Create one with: magicpipes add <port>");
    } else {
        let w = tunnels.iter().map(|t| t["name"].as_str().unwrap_or("").len()).max().unwrap_or(4).max(4);
        let u = tunnels.iter().map(|t| t["public_url"].as_str().unwrap_or("").len()).max().unwrap_or(10).max(10);
        println!("{:<w$}  {:<u$}  {:<24}  STATUS", "NAME", "PUBLIC URL", "TARGET");
        for t in &tunnels {
            println!(
                "{:<w$}  {:<u$}  {:<24}  {}",
                t["name"].as_str().unwrap_or(""),
                t["public_url"].as_str().unwrap_or(""),
                t["target"].as_str().unwrap_or(""),
                t["status"].as_str().unwrap_or(""),
            );
        }
    }
    if data["agent_running"] == false {
        println!("\nThe agent is not running; start it with: magicpipes agent start");
    }
    Ok(())
}

async fn status(out: Output) -> Result<(), ErrorInfo> {
    let cfg = AgentConfig::load().ok().flatten();
    let agent = match client::request(&IpcRequest::Status, |_, _| {}).await {
        Ok(d) => Some(d),
        Err(e) if e.is(ErrorCode::AgentNotRunning) => None,
        Err(e) => return Err(e),
    };
    let data = json!({
        "logged_in": cfg.is_some(),
        "server": cfg.as_ref().map(|c| c.server.clone()),
        "agent_id": cfg.as_ref().map(|c| c.agent_id.clone()),
        "agent": agent.as_ref().map(|a| a["agent"].clone()).unwrap_or(json!({ "running": false })),
        "connection": agent.as_ref().map(|a| a["connection"].clone()).unwrap_or(json!("stopped")),
        "last_error": agent.as_ref().map(|a| a["last_error"].clone()).unwrap_or(Value::Null),
        "server_protocol": agent.as_ref().map(|a| a["server_protocol"].clone()).unwrap_or(Value::Null),
        "tunnels": agent.as_ref().map(|a| a["tunnels"].clone()).unwrap_or(json!(state::load_tunnels().map(|t| t.len()).unwrap_or(0))),
    });
    if out.json {
        print_json(&data);
        return Ok(());
    }
    match &cfg {
        Some(c) => println!("Server:     {} (agent {})", c.server, c.agent_id),
        None => println!("Server:     not logged in (run `magicpipes login`)"),
    }
    match &agent {
        Some(a) => {
            println!("Agent:      running (pid {}, since {})", a["agent"]["pid"], a["agent"]["started_at"].as_str().unwrap_or(""));
            println!("Connection: {}", a["connection"].as_str().unwrap_or(""));
            if let Some(e) = a["last_error"].as_str() {
                println!("Last error: {e}");
            }
        }
        None => println!("Agent:      not running"),
    }
    println!("Tunnels:    {}", data["tunnels"]);
    Ok(())
}

async fn remove(selector: String, force: bool, out: Output) -> Result<(), ErrorInfo> {
    client::require_login()?;
    let spawned = client::ensure_agent().await?;
    let res = client::request(&IpcRequest::Remove { selector, force }, |_, _| {}).await;
    if spawned {
        let _ = client::request(&IpcRequest::Shutdown { if_idle: true }, |_, _| {}).await;
    }
    let data = res?;
    if out.json {
        print_json(&data);
    } else {
        println!("Removed tunnel {}", data["name"].as_str().unwrap_or_default());
    }
    Ok(())
}

async fn agent_start(out: Output) -> Result<(), ErrorInfo> {
    let spawned = client::ensure_agent().await?;
    let data = client::request(&IpcRequest::Status, |_, _| {}).await?;
    if out.json {
        print_json(&json!({ "started": spawned, "agent": data["agent"] }));
    } else if spawned {
        println!("Agent started (pid {})", data["agent"]["pid"]);
    } else {
        println!("Agent already running (pid {})", data["agent"]["pid"]);
    }
    Ok(())
}

async fn agent_stop(out: Output) -> Result<(), ErrorInfo> {
    let running = client::connect().await.is_some();
    if running {
        client::request(&IpcRequest::Shutdown { if_idle: false }, |_, _| {}).await?;
        if !client::wait_stopped(Duration::from_secs(10)).await {
            return Err(ErrorInfo::new(ErrorCode::AgentUnavailable, "agent did not stop within 10s"));
        }
    }
    if out.json {
        print_json(&json!({ "stopped": running }));
    } else if running {
        println!("Agent stopped. Tunnels stay registered and resume with `magicpipes agent start`.");
    } else {
        println!("Agent is not running.");
    }
    Ok(())
}

async fn logs(lines: usize, follow: bool) -> std::io::Result<()> {
    for l in client::tail_log(lines) {
        println!("{l}");
    }
    if !follow {
        return Ok(());
    }
    use std::io::{Read, Seek};
    let mut pos = std::fs::metadata(state::log_path()).map(|m| m.len()).unwrap_or(0);
    loop {
        tokio::time::sleep(Duration::from_millis(500)).await;
        let Ok(mut f) = std::fs::File::open(state::log_path()) else { continue };
        let len = f.metadata()?.len();
        if len < pos {
            pos = 0;
        }
        if len > pos {
            f.seek(std::io::SeekFrom::Start(pos))?;
            let mut buf = String::new();
            f.read_to_string(&mut buf)?;
            print!("{buf}");
            std::io::stdout().flush()?;
            pos = len;
        }
    }
}
