//! `magicpipes` — MagicPipes CLI and local agent.

mod agent;
mod client;
mod connect;
mod https;
mod ipc;
mod platform;
mod state;

use std::io::{IsTerminal, Write};
use std::path::PathBuf;
use std::process::ExitCode;
use std::sync::Arc;
use std::time::Duration;

use clap::{Args, Parser, Subcommand};
use magicpipes_core::error::ErrorCode;
use magicpipes_core::proto::{Kind, Visibility};
use serde_json::{Value, json};

use crate::ipc::{AddRequest, ErrorInfo, IpcRequest, StepState};
use crate::state::AgentConfig;

#[derive(Parser)]
#[command(
    name = "magicpipes",
    version,
    about = "Expose local applications at public HTTPS URLs",
    after_help = "Examples:
  magicpipes login --server https://mp.example.com   Enroll this machine
  magicpipes add 8080                                Give a local port its own address
  magicpipes add 8080 --private                      Only for people who sign in and are allowed
  magicpipes add --unix /run/app.sock                Give a local Unix socket its own address
  magicpipes add --serve ./public                    Share a folder
  magicpipes add 22 --tcp --allow-cidr 203.0.113.0/24   Open a raw TCP port to one network
  magicpipes add 5432 --tcp --tag team:dev           A private TCP tunnel, for people with that tag
  magicpipes connect db --local 5432                 Reach a private TCP or UDP tunnel from here
  magicpipes list                                    See what's running
  magicpipes remove <name>                           Stop one"
)]
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
    #[command(after_help = "Examples:
  magicpipes login --server https://mp.example.com                     Approve it in your browser
  magicpipes login --server https://mp.example.com --token-file token  With an enrollment token")]
    Login {
        /// Management URL of the server, e.g. https://example.com:8443
        #[arg(long)]
        server: String,
        /// Single-use enrollment token (from `magicpipesd enroll` or the UI). Without one, the
        /// CLI opens the server's sign-in page so you can approve this machine as yours.
        #[arg(long, env = "MAGICPIPES_TOKEN", hide_env_values = true)]
        token: Option<String>,
        /// Read the enrollment token from this file, which unlike --token doesn't show it to other
        /// programs on this machine.
        #[arg(long, value_name = "FILE", conflicts_with = "token")]
        token_file: Option<PathBuf>,
        /// Approve this machine in the browser even when not run in a terminal.
        #[arg(long, conflicts_with_all = ["token", "token_file"])]
        browser: bool,
        /// Extra CA certificate (PEM) to trust, e.g. the server's development CA.
        #[arg(long)]
        ca_cert: Option<PathBuf>,
        /// Name for this agent (defaults to the hostname).
        #[arg(long)]
        name: Option<String>,
        #[command(flatten)]
        out: Output,
    },
    /// Expose a local port or Unix socket, serve a directory or share a terminal; returns once the public address is verified to work.
    #[command(after_help = "Examples:
  magicpipes add 8080                         Anyone with the address can reach it
  magicpipes add 8080 --private               Only you, after signing in
  magicpipes add 8080 --tag team:dev          You and people with that tag
  magicpipes add 8080 --hostname shop.example.com
  magicpipes add --unix /run/app.sock         An application on a Unix socket
  magicpipes add --serve ./public             Share a folder
  magicpipes add --shell -- htop              Let people watch a program
  magicpipes add 5432 --tcp --allow-cidr 203.0.113.0/24
  magicpipes add 5432 --tcp --tag team:dev    No public port: they use `magicpipes connect`
  magicpipes add 22 --ssh --tag team:dev      Log in with `ssh -J`, with people sharing that tag
  magicpipes add 3389 --rdp --tag team:dev    A remote desktop in the browser, for people with that tag
  magicpipes add 5900 --vnc --tag team:dev    The same for a VNC server: Linux, a Mac, a Raspberry Pi
  magicpipes add 8006 --local-https --private An app that only speaks HTTPS, such as Proxmox's web UI

Run it again with other options to change a tunnel.")]
    Add {
        /// Local port of the application (TCP; UDP with --udp).
        port: Option<u16>,
        /// Forward to this Unix socket instead of a port (macOS and Linux). Connections reach it as
        /// you, so its file permissions don't apply to whoever opens the tunnel.
        #[arg(long, value_name = "PATH", conflicts_with_all = ["port", "host", "serve", "shell", "udp"])]
        unix: Option<PathBuf>,
        /// With --unix: publish a socket that usually hands over more than people mean to: Docker
        /// and other container engines, the system's services, your SSH or GPG agent, a terminal
        /// session or this agent itself.
        #[arg(long)]
        allow_sensitive_socket: bool,
        /// Publish a raw TCP port (tcp://host:port) instead of an HTTPS hostname: databases, SSH,
        /// game servers, anything that speaks TCP.
        #[arg(long, conflicts_with_all = ["serve", "shell", "udp"])]
        tcp: bool,
        /// Reach this machine's sshd through the server's SSH gateway (`ssh -J`). Always private:
        /// you, and people sharing a --tag with it, who then log in to sshd as usual.
        #[arg(long, conflicts_with_all = ["serve", "shell", "udp", "tcp", "unix", "public", "hostname", "no_verify"])]
        ssh: bool,
        /// Open this machine's (or --host's) Remote Desktop in the browser, from the server's
        /// management page. Always private: you, and people sharing a --tag with it, who then sign in
        /// to Windows as usual. Remote Desktop clients reach it with `magicpipes connect`.
        #[arg(long, conflicts_with_all = ["serve", "shell", "udp", "tcp", "ssh", "unix", "public", "hostname", "no_verify"])]
        rdp: bool,
        /// Open this machine's (or --host's) VNC server in the browser, from the server's
        /// management page. Always private: you, and people sharing a --tag with it, then the VNC
        /// server's own password if it has one. VNC viewers reach it with `magicpipes connect`.
        #[arg(long, conflicts_with_all = ["serve", "shell", "udp", "tcp", "ssh", "rdp", "unix", "public", "hostname", "no_verify"])]
        vnc: bool,
        /// Publish a UDP port (udp://host:port); datagrams go to the local UDP port.
        #[arg(long, conflicts_with_all = ["serve", "shell"])]
        udp: bool,
        /// With --tcp/--udp: ask for this public port (it must be in the server's range).
        #[arg(long, value_name = "PORT")]
        remote_port: Option<u16>,
        /// With --tcp/--udp: open a public port, for clients from this network only (CIDR or
        /// address; repeatable). A new public port needs this or --allow-any; re-adding without
        /// either keeps the list.
        #[arg(long = "allow-cidr", value_name = "CIDR", value_parser = parse_cidr)]
        allow_cidr: Vec<String>,
        /// With --tcp/--udp: open a public port to the whole internet, with only your service's own
        /// authentication in front of it.
        #[arg(long, conflicts_with = "allow_cidr")]
        allow_any: bool,
        /// Serve the files in DIR with the built-in web server instead of forwarding to a port.
        #[arg(long, value_name = "DIR", conflicts_with_all = ["port", "host", "shell"])]
        serve: Option<PathBuf>,
        /// With --serve: don't list directory contents (a directory's index.html is still served).
        /// Re-adding without --list or --no-list keeps the tunnel's setting.
        #[arg(long, conflicts_with = "list")]
        no_list: bool,
        /// With --serve: list directory contents (the default for a new tunnel).
        #[arg(long)]
        list: bool,
        /// With --serve: let pages run scripts, for a web app or site you trust. Without it, HTML and
        /// SVG files open with scripts turned off.
        #[arg(long)]
        site: bool,
        /// With --serve: publish a folder that holds more than people usually mean to share: the
        /// filesystem root, your home folder, a hidden folder in it, or this agent's own files.
        #[arg(long)]
        allow_sensitive_root: bool,
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
        /// Only you, and people sharing a --tag with it, can open it, after signing in. A private
        /// --tcp/--udp tunnel has no public port: people reach it with `magicpipes connect`. Default
        /// for machines enrolled once the server has user accounts.
        #[arg(long, conflicts_with_all = ["public", "remote_port", "allow_cidr", "allow_any"])]
        private: bool,
        /// Anyone with the address can open it (if this machine's enrollment allows it).
        #[arg(long, conflicts_with = "tags")]
        public: bool,
        /// With --private (implied): share it with people holding this tag (repeatable or
        /// comma-separated; only tags you hold).
        #[arg(long = "tag", value_name = "TAG", value_parser = parse_tag, value_delimiter = ',', conflicts_with_all = ["remote_port", "allow_cidr", "allow_any"])]
        tags: Vec<String>,
        /// Tunnel name (first label of the public hostname). Random if omitted.
        #[arg(long)]
        name: Option<String>,
        /// Serve it at this hostname instead of <name>.<base domain>. An administrator must have
        /// assigned the hostname to this machine (or to you), and its DNS must point at the server.
        #[arg(long, value_name = "HOSTNAME", conflicts_with_all = ["tcp", "udp"])]
        hostname: Option<String>,
        /// Register without waiting for the certificate or checking the public address, for
        /// example before DNS points here. The local service is still checked.
        #[arg(long)]
        no_verify: bool,
        /// Local host to connect to (default: 127.0.0.1, falling back to ::1).
        #[arg(long)]
        host: Option<String>,
        /// The app at <PORT> only speaks HTTPS (Proxmox, a NAS or a router's admin page): the agent
        /// connects with TLS, keeps the certificate the app shows now, and from then on reaches
        /// only an app showing that one. After it gets a new certificate, run the same command again.
        #[arg(long, conflicts_with_all = ["serve", "shell", "udp", "tcp", "ssh", "rdp", "vnc", "unix"])]
        local_https: bool,
        /// Path requested by the readiness probe.
        #[arg(long, default_value = "/")]
        probe_path: String,
        /// Overall timeout in seconds, including certificate issuance.
        #[arg(long, default_value_t = 120)]
        timeout: u64,
        #[command(flatten)]
        out: Output,
    },
    /// Reach a private TCP or UDP tunnel from this computer: listens here and passes each
    /// connection through the server, as you, until stopped.
    #[command(after_help = "Examples:
  magicpipes connect db                    Listen on a free local port, and print it
  magicpipes connect db --local 5432       Then: psql -h 127.0.0.1 -p 5432
  MAGICPIPES_API_TOKEN=tok_... magicpipes connect db --local 5432   In a script

The first time, it signs you in: approve it in a browser on this computer, or on any other
device with the address and code it prints. That lasts as long as a browser session.")]
    Connect {
        /// The tunnel's name.
        tunnel: String,
        /// Where to listen: a port, or address:port (default: a free port on 127.0.0.1).
        #[arg(long, value_name = "[ADDRESS:]PORT", value_parser = parse_local)]
        local: Option<std::net::SocketAddr>,
        /// The server's management URL (default: the server this machine is enrolled with).
        #[arg(long)]
        server: Option<String>,
        /// Extra CA certificate (PEM) to trust, e.g. the server's development CA.
        #[arg(long)]
        ca_cert: Option<PathBuf>,
        /// Don't open a browser to sign in; approve with the address and code shown, on any device.
        #[arg(long)]
        no_browser: bool,
        /// Connect with an API token from your account page instead of signing in, for scripts.
        /// Prefer the environment variable or --api-token-file, which other programs can't see.
        #[arg(long, env = "MAGICPIPES_API_TOKEN", hide_env_values = true)]
        api_token: Option<String>,
        /// Read the API token from this file.
        #[arg(long, value_name = "FILE", conflicts_with = "api_token")]
        api_token_file: Option<PathBuf>,
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
    let Command::Add { port, unix, allow_sensitive_socket, tcp, udp, ssh, rdp, vnc, remote_port, allow_cidr, allow_any, serve, no_list, list, site, allow_sensitive_root, shell, write, max_clients, command, .. } = cmd
    else {
        return;
    };
    let fail = |kind, msg: &str| {
        let mut cli = Cli::command();
        // Gives the subcommand's usage line its full name.
        cli.build();
        cli.find_subcommand_mut("add").expect("add subcommand").error(kind, msg).exit()
    };
    if port.is_none() && unix.is_none() && serve.is_none() && !shell {
        fail(ErrorKind::MissingRequiredArgument, "give a local <PORT>, --unix <PATH>, --serve <DIR> or --shell");
    }
    if *ssh && port.is_none() {
        fail(ErrorKind::MissingRequiredArgument, "--ssh needs the local port of sshd, usually: magicpipes add 22 --ssh");
    }
    if *rdp && port.is_none() {
        fail(ErrorKind::MissingRequiredArgument, "--rdp needs the port of Remote Desktop, usually: magicpipes add 3389 --rdp");
    }
    if *vnc && port.is_none() {
        fail(ErrorKind::MissingRequiredArgument, "--vnc needs the port of the VNC server, usually: magicpipes add 5900 --vnc");
    }
    if unix.is_none() && *allow_sensitive_socket {
        fail(ErrorKind::ArgumentConflict, "--allow-sensitive-socket can only be used with --unix");
    }
    if !shell && (*write || max_clients.is_some() || !command.is_empty()) {
        fail(ErrorKind::ArgumentConflict, "--write, --max-clients and a `-- <PROGRAM>` can only be used with --shell");
    }
    // Not clap's `requires`: it doesn't fire when the required flag conflicts with one that's given.
    if serve.is_none() && (*no_list || *list || *site || *allow_sensitive_root) {
        fail(ErrorKind::ArgumentConflict, "--no-list, --list, --site and --allow-sensitive-root can only be used with --serve");
    }
    if !tcp && !udp && (remote_port.is_some() || !allow_cidr.is_empty() || *allow_any) {
        fail(ErrorKind::ArgumentConflict, "--remote-port, --allow-cidr and --allow-any can only be used with --tcp or --udp");
    }
    if remote_port == &Some(0) {
        fail(ErrorKind::InvalidValue, "--remote-port must be between 1 and 65535");
    }
}

fn parse_tag(s: &str) -> Result<String, String> {
    magicpipes_core::tags::normalize(s)
}

fn parse_cidr(s: &str) -> Result<String, String> {
    magicpipes_core::cidr::Cidr::parse(s).map(|c| c.to_string())
}

/// `5432`, `0.0.0.0:5432` or `[::1]:5432`; a bare port is on 127.0.0.1.
fn parse_local(s: &str) -> Result<std::net::SocketAddr, String> {
    match s.parse::<u16>() {
        Ok(port) => Ok(std::net::SocketAddr::from(([127, 0, 0, 1], port))),
        Err(_) => s.parse().map_err(|_| format!("'{s}' isn't a port or address:port")),
    }
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
        Ok(agent::Start::Ran | agent::Start::Unwanted) => ExitCode::SUCCESS,
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
        Command::Login { server, token, token_file, browser, ca_cert, name, out } => (out, login(server, token, token_file, browser, ca_cert, name, out).await),
        Command::Add {
            port,
            unix,
            allow_sensitive_socket,
            tcp,
            udp,
            ssh,
            rdp,
            vnc,
            remote_port,
            allow_cidr,
            allow_any,
            serve,
            no_list,
            list,
            site,
            allow_sensitive_root,
            shell,
            write,
            max_clients,
            command,
            private,
            public,
            tags,
            name,
            hostname,
            no_verify,
            host,
            local_https,
            probe_path,
            timeout,
            out,
        } => {
            let visibility = match (private || !tags.is_empty(), public) {
                (true, _) => Some(Visibility::Private),
                (_, true) => Some(Visibility::Public),
                _ => None,
            };
            let kind = match (tcp, udp, ssh, rdp, vnc) {
                (true, ..) => Kind::Tcp,
                (_, true, ..) => Kind::Udp,
                (_, _, true, ..) => Kind::Ssh,
                (_, _, _, true, _) => Kind::Rdp,
                (.., true) => Kind::Vnc,
                _ => Kind::Http,
            };
            let req = AddRequest {
                port,
                unix,
                allow_sensitive_socket,
                kind,
                remote_port,
                allow: allow_cidr,
                allow_any,
                serve,
                list: !no_list,
                keep_list: !no_list && !list,
                site,
                allow_sensitive_root,
                shell: shell.then(|| if command.is_empty() { login_shell() } else { command }),
                cwd: None,
                writable: write,
                max_clients,
                host,
                local_https,
                name,
                probe_path,
                timeout_secs: timeout,
                visibility,
                tags,
                hostname,
                no_verify,
            };
            (out, add(req, out).await)
        }
        Command::Connect { tunnel, local, server, ca_cert, no_browser, api_token, api_token_file, out } => {
            let api_token = match api_token_file {
                Some(path) => std::fs::read_to_string(&path).map(Some).map_err(|e| ErrorInfo::new(ErrorCode::ConfigError, format!("reading {}: {e}", path.display()))),
                None => Ok(api_token),
            };
            let result = match api_token {
                Ok(api_token) => connect::run(connect::Options { tunnel, local, server, ca_cert, no_browser, api_token, json: out.json, quiet: out.quiet }).await,
                Err(e) => Err(e),
            };
            (out, result)
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

fn prompt_token() -> Result<String, ErrorInfo> {
    eprint!("Enrollment token: ");
    let _ = std::io::stderr().flush();
    let mut line = String::new();
    std::io::stdin().read_line(&mut line).map_err(|e| ErrorInfo::new(ErrorCode::ConfigError, e.to_string()))?;
    Ok(line)
}

/// Browser-approved login: asks the server for a code, opens its approval page and waits until
/// the user approves this machine there. Returns the enrollment token, or `None` if the server
/// predates this kind of login.
async fn browser_login(server: &str, tls: &Arc<rustls::ClientConfig>, agent_name: &str, quiet: bool) -> Result<Option<String>, ErrorInfo> {
    let s = connect::SignIn {
        start: "/api/v1/device",
        body: json!({ "agent_name": agent_name }),
        command: "login",
        ask: "To sign in, open this page and approve the machine:",
        refused: ErrorCode::InvalidEnrollmentToken,
    };
    let Some(resp) = connect::approve_in_browser(server, tls, s, true, quiet).await? else { return Ok(None) };
    let token = resp["enrollment_token"].as_str().ok_or_else(|| ErrorInfo::new(ErrorCode::Protocol, "unexpected answer to the login request"))?;
    Ok(Some(token.to_string()))
}

/// A failed attempt to reach the server, with what to try next.
fn unreachable_server(e: &anyhow::Error) -> ErrorInfo {
    let text = format!("{e:#}");
    let hint = if text.contains("UnknownIssuer") {
        " Its certificate isn't from an authority this machine trusts: for a private one, pass --ca-cert <file>."
    } else if text.contains("connecting to ") {
        " Check the server's URL and port, and that it's running."
    } else {
        ""
    };
    ErrorInfo::new(ErrorCode::ServerUnreachable, format!("{text}.{hint}"))
}

async fn login(
    server: String,
    token: Option<String>,
    token_file: Option<PathBuf>,
    browser: bool,
    ca_cert: Option<PathBuf>,
    name: Option<String>,
    out: Output,
) -> Result<(), ErrorInfo> {
    let server = server.trim().trim_end_matches('/').to_string();
    https::parse_server(&server).map_err(|e| ErrorInfo::new(ErrorCode::InvalidServer, e.to_string()))?;
    let ca_pem = match &ca_cert {
        Some(p) => Some(std::fs::read_to_string(p).map_err(|e| ErrorInfo::new(ErrorCode::ConfigError, format!("reading {}: {e}", p.display())))?),
        None => None,
    };
    let tls = https::tls_config(ca_pem.as_deref()).map_err(|e| ErrorInfo::new(ErrorCode::ConfigError, format!("{e:#}")))?;
    let agent_name = name.unwrap_or_else(platform::hostname);
    let interactive = std::io::stdin().is_terminal();
    let token = match &token_file {
        Some(path) => Some(std::fs::read_to_string(path).map_err(|e| ErrorInfo::new(ErrorCode::ConfigError, format!("reading {}: {e}", path.display())))?),
        None => token,
    };
    let token = match token {
        Some(t) => t,
        None if browser || interactive => match browser_login(&server, &tls, &agent_name, out.quiet).await? {
            Some(t) => t,
            // The server predates browser login.
            None if interactive => prompt_token()?,
            None => return Err(ErrorInfo::new(ErrorCode::ServerOutdated, "this server can't approve logins in the browser; pass --token")),
        },
        None => {
            return Err(ErrorInfo::new(
                ErrorCode::InvalidEnrollmentToken,
                "pass --token or set MAGICPIPES_TOKEN, or use --browser to approve this machine in your browser",
            ));
        }
    };
    let body = json!({ "enrollment_token": token.trim(), "agent_name": agent_name });
    let (status, resp) = https::post_json(&server, "/api/v1/enroll", &tls, &body)
        .await
        .map_err(|e| unreachable_server(&e))?;
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
        // Logging in again keeps how many connections were asked for.
        connections: AgentConfig::load().ok().flatten().and_then(|c| c.connections),
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
            StepState::Skipped => {
                let _ = writeln!(err, "skipped");
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
    if let Some(path) = &req.unix {
        if !platform::UNIX_SOCKETS {
            return Err(ErrorInfo::new(ErrorCode::Unsupported, "--unix needs macOS or Linux: Windows has no Unix socket support here yet"));
        }
        // Absolute, but with its links as they are: they may point somewhere new after a deploy.
        let abs = std::path::absolute(path).map_err(|e| ErrorInfo::new(ErrorCode::InvalidSocket, format!("cannot use {}: {e}", path.display())))?;
        if abs.to_str().is_none() {
            return Err(ErrorInfo::new(ErrorCode::InvalidSocket, format!("{} isn't valid UTF-8, which the agent needs its paths to be", abs.display())));
        }
        req.unix = Some(abs);
    }
    if req.shell.is_some() {
        let cwd = std::env::current_dir().and_then(std::fs::canonicalize);
        req.cwd = Some(cwd.map_err(|e| ErrorInfo::new(ErrorCode::InvalidCommand, format!("cannot use the current directory: {e}")))?);
    }
    let kind = req.kind;
    let serving = req.serve.clone();
    let listing = serving.is_some() && req.list;
    // Only worth a word if it's about a page people will actually open.
    let pages_without_scripts = !req.site && serving.as_ref().is_some_and(|dir| dir.join("index.html").is_file());
    let shell = req.shell.as_ref().map(|argv| (state::command_line(argv), req.writable, req.cwd.clone().unwrap_or_default()));
    let socket = req.unix.is_some();
    let spawned = client::ensure_agent().await?;
    if !spawned {
        client::check_agent_understands(&req).await?;
    }
    let local = if serving.is_some() {
        Some("Checking directory...")
    } else if shell.is_some() {
        Some("Checking program...")
    } else if socket {
        Some("Checking socket...")
    } else {
        None
    };
    let progress = Progress { enabled: !out.quiet, local };
    let result = client::request(&IpcRequest::Add(Box::new(req)), |s, st| progress.step(s, st)).await;
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
    let open_to_anyone = data["allow"].as_array().is_some_and(|a| a.is_empty());
    // A private TCP or UDP tunnel has no public port: its address is the command that reaches it.
    let by_command = kind.has_port() && data.get("public_port").is_none();
    if out.json {
        print_json(&data);
    } else {
        println!();
        println!("Tunnel ready");
        println!();
        let address = match kind {
            Kind::Ssh => "SSH:   ",
            Kind::Rdp | Kind::Vnc => "Desktop:",
            _ if by_command => "Reach: ",
            _ => "URL:   ",
        };
        println!("  {address} {}", data["share_url"].as_str().or(data["public_url"].as_str()).unwrap_or_default());
        match (&serving, &shell) {
            (Some(dir), _) => println!("  Serving: {}", state::display_path(dir)),
            (_, Some((cmd, writable, cwd))) => {
                println!("  Shell:  {cmd} ({})", if *writable { "read-write" } else { "read-only" });
                println!("  In:     {}", state::display_path(cwd));
            }
            // Lined up under the longer "Desktop:".
            _ if kind.is_desktop() => println!("  Local:   {}", data["target"].as_str().unwrap_or_default()),
            _ => println!("  Local:  {}", data["target"].as_str().unwrap_or_default()),
        }
        println!();
        let private = data["visibility"] == "private";
        match &shell {
            _ if private => {
                // `access`: the tags that let people in. `owner_tag` is the owner's personal tag;
                // other `user:` tags share it with one person each.
                let owner = data["owner_tag"].as_str();
                let tags: Vec<&str> = data["access"].as_array().into_iter().flatten().filter_map(|t| t.as_str()).collect();
                let mut who: Vec<String> = Vec::new();
                if owner.is_some_and(|o| tags.contains(&o)) {
                    who.push("you".into());
                }
                match tags.iter().filter(|t| t.starts_with("user:") && Some(**t) != owner).count() {
                    0 => {}
                    1 => who.push("1 other person".into()),
                    n => who.push(format!("{n} other people")),
                }
                let groups: Vec<&str> = tags.iter().copied().filter(|t| !t.starts_with("user:")).collect();
                if !groups.is_empty() {
                    who.push(format!("people with {}", groups.join(" or ")));
                }
                let who = if who.is_empty() { "nobody (give it a --tag)".to_string() } else { who.join(", ") };
                if kind == Kind::Ssh {
                    println!("Tunnel active in background. Private: only {who} can reach it, using an SSH key on an account.");
                } else if kind == Kind::Rdp {
                    println!("Tunnel active in background. Private: only {who} can open it, after signing in here and then to Windows.");
                    println!("Remote Desktop clients reach it with: magicpipes connect {}", data["name"].as_str().unwrap_or_default());
                } else if kind == Kind::Vnc {
                    println!("Tunnel active in background. Private: only {who} can open it, after signing in here, then to the VNC server if it asks.");
                    println!("VNC viewers reach it with: magicpipes connect {}", data["name"].as_str().unwrap_or_default());
                } else if by_command {
                    println!("Tunnel active in background. Private: only {who} can reach it, by running that command.");
                } else {
                    println!("Tunnel active in background. Private: only {who} can open it, after signing in.");
                }
            }
            Some((_, true, _)) => println!("Tunnel active in background. Anyone with this link can type into the terminal."),
            Some((_, false, _)) => println!("Tunnel active in background. Anyone with the URL can watch; each visitor gets their own copy."),
            None if kind.is_http() => println!("Tunnel active in background. Anyone with the URL can reach it."),
            None if open_to_anyone => println!("Tunnel active in background. Anyone who finds the port can connect."),
            None => println!("Tunnel active in background. Only the allowed networks can connect."),
        }
        if let Some(pin) = data["local_certificate"].as_str() {
            if data["replaced_certificate"].is_string() {
                println!("The app showed a new certificate, which is kept now instead of the old one (SHA-256 {pin}).");
            } else {
                println!("The app's certificate is kept, and only an app showing it is reached (SHA-256 {pin}).");
                println!("After the app gets a new certificate, run this command again.");
            }
        }
        if kind.is_http() && data["verified"] == false {
            println!("Not verified (--no-verify). Once its DNS points at the server, run the same command without --no-verify to check it.");
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
            eprintln!("Whoever runs the MagicPipes server can see it too, so only use --write through a server you trust.");
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
            if by_command {
                eprintln!("UDP cannot be verified end to end: datagrams sent through `{url}` now reach the local port.");
            } else {
                eprintln!("UDP cannot be verified end to end: datagrams to {url} now reach the local port.");
            }
        }
        if open_to_anyone {
            eprintln!();
            eprintln!("The port is open to the whole internet, and nothing but your service authenticates");
            eprintln!("clients. Use --allow-cidr to limit who can connect.");
        }
    }
    if socket && data["visibility"] != "private" && !out.quiet {
        eprintln!();
        eprintln!("Connections reach this socket as you. Its file permissions don't apply to them, and they get");
        eprintln!("anything the service behind it trusts your user for. Use --private to require signing in.");
    }
    if listing && !out.quiet {
        eprintln!();
        eprintln!("Directory listing is on: anyone with the URL can browse every non-hidden file in this directory.");
        eprintln!("Use --no-list to serve only files by exact path (and index.html).");
    }
    if pages_without_scripts && !out.quiet {
        eprintln!();
        eprintln!("Pages here open with scripts turned off. If this is a web app or a site you trust, add --site.");
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
                    // The same fields as a running agent's listing, from tunnels.json.
                    json!({ "id": t.id, "name": t.name, "kind": t.kind, "public_url": t.public_url, "target": t.describe(),
                            "share_url": t.share_url(), "status": "stopped", "error": null,
                            "created_at": magicpipes_core::rfc3339(t.created_at),
                            "visibility": t.visibility, "tags": t.tags })
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
        let width = |field: &str, heading: &str| tunnels.iter().map(|t| t[field].as_str().unwrap_or("").chars().count()).max().unwrap_or(0).max(heading.len());
        let (w, u, l) = (width("name", "NAME"), width("public_url", "URL"), width("target", "TARGET"));
        println!("{:<w$}  {:<u$}  {:<l$}  {:<7}  STATUS", "NAME", "URL", "TARGET", "ACCESS");
        for t in &tunnels {
            println!(
                "{:<w$}  {:<u$}  {:<l$}  {:<7}  {}",
                t["name"].as_str().unwrap_or(""),
                t["public_url"].as_str().unwrap_or(""),
                t["target"].as_str().unwrap_or(""),
                t["visibility"].as_str().unwrap_or("-"),
                t["status"].as_str().unwrap_or(""),
            );
        }
    }
    if data["agent_running"] == false {
        if matches!(AgentConfig::load(), Ok(Some(_))) {
            println!("\nThe agent is not running; start it with: magicpipes agent start");
        } else {
            println!("\nThis machine isn't enrolled yet; start with: magicpipes login --server <url>");
        }
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
        // Open connections to the server (older agents don't say).
        "connections": agent.as_ref().map(|a| a["connections"].clone()).unwrap_or(json!(0)),
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
            match a["connections"].as_u64() {
                Some(n) if n > 1 => println!("Connection: {} ({n} connections)", a["connection"].as_str().unwrap_or("")),
                _ => println!("Connection: {}", a["connection"].as_str().unwrap_or("")),
            }
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tags_can_be_repeated_or_comma_separated() {
        let tags = |args: &[&str]| {
            let line = ["magicpipes", "add", "8080"].iter().chain(args).copied();
            Cli::try_parse_from(line).map(|cli| match cli.command {
                Command::Add { tags, .. } => tags,
                _ => panic!("not add"),
            })
        };
        assert_eq!(tags(&["--tag", "team:dev,team:ops"]).unwrap(), ["team:dev", "team:ops"]);
        assert_eq!(tags(&["--tag", "team:dev", "--tag", "Team:Ops,qa"]).unwrap(), ["team:dev", "team:ops", "qa"]);
        assert_eq!(tags(&["--tag", "team:dev, team:ops"]).unwrap(), ["team:dev", "team:ops"], "a space after the comma, in quotes");
        // Each one is checked, and a stray comma is a mistake rather than nothing.
        assert!(tags(&["--tag", "team:dev,not valid"]).is_err());
        assert!(tags(&["--tag", "team:dev,"]).is_err());
    }

    #[test]
    fn failed_connections_say_what_to_try() {
        let message = |text: &str| unreachable_server(&anyhow::anyhow!(text.to_string())).message;
        assert!(message("TLS handshake with mp.example.com:443: invalid peer certificate: UnknownIssuer").contains("--ca-cert"));
        assert!(message("connecting to mp.example.com:443: Connection refused (os error 61)").contains("URL and port"));
        assert_eq!(message("the server answered 500"), "the server answered 500.");
    }
}
