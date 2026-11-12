//! Sending email through the mail server in `[smtp]` or on the Settings page, and what the messages
//! say. Who gets one, and how many, is decided in `control::email`.
//!
//! A code in a link goes in the fragment, which never reaches a server: not this one's logs, a proxy's
//! or a mail scanner's. The page puts it in its form, and without scripts it can be pasted, so each
//! message gives it on its own line as well. Messages are plain text, built from values this server
//! controls; `lettre` encodes the headers.

use std::path::Path;
use std::time::Duration;

use anyhow::{Context, anyhow};
use lettre::message::Mailbox;
use lettre::message::header::ContentType;
use lettre::transport::smtp::authentication::Credentials;
use lettre::transport::smtp::client::{Certificate, Tls, TlsParameters};
use lettre::transport::smtp::extension::ClientId;
use lettre::{AsyncSmtpTransport, AsyncTransport, Message, Tokio1Executor};
use magicpipes_core::secret;

use crate::config::{SmtpConfig, SmtpTls};

/// One step of the conversation with the mail server.
const STEP_TIMEOUT: Duration = Duration::from_secs(8);
/// All of a message. Fits in the management listener's request deadline, so someone waiting on a
/// page gets the reason, not a timeout.
const SEND_TIMEOUT: Duration = Duration::from_secs(12);

/// A connection's worth of settings; a connection is made per message, since there are few.
pub struct Mailer {
    transport: AsyncSmtpTransport<Tokio1Executor>,
    from: Mailbox,
    /// This server's name, which it greets the mail server with and puts in message ids.
    hostname: String,
}

impl Mailer {
    /// Reads the password from its file.
    pub fn load(cfg: &SmtpConfig, hostname: &str) -> anyhow::Result<Self> {
        let password = match &cfg.password_file {
            Some(path) => Some(read_password(path)?),
            None => None,
        };
        Self::new(cfg, password, hostname)
    }

    pub fn new(cfg: &SmtpConfig, password: Option<String>, hostname: &str) -> anyhow::Result<Self> {
        cfg.check().map_err(|m| anyhow!(m))?;
        let host = cfg.host.trim();
        let tls = match cfg.tls_mode() {
            SmtpTls::Starttls => Tls::Required(tls_parameters(cfg)?),
            SmtpTls::Implicit => Tls::Wrapper(tls_parameters(cfg)?),
            SmtpTls::None => Tls::None,
        };
        let mut builder = AsyncSmtpTransport::<Tokio1Executor>::builder_dangerous(host)
            .port(cfg.port_number())
            .tls(tls)
            .timeout(Some(STEP_TIMEOUT))
            // Not this machine's own name, which says nothing to anyone else.
            .hello_name(ClientId::Domain(hostname.to_string()));
        if let (Some(username), Some(password)) = (&cfg.username, password) {
            builder = builder.credentials(Credentials::new(username.trim().to_string(), password));
        }
        let from = cfg.from.parse().with_context(|| format!("'{}' is not an address to send from", cfg.from))?;
        Ok(Self { transport: builder.build(), from, hostname: hostname.to_string() })
    }

    /// Connects, starts TLS and signs in, without sending anything.
    pub async fn check(&self) -> anyhow::Result<()> {
        match tokio::time::timeout(SEND_TIMEOUT, self.transport.test_connection()).await {
            Ok(Ok(true)) => Ok(()),
            Ok(Ok(false)) => Err(anyhow!("the mail server didn't answer as expected")),
            Ok(Err(e)) => Err(said(e)),
            Err(_) => Err(anyhow!("the mail server took too long to answer")),
        }
    }

    pub async fn send(&self, to: &str, mail: &Mail) -> anyhow::Result<()> {
        let to: Mailbox = to.parse().context("that address can't receive email")?;
        let message = Message::builder()
            .from(self.from.clone())
            .to(to)
            .subject(mail.subject.as_str())
            .message_id(Some(format!("<{}@{}>", secret::random_string(24), self.hostname)))
            .header(ContentType::TEXT_PLAIN)
            .body(mail.body.clone())
            .context("building the message")?;
        match tokio::time::timeout(SEND_TIMEOUT, self.transport.send(message)).await {
            Ok(Ok(_)) => Ok(()),
            Ok(Err(e)) => Err(said(e)),
            Err(_) => Err(anyhow!("the mail server took too long to answer")),
        }
    }
}

/// What went wrong, once: `lettre`'s message already includes its cause.
fn said(e: lettre::transport::smtp::Error) -> anyhow::Error {
    anyhow!("{e}")
}

fn read_password(path: &Path) -> anyhow::Result<String> {
    let text = std::fs::read_to_string(path).with_context(|| format!("reading the password in {}", path.display()))?;
    let password = text.trim();
    if password.is_empty() {
        anyhow::bail!("{} is empty", path.display());
    }
    Ok(password.to_string())
}

fn tls_parameters(cfg: &SmtpConfig) -> anyhow::Result<TlsParameters> {
    let mut builder = TlsParameters::builder(cfg.host.trim().to_string());
    if let Some(path) = &cfg.ca_file {
        let pem = std::fs::read(path).with_context(|| format!("reading {}", path.display()))?;
        builder = builder.add_root_certificate(Certificate::from_pem(&pem).with_context(|| format!("reading the certificate in {}", path.display()))?);
    }
    builder.build_rustls().context("setting up TLS")
}

/// A message, ready to send.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Mail {
    pub subject: String,
    pub body: String,
}

fn host(server: &str) -> &str {
    server.strip_prefix("https://").unwrap_or(server)
}

/// Where a code goes: the link, and the code itself for a page without scripts.
fn with_code(server: &str, path: &str, code: &str) -> String {
    format!("{server}{path}#code={code}\n\nIf the page asks for a code, it's:\n{code}")
}

pub fn invitation(server: &str, inviter: &str, code: &str, days: i64) -> Mail {
    Mail {
        subject: format!("You're invited to MagicPipes at {}", host(server)),
        body: format!(
            "{inviter} invited you to MagicPipes at {host}.\n\nAccept the invitation here:\n{link}\n\nThe link works once, for {days} days. If you weren't expecting this, you can ignore it.\n",
            host = host(server),
            link = with_code(server, "/invite", code),
        ),
    }
}

pub fn sign_in_link(server: &str, code: &str, minutes: i64) -> Mail {
    Mail {
        subject: "Your MagicPipes sign-in link".to_string(),
        body: format!(
            "Someone asked to sign in to MagicPipes at {host} with this address.\n\nSign in here:\n{link}\n\nThe link works once, for {minutes} minutes. If that wasn't you, you can ignore it: nobody gets in without it.\n",
            host = host(server),
            link = with_code(server, "/login/link", code),
        ),
    }
}

pub fn confirm_address(server: &str, code: &str, hours: i64) -> Mail {
    Mail {
        subject: "Confirm your address for MagicPipes".to_string(),
        body: format!(
            "Confirm this address for your account at {host}, while signed in to it:\n{link}\n\nThe link works once, for {hours} hours. If you didn't ask for this, you can ignore it.\n",
            host = host(server),
            link = with_code(server, "/account/address/confirm", code),
        ),
    }
}

/// One change in an alert digest.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AlertLine {
    /// `Opened`, `Worse` or `Closed`.
    pub word: &'static str,
    /// When, as `14:05 UTC`.
    pub at: String,
    pub title: &'static str,
    /// The machine, tunnel or hostname.
    pub name: String,
    pub detail: String,
    pub link: Option<String>,
}

/// What changed with someone's alerts since their last message. `more`: changes left out.
pub fn alert_digest(server: &str, lines: &[AlertLine], more: usize) -> Mail {
    let subject = match lines {
        [one] if more == 0 => format!("{}: {}, {}", one.word, one.title, one.name),
        _ => {
            let count = |word: &str| lines.iter().filter(|l| l.word == word).count();
            let parts: Vec<String> = [("Opened", "opened"), ("Worse", "got worse"), ("Closed", "closed")]
                .iter()
                .filter_map(|(word, said)| Some(count(word)).filter(|n| *n > 0).map(|n| format!("{n} {said}")))
                .collect();
            format!("MagicPipes alerts: {}", parts.join(", "))
        }
    };
    let mut body = format!("At {}:\n", host(server));
    for l in lines {
        body.push_str(&format!("\n{} {}: {}, {}\n  {}\n", l.word, l.at, l.title, l.name, l.detail));
        if let Some(link) = &l.link {
            body.push_str(&format!("  {link}\n"));
        }
    }
    if more > 0 {
        body.push_str(&format!("\nAnd {more} more.\n"));
    }
    body.push_str(&format!("\nOpen alerts: {server}/health\nTo change what you get, or stop: {server}/account#alerts\n"));
    Mail { subject, body }
}

/// To someone whose account was disabled for going without a single sign-on, which stopped their
/// machines.
pub fn account_disabled(server: &str, days: u64) -> Mail {
    Mail {
        subject: "Your MagicPipes account was disabled".to_string(),
        body: format!(
            "Your account at {host} hasn't been signed in to for {days} days, so it was disabled and your machines stopped serving tunnels.\n\nSign in to enable it again, and your machines start serving again by themselves:\n{server}/login\n\nIf you no longer use it, there's nothing to do.\n",
            host = host(server),
        ),
    }
}

pub fn test_message(server: &str) -> Mail {
    Mail {
        subject: "MagicPipes test message".to_string(),
        body: format!("An administrator sent this from the Settings page at {}, so email works.\n", host(server)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn config(text: &str) -> SmtpConfig {
        toml::from_str(text).unwrap()
    }

    #[test]
    fn the_port_says_how_to_connect_unless_told_otherwise() {
        let base = "host = \"m.example.com\"\nfrom = \"a@example.com\"\n";
        let modes = |extra: &str| {
            let c = config(&format!("{base}{extra}"));
            (c.tls_mode(), c.port_number())
        };
        assert_eq!(modes(""), (SmtpTls::Starttls, 587));
        assert_eq!(modes("port = 465\n"), (SmtpTls::Implicit, 465));
        assert_eq!(modes("port = 2525\n"), (SmtpTls::Starttls, 2525));
        assert_eq!(modes("tls = \"implicit\"\n"), (SmtpTls::Implicit, 465));
        assert_eq!(modes("tls = \"none\"\n"), (SmtpTls::None, 25));
        assert_eq!(modes("tls = \"starttls\"\nport = 465\n"), (SmtpTls::Starttls, 465));
    }

    #[test]
    fn settings_that_cannot_work_are_refused() {
        let base = "host = \"m.example.com\"\nfrom = \"MagicPipes <a@example.com>\"\n";
        assert_eq!(config(base).check(), Ok(()));
        assert_eq!(config(&format!("{base}username = \"u\"\npassword_file = \"/p\"\n")).check(), Ok(()));
        assert_eq!(config(&format!("{base}tls = \"none\"\n")).check(), Ok(()), "a relay nobody signs in to");
        for bad in [
            "host = \"\"\nfrom = \"a@example.com\"\n".to_string(),
            "host = \"a b\"\nfrom = \"a@example.com\"\n".to_string(),
            "host = \"m.example.com\"\nfrom = \"nobody\"\n".to_string(),
            format!("{base}port = 0\n"),
            format!("{base}username = \"u\"\n"),
            format!("{base}password_file = \"/p\"\n"),
            format!("{base}username = \" \"\npassword_file = \"/p\"\n"),
            format!("{base}tls = \"none\"\nusername = \"u\"\npassword_file = \"/p\"\n"),
        ] {
            assert!(config(&bad).check().is_err(), "{bad}");
        }
    }

    #[test]
    fn a_missing_password_or_certificate_is_an_error_not_a_quiet_way_in() {
        let c = config("host = \"m.example.com\"\nfrom = \"a@example.com\"\nusername = \"u\"\npassword_file = \"/no/such/file\"\n");
        assert!(format!("{:#}", Mailer::load(&c, "mp.example.com").err().unwrap()).contains("/no/such/file"));
        let c = config("host = \"m.example.com\"\nfrom = \"a@example.com\"\nca_file = \"/no/such/file\"\n");
        assert!(format!("{:#}", Mailer::load(&c, "mp.example.com").err().unwrap()).contains("/no/such/file"));
        assert!(Mailer::load(&config("host = \"m.example.com\"\nfrom = \"a@example.com\"\n"), "mp.example.com").is_ok());
    }

    #[test]
    fn a_code_goes_in_the_fragment_and_on_its_own_line() {
        let server = "https://mp.example.com:8443";
        for (mail, link) in [
            (invitation(server, "ann@example.com", "mpi_abc", 7), "https://mp.example.com:8443/invite#code=mpi_abc\n"),
            (sign_in_link(server, "mpi_abc", 15), "https://mp.example.com:8443/login/link#code=mpi_abc\n"),
            (confirm_address(server, "mpi_abc", 24), "https://mp.example.com:8443/account/address/confirm#code=mpi_abc\n"),
        ] {
            assert!(mail.body.contains(link), "{}", mail.body);
            assert!(mail.body.contains("\nmpi_abc\n"), "{}", mail.body);
            assert!(!mail.body.contains("?"), "nothing in a query string: {}", mail.body);
            assert!(!mail.subject.contains("mpi_abc"));
        }
        assert!(invitation(server, "ann@example.com", "c", 7).body.starts_with("ann@example.com invited you to MagicPipes at mp.example.com:8443."));
    }

    #[test]
    fn an_alert_digest_lists_what_changed() {
        let line = |word, title, name: &str, link: Option<&str>| AlertLine {
            word,
            at: "14:05 UTC".into(),
            title,
            name: name.into(),
            detail: "Offline since 14:03 UTC.".into(),
            link: link.map(str::to_string),
        };
        let server = "https://mp.example.com";
        let one = alert_digest(server, &[line("Opened", "Offline", "studio-mac", Some("https://mp.example.com/machines/ag_1"))], 0);
        assert_eq!(one.subject, "Opened: Offline, studio-mac");
        assert!(one.body.starts_with("At mp.example.com:\n\nOpened 14:05 UTC: Offline, studio-mac\n  Offline since 14:03 UTC.\n  https://mp.example.com/machines/ag_1\n"), "{}", one.body);
        assert!(one.body.ends_with("To change what you get, or stop: https://mp.example.com/account#alerts\n"));
        let several = alert_digest(server, &[line("Opened", "Offline", "a", None), line("Opened", "Check failing", "b", None), line("Closed", "Offline", "c", None)], 4);
        assert_eq!(several.subject, "MagicPipes alerts: 2 opened, 1 closed");
        assert!(several.body.contains("\nAnd 4 more.\n"));
    }

    /// `lettre` should keep these out of the headers whatever a message says.
    #[test]
    fn a_message_is_built_with_its_headers_encoded() {
        let c = config("host = \"m.example.com\"\nfrom = \"MagicPipes <a@example.com>\"\n");
        let mailer = Mailer::load(&c, "mp.example.com").unwrap();
        assert!("victim@example.com\r\nBcc: other@example.com".parse::<Mailbox>().is_err());
        let message = Message::builder()
            .from(mailer.from.clone())
            .to("b@example.com".parse().unwrap())
            .subject("line one\r\nBcc: other@example.com")
            .body("hello".to_string())
            .unwrap();
        let text = String::from_utf8(message.formatted()).unwrap();
        assert!(!text.lines().any(|l| l.starts_with("Bcc:")), "{text}");
    }
}
