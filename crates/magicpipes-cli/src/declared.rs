//! Tunnels declared for `magicpipes agent run`, for containers: in `MAGICPIPES_TUNNELS`, or a file
//! named by `MAGICPIPES_TUNNELS_FILE` (a Kubernetes ConfigMap, say), or both. One tunnel a line,
//! written as the arguments of `magicpipes add`, so there's nothing new to learn and the same rules
//! check them:
//!
//! ```text
//! # The shop, for everyone; its admin pages, for the team.
//! 8080 --name shop --public
//! 8081 --name shop-admin --tag team:ops
//! ```
//!
//! Words split as a shell would split them, quotes and backslashes included. Each tunnel needs a
//! `--name` or `--hostname`, so it keeps its address when the agent starts again. The agent then
//! serves exactly these (`agent::declared`).

use std::io::Read;
use std::path::Path;

use clap::Parser;

use crate::ipc::AddRequest;
use crate::{Cli, add_args_problem, add_request, resolve_paths};

pub const TUNNELS_ENV: &str = "MAGICPIPES_TUNNELS";
pub const TUNNELS_FILE_ENV: &str = "MAGICPIPES_TUNNELS_FILE";
/// Tunnels one agent can be told to serve this way; each is a task trying until it works.
const MAX_DECLARED: usize = 100;
/// A file bigger than this is a mistake, not a list of tunnels.
const MAX_FILE: u64 = 256 * 1024;

/// A declared tunnel.
#[derive(Debug, Clone)]
pub struct Declared {
    /// Its `--name`, or its `--hostname`: how it's told apart and spoken of.
    pub label: String,
    pub req: AddRequest,
}

/// The declared tunnels, or `None` when nothing declares any: the agent then serves what `add`
/// gave it, as always. An error names the line.
pub fn from_env() -> Result<Option<Vec<Declared>>, String> {
    let mut sources = Vec::new();
    if let Some(text) = std::env::var_os(TUNNELS_ENV) {
        let text = text.into_string().map_err(|_| format!("{TUNNELS_ENV} isn't valid UTF-8"))?;
        sources.push((TUNNELS_ENV.to_string(), text));
    }
    if let Some(path) = std::env::var_os(TUNNELS_FILE_ENV) {
        let path = Path::new(&path);
        sources.push((path.display().to_string(), read_file(path)?));
    }
    if sources.is_empty() {
        return Ok(None);
    }
    let mut all: Vec<Declared> = Vec::new();
    for (source, text) in &sources {
        for d in parse(text, source)? {
            if all.iter().any(|a| a.label == d.label) {
                return Err(format!("{source}: '{}' is declared twice", d.label));
            }
            all.push(d);
        }
    }
    if all.len() > MAX_DECLARED {
        return Err(format!("{} tunnels are declared; one agent serves at most {MAX_DECLARED} this way", all.len()));
    }
    Ok(Some(all))
}

fn read_file(path: &Path) -> Result<String, String> {
    let file = std::fs::File::open(path).map_err(|e| format!("reading {}: {e}", path.display()))?;
    let mut text = String::new();
    file.take(MAX_FILE + 1).read_to_string(&mut text).map_err(|e| format!("reading {}: {e}", path.display()))?;
    if text.len() as u64 > MAX_FILE {
        return Err(format!("{} is bigger than {} KiB", path.display(), MAX_FILE / 1024));
    }
    Ok(text)
}

/// The tunnels in `text`; `source` says where it came from, for errors.
pub fn parse(text: &str, source: &str) -> Result<Vec<Declared>, String> {
    let mut out = Vec::new();
    for (n, line) in text.lines().enumerate() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let at = |msg: &str| format!("{source}, line {}: {msg}", n + 1);
        let words = words(line).map_err(|m| at(&m))?;
        let args = ["magicpipes", "add"].into_iter().map(String::from).chain(words);
        let cli = Cli::try_parse_from(args).map_err(|e| at(&clap_message(&e)))?;
        if let Some((_, msg)) = add_args_problem(&cli.command) {
            return Err(at(msg));
        }
        let (mut req, _) = add_request(cli.command).ok_or_else(|| at("not a tunnel"))?;
        let label = match (&req.name, &req.hostname) {
            (Some(name), _) => name.clone(),
            (None, Some(hostname)) => hostname.trim().trim_end_matches('.').to_ascii_lowercase(),
            (None, None) => return Err(at("give it a --name or --hostname, so it keeps its address when the agent starts again")),
        };
        resolve_paths(&mut req).map_err(|e| at(&e.message))?;
        out.push(Declared { label, req });
    }
    Ok(out)
}

/// clap's error without its usage lines: `unexpected argument '--fast' found`.
fn clap_message(e: &clap::Error) -> String {
    let text = e.render().to_string();
    let first = text.lines().next().unwrap_or("not valid arguments for add");
    first.strip_prefix("error: ").unwrap_or(first).to_string()
}

/// A line split into words as a POSIX shell would: whitespace between words, single quotes taken
/// literally, double quotes and backslashes as in `sh`. No variables, globs or substitutions.
fn words(line: &str) -> Result<Vec<String>, String> {
    let mut out = Vec::new();
    let mut word = String::new();
    let mut in_word = false;
    let mut chars = line.chars();
    while let Some(c) = chars.next() {
        match c {
            c if c.is_whitespace() => {
                if in_word {
                    out.push(std::mem::take(&mut word));
                    in_word = false;
                }
            }
            '\'' => {
                in_word = true;
                loop {
                    match chars.next() {
                        Some('\'') => break,
                        Some(c) => word.push(c),
                        None => return Err("a ' isn't closed".into()),
                    }
                }
            }
            '"' => {
                in_word = true;
                loop {
                    match chars.next() {
                        Some('"') => break,
                        // Inside double quotes a backslash only escapes these.
                        Some('\\') => match chars.next() {
                            Some(c @ ('"' | '\\' | '$' | '`')) => word.push(c),
                            Some(c) => {
                                word.push('\\');
                                word.push(c);
                            }
                            None => return Err("a \" isn't closed".into()),
                        },
                        Some(c) => word.push(c),
                        None => return Err("a \" isn't closed".into()),
                    }
                }
            }
            '\\' => {
                in_word = true;
                match chars.next() {
                    Some(c) => word.push(c),
                    None => return Err("the line ends in a \\".into()),
                }
            }
            c => {
                in_word = true;
                word.push(c);
            }
        }
    }
    if in_word {
        out.push(word);
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use magicpipes_core::proto::{Kind, Visibility};

    #[test]
    fn words_split_as_a_shell_splits_them() {
        let split = |s: &str| words(s).unwrap();
        assert_eq!(split("  8080   --name shop "), ["8080", "--name", "shop"]);
        assert_eq!(split(r#"--shell -- sh -c 'echo "hi there"'"#), ["--shell", "--", "sh", "-c", r#"echo "hi there""#]);
        assert_eq!(split(r#"--serve "/srv/my files" a\ b "q\"x\n""#), ["--serve", "/srv/my files", "a b", "q\"x\\n"]);
        assert_eq!(split("''"), [""], "an empty word is a word");
        for bad in ["'open", "\"open", "ends\\"] {
            assert!(words(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn lines_are_add_commands_with_a_name() {
        let text = "# the shop\n\n8080 --name shop --public\n  5432 --tcp --tag team:db --name db  \n9000 --hostname Shop.Example.com.\n";
        let got = parse(text, "MAGICPIPES_TUNNELS").unwrap();
        assert_eq!(got.iter().map(|d| d.label.as_str()).collect::<Vec<_>>(), ["shop", "db", "shop.example.com"]);
        assert_eq!((got[0].req.port, got[0].req.kind, got[0].req.visibility), (Some(8080), Kind::Http, Some(Visibility::Public)));
        assert_eq!((got[1].req.kind, got[1].req.visibility, got[1].req.tags.clone()), (Kind::Tcp, Some(Visibility::Private), vec!["team:db".to_string()]));
        assert_eq!(got[0].req.probe_path, "/", "add's defaults");

        let err = |text: &str| parse(text, "tunnels.txt").unwrap_err();
        assert_eq!(err("8080 --public"), "tunnels.txt, line 1: give it a --name or --hostname, so it keeps its address when the agent starts again");
        assert!(err("\n8080 --name a --fast").starts_with("tunnels.txt, line 2: unexpected argument '--fast'"), "{}", err("\n8080 --name a --fast"));
        assert_eq!(err("--name a"), "tunnels.txt, line 1: give a local <PORT>, --unix <PATH>, --serve <DIR> or --shell");
        assert_eq!(err("8080 --name a --allow-any"), "tunnels.txt, line 1: --remote-port, --allow-cidr and --allow-any can only be used with --tcp or --udp");
        assert!(err("8080 --name 'a").contains("isn't closed"));
        assert!(err("--serve /no/such/dir --name a").starts_with("tunnels.txt, line 1: cannot serve /no/such/dir"));
    }
}
