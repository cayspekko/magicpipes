//! A local certificate authority for development and automated tests (`tls.mode = "dev-ca"`).
//! Clients must trust `data_dir/dev-ca/ca.crt` explicitly.

use std::path::{Path, PathBuf};

use super::authority::Authority;

pub struct DevCa {
    dir: PathBuf,
    ca: Authority,
}

impl DevCa {
    /// A new CA may only vouch for `domains` and their subdomains (an X.509 name constraint), so
    /// trusting it for development cannot expose other sites. CAs created by older versions
    /// have no constraint; delete `dev-ca/` to get a new one.
    pub fn load_or_create(dir: &Path, domains: &[&str]) -> anyhow::Result<Self> {
        let ca = Authority::load_or_create(dir, "MagicPipes Development CA", domains)?;
        Ok(Self { dir: dir.to_path_buf(), ca })
    }

    pub fn ca_path(&self) -> PathBuf {
        self.dir.join("ca.crt")
    }

    pub fn issue(&self, host: &str) -> anyhow::Result<(String, String)> {
        self.ca.issue(host)
    }
}
