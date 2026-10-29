//! A local certificate authority for development and automated tests (`tls.mode = "dev-ca"`).
//! Clients must trust `data_dir/dev-ca/ca.crt` explicitly.

use std::path::{Path, PathBuf};

use anyhow::Context;
use rcgen::{BasicConstraints, CertificateParams, DnType, IsCa, Issuer, KeyPair, KeyUsagePurpose};

pub struct DevCa {
    dir: PathBuf,
    issuer: Issuer<'static, KeyPair>,
}

impl DevCa {
    pub fn load_or_create(dir: &Path) -> anyhow::Result<Self> {
        std::fs::create_dir_all(dir)?;
        let (crt, key) = (dir.join("ca.crt"), dir.join("ca.key"));
        if !crt.exists() {
            let key_pair = KeyPair::generate()?;
            let mut params = CertificateParams::new(Vec::<String>::new())?;
            params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
            params.distinguished_name.push(DnType::CommonName, "MagicPipes Development CA");
            params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
            let cert = params.self_signed(&key_pair)?;
            super::write_private(&key, key_pair.serialize_pem().as_bytes())?;
            std::fs::write(&crt, cert.pem())?;
            tracing::warn!(path = %crt.display(), "created development CA (not for production use)");
        }
        let key_pair = KeyPair::from_pem(&std::fs::read_to_string(&key).context("reading dev CA key")?)?;
        let issuer = Issuer::from_ca_cert_pem(&std::fs::read_to_string(&crt).context("reading dev CA cert")?, key_pair)?;
        Ok(Self { dir: dir.to_path_buf(), issuer })
    }

    pub fn ca_path(&self) -> PathBuf {
        self.dir.join("ca.crt")
    }

    pub fn issue(&self, host: &str) -> anyhow::Result<(String, String)> {
        let key = KeyPair::generate()?;
        let mut params = CertificateParams::new(vec![host.to_string()])?;
        params.distinguished_name.push(DnType::CommonName, host);
        let now = time::OffsetDateTime::now_utc();
        params.not_before = now - time::Duration::hours(1);
        params.not_after = now + time::Duration::days(30);
        let cert = params.signed_by(&key, &self.issuer)?;
        let mut chain = cert.pem();
        chain.push_str(&std::fs::read_to_string(self.ca_path())?);
        Ok((chain, key.serialize_pem()))
    }
}
