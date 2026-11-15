//! Certificate authorities this server issues certificates from: one per `[[tls.authorities]]`
//! domain, for internal names and closed networks that Let's Encrypt can't serve, and the
//! development CA of `tls.mode = "dev-ca"`. A CA the server makes may only vouch for its domains
//! (an X.509 name constraint), so a device that trusts it trusts it for nothing else. One people
//! bring is checked at start: a CA, its key, still valid, and able to name the domain.

use std::path::{Path, PathBuf};

use anyhow::{Context, anyhow, bail};
use rcgen::{
    BasicConstraints, CertificateParams, DnType, ExtendedKeyUsagePurpose, GeneralSubtree, IsCa, Issuer, KeyPair, KeyUsagePurpose, NameConstraints, PublicKeyData,
};
use rustls_pki_types::CertificateDer;
use rustls_pki_types::pem::PemObject;
use sha2::{Digest, Sha256};

/// How long a certificate it issues is valid. They're issued again at every start and renewed
/// at two thirds, so short is free.
const LEAF_DAYS: i64 = 30;
/// How long a CA the server makes is valid: devices that trust it keep doing so this long.
const CA_YEARS: i64 = 10;

pub struct Authority {
    /// The domain it issues for (`exhub.internal`), or the server's own names for the dev CA.
    pub domain: String,
    issuer: Issuer<'static, KeyPair>,
    /// Its certificate and any above it, PEM: what each certificate it issues is followed by,
    /// and what devices install.
    pub chain_pem: String,
    /// Where its certificate is, when the server made it.
    pub made_at: Option<PathBuf>,
    pub not_after: i64,
    /// SHA-256 of its certificate, as devices show it (`AB:CD:…`).
    pub fingerprint: String,
}

impl Authority {
    /// The CA in `dir`, made first if there's none: valid for [`CA_YEARS`], called `common_name`,
    /// able to vouch only for `domains` and the names under them.
    pub fn load_or_create(dir: &Path, common_name: &str, domains: &[&str]) -> anyhow::Result<Self> {
        let mut builder = std::fs::DirBuilder::new();
        builder.recursive(true);
        #[cfg(unix)]
        std::os::unix::fs::DirBuilderExt::mode(&mut builder, 0o700);
        builder.create(dir).with_context(|| format!("creating {}", dir.display()))?;
        let (crt, key) = (dir.join("ca.crt"), dir.join("ca.key"));
        if !crt.exists() {
            let key_pair = KeyPair::generate()?;
            let mut params = CertificateParams::new(Vec::<String>::new())?;
            params.is_ca = IsCa::Ca(BasicConstraints::Constrained(0));
            params.distinguished_name.push(DnType::CommonName, common_name);
            params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
            params.name_constraints =
                Some(NameConstraints { permitted_subtrees: domains.iter().map(|d| GeneralSubtree::DnsName(d.to_string())).collect(), excluded_subtrees: Vec::new() });
            let now = time::OffsetDateTime::now_utc();
            params.not_before = now - time::Duration::hours(1);
            params.not_after = now + time::Duration::days(CA_YEARS * 365);
            let cert = params.self_signed(&key_pair)?;
            // The key first: a certificate without its key would be taken for a whole CA.
            super::write_private(&key, key_pair.serialize_pem().as_bytes())?;
            std::fs::write(&crt, cert.pem()).with_context(|| format!("writing {}", crt.display()))?;
            tracing::warn!(path = %crt.display(), domains = ?domains, "made a certificate authority; devices that should trust it need this certificate");
        }
        let mut ca = Self::load(&crt, &key, domains.first().copied().unwrap_or_default())?;
        ca.made_at = Some(crt);
        Ok(ca)
    }

    /// A CA people brought: `cert_file` holds its certificate first, then any above it.
    pub fn load(cert_file: &Path, key_file: &Path, domain: &str) -> anyhow::Result<Self> {
        let chain_pem = std::fs::read_to_string(cert_file).with_context(|| format!("reading {}", cert_file.display()))?;
        // Without the parser's words: they can quote a line of the key.
        let key_pem = std::fs::read_to_string(key_file).with_context(|| format!("reading {}", key_file.display()))?;
        let key_pair = KeyPair::from_pem(&key_pem).map_err(|_| anyhow!("{}: not a private key this server can use (PKCS#8 PEM, ECDSA P-256/P-384 or RSA)", key_file.display()))?;
        let der = CertificateDer::pem_slice_iter(chain_pem.as_bytes())
            .next()
            .ok_or_else(|| anyhow!("{}: no certificate in it", cert_file.display()))?
            .map_err(|e| anyhow!("{}: {e}", cert_file.display()))?;
        let (_, x509) = x509_parser::parse_x509_certificate(&der).map_err(|e| anyhow!("{}: {e}", cert_file.display()))?;
        if !x509.basic_constraints().ok().flatten().is_some_and(|b| b.value.ca) {
            bail!("{}: not a certificate authority (its basic constraints don't say CA)", cert_file.display());
        }
        if x509.key_usage().ok().flatten().is_some_and(|k| !k.value.key_cert_sign()) {
            bail!("{}: its key usage doesn't allow signing certificates", cert_file.display());
        }
        if x509.public_key().raw != key_pair.subject_public_key_info().as_slice() {
            bail!("{} isn't the key of {}", key_file.display(), cert_file.display());
        }
        let not_after = x509.validity().not_after.timestamp();
        if not_after <= magicpipes_core::unix_now() {
            bail!("{}: expired on {}", cert_file.display(), magicpipes_core::rfc3339(not_after));
        }
        if !domain.is_empty() && !permits(&x509, domain) {
            bail!("{}: its name constraints don't allow {domain}", cert_file.display());
        }
        let issuer = Issuer::from_ca_cert_der(&der, key_pair).map_err(|e| anyhow!("{}: {e}", cert_file.display()))?;
        let fingerprint = Sha256::digest(&der).iter().map(|b| format!("{b:02X}")).collect::<Vec<_>>().join(":");
        let chain_pem = if chain_pem.ends_with('\n') { chain_pem } else { chain_pem + "\n" };
        Ok(Self { domain: domain.to_string(), issuer, chain_pem, made_at: None, not_after, fingerprint })
    }

    /// A certificate and key for `host` (PEM), its chain ending with this CA's.
    pub fn issue(&self, host: &str) -> anyhow::Result<(String, String)> {
        let key = KeyPair::generate()?;
        let mut params = CertificateParams::new(vec![host.to_string()])?;
        params.distinguished_name.push(DnType::CommonName, host);
        // Apple's platforms refuse a server certificate without it.
        params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
        params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
        let now = time::OffsetDateTime::now_utc();
        params.not_before = now - time::Duration::hours(1);
        // Never past the CA's own end, which clients would refuse.
        let ca_end = time::OffsetDateTime::from_unix_timestamp(self.not_after).unwrap_or(now);
        params.not_after = (now + time::Duration::days(LEAF_DAYS)).min(ca_end);
        let cert = params.signed_by(&key, &self.issuer)?;
        Ok((cert.pem() + &self.chain_pem, key.serialize_pem()))
    }
}

/// Whether a CA's name constraints, if any, let it vouch for `domain`.
fn permits(x509: &x509_parser::certificate::X509Certificate<'_>, domain: &str) -> bool {
    use x509_parser::extensions::GeneralName;
    let Ok(Some(nc)) = x509.name_constraints() else { return true };
    let under = |base: &str| {
        let base = base.trim_start_matches('.').to_ascii_lowercase();
        domain == base || domain.strip_suffix(&base).is_some_and(|rest| rest.ends_with('.'))
    };
    let excluded = nc.value.excluded_subtrees.as_ref().is_some_and(|s| s.iter().any(|t| matches!(t.base, GeneralName::DNSName(b) if under(b))));
    let permitted = match &nc.value.permitted_subtrees {
        None => true,
        Some(s) => {
            let dns: Vec<&str> = s.iter().filter_map(|t| if let GeneralName::DNSName(b) = t.base { Some(b) } else { None }).collect();
            dns.is_empty() || dns.iter().any(|b| under(b))
        }
    };
    permitted && !excluded
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dir() -> PathBuf {
        let d = std::env::temp_dir().join(format!("mp-authority-{}", magicpipes_core::secret::random_string(8)));
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    #[test]
    fn a_made_ca_vouches_only_for_its_domain_and_is_kept() {
        let d = dir();
        let ca = Authority::load_or_create(&d.join("exhub.internal"), "MagicPipes CA for exhub.internal", &["exhub.internal"]).unwrap();
        let again = Authority::load_or_create(&d.join("exhub.internal"), "MagicPipes CA for exhub.internal", &["exhub.internal"]).unwrap();
        assert_eq!(ca.fingerprint, again.fingerprint, "made once");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(std::fs::metadata(d.join("exhub.internal/ca.key")).unwrap().permissions().mode() & 0o777, 0o600);
        }
        let ca_der = CertificateDer::pem_slice_iter(ca.chain_pem.as_bytes()).next().unwrap().unwrap();
        let (_, x509) = x509_parser::parse_x509_certificate(&ca_der).unwrap();
        assert!(permits(&x509, "exhub.internal") && permits(&x509, "a.exhub.internal"));
        assert!(!permits(&x509, "example.com") && !permits(&x509, "notexhub.internal"));
        let years = (ca.not_after - magicpipes_core::unix_now()) / (365 * 86_400);
        assert!((9..=10).contains(&years), "{years}");

        let (chain, key) = ca.issue("tunnel.exhub.internal").unwrap();
        let loaded = super::super::load_pem(chain.as_bytes(), key.as_bytes()).unwrap();
        assert_eq!(loaded.names, ["tunnel.exhub.internal"]);
        assert!(loaded.not_after - loaded.not_before <= (LEAF_DAYS + 1) * 86_400);
        assert!(chain.ends_with(&ca.chain_pem), "the chain ends with the CA");
        std::fs::remove_dir_all(d).ok();
    }

    #[test]
    fn a_brought_ca_must_be_a_ca_with_its_key_and_allow_the_domain() {
        let d = dir();
        let made = Authority::load_or_create(&d.join("a"), "test", &["exhub.internal"]).unwrap();
        let (crt, key) = (d.join("a/ca.crt"), d.join("a/ca.key"));
        assert_eq!(Authority::load(&crt, &key, "exhub.internal").unwrap().fingerprint, made.fingerprint);
        let refused = |c: &Path, k: &Path, domain: &str| Authority::load(c, k, domain).err().map(|e| e.to_string()).unwrap_or_default();
        assert!(refused(&crt, &key, "example.com").contains("name constraints"));
        let other = Authority::load_or_create(&d.join("b"), "other", &["exhub.internal"]).unwrap();
        assert!(!other.fingerprint.is_empty());
        assert!(refused(&crt, &d.join("b/ca.key"), "exhub.internal").contains("isn't the key"));
        // A certificate that isn't a CA's.
        let (leaf, leaf_key) = made.issue("x.exhub.internal").unwrap();
        std::fs::write(d.join("leaf.crt"), &leaf).unwrap();
        std::fs::write(d.join("leaf.key"), &leaf_key).unwrap();
        assert!(refused(&d.join("leaf.crt"), &d.join("leaf.key"), "exhub.internal").contains("not a certificate authority"));
        std::fs::write(d.join("garbage.key"), "-----BEGIN PRIVATE KEY-----\nnot a key\n-----END PRIVATE KEY-----\n").unwrap();
        let said = refused(&crt, &d.join("garbage.key"), "exhub.internal");
        assert!(said.contains("not a private key") && !said.contains("not a key\n"), "{said}");
        std::fs::remove_dir_all(d).ok();
    }
}
