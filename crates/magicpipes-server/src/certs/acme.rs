//! ACME (RFC 8555) issuance with HTTP-01 challenges, via `instant-acme`.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::RwLock;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, anyhow, bail};
use instant_acme::{
    Account, AccountCredentials, AuthorizationStatus, ChallengeType, Identifier, NewAccount, NewOrder, OrderStatus,
    RetryPolicy,
};
use tokio::sync::OnceCell;

use crate::config::TlsConfig;

/// Pending HTTP-01 challenge responses (`token -> key authorization`), served on port 80.
#[derive(Default, Debug)]
pub struct Http01Challenges {
    map: RwLock<HashMap<String, String>>,
}

impl Http01Challenges {
    pub fn get(&self, token: &str) -> Option<String> {
        self.map.read().unwrap().get(token).cloned()
    }
    fn insert(&self, token: String, key_auth: String) {
        self.map.write().unwrap().insert(token, key_auth);
    }
    fn remove(&self, token: &str) {
        self.map.write().unwrap().remove(token);
    }
}

pub struct AcmeClient {
    directory: String,
    email: Option<String>,
    ca_root: Option<PathBuf>,
    account_path: PathBuf,
    account: OnceCell<Account>,
    challenges: Arc<Http01Challenges>,
    timeout: Duration,
}

impl AcmeClient {
    pub fn new(cfg: &TlsConfig, data_dir: &Path, challenges: Arc<Http01Challenges>) -> Self {
        Self {
            directory: cfg.acme_directory_url(),
            email: cfg.acme_email.clone(),
            ca_root: cfg.acme_ca_root.clone(),
            account_path: data_dir.join("acme-account.json"),
            account: OnceCell::new(),
            challenges,
            timeout: Duration::from_secs(cfg.issuance_timeout_secs),
        }
    }

    fn builder(&self) -> anyhow::Result<instant_acme::AccountBuilder> {
        Ok(match &self.ca_root {
            Some(p) => Account::builder_with_root(p).with_context(|| format!("loading ACME CA root {}", p.display()))?,
            None => Account::builder()?,
        })
    }

    /// Loads the persisted ACME account, or registers (and persists) a new one.
    async fn account(&self) -> anyhow::Result<&Account> {
        self.account
            .get_or_try_init(|| async {
                if let Ok(text) = std::fs::read_to_string(&self.account_path) {
                    let stored: StoredAccount = serde_json::from_str(&text).context("parsing ACME account file")?;
                    if stored.directory == self.directory {
                        return Ok(self.builder()?.from_credentials(stored.credentials).await?);
                    }
                }
                let contact = self.email.as_ref().map(|e| format!("mailto:{e}"));
                let contacts: Vec<&str> = contact.iter().map(String::as_str).collect();
                let (account, credentials) = self
                    .builder()?
                    .create(
                        &NewAccount { contact: &contacts, terms_of_service_agreed: true, only_return_existing: false },
                        self.directory.clone(),
                        None,
                    )
                    .await
                    .with_context(|| format!("registering ACME account at {}", self.directory))?;
                let stored = StoredAccount { directory: self.directory.clone(), credentials };
                super::write_private(&self.account_path, serde_json::to_string(&stored)?.as_bytes())?;
                tracing::info!(directory = %self.directory, "registered ACME account");
                Ok(account)
            })
            .await
    }

    /// Runs one order for `host`; returns `(certificate chain PEM, private key PEM)`.
    pub async fn order(&self, host: &str) -> anyhow::Result<(String, String)> {
        let account = self.account().await?;
        let ids = [Identifier::Dns(host.to_string())];
        let mut order = account.new_order(&NewOrder::new(&ids)).await.context("creating ACME order")?;
        let mut tokens = Vec::new();
        let result = async {
            let mut authzs = order.authorizations();
            while let Some(authz) = authzs.next().await {
                let mut authz = authz.context("fetching ACME authorization")?;
                match authz.status {
                    AuthorizationStatus::Pending => {}
                    AuthorizationStatus::Valid => continue,
                    other => bail!("ACME authorization is {other:?}"),
                }
                let mut challenge = authz
                    .challenge(ChallengeType::Http01)
                    .ok_or_else(|| anyhow!("ACME server offered no HTTP-01 challenge"))?;
                let token = challenge.token.clone();
                self.challenges.insert(token.clone(), challenge.key_authorization().as_str().to_string());
                tokens.push(token);
                challenge.set_ready().await.context("submitting ACME challenge")?;
            }
            let retry = RetryPolicy::new().initial_delay(Duration::from_millis(500)).timeout(self.timeout);
            let status = order.poll_ready(&retry).await.with_context(|| {
                format!("ACME challenge could not be completed; check that http://{host}/ reaches this server on port 80")
            })?;
            if status != OrderStatus::Ready {
                bail!(
                    "ACME challenge could not be completed (order {status:?}); check that http://{host}/ reaches this server on port 80"
                );
            }
            let key_pem = order.finalize().await.context("finalizing ACME order")?;
            let chain_pem = order.poll_certificate(&retry).await.context("downloading certificate")?;
            Ok((chain_pem, key_pem))
        }
        .await;
        for t in tokens {
            self.challenges.remove(&t);
        }
        result
    }
}

#[derive(serde::Serialize, serde::Deserialize)]
struct StoredAccount {
    directory: String,
    credentials: AccountCredentials,
}
