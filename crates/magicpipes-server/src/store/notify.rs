//! Telling people about alerts (migration 12): each account's alert email, and webhooks. Callers
//! pass validated values (`control::notify`). A webhook's address and secret aren't here, but in a
//! file of their own.

use std::collections::HashMap;

use rusqlite::{OptionalExtension, params};

use super::Store;
use super::users::{DEFAULT_ORG, USER_SELECT, UserRow, user_row};

/// Each one is a queue and a task on the control threads.
pub const MAX_WEBHOOKS: usize = 10;

/// What alerts someone gets by email.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum AlertEmail {
    #[default]
    Off,
    /// About their own machines and tunnels; for an administrator, also service agents and the
    /// server.
    Mine,
    /// Every alert. Only an administrator gets these; anyone else gets [`AlertEmail::Mine`].
    All,
}

impl AlertEmail {
    pub fn as_str(self) -> &'static str {
        match self {
            AlertEmail::Off => "off",
            AlertEmail::Mine => "mine",
            AlertEmail::All => "all",
        }
    }

    /// Something unreadable sends nothing.
    pub fn parse(s: &str) -> Option<AlertEmail> {
        [AlertEmail::Off, AlertEmail::Mine, AlertEmail::All].into_iter().find(|a| a.as_str() == s)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WebhookRow {
    pub id: String,
    pub name: String,
    pub host: String,
    pub created_by: String,
    pub created_at: i64,
}

impl Store {
    pub fn alert_email(&self, user_id: &str) -> anyhow::Result<AlertEmail> {
        let v: Option<String> = self.with(|c| c.query_row("SELECT alert_email FROM users WHERE id = ?1", [user_id], |r| r.get(0)).optional())?;
        Ok(v.as_deref().and_then(AlertEmail::parse).unwrap_or_default())
    }

    /// `false` if there's no such account.
    pub fn set_alert_email(&self, user_id: &str, choice: AlertEmail) -> anyhow::Result<bool> {
        Ok(self.with(|c| c.execute("UPDATE users SET alert_email = ?2 WHERE id = ?1", params![user_id, choice.as_str()]))? == 1)
    }

    /// Accounts that asked for alert email, whatever their state: the caller decides who can get it.
    pub fn alert_email_accounts(&self) -> anyhow::Result<Vec<(UserRow, AlertEmail)>> {
        self.with(|c| {
            let mut st = c.prepare("SELECT id, alert_email FROM users WHERE alert_email != 'off'")?;
            let choices: HashMap<String, String> = st.query_map([], |r| Ok((r.get(0)?, r.get(1)?)))?.collect::<rusqlite::Result<_>>()?;
            if choices.is_empty() {
                return Ok(Vec::new());
            }
            let mut st = c.prepare(&format!("{USER_SELECT} WHERE u.alert_email != 'off' ORDER BY u.created_at"))?;
            let rows = st.query_map([], user_row)?.collect::<rusqlite::Result<Vec<_>>>()?;
            Ok(rows
                .into_iter()
                .filter_map(|u| {
                    let choice = choices.get(&u.id).and_then(|s| AlertEmail::parse(s)).filter(|c| *c != AlertEmail::Off)?;
                    Some((u, choice))
                })
                .collect())
        })
    }

    pub fn webhooks(&self) -> anyhow::Result<Vec<WebhookRow>> {
        self.with(|c| {
            let mut st = c.prepare("SELECT id, name, host, created_by, created_at FROM webhooks WHERE org_id = ?1 ORDER BY created_at, id")?;
            let rows = st.query_map([DEFAULT_ORG], |r| Ok(WebhookRow { id: r.get(0)?, name: r.get(1)?, host: r.get(2)?, created_by: r.get(3)?, created_at: r.get(4)? }))?;
            rows.collect()
        })
    }

    /// `false` if there are [`MAX_WEBHOOKS`] already.
    pub fn create_webhook(&self, w: &WebhookRow) -> anyhow::Result<bool> {
        let n = self.with(|c| {
            let count: i64 = c.query_row("SELECT COUNT(*) FROM webhooks WHERE org_id = ?1", [DEFAULT_ORG], |r| r.get(0))?;
            if usize::try_from(count).unwrap_or(usize::MAX) >= MAX_WEBHOOKS {
                return Ok(0);
            }
            c.execute(
                "INSERT INTO webhooks (id, org_id, name, host, created_by, created_at) VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                params![w.id, DEFAULT_ORG, w.name, w.host, w.created_by, w.created_at],
            )
        })?;
        Ok(n == 1)
    }

    /// `false` if it was already gone.
    pub fn delete_webhook(&self, id: &str) -> anyhow::Result<bool> {
        Ok(self.with(|c| c.execute("DELETE FROM webhooks WHERE org_id = ?1 AND id = ?2", params![DEFAULT_ORG, id]))? == 1)
    }
}
