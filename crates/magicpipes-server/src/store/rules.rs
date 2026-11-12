//! Tag rules and what people matched (migration 13). Callers pass validated values
//! (`control::rules`).

use std::collections::BTreeSet;

use magicpipes_core::unix_now;
use rusqlite::params;

use super::Store;
use super::users::DEFAULT_ORG;

/// Rules in the organization. Each is checked at every single sign-on through its source.
pub const MAX_TAG_RULES: usize = 500;
/// The source of a rule that applies whatever someone signs in with.
pub const ANY_SOURCE: &str = "*";
/// The claim of a rule about a confirmed address's domain, which has [`ANY_SOURCE`].
pub const EMAIL_DOMAIN: &str = "email_domain";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TagRuleRow {
    pub id: String,
    /// The sign-in source: a provider's or the proxy's issuer, or [`ANY_SOURCE`].
    pub issuer: String,
    pub claim: String,
    pub value: String,
    pub tag: String,
    pub created_by: Option<String>,
    pub created_at: i64,
}

pub struct NewRule<'a> {
    pub id: &'a str,
    pub issuer: &'a str,
    pub claim: &'a str,
    pub value: &'a str,
    pub tag: &'a str,
    pub created_by: Option<&'a str>,
}

/// Why a rule wasn't added.
#[derive(Debug, PartialEq, Eq)]
pub enum NotAdded {
    /// The same rule is there already.
    Exists,
    /// There are [`MAX_TAG_RULES`].
    Full,
    /// Its tag isn't registered, or is someone's personal tag.
    NoSuchTag,
}

impl Store {
    pub fn tag_rules(&self) -> anyhow::Result<Vec<TagRuleRow>> {
        self.with(|c| {
            let mut st = c.prepare("SELECT id, issuer, claim, value, tag, created_by, created_at FROM tag_rules WHERE org_id = ?1 ORDER BY tag, issuer, claim, value")?;
            let rows = st.query_map([DEFAULT_ORG], |r| {
                Ok(TagRuleRow { id: r.get(0)?, issuer: r.get(1)?, claim: r.get(2)?, value: r.get(3)?, tag: r.get(4)?, created_by: r.get(5)?, created_at: r.get(6)? })
            })?;
            rows.collect()
        })
    }

    pub fn create_tag_rule(&self, rule: &NewRule) -> anyhow::Result<Result<(), NotAdded>> {
        let mut conn = self.conn.lock().unwrap_or_else(|e| e.into_inner());
        let tx = conn.transaction()?;
        let count: i64 = tx.query_row("SELECT COUNT(*) FROM tag_rules WHERE org_id = ?1", [DEFAULT_ORG], |r| r.get(0))?;
        if usize::try_from(count).unwrap_or(usize::MAX) >= MAX_TAG_RULES {
            return Ok(Err(NotAdded::Full));
        }
        let ordinary: bool = tx.query_row(
            "SELECT EXISTS(SELECT 1 FROM tags WHERE org_id = ?1 AND name = ?2 AND user_id IS NULL)",
            params![DEFAULT_ORG, rule.tag],
            |r| r.get(0),
        )?;
        if !ordinary {
            return Ok(Err(NotAdded::NoSuchTag));
        }
        let n = tx.execute(
            "INSERT INTO tag_rules (id, org_id, issuer, claim, value, tag, created_by, created_at) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)
             ON CONFLICT DO NOTHING",
            params![rule.id, DEFAULT_ORG, rule.issuer, rule.claim, rule.value, rule.tag, rule.created_by, unix_now()],
        )?;
        tx.commit()?;
        Ok(if n == 1 { Ok(()) } else { Err(NotAdded::Exists) })
    }

    /// `false` if it was already gone. Its matches go with it.
    pub fn delete_tag_rule(&self, id: &str) -> anyhow::Result<bool> {
        Ok(self.with(|c| c.execute("DELETE FROM tag_rules WHERE org_id = ?1 AND id = ?2", params![DEFAULT_ORG, id]))? == 1)
    }

    /// Replaces what `user_id` matched among the rules of `issuer` with `matched`, as of now.
    /// Matches of other sources stay. Returns whether the set of rules matched changed.
    pub fn set_rule_matches(&self, user_id: &str, issuer: &str, matched: &[String]) -> anyhow::Result<bool> {
        let mut conn = self.conn.lock().unwrap_or_else(|e| e.into_inner());
        let tx = conn.transaction()?;
        let before: BTreeSet<String> = {
            let mut st = tx.prepare("SELECT m.rule_id FROM user_rule_matches m JOIN tag_rules r ON r.id = m.rule_id WHERE m.user_id = ?1 AND r.issuer = ?2")?;
            st.query_map(params![user_id, issuer], |r| r.get(0))?.collect::<rusqlite::Result<_>>()?
        };
        tx.execute(
            "DELETE FROM user_rule_matches WHERE user_id = ?1 AND rule_id IN (SELECT id FROM tag_rules WHERE issuer = ?2)",
            params![user_id, issuer],
        )?;
        let now = unix_now();
        let mut after = BTreeSet::new();
        for id in matched {
            // Only a rule of this source, still there.
            let n = tx.execute(
                "INSERT OR REPLACE INTO user_rule_matches (user_id, rule_id, matched_at) SELECT ?1, id, ?3 FROM tag_rules WHERE id = ?2 AND issuer = ?4",
                params![user_id, id, now, issuer],
            )?;
            if n == 1 {
                after.insert(id.clone());
            }
        }
        tx.commit()?;
        Ok(before != after)
    }

    /// Who matched which rule, at a sign-on since `since`.
    pub fn rule_matches(&self, since: i64) -> anyhow::Result<Vec<(String, String)>> {
        self.with(|c| {
            let mut st = c.prepare("SELECT user_id, rule_id FROM user_rule_matches WHERE matched_at >= ?1 ORDER BY user_id, rule_id")?;
            st.query_map([since], |r| Ok((r.get(0)?, r.get(1)?)))?.collect()
        })
    }

    /// Forgets matches from before `before`, and says how many.
    pub fn prune_rule_matches(&self, before: i64) -> anyhow::Result<usize> {
        self.with(|c| c.execute("DELETE FROM user_rule_matches WHERE matched_at < ?1", [before]))
    }
}
