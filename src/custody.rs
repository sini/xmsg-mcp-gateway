use rusqlite::{params, Connection, OptionalExtension, TransactionBehavior};
use sha2::{Digest, Sha256};
use xmsg::client::{Delivery, RegisteredService};

use crate::grants::{Error as GrantError, Store};

#[derive(Clone, Debug)]
pub struct Scope {
    pub bus_instance: String,
    pub grant_id: String,
}

#[derive(Clone, Debug)]
pub struct Limits {
    pub max_items: i64,
    pub max_bytes: i64,
    pub max_item_bytes: i64,
    pub content_retention_secs: i64,
    pub max_metadata: i64,
    pub metadata_retention_secs: i64,
}
impl Default for Limits {
    fn default() -> Self {
        Self {
            max_items: 1000,
            max_bytes: 64 * 1024 * 1024,
            max_item_bytes: 256 * 1024,
            content_retention_secs: 604800,
            max_metadata: 1000,
            metadata_retention_secs: 604800,
        }
    }
}

#[derive(Debug, PartialEq, Eq)]
pub enum Acceptance {
    Stored { event_id: String },
    Duplicate { event_id: String },
    Quarantined,
    Refused,
}
impl Acceptance {
    fn can_ack(&self) -> bool {
        !matches!(self, Self::Refused)
    }
}

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("invalid custody configuration or timestamp")]
    Configuration,
    #[error("custody schema has not been explicitly migrated")]
    MigrationRequired,
    #[error("custody metadata capacity exhausted; delivery was not acknowledged")]
    MetadataFull,
    #[error("custody mailbox does not match the configured grant")]
    Mailbox,
    #[error(transparent)]
    Authority(#[from] GrantError),
    #[error("custody state unavailable")]
    Database(#[from] rusqlite::Error),
    #[error("custody encoding failed")]
    Encoding(#[from] serde_json::Error),
    #[error("xmsg operation failed; acknowledgement may be unknown")]
    Transport(#[from] xmsg::client::ClientError),
}

pub(crate) fn validate_schema(connection: &Connection) -> Result<(), GrantError> {
    connection.prepare("SELECT bus, upstream_id, event_id, grant_id, grant_revision, mailbox, owner, origin, text, envelope, in_reply_to, fingerprint, received_at, expires_at, held FROM custody_items LIMIT 0")?;
    connection.prepare("SELECT event_id, state FROM custody_outbox LIMIT 0")?;
    connection.prepare("SELECT bus, upstream_id, fingerprint, origin, reason, first_seen, expires_at FROM custody_metadata LIMIT 0")?;
    connection.prepare("SELECT name, value FROM custody_counters LIMIT 0")?;
    Ok(())
}

fn fingerprint(parts: &[&str]) -> String {
    let mut digest = Sha256::new();
    for part in parts {
        digest.update((part.len() as u64).to_be_bytes());
        digest.update(part.as_bytes());
    }
    format!("{:x}", digest.finalize())
}

fn expire(tx: &rusqlite::Transaction<'_>, limits: &Limits, now: i64) -> Result<(), Error> {
    let expired = tx.execute("DELETE FROM custody_metadata WHERE expires_at <= ?1", [now])?;
    tx.execute(
        "UPDATE custody_counters SET value=value+?1 WHERE name='expired_metadata'",
        [expired as i64],
    )?;
    tx.execute("UPDATE custody_outbox SET state='expired' WHERE event_id IN (SELECT event_id FROM custody_items WHERE text IS NOT NULL AND expires_at<=?1)", [now])?;
    let redacted = tx.execute("UPDATE custody_items SET text=NULL, envelope=NULL WHERE text IS NOT NULL AND expires_at<=?1", [now])?;
    tx.execute(
        "UPDATE custody_counters SET value=value+?1 WHERE name='expired_content'",
        [redacted as i64],
    )?;
    let cutoff = now.saturating_sub(limits.metadata_retention_secs);
    tx.execute("DELETE FROM custody_outbox WHERE event_id IN (SELECT event_id FROM custody_items WHERE text IS NULL AND expires_at<=?1)", [cutoff])?;
    let removed = tx.execute(
        "DELETE FROM custody_items WHERE text IS NULL AND expires_at<=?1",
        [cutoff],
    )?;
    tx.execute(
        "UPDATE custody_counters SET value=value+?1 WHERE name='expired_tombstones'",
        [removed as i64],
    )?;
    Ok(())
}

impl Store {
    pub fn migrate_custody(&mut self) -> Result<(), Error> {
        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let version: i64 = tx.pragma_query_value(None, "user_version", |row| row.get(0))?;
        if version != 1 {
            return Err(GrantError::NoChange.into());
        }
        tx.execute_batch(
            "CREATE TABLE custody_items (
                bus TEXT NOT NULL, upstream_id TEXT NOT NULL, event_id TEXT NOT NULL UNIQUE,
                grant_id TEXT NOT NULL, grant_revision INTEGER NOT NULL,
                mailbox TEXT NOT NULL, owner TEXT NOT NULL, origin TEXT NOT NULL,
                text TEXT, envelope TEXT, in_reply_to TEXT,
                fingerprint TEXT NOT NULL, received_at INTEGER NOT NULL,
                expires_at INTEGER NOT NULL, held INTEGER NOT NULL CHECK(held = 1),
                PRIMARY KEY(bus, upstream_id)
             );
             CREATE TABLE custody_outbox (event_id TEXT PRIMARY KEY NOT NULL,
                state TEXT NOT NULL CHECK(state IN ('held', 'expired')));
             CREATE TABLE custody_metadata (
                bus TEXT NOT NULL, upstream_id TEXT NOT NULL, fingerprint TEXT NOT NULL,
                origin TEXT NOT NULL, reason TEXT NOT NULL, first_seen INTEGER NOT NULL,
                expires_at INTEGER NOT NULL, PRIMARY KEY(bus, upstream_id, fingerprint, reason)
             );
             CREATE TABLE custody_counters (name TEXT PRIMARY KEY NOT NULL, value INTEGER NOT NULL);
             INSERT INTO custody_counters VALUES ('expired_metadata', 0), ('expired_content', 0), ('expired_tombstones', 0);",
        )?;
        tx.pragma_update(None, "user_version", 2)?;
        tx.commit()?;
        Ok(())
    }

    pub fn accept_delivery(
        &mut self,
        scope: &Scope,
        mailbox: &str,
        delivery: &Delivery,
        limits: &Limits,
        now: i64,
    ) -> Result<Acceptance, Error> {
        if scope.bus_instance.trim().is_empty()
            || scope.grant_id.trim().is_empty()
            || now < 0
            || [
                limits.max_items,
                limits.max_bytes,
                limits.max_item_bytes,
                limits.content_retention_secs,
                limits.max_metadata,
                limits.metadata_retention_secs,
            ]
            .iter()
            .any(|value| *value <= 0)
            || now.checked_add(limits.content_retention_secs).is_none()
            || now.checked_add(limits.metadata_retention_secs).is_none()
        {
            return Err(Error::Configuration);
        }
        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let version: i64 = tx.pragma_query_value(None, "user_version", |r| r.get(0))?;
        if version != 2 {
            return Err(Error::MigrationRequired);
        }
        expire(&tx, limits, now)?;
        let (service, owner, revision): (String, String, i64) = tx
            .query_row(
                "SELECT service, subject, revision FROM grants WHERE id = ?1",
                [&scope.grant_id],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .optional()?
            .ok_or(GrantError::Denied)?;
        if mailbox
            .split_once('@')
            .map(|(name, node)| name == service && !node.is_empty())
            != Some(true)
        {
            return Err(Error::Mailbox);
        }
        let origin = serde_json::to_string(&serde_json::json!({
            "id": delivery.origin().id, "service": delivery.origin().service,
            "node": delivery.origin().node,
        }))?;
        let correlation = serde_json::to_string(&delivery.in_reply_to())?;
        let hash = fingerprint(&[
            &origin,
            delivery.text(),
            delivery.envelope(),
            &correlation,
        ]);
        let existing: Option<(String, String)> = tx.query_row(
            "SELECT event_id, fingerprint FROM custody_items WHERE bus = ?1 AND upstream_id = ?2",
            params![scope.bus_instance, delivery.message_id()], |row| Ok((row.get(0)?, row.get(1)?)),
        ).optional()?;
        if let Some((event_id, stored_hash)) = existing {
            if stored_hash == hash {
                tx.commit()?;
                return Ok(Acceptance::Duplicate { event_id });
            }
        }
        let conflict: bool = tx.query_row(
            "SELECT EXISTS(SELECT 1 FROM custody_items WHERE bus = ?1 AND upstream_id = ?2)",
            params![scope.bus_instance, delivery.message_id()],
            |row| row.get(0),
        )?;
        let size = delivery
            .text()
            .len()
            .saturating_add(delivery.envelope().len())
            .saturating_add(origin.len())
            .saturating_add(delivery.in_reply_to().map_or(0, str::len));
        let (count, bytes): (i64, i64) = tx.query_row("SELECT COUNT(*), COALESCE(SUM(length(CAST(text AS BLOB)) + length(CAST(envelope AS BLOB)) + length(CAST(origin AS BLOB)) + COALESCE(length(CAST(in_reply_to AS BLOB)), 0)), 0) FROM custody_items", [], |row| Ok((row.get(0)?, row.get(1)?)))?;
        let refused = size as u128 > limits.max_item_bytes as u128
            || count >= limits.max_items
            || size as u128 + bytes as u128 > limits.max_bytes as u128;
        if conflict || refused {
            let reason = if conflict { "conflict" } else { "capacity" };
            let known: bool = tx.query_row("SELECT EXISTS(SELECT 1 FROM custody_metadata WHERE bus=?1 AND upstream_id=?2 AND fingerprint=?3 AND reason=?4)", params![scope.bus_instance, delivery.message_id(), hash, reason], |row| row.get(0))?;
            let records: i64 =
                tx.query_row("SELECT COUNT(*) FROM custody_metadata", [], |row| {
                    row.get(0)
                })?;
            if !known && records >= limits.max_metadata {
                return Err(Error::MetadataFull);
            }
            tx.execute("INSERT OR IGNORE INTO custody_metadata (bus, upstream_id, fingerprint, origin, reason, first_seen, expires_at) VALUES (?1,?2,?3,?4,?5,?6,?7)", params![scope.bus_instance, delivery.message_id(), hash, origin, reason, now, now + limits.metadata_retention_secs])?;
            tx.commit()?;
            return Ok(if conflict {
                Acceptance::Quarantined
            } else {
                Acceptance::Refused
            });
        }
        let event_id = format!(
            "event-{}",
            fingerprint(&[&scope.bus_instance, delivery.message_id()])
        );
        tx.execute("INSERT INTO custody_items (bus,upstream_id,event_id,grant_id,grant_revision,mailbox,owner,origin,text,envelope,in_reply_to,fingerprint,received_at,expires_at,held) VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14,1)", params![scope.bus_instance, delivery.message_id(), event_id, scope.grant_id, revision, mailbox, owner, origin, delivery.text(), delivery.envelope(), delivery.in_reply_to(), hash, now, now + limits.content_retention_secs])?;
        tx.execute(
            "INSERT INTO custody_outbox (event_id,state) VALUES (?1,'held')",
            [&event_id],
        )?;
        tx.commit()?;
        Ok(Acceptance::Stored { event_id })
    }
}

pub async fn receive_one(
    store: &mut Store,
    service: &mut RegisteredService,
    scope: &Scope,
    limits: &Limits,
    now: i64,
) -> Result<Option<Acceptance>, Error> {
    let Some(delivery) = service.poll(0).await? else {
        return Ok(None);
    };
    let mailbox = service
        .address()
        .ok_or(xmsg::client::ClientError::Disconnected)?;
    let accepted = store.accept_delivery(scope, mailbox, &delivery, limits, now)?;
    if accepted.can_ack() {
        service.ack(delivery.message_id()).await?;
    }
    Ok(Some(accepted))
}
