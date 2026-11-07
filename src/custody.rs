use rusqlite::{params, Connection, OptionalExtension, TransactionBehavior};
use sha2::{Digest, Sha256};
use xmsg::client::{Delivery, RegisteredService};

use crate::grants::{
    Error as GrantError, Store, CUSTODY_SCHEMA_VERSION, MAX_SUPPORTED_SCHEMA_VERSION,
};

#[derive(Clone, Debug, serde::Deserialize)]
#[serde(deny_unknown_fields)]
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
    pub max_gap_intervals: i64,
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
            max_gap_intervals: 1000,
        }
    }
}

impl Limits {
    fn validate(&self, now: i64) -> Result<(), Error> {
        if now < 0
            || [
                self.max_items,
                self.max_bytes,
                self.max_item_bytes,
                self.content_retention_secs,
                self.max_metadata,
                self.metadata_retention_secs,
                self.max_gap_intervals,
            ]
            .iter()
            .any(|value| *value <= 0)
            || now.checked_add(self.content_retention_secs).is_none()
            || now.checked_add(self.metadata_retention_secs).is_none()
        {
            return Err(Error::Configuration);
        }
        Ok(())
    }
}

#[derive(Debug)]
pub struct Status {
    pub held_items: i64,
    pub expired_items: i64,
    pub refusals: i64,
    pub quarantines: i64,
    pub pending: i64,
    pub oldest_pending_age_secs: Option<i64>,
    pub possible_known_loss: bool,
    pub offline_uncertainty: bool,
    pub expired_metadata: i64,
    pub expired_content: i64,
    pub expired_tombstones: i64,
    pub expired_pending: i64,
}

#[derive(Debug, PartialEq, Eq)]
pub enum Acceptance {
    Stored { event_id: String },
    Duplicate { event_id: String },
    Quarantined,
    Refused,
    Deferred,
}
impl Acceptance {
    fn can_ack(&self) -> bool {
        match self {
            Self::Stored { .. } | Self::Duplicate { .. } | Self::Quarantined | Self::Refused => {
                true
            }
            Self::Deferred => false,
        }
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
    connection.prepare("SELECT bus, upstream_id, fingerprint, origin, size, reason, first_seen, expires_at FROM custody_metadata LIMIT 0")?;
    connection.prepare("SELECT name, value FROM custody_counters LIMIT 0")?;
    connection
        .prepare("SELECT bus, upstream_id, first_seen, expires_at FROM custody_pending LIMIT 0")?;
    connection.prepare("SELECT bus, connected, disconnected_at, reconnected_at, outages, expired_first_seen, last_observed_at FROM custody_links LIMIT 0")?;
    connection.prepare("SELECT bus, gap_start, gap_end, expires_at FROM custody_gaps LIMIT 0")?;
    Ok(())
}

pub(crate) fn fingerprint(parts: &[&str]) -> String {
    let mut digest = Sha256::new();
    for part in parts {
        digest.update((part.len() as u64).to_be_bytes());
        digest.update(part.as_bytes());
    }
    format!("{:x}", digest.finalize())
}

fn ensure_link(tx: &rusqlite::Transaction<'_>, bus: &str, limits: &Limits) -> Result<(), Error> {
    let known: bool = tx.query_row(
        "SELECT EXISTS(SELECT 1 FROM custody_links WHERE bus=?1)",
        [bus],
        |row| row.get(0),
    )?;
    let count: i64 = tx.query_row("SELECT COUNT(*) FROM custody_links", [], |row| row.get(0))?;
    if !known && count >= limits.max_metadata {
        return Err(Error::MetadataFull);
    }
    tx.execute(
        "INSERT OR IGNORE INTO custody_links(bus,connected,outages) VALUES (?1,1,0)",
        [bus],
    )?;
    Ok(())
}

fn expire(tx: &rusqlite::Transaction<'_>, limits: &Limits, now: i64) -> Result<(), Error> {
    tx.execute("DELETE FROM custody_gaps WHERE expires_at<=?1", [now])?;
    tx.execute("UPDATE custody_links SET expired_first_seen = (SELECT MIN(first_seen) FROM (SELECT expired_first_seen AS first_seen UNION ALL SELECT first_seen FROM custody_pending WHERE bus = custody_links.bus AND expires_at<=?1)) WHERE EXISTS(SELECT 1 FROM custody_pending WHERE bus=custody_links.bus AND expires_at<=?1)", [now])?;
    let pending = tx.execute("DELETE FROM custody_pending WHERE expires_at<=?1", [now])?;
    tx.execute(
        "UPDATE custody_counters SET value=value+?1 WHERE name='expired_pending'",
        [pending as i64],
    )?;
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
    fn require_custody_ready(&self) -> Result<(), Error> {
        let version: i64 = self
            .connection
            .pragma_query_value(None, "user_version", |row| row.get(0))?;
        if !(CUSTODY_SCHEMA_VERSION..=MAX_SUPPORTED_SCHEMA_VERSION).contains(&version) {
            return Err(Error::MigrationRequired);
        }
        Ok(())
    }

    pub fn record_custody_link(
        &mut self,
        scope: &Scope,
        connected: bool,
        limits: &Limits,
        now: i64,
    ) -> Result<(), Error> {
        self.record_bus_link(&scope.bus_instance, connected, limits, now)
    }

    pub(crate) fn record_bus_link(
        &mut self,
        bus: &str,
        connected: bool,
        limits: &Limits,
        now: i64,
    ) -> Result<(), Error> {
        limits.validate(now)?;
        if bus.trim().is_empty() {
            return Err(Error::Configuration);
        }
        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        ensure_link(&tx, bus, limits)?;
        expire(&tx, limits, now)?;
        let (was_connected, last_observed, disconnected): (bool, Option<i64>, Option<i64>) = tx
            .query_row(
            "SELECT connected, last_observed_at, disconnected_at FROM custody_links WHERE bus=?1",
            [bus],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )?;
        let observed = now.max(last_observed.unwrap_or(now));
        let start = if was_connected {
            last_observed
        } else {
            disconnected.or(last_observed)
        };
        if let Some(start) = start {
            if observed > start {
                let expiry = observed
                    .checked_add(limits.metadata_retention_secs)
                    .ok_or(Error::Configuration)?;
                tx.execute("DELETE FROM custody_gaps WHERE bus=?1 AND gap_end-gap_start<=?2 AND expires_at<=?3", params![bus, observed-start, expiry])?;
                let count: i64 =
                    tx.query_row("SELECT COUNT(*) FROM custody_gaps", [], |row| row.get(0))?;
                if count >= limits.max_gap_intervals {
                    return Err(Error::MetadataFull);
                }
                tx.execute("INSERT INTO custody_gaps(bus,gap_start,gap_end,expires_at) VALUES (?1,?2,?3,?4)", params![bus, start, observed, expiry])?;
            }
        }
        tx.execute(
            "UPDATE custody_links SET last_observed_at=?2 WHERE bus=?1",
            params![bus, observed],
        )?;
        if was_connected == connected {
            tx.commit()?;
            return Ok(());
        }
        if connected {
            tx.execute(
                "UPDATE custody_links SET connected=1, reconnected_at=?2 WHERE bus=?1",
                params![bus, now],
            )?;
        } else {
            tx.execute("UPDATE custody_links SET disconnected_at=CASE WHEN connected=1 THEN ?2 ELSE disconnected_at END, outages=outages+connected, connected=0 WHERE bus=?1", params![bus, last_observed.unwrap_or(observed)])?;
        }
        tx.commit()?;
        Ok(())
    }

    pub fn record_custody_ack(&mut self, scope: &Scope, upstream_id: &str) -> Result<(), Error> {
        self.connection.execute(
            "DELETE FROM custody_pending WHERE bus=?1 AND upstream_id=?2",
            params![scope.bus_instance, upstream_id],
        )?;
        Ok(())
    }

    pub fn custody_status(
        &mut self,
        scope: &Scope,
        limits: &Limits,
        now: i64,
        effective_reply_ttl_secs: i64,
    ) -> Result<Status, Error> {
        limits.validate(now)?;
        if effective_reply_ttl_secs <= 0 {
            return Err(Error::Configuration);
        }
        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        expire(&tx, limits, now)?;
        let (held_items, expired_items): (i64, i64) = tx.query_row("SELECT COALESCE(SUM(text IS NOT NULL),0), COALESCE(SUM(text IS NULL),0) FROM custody_items WHERE bus=?1", [&scope.bus_instance], |row| Ok((row.get(0)?, row.get(1)?)))?;
        let (refusals, quarantines): (i64, i64) = tx.query_row("SELECT COALESCE(SUM(reason!='conflict'),0), COALESCE(SUM(reason='conflict'),0) FROM custody_metadata WHERE bus=?1", [&scope.bus_instance], |row| Ok((row.get(0)?, row.get(1)?)))?;
        let pending: i64 = tx.query_row(
            "SELECT COUNT(*) FROM custody_pending WHERE bus=?1",
            [&scope.bus_instance],
            |row| row.get(0),
        )?;
        let first_seen: Option<i64> = tx.query_row("SELECT MIN(first_seen) FROM (SELECT first_seen FROM custody_pending WHERE bus=?1 UNION ALL SELECT expired_first_seen FROM custody_links WHERE bus=?1)", [&scope.bus_instance], |row| row.get(0))?;
        let oldest_pending_age_secs = first_seen.map(|first| now.saturating_sub(first).max(0));
        let offline_uncertainty: bool = tx.query_row(
            "SELECT EXISTS(SELECT 1 FROM custody_gaps WHERE bus=?1 AND (gap_end-gap_start)>=?3) OR EXISTS(SELECT 1 FROM custody_links WHERE bus=?1 AND (?2-CASE WHEN connected=0 THEN disconnected_at ELSE last_observed_at END)>=?3)",
            params![scope.bus_instance, now, effective_reply_ttl_secs],
            |row| row.get(0),
        )?;
        let counter = |name: &str| -> Result<i64, rusqlite::Error> {
            tx.query_row(
                "SELECT value FROM custody_counters WHERE name=?1",
                [name],
                |row| row.get(0),
            )
        };
        let status = Status {
            held_items,
            expired_items,
            refusals,
            quarantines,
            pending,
            possible_known_loss: oldest_pending_age_secs
                .is_some_and(|age| age >= effective_reply_ttl_secs),
            oldest_pending_age_secs,
            offline_uncertainty,
            expired_metadata: counter("expired_metadata")?,
            expired_content: counter("expired_content")?,
            expired_tombstones: counter("expired_tombstones")?,
            expired_pending: counter("expired_pending")?,
        };
        tx.commit()?;
        Ok(status)
    }

    pub fn migrate_custody(&mut self) -> Result<(), Error> {
        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let version: i64 = tx.pragma_query_value(None, "user_version", |row| row.get(0))?;
        if version != CUSTODY_SCHEMA_VERSION - 1 {
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
                origin TEXT NOT NULL, size INTEGER NOT NULL CHECK(size >= 0), reason TEXT NOT NULL, first_seen INTEGER NOT NULL,
                expires_at INTEGER NOT NULL, PRIMARY KEY(bus, upstream_id, fingerprint, reason)
             );
             CREATE TABLE custody_counters (name TEXT PRIMARY KEY NOT NULL, value INTEGER NOT NULL);
             CREATE TABLE custody_pending (bus TEXT NOT NULL, upstream_id TEXT NOT NULL,
                first_seen INTEGER NOT NULL, expires_at INTEGER NOT NULL, PRIMARY KEY(bus, upstream_id));
             CREATE TABLE custody_links (bus TEXT PRIMARY KEY NOT NULL, connected INTEGER NOT NULL,
                disconnected_at INTEGER, reconnected_at INTEGER, outages INTEGER NOT NULL,
                expired_first_seen INTEGER, last_observed_at INTEGER);
             CREATE TABLE custody_gaps (bus TEXT NOT NULL, gap_start INTEGER NOT NULL,
                gap_end INTEGER NOT NULL, expires_at INTEGER NOT NULL);
             INSERT INTO custody_counters VALUES ('expired_metadata', 0), ('expired_content', 0), ('expired_tombstones', 0), ('expired_pending', 0);",
        )?;
        tx.pragma_update(None, "user_version", CUSTODY_SCHEMA_VERSION)?;
        tx.commit()?;
        Ok(())
    }

    pub fn accept_delivery(
        &mut self,
        scope: &Scope,
        service: &RegisteredService,
        delivery: &Delivery,
        limits: &Limits,
        now: i64,
    ) -> Result<Acceptance, Error> {
        limits.validate(now)?;
        if scope.bus_instance.trim().is_empty() || scope.grant_id.trim().is_empty() {
            return Err(Error::Configuration);
        }
        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let version: i64 = tx.pragma_query_value(None, "user_version", |r| r.get(0))?;
        if !(CUSTODY_SCHEMA_VERSION..=MAX_SUPPORTED_SCHEMA_VERSION).contains(&version) {
            return Err(Error::MigrationRequired);
        }
        expire(&tx, limits, now)?;
        ensure_link(&tx, &scope.bus_instance, limits)?;
        let known_pending: bool = tx.query_row(
            "SELECT EXISTS(SELECT 1 FROM custody_pending WHERE bus=?1 AND upstream_id=?2)",
            params![scope.bus_instance, delivery.message_id()],
            |row| row.get(0),
        )?;
        let pending_count: i64 =
            tx.query_row("SELECT COUNT(*) FROM custody_pending", [], |row| row.get(0))?;
        if !known_pending && pending_count >= limits.max_metadata {
            return Err(Error::MetadataFull);
        }
        tx.execute("INSERT OR IGNORE INTO custody_pending(bus,upstream_id,first_seen,expires_at) VALUES (?1,?2,?3,?4)", params![scope.bus_instance, delivery.message_id(), now, now + limits.metadata_retention_secs])?;
        let mailbox = service
            .address()
            .ok_or(xmsg::client::ClientError::Disconnected)?;
        let (owner, revision): (String, i64) = tx
            .query_row(
                "SELECT subject, revision FROM grants WHERE id = ?1",
                [&scope.grant_id],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()?
            .ok_or(GrantError::Denied)?;
        let origin = serde_json::to_string(&serde_json::json!({
            "id": delivery.origin().id, "service": delivery.origin().service,
            "node": delivery.origin().node,
        }))?;
        let correlation = serde_json::to_string(&delivery.in_reply_to())?;
        let hash = fingerprint(&[&origin, delivery.text(), delivery.envelope(), &correlation]);
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
        let oversized =
            size as u128 > limits.max_item_bytes as u128 || size as u128 > limits.max_bytes as u128;
        let refused = oversized
            || count >= limits.max_items
            || size as u128 + bytes as u128 > limits.max_bytes as u128;
        if !conflict && refused && !oversized {
            tx.commit()?;
            return Ok(Acceptance::Deferred);
        }
        if conflict || refused {
            let reason = if conflict {
                "conflict"
            } else if oversized {
                "oversized"
            } else {
                "capacity"
            };
            let known: bool = tx.query_row("SELECT EXISTS(SELECT 1 FROM custody_metadata WHERE bus=?1 AND upstream_id=?2 AND fingerprint=?3 AND reason=?4)", params![scope.bus_instance, delivery.message_id(), hash, reason], |row| row.get(0))?;
            let records: i64 =
                tx.query_row("SELECT COUNT(*) FROM custody_metadata", [], |row| {
                    row.get(0)
                })?;
            if !known && records >= limits.max_metadata {
                return Err(Error::MetadataFull);
            }
            let bounded_size = i64::try_from(size).map_err(|_| Error::Configuration)?;
            tx.execute("INSERT OR IGNORE INTO custody_metadata (bus, upstream_id, fingerprint, origin, size, reason, first_seen, expires_at) VALUES (?1,?2,?3,?4,?5,?6,?7,?8)", params![scope.bus_instance, delivery.message_id(), hash, origin, bounded_size, reason, now, now + limits.metadata_retention_secs])?;
            tx.commit()?;
            return Ok(if conflict {
                Acceptance::Quarantined
            } else if oversized {
                Acceptance::Refused
            } else {
                Acceptance::Deferred
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
        tracing::debug!(target: "gateway_custody_before_commit", "accept");
        tx.commit()?;
        tracing::debug!(target: "gateway_custody_after_commit", "accept");
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
    store.require_custody_ready()?;
    let polled = match service.poll(0).await {
        Ok(delivery) => {
            store.record_custody_link(scope, true, limits, now)?;
            delivery
        }
        Err(error) => {
            store.record_custody_link(scope, false, limits, now)?;
            return Err(error.into());
        }
    };
    let Some(delivery) = polled else {
        return Ok(None);
    };
    let accepted = store.accept_delivery(scope, service, &delivery, limits, now)?;
    if accepted.can_ack() {
        service.ack(delivery.message_id()).await?;
        store.record_custody_ack(scope, delivery.message_id())?;
    }
    Ok(Some(accepted))
}
