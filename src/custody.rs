use rusqlite::{params, Connection, OptionalExtension, TransactionBehavior};
use sha2::{Digest, Sha256};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
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

#[derive(Clone, Debug, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Limits {
    pub max_items: i64,
    pub max_bytes: i64,
    pub max_item_bytes: i64,
    pub content_retention_secs: i64,
    pub max_metadata: i64,
    pub metadata_retention_secs: i64,
    pub max_gap_intervals: i64,
}
struct Windows {
    observed: i64,
    content_expires: i64,
    metadata_expires: i64,
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
    pub(crate) fn validate(&self) -> Result<(), Error> {
        self.windows(SystemTime::now()).map(|_| ())
    }
    fn windows(&self, at: SystemTime) -> Result<Windows, Error> {
        if [
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
        {
            return Err(Error::Configuration);
        }
        let (observed, content_expires) = crate::deadline::window(at, self.content_retention_secs)
            .map_err(|_| Error::Configuration)?;
        let (_, metadata_expires) = crate::deadline::window(at, self.metadata_retention_secs)
            .map_err(|_| Error::Configuration)?;
        Ok(Windows {
            observed,
            content_expires,
            metadata_expires,
        })
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
    pub coalesced_uncertainty: bool,
    pub gap_observations: i64,
    pub gap_first_seen: Option<i64>,
    pub gap_last_seen: Option<i64>,
    pub widest_gap_secs: Option<i64>,
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
    let marker: i64 = connection.pragma_query_value(None, "application_id", |r| r.get(0))?;
    if marker == crate::grants::SUMMARY_APPLICATION_ID {
        connection.prepare("SELECT bus,reason,observations,max_size,first_seen,last_seen,expires_at FROM custody_refusal_summaries LIMIT 0")?;
        connection.prepare("SELECT bus,observations,gap_start,gap_end,widest,widest_expires_at,expires_at,last_start,last_end,last_expires_at FROM custody_gap_summary LIMIT 0")?;
    }
    Ok(())
}

const SUMMARY_SCHEMA: &str = "
CREATE TABLE custody_refusal_summaries (
 bus TEXT NOT NULL, reason TEXT NOT NULL CHECK(reason IN ('conflict','refusal')),
 observations INTEGER NOT NULL CHECK(observations>0), max_size INTEGER NOT NULL CHECK(max_size>=0), first_seen INTEGER NOT NULL,
 last_seen INTEGER NOT NULL, expires_at INTEGER NOT NULL, PRIMARY KEY(bus,reason));
CREATE TABLE custody_gap_summary (
 bus TEXT PRIMARY KEY NOT NULL, observations INTEGER NOT NULL CHECK(observations>0),
 gap_start INTEGER NOT NULL, gap_end INTEGER NOT NULL, widest INTEGER NOT NULL,
 widest_expires_at INTEGER NOT NULL, expires_at INTEGER NOT NULL,
 last_start INTEGER NOT NULL, last_end INTEGER NOT NULL, last_expires_at INTEGER NOT NULL);
";

fn create_summaries(tx: &rusqlite::Transaction<'_>) -> Result<(), Error> {
    tx.execute_batch(SUMMARY_SCHEMA)?;
    tx.execute_batch("INSERT INTO custody_refusal_summaries
        SELECT bus,CASE WHEN reason='conflict' THEN 'conflict' ELSE 'refusal' END,
          COUNT(*),MAX(size),MIN(first_seen),MAX(first_seen),MAX(expires_at)
        FROM custody_metadata GROUP BY bus,CASE WHEN reason='conflict' THEN 'conflict' ELSE 'refusal' END;")?;
    let gaps: Vec<(String, i64, i64, i64)> = {
        let mut query = tx.prepare("SELECT bus,gap_start,gap_end,expires_at FROM custody_gaps ORDER BY bus,gap_end,gap_start")?;
        let rows = query
            .query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)))?
            .collect::<Result<_, _>>()?;
        rows
    };
    for (bus, start, end, expiry) in gaps {
        record_gap(tx, &bus, start, end, expiry)?;
    }
    tx.execute("DELETE FROM custody_metadata", [])?;
    tx.execute("DELETE FROM custody_gaps", [])?;
    tx.pragma_update(
        None,
        "application_id",
        crate::grants::SUMMARY_APPLICATION_ID,
    )?;
    Ok(())
}

fn record_gap(
    tx: &rusqlite::Transaction<'_>,
    bus: &str,
    start: i64,
    end: i64,
    expiry: i64,
) -> Result<(), Error> {
    let previous: Option<i64> = tx.query_row("SELECT last_expires_at FROM custody_gap_summary WHERE bus=?1 AND last_start=?2 AND last_end=?3",params![bus,start,end],|r|r.get(0)).optional()?;
    let expiry = previous.map_or(expiry, |stored| stored.min(expiry));
    let width = end.saturating_sub(start);
    tx.execute("INSERT INTO custody_gap_summary(bus,observations,gap_start,gap_end,widest,widest_expires_at,expires_at,last_start,last_end,last_expires_at)
        VALUES(?1,1,?2,?3,?4,?5,?5,?2,?3,?5)
        ON CONFLICT(bus) DO UPDATE SET
        observations=CASE WHEN observations<9223372036854775807 THEN observations+1 ELSE observations END,
        gap_start=MIN(gap_start,excluded.gap_start),gap_end=MAX(gap_end,excluded.gap_end),
        widest_expires_at=CASE WHEN excluded.widest>widest THEN excluded.widest_expires_at WHEN excluded.widest=widest THEN MAX(widest_expires_at,excluded.widest_expires_at) ELSE widest_expires_at END,
        widest=MAX(widest,excluded.widest),
        expires_at=CASE WHEN last_start=excluded.last_start AND last_end=excluded.last_end THEN expires_at ELSE MAX(expires_at,excluded.expires_at) END,
        last_expires_at=excluded.last_expires_at,
        last_start=excluded.last_start,last_end=excluded.last_end",params![bus,start,end,width,expiry])?;
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

fn refs_bytes(refs: &str) -> usize {
    if refs == "[]" {
        0
    } else {
        refs.len()
    }
}
fn delivery_fingerprint(
    origin: &str,
    text: &str,
    envelope: &str,
    correlation: &str,
    refs: &str,
) -> String {
    if refs == "[]" {
        fingerprint(&[origin, text, envelope, correlation])
    } else {
        fingerprint(&[origin, text, envelope, correlation, refs])
    }
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
    let version: i64 = tx.pragma_query_value(None, "user_version", |row| row.get(0))?;
    if version >= crate::grants::EVENTS_SCHEMA_VERSION {
        crate::event_store::record_expiry(tx, now)?;
    }
    tx.execute(
        "DELETE FROM custody_gap_summary WHERE expires_at<=?1",
        [now],
    )?;
    let expired_observations = {
        let mut query =
            tx.prepare("SELECT observations FROM custody_refusal_summaries WHERE expires_at<=?1")?;
        let mut rows = query.query([now])?;
        let mut total = 0_i64;
        while let Some(row) = rows.next()? {
            total = total.saturating_add(row.get::<_, i64>(0)?);
        }
        total
    };
    tx.execute(
        "DELETE FROM custody_refusal_summaries WHERE expires_at<=?1",
        [now],
    )?;
    tx.execute("UPDATE custody_counters SET value=MIN(9223372036854775807-value,?1)+value WHERE name='expired_metadata'", [expired_observations])?;
    tx.execute("UPDATE custody_links SET expired_first_seen = (SELECT MIN(first_seen) FROM (SELECT expired_first_seen AS first_seen UNION ALL SELECT first_seen FROM custody_pending WHERE bus = custody_links.bus AND expires_at<=?1)) WHERE EXISTS(SELECT 1 FROM custody_pending WHERE bus=custody_links.bus AND expires_at<=?1)", [now])?;
    let pending = tx.execute("DELETE FROM custody_pending WHERE expires_at<=?1", [now])?;
    tx.execute(
        "UPDATE custody_counters SET value=value+?1 WHERE name='expired_pending'",
        [pending as i64],
    )?;
    if version >= crate::grants::EVENTS_SCHEMA_VERSION {
        tx.execute("UPDATE custody_outbox SET state='expired',body=NULL WHERE event_id IN (SELECT event_id FROM custody_items WHERE expires_at<=?1)", [now])?;
    } else {
        tx.execute("UPDATE custody_outbox SET state='expired' WHERE event_id IN (SELECT event_id FROM custody_items WHERE text IS NOT NULL AND expires_at<=?1)", [now])?;
    }
    let redaction = if crate::attachment_store::ready(tx)? {
        "UPDATE custody_items SET text=NULL,envelope=NULL,attachments='[]' WHERE text IS NOT NULL AND expires_at<=?1"
    } else {
        "UPDATE custody_items SET text=NULL, envelope=NULL WHERE text IS NOT NULL AND expires_at<=?1"
    };
    let redacted = tx.execute(redaction, [now])?;
    tx.execute(
        "UPDATE custody_counters SET value=value+?1 WHERE name='expired_content'",
        [redacted as i64],
    )?;
    let cutoff = now.saturating_sub(limits.metadata_retention_secs);
    if version >= crate::grants::EVENTS_SCHEMA_VERSION {
        crate::event_store::prune_expired(tx, cutoff)?;
    }
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
        let marker: i64 = self
            .connection
            .pragma_query_value(None, "application_id", |r| r.get(0))?;
        if marker != crate::grants::SUMMARY_APPLICATION_ID {
            return Err(Error::MigrationRequired);
        }
        self.connection.prepare("SELECT observations,max_size,first_seen,last_seen,expires_at FROM custody_refusal_summaries LIMIT 0")?;
        self.connection
            .prepare("SELECT widest,expires_at,last_expires_at FROM custody_gap_summary LIMIT 0")?;
        Ok(())
    }

    pub fn record_custody_link(
        &mut self,
        scope: &Scope,
        connected: bool,
        limits: &Limits,
        at: SystemTime,
    ) -> Result<(), Error> {
        self.record_bus_link(&scope.bus_instance, connected, limits, at)
    }

    pub(crate) fn record_bus_link(
        &mut self,
        bus: &str,
        connected: bool,
        limits: &Limits,
        at: SystemTime,
    ) -> Result<(), Error> {
        self.require_custody_ready()?;
        let deadlines = limits.windows(at)?;
        let now = deadlines.observed;
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
                let observed_at = UNIX_EPOCH
                    .checked_add(Duration::from_secs(observed as u64))
                    .ok_or(Error::Configuration)?;
                let observation_at = at.max(observed_at);
                let (_, proposed_expiry) =
                    crate::deadline::window(observation_at, limits.metadata_retention_secs)
                        .map_err(|_| Error::Configuration)?;
                record_gap(&tx, bus, start, observed, proposed_expiry)?;
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
        at: SystemTime,
        effective_reply_ttl_secs: i64,
    ) -> Result<Status, Error> {
        self.require_custody_ready()?;
        let now = limits.windows(at)?.observed;
        if effective_reply_ttl_secs <= 0 {
            return Err(Error::Configuration);
        }
        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        expire(&tx, limits, now)?;
        let (held_items, expired_items): (i64, i64) = tx.query_row("SELECT COALESCE(SUM(text IS NOT NULL),0), COALESCE(SUM(text IS NULL),0) FROM custody_items WHERE bus=?1", [&scope.bus_instance], |row| Ok((row.get(0)?, row.get(1)?)))?;
        let (refusals, quarantines): (i64, i64) = tx.query_row("SELECT COALESCE(MAX(CASE WHEN reason!='conflict' THEN observations ELSE 0 END),0), COALESCE(MAX(CASE WHEN reason='conflict' THEN observations ELSE 0 END),0) FROM custody_refusal_summaries WHERE bus=?1", [&scope.bus_instance], |row| Ok((row.get(0)?, row.get(1)?)))?;
        let pending: i64 = tx.query_row(
            "SELECT COUNT(*) FROM custody_pending WHERE bus=?1",
            [&scope.bus_instance],
            |row| row.get(0),
        )?;
        let first_seen: Option<i64> = tx.query_row("SELECT MIN(first_seen) FROM (SELECT first_seen FROM custody_pending WHERE bus=?1 UNION ALL SELECT expired_first_seen FROM custody_links WHERE bus=?1)", [&scope.bus_instance], |row| row.get(0))?;
        let oldest_pending_age_secs = first_seen.map(|first| now.saturating_sub(first).max(0));
        let offline_uncertainty: bool = tx.query_row(
            "SELECT EXISTS(SELECT 1 FROM custody_gap_summary WHERE bus=?1 AND widest>=?3) OR EXISTS(SELECT 1 FROM custody_links WHERE bus=?1 AND (?2-CASE WHEN connected=0 THEN disconnected_at ELSE last_observed_at END)>=?3)",
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
        let gap: Option<(i64,i64,i64,i64,i64)> = tx.query_row("SELECT observations,gap_start,gap_end,widest,widest_expires_at FROM custody_gap_summary WHERE bus=?1",[&scope.bus_instance],|r|Ok((r.get(0)?,r.get(1)?,r.get(2)?,r.get(3)?,r.get(4)?))).optional()?;
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
            coalesced_uncertainty: gap.is_some_and(|g| g.0 > 1 || g.4 <= now),
            gap_observations: gap.map_or(0, |g| g.0),
            gap_first_seen: gap.map(|g| g.1),
            gap_last_seen: gap.map(|g| g.2),
            widest_gap_secs: gap.map(|g| g.3),
            expired_metadata: counter("expired_metadata")?,
            expired_content: counter("expired_content")?,
            expired_tombstones: counter("expired_tombstones")?,
            expired_pending: counter("expired_pending")?,
        };
        tx.commit()?;
        Ok(status)
    }

    pub fn migrate_custody_summaries(&mut self) -> Result<(), Error> {
        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let version: i64 = tx.pragma_query_value(None, "user_version", |r| r.get(0))?;
        let marker: i64 = tx.pragma_query_value(None, "application_id", |r| r.get(0))?;
        if !(CUSTODY_SCHEMA_VERSION..=MAX_SUPPORTED_SCHEMA_VERSION).contains(&version) {
            return Err(Error::MigrationRequired);
        }
        if marker == crate::grants::SUMMARY_APPLICATION_ID {
            return Err(GrantError::NoChange.into());
        }
        create_summaries(&tx)?;
        tx.commit()?;
        Ok(())
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
        create_summaries(&tx)?;
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
        at: SystemTime,
    ) -> Result<Acceptance, Error> {
        let deadlines = limits.windows(at)?;
        let now = deadlines.observed;
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
        let marker: i64 = tx.pragma_query_value(None, "application_id", |r| r.get(0))?;
        if marker != crate::grants::SUMMARY_APPLICATION_ID {
            return Err(Error::MigrationRequired);
        }
        let attachments_ready = crate::attachment_store::ready(&tx)?;
        if !delivery.attachments().is_empty() && !attachments_ready {
            return Err(Error::MigrationRequired);
        }
        if !crate::attachments::validate_refs(delivery.attachments()) {
            return Err(Error::Configuration);
        }
        let refs = serde_json::to_string(delivery.attachments())?;
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
        tx.execute("INSERT OR IGNORE INTO custody_pending(bus,upstream_id,first_seen,expires_at) VALUES (?1,?2,?3,?4)", params![scope.bus_instance, delivery.message_id(), now, deadlines.metadata_expires])?;
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
        let hash = delivery_fingerprint(
            &origin,
            delivery.text(),
            delivery.envelope(),
            &correlation,
            &refs,
        );
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
            .saturating_add(delivery.in_reply_to().map_or(0, str::len))
            .saturating_add(refs_bytes(&refs));
        let stored_refs = if attachments_ready {
            "+CASE WHEN attachments='[]' THEN 0 ELSE length(CAST(attachments AS BLOB)) END"
        } else {
            ""
        };
        let (count,bytes):(i64,i64)=tx.query_row(&format!("SELECT COUNT(*),COALESCE(SUM(length(CAST(text AS BLOB))+length(CAST(envelope AS BLOB))+length(CAST(origin AS BLOB))+COALESCE(length(CAST(in_reply_to AS BLOB)),0){stored_refs}),0) FROM custody_items"),[],|row|Ok((row.get(0)?,row.get(1)?)))?;
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
            let reason = if conflict { "conflict" } else { "refusal" };
            let bounded_size = i64::try_from(size).map_err(|_| Error::Configuration)?;
            tx.execute("INSERT INTO custody_refusal_summaries(bus,reason,observations,max_size,first_seen,last_seen,expires_at) VALUES(?1,?2,1,?5,?3,?3,?4)
                ON CONFLICT(bus,reason) DO UPDATE SET
                observations=CASE WHEN observations<9223372036854775807 THEN observations+1 ELSE observations END,
                max_size=MAX(max_size,excluded.max_size),first_seen=MIN(first_seen,excluded.first_seen),last_seen=MAX(last_seen,excluded.last_seen),expires_at=MAX(expires_at,excluded.expires_at)", params![scope.bus_instance,reason,now,deadlines.metadata_expires,bounded_size])?;
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
        tx.execute("INSERT INTO custody_items (bus,upstream_id,event_id,grant_id,grant_revision,mailbox,owner,origin,text,envelope,in_reply_to,fingerprint,received_at,expires_at,held) VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14,1)", params![scope.bus_instance, delivery.message_id(), event_id, scope.grant_id, revision, mailbox, owner, origin, delivery.text(), delivery.envelope(), delivery.in_reply_to(), hash, now, deadlines.content_expires])?;
        if attachments_ready {
            tx.execute(
                "UPDATE custody_items SET attachments=?1 WHERE bus=?2 AND upstream_id=?3",
                params![refs, scope.bus_instance, delivery.message_id()],
            )?;
        }
        tx.execute(
            "INSERT INTO custody_outbox (event_id,state) VALUES (?1,'held')",
            [&event_id],
        )?;
        if version >= crate::grants::EVENTS_SCHEMA_VERSION {
            crate::event_store::record_acceptance(&tx, &event_id, &scope.grant_id, revision)?;
        }
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
    at: SystemTime,
) -> Result<Option<Acceptance>, Error> {
    store.require_custody_ready()?;
    let polled = match service.poll(0).await {
        Ok(delivery) => {
            store.record_custody_link(scope, true, limits, at)?;
            delivery
        }
        Err(error) => {
            store.record_custody_link(scope, false, limits, at)?;
            return Err(error.into());
        }
    };
    let Some(delivery) = polled else {
        return Ok(None);
    };
    let accepted = store.accept_delivery(scope, service, &delivery, limits, at)?;
    if accepted.can_ack() {
        service.ack(delivery.message_id()).await?;
        store.record_custody_ack(scope, delivery.message_id())?;
    }
    Ok(Some(accepted))
}

#[cfg(test)]
mod retention_tests {
    use super::*;

    fn store() -> (tempfile::TempDir, Store) {
        let directory = tempfile::tempdir().unwrap();
        let mut store = Store::initialize(&directory.path().join("store.db")).unwrap();
        store.migrate_custody().unwrap();
        (directory, store)
    }

    #[test]
    fn rolling_gap_keeps_widest_uncertainty_without_blocking_live_observation() {
        let (_directory, mut store) = store();
        let limits = Limits {
            metadata_retention_secs: 10,
            ..Limits::default()
        };
        let at = |n| UNIX_EPOCH + Duration::from_secs(n);
        store
            .record_bus_link("node", true, &limits, at(100))
            .unwrap();
        store
            .record_bus_link("node", true, &limits, at(120))
            .unwrap();
        for second in 121..=145 {
            store
                .record_bus_link("node", true, &limits, at(second))
                .unwrap();
        }
        let scope = Scope {
            bus_instance: "node".into(),
            grant_id: "unused".into(),
        };
        let status = store.custody_status(&scope, &limits, at(145), 15).unwrap();
        assert!(
            status.offline_uncertainty,
            "summary forgot the widest interval"
        );
        assert!(
            status.coalesced_uncertainty,
            "rolling witness lost coalesced uncertainty"
        );
        assert_eq!(status.widest_gap_secs, Some(20));
        assert_eq!(status.gap_observations, 26);
        assert!(
            !status.possible_known_loss,
            "summary fabricated a known message loss"
        );
        store
            .record_bus_link("node", true, &limits, at(146))
            .expect("stale widest witness blocked live readiness");
    }

    #[test]
    fn summaries_saturate_without_breaking_status_or_expiry() {
        let (_directory, mut store) = store();
        let limits = Limits::default();
        store
            .record_bus_link("node", true, &limits, UNIX_EPOCH + Duration::from_secs(100))
            .unwrap();
        store.connection.execute_batch("INSERT INTO custody_refusal_summaries VALUES ('node','conflict',9223372036854775807,1,1,2,200),('node','refusal',9223372036854775807,1,1,2,200);").unwrap();
        store
            .record_bus_link("node", true, &limits, UNIX_EPOCH + Duration::from_secs(101))
            .unwrap();
        store
            .connection
            .execute(
                "UPDATE custody_gap_summary SET observations=9223372036854775807",
                [],
            )
            .unwrap();
        store
            .record_bus_link("node", true, &limits, UNIX_EPOCH + Duration::from_secs(102))
            .unwrap();
        let count: i64 = store
            .connection
            .query_row("SELECT observations FROM custody_gap_summary", [], |r| {
                r.get(0)
            })
            .unwrap();
        assert_eq!(count, i64::MAX, "gap observation count did not saturate");
        let scope = Scope {
            bus_instance: "node".into(),
            grant_id: "unused".into(),
        };
        let status = store
            .custody_status(&scope, &limits, UNIX_EPOCH + Duration::from_secs(101), 15)
            .unwrap();
        assert_eq!((status.refusals, status.quarantines), (i64::MAX, i64::MAX));
        let status = store
            .custody_status(&scope, &limits, UNIX_EPOCH + Duration::from_secs(200), 15)
            .unwrap();
        assert_eq!(
            status.expired_metadata,
            i64::MAX,
            "expiry total did not saturate"
        );
        store.connection.execute_batch("UPDATE custody_counters SET value=0 WHERE name='expired_metadata'; INSERT INTO custody_refusal_summaries VALUES ('node','refusal',9007199254740993,1,1,2,300);").unwrap();
        let status = store
            .custody_status(&scope, &limits, UNIX_EPOCH + Duration::from_secs(300), 15)
            .unwrap();
        assert_eq!(
            status.expired_metadata, 9007199254740993,
            "expiry total lost integer precision"
        );
    }

    #[test]
    fn explicit_summary_migration_preserves_history_and_rolls_back_failure() {
        let (directory, mut store) = store();
        store.connection.execute_batch("DROP TABLE custody_refusal_summaries; DROP TABLE custody_gap_summary;
            INSERT INTO custody_metadata VALUES ('node','one','hash-one','origin',1,'conflict',10,800),('node','two','hash-two','origin',1,'oversized',20,900);
            INSERT INTO custody_gaps VALUES ('node',1,101,800),('node',200,201,900);
            INSERT INTO custody_items VALUES ('node','accepted','event','grant',1,'mailbox','owner','origin','original body','envelope',NULL,'original fingerprint',10,1000,1);
            INSERT INTO custody_pending VALUES ('node','pending',10,900);
            CREATE TRIGGER fail_fold BEFORE DELETE ON custody_metadata BEGIN SELECT RAISE(ABORT,'forced fold failure'); END;").unwrap();
        store
            .connection
            .execute("INSERT INTO custody_outbox VALUES ('event','held')", [])
            .unwrap();
        fn unchanged_rows(store: &Store) -> Vec<Vec<rusqlite::types::Value>> {
            [
                "custody_items",
                "custody_pending",
                "custody_outbox",
                "grants",
                "custody_links",
                "custody_counters",
            ]
            .iter()
            .flat_map(|table| {
                let mut query = store
                    .connection
                    .prepare(&format!("SELECT * FROM {table} ORDER BY 1"))
                    .unwrap();
                let columns = query.column_count();
                query
                    .query_map([], |r| (0..columns).map(|n| r.get(n)).collect())
                    .unwrap()
                    .collect::<Result<Vec<Vec<rusqlite::types::Value>>, _>>()
                    .unwrap()
            })
            .collect()
        }
        let original = unchanged_rows(&store);
        store
            .connection
            .pragma_update(
                None,
                "application_id",
                crate::grants::RETIREMENT_APPLICATION_ID,
            )
            .unwrap();
        assert!(store.migrate_custody_summaries().is_err());
        let marker: i64 = store
            .connection
            .pragma_query_value(None, "application_id", |r| r.get(0))
            .unwrap();
        assert_eq!(
            marker,
            crate::grants::RETIREMENT_APPLICATION_ID,
            "failed fold changed writer marker"
        );
        assert!(
            store
                .connection
                .prepare("SELECT * FROM custody_gap_summary")
                .is_err(),
            "failed fold retained partial schema"
        );
        let old: i64 = store
            .connection
            .query_row("SELECT COUNT(*) FROM custody_metadata", [], |r| r.get(0))
            .unwrap();
        assert_eq!(old, 2, "failed fold dropped durable evidence");
        store
            .connection
            .execute_batch("DROP TRIGGER fail_fold")
            .unwrap();
        store.migrate_custody_summaries().unwrap();
        assert_eq!(unchanged_rows(&store),original,"migration changed accepted content, original fingerprints, pending IDs, outbox or authority");
        let marker: i64 = store
            .connection
            .pragma_query_value(None, "application_id", |r| r.get(0))
            .unwrap();
        assert_ne!(marker, crate::grants::LEGACY_APPLICATION_ID);
        assert_ne!(
            marker,
            crate::grants::RETIREMENT_APPLICATION_ID,
            "old reader accepts summary store"
        );
        let content: (String, String) = store
            .connection
            .query_row("SELECT text,fingerprint FROM custody_items", [], |r| {
                Ok((r.get(0)?, r.get(1)?))
            })
            .unwrap();
        assert_eq!(
            content,
            ("original body".into(), "original fingerprint".into())
        );
        let summary: (i64, i64, i64) = store
            .connection
            .query_row(
                "SELECT observations,widest,expires_at FROM custody_gap_summary",
                [],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
            )
            .unwrap();
        assert_eq!(
            summary,
            (2, 100, 900),
            "migration lost widest or retained expiry"
        );
        let pending: i64 = store
            .connection
            .query_row("SELECT COUNT(*) FROM custody_pending", [], |r| r.get(0))
            .unwrap();
        assert_eq!(pending, 1);
        drop(store);
        Store::open(&directory.path().join("store.db")).unwrap();
    }

    #[test]
    fn thousand_shrinking_gaps_keep_observation_ready() {
        let (_directory, mut store) = store();
        let limits = Limits::default();
        let mut seconds = 100;
        store
            .record_bus_link(
                "node",
                true,
                &limits,
                UNIX_EPOCH + Duration::from_secs(seconds),
            )
            .unwrap();
        for width in (1..=1001).rev() {
            seconds += width;
            assert!(
                store
                    .record_bus_link(
                        "node",
                        true,
                        &limits,
                        UNIX_EPOCH + Duration::from_secs(seconds)
                    )
                    .is_ok(),
                "shrinking gaps exhausted readiness at width {width}"
            );
        }
        let count: i64 = store
            .connection
            .query_row("SELECT COUNT(*) FROM custody_gap_summary", [], |r| r.get(0))
            .unwrap();
        assert_eq!(count, 1, "gap summary row bound missing");
    }

    #[test]
    fn fractional_gap_retention_preserves_the_complete_lifetime() {
        for nanos in [1, 999_999_999] {
            for lifetime in [1, 86_400] {
                let (_directory, mut store) = store();
                let limits = Limits {
                    metadata_retention_secs: lifetime,
                    ..Limits::default()
                };
                store
                    .record_bus_link("node", true, &limits, UNIX_EPOCH + Duration::from_secs(100))
                    .unwrap();
                let at = UNIX_EPOCH + Duration::new(101, nanos);
                store.record_bus_link("node", false, &limits, at).unwrap();
                let expires: i64 = store
                    .connection
                    .query_row("SELECT expires_at FROM custody_gap_summary", [], |row| {
                        row.get(0)
                    })
                    .unwrap();
                let remaining = (UNIX_EPOCH + Duration::from_secs(expires as u64))
                    .duration_since(at)
                    .unwrap();
                assert!(remaining >= Duration::from_secs(lifetime as u64));
                assert!(remaining < Duration::from_secs(lifetime as u64 + 1));
                let scope = Scope {
                    bus_instance: "node".into(),
                    grant_id: "unused".into(),
                };
                store
                    .custody_status(
                        &scope,
                        &limits,
                        at + Duration::from_secs(lifetime as u64),
                        604800,
                    )
                    .unwrap();
                let visible: i64 = store
                    .connection
                    .query_row("SELECT COUNT(*) FROM custody_gap_summary", [], |row| {
                        row.get(0)
                    })
                    .unwrap();
                assert_eq!(visible, 1, "gap expired before its guaranteed lifetime");
                store
                    .custody_status(
                        &scope,
                        &limits,
                        at + Duration::from_secs(lifetime as u64 + 1),
                        604800,
                    )
                    .unwrap();
                let visible: i64 = store
                    .connection
                    .query_row("SELECT COUNT(*) FROM custody_gap_summary", [], |row| {
                        row.get(0)
                    })
                    .unwrap();
                assert_eq!(visible, 0, "expired gap remained observable");
            }
        }
    }

    #[test]
    fn repeated_gap_observations_never_extend_the_stored_expiry() {
        let (_directory, mut store) = store();
        let mut limits = Limits {
            metadata_retention_secs: 1,
            ..Limits::default()
        };
        store
            .record_bus_link("node", true, &limits, UNIX_EPOCH + Duration::from_secs(100))
            .unwrap();
        store
            .record_bus_link(
                "node",
                false,
                &limits,
                UNIX_EPOCH + Duration::from_secs(101),
            )
            .unwrap();
        limits.metadata_retention_secs = 10;
        store
            .record_bus_link(
                "node",
                false,
                &limits,
                UNIX_EPOCH + Duration::new(101, 999_999_999),
            )
            .unwrap();
        let (count, expires, last_expires, widest_expires): (i64, i64, i64, i64) = store
            .connection
            .query_row(
                "SELECT COUNT(*), MIN(expires_at), MIN(last_expires_at), MIN(widest_expires_at) FROM custody_gap_summary",
                [],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
            )
            .unwrap();
        assert_eq!(
            (count, expires, last_expires, widest_expires),
            (1, 102, 102, 102),
            "repeat extended the same gap's retention"
        );
    }
}

#[cfg(test)]
mod expiry_boundary_tests {
    use super::*;

    fn boundary(site: &str) {
        for nanos in [1, 999_999_999] {
            let directory = tempfile::tempdir().unwrap();
            let mut store = Store::initialize(&directory.path().join("store.db")).unwrap();
            store.migrate_custody().unwrap();
            let limits = Limits {
                content_retention_secs: 3,
                metadata_retention_secs: 3,
                ..Limits::default()
            };
            let at = UNIX_EPOCH + Duration::new(100, nanos);
            let (created, expiry) = crate::deadline::window(at, 3).unwrap();
            let scope = Scope {
                bus_instance: "boundary-node".into(),
                grant_id: "fixture".into(),
            };
            store
                .record_custody_link(&scope, true, &limits, at)
                .unwrap();
            // Persisted fixture rows exercise the public maintenance API without a daemon or a Delivery constructor.
            store
                .connection
                .execute(
                    "INSERT INTO custody_gap_summary VALUES (?1,1,99,100,1,?2,?2,99,100,?2)",
                    params![scope.bus_instance, expiry],
                )
                .unwrap();
            store
                .connection
                .execute(
                    "INSERT INTO custody_pending VALUES (?1,'message',?2,?3)",
                    params![scope.bus_instance, created, expiry],
                )
                .unwrap();
            store
                .connection
                .execute(
                    "INSERT INTO custody_refusal_summaries VALUES (?1,'refusal',1,1,?2,?2,?3)",
                    params![scope.bus_instance, created, expiry],
                )
                .unwrap();
            store.connection.execute("INSERT INTO custody_items VALUES (?1,'message','event','fixture',1,'gateway','owner','origin','body','envelope',NULL,'fingerprint',?2,?3,1)", params![scope.bus_instance, created, expiry]).unwrap();
            store
                .connection
                .execute("INSERT INTO custody_outbox VALUES ('event','held')", [])
                .unwrap();
            let observed = |second: i64| UNIX_EPOCH + Duration::new(second as u64, 999_999_999);
            let before = store
                .custody_status(&scope, &limits, observed(expiry - 1), 604800)
                .unwrap();
            assert_eq!(
                (before.pending, before.refusals, before.held_items),
                (1, 1, 1)
            );
            let gap_count = |store: &Store| -> i64 {
                store
                    .connection
                    .query_row("SELECT COUNT(*) FROM custody_gap_summary", [], |row| {
                        row.get(0)
                    })
                    .unwrap()
            };
            let outbox = |store: &Store| -> String {
                store
                    .connection
                    .query_row("SELECT state FROM custody_outbox", [], |row| row.get(0))
                    .unwrap()
            };
            assert_eq!(gap_count(&store), 1);
            assert_eq!(outbox(&store), "held");
            let expired = store
                .custody_status(&scope, &limits, observed(expiry), 604800)
                .unwrap();
            match site {
                "gaps" => assert_eq!(gap_count(&store), 0, "gap remained visible at expiry"),
                "pending" => {
                    assert_eq!(expired.pending, 0, "pending ID remained visible at expiry");
                    assert_eq!(
                        expired.oldest_pending_age_secs,
                        Some(expiry - created),
                        "expired pending uncertainty summary missing at expiry"
                    );
                }
                "metadata" => {
                    assert_eq!(expired.refusals, 0, "metadata remained visible at expiry")
                }
                "content" => {
                    assert_eq!(expired.held_items, 0, "content remained visible at expiry")
                }
                "outbox" => assert_eq!(outbox(&store), "expired", "outbox remained held at expiry"),
                "tombstones" => {
                    let count = |store: &Store, table: &str| -> i64 {
                        store
                            .connection
                            .query_row(&format!("SELECT COUNT(*) FROM {table}"), [], |row| {
                                row.get(0)
                            })
                            .unwrap()
                    };
                    let cutoff = expiry + limits.metadata_retention_secs;
                    store
                        .custody_status(&scope, &limits, observed(cutoff - 1), 604800)
                        .unwrap();
                    assert_eq!(count(&store, "custody_items"), 1);
                    assert_eq!(count(&store, "custody_outbox"), 1);
                    store
                        .custody_status(&scope, &limits, observed(cutoff), 604800)
                        .unwrap();
                    assert_eq!(
                        count(&store, "custody_items"),
                        0,
                        "tombstone remained visible at cutoff"
                    );
                    assert_eq!(
                        count(&store, "custody_outbox"),
                        0,
                        "tombstone outbox remained visible at cutoff"
                    );
                }
                _ => panic!("unknown expiry site"),
            }
        }
    }

    #[test]
    fn gaps_expire_at_the_observed_boundary() {
        boundary("gaps");
    }
    #[test]
    fn pending_ids_expire_at_the_observed_boundary() {
        boundary("pending");
    }
    #[test]
    fn refusal_metadata_expires_at_the_observed_boundary() {
        boundary("metadata");
    }
    #[test]
    fn held_content_expires_at_the_observed_boundary() {
        boundary("content");
    }
    #[test]
    fn outbox_expires_at_the_observed_boundary() {
        boundary("outbox");
    }
    #[test]
    fn tombstones_expire_at_the_observed_cutoff() {
        boundary("tombstones");
    }
}

#[cfg(all(test, unix))]
mod attachment_custody_tests {
    use super::*;
    use std::os::unix::fs::{MetadataExt, PermissionsExt};
    use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
    use xmsg::client::{AttachmentRef, ClientOptions};
    struct Feed {
        _directory: tempfile::TempDir,
        service: RegisteredService,
        delivery: Delivery,
        worker: tokio::task::JoinHandle<()>,
    }
    impl Drop for Feed {
        fn drop(&mut self) {
            self.worker.abort();
        }
    }
    impl Feed {
        async fn new(id: &str, refs: Vec<AttachmentRef>) -> Self {
            let directory = tempfile::tempdir().unwrap();
            std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o700))
                .unwrap();
            let socket = directory.path().join("register.sock");
            let listener = tokio::net::UnixListener::bind(&socket).unwrap();
            std::fs::set_permissions(&socket, std::fs::Permissions::from_mode(0o600)).unwrap();
            let id = id.to_string();
            let worker = tokio::spawn(async move {
                let (stream, _) = listener.accept().await.unwrap();
                let mut stream = BufReader::new(stream);
                let mut line = String::new();
                stream.read_line(&mut line).await.unwrap();
                stream
                    .get_mut()
                    .write_all(
                        b"{\"status\":\"ok\",\"address\":\"gateway@node\",\"node\":\"node\"}\n",
                    )
                    .await
                    .unwrap();
                line.clear();
                stream.read_line(&mut line).await.unwrap();
                let value = serde_json::json!({"action":"deliver","messageId":id,"fromName":"source","text":"body","envelope":"envelope","origin":{"service":"source","node":"peer"},"inReplyTo":null,"attachments":refs});
                stream
                    .get_mut()
                    .write_all(format!("{value}\n").as_bytes())
                    .await
                    .unwrap();
                line.clear();
                let _ = stream.read_line(&mut line).await;
            });
            let mut service = RegisteredService::register(ClientOptions {
                register_socket: socket,
                agent_socket: directory.path().join("agent.sock"),
                max_frame_bytes: 1048576,
                operation_timeout: Duration::from_secs(2),
                service: "gateway".into(),
                expected_node: Some("node".into()),
                daemon_uid: std::fs::metadata(directory.path()).unwrap().uid(),
            })
            .await
            .unwrap();
            let delivery = service.poll(0).await.unwrap().unwrap();
            Self {
                _directory: directory,
                service,
                delivery,
                worker,
            }
        }
    }
    fn reference(name: &str) -> AttachmentRef {
        AttachmentRef {
            name: name.into(),
            size: 4,
            media_type: "text/plain".into(),
            sha256: "a".repeat(64),
        }
    }
    fn store() -> (tempfile::TempDir, Store) {
        let directory = tempfile::tempdir().unwrap();
        let mut store = Store::initialize(&directory.path().join("authority.db")).unwrap();
        store
            .enroll(
                "grant",
                &crate::grants::Binding {
                    service: "gateway".into(),
                    issuer: "https://issuer.example".into(),
                    resource: "https://gateway.example/mcp".into(),
                    subject: "owner".into(),
                    hosted_client: "client".into(),
                },
            )
            .unwrap();
        store.migrate_custody().unwrap();
        store.migrate_outbound().unwrap();
        (directory, store)
    }
    fn scope() -> Scope {
        Scope {
            bus_instance: "bus".into(),
            grant_id: "grant".into(),
        }
    }
    #[test]
    fn m12_refs_change_custody_identity_without_changing_legacy_hashes() {
        assert_eq!(
            delivery_fingerprint("origin", "text", "envelope", "null", "[]"),
            fingerprint(&["origin", "text", "envelope", "null"])
        );
        let first = serde_json::to_string(&vec![reference("first.txt")]).unwrap();
        let second = serde_json::to_string(&vec![reference("second.txt")]).unwrap();
        assert_ne!(
            delivery_fingerprint("origin", "text", "envelope", "null", &first),
            delivery_fingerprint("origin", "text", "envelope", "null", &second),
            "M12: attachment-only changed delivery collided with accepted fingerprint"
        );
    }
    #[tokio::test]
    async fn refs_require_migration_and_commit_with_content_then_redact() {
        let feed = Feed::new("item", vec![reference("first.txt")]).await;
        let (_directory, mut store) = store();
        let limits = Limits {
            content_retention_secs: 10,
            ..Limits::default()
        };
        assert!(matches!(
            store.accept_delivery(
                &scope(),
                &feed.service,
                &feed.delivery,
                &limits,
                UNIX_EPOCH + Duration::from_secs(100)
            ),
            Err(Error::MigrationRequired)
        ));
        assert_eq!(
            store
                .connection
                .query_row("SELECT COUNT(*) FROM custody_items", [], |r| r
                    .get::<_, i64>(0))
                .unwrap(),
            0
        );
        store.migrate_attachments().unwrap();
        assert!(matches!(
            store
                .accept_delivery(
                    &scope(),
                    &feed.service,
                    &feed.delivery,
                    &limits,
                    UNIX_EPOCH + Duration::from_secs(100)
                )
                .unwrap(),
            Acceptance::Stored { .. }
        ));
        let first: (String, String) = store
            .connection
            .query_row(
                "SELECT attachments,fingerprint FROM custody_items",
                [],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .unwrap();
        assert_eq!(
            serde_json::from_str::<Vec<AttachmentRef>>(&first.0).unwrap(),
            vec![reference("first.txt")]
        );
        assert!(matches!(
            store
                .accept_delivery(
                    &scope(),
                    &feed.service,
                    &feed.delivery,
                    &limits,
                    UNIX_EPOCH + Duration::from_secs(101)
                )
                .unwrap(),
            Acceptance::Duplicate { .. }
        ));
        let changed = Feed::new("item", vec![reference("second.txt")]).await;
        assert_eq!(
            store
                .accept_delivery(
                    &scope(),
                    &changed.service,
                    &changed.delivery,
                    &limits,
                    UNIX_EPOCH + Duration::from_secs(102)
                )
                .unwrap(),
            Acceptance::Quarantined,
            "M12: attachment-only changed frame was not quarantined"
        );
        store
            .record_custody_link(
                &scope(),
                true,
                &limits,
                UNIX_EPOCH + Duration::from_secs(111),
            )
            .unwrap();
        let after: (String, String, Option<String>) = store
            .connection
            .query_row(
                "SELECT attachments,fingerprint,text FROM custody_items",
                [],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
            )
            .unwrap();
        assert_eq!(after, ("[]".into(), first.1, None));
    }
    #[tokio::test]
    async fn refs_are_billed_in_both_item_and_total_capacity() {
        let feed = Feed::new("first", vec![reference("file.txt")]).await;
        let origin =
            serde_json::to_string(&serde_json::json!({"id":null,"service":"source","node":"peer"}))
                .unwrap();
        let plain = origin.len() + "body".len() + "envelope".len();
        let size = plain
            + serde_json::to_string(feed.delivery.attachments())
                .unwrap()
                .len();
        let (_directory, mut store) = store();
        store.migrate_attachments().unwrap();
        let mut limits = Limits {
            max_item_bytes: plain as i64,
            ..Limits::default()
        };
        assert_eq!(
            store
                .accept_delivery(
                    &scope(),
                    &feed.service,
                    &feed.delivery,
                    &limits,
                    UNIX_EPOCH + Duration::from_secs(100)
                )
                .unwrap(),
            Acceptance::Refused,
            "refs missing from individual retained byte bound"
        );
        limits.max_item_bytes = 100000;
        limits.max_bytes = (size * 2 - 1) as i64;
        assert!(matches!(
            store
                .accept_delivery(
                    &scope(),
                    &feed.service,
                    &feed.delivery,
                    &limits,
                    UNIX_EPOCH + Duration::from_secs(101)
                )
                .unwrap(),
            Acceptance::Stored { .. }
        ));
        let second = Feed::new("second", vec![reference("file.txt")]).await;
        assert_eq!(
            store
                .accept_delivery(
                    &scope(),
                    &second.service,
                    &second.delivery,
                    &limits,
                    UNIX_EPOCH + Duration::from_secs(102)
                )
                .unwrap(),
            Acceptance::Deferred,
            "refs missing from aggregate retained byte bound"
        );
        assert_eq!(
            store
                .connection
                .query_row("SELECT COUNT(*) FROM custody_items", [], |r| r
                    .get::<_, i64>(0))
                .unwrap(),
            1
        );
    }
}
