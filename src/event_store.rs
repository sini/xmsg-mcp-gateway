//! Durable Events authority, encryption and explicit schema migration.
use std::fs;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::Path;

use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use rusqlite::{params, Connection, Transaction, TransactionBehavior};

use crate::grants::{Error as GrantError, Store, EVENTS_SCHEMA_VERSION};

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("Events schema requires an explicit owner migration")]
    MigrationRequired,
    #[error("Events encryption key is missing, invalid or does not match this store")]
    Key,
    #[error("Events state is unavailable")]
    Database(#[from] rusqlite::Error),
    #[error(transparent)]
    Authority(#[from] GrantError),
}

#[derive(Clone)]
pub struct EventKey {
    bytes: [u8; 32],
    owner: u32,
}
impl EventKey {
    pub fn load(file: &Path) -> Result<Self, Error> {
        let metadata = fs::symlink_metadata(file).map_err(|_| Error::Key)?;
        let parent = file.parent().ok_or(Error::Key)?;
        let directory = parent.metadata().map_err(|_| Error::Key)?;
        if !metadata.is_file()
            || metadata.permissions().mode() & 0o777 != 0o600
            || metadata.len() != 32
            || !directory.is_dir()
            || directory.mode() & 0o022 != 0
            || metadata.uid() != directory.uid()
        {
            return Err(Error::Key);
        }
        let bytes = fs::read(file).map_err(|_| Error::Key)?;
        Ok(Self {
            bytes: bytes.try_into().map_err(|_| Error::Key)?,
            owner: metadata.uid(),
        })
    }

    pub fn seal(&self, context: &str, bytes: &[u8]) -> Result<Vec<u8>, Error> {
        let cipher = XChaCha20Poly1305::new((&self.bytes).into());
        let mut nonce = [0u8; 24];
        getrandom::fill(&mut nonce).map_err(|_| Error::Key)?;
        let encrypted = cipher
            .encrypt(
                XNonce::from_slice(&nonce),
                Payload {
                    msg: bytes,
                    aad: context.as_bytes(),
                },
            )
            .map_err(|_| Error::Key)?;
        let mut sealed = nonce.to_vec();
        sealed.extend(encrypted);
        Ok(sealed)
    }

    pub fn open(&self, context: &str, sealed: &[u8]) -> Result<Vec<u8>, Error> {
        if sealed.len() < 40 {
            return Err(Error::Key);
        }
        XChaCha20Poly1305::new((&self.bytes).into())
            .decrypt(
                XNonce::from_slice(&sealed[..24]),
                Payload {
                    msg: &sealed[24..],
                    aad: context.as_bytes(),
                },
            )
            .map_err(|_| Error::Key)
    }
}

pub(crate) fn validate_schema(db: &Connection) -> Result<(), GrantError> {
    db.prepare("SELECT grant_id,ever_enabled FROM grants_event_history LIMIT 0")?;
    db.prepare("SELECT event_id,acceptance_enabled,acceptance_ever_enabled,acceptance_class,dispatch_revision FROM event_authorizations LIMIT 0")?;
    db.prepare("SELECT seq,event_id FROM event_occurrences LIMIT 0")?;
    db.prepare("SELECT event_id,attempts,next_attempt,body,last_error,subscription_generation FROM custody_outbox LIMIT 0")?;
    db.prepare("SELECT id,owner_key,service,issuer,resource,subject,hosted_client,bus,mailbox,grant_id,grant_revision,generation,expires,url,secret,old_secret,bearer,rotation_until,status,verified_at,callback_cursor,observation_checkpoint FROM event_subscriptions LIMIT 0")?;
    db.prepare("SELECT event_id,observed_at FROM event_observations LIMIT 0")?;
    db.prepare("SELECT owner_key,unavailable_through FROM event_availability LIMIT 0")?;
    db.prepare("SELECT event_id,grant_id,old_revision,new_revision,operator,reason FROM event_release_audit LIMIT 0")?;
    db.prepare("SELECT subscription_id,old_generation,new_generation,operator,reason,replay_after FROM event_binding_audit LIMIT 0")?;
    db.prepare("SELECT id,value FROM event_key_check LIMIT 0")?;
    Ok(())
}

impl Store {
    pub fn require_events_ready(&self, key: &EventKey) -> Result<(), Error> {
        let version: i64 = self
            .connection
            .pragma_query_value(None, "user_version", |r| r.get(0))?;
        if version != EVENTS_SCHEMA_VERSION {
            return Err(Error::MigrationRequired);
        }
        validate_schema(&self.connection)?;
        if self.file.metadata().map_err(|_| Error::Key)?.uid() != key.owner {
            return Err(Error::Key);
        }
        let sealed: Vec<u8> =
            self.connection
                .query_row("SELECT value FROM event_key_check WHERE id=1", [], |r| {
                    r.get(0)
                })?;
        if key.open("events/key-check/v1", &sealed)? != b"xmsg-events-key-v1" {
            return Err(Error::Key);
        }
        Ok(())
    }

    pub fn migrate_events(&mut self, key: &EventKey) -> Result<(), Error> {
        if self.file.metadata().map_err(|_| Error::Key)?.uid() != key.owner {
            return Err(Error::Key);
        }
        let check = key.seal("events/key-check/v1", b"xmsg-events-key-v1")?;
        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let version: i64 = tx.pragma_query_value(None, "user_version", |r| r.get(0))?;
        if version != EVENTS_SCHEMA_VERSION - 1 {
            return Err(GrantError::NoChange.into());
        }
        tx.execute_batch("CREATE TABLE grants_event_history (
            grant_id TEXT PRIMARY KEY NOT NULL REFERENCES grants(id),
            ever_enabled INTEGER CHECK(ever_enabled IN (0,1)));
            INSERT INTO grants_event_history SELECT id,CASE WHEN enabled=1 THEN 1 ELSE NULL END FROM grants;
            CREATE TABLE event_authorizations (
              event_id TEXT PRIMARY KEY NOT NULL,
              acceptance_enabled INTEGER CHECK(acceptance_enabled IN (0,1)),
              acceptance_ever_enabled INTEGER CHECK(acceptance_ever_enabled IN (0,1)),
              acceptance_class TEXT NOT NULL CHECK(acceptance_class IN ('unknown','never_enabled','current','previous')),
              dispatch_revision INTEGER CHECK(dispatch_revision>0));
            INSERT INTO event_authorizations(event_id,acceptance_class) SELECT event_id,'unknown' FROM custody_items;
            CREATE TABLE event_occurrences (
              seq INTEGER PRIMARY KEY AUTOINCREMENT, event_id TEXT NOT NULL UNIQUE);
            INSERT INTO event_occurrences(event_id) SELECT event_id FROM custody_items ORDER BY rowid;
            ALTER TABLE custody_outbox RENAME TO custody_outbox_old;
            CREATE TABLE custody_outbox (
              event_id TEXT PRIMARY KEY NOT NULL,
              state TEXT NOT NULL CHECK(state IN ('held','pending','dispatching','accepted','dead','expired')),
              attempts INTEGER NOT NULL DEFAULT 0 CHECK(attempts>=0),
              next_attempt INTEGER NOT NULL DEFAULT 0,
              body BLOB, last_error TEXT, subscription_generation INTEGER);
            INSERT INTO custody_outbox(event_id,state) SELECT event_id,state FROM custody_outbox_old;
            DROP TABLE custody_outbox_old;
            CREATE TABLE event_subscriptions (
              id TEXT PRIMARY KEY NOT NULL, owner_key TEXT NOT NULL UNIQUE,
              service TEXT NOT NULL, issuer TEXT NOT NULL, resource TEXT NOT NULL,
              subject TEXT NOT NULL, hosted_client TEXT NOT NULL,
              bus TEXT NOT NULL, mailbox TEXT NOT NULL,
              grant_id TEXT NOT NULL, grant_revision INTEGER NOT NULL,
              generation INTEGER NOT NULL CHECK(generation>0), expires INTEGER NOT NULL,
              url BLOB NOT NULL, secret BLOB NOT NULL, old_secret BLOB, bearer BLOB NOT NULL,
              rotation_until INTEGER NOT NULL DEFAULT 0,
              status TEXT NOT NULL CHECK(status IN ('verifying','active','disabled')),
              verified_at INTEGER, callback_cursor INTEGER NOT NULL DEFAULT 0,
              observation_checkpoint INTEGER NOT NULL DEFAULT 0);
            CREATE TABLE event_observations(event_id TEXT PRIMARY KEY NOT NULL,observed_at INTEGER NOT NULL);
            CREATE TABLE event_availability(owner_key TEXT PRIMARY KEY NOT NULL,unavailable_through INTEGER NOT NULL DEFAULT 0);
            CREATE TABLE event_release_audit (
              seq INTEGER PRIMARY KEY AUTOINCREMENT,event_id TEXT NOT NULL,grant_id TEXT NOT NULL,
              old_revision INTEGER NOT NULL,new_revision INTEGER NOT NULL,
              operator TEXT NOT NULL,reason TEXT NOT NULL);
            CREATE TABLE event_binding_audit (
              seq INTEGER PRIMARY KEY AUTOINCREMENT,subscription_id TEXT NOT NULL,
              old_generation INTEGER NOT NULL,new_generation INTEGER NOT NULL,
              operator TEXT NOT NULL,reason TEXT NOT NULL,replay_after INTEGER NOT NULL);
            CREATE TABLE event_key_check(id INTEGER PRIMARY KEY CHECK(id=1),value BLOB NOT NULL);")?;
        tx.execute("INSERT INTO event_key_check VALUES (1,?1)", [check])?;
        tx.pragma_update(None, "user_version", EVENTS_SCHEMA_VERSION)?;
        tx.commit()?;
        Ok(())
    }
}

pub(crate) fn record_acceptance(
    tx: &Transaction<'_>,
    event_id: &str,
    grant_id: &str,
    revision: i64,
) -> Result<(), rusqlite::Error> {
    let (enabled, ever): (bool, Option<bool>) = tx.query_row(
        "SELECT g.enabled,h.ever_enabled FROM grants g JOIN grants_event_history h ON h.grant_id=g.id WHERE g.id=?1 AND g.revision=?2",
        params![grant_id,revision], |r| Ok((r.get(0)?,r.get(1)?)))?;
    let class = if enabled {
        "current"
    } else if ever == Some(false) {
        "never_enabled"
    } else if ever == Some(true) {
        "previous"
    } else {
        "unknown"
    };
    tx.execute("INSERT INTO event_authorizations(event_id,acceptance_enabled,acceptance_ever_enabled,acceptance_class,dispatch_revision) VALUES (?1,?2,?3,?4,?5)", params![event_id,enabled,ever,class,enabled.then_some(revision)])?;
    tx.execute(
        "INSERT INTO event_occurrences(event_id) VALUES (?1)",
        [event_id],
    )?;
    if enabled {
        tx.execute(
            "UPDATE custody_outbox SET state='pending' WHERE event_id=?1",
            [event_id],
        )?;
    }
    Ok(())
}

pub(crate) fn enabled_transition(
    tx: &Transaction<'_>,
    id: &str,
    next: i64,
    enabled: bool,
) -> Result<(), rusqlite::Error> {
    revision_changed(tx, id)?;
    if enabled {
        let first: bool = tx.query_row(
            "SELECT ever_enabled=0 FROM grants_event_history WHERE grant_id=?1",
            [id],
            |r| r.get::<_, Option<bool>>(0).map(|v| v.unwrap_or(false)),
        )?;
        if first {
            tx.execute("INSERT INTO event_release_audit(event_id,grant_id,old_revision,new_revision,operator,reason) SELECT c.event_id,c.grant_id,c.grant_revision,?2,'local-owner','first-enable' FROM custody_items c JOIN event_authorizations a ON a.event_id=c.event_id WHERE c.grant_id=?1 AND a.acceptance_class='never_enabled' AND a.acceptance_enabled=0 AND a.acceptance_ever_enabled=0 AND a.dispatch_revision IS NULL", params![id,next])?;
            tx.execute("UPDATE event_authorizations SET dispatch_revision=?2 WHERE event_id IN (SELECT c.event_id FROM custody_items c WHERE c.grant_id=?1) AND acceptance_class='never_enabled' AND acceptance_enabled=0 AND acceptance_ever_enabled=0 AND dispatch_revision IS NULL", params![id,next])?;
            tx.execute("UPDATE custody_outbox SET state='pending' WHERE state='held' AND event_id IN (SELECT c.event_id FROM custody_items c JOIN event_authorizations a ON a.event_id=c.event_id WHERE c.grant_id=?1 AND a.dispatch_revision=?2)", params![id,next])?;
        }
        tx.execute(
            "UPDATE grants_event_history SET ever_enabled=1 WHERE grant_id=?1",
            [id],
        )?;
    }
    Ok(())
}

pub(crate) fn revision_changed(tx: &Transaction<'_>, id: &str) -> Result<(), rusqlite::Error> {
    tx.execute("UPDATE custody_outbox SET state='held' WHERE state IN ('pending','dispatching') AND event_id IN (SELECT event_id FROM custody_items WHERE grant_id=?1)", [id])?;
    tx.execute("UPDATE event_subscriptions SET status='disabled',generation=generation+1 WHERE grant_id=?1", [id])?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::grants::Binding;
    use std::os::unix::fs::PermissionsExt;
    #[test]
    fn acceptance_snapshots_enabled_and_history_without_inference() {
        let dir = tempfile::tempdir().unwrap();
        let key_file = dir.path().join("key");
        fs::write(&key_file, [8u8; 32]).unwrap();
        fs::set_permissions(&key_file, fs::Permissions::from_mode(0o600)).unwrap();
        let key = EventKey::load(&key_file).unwrap();
        let mut store = Store::initialize(&dir.path().join("store")).unwrap();
        store.migrate_custody().unwrap();
        store.migrate_outbound().unwrap();
        let binding = Binding {
            service: "gateway".into(),
            issuer: "issuer".into(),
            resource: "resource".into(),
            subject: "owner".into(),
            hosted_client: "client".into(),
        };
        store.enroll("legacy", &binding).unwrap();
        store.migrate_events(&key).unwrap();
        store.enroll("fresh", &binding).unwrap();
        let tx = store.connection.transaction().unwrap();
        for (event, grant) in [("unknown", "legacy"), ("never", "fresh")] {
            tx.execute(
                "INSERT INTO custody_outbox(event_id,state) VALUES (?1,'held')",
                [event],
            )
            .unwrap();
            record_acceptance(&tx, event, grant, 1).unwrap();
        }
        tx.commit().unwrap();
        store.set_enabled("fresh", 1, true).unwrap();
        let tx = store.connection.transaction().unwrap();
        tx.execute(
            "INSERT INTO custody_outbox(event_id,state) VALUES ('current','held')",
            [],
        )
        .unwrap();
        record_acceptance(&tx, "current", "fresh", 2).unwrap();
        tx.commit().unwrap();
        store.set_enabled("fresh", 2, false).unwrap();
        let tx = store.connection.transaction().unwrap();
        tx.execute(
            "INSERT INTO custody_outbox(event_id,state) VALUES ('previous','held')",
            [],
        )
        .unwrap();
        record_acceptance(&tx, "previous", "fresh", 3).unwrap();
        tx.commit().unwrap();
        for (event, class, enabled, ever, dispatch) in [
            ("unknown", "unknown", false, None, None),
            ("never", "never_enabled", false, Some(false), None),
            ("current", "current", true, Some(true), Some(2)),
            ("previous", "previous", false, Some(true), None),
        ] {
            let row:(String,bool,Option<bool>,Option<i64>)=store.connection.query_row("SELECT acceptance_class,acceptance_enabled,acceptance_ever_enabled,dispatch_revision FROM event_authorizations WHERE event_id=?1",[event],|r|Ok((r.get(0)?,r.get(1)?,r.get(2)?,r.get(3)?))).unwrap();
            assert_eq!(
                row,
                (class.into(), enabled, ever, dispatch),
                "acceptance history misclassified {event}"
            );
        }
    }
}
