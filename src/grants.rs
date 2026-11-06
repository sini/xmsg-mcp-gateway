use std::fs::OpenOptions;
use std::path::Path;
use std::time::Duration;

use crate::auth::VerifiedIdentity;
use rusqlite::{params, Connection, OpenFlags, OptionalExtension};
use serde::Deserialize;
use serde_json::Value;
use thiserror::Error;

const APPLICATION_ID: i64 = 0x584d4757;
const SCHEMA_VERSION: i64 = 1;
pub const MAX_SUPPORTED_SCHEMA_VERSION: i64 = 2;

#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Binding {
    pub service: String,
    pub issuer: String,
    pub resource: String,
    pub subject: String,
    pub hosted_client: String,
}

#[derive(Debug, PartialEq, Eq)]
pub struct Authorization {
    pub grant_id: String,
    pub revision: i64,
}

#[derive(Debug, Error)]
pub enum Error {
    #[error("grant denied")]
    Denied,
    #[error("no grant changed: unknown id, stale revision or unchanged state")]
    NoChange,
    #[error("another binding is already enabled for this service")]
    Conflict,
    #[error("invalid empty grant binding")]
    InvalidBinding,
    #[error("unrecognized authority store")]
    InvalidStore,
    #[error("authority store belongs to a different service, resource or owner profile")]
    ProfileMismatch,
    #[error("authority store I/O failed")]
    Io(#[from] std::io::Error),
    #[error("authority store unavailable")]
    Database(#[from] rusqlite::Error),
}

pub fn exact_audience(value: &Value, resource: &str) -> bool {
    match value {
        Value::String(audience) => audience == resource,
        Value::Array(audiences) => audiences.len() == 1 && audiences[0].as_str() == Some(resource),
        _ => false,
    }
}

pub struct Store {
    pub(crate) connection: Connection,
}

impl Store {
    pub fn initialize(file: &Path) -> Result<Self, Error> {
        let mut options = OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        options.open(file)?;
        let mut connection = Self::connect(file)?;
        let tx = connection.transaction()?;
        tx.execute_batch(
            "CREATE TABLE grants (
                id TEXT PRIMARY KEY NOT NULL,
                service TEXT NOT NULL,
                issuer TEXT NOT NULL,
                resource TEXT NOT NULL,
                subject TEXT NOT NULL,
                hosted_client TEXT NOT NULL,
                revision INTEGER NOT NULL CHECK(revision > 0),
                enabled INTEGER NOT NULL CHECK(enabled IN (0, 1))
             );
             CREATE UNIQUE INDEX one_enabled_per_service ON grants(service)
                WHERE enabled = 1;",
        )?;
        tx.pragma_update(None, "application_id", APPLICATION_ID)?;
        tx.pragma_update(None, "user_version", SCHEMA_VERSION)?;
        tx.commit()?;
        Ok(Self { connection })
    }

    pub fn open(file: &Path) -> Result<Self, Error> {
        tracing::debug!(target: "gateway_policy_store", "open");
        let connection = Self::connect(file)?;
        let application: i64 =
            connection.pragma_query_value(None, "application_id", |r| r.get(0))?;
        let version: i64 = connection.pragma_query_value(None, "user_version", |r| r.get(0))?;
        if application != APPLICATION_ID
            || (version != SCHEMA_VERSION && version != MAX_SUPPORTED_SCHEMA_VERSION)
        {
            return Err(Error::InvalidStore);
        }
        connection.prepare("SELECT id, service, issuer, resource, subject, hosted_client, revision, enabled FROM grants LIMIT 0")?;
        if version == MAX_SUPPORTED_SCHEMA_VERSION {
            crate::custody::validate_schema(&connection)?;
        }
        Ok(Self { connection })
    }

    fn connect(file: &Path) -> Result<Connection, Error> {
        let connection = Connection::open_with_flags(file, OpenFlags::SQLITE_OPEN_READ_WRITE)?;
        connection.busy_timeout(Duration::from_secs(30))?;
        connection.pragma_update(None, "synchronous", "FULL")?;
        Ok(connection)
    }

    pub fn enroll(&mut self, id: &str, binding: &Binding) -> Result<(), Error> {
        if [
            id,
            &binding.service,
            &binding.issuer,
            &binding.resource,
            &binding.subject,
            &binding.hosted_client,
        ]
        .iter()
        .any(|s| s.trim().is_empty())
        {
            return Err(Error::InvalidBinding);
        }
        self.connection.execute(
            "INSERT INTO grants (id, service, issuer, resource, subject, hosted_client, revision, enabled)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, 1, 0)",
            params![id, binding.service, binding.issuer, binding.resource, binding.subject, binding.hosted_client],
        )?;
        Ok(())
    }

    pub fn set_enabled(&mut self, id: &str, revision: i64, enabled: bool) -> Result<i64, Error> {
        let tx = self.connection.transaction()?;
        let changed = tx.execute(
            "UPDATE grants SET enabled = ?1, revision = revision + 1
             WHERE id = ?2 AND revision = ?3 AND enabled != ?1",
            params![enabled, id, revision],
        ).map_err(|error| {
            if matches!(&error, rusqlite::Error::SqliteFailure(code, _) if code.extended_code == rusqlite::ffi::SQLITE_CONSTRAINT_UNIQUE) {
                Error::Conflict
            } else {
                Error::Database(error)
            }
        })?;
        if changed != 1 {
            return Err(Error::NoChange);
        }
        let next = tx.query_row("SELECT revision FROM grants WHERE id = ?1", [id], |r| {
            r.get(0)
        })?;
        tx.commit()?;
        Ok(next)
    }

    pub fn validate_profile(&self, binding: &Binding) -> Result<(), Error> {
        let (total, foreign): (i64, i64) = self.connection.query_row(
            "SELECT COUNT(*), COALESCE(SUM(service != ?1 OR issuer != ?2 OR resource != ?3 OR subject != ?4), 0) FROM grants",
            params![binding.service, binding.issuer, binding.resource, binding.subject],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )?;
        if total == 0 || foreign != 0 {
            return Err(Error::ProfileMismatch);
        }
        Ok(())
    }

    pub fn authorize(&self, binding: &VerifiedIdentity) -> Result<Authorization, Error> {
        self.connection
            .query_row(
                "SELECT id, revision FROM grants WHERE service = ?1 AND issuer = ?2
             AND resource = ?3 AND subject = ?4 AND hosted_client = ?5 AND enabled = 1",
                params![
                    binding.service(),
                    binding.issuer(),
                    binding.resource(),
                    binding.subject(),
                    binding.hosted_client()
                ],
                |r| {
                    Ok(Authorization {
                        grant_id: r.get(0)?,
                        revision: r.get(1)?,
                    })
                },
            )
            .optional()?
            .ok_or(Error::Denied)
    }
}
