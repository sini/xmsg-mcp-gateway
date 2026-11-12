use crate::grants::{Error, Store, OUTBOUND_SCHEMA_VERSION};
use rusqlite::{Connection, OptionalExtension, TransactionBehavior};

fn column(
    connection: &Connection,
    table: &str,
) -> rusqlite::Result<Option<(String, i64, Option<String>)>> {
    let mut query = connection.prepare(&format!("PRAGMA table_info({table})"))?;
    let mut rows = query.query([])?;
    while let Some(row) = rows.next()? {
        if row.get::<_, String>(1)? == "attachments" {
            return Ok(Some((row.get(2)?, row.get(3)?, row.get(4)?)));
        }
    }
    Ok(None)
}

pub(crate) fn ready(connection: &Connection) -> rusqlite::Result<bool> {
    let marker: Option<String> = connection
        .query_row(
            "SELECT type FROM sqlite_master WHERE name='attachment_schema'",
            [],
            |r| r.get(0),
        )
        .optional()?;
    let custody = column(connection, "custody_items")?;
    let outbound = column(connection, "outbound_reservations")?;
    if marker.is_none() && custody.is_none() && outbound.is_none() {
        return Ok(false);
    }
    let expected = Some(("TEXT".to_string(), 1, Some("'[]'".to_string())));
    if marker.as_deref() != Some("table") || custody != expected || outbound != expected {
        return Err(rusqlite::Error::InvalidQuery);
    }
    let versions = connection
        .prepare("SELECT version FROM attachment_schema")?
        .query_map([], |r| r.get::<_, i64>(0))?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    if versions != [1] {
        return Err(rusqlite::Error::InvalidQuery);
    }
    Ok(true)
}
pub(crate) fn validate_optional(connection: &Connection) -> Result<(), Error> {
    ready(connection)?;
    Ok(())
}
impl Store {
    pub fn migrate_attachments(&mut self) -> Result<(), Error> {
        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        if ready(&tx)? {
            return Err(Error::NoChange);
        }
        let version: i64 = tx.pragma_query_value(None, "user_version", |r| r.get(0))?;
        if version < OUTBOUND_SCHEMA_VERSION {
            return Err(Error::InvalidStore);
        }
        tx.execute_batch(
            "ALTER TABLE custody_items ADD COLUMN attachments TEXT NOT NULL DEFAULT '[]';
            ALTER TABLE outbound_reservations ADD COLUMN attachments TEXT NOT NULL DEFAULT '[]';
            CREATE TABLE attachment_schema (version INTEGER NOT NULL CHECK(version=1));
            INSERT INTO attachment_schema VALUES(1);",
        )?;
        if !ready(&tx)? {
            return Err(Error::InvalidStore);
        }
        tx.commit()?;
        Ok(())
    }
    pub fn attachments_migrated(&self) -> Result<bool, Error> {
        Ok(ready(&self.connection)?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn store() -> (tempfile::TempDir, Store) {
        let directory = tempfile::tempdir().unwrap();
        let mut store = Store::initialize(&directory.path().join("authority.db")).unwrap();
        store.migrate_custody().unwrap();
        store.migrate_outbound().unwrap();
        (directory, store)
    }
    #[test]
    fn extension_is_explicit_atomic_and_keeps_legacy_rows_and_global_version() {
        let (_directory, mut store) = store();
        assert!(!store.attachments_migrated().unwrap());
        store.connection.execute("INSERT INTO custody_items VALUES ('bus','item','event','grant',1,'mailbox','owner','{}','text','envelope',NULL,'old-fingerprint',1,999,1)",[]).unwrap();
        let version: i64 = store
            .connection
            .pragma_query_value(None, "user_version", |r| r.get(0))
            .unwrap();
        store.migrate_attachments().unwrap();
        assert!(store.attachments_migrated().unwrap());
        let held: (String, String) = store
            .connection
            .query_row(
                "SELECT attachments,fingerprint FROM custody_items",
                [],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .unwrap();
        assert_eq!(held, ("[]".into(), "old-fingerprint".into()));
        assert_eq!(
            store
                .connection
                .pragma_query_value::<i64, _>(None, "user_version", |r| r.get(0))
                .unwrap(),
            version
        );
        assert!(matches!(store.migrate_attachments(), Err(Error::NoChange)));
    }
    #[test]
    fn a_partial_or_malformed_extension_fails_closed() {
        let (_directory, store) = store();
        store
            .connection
            .execute_batch(
                "ALTER TABLE custody_items ADD COLUMN attachments TEXT NOT NULL DEFAULT '[]'",
            )
            .unwrap();
        assert!(
            ready(&store.connection).is_err(),
            "one refs column without marker was accepted"
        );
    }
    #[test]
    fn failed_second_alter_rolls_back_the_first() {
        let (_directory, mut store) = store();
        store
            .connection
            .execute_batch("DROP TABLE outbound_reservations")
            .unwrap();
        assert!(store.migrate_attachments().is_err());
        assert!(!store
            .connection
            .prepare("PRAGMA table_info(custody_items)")
            .unwrap()
            .query_map([], |r| r.get::<_, String>(1))
            .unwrap()
            .any(|r| r.unwrap() == "attachments"));
    }
}
