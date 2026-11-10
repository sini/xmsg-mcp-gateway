//! Permanent request identity fences and body-free retirement witnesses.
use crate::grants::Store;
use crate::outbound::{Error, Limits};
use rusqlite::{params, OptionalExtension, TransactionBehavior};
use std::time::{SystemTime, UNIX_EPOCH};

pub const RETIREMENT_SCHEMA_VERSION: i64 = 5;
fn now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs().min(i64::MAX as u64) as i64)
        .unwrap_or(0)
}
fn cap(created: i64, lifetime: i64) -> i64 {
    created.saturating_add(lifetime).saturating_add(1)
}
impl Store {
    pub fn migrate_retirement(&mut self) -> Result<(), Error> {
        self.require_outbound_ready()?;
        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        tx.pragma_update(
            None,
            "application_id",
            crate::grants::RETIREMENT_APPLICATION_ID,
        )?;
        tx.execute_batch("CREATE TABLE outbound_retirement_schema(version INTEGER NOT NULL CHECK(version=5));
          INSERT INTO outbound_retirement_schema VALUES(5);
          ALTER TABLE outbound_reservations ADD COLUMN recovery_until INTEGER;
          CREATE TABLE outbound_request_fences(owner TEXT NOT NULL,request_id TEXT NOT NULL,PRIMARY KEY(owner,request_id));
          INSERT INTO outbound_request_fences SELECT DISTINCT owner,request_id FROM outbound_reservations;
          CREATE TABLE outbound_retired(owner TEXT NOT NULL,request_id TEXT NOT NULL,sender TEXT NOT NULL,grant_id TEXT NOT NULL,PRIMARY KEY(owner,request_id,sender,grant_id));
          CREATE TABLE outbound_retirement_clock(service TEXT PRIMARY KEY NOT NULL,last_observed INTEGER NOT NULL);")?;
        tx.commit()?;
        Ok(())
    }
    pub(crate) fn require_retirement_ready(&self) -> Result<(), Error> {
        let application: i64 = self
            .connection
            .pragma_query_value(None, "application_id", |r| r.get(0))?;
        if application != crate::grants::RETIREMENT_APPLICATION_ID {
            return Err(Error::MigrationRequired);
        }
        let ready: bool = self
            .connection
            .query_row(
                "SELECT COUNT(*)=1 AND MAX(version)=5 FROM outbound_retirement_schema",
                [],
                |r| r.get(0),
            )
            .map_err(|_| Error::MigrationRequired)?;
        if !ready {
            return Err(Error::MigrationRequired);
        }
        self.connection
            .prepare("SELECT recovery_until FROM outbound_reservations LIMIT 0")?;
        self.connection
            .prepare("SELECT owner,request_id,sender,grant_id FROM outbound_retired LIMIT 0")?;
        self.connection
            .prepare("SELECT owner,request_id FROM outbound_request_fences LIMIT 0")?;
        self.connection
            .prepare("SELECT service,last_observed FROM outbound_retirement_clock LIMIT 0")?;
        Ok(())
    }
    pub fn retired_outbound(
        &self,
        owner: &str,
        id: &str,
        sender: &str,
        grant: &str,
    ) -> Result<bool, Error> {
        self.require_retirement_ready()?;
        Ok(self.connection.query_row("SELECT EXISTS(SELECT 1 FROM outbound_retired WHERE owner=?1 AND request_id=?2 AND sender=?3 AND grant_id=?4) AND NOT EXISTS(SELECT 1 FROM outbound_reservations WHERE owner=?1 AND request_id=?2 AND sender=?3 AND grant_id=?4)",params![owner,id,sender,grant],|r|r.get(0))?)
    }
    pub(crate) fn outbound_id_retired(&self, owner: &str, id: &str) -> Result<bool, Error> {
        self.require_retirement_ready()?;
        Ok(self.connection.query_row(
            "SELECT EXISTS(SELECT 1 FROM outbound_retired WHERE owner=?1 AND request_id=?2)",
            params![owner, id],
            |r| r.get(0),
        )?)
    }
    pub(crate) fn outbound_id_conflicts(
        &self,
        owner: &str,
        id: &str,
        op: &str,
    ) -> Result<bool, Error> {
        self.require_retirement_ready()?;
        Ok(self.connection.query_row("SELECT EXISTS(SELECT 1 FROM outbound_request_fences WHERE owner=?1 AND request_id=?2) AND NOT EXISTS(SELECT 1 FROM outbound_reservations WHERE owner=?1 AND request_id=?2 AND operation=?3)",params![owner,id,op],|r|r.get(0))?)
    }
    pub fn outbound_recovery_expired(
        &self,
        owner: &str,
        id: &str,
        sender: &str,
        grant: &str,
        limits: &Limits,
    ) -> Result<bool, Error> {
        let mut q=self.connection.prepare("SELECT created_at,retry_until,recovery_until FROM outbound_reservations WHERE owner=?1 AND request_id=?2 AND sender=?3 AND grant_id=?4")?;
        let rows = q.query_map(params![owner, id, sender, grant], |r| {
            Ok((
                r.get::<_, i64>(0)?,
                r.get::<_, i64>(1)?,
                r.get::<_, Option<i64>>(2)?,
            ))
        })?;
        let now = now();
        let observed:Option<i64>=self.connection.query_row("SELECT c.last_observed FROM outbound_retirement_clock c JOIN grants g ON g.service=c.service WHERE g.id=?1",[grant],|r|r.get(0)).optional()?;
        if observed.is_some_and(|at| now < at) {
            return Err(Error::Busy);
        }
        let mut saw_row = false;
        let mut expired = true;
        for row in rows {
            let (created, e, r) = row?;
            let r = r.ok_or(Error::Busy)?;
            if cap(created, limits.result_recovery_secs) < r
                || cap(created, limits.dedup_lifetime_secs) < e
            {
                return Err(Error::Busy);
            }
            if now < created {
                return Err(Error::Busy);
            }
            saw_row = true;
            expired &= now >= r;
        }
        if saw_row {
            Ok(expired)
        } else {
            self.retired_outbound(owner, id, sender, grant)
        }
    }
    pub fn retire_outbound(&mut self, service: &str, limits: &Limits) -> Result<(), Error> {
        limits.validate()?;
        self.require_retirement_ready()?;
        let Some(_lease) = self.try_operation_lease(service)? else {
            return Ok(());
        };
        self.retire_outbound_locked(service, limits, now())
    }
    pub(crate) fn retire_outbound_locked(
        &mut self,
        service: &str,
        limits: &Limits,
        at: i64,
    ) -> Result<(), Error> {
        self.require_retirement_ready()?;
        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let previous: Option<i64> = tx
            .query_row(
                "SELECT last_observed FROM outbound_retirement_clock WHERE service=?1",
                [service],
                |r| r.get(0),
            )
            .optional()?;
        let rollback = previous.is_some_and(|p| at < p);
        let mut q=tx.prepare("SELECT r.owner,r.operation,r.request_id,r.created_at,r.retry_until,r.recovery_until FROM outbound_reservations r JOIN grants g ON g.id=r.grant_id WHERE g.service=?1")?;
        let rows = q
            .query_map([service], |r| {
                Ok((
                    r.get::<_, String>(0)?,
                    r.get::<_, String>(1)?,
                    r.get::<_, String>(2)?,
                    r.get::<_, i64>(3)?,
                    r.get::<_, i64>(4)?,
                    r.get::<_, Option<i64>>(5)?,
                ))
            })?
            .collect::<Result<Vec<_>, _>>()?;
        drop(q);
        for (owner, op, id, created, e, r) in rows {
            let e = e.min(cap(created, limits.dedup_lifetime_secs));
            let mut r = r
                .unwrap_or_else(|| cap(created, limits.result_recovery_secs))
                .min(cap(created, limits.result_recovery_secs));
            if rollback || at < created {
                r = r.min(at);
            }
            tx.execute("UPDATE outbound_reservations SET retry_until=?4,recovery_until=?5 WHERE owner=?1 AND operation=?2 AND request_id=?3",params![owner,op,id,e,r])?;
        }
        tx.execute("INSERT OR IGNORE INTO outbound_retired(owner,request_id,sender,grant_id) SELECT r.owner,r.request_id,r.sender,r.grant_id FROM outbound_reservations r JOIN grants g ON g.id=r.grant_id WHERE g.service=?1 AND r.recovery_until<=?2",params![service,at])?;
        tx.execute("DELETE FROM outbound_reservations WHERE rowid IN (SELECT r.rowid FROM outbound_reservations r JOIN grants g ON g.id=r.grant_id WHERE g.service=?1 AND r.recovery_until<=?2)",params![service,at])?;
        tx.execute("INSERT INTO outbound_retirement_clock(service,last_observed) VALUES(?1,?2) ON CONFLICT(service) DO UPDATE SET last_observed=MAX(last_observed,excluded.last_observed)",params![service,at])?;
        tx.commit()?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::grants::Binding;
    pub(super) fn setup() -> (tempfile::TempDir, Store) {
        let dir = tempfile::tempdir().unwrap();
        let mut s = Store::initialize(&dir.path().join("state.db")).unwrap();
        s.enroll(
            "g",
            &Binding {
                service: "gateway".into(),
                issuer: "issuer".into(),
                resource: "resource".into(),
                subject: "subject".into(),
                hosted_client: "client".into(),
            },
        )
        .unwrap();
        s.migrate_custody().unwrap();
        s.migrate_outbound().unwrap();
        (dir, s)
    }
    pub(super) fn limits(e: i64, r: i64) -> Limits {
        Limits {
            dedup_lifetime_secs: e,
            result_recovery_secs: r,
            max_framed_bytes: 65536,
            timeout: std::time::Duration::from_secs(1),
            max_reservations: 10,
            max_retained_bytes: 655360,
        }
    }
    pub(super) fn seed(s: &Store, op: &str, id: &str, receipt: Option<&str>) {
        s.connection.execute("INSERT INTO outbound_reservations(owner,operation,request_id,payload_hash,sender,grant_id,grant_revision,idempotency_key,target,correlation,framed_text,created_at,retry_until,state,receipt) VALUES('o',?1,?2,'hash','gateway@bus','g',1,?3,'receiver@node',NULL,'original body',100,161,?4,?5)",params![op,id,format!("{op}-{id}"),if receipt.is_some(){"confirmed"}else{"unknown"},receipt]).unwrap();
    }
    #[test]
    fn migration_preserves_legacy_shared_id_outcomes_without_enabling_events() {
        let (_dir, mut s) = setup();
        seed(&s, "send", "shared", Some("{\"receipt\":1}"));
        seed(&s, "reply", "shared", None);
        s.migrate_retirement().unwrap();
        let version: i64 = s
            .connection
            .pragma_query_value(None, "user_version", |r| r.get(0))
            .unwrap();
        assert_eq!(version, 3);
        assert!(s
            .connection
            .prepare("SELECT * FROM event_authorizations")
            .is_err());
        assert_eq!(
            s.connection
                .query_row("SELECT COUNT(*) FROM outbound_request_fences", [], |r| r
                    .get::<_, i64>(0))
                .unwrap(),
            1
        );
        assert_eq!(
            s.connection
                .query_row(
                    "SELECT COUNT(*) FROM outbound_reservations WHERE recovery_until IS NULL",
                    [],
                    |r| r.get::<_, i64>(0)
                )
                .unwrap(),
            2
        );
        assert!(matches!(
            s.outbound_recovery_expired("o", "shared", "gateway@bus", "g", &limits(60, 120)),
            Err(Error::Busy)
        ));
        s.retire_outbound_locked("gateway", &limits(60, 120), 110)
            .unwrap();
        assert_eq!(
            s.connection
                .query_row(
                    "SELECT receipt FROM outbound_reservations WHERE operation='send'",
                    [],
                    |r| r.get::<_, String>(0)
                )
                .unwrap(),
            "{\"receipt\":1}"
        );
        assert_eq!(
            s.connection
                .query_row("SELECT COUNT(*) FROM outbound_reservations", [], |r| r
                    .get::<_, i64>(0))
                .unwrap(),
            2
        );
        assert!(s.migrate_retirement().is_err());
    }
    #[test]
    fn archival_witness_and_body_delete_are_one_atomic_transaction() {
        let (_dir, mut s) = setup();
        seed(&s, "send", "one", Some("{}"));
        s.migrate_retirement().unwrap();
        s.connection.execute_batch("CREATE TRIGGER refuse_archive BEFORE INSERT ON outbound_retired BEGIN SELECT RAISE(ABORT,'forced archive failure'); END;").unwrap();
        assert!(s
            .retire_outbound_locked("gateway", &limits(60, 120), 300)
            .is_err());
        assert_eq!(s.connection.query_row("SELECT COUNT(*) FROM outbound_reservations WHERE framed_text='original body' AND recovery_until IS NULL",[],|r|r.get::<_,i64>(0)).unwrap(),1);
        assert!(!s.outbound_id_retired("o", "one").unwrap());
        s.connection
            .execute_batch("DROP TRIGGER refuse_archive;")
            .unwrap();
        s.retire_outbound_locked("gateway", &limits(60, 120), 300)
            .unwrap();
        assert!(s.outbound_id_retired("o", "one").unwrap());
        assert!(s.retired_outbound("o", "one", "gateway@bus", "g").unwrap());
        assert!(!s.retired_outbound("o", "one", "foreign@bus", "g").unwrap());
        assert_eq!(
            s.connection
                .query_row("SELECT COUNT(*) FROM outbound_reservations", [], |r| r
                    .get::<_, i64>(0))
                .unwrap(),
            0
        );
        assert_eq!(
            s.connection
                .query_row(
                    "SELECT COUNT(*) FROM pragma_table_info('outbound_retired')",
                    [],
                    |r| r.get::<_, i64>(0)
                )
                .unwrap(),
            4
        );
    }
    #[test]
    fn shrinks_are_persistent_and_clock_rollback_expires_conservatively() {
        let (_dir, mut s) = setup();
        seed(&s, "send", "one", None);
        s.migrate_retirement().unwrap();
        s.retire_outbound_locked("gateway", &limits(60, 120), 110)
            .unwrap();
        s.retire_outbound_locked("gateway", &limits(30, 70), 120)
            .unwrap();
        s.retire_outbound_locked("gateway", &limits(60, 120), 130)
            .unwrap();
        assert_eq!(
            s.connection
                .query_row(
                    "SELECT retry_until,recovery_until FROM outbound_reservations",
                    [],
                    |r| Ok((r.get::<_, i64>(0)?, r.get::<_, i64>(1)?))
                )
                .unwrap(),
            (131, 171)
        );
        s.retire_outbound_locked("gateway", &limits(60, 120), 129)
            .unwrap();
        assert!(s.outbound_id_retired("o", "one").unwrap());
        s.retire_outbound_locked("gateway", &limits(60, 999), 500)
            .unwrap();
        assert!(s.outbound_id_retired("o", "one").unwrap());
    }
    #[test]
    fn busy_service_lease_prevents_retirement() {
        let (_dir, mut s) = setup();
        seed(&s, "send", "one", None);
        s.migrate_retirement().unwrap();
        let held = s.try_operation_lease("gateway").unwrap().unwrap();
        s.retire_outbound("gateway", &limits(60, 120)).unwrap();
        assert!(!s.outbound_id_retired("o", "one").unwrap());
        drop(held);
        s.retire_outbound("gateway", &limits(60, 120)).unwrap();
        assert!(s.outbound_id_retired("o", "one").unwrap());
    }
}

#[cfg(test)]
mod staggered_legacy_tests {
    use super::*;
    #[test]
    fn an_archived_legacy_operation_does_not_hide_the_other_live_outcome() {
        let (_dir, mut s) = super::tests::setup();
        super::tests::seed(&s, "send", "shared", Some("{\"old\":1}"));
        super::tests::seed(&s, "reply", "shared", Some("{\"live\":2}"));
        s.connection.execute("UPDATE outbound_reservations SET created_at=120,retry_until=181 WHERE operation='reply'",[]).unwrap();
        s.migrate_retirement().unwrap();
        s.retire_outbound_locked("gateway", &super::tests::limits(60, 120), 130)
            .unwrap();
        s.retire_outbound_locked("gateway", &super::tests::limits(60, 120), 221)
            .unwrap();
        assert!(s.outbound_id_retired("o", "shared").unwrap());
        assert!(!s
            .retired_outbound("o", "shared", "gateway@bus", "g")
            .unwrap());
        assert_eq!(
            s.connection
                .query_row(
                    "SELECT receipt FROM outbound_reservations WHERE operation='reply'",
                    [],
                    |r| r.get::<_, String>(0)
                )
                .unwrap(),
            "{\"live\":2}"
        );
        s.retire_outbound_locked("gateway", &super::tests::limits(60, 120), 241)
            .unwrap();
        assert!(s
            .retired_outbound("o", "shared", "gateway@bus", "g")
            .unwrap());
    }
}

#[cfg(test)]
mod readiness_tests {
    use super::*;
    #[test]
    fn readiness_rejects_duplicate_version_rows_and_missing_clock() {
        let (_dir, mut s) = super::tests::setup();
        s.migrate_retirement().unwrap();
        s.connection
            .execute("INSERT INTO outbound_retirement_schema VALUES(5)", [])
            .unwrap();
        assert!(s.require_retirement_ready().is_err());
        s.connection.execute("DELETE FROM outbound_retirement_schema WHERE rowid=(SELECT MAX(rowid) FROM outbound_retirement_schema)",[]).unwrap();
        assert!(s.require_retirement_ready().is_ok());
        s.connection
            .execute_batch("DROP TABLE outbound_retirement_clock")
            .unwrap();
        assert!(s.require_retirement_ready().is_err());
    }
    #[test]
    fn migration_from_events_preserves_events_and_v3_retirement_does_not_skip_it() {
        use std::os::unix::fs::PermissionsExt;
        for events_first in [false, true] {
            let (dir, mut s) = super::tests::setup();
            let file = dir.path().join("key");
            std::fs::write(&file, [8; 32]).unwrap();
            std::fs::set_permissions(&file, std::fs::Permissions::from_mode(0o600)).unwrap();
            let key = crate::event_store::EventKey::load(&file).unwrap();
            if events_first {
                s.migrate_events(&key).unwrap();
            }
            s.migrate_retirement().unwrap();
            if !events_first {
                s.migrate_events(&key).unwrap();
            }
            assert_eq!(
                s.connection
                    .pragma_query_value(None, "user_version", |r| r.get::<_, i64>(0))
                    .unwrap(),
                4
            );
            assert!(s.require_retirement_ready().is_ok());
            s.require_events_ready(&key).unwrap();
        }
    }
}

#[cfg(test)]
mod application_marker_tests {
    use super::*;
    #[test]
    fn old_reader_exact_marker_predicate_rejects_migrated_store() {
        let (_dir, mut s) = super::tests::setup();
        let before: i64 = s
            .connection
            .pragma_query_value(None, "application_id", |r| r.get(0))
            .unwrap();
        assert_eq!(before, crate::grants::LEGACY_APPLICATION_ID);
        s.migrate_retirement().unwrap();
        let after: i64 = s
            .connection
            .pragma_query_value(None, "application_id", |r| r.get(0))
            .unwrap();
        assert_ne!(after, crate::grants::LEGACY_APPLICATION_ID);
        assert_eq!(after, crate::grants::RETIREMENT_APPLICATION_ID);
        Store::open(&s.file).unwrap();
    }
    #[test]
    fn failed_migration_rolls_back_application_marker_and_ddl() {
        let (_dir, mut s) = super::tests::setup();
        s.connection
            .execute_batch("CREATE TABLE outbound_request_fences(blocker INTEGER)")
            .unwrap();
        assert!(s.migrate_retirement().is_err());
        assert_eq!(
            s.connection
                .pragma_query_value(None, "application_id", |r| r.get::<_, i64>(0))
                .unwrap(),
            crate::grants::LEGACY_APPLICATION_ID
        );
        assert!(s
            .connection
            .prepare("SELECT recovery_until FROM outbound_reservations")
            .is_err());
        assert!(s
            .connection
            .prepare("SELECT * FROM outbound_retirement_schema")
            .is_err());
        Store::open(&s.file).unwrap();
    }
}
