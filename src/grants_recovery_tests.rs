use super::*;
use std::fs;
use std::process::{Child, Command};
use std::time::{Duration, Instant};
use tempfile::TempDir;

fn journal(db: &Path) -> PathBuf {
    PathBuf::from(format!("{}-journal", db.display()))
}
fn recovery(db: &Path) -> PathBuf {
    PathBuf::from(format!("{}.recovery", db.display()))
}
fn fixture() -> (TempDir, PathBuf) {
    let dir = tempfile::tempdir().unwrap();
    let db = dir.path().join("authority.sqlite");
    let store = Store::initialize(&db).unwrap();
    store.connection.execute_batch("CREATE TABLE crash_marker(id INTEGER PRIMARY KEY, value BLOB); INSERT INTO crash_marker VALUES(1, 'committed'); INSERT INTO grants VALUES('synthetic-grant','service','issuer','resource','subject','client',1,1);").unwrap();
    drop(store);
    (dir, db)
}

// This subprocess deliberately keeps its SQLite transaction open until its owner kills it.
#[test]
fn recovery_writer_child() {
    let Some(db) = std::env::var_os("NQCX_WRITER_DB") else {
        return;
    };
    let ready = std::env::var_os("NQCX_WRITER_READY").unwrap();
    let c = Connection::open(db).unwrap();
    c.execute_batch("PRAGMA journal_mode=DELETE; PRAGMA synchronous=FULL; PRAGMA cache_size=1; PRAGMA cache_spill=ON; BEGIN IMMEDIATE; UPDATE crash_marker SET value='uncommitted' WHERE id=1; UPDATE grants SET revision=99; INSERT INTO crash_marker SELECT value+2,zeroblob(8192) FROM json_each('[0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15]');").unwrap();
    fs::write(ready, b"READY").unwrap();
    loop {
        std::thread::sleep(Duration::from_secs(1));
    }
}

struct Writer(Child);
impl Drop for Writer {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}
fn writer(db: &Path) -> Writer {
    let ready = db.with_extension("ready");
    let mut child = Writer(
        Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "grants::recovery_tests::recovery_writer_child",
                "--nocapture",
            ])
            .env("NQCX_WRITER_DB", db)
            .env("NQCX_WRITER_READY", &ready)
            .spawn()
            .unwrap(),
    );
    let deadline = Instant::now() + Duration::from_secs(15);
    while !ready.exists() {
        assert!(
            child.0.try_wait().unwrap().is_none(),
            "writer exited before READY"
        );
        assert!(Instant::now() < deadline, "writer READY timeout");
        std::thread::sleep(Duration::from_millis(10));
    }
    child
}
fn assert_committed(s: &Store) {
    assert!(s.connection.is_readonly("main").unwrap());
    let value: String = s
        .connection
        .query_row("SELECT value FROM crash_marker WHERE id=1", [], |r| {
            r.get(0)
        })
        .unwrap();
    assert_eq!(value, "committed");
    let rows: i64 = s
        .connection
        .query_row("SELECT count(*) FROM crash_marker", [], |r| r.get(0))
        .unwrap();
    assert_eq!(rows, 1);
    let rev: i64 = s
        .connection
        .query_row(
            "SELECT revision FROM grants WHERE id='synthetic-grant'",
            [],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(rev, 1);
}

#[test]
fn sigkill_hot_journal_recovers_once_with_exact_private_forensics() {
    use std::os::unix::fs::PermissionsExt;
    let (_dir, db) = fixture();
    let committed_db = fs::read(&db).unwrap();
    let mut child = writer(&db);
    child.0.kill().unwrap();
    let status = child.0.wait().unwrap();
    use std::os::unix::process::ExitStatusExt;
    assert_eq!(
        status.signal(),
        Some(9),
        "fixture must be SIGKILL, never graceful rollback"
    );
    let raw_db = fs::read(&db).unwrap();
    assert_ne!(
        raw_db, committed_db,
        "dirty pages must spill before SIGKILL"
    );
    let raw_journal = fs::read(journal(&db)).unwrap();
    assert!(raw_journal.len() > 512);
    assert_ne!(&raw_journal[..8], &[0; 8], "journal must have a hot header");
    let opened = Store::open_readonly(&db)
        .expect("hot journal should recover before returning readonly store");
    assert_committed(&opened);
    drop(opened);
    let entries: Vec<_> = fs::read_dir(recovery(&db))
        .unwrap()
        .map(|e| e.unwrap().path())
        .collect();
    assert_eq!(entries.len(), 1);
    assert_eq!(
        fs::metadata(recovery(&db)).unwrap().permissions().mode() & 0o777,
        0o700
    );
    assert_eq!(
        fs::metadata(&entries[0]).unwrap().permissions().mode() & 0o777,
        0o700
    );
    for (name, expected) in [("database", raw_db), ("journal", raw_journal)] {
        let f = entries[0].join(name);
        assert_eq!(fs::read(&f).unwrap(), expected);
        assert_eq!(fs::metadata(f).unwrap().permissions().mode() & 0o777, 0o600);
    }
    assert_committed(&Store::open_readonly(&db).unwrap());
    assert_eq!(fs::read_dir(recovery(&db)).unwrap().count(), 1);
}

#[test]
fn ordinary_readonly_open_preserves_bytes_mtime_and_directory() {
    let (dir, db) = fixture();
    let before = fs::read(&db).unwrap();
    let modified = fs::metadata(&db).unwrap().modified().unwrap();
    let names: Vec<_> = fs::read_dir(dir.path())
        .unwrap()
        .map(|e| e.unwrap().file_name())
        .collect();
    assert_committed(&Store::open_readonly(&db).unwrap());
    assert_eq!(fs::read(&db).unwrap(), before);
    assert_eq!(fs::metadata(&db).unwrap().modified().unwrap(), modified);
    assert_eq!(
        fs::read_dir(dir.path())
            .unwrap()
            .map(|e| e.unwrap().file_name())
            .collect::<Vec<_>>(),
        names
    );
}

#[test]
fn live_writer_nonhot_journal_returns_committed_readonly_view() {
    let (_dir, db) = fixture();
    let c = Connection::open(&db).unwrap();
    c.execute_batch("PRAGMA journal_mode=DELETE; BEGIN IMMEDIATE; UPDATE crash_marker SET value='live-uncommitted';").unwrap();
    assert!(fs::metadata(journal(&db)).unwrap().len() > 0);
    let before = fs::read(journal(&db)).unwrap();
    assert_committed(&Store::open_readonly(&db).unwrap());
    assert_eq!(fs::read(journal(&db)).unwrap(), before);
    assert!(!recovery(&db).exists());
    c.execute_batch("ROLLBACK").unwrap();
}

#[test]
fn stale_empty_and_zero_journals_are_untouched() {
    for bytes in [Vec::new(), vec![0; 1024]] {
        let (_dir, db) = fixture();
        fs::write(journal(&db), &bytes).unwrap();
        assert_committed(&Store::open_readonly(&db).unwrap());
        assert_eq!(fs::read(journal(&db)).unwrap(), bytes);
        assert!(!recovery(&db).exists());
    }
}

#[test]
fn garbage_journal_fails_closed_with_exact_forensics_and_no_source_changes() {
    let (_dir, db) = fixture();
    let raw = fs::read(&db).unwrap();
    let garbage = b"not a sqlite journal";
    fs::write(journal(&db), garbage).unwrap();
    let error = match Store::open_readonly(&db) {
        Ok(_) => panic!("garbage journal must fail closed without a writable open"),
        Err(error) => error,
    };
    assert!(
        matches!(error, Error::Io(ref cause) if cause.to_string() == "unrecognized-journal"),
        "unexpected failure class: {error:?}"
    );
    assert_eq!(fs::read(&db).unwrap(), raw);
    assert_eq!(fs::read(journal(&db)).unwrap(), garbage);
    let entries: Vec<_> = fs::read_dir(recovery(&db))
        .unwrap()
        .map(|e| e.unwrap().path())
        .collect();
    assert_eq!(entries.len(), 1);
    assert_eq!(fs::read(entries[0].join("database")).unwrap(), raw);
    assert_eq!(fs::read(entries[0].join("journal")).unwrap(), garbage);
}

#[test]
fn missing_and_unrelated_corrupt_stores_never_create_recovery_artifacts() {
    let dir = tempfile::tempdir().unwrap();
    let db = dir.path().join("missing.sqlite");
    assert!(Store::open_readonly(&db).is_err());
    assert_eq!(fs::read_dir(dir.path()).unwrap().count(), 0);
    fs::write(&db, b"unrelated corrupt store").unwrap();
    assert!(Store::open_readonly(&db).is_err());
    assert_eq!(fs::read(&db).unwrap(), b"unrelated corrupt store");
    assert_eq!(fs::read_dir(dir.path()).unwrap().count(), 1);
}

#[test]
fn backup_directory_failure_fails_closed_without_recovering() {
    let (_dir, db) = fixture();
    let mut child = writer(&db);
    child.0.kill().unwrap();
    child.0.wait().unwrap();
    let raw = fs::read(&db).unwrap();
    let j = fs::read(journal(&db)).unwrap();
    fs::write(recovery(&db), b"occupied").unwrap();
    assert!(Store::open_readonly(&db).is_err());
    assert_eq!(fs::read(&db).unwrap(), raw);
    assert_eq!(fs::read(journal(&db)).unwrap(), j);
}

#[test]
fn quick_check_failure_returns_error_after_one_preserved_recovery() {
    let (_dir, db) = fixture();
    let c = Connection::open(&db).unwrap();
    c.execute_batch("PRAGMA ignore_check_constraints=ON; CREATE TABLE failed_check(value INTEGER CHECK(value>0)); INSERT INTO failed_check VALUES(-1); PRAGMA ignore_check_constraints=OFF;").unwrap();
    let check: String = c.query_row("PRAGMA quick_check", [], |r| r.get(0)).unwrap();
    assert_ne!(
        check, "ok",
        "positive control must exercise SQLite quick_check failure"
    );
    drop(c);
    let mut child = writer(&db);
    child.0.kill().unwrap();
    child.0.wait().unwrap();
    let raw = fs::read(&db).unwrap();
    let j = fs::read(journal(&db)).unwrap();
    assert!(
        Store::open_readonly(&db).is_err(),
        "failed quick_check must fail closed"
    );
    let entries: Vec<_> = fs::read_dir(recovery(&db))
        .unwrap()
        .map(|e| e.unwrap().path())
        .collect();
    assert_eq!(entries.len(), 1, "exactly one recovery attempt");
    assert_eq!(fs::read(entries[0].join("database")).unwrap(), raw);
    assert_eq!(fs::read(entries[0].join("journal")).unwrap(), j);
}
