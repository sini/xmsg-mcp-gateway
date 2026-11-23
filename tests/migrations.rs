use std::path::Path;
use std::process::{Command, Output};
use xmsg_mcp_gateway::grants::Store;

const COMMANDS: [&str; 8] = [
    "migrate-custody",
    "migrate-custody-summaries",
    "migrate-outbound",
    "migrate-retirement",
    "migrate-events",
    "migrate-profiles",
    "migrate-attachments",
    "migrate-authorization-server",
];
fn run(file: &Path, args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_xmsg-mcp-gateway"))
        .arg("--state")
        .arg(file)
        .args(args)
        .output()
        .unwrap()
}
fn key(dir: &Path) -> std::path::PathBuf {
    use std::os::unix::fs::PermissionsExt;
    let file = dir.join("key");
    std::fs::write(&file, [4u8; 32]).unwrap();
    std::fs::set_permissions(&file, std::fs::Permissions::from_mode(0o600)).unwrap();
    file
}
fn complete(file: &Path, key: &Path) {
    Store::initialize(file).unwrap();
    for command in ["migrate-custody", "migrate-outbound", "migrate-retirement"] {
        let output = run(file, &[command, "--if-needed"]);
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
    }
    let output = run(
        file,
        &[
            "migrate-events",
            "--if-needed",
            "--key-file",
            key.to_str().unwrap(),
        ],
    );
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(run(file, &["migrate-profiles", "--if-needed"])
        .status
        .success());
    assert!(run(file, &["migrate-attachments", "--if-needed"])
        .status
        .success());
    assert!(run(file, &["migrate-authorization-server", "--if-needed"])
        .status
        .success());
}

#[test]
fn if_needed_chain_migrates_and_all_completed_commands_are_byte_identical_noops() {
    let dir = tempfile::tempdir().unwrap();
    let file = dir.path().join("state.db");
    let key = key(dir.path());
    Store::initialize(&file).unwrap();
    for (command, version) in [
        ("migrate-custody", 2i64),
        ("migrate-outbound", 3),
        ("migrate-retirement", 3),
    ] {
        let output = run(&file, &[command, "--if-needed"]);
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(
            !String::from_utf8_lossy(&output.stdout).contains("already migrated"),
            "needed migration was skipped"
        );
        assert_eq!(
            rusqlite::Connection::open(&file)
                .unwrap()
                .pragma_query_value(None, "user_version", |r| r.get::<_, i64>(0))
                .unwrap(),
            version
        );
    }
    let before = std::fs::read(&file).unwrap();
    assert!(!run(&file, &["migrate-events", "--if-needed"])
        .status
        .success());
    assert_eq!(
        std::fs::read(&file).unwrap(),
        before,
        "missing needed key modified state"
    );
    assert!(run(
        &file,
        &[
            "migrate-events",
            "--if-needed",
            "--key-file",
            key.to_str().unwrap()
        ]
    )
    .status
    .success());
    assert!(run(&file, &["migrate-profiles", "--if-needed"])
        .status
        .success());
    assert!(run(&file, &["migrate-attachments", "--if-needed"])
        .status
        .success());
    assert!(run(&file, &["migrate-authorization-server", "--if-needed"])
        .status
        .success());
    for command in COMMANDS {
        let before = std::fs::read(&file).unwrap();
        let output = run(&file, &[command, "--if-needed"]);
        assert!(
            output.status.success(),
            "{command}: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert_eq!(output.stdout, b"already migrated\n");
        assert_eq!(
            std::fs::read(&file).unwrap(),
            before,
            "{command} wrote during no-op"
        );
        let args = if command == "migrate-events" {
            vec![command, "--key-file", key.to_str().unwrap()]
        } else {
            vec![command]
        };
        assert!(
            !run(&file, &args).status.success(),
            "strict {command} silently skipped"
        );
        assert_eq!(std::fs::read(&file).unwrap(), before);
    }
    let output = run(
        &file,
        &["migrate-events", "--if-needed", "--key-file", "missing-key"],
    );
    assert!(
        output.status.success(),
        "completed Events migration loaded a key"
    );
}

#[test]
fn legacy_summary_upgrade_is_needed_and_newer_summary_lineage_skips_retirement() {
    let dir = tempfile::tempdir().unwrap();
    let file = dir.path().join("state.db");
    let key = key(dir.path());
    complete(&file, &key);
    let db = rusqlite::Connection::open(&file).unwrap();
    db.execute_batch("DROP TABLE custody_refusal_summaries; DROP TABLE custody_gap_summary; PRAGMA application_id=0x584d4752;").unwrap();
    drop(db);
    let output = run(&file, &["migrate-custody-summaries", "--if-needed"]);
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(!String::from_utf8_lossy(&output.stdout).contains("already migrated"));
    let before = std::fs::read(&file).unwrap();
    let output = run(&file, &["migrate-retirement", "--if-needed"]);
    assert!(output.status.success());
    assert_eq!(output.stdout, b"already migrated\n");
    assert_eq!(std::fs::read(&file).unwrap(), before);
}

#[test]
fn if_needed_refuses_unknown_corrupt_partial_and_not_ready_stores_without_writes() {
    for alteration in [
        "PRAGMA application_id=42;",
        "PRAGMA user_version=99;",
        "DROP TABLE custody_gap_summary;",
        "DROP TABLE outbound_retirement_clock;",
        "INSERT INTO outbound_retirement_schema VALUES(5);",
        "DROP TABLE event_observations;",
        "DELETE FROM event_key_check;",
    ] {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("state.db");
        let key = key(dir.path());
        complete(&file, &key);
        rusqlite::Connection::open(&file)
            .unwrap()
            .execute_batch(alteration)
            .unwrap();
        for command in COMMANDS {
            let before = std::fs::read(&file).unwrap();
            let output = run(&file, &[command, "--if-needed"]);
            assert!(
                !output.status.success(),
                "{command} skipped corrupt state: {alteration}"
            );
            assert_eq!(std::fs::read(&file).unwrap(), before);
        }
    }
    let dir = tempfile::tempdir().unwrap();
    let file = dir.path().join("state.db");
    Store::initialize(&file).unwrap();
    let before = std::fs::read(&file).unwrap();
    assert!(!run(&file, &["migrate-outbound", "--if-needed"])
        .status
        .success());
    assert_eq!(std::fs::read(&file).unwrap(), before);
    rusqlite::Connection::open(&file)
        .unwrap()
        .pragma_update(None, "application_id", 0x584d4753i64)
        .unwrap();
    let before = std::fs::read(&file).unwrap();
    assert!(!run(&file, &["migrate-custody", "--if-needed"])
        .status
        .success());
    assert_eq!(std::fs::read(&file).unwrap(), before);
}

#[test]
fn migrations_pending_matches_shared_predicates_without_writes() {
    let dir = tempfile::tempdir().unwrap();
    let file = dir.path().join("state.db");
    Store::initialize(&file).unwrap();
    let inspect = |expected: &[u8], code| {
        let before = std::fs::read(&file).unwrap();
        let output = run(&file, &["migrations-pending"]);
        assert_eq!(
            output.status.code(),
            Some(code),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert_eq!(
            output.stdout, expected,
            "pending migration report diverged from shared predicates"
        );
        assert_eq!(
            std::fs::read(&file).unwrap(),
            before,
            "inspection wrote state"
        );
    };
    inspect(b"migrate-custody\nmigrate-outbound\nmigrate-retirement\nmigrate-custody-summaries\nmigrate-events\nmigrate-profiles\nmigrate-attachments\nmigrate-authorization-server\n", 10);
    std::fs::remove_file(&file).unwrap();
    complete(&file, &key(dir.path()));
    inspect(b"", 0);
    rusqlite::Connection::open(&file).unwrap().execute_batch("DROP TABLE custody_refusal_summaries; DROP TABLE custody_gap_summary; PRAGMA application_id=0x584d4752;").unwrap();
    inspect(b"migrate-custody-summaries\n", 10);
}

#[test]
fn migrations_pending_rejects_missing_and_corrupt_without_writes() {
    let dir = tempfile::tempdir().unwrap();
    let missing = dir.path().join("missing.db");
    assert_eq!(
        run(&missing, &["migrations-pending"]).status.code(),
        Some(1)
    );
    assert!(!missing.exists());
    for alteration in [
        "PRAGMA application_id=42;",
        "PRAGMA user_version=99;",
        "DROP TABLE custody_gap_summary;",
        "DROP TABLE outbound_retirement_clock;",
        "DELETE FROM event_key_check;",
    ] {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("state.db");
        complete(&file, &key(dir.path()));
        rusqlite::Connection::open(&file)
            .unwrap()
            .execute_batch(alteration)
            .unwrap();
        let before = std::fs::read(&file).unwrap();
        let output = run(&file, &["migrations-pending"]);
        assert_eq!(
            output.status.code(),
            Some(1),
            "corrupt state accepted: {alteration}"
        );
        assert!(output.stdout.is_empty());
        assert_eq!(std::fs::read(&file).unwrap(), before);
    }
}

#[path = "common/outbound_observer.rs"]
mod outbound_observer;

#[test]
fn migrations_pending_keeps_one_readonly_snapshot_during_migration() {
    use std::sync::{mpsc, Mutex};
    use std::time::Duration;
    let dir = tempfile::tempdir().unwrap();
    let file = dir.path().join("state.db");
    Store::initialize(&file).unwrap();
    rusqlite::Connection::open(&file)
        .unwrap()
        .pragma_update(None, "journal_mode", "WAL")
        .unwrap();
    let (selected_tx, selected_rx) = mpsc::channel();
    let (ready_tx, ready_rx) = mpsc::channel();
    let (primed_tx, primed_rx) = mpsc::channel();
    let (release_tx, release_rx) = mpsc::channel();
    let inspection_file = file.clone();
    let inspector = std::thread::spawn(move || {
        let release_rx = Mutex::new(release_rx);
        tracing::subscriber::with_default(
            outbound_observer::AtEvent::new("gateway_migrations_snapshot", move || {
                selected_tx.send(()).unwrap();
                release_rx
                    .lock()
                    .unwrap()
                    .recv_timeout(Duration::from_secs(3))
                    .unwrap();
            }),
            || {
                ready_tx.send(()).unwrap();
                primed_rx.recv_timeout(Duration::from_secs(3)).unwrap();
                Store::open_readonly(&inspection_file)
                    .unwrap()
                    .pending_migrations()
                    .unwrap()
            },
        )
    });
    ready_rx.recv_timeout(Duration::from_secs(3)).unwrap();
    assert_eq!(
        Store::open_readonly(&file)
            .unwrap()
            .pending_migrations()
            .unwrap()
            .len(),
        8
    );
    primed_tx.send(()).unwrap();
    selected_rx.recv_timeout(Duration::from_secs(3)).unwrap();
    Store::open(&file).unwrap().migrate_custody().unwrap();
    release_tx.send(()).unwrap();
    assert_eq!(
        inspector.join().unwrap().len(),
        8,
        "mixed migration snapshots"
    );
    assert_eq!(
        Store::open_readonly(&file)
            .unwrap()
            .pending_migrations()
            .unwrap(),
        [
            "migrate-outbound",
            "migrate-retirement",
            "migrate-events",
            "migrate-profiles",
            "migrate-attachments",
            "migrate-authorization-server"
        ]
    );
}

#[test]
fn attachment_marker_and_as_migrations_work_in_both_orders_and_preserve_metadata() {
    for attachments_first in [false, true] {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("state.db");
        let key = key(dir.path());
        let mut store = Store::initialize(&file).unwrap();
        store.migrate_profiles().unwrap();
        store.migrate_custody().unwrap();
        store.migrate_outbound().unwrap();
        store.migrate_retirement().unwrap();
        store
            .migrate_events(&xmsg_mcp_gateway::event_store::EventKey::load(&key).unwrap())
            .unwrap();
        assert_eq!(
            store.pending_migrations().unwrap(),
            ["migrate-attachments", "migrate-authorization-server"]
        );
        if !attachments_first {
            store.migrate_authorization_server().unwrap();
        }
        let before = rusqlite::Connection::open(&file)
            .unwrap()
            .pragma_query_value::<i64, _>(None, "user_version", |r| r.get(0))
            .unwrap();
        store.migrate_attachments().unwrap();
        let db = rusqlite::Connection::open(&file).unwrap();
        assert_eq!(
            db.pragma_query_value::<i64, _>(None, "user_version", |r| r.get(0))
                .unwrap(),
            before,
            "attachment marker changed global schema version"
        );
        if attachments_first {
            store.migrate_authorization_server().unwrap();
        }
        assert_eq!(
            db.pragma_query_value::<i64, _>(None, "user_version", |r| r.get(0))
                .unwrap(),
            5
        );
        assert!(store
            .migration_applied(xmsg_mcp_gateway::grants::Migration::Attachments)
            .unwrap());
        assert!(store
            .migration_applied(xmsg_mcp_gateway::grants::Migration::AuthorizationServer)
            .unwrap());
        for table in ["custody_items", "outbound_reservations"] {
            let column:(String,i64,String)=db.query_row("SELECT type,[notnull],dflt_value FROM pragma_table_info(?1) WHERE name='attachments'",[table],|r|Ok((r.get(0)?,r.get(1)?,r.get(2)?))).unwrap();
            assert_eq!(column, ("TEXT".into(), 1, "'[]'".into()));
        }
        assert!(Store::open(&file)
            .unwrap()
            .pending_migrations()
            .unwrap()
            .is_empty());
    }
}

fn authority_digest(file: &Path) -> [u8; 32] {
    use sha2::Digest;
    sha2::Sha256::digest(std::fs::read(file).unwrap()).into()
}

#[test]
fn init_if_needed_creates_missing_store_then_preserves_existing_authority() {
    let dir = tempfile::tempdir().unwrap();
    let file = dir.path().join("state.db");
    let created = run(&file, &["init", "--if-needed"]);
    assert!(
        file.exists(),
        "init --if-needed must create the missing authority store"
    );
    assert!(
        created.status.success(),
        "{}",
        String::from_utf8_lossy(&created.stderr)
    );
    let binding = xmsg_mcp_gateway::grants::Binding {
        service: "service".into(),
        issuer: "issuer".into(),
        resource: "resource".into(),
        subject: "subject".into(),
        hosted_client: "client".into(),
    };
    let mut store = Store::open(&file).unwrap();
    store.enroll("grant", &binding).unwrap();
    drop(store);
    rusqlite::Connection::open(&file)
        .unwrap()
        .execute(
            "UPDATE grants SET revision=7, enabled=1 WHERE id='grant'",
            [],
        )
        .unwrap();
    let before = authority_digest(&file);
    let result = run(&file, &["init", "--if-needed"]);
    assert_eq!(
        authority_digest(&file),
        before,
        "existing initialization must not reset authority"
    );
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
}

#[test]
fn enroll_if_needed_preserves_enabled_revision_and_outbound_policy() {
    use xmsg_mcp_gateway::grants::Binding;
    use xmsg_mcp_gateway::outbound::{Permission, Policy};
    let dir = tempfile::tempdir().unwrap();
    let file = dir.path().join("state.db");
    complete(&file, &key(dir.path()));
    let binding = Binding {
        service: "service".into(),
        issuer: "issuer".into(),
        resource: "resource".into(),
        subject: "subject".into(),
        hosted_client: "client".into(),
    };
    let mut store = Store::open(&file).unwrap();
    store.enroll("grant", &binding).unwrap();
    let revision = store.set_enabled("grant", 1, true).unwrap();
    assert_eq!(
        store
            .set_outbound_policy(
                "grant",
                revision,
                &Policy {
                    send: Some(Permission {
                        targets: ["receiver@peer".into()].into(),
                        required_scope: "messages:send".into()
                    }),
                    reply: None,
                }
            )
            .unwrap(),
        3
    );
    drop(store);
    let document = dir.path().join("binding.json");
    std::fs::write(&document, br#"{"service":"service","issuer":"issuer","resource":"resource","subject":"subject","hosted_client":"client"}"#).unwrap();
    let before = authority_digest(&file);
    let result = run(
        &file,
        &["enroll", "--if-needed", "grant", document.to_str().unwrap()],
    );
    assert_eq!(
        authority_digest(&file),
        before,
        "an exact enrollment must preserve every authority byte"
    );
    assert!(
        result.status.success(),
        "enroll --if-needed must accept the exact existing binding: {}",
        String::from_utf8_lossy(&result.stderr)
    );
}

#[test]
fn backup_if_pending_complete_store_has_no_backup_effects() {
    let dir = tempfile::tempdir().unwrap();
    let file = dir.path().join("state.db");
    complete(&file, &key(dir.path()));
    let backups = dir.path().join("backups");
    let before = authority_digest(&file);
    let result = run(
        &file,
        &[
            "backup-if-pending",
            "--backup-dir",
            backups.to_str().unwrap(),
            "--keep",
            "1",
        ],
    );
    assert!(
        !backups.exists(),
        "a complete store must not create a backup directory"
    );
    assert_eq!(
        authority_digest(&file),
        before,
        "a complete backup check must not write authority"
    );
    assert!(
        result.status.success(),
        "complete backup check must exit zero: {}",
        String::from_utf8_lossy(&result.stderr)
    );
}

#[test]
fn backup_if_pending_captures_committed_wal_state_with_private_snapshot() {
    use std::os::unix::fs::PermissionsExt;
    let dir = tempfile::tempdir().unwrap();
    let file = dir.path().join("state.db");
    let mut store = Store::initialize(&file).unwrap();
    store
        .enroll(
            "grant",
            &xmsg_mcp_gateway::grants::Binding {
                service: "service".into(),
                issuer: "issuer".into(),
                resource: "resource".into(),
                subject: "subject".into(),
                hosted_client: "client".into(),
            },
        )
        .unwrap();
    drop(store);
    let writer = rusqlite::Connection::open(&file).unwrap();
    writer.execute_batch("PRAGMA journal_mode=WAL; PRAGMA wal_autocheckpoint=0; UPDATE grants SET revision=7 WHERE id='grant';").unwrap();
    let control = dir.path().join("bare-copy.db");
    std::fs::copy(&file, &control).unwrap();
    let bare = rusqlite::Connection::open(&control).unwrap();
    assert_eq!(
        bare.query_row("SELECT revision FROM grants WHERE id='grant'", [], |r| r
            .get::<_, i64>(0))
            .unwrap(),
        1,
        "fixture must distinguish a bare file copy from the committed WAL snapshot"
    );
    drop(bare);
    let source_before = authority_digest(&file);
    let backups = dir.path().join("backups");
    let result = run(
        &file,
        &[
            "backup-if-pending",
            "--backup-dir",
            backups.to_str().unwrap(),
            "--keep",
            "1",
        ],
    );
    assert!(
        backups.exists(),
        "pending migration backup must publish a completed snapshot"
    );
    let completed: Vec<_> = std::fs::read_dir(&backups)
        .unwrap()
        .map(|e| e.unwrap().path())
        .filter(|p| p.join("database").is_file() && p.join("manifest.json").is_file())
        .collect();
    assert_eq!(
        completed.len(),
        1,
        "pending backup must publish exactly one completed pair"
    );
    let database = completed[0].join("database");
    let snapshot = rusqlite::Connection::open_with_flags(
        &database,
        rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY,
    )
    .unwrap();
    assert_eq!(
        snapshot
            .query_row("SELECT revision FROM grants WHERE id='grant'", [], |r| r
                .get::<_, i64>(0))
            .unwrap(),
        7,
        "backup must include committed WAL authority, not just main-file bytes"
    );
    assert_eq!(
        snapshot
            .query_row("PRAGMA quick_check", [], |r| r.get::<_, String>(0))
            .unwrap(),
        "ok"
    );
    assert_eq!(
        authority_digest(&file),
        source_before,
        "backup must not modify the source database"
    );
    assert_eq!(
        writer
            .query_row("SELECT revision FROM grants WHERE id='grant'", [], |r| r
                .get::<_, i64>(0))
            .unwrap(),
        7
    );
    for p in [&backups, &completed[0]] {
        assert_eq!(
            std::fs::metadata(p).unwrap().permissions().mode() & 0o777,
            0o700
        );
    }
    for p in [&database, &completed[0].join("manifest.json")] {
        assert_eq!(
            std::fs::metadata(p).unwrap().permissions().mode() & 0o777,
            0o600
        );
    }
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
}

#[test]
fn init_if_needed_rejects_corrupt_incompatible_and_dangling_state_without_reset() {
    let dir = tempfile::tempdir().unwrap();
    for (name, kind) in [("garbage.db", 0), ("foreign.db", 1), ("future.db", 2)] {
        let file = dir.path().join(name);
        if kind == 0 {
            std::fs::write(&file, b"not an authority database").unwrap();
        } else if kind == 1 {
            rusqlite::Connection::open(&file)
                .unwrap()
                .execute_batch("PRAGMA application_id=42; CREATE TABLE unrelated(value TEXT);")
                .unwrap();
        } else {
            Store::initialize(&file).unwrap();
            rusqlite::Connection::open(&file)
                .unwrap()
                .pragma_update(None, "user_version", 99)
                .unwrap();
        }
        let before = authority_digest(&file);
        let result = run(&file, &["init", "--if-needed"]);
        assert_eq!(
            authority_digest(&file),
            before,
            "invalid existing state was reset"
        );
        assert_eq!(
            result.status.code(),
            Some(1),
            "invalid existing state was accepted: {name}"
        );
    }
    let target = dir.path().join("absent.db");
    let dangling = dir.path().join("dangling.db");
    std::os::unix::fs::symlink(&target, &dangling).unwrap();
    let result = run(&dangling, &["init", "--if-needed"]);
    assert!(
        !target.exists(),
        "dangling initialization must never create the symlink target"
    );
    assert!(std::fs::symlink_metadata(&dangling)
        .unwrap()
        .file_type()
        .is_symlink());
    assert_eq!(result.status.code(), Some(1));
    let valid = dir.path().join("valid.db");
    Store::initialize(&valid).unwrap();
    let alias = dir.path().join("alias.db");
    std::os::unix::fs::symlink(&valid, &alias).unwrap();
    let before = authority_digest(&valid);
    let result = run(&alias, &["init", "--if-needed"]);
    assert_eq!(authority_digest(&valid), before);
    assert!(std::fs::symlink_metadata(&alias)
        .unwrap()
        .file_type()
        .is_symlink());
    assert!(
        result.status.success(),
        "a valid existing alias must retain the existing readonly-open behavior"
    );
}

#[test]
fn enroll_if_needed_inserts_disabled_once_and_refuses_binding_changes() {
    let dir = tempfile::tempdir().unwrap();
    let file = dir.path().join("state.db");
    Store::initialize(&file).unwrap();
    let document = dir.path().join("binding.json");
    let original = serde_json::json!({"service":"service","issuer":"issuer","resource":"resource","subject":"subject","hosted_client":"client"});
    std::fs::write(&document, serde_json::to_vec(&original).unwrap()).unwrap();
    let result = run(
        &file,
        &["enroll", "--if-needed", "grant", document.to_str().unwrap()],
    );
    let c = rusqlite::Connection::open(&file).unwrap();
    assert_eq!(
        c.query_row(
            "SELECT revision,enabled FROM grants WHERE id='grant'",
            [],
            |r| Ok((r.get::<_, i64>(0)?, r.get::<_, bool>(1)?))
        )
        .unwrap(),
        (1, false),
        "new enrollment must remain disabled at revision one"
    );
    drop(c);
    assert!(result.status.success());
    let before = authority_digest(&file);
    for field in ["service", "issuer", "resource", "subject", "hosted_client"] {
        let mut changed = original.clone();
        changed[field] = serde_json::json!(format!("other-{field}"));
        std::fs::write(&document, serde_json::to_vec(&changed).unwrap()).unwrap();
        let result = run(
            &file,
            &["enroll", "--if-needed", "grant", document.to_str().unwrap()],
        );
        assert_eq!(
            authority_digest(&file),
            before,
            "binding mismatch {field} changed authority"
        );
        assert_eq!(
            result.status.code(),
            Some(1),
            "binding mismatch {field} was silently accepted"
        );
    }
}

#[test]
fn strict_duplicate_enrollment_preserves_legacy_enabled_authority() {
    let dir = tempfile::tempdir().unwrap();
    let file = dir.path().join("state.db");
    let mut store = Store::initialize(&file).unwrap();
    store
        .enroll(
            "grant",
            &xmsg_mcp_gateway::grants::Binding {
                service: "service".into(),
                issuer: "issuer".into(),
                resource: "resource".into(),
                subject: "subject".into(),
                hosted_client: "client".into(),
            },
        )
        .unwrap();
    drop(store);
    rusqlite::Connection::open(&file)
        .unwrap()
        .execute("UPDATE grants SET revision=7,enabled=1", [])
        .unwrap();
    let document = dir.path().join("binding.json");
    std::fs::write(&document, br#"{"service":"other","issuer":"issuer","resource":"resource","subject":"subject","hosted_client":"client"}"#).unwrap();
    let before = authority_digest(&file);
    let result = run(&file, &["enroll", "grant", document.to_str().unwrap()]);
    assert_eq!(
        authority_digest(&file),
        before,
        "strict duplicate enrollment clobbered legacy authority"
    );
    assert_eq!(result.status.code(), Some(1));
}

#[test]
#[ignore = "test-only SQLite crash writer; parent supplies private fixture and kills/reaps it"]
fn hot_journal_writer_for_migrations_cli() {
    let file = std::env::var_os("UNIT5_HOT_DB").expect("crash helper requires fixture database");
    let ready = std::env::var_os("UNIT5_HOT_READY").unwrap();
    let c = rusqlite::Connection::open(file).unwrap();
    c.execute_batch("PRAGMA journal_mode=DELETE; PRAGMA synchronous=FULL; PRAGMA cache_size=1; PRAGMA cache_spill=ON; BEGIN IMMEDIATE; UPDATE crash_marker SET value='uncommitted' WHERE id=1; UPDATE grants SET revision=99,enabled=0; INSERT INTO crash_marker SELECT value+2,zeroblob(8192) FROM json_each('[0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15]');").unwrap();
    std::fs::write(ready, b"READY").unwrap();
    loop {
        std::thread::sleep(std::time::Duration::from_secs(1));
    }
}

#[test]
fn migrations_pending_cli_preserves_hot_journal_before_rollback_and_reports_pending() {
    use std::os::unix::fs::PermissionsExt;
    use std::os::unix::process::ExitStatusExt;
    struct Writer(std::process::Child);
    impl Drop for Writer {
        fn drop(&mut self) {
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }
    let dir = tempfile::tempdir().unwrap();
    let file = dir.path().join("state.db");
    Store::initialize(&file).unwrap();
    rusqlite::Connection::open(&file).unwrap().execute_batch("CREATE TABLE crash_marker(id INTEGER PRIMARY KEY,value BLOB); INSERT INTO crash_marker VALUES(1,'committed'); INSERT INTO grants VALUES('grant','service','issuer','resource','subject','client',1,1);").unwrap();
    let committed = authority_digest(&file);
    let ready = dir.path().join("ready");
    let mut writer = Writer(
        Command::new(std::env::current_exe().unwrap())
            .args([
                "--ignored",
                "--exact",
                "hot_journal_writer_for_migrations_cli",
                "--nocapture",
            ])
            .env("UNIT5_HOT_DB", &file)
            .env("UNIT5_HOT_READY", &ready)
            .spawn()
            .unwrap(),
    );
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(15);
    while !ready.exists() {
        assert!(
            writer.0.try_wait().unwrap().is_none(),
            "crash writer exited before READY"
        );
        assert!(
            std::time::Instant::now() < deadline,
            "crash writer READY deadline"
        );
        std::thread::sleep(std::time::Duration::from_millis(10));
    }
    writer.0.kill().unwrap();
    assert_eq!(writer.0.wait().unwrap().signal(), Some(9));
    let raw_database = std::fs::read(&file).unwrap();
    assert_ne!(
        authority_digest(&file),
        committed,
        "dirty pages must spill before the crash"
    );
    let journal = dir.path().join("state.db-journal");
    let raw_journal = std::fs::read(&journal).unwrap();
    assert!(raw_journal.len() > 512);
    assert_eq!(
        &raw_journal[..8],
        &[0xd9, 0xd5, 0x05, 0xf9, 0x20, 0xa1, 0x63, 0xd7]
    );
    let result = run(&file, &["migrations-pending"]);
    let recovery = dir.path().join("state.db.recovery");
    assert!(
        recovery.is_dir(),
        "migrations-pending must preserve crash evidence before rollback"
    );
    let pairs: Vec<_> = std::fs::read_dir(&recovery)
        .unwrap()
        .map(|e| e.unwrap().path())
        .collect();
    assert_eq!(
        pairs.len(),
        1,
        "migrations-pending must preserve one crash pair"
    );
    use sha2::Digest;
    assert_eq!(
        authority_digest(&pairs[0].join("database")),
        <[u8; 32]>::from(sha2::Sha256::digest(&raw_database))
    );
    assert_eq!(
        authority_digest(&pairs[0].join("journal")),
        <[u8; 32]>::from(sha2::Sha256::digest(&raw_journal))
    );
    for item in [&recovery, &pairs[0]] {
        assert_eq!(
            std::fs::metadata(item).unwrap().permissions().mode() & 0o777,
            0o700
        );
    }
    for item in [pairs[0].join("database"), pairs[0].join("journal")] {
        assert_eq!(
            std::fs::metadata(item).unwrap().permissions().mode() & 0o777,
            0o600
        );
    }
    assert_eq!(
        result.status.code(),
        Some(10),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    assert_eq!(result.stdout, b"migrate-custody\nmigrate-outbound\nmigrate-retirement\nmigrate-custody-summaries\nmigrate-events\nmigrate-profiles\nmigrate-attachments\nmigrate-authorization-server\n");
    let c =
        rusqlite::Connection::open_with_flags(&file, rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY)
            .unwrap();
    assert_eq!(
        c.query_row("SELECT value FROM crash_marker WHERE id=1", [], |r| r
            .get::<_, String>(0))
            .unwrap(),
        "committed"
    );
    assert_eq!(
        c.query_row(
            "SELECT revision,enabled FROM grants WHERE id='grant'",
            [],
            |r| Ok((r.get::<_, i64>(0)?, r.get::<_, bool>(1)?))
        )
        .unwrap(),
        (1, true)
    );
}

#[test]
fn backup_if_pending_resolves_relative_directory_in_cli_working_directory() {
    let dir = tempfile::tempdir().unwrap();
    let file = dir.path().join("state.db");
    Store::initialize(&file).unwrap();
    let result = Command::new(env!("CARGO_BIN_EXE_xmsg-mcp-gateway"))
        .current_dir(dir.path())
        .arg("--state")
        .arg(&file)
        .args([
            "backup-if-pending",
            "--backup-dir",
            "backups",
            "--keep",
            "1",
        ])
        .output()
        .unwrap();
    let root = dir.path().join("backups");
    let complete = std::fs::read_dir(&root)
        .unwrap()
        .filter_map(Result::ok)
        .filter(|entry| entry.path().join("manifest.json").is_file())
        .count();
    assert_eq!(
        complete, 1,
        "relative backup directory must receive a completed snapshot"
    );
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
}

#[test]
fn backup_if_pending_complete_store_does_not_prune_existing_snapshots() {
    let dir = tempfile::tempdir().unwrap();
    let file = dir.path().join("state.db");
    Store::initialize(&file).unwrap();
    let root = dir.path().join("backups");
    for _ in 0..3 {
        assert!(run(
            &file,
            &[
                "backup-if-pending",
                "--backup-dir",
                root.to_str().unwrap(),
                "--keep",
                "10"
            ]
        )
        .status
        .success());
    }
    let event_key = key(dir.path());
    for command in COMMANDS {
        let mut args = vec![command, "--if-needed"];
        if command == "migrate-events" {
            args.extend(["--key-file", event_key.to_str().unwrap()]);
        }
        let result = run(&file, &args);
        assert!(
            result.status.success(),
            "{}",
            String::from_utf8_lossy(&result.stderr)
        );
    }
    assert!(run(&file, &["migrations-pending"]).status.success());
    let inventory = || {
        let mut found: Vec<_> = std::fs::read_dir(&root)
            .unwrap()
            .map(|entry| {
                let artifact = entry.unwrap().path();
                (
                    artifact.file_name().unwrap().to_owned(),
                    authority_digest(&artifact.join("database")),
                    authority_digest(&artifact.join("manifest.json")),
                )
            })
            .collect();
        found.sort();
        found
    };
    let before = inventory();
    assert_eq!(before.len(), 3);
    let authority = authority_digest(&file);
    let result = run(
        &file,
        &[
            "backup-if-pending",
            "--backup-dir",
            root.to_str().unwrap(),
            "--keep",
            "1",
        ],
    );
    assert_eq!(
        inventory(),
        before,
        "a complete store must not prune its existing rollback snapshots"
    );
    assert_eq!(authority_digest(&file), authority);
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
}

#[test]
fn backup_if_pending_rejects_zero_retention_before_filesystem_effects() {
    let dir = tempfile::tempdir().unwrap();
    let file = dir.path().join("state.db");
    Store::initialize(&file).unwrap();
    let root = dir.path().join("backups");
    let before = authority_digest(&file);
    let result = run(
        &file,
        &[
            "backup-if-pending",
            "--backup-dir",
            root.to_str().unwrap(),
            "--keep",
            "0",
        ],
    );
    assert!(!root.exists());
    assert_eq!(authority_digest(&file), before);
    assert_eq!(result.status.code(), Some(2));
}
