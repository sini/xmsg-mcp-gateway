use std::path::Path;
use std::process::{Command, Output};
use xmsg_mcp_gateway::grants::Store;

const COMMANDS: [&str; 7] = [
    "migrate-custody",
    "migrate-custody-summaries",
    "migrate-outbound",
    "migrate-retirement",
    "migrate-events",
    "migrate-profiles",
    "migrate-attachments",
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
    inspect(b"migrate-custody\nmigrate-outbound\nmigrate-retirement\nmigrate-custody-summaries\nmigrate-events\nmigrate-profiles\nmigrate-attachments\n", 10);
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
    let (release_tx, release_rx) = mpsc::channel();
    let inspection_file = file.clone();
    let inspector = std::thread::spawn(move || {
        let release_rx = Mutex::new(release_rx);
        tracing::subscriber::with_default(
            outbound_observer::AtEvent {
                target: "gateway_migrations_snapshot",
                action: move || {
                    selected_tx.send(()).unwrap();
                    release_rx
                        .lock()
                        .unwrap()
                        .recv_timeout(Duration::from_secs(3))
                        .unwrap();
                },
            },
            || {
                Store::open_readonly(&inspection_file)
                    .unwrap()
                    .pending_migrations()
                    .unwrap()
            },
        )
    });
    selected_rx.recv_timeout(Duration::from_secs(3)).unwrap();
    Store::open(&file).unwrap().migrate_custody().unwrap();
    release_tx.send(()).unwrap();
    assert_eq!(
        inspector.join().unwrap().len(),
        7,
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
            "migrate-attachments"
        ]
    );
}
