use std::path::Path;
use std::process::{Command, Output};
use xmsg_mcp_gateway::grants::Store;

const COMMANDS: [&str; 5] = [
    "migrate-custody",
    "migrate-custody-summaries",
    "migrate-outbound",
    "migrate-retirement",
    "migrate-events",
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
