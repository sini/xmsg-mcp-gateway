use rusqlite::Connection;
use xmsg_mcp_gateway::grants::{Binding, Store};

#[test]
fn migration_is_explicit_and_preserves_disabled_authority() {
    let temp = tempfile::tempdir().unwrap();
    let db = temp.path().join("authority.db");
    let mut store = Store::initialize(&db).unwrap();
    store
        .enroll(
            "owner-grant",
            &Binding {
                service: "gateway".into(),
                issuer: "https://issuer.example/".into(),
                resource: "https://gateway.example/mcp".into(),
                subject: "owner".into(),
                hosted_client: "hosted-client".into(),
            },
        )
        .unwrap();
    drop(store);
    let mut store = Store::open(&db).unwrap();
    let inspect = Connection::open(&db).unwrap();
    let before: i64 = inspect
        .pragma_query_value(None, "user_version", |row| row.get(0))
        .unwrap();
    assert_eq!(before, 1, "opening silently migrated state");
    let migrated = std::process::Command::new(env!("CARGO_BIN_EXE_xmsg-mcp-gateway"))
        .arg("--state")
        .arg(&db)
        .arg("migrate-custody")
        .output()
        .unwrap();
    assert!(migrated.status.success(), "owner migration command failed");
    assert_eq!(
        String::from_utf8(migrated.stdout).unwrap(),
        "custody schema migrated; startup remains unavailable\n"
    );
    let after: i64 = inspect
        .pragma_query_value(None, "user_version", |row| row.get(0))
        .unwrap();
    assert_eq!(after, 2);
    let snapshot: (String, i64, bool) = inspect
        .query_row(
            "SELECT subject, revision, enabled FROM grants WHERE id='owner-grant'",
            [],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .unwrap();
    assert_eq!(snapshot, ("owner".into(), 1, false));
    assert!(
        store.migrate_custody().is_err(),
        "unchanged migration reported success"
    );
    drop(store);
    Store::open(&db).unwrap();
}

#[test]
fn failed_migration_rolls_back_all_tables_and_version() {
    let temp = tempfile::tempdir().unwrap();
    let db = temp.path().join("authority.db");
    let mut store = Store::initialize(&db).unwrap();
    let inspect = Connection::open(&db).unwrap();
    inspect
        .execute("CREATE TABLE custody_metadata (foreign_data TEXT)", [])
        .unwrap();
    assert!(store.migrate_custody().is_err());
    let version: i64 = inspect
        .pragma_query_value(None, "user_version", |row| row.get(0))
        .unwrap();
    assert_eq!(version, 1, "failed migration changed version");
    let partial: i64 = inspect.query_row("SELECT COUNT(*) FROM sqlite_schema WHERE name IN ('custody_items','custody_outbox','custody_counters')", [], |row| row.get(0)).unwrap();
    assert_eq!(partial, 0, "failed migration retained partial tables");
}

#[test]
fn corrupt_custody_state_is_not_silently_recreated() {
    let temp = tempfile::tempdir().unwrap();
    let db = temp.path().join("authority.db");
    let mut store = Store::initialize(&db).unwrap();
    store.migrate_custody().unwrap();
    drop(store);
    Connection::open(&db)
        .unwrap()
        .execute("DROP TABLE custody_outbox", [])
        .unwrap();
    assert!(
        Store::open(&db).is_err(),
        "missing custody schema was accepted"
    );
}
