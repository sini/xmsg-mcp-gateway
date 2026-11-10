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
        "custody schema migrated; worker startup remains unavailable\n"
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

#[test]
fn explicit_summary_owner_command_preserves_outbound_and_events_versions() {
    use xmsg_mcp_gateway::event_store::EventKey;
    for schema in [2, 3, 4] {
        let directory = tempfile::tempdir().unwrap();
        let file = directory.path().join("store.db");
        let mut store = Store::initialize(&file).unwrap();
        store.migrate_custody().unwrap();
        if schema >= 3 {
            store.migrate_outbound().unwrap();
            store.migrate_retirement().unwrap();
        }
        if schema == 4 {
            let keyfile = directory.path().join("events.key");
            std::fs::write(&keyfile, [8; 32]).unwrap();
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                std::fs::set_permissions(&keyfile, std::fs::Permissions::from_mode(0o600)).unwrap();
            }
            store
                .migrate_events(&EventKey::load(&keyfile).unwrap())
                .unwrap();
        }
        let db = Connection::open(&file).unwrap();
        db.execute_batch("DROP TABLE custody_refusal_summaries; DROP TABLE custody_gap_summary;
            PRAGMA application_id=1481459538;
            INSERT INTO custody_metadata VALUES('bus','one','hash','origin',11,'unknown-legacy-reason',10,1000);
            INSERT INTO custody_gaps VALUES('bus',10,510,1000),('bus',600,601,1100);").unwrap();
        if schema == 2 {
            db.pragma_update(None, "application_id", 0x584d4757_i64)
                .unwrap();
        }
        drop(store);
        let mut old = Store::open(&file).unwrap();
        assert!(
            old.record_custody_link(
                &xmsg_mcp_gateway::custody::Scope {
                    bus_instance: "bus".into(),
                    grant_id: "grant".into()
                },
                true,
                &Default::default(),
                std::time::UNIX_EPOCH + std::time::Duration::from_secs(100)
            )
            .is_err(),
            "legacy custody started without explicit summary migration"
        );
        drop(old);
        let migrated = std::process::Command::new(env!("CARGO_BIN_EXE_xmsg-mcp-gateway"))
            .arg("--state")
            .arg(&file)
            .arg("migrate-custody-summaries")
            .output()
            .unwrap();
        assert!(
            migrated.status.success(),
            "summary CLI failed: {}",
            String::from_utf8_lossy(&migrated.stderr)
        );
        assert_eq!(
            String::from_utf8(migrated.stdout).unwrap(),
            "custody observations folded into bounded summaries\n"
        );
        let version: i64 = db
            .pragma_query_value(None, "user_version", |r| r.get(0))
            .unwrap();
        assert_eq!(
            version, schema,
            "summary migration skipped or changed Events migration"
        );
        let summary: (String, i64, i64) = db
            .query_row(
                "SELECT reason,observations,max_size FROM custody_refusal_summaries",
                [],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
            )
            .unwrap();
        assert_eq!(summary, ("refusal".into(), 1, 11));
        let widest: i64 = db
            .query_row("SELECT widest FROM custody_gap_summary", [], |r| r.get(0))
            .unwrap();
        assert_eq!(widest, 500);
        if schema >= 3 {
            let retirement: i64 = db
                .query_row("SELECT version FROM outbound_retirement_schema", [], |r| {
                    r.get(0)
                })
                .unwrap();
            assert_eq!(retirement, 5);
        } else {
            let retirement_tables: i64 = db
                .query_row(
                    "SELECT COUNT(*) FROM sqlite_schema WHERE name='outbound_retirement_schema'",
                    [],
                    |r| r.get(0),
                )
                .unwrap();
            assert_eq!(
                retirement_tables, 0,
                "summary migration created outbound state"
            );
        }
        Store::open(&file).unwrap();
    }
}

#[test]
fn summary_marker_requires_all_summary_tables_and_retirement_cannot_downgrade_it() {
    for table in ["custody_refusal_summaries", "custody_gap_summary"] {
        let directory = tempfile::tempdir().unwrap();
        let file = directory.path().join("store.db");
        let mut store = Store::initialize(&file).unwrap();
        store.migrate_custody().unwrap();
        let db = Connection::open(&file).unwrap();
        let marker: i64 = db
            .pragma_query_value(None, "application_id", |r| r.get(0))
            .unwrap();
        store.migrate_outbound().unwrap();
        store.migrate_retirement().unwrap();
        let after: i64 = db
            .pragma_query_value(None, "application_id", |r| r.get(0))
            .unwrap();
        assert_eq!(marker, after, "retirement downgraded summary writer marker");
        db.execute_batch(&format!("DROP TABLE {table}")).unwrap();
        drop(store);
        assert!(
            Store::open(&file).is_err(),
            "partial summary schema was accepted"
        );
    }
}
