use std::os::unix::fs::PermissionsExt;
use xmsg_mcp_gateway::grants::{Binding, Store};

#[test]
fn cutover_cli_reports_busy_unread_and_complete_without_outbox_state_confusion() {
    for scenario in [
        "busy",
        "unread-dispatching",
        "observed-pending",
        "observed-held",
        "abandon",
    ] {
        let directory = tempfile::tempdir().unwrap();
        let file = directory.path().join("state.db");
        let key_file = directory.path().join("key");
        std::fs::write(&key_file, [7u8; 32]).unwrap();
        std::fs::set_permissions(&key_file, std::fs::Permissions::from_mode(0o600)).unwrap();
        let mut store = Store::initialize(&file).unwrap();
        store.migrate_profiles().unwrap();
        for (id, issuer) in [
            ("old", "https://old.example"),
            ("new", "https://new.example"),
        ] {
            store
                .enroll(
                    id,
                    &Binding {
                        service: "gateway".into(),
                        issuer: issuer.into(),
                        resource: "https://gateway.example/mcp".into(),
                        subject: "owner".into(),
                        hosted_client: "dot".into(),
                    },
                )
                .unwrap();
            store.set_enabled(id, 1, true).unwrap();
        }
        store.migrate_custody().unwrap();
        store.migrate_outbound().unwrap();
        store.migrate_retirement().unwrap();
        store
            .migrate_events(&xmsg_mcp_gateway::event_store::EventKey::load(&key_file).unwrap())
            .unwrap();
        store.migrate_authorization_server().unwrap();
        let db = rusqlite::Connection::open(&file).unwrap();
        db.execute_batch("INSERT INTO custody_items(bus,upstream_id,event_id,grant_id,grant_revision,mailbox,owner,origin,text,envelope,fingerprint,received_at,expires_at,held) VALUES('bus','item','item','old',2,'gateway@bus','owner','{}','body','{}','fingerprint',1,9999999999,1);").unwrap();
        let state = match scenario {
            "unread-dispatching" => "dispatching",
            "observed-held" => "held",
            _ => "pending",
        };
        db.execute(
            "INSERT INTO custody_outbox(event_id,state) VALUES('item',?1)",
            [state],
        )
        .unwrap();
        if scenario.starts_with("observed") {
            db.execute("INSERT INTO event_observations VALUES('item',1)", [])
                .unwrap();
        }
        let config = directory.path().join("owner.json");
        std::fs::write(&config,serde_json::json!({"bind":"127.0.0.1:0","grant_store":file,"request_timeout_ms":5000,"allowed_hosts":["gateway.example"],"allowed_origins":[]}).to_string()).unwrap();
        std::fs::set_permissions(&config, std::fs::Permissions::from_mode(0o600)).unwrap();
        let lease =
            (scenario == "busy").then(|| store.try_operation_lease("gateway").unwrap().unwrap());
        let mut command = std::process::Command::new(env!("CARGO_BIN_EXE_xmsg-mcp-gateway"));
        command
            .args(["cutover-events", "--config"])
            .arg(&config)
            .args([
                "--from",
                "old",
                "--to",
                "new",
                "--operator",
                "fixture",
                "--reason",
                "cutover control",
            ]);
        if scenario == "abandon" {
            command.arg("--abandon-unread");
        }
        let output = command.output().unwrap();
        let expected = match scenario {
            "busy" => 4,
            "unread-dispatching" => 3,
            _ => 0,
        };
        assert_eq!(
            output.status.code(),
            Some(expected),
            "CLI cutover class wrong: {scenario}; {}",
            String::from_utf8_lossy(&output.stderr)
        );
        let markers: i64 = db
            .query_row("SELECT COUNT(*) FROM events_cutover", [], |r| r.get(0))
            .unwrap();
        assert_eq!(
            markers,
            i64::from(expected == 0),
            "failed cutover wrote marker: {scenario}"
        );
        let audit: i64 = db
            .query_row("SELECT COUNT(*) FROM event_release_audit", [], |r| r.get(0))
            .unwrap();
        assert_eq!(audit, i64::from(scenario == "abandon"));
        drop(lease);
    }
}
