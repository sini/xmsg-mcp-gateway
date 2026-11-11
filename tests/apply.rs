use rusqlite::Connection;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use xmsg_mcp_gateway::event_store::EventKey;
use xmsg_mcp_gateway::grants::{Binding, Error as GrantError, Store};
use xmsg_mcp_gateway::outbound::{Error, Policy};
#[path = "common/outbound_observer.rs"]
mod observer;

fn binding() -> Binding {
    Binding {
        service: "gateway".into(),
        issuer: "issuer".into(),
        resource: "resource".into(),
        subject: "owner".into(),
        hosted_client: "client".into(),
    }
}
fn base() -> (tempfile::TempDir, Store, PathBuf) {
    use std::os::unix::fs::PermissionsExt;
    let dir = tempfile::tempdir().unwrap();
    let file = dir.path().join("state.db");
    let mut store = Store::initialize(&file).unwrap();
    store.migrate_custody().unwrap();
    store.migrate_outbound().unwrap();
    store.migrate_retirement().unwrap();
    let key = dir.path().join("key");
    std::fs::write(&key, [9u8; 32]).unwrap();
    std::fs::set_permissions(&key, std::fs::Permissions::from_mode(0o600)).unwrap();
    store
        .migrate_events(&EventKey::load(&key).unwrap())
        .unwrap();
    store.enroll("grant", &binding()).unwrap();
    (dir, store, file)
}
fn policy(target: &str) -> Policy {
    serde_json::from_value(
        serde_json::json!({"send":{"targets":[target],"required_scope":"send:write"},"reply":null}),
    )
    .unwrap()
}
fn state(file: &Path) -> (i64, bool) {
    Connection::open(file)
        .unwrap()
        .query_row(
            "SELECT revision,enabled FROM grants WHERE id='grant'",
            [],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .unwrap()
}
fn snapshot(file: &Path) -> Vec<(String, Vec<String>)> {
    let sql = Connection::open(file).unwrap();
    let names = sql
        .prepare("SELECT name FROM sqlite_master WHERE type='table' ORDER BY name")
        .unwrap()
        .query_map([], |r| r.get::<_, String>(0))
        .unwrap()
        .collect::<Result<Vec<_>, _>>()
        .unwrap();
    names
        .into_iter()
        .map(|name| {
            let mut statement = sql
                .prepare(&format!("SELECT * FROM \"{}\"", name.replace('"', "\"\"")))
                .unwrap();
            let columns = statement.column_count();
            let mut rows = statement
                .query_map([], |row| {
                    Ok((0..columns)
                        .map(|i| format!("{:?}", row.get_ref(i).unwrap()))
                        .collect::<Vec<_>>()
                        .join("|"))
                })
                .unwrap()
                .collect::<Result<Vec<_>, _>>()
                .unwrap();
            rows.sort();
            (name, rows)
        })
        .collect()
}
fn cli(file: &Path, policy: &Path, extra: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_xmsg-mcp-gateway"))
        .args(["--state"])
        .arg(file)
        .args(["apply", "--id", "grant", "--policy"])
        .arg(policy)
        .args(extra)
        .output()
        .unwrap()
}
fn seed_events(file: &Path) {
    let sql = Connection::open(file).unwrap();
    sql.execute_batch("INSERT INTO custody_items(bus,upstream_id,event_id,grant_id,grant_revision,mailbox,owner,origin,text,envelope,fingerprint,received_at,expires_at,held) VALUES ('bus','upstream','event','grant',1,'gateway@bus','owner','{}','retained body','envelope','fingerprint',1,9999999999,1);
        INSERT INTO custody_outbox(event_id,state) VALUES ('event','pending');
        INSERT INTO event_authorizations(event_id,acceptance_class,acceptance_enabled,acceptance_ever_enabled) VALUES ('event','never_enabled',0,0);
        INSERT INTO event_occurrences(event_id) VALUES ('event');
        INSERT INTO event_subscriptions(id,owner_key,service,issuer,resource,subject,hosted_client,bus,mailbox,grant_id,grant_revision,generation,expires,url,secret,bearer,status) VALUES ('subscription','owner-key','gateway','issuer','resource','owner','client','bus','gateway@bus','grant',1,1,9999999999,X'01',X'02',X'03','active');").unwrap();
}

#[test]
fn apply_cli_is_idempotent_typed_and_preserves_enablement_without_a_flag() {
    let (dir, _store, file) = base();
    let input = dir.path().join("policy.json");
    std::fs::write(
        &input,
        r#"{"send":{"targets":["b@node","a@node"],"required_scope":"send:write"},"reply":null}"#,
    )
    .unwrap();
    assert!(cli(&file, &input, &["--enabled"]).status.success());
    assert_eq!(state(&file), (3, true));
    let before = snapshot(&file);
    std::fs::write(&input,r#"{ "reply":null,"send":{ "required_scope":"send:write", "targets":["a@node","b@node","a@node"] } }"#).unwrap();
    let output = cli(&file, &input, &["--enabled"]);
    assert!(output.status.success());
    assert_eq!(
        String::from_utf8(output.stdout).unwrap(),
        "unchanged at revision 3\n"
    );
    assert_eq!(
        snapshot(&file),
        before,
        "typed-equivalent JSON moved business state"
    );
    std::fs::write(&input, serde_json::to_vec(&policy("c@node")).unwrap()).unwrap();
    assert!(cli(&file, &input, &[]).status.success());
    assert_eq!(
        state(&file),
        (4, true),
        "absent enablement flag disabled the grant"
    );
    assert!(cli(&file, &input, &["--disabled"]).status.success());
    assert_eq!(state(&file), (5, false));
    let before = snapshot(&file);
    assert!(!cli(&file, &input, &["--enabled", "--disabled"])
        .status
        .success());
    assert_eq!(snapshot(&file), before);
}

#[test]
fn apply_revisions_and_policy_writes_are_minimal() {
    let (_dir, mut store, file) = base();
    let sql = Connection::open(&file).unwrap();
    sql.execute_batch("CREATE TABLE policy_writes(kind TEXT); CREATE TRIGGER count_policy_insert AFTER INSERT ON outbound_policy BEGIN INSERT INTO policy_writes VALUES ('insert'); END; CREATE TRIGGER count_policy_update AFTER UPDATE ON outbound_policy BEGIN INSERT INTO policy_writes VALUES ('update'); END;").unwrap();
    let noop = store
        .apply_outbound_policy("grant", &Policy::default(), None)
        .unwrap();
    assert_eq!((noop.revision, noop.changed), (1, false));
    let first = store
        .apply_outbound_policy("grant", &policy("a@node"), None)
        .unwrap();
    assert_eq!((first.revision, first.changed), (2, true));
    assert_eq!(state(&file), (2, false));
    assert_eq!(
        store
            .apply_outbound_policy("grant", &policy("a@node"), Some(true))
            .unwrap()
            .revision,
        3
    );
    assert_eq!(
        store
            .apply_outbound_policy("grant", &policy("b@node"), Some(false))
            .unwrap()
            .revision,
        5
    );
    assert_eq!(state(&file), (5, false));
    assert_eq!(
        sql.query_row("SELECT COUNT(*) FROM policy_writes", [], |r| r
            .get::<_, i64>(0))
            .unwrap(),
        2,
        "apply wrote an equal policy or wrote a changed policy twice"
    );
    let before = snapshot(&file);
    let noop = store
        .apply_outbound_policy("grant", &policy("b@node"), Some(false))
        .unwrap();
    assert_eq!((noop.revision, noop.changed), (5, false));
    assert_eq!(snapshot(&file), before);
}

#[test]
fn invalid_apply_policy_and_missing_grant_never_write_business_state() {
    let (_dir, mut store, file) = base();
    seed_events(&file);
    let before = snapshot(&file);
    for document in [
        serde_json::json!({"reply":{"targets":[],"required_scope":"reply:write"}}),
        serde_json::json!({"send":{"targets":["invalid"],"required_scope":"send:write"}}),
        serde_json::json!({"send":{"targets":["a@node"],"required_scope":" "}}),
    ] {
        let invalid: Policy = serde_json::from_value(document).unwrap();
        assert!(
            matches!(
                store.apply_outbound_policy("grant", &invalid, Some(true)),
                Err(Error::Configuration)
            ),
            "apply accepted an invalid policy"
        );
        assert_eq!(
            snapshot(&file),
            before,
            "invalid apply changed business state"
        );
    }
    assert!(matches!(
        store.apply_outbound_policy("missing", &policy("a@node"), Some(true)),
        Err(Error::Authority(GrantError::NoChange))
    ));
    assert_eq!(snapshot(&file), before);
}

#[test]
fn apply_enable_conflict_rolls_back_policy_revision_events_and_custody() {
    let (_dir, mut store, file) = base();
    store
        .enroll(
            "other",
            &Binding {
                subject: "other-owner".into(),
                ..binding()
            },
        )
        .unwrap();
    store.set_enabled("other", 1, true).unwrap();
    seed_events(&file);
    let before = snapshot(&file);
    assert!(matches!(
        store.apply_outbound_policy("grant", &policy("a@node"), Some(true)),
        Err(Error::Authority(GrantError::Conflict))
    ));
    assert_eq!(
        snapshot(&file),
        before,
        "enable conflict committed part of apply"
    );
}

#[test]
fn apply_reuses_events_transitions_at_each_actual_revision_change() {
    let (_dir, mut store, file) = base();
    seed_events(&file);
    assert_eq!(
        store
            .apply_outbound_policy("grant", &policy("a@node"), Some(true))
            .unwrap()
            .revision,
        3
    );
    let sql = Connection::open(&file).unwrap();
    let released:(i64,i64,String,i64)=sql.query_row("SELECT a.old_revision,a.new_revision,o.state,s.generation FROM event_release_audit a JOIN custody_outbox o USING(event_id),event_subscriptions s",[],|r|Ok((r.get(0)?,r.get(1)?,r.get(2)?,r.get(3)?))).unwrap();
    assert_eq!(released, (1, 3, "pending".into(), 2));
    assert_eq!(
        store
            .apply_outbound_policy("grant", &policy("b@node"), Some(true))
            .unwrap()
            .revision,
        4
    );
    assert_eq!(state(&file), (4, true));
    let held: (String, i64) = sql
        .query_row(
            "SELECT o.state,s.generation FROM custody_outbox o,event_subscriptions s",
            [],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .unwrap();
    assert_eq!(held, ("pending".into(), 2));
    assert_eq!(
        sql.query_row("SELECT COUNT(*) FROM event_release_audit", [], |r| r
            .get::<_, i64>(0))
            .unwrap(),
        1
    );
    let before = snapshot(&file);
    assert!(
        !store
            .apply_outbound_policy("grant", &policy("b@node"), Some(true))
            .unwrap()
            .changed
    );
    assert_eq!(snapshot(&file), before);
}

#[test]
fn apply_rechecks_the_pre_lease_revision_even_for_a_prospective_noop() {
    use std::sync::{
        atomic::{AtomicBool, Ordering},
        mpsc, Arc,
    };
    use std::time::Duration;
    for noop in [false, true] {
        let (_dir, store, file) = base();
        let held = store.try_operation_lease("gateway").unwrap().unwrap();
        let (tx, rx) = mpsc::channel();
        let signaled = Arc::new(AtomicBool::new(false));
        let worker_file = file.clone();
        let worker = std::thread::spawn(move || {
            let observer = observer::AtEvent {
                target: "gateway_operation_wait",
                action: move || {
                    if !signaled.swap(true, Ordering::SeqCst) {
                        tx.send(()).unwrap();
                    }
                },
            };
            tracing::subscriber::with_default(observer, || {
                Store::open(&worker_file).unwrap().apply_outbound_policy(
                    "grant",
                    &if noop {
                        Policy::default()
                    } else {
                        policy("a@node")
                    },
                    None,
                )
            })
        });
        rx.recv_timeout(Duration::from_secs(3))
            .expect("apply never reached service lease contention");
        let sql = Connection::open(&file).unwrap();
        sql.execute("UPDATE grants SET revision=revision+1 WHERE id='grant'", [])
            .unwrap();
        let winner = snapshot(&file);
        drop(held);
        assert!(
            matches!(
                worker.join().unwrap(),
                Err(Error::Authority(GrantError::NoChange))
            ),
            "apply overwrote a concurrent revision, including no-op={noop}"
        );
        assert_eq!(snapshot(&file), winner);
    }
}
