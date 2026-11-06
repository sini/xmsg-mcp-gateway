#![cfg(target_os = "linux")]

#[allow(dead_code)]
#[path = "common/real_node.rs"]
mod real_node;

use xmsg_mcp_gateway::custody::{Acceptance, Limits, Scope};
use xmsg_mcp_gateway::grants::{Binding, Store};

#[tokio::test]
#[ignore = "mandatory private-node custody profile"]
async fn commit_before_ack_preserves_the_original_event_across_restart() {
    let binary = real_node::pinned_binary();
    let mut node = real_node::Node::start(&binary).await;
    let temp = tempfile::tempdir().unwrap();
    let db = temp.path().join("authority.db");
    let mut store = Store::initialize(&db).unwrap();
    store
        .enroll(
            "grant",
            &Binding {
                service: "gateway".into(),
                issuer: "https://issuer.example/".into(),
                resource: "https://gateway.example/mcp".into(),
                subject: "owner".into(),
                hosted_client: "hosted-client".into(),
            },
        )
        .unwrap();
    store.migrate_custody().unwrap();
    let scope = Scope {
        bus_instance: "isolated-node-db-1".into(),
        grant_id: "grant".into(),
    };
    let mut service = node.config.register().await.unwrap();
    let sent = service
        .send(
            service.address().unwrap(),
            "original stored bytes",
            Some("custody-crash"),
        )
        .await
        .unwrap();
    let delivery = service.poll(1).await.unwrap().unwrap();
    let first = store
        .accept_delivery(&scope, &service, &delivery, &Limits::default(), 100)
        .unwrap();
    let Acceptance::Stored { event_id } = first else {
        panic!("first delivery was not stored")
    };
    let persisted = rusqlite::Connection::open(&db).unwrap();
    let (text, occurrences, held, snapshot): (String, i64, i64, i64) = persisted.query_row(
        "SELECT text, (SELECT COUNT(*) FROM custody_outbox), held, grant_revision FROM custody_items", [],
        |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
    ).unwrap();
    assert_eq!(
        text, "original stored bytes",
        "stored body differs from the accepted delivery"
    );
    assert_eq!((occurrences, held, snapshot), (1, 1, 1));
    drop(persisted);
    drop(store);
    drop(service);
    node.restart(&binary).await;
    let mut store = Store::open(&db).unwrap();
    let mut service = node.config.register().await.unwrap();
    let again = service.poll(1).await.unwrap().unwrap();
    assert_eq!(again.message_id(), sent.message_id);
    let repeated = store
        .accept_delivery(&scope, &service, &again, &Limits::default(), 101)
        .unwrap();
    assert_eq!(repeated, Acceptance::Duplicate { event_id });
    service.ack(again.message_id()).await.unwrap();
    drop(service);
    node.restart(&binary).await;
    let mut service = node.config.register().await.unwrap();
    assert!(
        service.poll(0).await.unwrap().is_none(),
        "ACK did not survive second restart"
    );
    println!("gateway-custody-complete:commit-before-ack");
}

fn authority(db: &std::path::Path) -> Store {
    let mut store = Store::initialize(db).unwrap();
    store
        .enroll(
            "grant",
            &Binding {
                service: "gateway".into(),
                issuer: "https://issuer.example/".into(),
                resource: "https://gateway.example/mcp".into(),
                subject: "owner".into(),
                hosted_client: "hosted-client".into(),
            },
        )
        .unwrap();
    store
}

#[tokio::test]
#[ignore = "mandatory private-node custody profile"]
async fn oversized_refusal_is_durable_content_free_before_ack() {
    let binary = real_node::pinned_binary();
    let mut node = real_node::Node::start(&binary).await;
    let temp = tempfile::tempdir().unwrap();
    let db = temp.path().join("authority.db");
    let mut store = authority(&db);
    store.migrate_custody().unwrap();
    let scope = Scope {
        bus_instance: "isolated-node-db-1".into(),
        grant_id: "grant".into(),
    };
    let limits = Limits {
        max_item_bytes: 1,
        ..Limits::default()
    };
    let mut service = node.config.register().await.unwrap();
    let sent = service
        .send(
            service.address().unwrap(),
            "private oversized content",
            Some("oversized"),
        )
        .await
        .unwrap();
    assert_eq!(
        xmsg_mcp_gateway::custody::receive_one(&mut store, &mut service, &scope, &limits, 100)
            .await
            .unwrap(),
        Some(Acceptance::Refused)
    );
    drop(store);
    drop(service);
    node.restart(&binary).await;
    let mut service = node.config.register().await.unwrap();
    assert!(
        service.poll(0).await.unwrap().is_none(),
        "permanent refusal retained upstream queue slot"
    );
    let persisted = rusqlite::Connection::open(&db).unwrap();
    let (id, origin, size, reason): (String, String, i64, String) = persisted
        .query_row(
            "SELECT upstream_id, origin, size, reason FROM custody_metadata",
            [],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
        )
        .unwrap();
    assert_eq!(id, sent.message_id);
    assert_eq!(reason, "oversized", "durable refusal missing");
    assert!(
        size > "private oversized content".len() as i64,
        "actual bounded byte size missing"
    );
    assert!(!origin.contains("private oversized content"));
    let count: i64 = persisted
        .query_row("SELECT COUNT(*) FROM custody_items", [], |row| row.get(0))
        .unwrap();
    assert_eq!(count, 0);
    println!("gateway-custody-complete:oversized-refusal");
}

#[tokio::test]
#[ignore = "mandatory private-node custody profile"]
async fn conflict_is_quarantined_before_the_upstream_ack() {
    let binary = real_node::pinned_binary();
    let mut node = real_node::Node::start(&binary).await;
    let temp = tempfile::tempdir().unwrap();
    let db = temp.path().join("authority.db");
    let mut store = authority(&db);
    store.migrate_custody().unwrap();
    let scope = Scope {
        bus_instance: "isolated-node-db-1".into(),
        grant_id: "grant".into(),
    };
    let mut service = node.config.register().await.unwrap();
    let sent = service
        .send(service.address().unwrap(), "original", Some("conflict"))
        .await
        .unwrap();
    let delivery = service.poll(1).await.unwrap().unwrap();
    store
        .accept_delivery(&scope, &service, &delivery, &Limits::default(), 100)
        .unwrap();
    drop(service);
    let node_db = node
        .config
        .register_socket
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .join("node.db");
    let upstream = rusqlite::Connection::open(&node_db).unwrap();
    assert_eq!(
        upstream
            .execute(
                "UPDATE svc_pending_messages SET text = 'changed payload' WHERE id=?1",
                [&sent.message_id]
            )
            .unwrap(),
        1
    );
    drop(upstream);
    node.restart(&binary).await;
    let mut service = node.config.register().await.unwrap();
    assert_eq!(
        xmsg_mcp_gateway::custody::receive_one(
            &mut store,
            &mut service,
            &scope,
            &Limits::default(),
            101
        )
        .await
        .unwrap(),
        Some(Acceptance::Quarantined)
    );
    drop(service);
    node.restart(&binary).await;
    let mut service = node.config.register().await.unwrap();
    assert!(
        service.poll(0).await.unwrap().is_none(),
        "durably quarantined conflict was not ACKed"
    );
    drop(store);
    let persisted = rusqlite::Connection::open(&db).unwrap();
    let conflicts: i64 = persisted
        .query_row(
            "SELECT COUNT(*) FROM custody_metadata WHERE reason='conflict'",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(conflicts, 1, "durable quarantine missing");
    let text: String = persisted
        .query_row("SELECT text FROM custody_items", [], |row| row.get(0))
        .unwrap();
    assert_eq!(text, "original", "conflict replaced original body");
    println!("gateway-custody-complete:conflict-quarantine");
}

#[tokio::test]
#[ignore = "mandatory private-node custody profile"]
async fn failed_transaction_never_acknowledges_or_retains_partial_custody() {
    let binary = real_node::pinned_binary();
    let mut node = real_node::Node::start(&binary).await;
    let temp = tempfile::tempdir().unwrap();
    let db = temp.path().join("authority.db");
    let mut store = authority(&db);
    let scope = Scope {
        bus_instance: "isolated-node-db-1".into(),
        grant_id: "grant".into(),
    };
    let mut service = node.config.register().await.unwrap();
    let sent = service
        .send(
            service.address().unwrap(),
            "must remain upstream",
            Some("failed-commit"),
        )
        .await
        .unwrap();
    assert!(
        matches!(
            xmsg_mcp_gateway::custody::receive_one(
                &mut store,
                &mut service,
                &scope,
                &Limits::default(),
                100
            )
            .await,
            Err(xmsg_mcp_gateway::custody::Error::MigrationRequired)
        ),
        "legacy custody did not refuse before polling"
    );
    let injected = rusqlite::Connection::open(&db).unwrap();
    let version: i64 = injected
        .pragma_query_value(None, "user_version", |row| row.get(0))
        .unwrap();
    assert_eq!(version, 1, "custody entry silently migrated state");
    store.migrate_custody().unwrap();
    injected.execute_batch("CREATE TRIGGER reject_outbox BEFORE INSERT ON custody_outbox BEGIN SELECT RAISE(ABORT, 'fixture disk failure'); END;").unwrap();
    drop(injected);
    assert!(
        xmsg_mcp_gateway::custody::receive_one(
            &mut store,
            &mut service,
            &scope,
            &Limits::default(),
            100
        )
        .await
        .is_err(),
        "failed custody transaction was not attempted after explicit migration"
    );
    drop(service);
    node.restart(&binary).await;
    let mut service = node.config.register().await.unwrap();
    let redelivered = service.poll(1).await.unwrap();
    assert!(
        redelivered.is_some(),
        "failed custody transaction ACKed upstream"
    );
    assert_eq!(redelivered.unwrap().message_id(), sent.message_id);
    let inspected = rusqlite::Connection::open(&db).unwrap();
    let rows: i64 = inspected
        .query_row("SELECT COUNT(*) FROM custody_items", [], |row| row.get(0))
        .unwrap();
    assert_eq!(rows, 0, "partial custody survived failed transaction");
    println!("gateway-custody-complete:failed-transaction");
}

#[tokio::test]
#[ignore = "mandatory private-node custody profile"]
async fn permanent_refusals_do_not_starve_valid_traffic() {
    let binary = real_node::pinned_binary();
    let node = real_node::Node::start(&binary).await;
    let temp = tempfile::tempdir().unwrap();
    let db = temp.path().join("authority.db");
    let mut store = authority(&db);
    store.migrate_custody().unwrap();
    let scope = Scope {
        bus_instance: "isolated-node-db-1".into(),
        grant_id: "grant".into(),
    };
    let limits = Limits {
        max_item_bytes: 1024,
        ..Limits::default()
    };
    let mut service = node.config.register().await.unwrap();
    let mut processed = 0;
    for index in 0..150 {
        if service
            .send(
                service.address().unwrap(),
                &"x".repeat(2000),
                Some(&format!("oversized-{index}")),
            )
            .await
            .is_err()
        {
            break;
        }
        assert_eq!(
            xmsg_mcp_gateway::custody::receive_one(
                &mut store,
                &mut service,
                &scope,
                &limits,
                100 + index
            )
            .await
            .unwrap(),
            Some(Acceptance::Refused)
        );
        processed += 1;
    }
    let node_db = node
        .config
        .register_socket
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .join("node.db");
    let upstream = rusqlite::Connection::open(&node_db).unwrap();
    let queued: i64 = upstream
        .query_row(
            "SELECT COUNT(*) FROM svc_pending_messages WHERE delivered_at IS NULL",
            [],
            |row| row.get(0),
        )
        .unwrap();
    let valid = service
        .send(
            service.address().unwrap(),
            "valid traffic",
            Some("valid-after-oversized"),
        )
        .await;
    assert!(
        valid.is_ok(),
        "oversized refusals exhausted node queue: processed={processed}, queued={queued}"
    );
    assert_eq!(processed, 150);
    assert_eq!(
        queued, 0,
        "permanent refusals retained upstream queue slots"
    );
    assert!(matches!(
        xmsg_mcp_gateway::custody::receive_one(&mut store, &mut service, &scope, &limits, 251)
            .await
            .unwrap(),
        Some(Acceptance::Stored { .. })
    ));
    let persisted = rusqlite::Connection::open(&db).unwrap();
    let refusals: i64 = persisted
        .query_row(
            "SELECT COUNT(*) FROM custody_metadata WHERE reason='oversized'",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(refusals, 150, "permanent refusal audit missing");
    println!("gateway-custody-complete:permanent-refusal-pressure");
}

#[tokio::test]
#[ignore = "mandatory private-node custody profile"]
async fn retention_redacts_content_without_rebinding_the_tombstone() {
    let binary = real_node::pinned_binary();
    let node = real_node::Node::start(&binary).await;
    let temp = tempfile::tempdir().unwrap();
    let db = temp.path().join("authority.db");
    let mut store = authority(&db);
    store.migrate_custody().unwrap();
    let scope = Scope {
        bus_instance: "isolated-node-db-1".into(),
        grant_id: "grant".into(),
    };
    let limits = Limits {
        content_retention_secs: 2,
        metadata_retention_secs: 4,
        ..Limits::default()
    };
    let mut service = node.config.register().await.unwrap();
    service
        .send(
            service.address().unwrap(),
            "content that expires",
            Some("retention"),
        )
        .await
        .unwrap();
    let delivery = service.poll(1).await.unwrap().unwrap();
    let first = store
        .accept_delivery(&scope, &service, &delivery, &limits, 100)
        .unwrap();
    let Acceptance::Stored { event_id } = first else {
        panic!("not stored")
    };
    store.set_enabled("grant", 1, true).unwrap();
    store.set_enabled("grant", 2, false).unwrap();
    store.set_enabled("grant", 3, true).unwrap();
    assert_eq!(
        store
            .accept_delivery(&scope, &service, &delivery, &limits, 102)
            .unwrap(),
        Acceptance::Duplicate { event_id }
    );
    let inspect = rusqlite::Connection::open(&db).unwrap();
    let (text, envelope, revision, held): (Option<String>, Option<String>, i64, bool) = inspect
        .query_row(
            "SELECT text, envelope, grant_revision, held FROM custody_items",
            [],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
        )
        .unwrap();
    assert_eq!(text, None, "expired body retained");
    assert_eq!(envelope, None, "expired envelope retained");
    assert_eq!(
        (revision, held),
        (1, true),
        "expiry or re-enable rebound old work"
    );
    let expired: i64 = inspect
        .query_row(
            "SELECT value FROM custody_counters WHERE name='expired_content'",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(expired, 1);
    assert!(
        matches!(
            store
                .accept_delivery(&scope, &service, &delivery, &limits, 106)
                .unwrap(),
            Acceptance::Stored { .. }
        ),
        "expired tombstone was not reclaimed"
    );
    let count: i64 = inspect
        .query_row("SELECT COUNT(*) FROM custody_items", [], |row| row.get(0))
        .unwrap();
    assert_eq!(count, 1, "expired tombstones grew unbounded");
    let expired: i64 = inspect
        .query_row(
            "SELECT value FROM custody_counters WHERE name='expired_tombstones'",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(expired, 1);
    println!("gateway-custody-complete:retention");
}

#[tokio::test]
#[ignore = "mandatory private-node custody profile"]
async fn mailbox_is_derived_from_the_registered_handle_not_configuration() {
    let binary = real_node::pinned_binary();
    let node = real_node::Node::start(&binary).await;
    let temp = tempfile::tempdir().unwrap();
    let db = temp.path().join("authority.db");
    let mut store = Store::initialize(&db).unwrap();
    store
        .enroll(
            "grant",
            &Binding {
                service: "logical-resource-profile".into(),
                issuer: "https://issuer.example/".into(),
                resource: "https://gateway.example/mcp".into(),
                subject: "owner".into(),
                hosted_client: "hosted-client".into(),
            },
        )
        .unwrap();
    store.migrate_custody().unwrap();
    let mut configured = serde_json::json!({"bus_instance":"configured-mailbox@wrong.node", "grant_id":"grant", "mailbox":"victim@other.node"});
    assert!(
        serde_json::from_value::<Scope>(configured.clone()).is_err(),
        "configured mailbox redirect was accepted"
    );
    configured.as_object_mut().unwrap().remove("mailbox");
    let scope: Scope = serde_json::from_value(configured).unwrap();
    let mut service = node.config.register().await.unwrap();
    service
        .send(
            service.address().unwrap(),
            "handle-selected mailbox",
            Some("mailbox-binding"),
        )
        .await
        .unwrap();
    let delivery = service.poll(1).await.unwrap().unwrap();
    store
        .accept_delivery(&scope, &service, &delivery, &Limits::default(), 100)
        .unwrap();
    let inspected = rusqlite::Connection::open(&db).unwrap();
    let (mailbox, owner, snapshot): (String, String, i64) = inspected
        .query_row(
            "SELECT mailbox, owner, grant_revision FROM custody_items",
            [],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .unwrap();
    assert_eq!(
        mailbox,
        service.address().unwrap(),
        "mailbox came from configuration instead of the registered handle"
    );
    assert_eq!((owner, snapshot), ("owner".into(), 1));
    println!("gateway-custody-complete:mailbox-binding");
}

#[path = "common/custody_crash.rs"]
mod crash;

#[test]
#[ignore = "subprocess fixture; mandatory profile also checks its inert control"]
fn custody_crash_child() {
    let Ok(phase) = std::env::var("CUSTODY_CRASH_PHASE") else {
        println!("gateway-custody-complete:crash-helper-control");
        return;
    };
    let config: xmsg_mcp_gateway::xmsg_config::XmsgConfig = serde_json::from_slice(
        &std::fs::read(std::env::var_os("CUSTODY_CRASH_CONFIG").unwrap()).unwrap(),
    )
    .unwrap();
    tracing::subscriber::set_global_default(crash::Cut {
        target: match phase.as_str() {
            "before" => "gateway_custody_before_commit",
            "after" => "gateway_custody_after_commit",
            _ => panic!("unknown crash cut"),
        },
        marker: std::env::var_os("CUSTODY_CRASH_MARKER").unwrap().into(),
    })
    .unwrap();
    let db = std::path::PathBuf::from(std::env::var_os("CUSTODY_CRASH_DB").unwrap());
    let scope = Scope {
        bus_instance: "isolated-node-db-1".into(),
        grant_id: "grant".into(),
    };
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap()
        .block_on(async {
            let mut store = Store::open(&db).unwrap();
            let mut service = config.register().await.unwrap();
            xmsg_mcp_gateway::custody::receive_one(
                &mut store,
                &mut service,
                &scope,
                &Limits::default(),
                100,
            )
            .await
            .unwrap();
        });
    panic!("crash cut not reached");
}

async fn crash_at(phase: &str) {
    use std::process::{Command, Stdio};
    use std::time::{Duration, Instant};
    let binary = real_node::pinned_binary();
    let mut node = real_node::Node::start(&binary).await;
    let temp = tempfile::tempdir().unwrap();
    let db = temp.path().join("authority.db");
    let mut store = authority(&db);
    store.migrate_custody().unwrap();
    drop(store);
    let service = node.config.register().await.unwrap();
    let sent = service
        .send(
            service.address().unwrap(),
            "crash-preserved bytes",
            Some(phase),
        )
        .await
        .unwrap();
    drop(service);
    node.restart(&binary).await;
    let config = temp.path().join("node-client.json");
    std::fs::write(
        &config,
        serde_json::to_vec(&serde_json::json!({
            "service":node.config.service, "expected_node":node.config.expected_node,
            "daemon_uid":node.config.daemon_uid, "register_socket":node.config.register_socket,
            "agent_socket":node.config.agent_socket, "operation_timeout_ms":2000,
        }))
        .unwrap(),
    )
    .unwrap();
    let marker = temp.path().join("crash-cut");
    let log_file = temp.path().join("child.log");
    let mut child = crash::Worker(
        Command::new(std::env::current_exe().unwrap())
            .args(["custody_crash_child", "--exact", "--ignored", "--nocapture"])
            .env("CUSTODY_CRASH_PHASE", phase)
            .env("CUSTODY_CRASH_CONFIG", &config)
            .env("CUSTODY_CRASH_DB", &db)
            .env("CUSTODY_CRASH_MARKER", &marker)
            .stdout(Stdio::null())
            .stderr(std::fs::File::create(&log_file).unwrap())
            .spawn()
            .unwrap(),
    );
    let deadline = Instant::now() + Duration::from_secs(10);
    while !marker.exists() {
        assert!(
            child.0.try_wait().unwrap().is_none(),
            "crash worker exited before cut: {}",
            std::fs::read_to_string(&log_file).unwrap()
        );
        assert!(Instant::now() < deadline, "crash cut not observed");
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    let inspect = rusqlite::Connection::open(&db).unwrap();
    let old_id: Option<String> = {
        use rusqlite::OptionalExtension;
        inspect
            .query_row("SELECT event_id FROM custody_items", [], |row| row.get(0))
            .optional()
            .unwrap()
    };
    assert_eq!(
        old_id.is_some(),
        phase == "after",
        "commit boundary was not observed"
    );
    drop(inspect);
    child.0.kill().unwrap();
    assert!(!child.0.wait().unwrap().success(), "worker was not killed");
    node.restart(&binary).await;
    let mut store = Store::open(&db).unwrap();
    let mut service = node.config.register().await.unwrap();
    let delivery = service.poll(1).await.unwrap();
    assert!(
        delivery.is_some(),
        "process crash lost unacknowledged upstream delivery"
    );
    let delivery = delivery.unwrap();
    assert_eq!(delivery.message_id(), sent.message_id);
    let scope = Scope {
        bus_instance: "isolated-node-db-1".into(),
        grant_id: "grant".into(),
    };
    let accepted = store
        .accept_delivery(&scope, &service, &delivery, &Limits::default(), 101)
        .unwrap();
    match (phase, accepted) {
        ("before", Acceptance::Stored { .. }) => {}
        ("after", Acceptance::Duplicate { event_id }) => assert_eq!(
            Some(event_id),
            old_id,
            "crash redelivery minted a different event"
        ),
        _ => panic!("crash recovery did not preserve custody state"),
    }
    let inspect = rusqlite::Connection::open(&db).unwrap();
    let (body, items, occurrences): (String, i64, i64) = inspect.query_row("SELECT text, (SELECT COUNT(*) FROM custody_items), (SELECT COUNT(*) FROM custody_outbox) FROM custody_items", [], |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?))).unwrap();
    assert_eq!(body, "crash-preserved bytes");
    assert_eq!((items, occurrences), (1, 1));
    service.ack(delivery.message_id()).await.unwrap();
    store
        .record_custody_ack(&scope, delivery.message_id())
        .unwrap();
    drop(service);
    node.restart(&binary).await;
    let mut service = node.config.register().await.unwrap();
    assert!(
        service.poll(0).await.unwrap().is_none(),
        "ACK did not survive final restart"
    );
    println!("gateway-custody-complete:crash-{phase}");
}

#[tokio::test]
#[ignore = "mandatory private-node custody profile"]
async fn process_crash_before_commit_leaves_redelivery() {
    crash_at("before").await;
}

#[tokio::test]
#[ignore = "mandatory private-node custody profile"]
async fn process_crash_after_commit_preserves_one_event() {
    crash_at("after").await;
}

#[tokio::test]
#[ignore = "mandatory private-node custody profile"]
async fn repeated_conflicts_do_not_starve_valid_traffic() {
    let binary = real_node::pinned_binary();
    let node = real_node::Node::start(&binary).await;
    let temp = tempfile::tempdir().unwrap();
    let db = temp.path().join("authority.db");
    let mut store = authority(&db);
    store.migrate_custody().unwrap();
    let scope = Scope {
        bus_instance: "isolated-node-db-1".into(),
        grant_id: "grant".into(),
    };
    let mut service = node.config.register().await.unwrap();
    let node_db = node
        .config
        .register_socket
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .join("node.db");
    let upstream = rusqlite::Connection::open(&node_db).unwrap();
    let mut processed = 0;
    for index in 0..150 {
        let Ok(sent) = service
            .send(
                service.address().unwrap(),
                "original body",
                Some(&format!("conflict-{index}")),
            )
            .await
        else {
            break;
        };
        assert!(matches!(
            xmsg_mcp_gateway::custody::receive_one(
                &mut store,
                &mut service,
                &scope,
                &Limits::default(),
                100
            )
            .await
            .unwrap(),
            Some(Acceptance::Stored { .. })
        ));
        assert_eq!(upstream.execute("UPDATE svc_pending_messages SET text='conflicting body', delivered_at=NULL WHERE id=?1", [&sent.message_id]).unwrap(), 1);
        assert_eq!(
            xmsg_mcp_gateway::custody::receive_one(
                &mut store,
                &mut service,
                &scope,
                &Limits::default(),
                101
            )
            .await
            .unwrap(),
            Some(Acceptance::Quarantined)
        );
        processed += 1;
    }
    let queued: i64 = upstream
        .query_row(
            "SELECT COUNT(*) FROM svc_pending_messages WHERE delivered_at IS NULL",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert!(
        service
            .send(
                service.address().unwrap(),
                "valid after conflicts",
                Some("valid-after-conflicts")
            )
            .await
            .is_ok(),
        "conflicts exhausted node queue: processed={processed}, queued={queued}"
    );
    assert_eq!(processed, 150);
    assert_eq!(queued, 0, "conflicts retained upstream slots");
    assert!(matches!(
        xmsg_mcp_gateway::custody::receive_one(
            &mut store,
            &mut service,
            &scope,
            &Limits::default(),
            102
        )
        .await
        .unwrap(),
        Some(Acceptance::Stored { .. })
    ));
    let status = store
        .custody_status(&scope, &Limits::default(), 102, 604800)
        .unwrap();
    assert_eq!(status.quarantines, 150);
    assert_eq!(status.pending, 0, "confirmed ACKs retained pending IDs");
    println!("gateway-custody-complete:conflict-pressure");
}

#[tokio::test]
#[ignore = "mandatory private-node custody profile"]
async fn transient_capacity_and_failed_refusal_persistence_keep_redelivery() {
    let binary = real_node::pinned_binary();
    let mut node = real_node::Node::start(&binary).await;
    let temp = tempfile::tempdir().unwrap();
    let db = temp.path().join("authority.db");
    let mut store = authority(&db);
    store.migrate_custody().unwrap();
    let scope = Scope {
        bus_instance: "isolated-node-db-1".into(),
        grant_id: "grant".into(),
    };
    let limits = Limits {
        max_items: 1,
        max_metadata: 1,
        ..Limits::default()
    };
    let mut service = node.config.register().await.unwrap();
    service
        .send(service.address().unwrap(), "first", Some("first-capacity"))
        .await
        .unwrap();
    xmsg_mcp_gateway::custody::receive_one(&mut store, &mut service, &scope, &limits, 100)
        .await
        .unwrap();
    let second = service
        .send(
            service.address().unwrap(),
            "second",
            Some("second-capacity"),
        )
        .await
        .unwrap();
    assert_eq!(
        xmsg_mcp_gateway::custody::receive_one(&mut store, &mut service, &scope, &limits, 101)
            .await
            .unwrap(),
        Some(Acceptance::Deferred)
    );
    drop(service);
    node.restart(&binary).await;
    let mut service = node.config.register().await.unwrap();
    let replay = service.poll(1).await.unwrap();
    assert!(
        replay.is_some(),
        "transient capacity refusal ACKed upstream"
    );
    assert_eq!(replay.unwrap().message_id(), second.message_id);
    let third = service
        .send(service.address().unwrap(), "third", Some("third-capacity"))
        .await
        .unwrap();
    assert!(
        xmsg_mcp_gateway::custody::receive_one(&mut store, &mut service, &scope, &limits, 102)
            .await
            .is_err(),
        "metadata capacity was not bounded"
    );
    drop(service);
    node.restart(&binary).await;
    let mut service = node.config.register().await.unwrap();
    let mut redelivered = Vec::new();
    for _ in 0..2 {
        redelivered.push(
            service
                .poll(1)
                .await
                .unwrap()
                .unwrap()
                .message_id()
                .to_owned(),
        );
    }
    assert!(
        redelivered.contains(&second.message_id) && redelivered.contains(&third.message_id),
        "storage failure ACKed a pending delivery"
    );
    println!("gateway-custody-complete:transient-capacity");
}

#[tokio::test]
#[ignore = "mandatory private-node custody profile"]
async fn metadata_retention_and_status_survive_restart_without_fake_loss_ids() {
    let binary = real_node::pinned_binary();
    let node = real_node::Node::start(&binary).await;
    let temp = tempfile::tempdir().unwrap();
    let db = temp.path().join("authority.db");
    let mut store = authority(&db);
    store.migrate_custody().unwrap();
    let scope = Scope {
        bus_instance: "isolated-node-db-1".into(),
        grant_id: "grant".into(),
    };
    let limits = Limits {
        max_item_bytes: 1,
        max_metadata: 1,
        metadata_retention_secs: 10,
        ..Limits::default()
    };
    let mut service = node.config.register().await.unwrap();
    service
        .send(
            service.address().unwrap(),
            "refused body",
            Some("retained-refusal"),
        )
        .await
        .unwrap();
    xmsg_mcp_gateway::custody::receive_one(&mut store, &mut service, &scope, &limits, 100)
        .await
        .unwrap();
    store
        .record_custody_link(&scope, false, &limits, 101)
        .unwrap();
    drop(store);
    let mut store = Store::open(&db).unwrap();
    let before = store.custody_status(&scope, &limits, 109, 3).unwrap();
    assert_eq!(before.refusals, 1, "refusal expired before retention bound");
    assert_eq!(before.pending, 0);
    assert!(
        before.offline_uncertainty,
        "disconnect uncertainty was not durable"
    );
    assert!(
        !before.possible_known_loss,
        "downtime invented known message loss"
    );
    let expired = store.custody_status(&scope, &limits, 110, 3).unwrap();
    assert_eq!(expired.refusals, 0, "refusal retention did not expire");
    assert_eq!(
        expired.expired_metadata, 1,
        "metadata expiry counter missing"
    );
    store
        .record_custody_link(&scope, true, &limits, 110)
        .unwrap();
    service
        .send(
            service.address().unwrap(),
            "unacknowledged",
            Some("aged-pending"),
        )
        .await
        .unwrap();
    let delivery = service.poll(1).await.unwrap().unwrap();
    store
        .accept_delivery(
            &scope,
            &service,
            &delivery,
            &Limits {
                metadata_retention_secs: 10,
                ..Limits::default()
            },
            111,
        )
        .unwrap();
    store
        .record_custody_link(&scope, false, &limits, 115)
        .unwrap();
    store
        .record_custody_link(&scope, true, &limits, 116)
        .unwrap();
    let aged = store.custody_status(&scope, &limits, 116, 3).unwrap();
    assert_eq!(aged.oldest_pending_age_secs, Some(5));
    assert!(
        aged.possible_known_loss,
        "known message age did not drive possible loss"
    );
    assert_eq!(aged.pending, 1);
    let forgotten = store.custody_status(&scope, &limits, 121, 3).unwrap();
    assert_eq!(
        forgotten.pending, 0,
        "known pending IDs were not retention-bounded"
    );
    assert_eq!(forgotten.expired_pending, 1);
    assert!(
        forgotten.possible_known_loss,
        "expired pending uncertainty disappeared"
    );
    let inspect = rusqlite::Connection::open(&db).unwrap();
    let items: i64 = inspect
        .query_row("SELECT COUNT(*) FROM custody_items", [], |row| row.get(0))
        .unwrap();
    assert_eq!(items, 1, "outage invented unknown message IDs");
    println!("gateway-custody-complete:metadata-status");
}

#[tokio::test]
#[ignore = "mandatory private-node custody profile"]
async fn refusal_metadata_is_bounded_and_failed_audit_never_acks() {
    let binary = real_node::pinned_binary();
    let mut node = real_node::Node::start(&binary).await;
    let temp = tempfile::tempdir().unwrap();
    let db = temp.path().join("authority.db");
    let mut store = authority(&db);
    store.migrate_custody().unwrap();
    let scope = Scope {
        bus_instance: "isolated-node-db-1".into(),
        grant_id: "grant".into(),
    };
    let limits = Limits {
        max_metadata: 1,
        max_item_bytes: 1,
        ..Limits::default()
    };
    let mut service = node.config.register().await.unwrap();
    service
        .send(
            service.address().unwrap(),
            "first refusal",
            Some("metadata-first"),
        )
        .await
        .unwrap();
    xmsg_mcp_gateway::custody::receive_one(&mut store, &mut service, &scope, &limits, 100)
        .await
        .unwrap();
    let second = service
        .send(
            service.address().unwrap(),
            "second refusal",
            Some("metadata-second"),
        )
        .await
        .unwrap();
    assert!(
        xmsg_mcp_gateway::custody::receive_one(&mut store, &mut service, &scope, &limits, 101)
            .await
            .is_err(),
        "refusal metadata count bound missing"
    );
    drop(service);
    node.restart(&binary).await;
    let mut service = node.config.register().await.unwrap();
    let delivery = service.poll(1).await.unwrap();
    assert!(
        delivery.is_some(),
        "failed refusal persistence ACKed upstream"
    );
    assert_eq!(delivery.unwrap().message_id(), second.message_id);
    let status = store.custody_status(&scope, &limits, 102, 604800).unwrap();
    assert_eq!(status.refusals, 1);
    assert_eq!(status.pending, 0);
    println!("gateway-custody-complete:metadata-bound");
}

#[tokio::test]
#[ignore = "mandatory private-node custody profile"]
async fn refusal_and_offline_uncertainty_outlive_real_upstream_expiry() {
    let binary = real_node::pinned_binary();
    let mut node = real_node::Node::start_with_reply_ttl(&binary, 1).await;
    let temp = tempfile::tempdir().unwrap();
    let db = temp.path().join("authority.db");
    let mut store = authority(&db);
    store.migrate_custody().unwrap();
    let scope = Scope {
        bus_instance: "isolated-node-db-1".into(),
        grant_id: "grant".into(),
    };
    let limits = Limits {
        max_item_bytes: 1,
        ..Limits::default()
    };
    let mut service = node.config.register().await.unwrap();
    let sent = service
        .send(
            service.address().unwrap(),
            "expires upstream",
            Some("upstream-expiry"),
        )
        .await
        .unwrap();
    xmsg_mcp_gateway::custody::receive_one(&mut store, &mut service, &scope, &limits, 100)
        .await
        .unwrap();
    store
        .record_custody_link(&scope, false, &limits, 101)
        .unwrap();
    drop(service);
    drop(store);
    tokio::time::sleep(std::time::Duration::from_millis(2100)).await;
    node.restart(&binary).await;
    let mut service = node.config.register().await.unwrap();
    assert!(service.poll(0).await.unwrap().is_none());
    let node_db = node
        .config
        .register_socket
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .join("node.db");
    let upstream = rusqlite::Connection::open(&node_db).unwrap();
    let expired: i64 = upstream
        .query_row(
            "SELECT COUNT(*) FROM svc_pending_messages WHERE id=?1",
            [&sent.message_id],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(
        expired, 0,
        "shortened real upstream TTL did not expire the row"
    );
    let mut store = Store::open(&db).unwrap();
    store
        .record_custody_link(&scope, true, &limits, 104)
        .unwrap();
    let status = store.custody_status(&scope, &limits, 104, 1).unwrap();
    assert_eq!(
        status.refusals, 1,
        "durable refusal vanished with upstream expiry"
    );
    assert!(status.offline_uncertainty, "durable offline gap missing");
    assert!(
        !status.possible_known_loss,
        "outage fabricated a known expired message"
    );
    assert_eq!(status.held_items, 0);
    println!("gateway-custody-complete:real-upstream-expiry");
}

#[tokio::test]
#[ignore = "mandatory private-node custody profile"]
async fn a_delivery_larger_than_total_capacity_is_a_permanent_refusal() {
    let binary = real_node::pinned_binary();
    let node = real_node::Node::start(&binary).await;
    let temp = tempfile::tempdir().unwrap();
    let mut store = authority(&temp.path().join("authority.db"));
    store.migrate_custody().unwrap();
    let scope = Scope {
        bus_instance: "isolated-node-db-1".into(),
        grant_id: "grant".into(),
    };
    let limits = Limits {
        max_bytes: 1,
        ..Limits::default()
    };
    let mut service = node.config.register().await.unwrap();
    service
        .send(service.address().unwrap(), "cannot ever fit", Some("unfit"))
        .await
        .unwrap();
    assert_eq!(
        xmsg_mcp_gateway::custody::receive_one(&mut store, &mut service, &scope, &limits, 100)
            .await
            .unwrap(),
        Some(Acceptance::Refused),
        "unfit delivery was treated as transient"
    );
    assert!(service.poll(0).await.unwrap().is_none());
    println!("gateway-custody-complete:total-capacity-permanent");
}

#[tokio::test]
#[ignore = "mandatory private-node custody profile"]
async fn aggregate_byte_capacity_is_transient_and_preserves_redelivery() {
    let binary = real_node::pinned_binary();
    let mut node = real_node::Node::start(&binary).await;
    let temp = tempfile::tempdir().unwrap();
    let mut store = authority(&temp.path().join("authority.db"));
    store.migrate_custody().unwrap();
    let scope = Scope {
        bus_instance: "isolated-node-db-1".into(),
        grant_id: "grant".into(),
    };
    let limits = Limits {
        max_bytes: 4096,
        ..Limits::default()
    };
    let mut service = node.config.register().await.unwrap();
    service
        .send(
            service.address().unwrap(),
            &"x".repeat(1500),
            Some("bytes-first"),
        )
        .await
        .unwrap();
    assert!(matches!(
        xmsg_mcp_gateway::custody::receive_one(&mut store, &mut service, &scope, &limits, 100)
            .await
            .unwrap(),
        Some(Acceptance::Stored { .. })
    ));
    let second = service
        .send(
            service.address().unwrap(),
            &"x".repeat(1500),
            Some("bytes-second"),
        )
        .await
        .unwrap();
    assert_eq!(
        xmsg_mcp_gateway::custody::receive_one(&mut store, &mut service, &scope, &limits, 101)
            .await
            .unwrap(),
        Some(Acceptance::Deferred),
        "aggregate byte capacity was not enforced"
    );
    drop(service);
    node.restart(&binary).await;
    let mut service = node.config.register().await.unwrap();
    let delivery = service.poll(1).await.unwrap();
    assert!(delivery.is_some(), "byte-capacity deferral ACKed upstream");
    assert_eq!(delivery.unwrap().message_id(), second.message_id);
    println!("gateway-custody-complete:byte-capacity");
}

#[tokio::test]
#[ignore = "mandatory private-node custody profile"]
async fn idle_poll_enforces_retention_and_observes_connection_changes() {
    let binary = real_node::pinned_binary();
    let mut node = real_node::Node::start(&binary).await;
    let temp = tempfile::tempdir().unwrap();
    let db = temp.path().join("authority.db");
    let mut store = authority(&db);
    store.migrate_custody().unwrap();
    let scope = Scope {
        bus_instance: "isolated-node-db-1".into(),
        grant_id: "grant".into(),
    };
    let limits = Limits {
        max_item_bytes: 1,
        metadata_retention_secs: 2,
        ..Limits::default()
    };
    let mut service = node.config.register().await.unwrap();
    service
        .send(
            service.address().unwrap(),
            "idle expiry",
            Some("idle-expiry"),
        )
        .await
        .unwrap();
    xmsg_mcp_gateway::custody::receive_one(&mut store, &mut service, &scope, &limits, 100)
        .await
        .unwrap();
    assert_eq!(
        xmsg_mcp_gateway::custody::receive_one(&mut store, &mut service, &scope, &limits, 102)
            .await
            .unwrap(),
        None
    );
    let inspect = rusqlite::Connection::open(&db).unwrap();
    let retained: i64 = inspect
        .query_row("SELECT COUNT(*) FROM custody_metadata", [], |row| {
            row.get(0)
        })
        .unwrap();
    assert_eq!(retained, 0, "idle receive ignored retention");
    node.restart(&binary).await;
    assert!(
        xmsg_mcp_gateway::custody::receive_one(&mut store, &mut service, &scope, &limits, 104)
            .await
            .is_err()
    );
    let disconnected: Option<i64> = inspect
        .query_row("SELECT disconnected_at FROM custody_links", [], |row| {
            row.get(0)
        })
        .unwrap();
    assert_eq!(disconnected, Some(104), "disconnect was not recorded");
    drop(service);
    let mut service = node.config.register().await.unwrap();
    assert_eq!(
        xmsg_mcp_gateway::custody::receive_one(&mut store, &mut service, &scope, &limits, 105)
            .await
            .unwrap(),
        None
    );
    let (connected, reconnected): (bool, Option<i64>) = inspect
        .query_row(
            "SELECT connected, reconnected_at FROM custody_links",
            [],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .unwrap();
    assert!(connected, "reconnected handle was not recorded");
    assert_eq!(reconnected, Some(105));
    println!("gateway-custody-complete:idle-maintenance");
}
