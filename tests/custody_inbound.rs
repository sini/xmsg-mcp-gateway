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
    store.migrate_custody().unwrap();
    let injected = rusqlite::Connection::open(&db).unwrap();
    injected.execute_batch("CREATE TRIGGER reject_outbox BEFORE INSERT ON custody_outbox BEGIN SELECT RAISE(ABORT, 'fixture disk failure'); END;").unwrap();
    drop(injected);
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
    assert!(xmsg_mcp_gateway::custody::receive_one(
        &mut store,
        &mut service,
        &scope,
        &Limits::default(),
        100
    )
    .await
    .is_err());
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
    assert!(matches!(
        store
            .accept_delivery(&scope, &service, &delivery, &limits, 106)
            .unwrap(),
        Acceptance::Stored { .. }
    ));
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
