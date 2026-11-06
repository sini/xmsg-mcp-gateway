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
        .accept_delivery(
            &scope,
            service.address().unwrap(),
            &delivery,
            &Limits::default(),
            100,
        )
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
        .accept_delivery(
            &scope,
            service.address().unwrap(),
            &again,
            &Limits::default(),
            101,
        )
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
async fn oversized_refusal_is_durable_content_free_and_never_acked() {
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
    assert_eq!(
        service.poll(1).await.unwrap().unwrap().message_id(),
        sent.message_id,
        "refused delivery was ACKed"
    );
    let persisted = rusqlite::Connection::open(&db).unwrap();
    let (origin, reason): (String, String) = persisted
        .query_row("SELECT origin, reason FROM custody_metadata", [], |row| {
            Ok((row.get(0)?, row.get(1)?))
        })
        .unwrap();
    assert_eq!(reason, "capacity", "durable refusal missing");
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
        .accept_delivery(
            &scope,
            service.address().unwrap(),
            &delivery,
            &Limits::default(),
            100,
        )
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
    assert_eq!(
        service.poll(1).await.unwrap().unwrap().message_id(),
        sent.message_id,
        "failed custody transaction ACKed upstream"
    );
    let inspected = rusqlite::Connection::open(&db).unwrap();
    let rows: i64 = inspected
        .query_row("SELECT COUNT(*) FROM custody_items", [], |row| row.get(0))
        .unwrap();
    assert_eq!(rows, 0, "partial custody survived failed transaction");
    println!("gateway-custody-complete:failed-transaction");
}
