#![cfg(target_os = "linux")]

#[path = "common/real_node.rs"]
mod real_node;

use xmsg::client::{ClientError, ListQuery};

#[tokio::test]
#[ignore = "requires the pinned socket-activation daemon"]
async fn socket_activation_survives_an_occupied_port_and_restart() {
    let occupied = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let authority = real_node::Authority::generate();
    let prepared = real_node::Prepared::create("gateway", "gateway", Some(&authority));
    let peer = real_node::Prepared::create("peer", "peer", Some(&authority));
    assert_ne!(prepared.port, occupied.local_addr().unwrap().port());
    prepared.peer(&peer, serde_json::json!({}));
    let binary = real_node::pinned_binary();
    let mut node = prepared.launch(&binary).await;
    for restart in [false, true] {
        if restart {
            node.restart(&binary).await;
        }
        let mut service = node.config.register().await.unwrap();
        let sent = service
            .send(service.address().unwrap(), "activation", None)
            .await
            .unwrap();
        let delivered = service.poll(0).await.unwrap().unwrap();
        assert_eq!(delivered.message_id(), sent.message_id);
        service.ack(delivered.message_id()).await.unwrap();
    }
    drop(occupied);
    println!("gateway-real-node-complete:socket-activation");
}

#[test]
fn mandatory_profile_includes_real_node_cases() {
    if std::env::var_os("XMSG_GATEWAY_REQUIRED").is_some() {
        assert!(
            std::env::args().any(|arg| arg == "--ignored" || arg == "--include-ignored"),
            "mandatory real-node cases require --include-ignored"
        );
    }
}

#[tokio::test]
#[ignore = "requires a revision-verified real daemon; the mandatory CI profile runs this"]
async fn pinned_node_roundtrip_uses_the_registered_service_identity() {
    let node = real_node::Node::start(&real_node::pinned_binary()).await;
    let mut service = node.config.register().await.unwrap();
    let address = service.address().unwrap().to_owned();
    assert_eq!(address, "gateway@gateway.fixture");
    let recipients = service.list(ListQuery::default()).await.unwrap();
    assert!(recipients
        .recipients
        .iter()
        .any(|recipient| recipient.address == address && recipient.kind == "service"));
    let first = service
        .send(&address, "untrusted fixture data", Some("roundtrip-key"))
        .await
        .unwrap();
    let repeated = service
        .send(&address, "untrusted fixture data", Some("roundtrip-key"))
        .await
        .unwrap();
    assert_eq!(first.message_id, repeated.message_id);
    let delivery = service.poll(1).await.unwrap().unwrap();
    assert_eq!(delivery.message_id(), first.message_id);
    assert_eq!(delivery.text(), "untrusted fixture data");
    assert_eq!(delivery.origin().service.as_deref(), Some("gateway"));
    assert_eq!(delivery.origin().node, "gateway.fixture");
    service.ack(delivery.message_id()).await.unwrap();
    assert!(service.poll(0).await.unwrap().is_none());
    let reply = service
        .reply(&first.message_id, "fixture reply", Some("reply-key"))
        .await
        .unwrap();
    let delivered_reply = service.poll(1).await.unwrap().unwrap();
    assert_eq!(
        reply.pushed_message_id.as_deref(),
        Some(delivered_reply.message_id())
    );
    assert_eq!(
        delivered_reply.in_reply_to(),
        Some(first.message_id.as_str())
    );
    service.ack(delivered_reply.message_id()).await.unwrap();
    println!("gateway-real-node-complete:roundtrip");
}

#[tokio::test]
#[ignore = "requires a revision-verified real daemon; the mandatory CI profile runs this"]
async fn pinned_node_refuses_a_different_configured_identity() {
    let node = real_node::Node::start(&real_node::pinned_binary()).await;
    let mut config = node.config.clone();
    config.expected_node = "other.fixture".into();
    assert!(matches!(config.register().await, Err(ClientError::Peer)));
    println!("gateway-real-node-complete:wrong-node");
}

async fn federation_cell(field: &str, denied: serde_json::Value) {
    let binary = real_node::pinned_binary();
    for negative in [false, true] {
        let ca = real_node::Authority::generate();
        let sender = real_node::Prepared::create("gateway", "gateway", Some(&ca));
        let receiver = real_node::Prepared::create("receiver", "receiver", Some(&ca));
        sender.peer(&receiver, serde_json::json!({}));
        let grants = if negative {
            serde_json::json!({field:denied})
        } else {
            serde_json::json!({})
        };
        receiver.peer(&sender, grants);
        let sender = sender.launch(&binary).await;
        let receiver = receiver.launch(&binary).await;
        let from = sender.config.register().await.unwrap();
        let mut to = receiver.config.register().await.unwrap();
        let destination = to.address().unwrap().to_owned();
        let sent = from
            .send(
                &destination,
                "federation fixture body",
                Some("federation-key"),
            )
            .await;
        if negative {
            assert!(sent.is_err(), "federation {field} refusal was bypassed");
            assert!(
                to.poll(0).await.unwrap().is_none(),
                "federation {field} refusal delivered a message"
            );
        } else {
            let receipt = sent.unwrap();
            let delivery = to.poll(1).await.unwrap().unwrap();
            assert_eq!(delivery.message_id(), receipt.message_id);
            assert_eq!(delivery.origin().node, "gateway.fixture");
            assert_eq!(delivery.origin().service.as_deref(), Some("gateway"));
            assert_eq!(delivery.text(), "federation fixture body");
            to.ack(delivery.message_id()).await.unwrap();
        }
    }
    println!("gateway-real-node-complete:federation-{field}");
}

#[tokio::test]
#[ignore = "mandatory pinned private-node compatibility profile"]
async fn federation_requires_peer_send_permission() {
    federation_cell("allow", serde_json::json!(["list"])).await;
}
#[tokio::test]
#[ignore = "mandatory pinned private-node compatibility profile"]
async fn federation_requires_the_approved_service_principal() {
    federation_cell("principals", serde_json::json!(["different-service"])).await;
}
#[tokio::test]
#[ignore = "mandatory pinned private-node compatibility profile"]
async fn federation_requires_the_approved_target() {
    federation_cell("targets", serde_json::json!(["different-target"])).await;
}
#[tokio::test]
#[ignore = "mandatory pinned private-node compatibility profile"]
async fn federation_requires_the_observed_source_address() {
    federation_cell("from", serde_json::json!(["127.0.0.2/32"])).await;
}

#[tokio::test]
#[ignore = "mandatory pinned private-node compatibility profile"]
async fn unacked_delivery_retains_identity_across_daemon_restart() {
    let binary = real_node::pinned_binary();
    let mut node = real_node::Node::start(&binary).await;
    let mut service = node.config.register().await.unwrap();
    let sent = service
        .send(
            service.address().unwrap(),
            "unacked fixture body",
            Some("restart-key"),
        )
        .await
        .unwrap();
    let delivery = service.poll(1).await.unwrap().unwrap();
    assert_eq!(delivery.message_id(), sent.message_id);
    drop(service);
    node.restart(&binary).await;
    let mut service = node.config.register().await.unwrap();
    let delivery = service.poll(1).await.unwrap().unwrap();
    assert_eq!(delivery.message_id(), sent.message_id);
    assert_eq!(delivery.text(), "unacked fixture body");
    service.ack(delivery.message_id()).await.unwrap();
    assert!(service.poll(0).await.unwrap().is_none());
    println!("gateway-real-node-complete:restart-redelivery");
}
