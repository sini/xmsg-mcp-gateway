#![cfg(target_os = "linux")]

#[path = "common/real_node.rs"]
mod real_node;

use xmsg::client::{ClientError, ListQuery};

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
