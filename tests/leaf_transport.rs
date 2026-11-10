#![cfg(target_os = "linux")]

#[allow(dead_code)]
#[path = "common/real_node.rs"]
mod real_node;

use xmsg::client::ClientError;

#[test]
fn mandatory_profile_includes_leaf_transport() {
    if std::env::var_os("XMSG_GATEWAY_REQUIRED").is_some() {
        assert!(
            std::env::args().any(|arg| arg == "--ignored" || arg == "--include-ignored"),
            "mandatory leaf transport case requires --include-ignored"
        );
    }
}

#[tokio::test]
#[ignore = "requires a revision-verified real leaf daemon; mandatory transport CI runs this"]
async fn leaf_agent_socket_send_reply_preserve_service_identity() {
    let leaf_binary = real_node::pinned_binary();
    let hub_binary = std::path::PathBuf::from(
        std::env::var_os("XMSG_GATEWAY_HUB_BIN").expect("required normal hub fixture missing"),
    );
    let authority = real_node::Authority::generate();
    let prepared_leaf = real_node::Prepared::create("gateway", "leaf", Some(&authority));
    let prepared_hub = real_node::Prepared::create("receiver", "hub", Some(&authority));
    prepared_leaf.peer(&prepared_hub, serde_json::json!({}));
    prepared_hub.peer(
        &prepared_leaf,
        serde_json::json!({"leaf":true,"targets":["gateway","receiver"]}),
    );
    let hub = prepared_hub.launch(&hub_binary).await;
    let node = prepared_leaf.launch_leaf(&leaf_binary).await;
    let mut receiver = hub.config.register().await.unwrap();
    let mut wrong = node.config.clone();
    wrong.service = "not-the-leaf-principal".into();
    assert!(matches!(
        wrong.register().await,
        Err(ClientError::Refused { code }) if code == "denied"
    ));
    let mut service = node.config.register().await.unwrap();
    assert_eq!(service.address(), Some("gateway@leaf.fixture"));
    let client = service.agent_client();
    let sent = client
        .send("receiver@hub.fixture", "leaf request", Some("leaf-send"))
        .await
        .unwrap();
    let repeated = client
        .send("receiver@hub.fixture", "leaf request", Some("leaf-send"))
        .await
        .unwrap();
    assert_eq!(repeated.message_id, sent.message_id);
    let delivery = receiver.poll(1).await.unwrap().unwrap();
    assert_eq!(delivery.message_id(), sent.message_id);
    assert_eq!(delivery.text(), "leaf request");
    assert_eq!(delivery.origin().service.as_deref(), Some("gateway"));
    assert_eq!(delivery.origin().node, "leaf.fixture");
    receiver.ack(delivery.message_id()).await.unwrap();
    let question = receiver
        .send("gateway@leaf.fixture", "hub question", Some("hub-question"))
        .await
        .unwrap();
    let incoming = service.poll(5).await.unwrap().unwrap();
    assert_eq!(incoming.message_id(), question.message_id);
    assert_eq!(incoming.origin().service.as_deref(), Some("receiver"));
    assert_eq!(incoming.origin().node, "hub.fixture");
    service.ack(incoming.message_id()).await.unwrap();

    let replied = client
        .reply(&question.message_id, "leaf answer", Some("leaf-reply"))
        .await
        .unwrap();
    let repeated_reply = client
        .reply(&question.message_id, "leaf answer", Some("leaf-reply"))
        .await
        .unwrap();
    assert_eq!(repeated_reply.seq, replied.seq);
    assert_eq!(repeated_reply.pushed_message_id, replied.pushed_message_id);
    assert_eq!(replied.replier_session_id, "gateway");
    let answer = receiver.poll(5).await.unwrap().unwrap();
    assert_eq!(
        answer.message_id(),
        replied.pushed_message_id.as_ref().unwrap()
    );
    assert_eq!(answer.text(), "leaf answer");
    assert_eq!(answer.in_reply_to(), Some(question.message_id.as_str()));
    assert_eq!(answer.origin().service.as_deref(), Some("gateway"));
    assert_eq!(answer.origin().node, "leaf.fixture");
    receiver.ack(answer.message_id()).await.unwrap();
    assert!(service.poll(0).await.unwrap().is_none());

    let parked_socket = node.config.agent_socket.with_extension("parked");
    std::fs::rename(&node.config.agent_socket, &parked_socket).unwrap();
    assert!(client
        .send(
            "gateway@leaf.fixture",
            "must use agent.sock",
            Some("no-socket")
        )
        .await
        .is_err());
    assert!(client
        .reply(
            &sent.message_id,
            "must use agent.sock",
            Some("no-socket-reply")
        )
        .await
        .is_err());
    std::fs::rename(parked_socket, &node.config.agent_socket).unwrap();
    println!("gateway-leaf-transport-complete:send-reply-service-identity");
}

#[tokio::test]
#[ignore = "requires revision-verified fixture; the leaf runner also measures missing-proc control"]
async fn nonleaf_registration_measures_process_metadata_availability() {
    let node = real_node::Node::start(&real_node::pinned_binary()).await;
    let registered = node.config.register().await;
    if let Some(root) = std::env::var_os("XMSG_GATEWAY_UNAVAILABLE_PROC_ROOT") {
        assert!(!std::path::Path::new(&root).exists());
        assert!(
            registered.is_err(),
            "non-leaf executable attestation must fail without process metadata"
        );
        println!("gateway-leaf-proc-control:nonleaf-refused");
    } else {
        assert!(
            registered.is_ok(),
            "normal non-leaf process attestation control must pass"
        );
        println!("gateway-leaf-proc-control:nonleaf-accepted");
    }
}
