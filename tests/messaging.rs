#![cfg(target_os = "linux")]

#[allow(dead_code)]
#[path = "common/provider.rs"]
mod provider;
#[allow(dead_code)]
#[path = "common/real_node.rs"]
mod real_node;
#[allow(dead_code)]
#[path = "common/serving_fixture.rs"]
mod serving_fixture;

use axum::http::StatusCode;
use serde_json::json;
use std::sync::atomic::Ordering;
use xmsg_mcp_gateway::outbound::Receipt;

fn owner(fixture: &serving_fixture::Fixture, arguments: &[&str]) {
    let output = std::process::Command::new(env!("CARGO_BIN_EXE_xmsg-mcp-gateway"))
        .arg("--state")
        .arg(&fixture.store_file)
        .args(arguments)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "owner command: {:?}",
        output.stderr
    );
}

fn policy(fixture: &serving_fixture::Fixture, revision: &str, document: serde_json::Value) {
    let file = fixture.keys._directory.path().join("policy.json");
    serving_fixture::private_file(&file, &serde_json::to_vec(&document).unwrap());
    owner(
        fixture,
        &[
            "set-outbound-policy",
            "grant",
            revision,
            file.to_str().unwrap(),
        ],
    );
}

fn configure(fixture: &mut serving_fixture::Fixture, node: &real_node::Node) {
    let connection = &node.config;
    fixture.config["request_timeout_ms"] = json!(60000);
    fixture.config["messaging"] = json!({
        "xmsg": {"service":connection.service,"expected_node":connection.expected_node,
            "daemon_uid":connection.daemon_uid,"register_socket":connection.register_socket,
            "agent_socket":connection.agent_socket,"max_frame_bytes":connection.max_frame_bytes,
            "operation_timeout_ms":connection.operation_timeout_ms},
        "manifest":{"reply_ttl_secs":604800,"idempotency_ttl_secs":86400,
            "svc_queue_cap":100,"dedup_lifetime_secs":3600,"max_framed_bytes":65536},
        "submission_timeout_ms":10000,"max_reservations":1000,"max_retained_bytes":67108864
    });
    serving_fixture::private_file(
        &fixture.config_file,
        &serde_json::to_vec(&fixture.config).unwrap(),
    );
}

#[tokio::test]
#[ignore = "requires the revision-verified private daemon in the wiring profile"]
async fn real_mcp_send_keeps_request_identity_and_owner_policy() {
    let node = real_node::Node::start(&real_node::pinned_binary()).await;
    let mut fixture = serving_fixture::Fixture::new();
    owner(&fixture, &["migrate-custody"]);
    owner(&fixture, &["migrate-outbound"]);
    policy(
        &fixture,
        "2",
        json!({"send":{"targets":["gateway@gateway.fixture"],
        "required_scope":"identity:read"},"reply":null}),
    );
    configure(&mut fixture, &node);
    let serving = fixture.serving().await;
    let discovery = json!({"jsonrpc":"2.0","id":100,"method":"tools/list","params":{}});
    let (status, listed, _) =
        serving_fixture::request(&serving, "good-token", discovery.clone()).await;
    assert_eq!(status, StatusCode::OK);
    let tools = listed["result"]["tools"].as_array().unwrap();
    let send_schema = tools
        .iter()
        .find(|tool| tool["name"] == "xmsg_send")
        .unwrap();
    assert!(send_schema["inputSchema"]["properties"]["to"].is_object());
    assert!(!tools.iter().any(|tool| tool["name"] == "xmsg_reply"));
    let send = json!({"jsonrpc":"2.0","id":101,"method":"tools/call",
        "params":{"name":"xmsg_send","arguments":{"request_id":"send-operation",
            "to":"gateway@gateway.fixture","text":"untrusted private fixture message"}}});
    let (status, first, probe) =
        serving_fixture::request(&serving, "good-token", send.clone()).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(first["result"]["structuredContent"]["state"], "confirmed");
    assert_eq!(probe.opens.load(Ordering::SeqCst), 2);
    assert_eq!(probe.dispatches.load(Ordering::SeqCst), 1);
    let mut replay = send.clone();
    replay["id"] = json!(102);
    let (status, repeated, probe) = serving_fixture::request(&serving, "good-token", replay).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        first["result"], repeated["result"],
        "RPC id changed logical send"
    );
    assert_eq!(probe.opens.load(Ordering::SeqCst), 2);
    for rpc_id in [103, 104] {
        let mut missing = send.clone();
        missing["id"] = json!(rpc_id);
        missing["params"]["arguments"]
            .as_object_mut()
            .unwrap()
            .remove("request_id");
        missing["params"]["_meta"] = json!({"request_id":"metadata-is-not-an-argument"});
        let (_, response, probe) = serving_fixture::request(&serving, "good-token", missing).await;
        assert_eq!(
            response["error"]["code"], -32602,
            "missing request_id was derived from a stringified RPC id"
        );
        assert_eq!(probe.dispatches.load(Ordering::SeqCst), 0);
        assert_eq!(probe.opens.load(Ordering::SeqCst), 1);
    }
    policy(&fixture, "3", json!({"send":null,"reply":null}));
    let (_, listed, _) = serving_fixture::request(&serving, "good-token", discovery).await;
    assert_eq!(listed["result"]["tools"].as_array().unwrap().len(), 1);
    let mut denied = send;
    denied["params"]["arguments"]["request_id"] = json!("new-denied-operation");
    let (status, _, probe) = serving_fixture::request(&serving, "good-token", denied).await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert_eq!(probe.dispatches.load(Ordering::SeqCst), 0);
    assert_eq!(probe.opens.load(Ordering::SeqCst), 1);
    let receipt: Receipt =
        serde_json::from_value(first["result"]["structuredContent"]["receipt"].clone()).unwrap();
    drop(serving);
    let mut mailbox = node.config.register().await.unwrap();
    let delivery = mailbox.poll(1).await.unwrap().unwrap();
    let Receipt::Send(receipt) = receipt else {
        panic!("wrong receipt vocabulary")
    };
    assert_eq!(delivery.message_id(), receipt.message_id);
    mailbox.ack(delivery.message_id()).await.unwrap();
    assert!(
        mailbox.poll(0).await.unwrap().is_none(),
        "duplicate logical delivery"
    );
    println!("gateway-wiring-complete:mcp-request-id-policy");
}
