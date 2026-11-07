#![cfg(target_os = "linux")]

#[path = "common/agent_stall.rs"]
mod agent_stall;
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
use tracing::instrument::WithSubscriber;
use xmsg_mcp_gateway::outbound::Receipt;
use xmsg_mcp_gateway::serving::{Serving, StartupError};
use xmsg_mcp_gateway::xmsg_config::ManifestError;

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

fn migrated_fixture(node: &real_node::Node) -> serving_fixture::Fixture {
    let mut fixture = serving_fixture::Fixture::new();
    owner(&fixture, &["migrate-custody"]);
    owner(&fixture, &["migrate-outbound"]);
    configure(&mut fixture, node);
    fixture
}

fn save(fixture: &serving_fixture::Fixture) {
    serving_fixture::private_file(
        &fixture.config_file,
        &serde_json::to_vec(&fixture.config).unwrap(),
    );
}

#[tokio::test]
#[ignore = "requires the revision-verified private daemon in the wiring profile"]
async fn serving_recovers_after_a_real_daemon_restart_without_consuming_mail() {
    let binary = real_node::pinned_binary();
    let mut node = real_node::Node::start(&binary).await;
    let fixture = migrated_fixture(&node);
    policy(
        &fixture,
        "2",
        json!({"send":{"targets":["gateway@gateway.fixture"],"required_scope":"identity:read"},"reply":null}),
    );
    let serving = fixture.serving().await;
    let send = |request_id: &str| json!({"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"xmsg_send","arguments":{"request_id":request_id,"to":"gateway@gateway.fixture","text":"restart test"}}});
    let (status, before, _) =
        serving_fixture::request(&serving, "good-token", send("before-restart")).await;
    assert_eq!(status, StatusCode::OK);
    let before = before["result"]["structuredContent"]["receipt"].clone();
    assert!(before["receipt"]["message_id"].is_string());
    node.restart(&binary).await;
    let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(10);
    let after = loop {
        let (status, response, _) =
            serving_fixture::request(&serving, "good-token", send("after-restart")).await;
        if status == StatusCode::OK
            && response["result"]["structuredContent"]["state"] == "confirmed"
        {
            break response["result"]["structuredContent"]["receipt"].clone();
        }
        assert_ne!(
            status,
            StatusCode::FORBIDDEN,
            "disconnect is not a policy denial"
        );
        assert!(
            tokio::time::Instant::now() < deadline,
            "serving failed to recover its registration"
        );
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    };
    let (status, replay, _) =
        serving_fixture::request(&serving, "good-token", send("after-restart")).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(replay["result"]["structuredContent"]["receipt"], after);
    drop(serving);
    tokio::task::yield_now().await;
    let mut mailbox = node.config.register().await.unwrap();
    let mut ids = Vec::new();
    while let Some(delivery) = mailbox.poll(0).await.unwrap() {
        ids.push(delivery.message_id().to_owned());
        mailbox.ack(delivery.message_id()).await.unwrap();
    }
    ids.sort();
    let mut expected = vec![
        before["receipt"]["message_id"].as_str().unwrap().to_owned(),
        after["receipt"]["message_id"].as_str().unwrap().to_owned(),
    ];
    expected.sort();
    assert_eq!(
        ids, expected,
        "recovery must not poll, ACK or duplicate queued mail"
    );
    println!("gateway-wiring-complete:daemon-recovery");
}

#[tokio::test]
#[ignore = "requires the revision-verified private daemon in the wiring profile"]
async fn reconnect_rechecks_changed_limits_and_records_the_link_before_readiness() {
    let binary = real_node::pinned_binary();
    let mut node = real_node::Node::start(&binary).await;
    let fixture = migrated_fixture(&node);
    policy(
        &fixture,
        "2",
        json!({"send":{"targets":["gateway@gateway.fixture"],"required_scope":"identity:read"},"reply":null}),
    );
    let serving = fixture.serving().await;
    let identity = json!({"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"xmsg_identity","arguments":{}}});
    let (_, ready, _) = serving_fixture::request(&serving, "good-token", identity.clone()).await;
    assert_eq!(
        ready["result"]["structuredContent"]["messaging_status"]["state"],
        "ready"
    );
    node.restart_with_reply_ttl(&binary, 604799).await;
    let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(10);
    loop {
        let (_, response, _) =
            serving_fixture::request(&serving, "good-token", identity.clone()).await;
        let state = &response["result"]["structuredContent"]["messaging_status"];
        if state["state"] == "blocked" {
            assert_eq!(
                state["reason"], "reply_ttl_mismatch",
                "new handle must be checked against the original manifest"
            );
            break;
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "changed node limits were published as ready"
        );
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    }
    let send = json!({"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"xmsg_send","arguments":{"request_id":"changed-limits","to":"gateway@gateway.fixture","text":"must refuse"}}});
    let (status, _, probe) = serving_fixture::request(&serving, "good-token", send).await;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(probe.dispatches.load(Ordering::SeqCst), 0);
    let connection = rusqlite::Connection::open(&fixture.store_file).unwrap();
    let connected: bool = connection
        .query_row(
            "SELECT connected FROM custody_links WHERE bus='gateway.fixture'",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert!(!connected, "disconnect must be durably recorded");
    node.restart_with_reply_ttl(&binary, 604800).await;
    let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(10);
    loop {
        let (_, response, _) =
            serving_fixture::request(&serving, "good-token", identity.clone()).await;
        if response["result"]["structuredContent"]["messaging_status"]["state"] == "ready" {
            let connected: bool = connection
                .query_row(
                    "SELECT connected FROM custody_links WHERE bus='gateway.fixture'",
                    [],
                    |row| row.get(0),
                )
                .unwrap();
            assert!(connected, "readiness preceded the durable reconnect");
            break;
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "original manifest did not recover"
        );
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    }
    println!("gateway-wiring-complete:reconnect-limits-ledger");
}

#[tokio::test]
#[ignore = "requires the revision-verified private daemon in the wiring profile"]
async fn an_accepted_operation_across_restart_recovers_its_original_receipt_and_key() {
    let binary = real_node::pinned_binary();
    let mut node = real_node::Node::start(&binary).await;
    let fixture = migrated_fixture(&node);
    policy(
        &fixture,
        "2",
        json!({"send":{"targets":["gateway@gateway.fixture"],"required_scope":"identity:read"},"reply":null}),
    );
    let serving = std::sync::Arc::new(fixture.serving().await);
    let send = json!({"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"xmsg_send","arguments":{"request_id":"accepted-across-restart","to":"gateway@gateway.fixture","text":"accepted before restart"}}});
    let mut stall = agent_stall::AgentStall::install(&node.config, "send");
    let task_serving = serving.clone();
    let task_send = send.clone();
    let request = tokio::spawn(async move {
        serving_fixture::request(&task_serving, "good-token", task_send).await
    });
    let accepted = stall.reached().await;
    let original_id = accepted["message_id"].as_str().unwrap().to_owned();
    let connection = rusqlite::Connection::open(&fixture.store_file).unwrap();
    let original_key: String = connection.query_row("SELECT idempotency_key FROM outbound_reservations WHERE request_id='accepted-across-restart'", [], |row| row.get(0)).unwrap();
    node.stop();
    stall.finish(false).await;
    let (status, uncertain, _) = request.await.unwrap();
    assert_eq!(status, StatusCode::OK);
    assert_eq!(uncertain["result"]["structuredContent"]["state"], "unknown");
    node.restart(&binary).await;
    let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(10);
    loop {
        let (status, replay, _) =
            serving_fixture::request(&serving, "good-token", send.clone()).await;
        if status == StatusCode::OK && replay["result"]["structuredContent"]["state"] == "confirmed"
        {
            let receipt: Receipt =
                serde_json::from_value(replay["result"]["structuredContent"]["receipt"].clone())
                    .unwrap();
            let Receipt::Send(receipt) = receipt else {
                panic!("wrong receipt kind")
            };
            assert_eq!(receipt.message_id, original_id);
            break;
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "in-flight operation did not recover its receipt"
        );
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    }
    let recovered_key: String = connection.query_row("SELECT idempotency_key FROM outbound_reservations WHERE request_id='accepted-across-restart'", [], |row| row.get(0)).unwrap();
    assert_eq!(recovered_key, original_key);
    drop(serving);
    tokio::task::yield_now().await;
    let mut mailbox = node.config.register().await.unwrap();
    let delivery = mailbox.poll(0).await.unwrap().unwrap();
    assert_eq!(delivery.message_id(), original_id);
    mailbox.ack(delivery.message_id()).await.unwrap();
    assert!(mailbox.poll(0).await.unwrap().is_none());
    println!("gateway-wiring-complete:in-flight-recovery");
}

#[tokio::test]
#[ignore = "requires the revision-verified private daemon in the wiring profile"]
async fn reconnect_publication_waits_for_a_durable_ledger_commit() {
    let binary = real_node::pinned_binary();
    let mut node = real_node::Node::start(&binary).await;
    let fixture = migrated_fixture(&node);
    let probe = serving_fixture::Probe::default();
    let serving = Serving::from_owner_file(&fixture.config_file)
        .with_subscriber(probe.clone())
        .await
        .unwrap();
    assert_eq!(probe.registrations.load(Ordering::SeqCst), 1);
    node.stop();
    let connection = rusqlite::Connection::open(&fixture.store_file).unwrap();
    let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(10);
    loop {
        let connected: bool = connection
            .query_row(
                "SELECT connected FROM custody_links WHERE bus='gateway.fixture'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        if !connected {
            break;
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "disconnect was not recorded"
        );
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    }
    connection.execute_batch("BEGIN IMMEDIATE").unwrap();
    node.restart(&binary).await;
    let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(10);
    while probe.registrations.load(Ordering::SeqCst) < 2 {
        assert!(
            tokio::time::Instant::now() < deadline,
            "replacement registration was not observed"
        );
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    }
    let identity = json!({"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"xmsg_identity","arguments":{}}});
    let (status, response, _) =
        serving_fixture::request(&serving, "good-token", identity.clone()).await;
    assert_eq!(status, StatusCode::OK);
    assert_ne!(
        response["result"]["structuredContent"]["messaging_status"]["state"], "ready",
        "replacement published before durable reconnect"
    );
    connection.execute_batch("COMMIT").unwrap();
    let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(10);
    loop {
        let (_, response, _) =
            serving_fixture::request(&serving, "good-token", identity.clone()).await;
        if response["result"]["structuredContent"]["messaging_status"]["state"] == "ready" {
            break;
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "committed reconnect was not published"
        );
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    }
    let connected: bool = connection
        .query_row(
            "SELECT connected FROM custody_links WHERE bus='gateway.fixture'",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert!(connected);
    println!("gateway-wiring-complete:durable-reconnect-publication");
}

async fn cli_refuses(fixture: &serving_fixture::Fixture) {
    let result = tokio::time::timeout(
        std::time::Duration::from_secs(5),
        tokio::process::Command::new(env!("CARGO_BIN_EXE_xmsg-mcp-gateway"))
            .kill_on_drop(true)
            .arg("serve")
            .arg("--config")
            .arg(&fixture.config_file)
            .output(),
    )
    .await
    .expect("invalid startup did not exit")
    .unwrap();
    assert!(
        !result.status.success(),
        "invalid startup exited successfully"
    );
    assert!(
        !String::from_utf8_lossy(&result.stdout).contains("serving MCP at"),
        "invalid startup exposed a listener"
    );
}

async fn manifest_refusal(field: &str, value: serde_json::Value, expected: ManifestError) {
    let node = real_node::Node::start(&real_node::pinned_binary()).await;
    let mut fixture = migrated_fixture(&node);
    drop(fixture.serving().await);
    fixture.config["messaging"]["manifest"][field] = value;
    save(&fixture);
    match Serving::from_owner_file(&fixture.config_file).await {
        Err(StartupError::Manifest(actual)) => assert_eq!(actual, expected),
        Err(error) => panic!("wrong startup refusal: {error}"),
        Ok(_) => panic!("inconsistent node manifest reached the router: {field}"),
    }
    cli_refuses(&fixture).await;
}

#[tokio::test]
#[ignore = "requires the revision-verified private daemon in the wiring profile"]
async fn reply_ttl_mismatch_refuses_before_router_availability() {
    manifest_refusal("reply_ttl_secs", json!(604799), ManifestError::ReplyTtl).await;
    println!("gateway-wiring-complete:reply-ttl");
}

#[tokio::test]
#[ignore = "requires the revision-verified private daemon in the wiring profile"]
async fn reported_body_bound_refuses_an_oversized_deployment_manifest() {
    let node = real_node::Node::start_with_max_body(&real_node::pinned_binary(), 1024).await;
    let mut fixture = migrated_fixture(&node);
    fixture.config["messaging"]["manifest"]["max_framed_bytes"] = json!(1024);
    save(&fixture);
    drop(fixture.serving().await);
    fixture.config["messaging"]["manifest"]["max_framed_bytes"] = json!(1025);
    save(&fixture);
    match Serving::from_owner_file(&fixture.config_file).await {
        Err(StartupError::Manifest(ManifestError::TextBound)) => {}
        Err(error) => panic!("wrong startup refusal: {error}"),
        Ok(_) => panic!("configured bound above the effective node body limit reached the router"),
    }
    cli_refuses(&fixture).await;
    println!("gateway-wiring-complete:reported-body-bound");
}

#[tokio::test]
#[ignore = "requires the revision-verified private daemon in the wiring profile"]
async fn idempotency_ttl_mismatch_refuses_before_router_availability() {
    manifest_refusal(
        "idempotency_ttl_secs",
        json!(86401),
        ManifestError::IdempotencyTtl,
    )
    .await;
    println!("gateway-wiring-complete:idempotency-ttl");
}

#[tokio::test]
#[ignore = "requires the revision-verified private daemon in the wiring profile"]
async fn queue_capacity_mismatch_refuses_before_router_availability() {
    manifest_refusal("svc_queue_cap", json!(101), ManifestError::QueueCapacity).await;
    println!("gateway-wiring-complete:queue-capacity");
}

#[tokio::test]
#[ignore = "requires the revision-verified private daemon in the wiring profile"]
async fn dedup_lifetime_above_the_node_limit_refuses_startup() {
    manifest_refusal(
        "dedup_lifetime_secs",
        json!(86401),
        ManifestError::DedupLifetime,
    )
    .await;
    println!("gateway-wiring-complete:dedup-lifetime");
}

#[tokio::test]
#[ignore = "requires the revision-verified private daemon in the wiring profile"]
async fn invalid_service_names_refuse_at_configuration_load() {
    let node = real_node::Node::start(&real_node::pinned_binary()).await;
    let mut fixture = migrated_fixture(&node);
    for service in [
        "a/b",
        "550e8400-e29b-41d4-a716-446655440000/child",
        "with space",
        "naïve",
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        "xmsg",
    ] {
        fixture.config["messaging"]["xmsg"]["service"] = json!(service);
        save(&fixture);
        assert!(
            matches!(
                Serving::from_owner_file(&fixture.config_file).await,
                Err(StartupError::ConnectionConfiguration)
            ),
            "invalid name reached registration: {service}"
        );
        cli_refuses(&fixture).await;
    }
    println!("gateway-wiring-complete:service-name");
}

#[tokio::test]
#[ignore = "requires the revision-verified private daemon in the wiring profile"]
async fn registration_failure_never_degrades_to_identity_only() {
    let node = real_node::Node::start(&real_node::pinned_binary()).await;
    let mut fixture = migrated_fixture(&node);
    fixture.config["messaging"]["xmsg"]["register_socket"] =
        json!(fixture.keys._directory.path().join("missing.sock"));
    save(&fixture);
    assert!(
        matches!(
            Serving::from_owner_file(&fixture.config_file).await,
            Err(StartupError::Registration(_))
        ),
        "registration failure reached the router"
    );
    cli_refuses(&fixture).await;
    println!("gateway-wiring-complete:registration-failure");
}

#[tokio::test]
#[ignore = "requires the revision-verified private daemon in the wiring profile"]
async fn messaging_requires_explicit_migration_and_a_complete_budget() {
    let node = real_node::Node::start(&real_node::pinned_binary()).await;
    let mut fixture = serving_fixture::Fixture::new();
    configure(&mut fixture, &node);
    assert!(matches!(
        Serving::from_owner_file(&fixture.config_file).await,
        Err(StartupError::Store(
            xmsg_mcp_gateway::outbound::Error::MigrationRequired
        ))
    ));
    cli_refuses(&fixture).await;
    owner(&fixture, &["migrate-custody"]);
    owner(&fixture, &["migrate-outbound"]);
    fixture.config["request_timeout_ms"] = json!(10000);
    save(&fixture);
    assert!(
        matches!(
            Serving::from_owner_file(&fixture.config_file).await,
            Err(StartupError::RequestBudget)
        ),
        "insufficient messaging budget was accepted"
    );
    cli_refuses(&fixture).await;
    println!("gateway-wiring-complete:migration-budget");
}

#[tokio::test]
#[ignore = "requires the revision-verified private daemon in the wiring profile"]
async fn absent_messaging_is_identity_only_and_partial_messaging_is_not() {
    let node = real_node::Node::start(&real_node::pinned_binary()).await;
    let mut fixture = serving_fixture::Fixture::new();
    let absent = serving_fixture::Probe::default();
    let serving = Serving::from_owner_file(&fixture.config_file)
        .with_subscriber(absent.clone())
        .await
        .unwrap();
    let (status, _, _) =
        serving_fixture::request(&serving, "good-token", serving_fixture::Fixture::call()).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(absent.registrations.load(Ordering::SeqCst), 0);
    drop(serving);
    owner(&fixture, &["migrate-custody"]);
    owner(&fixture, &["migrate-outbound"]);
    configure(&mut fixture, &node);
    let present = serving_fixture::Probe::default();
    drop(
        Serving::from_owner_file(&fixture.config_file)
            .with_subscriber(present.clone())
            .await
            .unwrap(),
    );
    assert_eq!(
        present.registrations.load(Ordering::SeqCst),
        1,
        "registration positive control did not fire"
    );
    let complete = fixture.config.clone();
    for field in [
        "reply_ttl_secs",
        "idempotency_ttl_secs",
        "svc_queue_cap",
        "dedup_lifetime_secs",
        "max_framed_bytes",
    ] {
        fixture.config = complete.clone();
        fixture.config["messaging"]["manifest"]
            .as_object_mut()
            .unwrap()
            .remove(field);
        save(&fixture);
        assert!(
            matches!(
                Serving::from_owner_file(&fixture.config_file).await,
                Err(StartupError::Configuration(_))
            ),
            "missing messaging value was defaulted: {field}"
        );
    }
    fixture.config = complete;
    fixture.config["messaging"] = serde_json::Value::Null;
    save(&fixture);
    assert!(
        matches!(
            Serving::from_owner_file(&fixture.config_file).await,
            Err(StartupError::Configuration(_))
        ),
        "null messaging silently became identity-only"
    );
    println!("gateway-wiring-complete:strict-optional-profile");
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
            "request_id came from outside strict tool arguments"
        );
        assert_eq!(probe.dispatches.load(Ordering::SeqCst), 0);
        assert_eq!(probe.opens.load(Ordering::SeqCst), 1);
    }
    policy(&fixture, "3", json!({"send":null,"reply":null}));
    let (_, listed, _) = serving_fixture::request(&serving, "good-token", discovery).await;
    assert_eq!(
        listed["result"]["tools"].as_array().unwrap().len(),
        1,
        "empty policy advertised messaging authority"
    );
    let mut denied = send;
    denied["params"]["arguments"]["request_id"] = json!("new-denied-operation");
    let (status, _, probe) = serving_fixture::request(&serving, "good-token", denied).await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert_eq!(
        probe.dispatches.load(Ordering::SeqCst),
        0,
        "empty policy reached dispatcher"
    );
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
    assert!(
        delivery
            .text()
            .ends_with("untrusted private fixture message"),
        "handler changed outbound text"
    );
    mailbox.ack(delivery.message_id()).await.unwrap();
    assert!(
        mailbox.poll(0).await.unwrap().is_none(),
        "duplicate logical delivery"
    );
    println!("gateway-wiring-complete:mcp-request-id-policy");
}

#[tokio::test]
#[ignore = "requires the revision-verified private daemon in the wiring profile"]
async fn cancelling_a_handler_does_not_cancel_the_accepted_operation() {
    use axum::{body::Body, http::Request};
    use tower::ServiceExt;
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
    let mut stall = agent_stall::AgentStall::install(&node.config, "send");
    let send = json!({"jsonrpc":"2.0","id":201,"method":"tools/call",
        "params":{"name":"xmsg_send","arguments":{"request_id":"cancel-operation",
            "to":"gateway@gateway.fixture","text":"accepted before handler cancellation"}}});
    let request = Request::builder()
        .method("POST")
        .uri("/mcp")
        .header("host", "gateway.example")
        .header("content-type", "application/json")
        .header("authorization", "Bearer good-token")
        .body(Body::from(send.to_string()))
        .unwrap();
    let handler = tokio::spawn(serving.router().oneshot(request));
    let accepted = tokio::time::timeout(std::time::Duration::from_secs(5), stall.reached())
        .await
        .unwrap();
    handler.abort();
    assert!(handler.await.unwrap_err().is_cancelled());
    stall.finish(true).await;
    let recorded = tokio::time::timeout(std::time::Duration::from_secs(5), async {
        loop {
            let connection = rusqlite::Connection::open(&fixture.store_file).unwrap();
            let state: (String, bool) = connection.query_row(
                "SELECT state, receipt IS NOT NULL FROM outbound_reservations WHERE request_id='cancel-operation'",
                [], |row| Ok((row.get(0)?, row.get(1)?))).unwrap();
            if state.0 == "confirmed" && state.1 { return; }
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
    }).await;
    assert!(
        recorded.is_ok(),
        "detached dispatch did not commit before retry"
    );
    let (status, response, _) = serving_fixture::request(&serving, "good-token", send).await;
    assert_eq!(status, StatusCode::OK);
    let receipt: Receipt =
        serde_json::from_value(response["result"]["structuredContent"]["receipt"].clone()).unwrap();
    let Receipt::Send(receipt) = receipt else {
        panic!("wrong receipt vocabulary")
    };
    assert_eq!(accepted["status"], "ok");
    let mut accepted = accepted;
    accepted.as_object_mut().unwrap().remove("status");
    let accepted: xmsg::client::SendResult = serde_json::from_value(accepted).unwrap();
    assert_eq!(receipt, accepted);
    drop(serving);
    let mut mailbox = node.config.register().await.unwrap();
    let delivery = mailbox.poll(1).await.unwrap().unwrap();
    assert_eq!(delivery.message_id(), receipt.message_id);
    mailbox.ack(delivery.message_id()).await.unwrap();
    assert!(mailbox.poll(0).await.unwrap().is_none());
    println!("gateway-wiring-complete:handler-cancellation");
}

#[tokio::test]
#[ignore = "requires the revision-verified private daemon in the wiring profile"]
async fn fresh_policy_is_empty_and_cannot_be_changed_by_mcp() {
    let node = real_node::Node::start(&real_node::pinned_binary()).await;
    let fixture = migrated_fixture(&node);
    let serving = fixture.serving().await;
    let (_, listed, _) = serving_fixture::request(
        &serving,
        "good-token",
        json!({"jsonrpc":"2.0","id":1,"method":"tools/list","params":{}}),
    )
    .await;
    assert_eq!(
        listed["result"]["tools"].as_array().unwrap().len(),
        1,
        "empty policy advertised messaging authority"
    );
    for (name, arguments) in [
        (
            "xmsg_send",
            json!({"request_id":"empty-policy","to":"gateway@gateway.fixture","text":"must refuse"}),
        ),
        ("set_outbound_policy", json!({})),
    ] {
        let (status, response, probe) = serving_fixture::request(&serving, "good-token",
            json!({"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":name,"arguments":arguments}})).await;
        if name == "xmsg_send" {
            assert_eq!(status, StatusCode::FORBIDDEN);
        } else {
            assert_eq!(response["error"]["code"], -32004);
        }
        assert_eq!(probe.dispatches.load(Ordering::SeqCst), 0);
    }
    drop(serving);
    let mut mailbox = node.config.register().await.unwrap();
    assert!(mailbox.poll(0).await.unwrap().is_none());
    println!("gateway-wiring-complete:fresh-empty-policy");
}

#[tokio::test]
#[ignore = "requires the revision-verified private daemon in the wiring profile"]
async fn mcp_replies_use_owned_custody_and_the_original_bus_receipt() {
    use xmsg_mcp_gateway::{custody, grants::Store};
    let node = real_node::Node::start(&real_node::pinned_binary()).await;
    let fixture = migrated_fixture(&node);
    policy(
        &fixture,
        "2",
        json!({"send":null,"reply":{"targets":["gateway@gateway.fixture"],
        "required_scope":"identity:read"}}),
    );
    let mut mailbox = node.config.register().await.unwrap();
    let original = mailbox
        .send(
            mailbox.address().unwrap(),
            "owned inbound fixture",
            Some("owned-inbound"),
        )
        .await
        .unwrap();
    let delivery = mailbox.poll(1).await.unwrap().unwrap();
    Store::open(&fixture.store_file)
        .unwrap()
        .accept_delivery(
            &custody::Scope {
                bus_instance: mailbox.node().unwrap().into(),
                grant_id: "grant".into(),
            },
            &mailbox,
            &delivery,
            &custody::Limits::default(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs() as i64,
        )
        .unwrap();
    mailbox.ack(delivery.message_id()).await.unwrap();
    drop(mailbox);
    let serving = fixture.serving().await;
    let call = json!({"jsonrpc":"2.0","id":301,"method":"tools/call","params":{
        "name":"xmsg_reply","arguments":{"request_id":"owned-reply-operation",
            "message_id":original.message_id,"text":"owned reply"}}});
    let (status, first, probe) =
        serving_fixture::request(&serving, "good-token", call.clone()).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        first["result"]["structuredContent"]["state"], "confirmed",
        "owned MCP reply was not confirmed"
    );
    assert_eq!(probe.opens.load(Ordering::SeqCst), 2);
    let mut repeated = call.clone();
    repeated["id"] = json!(302);
    let (_, replay, _) = serving_fixture::request(&serving, "good-token", repeated).await;
    assert_eq!(first["result"], replay["result"]);
    let mut unknown = call;
    unknown["params"]["arguments"]["request_id"] = json!("unknown-correlation");
    unknown["params"]["arguments"]["message_id"] = json!("01ARZ3NDEKTSV4RRFFQ69G5FAV");
    let (status, _, _) = serving_fixture::request(&serving, "good-token", unknown).await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    let receipt: Receipt =
        serde_json::from_value(first["result"]["structuredContent"]["receipt"].clone()).unwrap();
    let Receipt::Reply(receipt) = receipt else {
        panic!("reply did not preserve the xmsg reply record")
    };
    assert_eq!(receipt.message_id, original.message_id);
    drop(serving);
    let mut mailbox = node.config.register().await.unwrap();
    let delivery = mailbox.poll(1).await.unwrap().unwrap();
    assert_eq!(
        receipt.pushed_message_id.as_deref(),
        Some(delivery.message_id())
    );
    assert_eq!(delivery.in_reply_to(), Some(original.message_id.as_str()));
    mailbox.ack(delivery.message_id()).await.unwrap();
    assert!(mailbox.poll(0).await.unwrap().is_none());
    println!("gateway-wiring-complete:owned-reply");
}

#[tokio::test]
#[ignore = "requires the revision-verified private daemon in the wiring profile"]
async fn unconfigured_scopes_do_not_advertise_or_dispatch_messaging() {
    let node = real_node::Node::start(&real_node::pinned_binary()).await;
    let fixture = migrated_fixture(&node);
    policy(
        &fixture,
        "2",
        json!({"send":{"targets":["gateway@gateway.fixture"],
        "required_scope":"unconfigured:write"},"reply":null}),
    );
    let serving = fixture.serving().await;
    let (_, listed, _) = serving_fixture::request(
        &serving,
        "good-token",
        json!({"jsonrpc":"2.0","id":1,"method":"tools/list","params":{}}),
    )
    .await;
    assert_eq!(
        listed["result"]["tools"].as_array().unwrap().len(),
        1,
        "unconfigured scope advertised messaging authority"
    );
    let (status, _, probe) = serving_fixture::request(
        &serving,
        "good-token",
        json!({"jsonrpc":"2.0","id":2,"method":"tools/call","params":{
            "name":"xmsg_send","arguments":{"request_id":"scope-refused",
                "to":"gateway@gateway.fixture","text":"must refuse"}}}),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert_eq!(probe.dispatches.load(Ordering::SeqCst), 0);
    println!("gateway-wiring-complete:scope-ceiling");
}

#[tokio::test]
#[ignore = "requires the revision-verified private daemon in the wiring profile"]
async fn the_complete_framed_bound_is_used_instead_of_the_payload_length() {
    let node = real_node::Node::start(&real_node::pinned_binary()).await;
    let mut fixture = migrated_fixture(&node);
    policy(
        &fixture,
        "2",
        json!({"send":{"targets":["gateway@gateway.fixture"],
        "required_scope":"identity:read"},"reply":null}),
    );
    fixture.config["messaging"]["manifest"]["max_framed_bytes"] = json!(1);
    save(&fixture);
    let serving = fixture.serving().await;
    let (status, response, _) = serving_fixture::request(
        &serving,
        "good-token",
        json!({"jsonrpc":"2.0","id":1,"method":"tools/call","params":{
            "name":"xmsg_send","arguments":{"request_id":"framed-bound",
                "to":"gateway@gateway.fixture","text":"x"}}}),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        response["error"]["code"], -32602,
        "configured complete framed bound was ignored"
    );
    drop(serving);
    let mut mailbox = node.config.register().await.unwrap();
    assert!(mailbox.poll(0).await.unwrap().is_none());
    println!("gateway-wiring-complete:complete-framed-bound");
}

#[tokio::test]
#[ignore = "requires the revision-verified private daemon in the wiring profile"]
async fn handler_deadline_reports_pending_without_cancelling_accepted_work() {
    use axum::{
        body::{to_bytes, Body, Bytes},
        http::Request,
    };
    use tower::ServiceExt;
    let node = real_node::Node::start(&real_node::pinned_binary()).await;
    let mut fixture = migrated_fixture(&node);
    policy(
        &fixture,
        "2",
        json!({"send":{"targets":["gateway@gateway.fixture"],
        "required_scope":"identity:read"},"reply":null}),
    );
    fixture.config["request_timeout_ms"] = json!(33000);
    fixture.config["messaging"]["submission_timeout_ms"] = json!(1000);
    save(&fixture);
    let serving = fixture.serving().await;
    let mut stall = agent_stall::AgentStall::install(&node.config, "send");
    let send = json!({"jsonrpc":"2.0","id":401,"method":"tools/call","params":{
        "name":"xmsg_send","arguments":{"request_id":"deadline-operation",
            "to":"gateway@gateway.fixture","text":"accepted after a slow request body"}}});
    let body = send.to_string();
    let (entered_tx, entered_rx) = tokio::sync::oneshot::channel();
    let (release_tx, release_rx) = tokio::sync::oneshot::channel();
    let stream = futures_util::stream::once(async move {
        entered_tx.send(()).unwrap();
        release_rx.await.unwrap();
        Ok::<_, std::convert::Infallible>(Bytes::from(body))
    });
    let request = Request::builder()
        .method("POST")
        .uri("/mcp")
        .header("host", "gateway.example")
        .header("content-type", "application/json")
        .header("authorization", "Bearer good-token")
        .body(Body::from_stream(stream))
        .unwrap();
    let handler = tokio::spawn(serving.router().oneshot(request));
    tokio::time::timeout(std::time::Duration::from_secs(5), entered_rx)
        .await
        .unwrap()
        .unwrap();
    // Spend the real handler budget in its body reader, after observing its first poll.
    tokio::time::sleep(std::time::Duration::from_millis(32500)).await;
    release_tx.send(()).unwrap();
    let accepted = tokio::time::timeout(std::time::Duration::from_secs(3), stall.reached())
        .await
        .unwrap();
    let response = tokio::time::timeout(std::time::Duration::from_secs(3), handler)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    let status = response.status();
    assert_eq!(
        status,
        StatusCode::OK,
        "handler deadline hid its pending request"
    );
    let body: serde_json::Value =
        serde_json::from_slice(&to_bytes(response.into_body(), 100_000).await.unwrap()).unwrap();
    assert_eq!(
        body["result"]["structuredContent"]["state"], "pending",
        "handler deadline hid its pending request"
    );
    assert_eq!(
        body["result"]["structuredContent"]["request_id"],
        "deadline-operation"
    );
    stall.finish(true).await;
    tokio::time::timeout(std::time::Duration::from_secs(5), async {
        loop {
            let connection = rusqlite::Connection::open(&fixture.store_file).unwrap();
            let confirmed: bool = connection.query_row(
                "SELECT state='confirmed' AND receipt IS NOT NULL FROM outbound_reservations WHERE request_id='deadline-operation'",
                [], |row| row.get(0)).unwrap();
            if confirmed { break; }
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
    }).await.expect("deadline cancelled the dispatch outcome commit");
    let (_, replay, _) = serving_fixture::request(&serving, "good-token", send).await;
    let receipt: Receipt =
        serde_json::from_value(replay["result"]["structuredContent"]["receipt"].clone()).unwrap();
    let Receipt::Send(receipt) = receipt else {
        panic!("wrong receipt vocabulary")
    };
    assert_eq!(receipt.message_id, accepted["message_id"]);
    drop(serving);
    let mut mailbox = node.config.register().await.unwrap();
    let delivery = mailbox.poll(1).await.unwrap().unwrap();
    assert_eq!(delivery.message_id(), receipt.message_id);
    mailbox.ack(delivery.message_id()).await.unwrap();
    assert!(mailbox.poll(0).await.unwrap().is_none());
    println!("gateway-wiring-complete:deadline-pending");
}
