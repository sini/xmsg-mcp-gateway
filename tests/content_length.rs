#[allow(dead_code)]
#[path = "common/provider.rs"]
mod provider;
#[allow(dead_code)]
#[cfg(target_os = "linux")]
#[path = "common/real_node.rs"]
mod real_node;
#[allow(dead_code)]
#[path = "common/serving_fixture.rs"]
mod serving_fixture;

use serde_json::{json, Value};
use std::sync::atomic::Ordering;
use std::time::Duration;
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use xmsg_mcp_gateway::serving::{Serving, StartupError};

fn save(fixture: &serving_fixture::Fixture) {
    serving_fixture::private_file(
        &fixture.config_file,
        &serde_json::to_vec(&fixture.config).unwrap(),
    );
}

async fn listener(fixture: &serving_fixture::Fixture) -> (tokio::process::Child, String) {
    eprintln!(
        "gateway-mutant-app:{}",
        env!("CARGO_BIN_EXE_xmsg-mcp-gateway")
    );
    let mut child = tokio::process::Command::new(env!("CARGO_BIN_EXE_xmsg-mcp-gateway"))
        .args(["serve", "--config"])
        .arg(&fixture.config_file)
        .stdout(std::process::Stdio::piped())
        .kill_on_drop(true)
        .spawn()
        .unwrap();
    let mut lines = BufReader::new(child.stdout.take().unwrap()).lines();
    let line = tokio::time::timeout(Duration::from_secs(5), lines.next_line())
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    let address = line
        .strip_prefix("serving MCP at ")
        .expect("listener readiness")
        .to_owned();
    (child, address)
}

async fn post(address: &str, body: String) -> Value {
    let response = reqwest::Client::new()
        .post(format!("http://{address}/mcp"))
        .bearer_auth("good-token")
        .header("content-type", "application/json")
        .body(body)
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), reqwest::StatusCode::OK);
    serde_json::from_slice(&response.bytes().await.unwrap()).unwrap()
}

#[tokio::test]
async fn oversized_advertised_body_is_refused_before_body_bytes() {
    let mut fixture = serving_fixture::Fixture::new();
    fixture.config["max_request_body_bytes"] = json!(409600);
    save(&fixture);
    let (_child, address) = listener(&fixture).await;
    let mut socket = tokio::net::TcpStream::connect(&address).await.unwrap();
    socket.write_all(b"POST /mcp HTTP/1.1\r\nHost: gateway.example\r\nAuthorization: Bearer good-token\r\nContent-Type: application/json\r\nContent-Length: 409601\r\n\r\n").await.unwrap();
    let mut response = [0; 1024];
    let count = tokio::time::timeout(Duration::from_millis(750), socket.read(&mut response))
        .await
        .expect("oversized declared body waited for body bytes")
        .unwrap();
    assert!(String::from_utf8_lossy(&response[..count]).starts_with("HTTP/1.1 413"));
    assert_eq!(fixture.requests.load(Ordering::SeqCst), 0);
    println!(
        "content-length-complete:no-body:{}",
        option_env!("GW_H1_NONCE").unwrap_or("local")
    );
}

#[tokio::test]
async fn exact_limit_valid_padded_rpc_is_accepted() {
    let mut fixture = serving_fixture::Fixture::new();
    fixture.config["max_request_body_bytes"] = json!(409600);
    save(&fixture);
    let (_child, address) = listener(&fixture).await;
    let mut body = json!({"jsonrpc":"2.0","id":"exact-limit","method":"ping"}).to_string();
    body.extend(std::iter::repeat_n(' ', 409600 - body.len()));
    let response = post(&address, body).await;
    assert_eq!(
        response,
        json!({"jsonrpc":"2.0","id":"exact-limit","result":{}})
    );
    assert_eq!(fixture.requests.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn streaming_body_keeps_the_configured_bound() {
    use axum::{body::Body, http::Request};
    let mut fixture = serving_fixture::Fixture::new();
    fixture.config["max_request_body_bytes"] = json!(256);
    save(&fixture);
    let serving = fixture.serving().await;
    let request = Request::builder()
        .method("POST")
        .uri("/mcp")
        .header("host", "gateway.example")
        .header("authorization", "Bearer good-token")
        .body(Body::from(vec![b' '; 257]))
        .unwrap();
    let (status, _, _) = serving_fixture::raw_request(&serving, request).await;
    assert_eq!(status, axum::http::StatusCode::PAYLOAD_TOO_LARGE);
    assert_eq!(fixture.requests.load(Ordering::SeqCst), 0);
}

fn messaging(
    fixture: &mut serving_fixture::Fixture,
    connection: &xmsg_mcp_gateway::xmsg_config::XmsgConfig,
) {
    fixture.config["request_timeout_ms"] = json!(60000);
    fixture.config["messaging"] = json!({"xmsg": {
        "service":connection.service,"expected_node":connection.expected_node,
        "daemon_uid":connection.daemon_uid,"register_socket":connection.register_socket,
        "agent_socket":connection.agent_socket,"max_frame_bytes":connection.max_frame_bytes,
        "operation_timeout_ms":connection.operation_timeout_ms},
        "manifest":{"reply_ttl_secs":604800,"idempotency_ttl_secs":86400,
        "svc_queue_cap":100,"dedup_lifetime_secs":3600,"max_framed_bytes":65536},
        "submission_timeout_ms":10000,"max_reservations":1000,"max_retained_bytes":67108864});
}

#[tokio::test]
async fn insufficient_escaped_body_budget_is_a_typed_startup_refusal() {
    let mut fixture = serving_fixture::Fixture::new();
    let connection = xmsg_mcp_gateway::xmsg_config::XmsgConfig {
        service: "gateway".into(),
        expected_node: "gateway.fixture".into(),
        daemon_uid: unsafe { libc::getuid() },
        register_socket: "/nonexistent/register".into(),
        agent_socket: "/nonexistent/agent".into(),
        max_frame_bytes: 1048576,
        operation_timeout_ms: 10000,
    };
    messaging(&mut fixture, &connection);
    fixture.config["max_request_body_bytes"] = json!(409599);
    save(&fixture);
    assert!(
        matches!(
            Serving::from_owner_file(&fixture.config_file).await,
            Err(StartupError::RequestBodyBudget)
        ),
        "insufficient escaped request budget was accepted or refused for the wrong reason"
    );
    println!(
        "content-length-complete:startup-budget:{}",
        option_env!("GW_H1_NONCE").unwrap_or("local")
    );
}

#[cfg(target_os = "linux")]
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

#[tokio::test]
#[cfg(target_os = "linux")]
#[ignore = "requires the revision-verified private daemon in the body profile"]
async fn maximum_escaped_complete_frame_survives_the_real_listener() {
    let mut prepared = real_node::Prepared::create("gateway", "gateway", None);
    prepared
        .extra_service_executables
        .push(("receiver".into(), std::env::current_exe().unwrap()));
    let node = prepared
        .launch_as(
            &real_node::pinned_binary(),
            std::path::Path::new(env!("CARGO_BIN_EXE_xmsg-mcp-gateway")),
        )
        .await;
    let mut receiver_config = node.config.clone();
    receiver_config.service = "receiver".into();
    let mut fixture = serving_fixture::Fixture::new();
    owner(&fixture, &["migrate-custody"]);
    owner(&fixture, &["migrate-outbound"]);
    let policy_file = fixture.keys._directory.path().join("policy.json");
    serving_fixture::private_file(&policy_file, &serde_json::to_vec(&json!({"send":{"targets":["receiver@gateway.fixture"],"required_scope":"identity:read"},"reply":null})).unwrap());
    owner(
        &fixture,
        &[
            "set-outbound-policy",
            "grant",
            "2",
            policy_file.to_str().unwrap(),
        ],
    );
    messaging(&mut fixture, &node.config);
    fixture.config["max_request_body_bytes"] = json!(409600);
    save(&fixture);
    let (_child, address) = listener(&fixture).await;
    let mut mailbox = receiver_config.register().await.unwrap();
    let send = |request_id: &str, text: &str| {
        json!({"jsonrpc":"2.0","id":request_id,"method":"tools/call","params":{"name":"xmsg_send","arguments":{"request_id":request_id,"to":"receiver@gateway.fixture","text":text}}}).to_string()
    };
    let probe = post(&address, send("frame-probe", "\u{1}")).await;
    assert_eq!(probe["result"]["structuredContent"]["state"], "confirmed");
    let delivery = mailbox.poll(1).await.unwrap().unwrap();
    let observed = delivery.text().to_owned();
    assert!(observed.ends_with('\u{1}'));
    let preamble = observed.strip_suffix('\u{1}').unwrap().to_owned();
    mailbox.ack(delivery.message_id()).await.unwrap();
    let text = "\u{1}".repeat(65536 - preamble.len());
    let raw = send("maximum-escaped-frame", &text);
    assert!(raw.contains("\\u0001"));
    assert!(raw.len() <= 409600);
    let response = post(&address, raw).await;
    assert_eq!(
        response["result"]["structuredContent"]["state"],
        "confirmed"
    );
    assert_eq!(response["id"], "maximum-escaped-frame");
    let delivery = mailbox.poll(1).await.unwrap().unwrap();
    assert_eq!(delivery.text().len(), 65536);
    assert!(delivery.text().ends_with(&text));
    let connection = rusqlite::Connection::open(&fixture.store_file).unwrap();
    let framed: String = connection.query_row(
        "SELECT framed_text FROM outbound_reservations WHERE request_id = 'maximum-escaped-frame'", [], |row| row.get(0)).unwrap();
    assert_eq!(delivery.text(), framed);
    mailbox.ack(delivery.message_id()).await.unwrap();
    println!(
        "content-length-complete:maximum-escaped-frame:{}",
        option_env!("GW_H1_NONCE").unwrap_or("local")
    );
}

#[tokio::test]
async fn body_configuration_refuses_invalid_values_and_preserves_owner_file_bound() {
    let mut fixture = serving_fixture::Fixture::new();
    for value in [
        json!(0),
        json!(-1),
        json!(1.5),
        json!("1048576"),
        json!(null),
    ] {
        fixture.config["max_request_body_bytes"] = value;
        save(&fixture);
        assert!(matches!(
            Serving::from_owner_file(&fixture.config_file).await,
            Err(StartupError::Configuration(_))
        ));
    }
    fixture.config["max_request_body_bytes"] = json!(1048576);
    save(&fixture);
    assert!(Serving::from_owner_file(&fixture.config_file).await.is_ok());
    let mut file = serde_json::to_vec(&fixture.config).unwrap();
    file.resize(65537, b' ');
    serving_fixture::private_file(&fixture.config_file, &file);
    assert!(matches!(
        Serving::from_owner_file(&fixture.config_file).await,
        Err(StartupError::Configuration(_))
    ));
}
