#[allow(dead_code)]
#[path = "common/serving_fixture.rs"]
mod fixture;
#[allow(dead_code)]
#[path = "common/provider.rs"]
mod provider;

use fixture::Fixture;
use std::process::Stdio;
use std::time::{Duration, Instant};
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::TcpStream;

async fn normal(address: &str) {
    let response = reqwest::Client::builder()
        .no_proxy()
        .timeout(Duration::from_secs(3))
        .build()
        .unwrap()
        .post(format!("http://{address}/mcp"))
        .bearer_auth("good-token")
        .header("content-type", "application/json")
        .body(Fixture::call().to_string())
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), reqwest::StatusCode::OK);
    assert_eq!(
        serde_json::from_slice::<serde_json::Value>(&response.bytes().await.unwrap()).unwrap()
            ["result"]["structuredContent"]["subject"],
        "owner"
    );
}

#[tokio::test]
async fn header_deadline_is_absolute_and_excludes_body() {
    eprintln!(
        "header-timeout nonce={}",
        std::env::var("GW_H1_NONCE").unwrap_or_else(|_| "local".into())
    );
    let mut fixture = Fixture::new();
    fixture.config["header_read_timeout_ms"] = serde_json::json!(300);
    fixture::private_file(
        &fixture.config_file,
        &serde_json::to_vec(&fixture.config).unwrap(),
    );
    let mut child = tokio::process::Command::new(env!("CARGO_BIN_EXE_xmsg-mcp-gateway"))
        .args(["serve", "--config"])
        .arg(&fixture.config_file)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true)
        .spawn()
        .unwrap();
    let mut lines = BufReader::new(child.stdout.take().unwrap()).lines();
    let ready = tokio::time::timeout(Duration::from_secs(5), lines.next_line())
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    let address = ready.strip_prefix("serving MCP at ").unwrap();
    normal(address).await;
    let mut socket = TcpStream::connect(address).await.unwrap();
    socket
        .write_all(b"POST /mcp HTTP/1.1\r\nHost: gateway.example\r\nX-Drip: ")
        .await
        .unwrap();
    let started = Instant::now();
    let mut tick = tokio::time::interval(Duration::from_millis(40));
    let mut byte = [0];
    let closed = tokio::time::timeout(Duration::from_millis(1500), async {
        loop {
            tokio::select! {
                result = socket.read(&mut byte) => {
                    match result {
                        Ok(0) => break,
                        Err(error) if matches!(error.kind(), std::io::ErrorKind::ConnectionReset | std::io::ErrorKind::ConnectionAborted) => break,
                        other => panic!("unexpected incomplete-header response: {other:?}"),
                    }
                }
                _ = tick.tick() => {
                    // Continue dripping beyond the absolute deadline; every read stays active.
                    let _ = socket.write_all(b"x").await;
                }
            }
        }
    }).await;
    assert!(
        closed.is_ok(),
        "slow headers were not disconnected within header deadline plus scheduling tolerance"
    );
    assert!(
        started.elapsed() >= Duration::from_millis(200),
        "deadline fired before configured bound"
    );
    normal(address).await;
    let mut socket = TcpStream::connect(address).await.unwrap();
    let body = Fixture::call().to_string();
    socket.write_all(format!("POST /mcp HTTP/1.1\r\nHost: gateway.example\r\nAuthorization: Bearer good-token\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n", body.len()).as_bytes()).await.unwrap();
    tokio::time::sleep(Duration::from_millis(700)).await;
    socket.write_all(body.as_bytes()).await.unwrap();
    let mut response = Vec::new();
    tokio::time::timeout(Duration::from_secs(3), socket.read_to_end(&mut response))
        .await
        .unwrap()
        .unwrap();
    assert!(
        response.starts_with(b"HTTP/1.1 200 OK"),
        "delayed body was rejected: {}",
        String::from_utf8_lossy(&response)
    );
    assert!(String::from_utf8_lossy(&response).contains("owner"));
    normal(address).await;
    child.kill().await.unwrap();
    child.wait().await.unwrap();
}

#[tokio::test]
async fn header_deadline_configuration_is_typed_and_optional() {
    let fixture = Fixture::new();
    assert!(
        xmsg_mcp_gateway::serving::Serving::from_owner_file(&fixture.config_file)
            .await
            .is_ok()
    );
    for invalid in [
        serde_json::json!(0),
        serde_json::json!(60001),
        serde_json::json!(-1),
        serde_json::json!("5000"),
        serde_json::json!(1.5),
        serde_json::Value::Null,
    ] {
        let mut config = fixture.config.clone();
        config["header_read_timeout_ms"] = invalid;
        fixture::private_file(&fixture.config_file, &serde_json::to_vec(&config).unwrap());
        assert!(matches!(
            xmsg_mcp_gateway::serving::Serving::from_owner_file(&fixture.config_file).await,
            Err(xmsg_mcp_gateway::serving::StartupError::Configuration(_))
        ));
    }
}
