#[allow(dead_code)]
#[path = "common/serving_fixture.rs"]
mod fixture;
#[allow(dead_code)]
#[path = "common/provider.rs"]
mod provider;

use std::time::Duration;

use serde_json::json;
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::TcpStream;
use xmsg_mcp_gateway::serving::{Serving, StartupError};

async fn metadata(socket: &mut TcpStream) {
    socket
        .write_all(
            b"GET /.well-known/oauth-protected-resource HTTP/1.1\r\nHost: gateway.example\r\n\r\n",
        )
        .await
        .unwrap();
    let mut reader = BufReader::new(socket);
    let mut line = String::new();
    reader.read_line(&mut line).await.unwrap();
    assert!(line.starts_with("HTTP/1.1 200"), "metadata control: {line}");
    let mut length = None;
    loop {
        line.clear();
        reader.read_line(&mut line).await.unwrap();
        if line == "\r\n" {
            break;
        }
        if let Some(value) = line.to_ascii_lowercase().strip_prefix("content-length: ") {
            length = Some(value.trim().parse::<usize>().unwrap());
        }
    }
    let mut body = vec![0; length.unwrap()];
    reader.read_exact(&mut body).await.unwrap();
    let value: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(value["resource"], "https://gateway.example/mcp");
}

#[tokio::test]
async fn connection_cap_bounds_idle_and_keepalive_and_releases_slots() {
    if let Ok(nonce) = std::env::var("GW_CAP_NONCE") {
        eprintln!("GW_CAP_EXECUTED={nonce}");
    }
    let mut fixture = fixture::Fixture::new();
    fixture.config["max_connections"] = json!(2);
    fixture.config["header_read_timeout_ms"] = json!(60_000);
    fixture::private_file(
        &fixture.config_file,
        &serde_json::to_vec(&fixture.config).unwrap(),
    );
    let mut child = tokio::process::Command::new(env!("CARGO_BIN_EXE_xmsg-mcp-gateway"))
        .arg("serve")
        .arg("--config")
        .arg(&fixture.config_file)
        .stdout(std::process::Stdio::piped())
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
    let mut idle = TcpStream::connect(address).await.unwrap();
    let mut keepalive = TcpStream::connect(address).await.unwrap();
    tokio::time::timeout(Duration::from_secs(2), metadata(&mut keepalive))
        .await
        .unwrap();
    let mut excess = TcpStream::connect(address).await.unwrap();
    let mut byte = [0];
    let refusal = tokio::time::timeout(Duration::from_millis(750), excess.read(&mut byte)).await;
    assert!(
        matches!(refusal, Ok(Ok(0)))
            || matches!(refusal, Ok(Err(ref error)) if matches!(error.kind(), std::io::ErrorKind::ConnectionReset | std::io::ErrorKind::ConnectionAborted)),
        "connection cap failed to promptly refuse N+1: {refusal:?}"
    );
    tokio::time::timeout(Duration::from_secs(2), metadata(&mut idle))
        .await
        .unwrap();
    tokio::time::timeout(Duration::from_secs(2), metadata(&mut keepalive))
        .await
        .unwrap();
    drop(idle);
    // Wait for the remote FIN to retire the old connection, then require a full response.
    tokio::time::sleep(Duration::from_millis(100)).await;
    let mut replacement = TcpStream::connect(address).await.unwrap();
    tokio::time::timeout(Duration::from_secs(2), metadata(&mut replacement))
        .await
        .unwrap();
    drop(replacement);
    drop(keepalive);
    drop(excess);
    child.kill().await.unwrap();
    child.wait().await.unwrap();
}

#[tokio::test]
async fn connection_cap_configuration_is_typed_and_defaults_remain_valid() {
    let mut fixture = fixture::Fixture::new();
    assert!(Serving::from_owner_file(&fixture.config_file).await.is_ok());
    for value in [
        json!(0),
        json!(-1),
        json!(1.5),
        json!("2"),
        json!(null),
        json!(u64::MAX),
    ] {
        fixture.config["max_connections"] = value;
        fixture::private_file(
            &fixture.config_file,
            &serde_json::to_vec(&fixture.config).unwrap(),
        );
        assert!(matches!(
            Serving::from_owner_file(&fixture.config_file).await,
            Err(StartupError::Configuration(_))
        ));
    }
}
