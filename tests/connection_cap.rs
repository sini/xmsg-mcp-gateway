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

const REQUEST_SECRET: &str = "cap-request-secret-must-not-reach-stderr";

async fn metadata(socket: &mut TcpStream) -> std::io::Result<()> {
    socket
        .write_all(
            format!("GET /.well-known/oauth-protected-resource HTTP/1.1\r\nHost: gateway.example\r\nX-Request-Secret: {REQUEST_SECRET}\r\n\r\n").as_bytes(),
        )
        .await?;
    let mut reader = BufReader::new(socket);
    let mut line = String::new();
    if reader.read_line(&mut line).await? == 0 {
        return Err(std::io::ErrorKind::UnexpectedEof.into());
    }
    assert!(line.starts_with("HTTP/1.1 200"), "metadata control: {line}");
    let mut length = None;
    loop {
        line.clear();
        if reader.read_line(&mut line).await? == 0 {
            return Err(std::io::ErrorKind::UnexpectedEof.into());
        }
        if line == "\r\n" {
            break;
        }
        if let Some(value) = line.to_ascii_lowercase().strip_prefix("content-length: ") {
            length = Some(value.trim().parse::<usize>().unwrap());
        }
    }
    let mut body = vec![0; length.unwrap()];
    reader.read_exact(&mut body).await?;
    let value: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(value["resource"], "https://gateway.example/mcp");
    Ok(())
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
        .stderr(std::process::Stdio::piped())
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
        .unwrap()
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
        .unwrap()
        .unwrap();
    tokio::time::timeout(Duration::from_secs(2), metadata(&mut keepalive))
        .await
        .unwrap()
        .unwrap();
    drop(idle);
    tokio::time::timeout(Duration::from_secs(2), async {
        let mut attempts = tokio::time::interval(Duration::from_millis(10));
        loop {
            attempts.tick().await;
            let mut replacement = TcpStream::connect(address).await.unwrap();
            if metadata(&mut replacement).await.is_ok() {
                break;
            }
        }
    })
    .await
    .expect("released connection slot did not admit a replacement before the deadline");
    drop(keepalive);
    drop(excess);
    child.kill().await.unwrap();
    child.wait().await.unwrap();
    let mut stderr = String::new();
    child
        .stderr
        .take()
        .unwrap()
        .read_to_string(&mut stderr)
        .await
        .unwrap();
    assert!(
        stderr.contains("ConnectionCapacityRefusal"),
        "missing production cap reason: {stderr}"
    );
    assert!(
        !stderr.contains(REQUEST_SECRET),
        "request secret leaked to stderr"
    );
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
