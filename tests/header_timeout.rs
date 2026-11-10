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
    let mut body = Fixture::call();
    body["params"]["_meta"] = serde_json::json!({"opaque":"HEADER_BODY_CANARY_34"});
    let response = reqwest::Client::builder()
        .no_proxy()
        .timeout(Duration::from_secs(3))
        .build()
        .unwrap()
        .post(format!("http://{address}/mcp"))
        .bearer_auth("good-token")
        .header("content-type", "application/json")
        .body(body.to_string())
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
        .env_remove("RUST_LOG")
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
    let mut invalid = Fixture::call();
    invalid["id"] = serde_json::json!("HEADER_ID_CANARY_34");
    invalid["params"]["arguments"] = serde_json::json!({"opaque":"HEADER_ARGUMENT_CANARY_34"});
    invalid["params"]["_meta"] = serde_json::json!({"opaque":"HEADER_BODY_CANARY_34"});
    let refused = reqwest::Client::builder()
        .no_proxy()
        .timeout(Duration::from_secs(3))
        .build()
        .unwrap()
        .post(format!("http://{address}/mcp"))
        .bearer_auth("good-token")
        .header("content-type", "application/json")
        .body(invalid.to_string())
        .send()
        .await
        .unwrap();
    assert_eq!(refused.status(), reqwest::StatusCode::OK);
    let refused: serde_json::Value =
        serde_json::from_slice(&refused.bytes().await.unwrap()).unwrap();
    assert_eq!(refused["error"]["code"], -32602);
    let mut socket = TcpStream::connect(address).await.unwrap();
    socket
        .write_all(b"POST /mcp HTTP/1.1\r\nHost: gateway.example\r\nAuthorization: Bearer header-secret-token\r\nX-Drip: ")
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
    let mut body = Fixture::call();
    body["params"]["_meta"] = serde_json::json!({"opaque":"HEADER_BODY_CANARY_34"});
    let body = body.to_string();
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
    let mut logs = String::new();
    child
        .stderr
        .take()
        .unwrap()
        .read_to_string(&mut logs)
        .await
        .unwrap();
    assert!(
        logs.contains("HeaderReadTimeout"),
        "header timeout reason was not emitted: {logs}"
    );
    let outcomes: Vec<_> = logs
        .lines()
        .filter(|line| line.contains("gateway_dispatch: dispatch outcome"))
        .collect();
    assert_eq!(
        outcomes.len(),
        1,
        "default CLI did not emit exactly one outcome: {logs}"
    );
    assert!(
        outcomes[0].contains("operation=\"xmsg_identity\"")
            && outcomes[0].contains("class=\"invalid\"")
            && outcomes[0].contains("kind=\"arguments\""),
        "default CLI outcome fields were not static: {logs}"
    );
    for secret in [
        "HEADER_ID_CANARY_34",
        "HEADER_ARGUMENT_CANARY_34",
        "header-secret-token",
        "good-token",
        "tools/call",
        "HEADER_BODY_CANARY_34",
        "\"name\":\"xmsg_identity\"",
    ] {
        assert!(
            !logs.contains(secret),
            "transport logs exposed request data: {logs}"
        );
    }
    eprintln!("actual-cli-static-outcome: {}", outcomes[0]);
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

async fn listener(fixture: &Fixture, limited_descriptors: bool) -> (tokio::process::Child, String) {
    let mut command = if limited_descriptors {
        let mut command = tokio::process::Command::new("prlimit");
        command.args([
            "--nofile=64:64",
            "--",
            env!("CARGO_BIN_EXE_xmsg-mcp-gateway"),
        ]);
        command
    } else {
        tokio::process::Command::new(env!("CARGO_BIN_EXE_xmsg-mcp-gateway"))
    };
    let mut child = command
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
    (
        child,
        ready.strip_prefix("serving MCP at ").unwrap().to_owned(),
    )
}

#[tokio::test]
async fn idle_keepalive_is_bounded_by_the_next_header_deadline() {
    let mut fixture = Fixture::new();
    fixture.config["header_read_timeout_ms"] = serde_json::json!(300);
    fixture::private_file(
        &fixture.config_file,
        &serde_json::to_vec(&fixture.config).unwrap(),
    );
    let (mut child, address) = listener(&fixture, false).await;
    let mut socket = BufReader::new(TcpStream::connect(&address).await.unwrap());
    let started = Instant::now();
    socket
        .get_mut()
        .write_all(
            b"GET /.well-known/oauth-protected-resource HTTP/1.1\r\nHost: gateway.example\r\n\r\n",
        )
        .await
        .unwrap();
    let mut status = String::new();
    socket.read_line(&mut status).await.unwrap();
    assert!(status.starts_with("HTTP/1.1 200 OK"), "{status}");
    let mut length = None;
    loop {
        let mut line = String::new();
        assert!(socket.read_line(&mut line).await.unwrap() > 0);
        if line == "\r\n" {
            break;
        }
        if let Some(value) = line.to_ascii_lowercase().strip_prefix("content-length:") {
            length = Some(value.trim().parse::<usize>().unwrap());
        }
    }
    let mut body = vec![0; length.expect("metadata must have a bounded body")];
    socket.read_exact(&mut body).await.unwrap();
    assert_eq!(
        serde_json::from_slice::<serde_json::Value>(&body).unwrap()["resource"],
        fixture.binding.resource
    );
    let mut byte = [0];
    let closed = tokio::time::timeout(Duration::from_millis(1500), socket.read(&mut byte)).await;
    assert!(
        matches!(closed, Ok(Ok(0))),
        "idle keep-alive exceeded next-header deadline: {closed:?}"
    );
    assert!(
        started.elapsed() >= Duration::from_millis(200),
        "idle keep-alive closed before header deadline"
    );
    normal(&address).await;
    child.kill().await.unwrap();
    child.wait().await.unwrap();
}

#[cfg(target_os = "linux")]
async fn descriptor_pressure(fixture: &Fixture) -> (tokio::process::Child, String, Vec<TcpStream>) {
    let (mut child, address) = listener(fixture, true).await;
    normal(&address).await;
    let mut logs = BufReader::new(child.stderr.take().unwrap()).lines();
    let mut held = Vec::new();
    for _ in 0..100 {
        let connected = tokio::time::timeout(Duration::from_secs(3), TcpStream::connect(&address))
            .await
            .unwrap();
        match connected {
            Ok(socket) => held.push(socket),
            Err(error) => {
                let exited = tokio::time::timeout(Duration::from_secs(1), child.wait()).await;
                assert!(
                    matches!(exited, Ok(Ok(_))),
                    "connection failed while server remained alive: {error}"
                );
                panic!("server terminated on recoverable accept error: {error}");
            }
        }
    }
    tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            tokio::select! {
                exited = child.wait() => panic!("server terminated on recoverable accept error: {exited:?}"),
                line = logs.next_line() => {
                    let line = line.unwrap().expect("server terminated on recoverable accept error");
                    if line.contains("accept failed; retrying") { break; }
                }
            }
        }
    }).await.expect("descriptor exhaustion did not exercise accept recovery");
    assert!(
        child.try_wait().unwrap().is_none(),
        "server terminated on recoverable accept error"
    );
    tokio::spawn(async move { while let Ok(Some(_)) = logs.next_line().await {} });
    (child, address, held)
}

#[cfg(target_os = "linux")]
fn pressure_configuration(fixture: &mut Fixture) {
    fixture.config["header_read_timeout_ms"] = serde_json::json!(60000);
    fixture.config["max_connections"] = serde_json::json!(1000);
    fixture::private_file(
        &fixture.config_file,
        &serde_json::to_vec(&fixture.config).unwrap(),
    );
}

#[cfg(target_os = "linux")]
#[tokio::test]
async fn accept_errors_recover_after_descriptor_exhaustion() {
    let mut fixture = Fixture::new();
    pressure_configuration(&mut fixture);
    let (mut child, address, held) = descriptor_pressure(&fixture).await;
    drop(held);
    let client = reqwest::Client::builder()
        .no_proxy()
        .timeout(Duration::from_secs(1))
        .build()
        .unwrap();
    let recovered = tokio::time::timeout(Duration::from_secs(6), async {
        loop {
            assert!(
                child.try_wait().unwrap().is_none(),
                "server terminated on recoverable accept error"
            );
            if let Ok(response) = client
                .get(format!(
                    "http://{address}/.well-known/oauth-protected-resource"
                ))
                .send()
                .await
            {
                if response.status() == reqwest::StatusCode::OK {
                    break;
                }
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await;
    assert!(
        recovered.is_ok(),
        "listener did not recover after descriptor release"
    );
    normal(&address).await;
    child.kill().await.unwrap();
    child.wait().await.unwrap();
}

#[cfg(target_os = "linux")]
#[tokio::test]
async fn shutdown_is_not_delayed_by_accept_backoff() {
    let mut fixture = Fixture::new();
    pressure_configuration(&mut fixture);
    let (mut child, _, held) = descriptor_pressure(&fixture).await;
    drop(held);
    let pid = child
        .id()
        .expect("owned gateway process exited before SIGTERM");
    let started = Instant::now();
    assert_eq!(
        unsafe { libc::kill(pid.try_into().unwrap(), libc::SIGTERM) },
        0
    );
    let status = tokio::time::timeout(Duration::from_millis(750), child.wait())
        .await
        .expect("shutdown delayed by accept-error backoff")
        .unwrap();
    assert!(status.success(), "gateway shutdown failed: {status}");
    eprintln!(
        "accept-backoff shutdown elapsed_ms={}",
        started.elapsed().as_millis()
    );
}
