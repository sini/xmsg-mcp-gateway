#![cfg(unix)]

use std::os::unix::fs::PermissionsExt;

use serde_json::json;
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::UnixListener;
use xmsg::client::ClientError;
use xmsg_mcp_gateway::xmsg_config::XmsgConfig;

fn fixture() -> (tempfile::TempDir, XmsgConfig, UnixListener) {
    let temp = tempfile::tempdir().unwrap();
    std::fs::set_permissions(temp.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    let config = XmsgConfig {
        service: "gateway".into(),
        expected_node: "gateway.fixture".into(),
        daemon_uid: xmsg::client::current_uid(),
        register_socket: temp.path().join("register.sock"),
        agent_socket: temp.path().join("agent.sock"),
        max_frame_bytes: 4096,
        operation_timeout_ms: 2000,
    };
    let listener = UnixListener::bind(&config.register_socket).unwrap();
    std::fs::set_permissions(
        &config.register_socket,
        std::fs::Permissions::from_mode(0o600),
    )
    .unwrap();
    (temp, config, listener)
}

#[test]
fn owner_configuration_requires_node_uid_and_rejects_unknown_fields() {
    let value = json!({
        "service":"gateway", "expected_node":"gateway.fixture", "daemon_uid":123,
        "register_socket":"/private/register.sock", "agent_socket":"/private/agent.sock"
    });
    let parsed: XmsgConfig = serde_json::from_value(value.clone()).unwrap();
    assert_eq!(parsed.max_frame_bytes, 1_048_576);
    assert_eq!(parsed.operation_timeout_ms, 10_000);
    for field in ["expected_node", "daemon_uid"] {
        let mut missing = value.clone();
        missing.as_object_mut().unwrap().remove(field);
        assert!(serde_json::from_value::<XmsgConfig>(missing).is_err());
    }
    let mut extra = value;
    extra["as_agent"] = json!("other");
    assert!(serde_json::from_value::<XmsgConfig>(extra).is_err());
}

#[tokio::test]
async fn empty_identity_and_zero_bounds_fail_before_transport() {
    let (_temp, config, _listener) = fixture();
    for field in 0..4 {
        let mut invalid = config.clone();
        match field {
            0 => invalid.expected_node = " ".into(),
            1 => invalid.service.clear(),
            2 => invalid.max_frame_bytes = 0,
            _ => invalid.operation_timeout_ms = 0,
        }
        assert!(matches!(
            invalid.register().await,
            Err(ClientError::Configuration)
        ));
    }
}

#[tokio::test]
async fn registration_requires_the_configured_node_and_real_address() {
    for (expected, accepted) in [("gateway.fixture", true), ("other.fixture", false)] {
        let (_temp, mut config, listener) = fixture();
        config.expected_node = expected.into();
        let server = tokio::spawn(async move {
            let mut stream = BufReader::new(listener.accept().await.unwrap().0);
            let mut line = String::new();
            stream.read_line(&mut line).await.unwrap();
            let request: serde_json::Value = serde_json::from_str(&line).unwrap();
            assert_eq!(request["harness"], "svc");
            assert_eq!(request["name"], "gateway");
            stream.get_mut().write_all(b"{\"status\":\"ok\",\"node\":\"gateway.fixture\",\"address\":\"gateway@gateway.fixture\"}\n").await.unwrap();
            let mut closed = [0];
            assert_eq!(stream.read(&mut closed).await.unwrap(), 0);
        });
        let result = config.register().await;
        if accepted {
            let service = result.unwrap();
            assert_eq!(service.node(), Some("gateway.fixture"));
            assert_eq!(service.address(), Some("gateway@gateway.fixture"));
        } else {
            assert!(
                matches!(&result, Err(ClientError::Peer)),
                "unexpected registration error: {:?}",
                result.err()
            );
        }
        server.await.unwrap();
    }
}

#[tokio::test]
async fn configured_daemon_uid_is_preserved() {
    let (_temp, mut config, _listener) = fixture();
    config.daemon_uid += 1;
    assert!(matches!(config.register().await, Err(ClientError::Peer)));
}
