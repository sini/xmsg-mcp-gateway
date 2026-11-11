#[allow(dead_code)]
#[path = "common/serving_fixture.rs"]
mod fixture;
#[allow(dead_code)]
#[path = "common/provider.rs"]
mod provider;

use axum::{
    body::Body,
    http::{Request, StatusCode},
};
use base64::Engine;
use fixture::{request, Fixture};
use serde_json::json;
use tower::ServiceExt;
use xmsg_mcp_gateway::{grants::Store, serving::Serving};

#[tokio::test]
async fn collection_requires_migration_and_exactly_one_configuration_form() {
    let mut fixture = Fixture::new();
    let profile = fixture.config["verifier"].clone();
    fixture.config["verifier_profiles"] = json!([profile]);
    std::fs::write(&fixture.config_file, fixture.config.to_string()).unwrap();
    assert!(Serving::from_owner_file(&fixture.config_file)
        .await
        .is_err());
    fixture.config.as_object_mut().unwrap().remove("verifier");
    std::fs::write(&fixture.config_file, fixture.config.to_string()).unwrap();
    assert!(Serving::from_owner_file(&fixture.config_file)
        .await
        .is_err());
    Store::open(&fixture.store_file)
        .unwrap()
        .migrate_profiles()
        .unwrap();
    assert!(Serving::from_owner_file(&fixture.config_file).await.is_ok());
    fixture
        .config
        .as_object_mut()
        .unwrap()
        .remove("verifier_profiles");
    std::fs::write(&fixture.config_file, fixture.config.to_string()).unwrap();
    assert!(Serving::from_owner_file(&fixture.config_file)
        .await
        .is_err());
}

async fn add_events(fixture: &mut Fixture) -> tokio::task::JoinHandle<()> {
    use std::os::unix::fs::PermissionsExt;
    use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
    let directory = fixture.keys._directory.path();
    std::fs::set_permissions(directory, std::fs::Permissions::from_mode(0o700)).unwrap();
    let socket = directory.join("register.sock");
    let listener = tokio::net::UnixListener::bind(&socket).unwrap();
    std::fs::set_permissions(&socket, std::fs::Permissions::from_mode(0o600)).unwrap();
    let key_file = directory.join("events-key");
    fixture::private_file(&key_file, &[8; 32]);
    let key = xmsg_mcp_gateway::event_store::EventKey::load(&key_file).unwrap();
    let mut store = Store::open(&fixture.store_file).unwrap();
    store.migrate_custody().unwrap();
    store.migrate_outbound().unwrap();
    store.migrate_events(&key).unwrap();
    store.migrate_retirement().unwrap();
    fixture.config["request_timeout_ms"] = json!(60000);
    fixture.config["events"] =
        json!({"grant_id":"grant", "key_file":key_file, "dispatch_timeout_ms":13000});
    fixture.config["messaging"] = json!({"xmsg":{"service":"gateway","expected_node":"bus","daemon_uid":xmsg::client::current_uid(),"register_socket":socket,"agent_socket":directory.join("unused.sock"),"operation_timeout_ms":1000},"manifest":{"reply_ttl_secs":604800,"idempotency_ttl_secs":604800,"svc_queue_cap":1000,"dedup_lifetime_secs":604800,"max_framed_bytes":65536},"result_recovery_secs":604800,"submission_timeout_ms":1000,"max_reservations":100,"max_retained_bytes":1048576});
    fixture.config["verifier_profiles"][0]["required_scopes"] =
        json!(["identity:read", "events:subscribe"]);
    fixture
        .tokens
        .lock()
        .unwrap()
        .get_mut("good-token")
        .unwrap()["scope"] = json!("identity:read events:subscribe");
    tokio::spawn(async move {
        let mut connections = tokio::task::JoinSet::new();
        loop {
            let (stream, _) = listener.accept().await.unwrap();
            connections.spawn(async move {
                let mut stream = BufReader::new(stream);
                let mut line = String::new();
                stream.read_line(&mut line).await.unwrap();
                let ready = json!({"status":"ok","address":"gateway@bus","node":"bus","reply_ttl_secs":604800,"idempotency_ttl_secs":604800,"svc_queue_cap":1000,"max_body_bytes":65536});
                stream.get_mut().write_all(format!("{ready}\n").as_bytes()).await.unwrap();
                loop {
                    line.clear();
                    if stream.read_line(&mut line).await.unwrap() == 0 { break; }
                    stream.get_mut().write_all(b"{\"action\":\"timeout\"}\n").await.unwrap();
                }
            });
        }
    })
}

#[tokio::test]
async fn one_endpoint_selects_two_profiles_and_advertises_both_issuers() {
    let mut fixture = Fixture::new();
    let mut store = Store::open(&fixture.store_file).unwrap();
    store.migrate_profiles().unwrap();
    let mut second_binding = fixture.binding.clone();
    second_binding.issuer = "https://second-issuer.example/".into();
    second_binding.subject = "second-owner".into();
    second_binding.hosted_client = "second-client".into();
    store.enroll("second", &second_binding).unwrap();
    store.set_enabled("second", 1, true).unwrap();
    let mut first = fixture.config["verifier"].clone();
    first["opaque_default"] = json!(true);
    let mut second = fixture.config["verifier"].clone();
    second["issuer"] = json!(second_binding.issuer);
    second["subject"] = json!(second_binding.subject);
    second["hosted_client"] = json!(second_binding.hosted_client);
    fixture.config.as_object_mut().unwrap().remove("verifier");
    fixture.config["verifier_profiles"] = json!([first, second]);
    let claims = {
        let mut tokens = fixture.tokens.lock().unwrap();
        let mut claims = tokens["good-token"].clone();
        claims["iss"] = json!(second_binding.issuer);
        claims["sub"] = json!(second_binding.subject);
        claims["client_id"] = json!(second_binding.hosted_client);
        let token = format!(
            "e30.{}.signature",
            base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(claims.to_string())
        );
        tokens.insert(token.clone(), claims);
        token
    };
    std::fs::write(&fixture.config_file, fixture.config.to_string()).unwrap();
    let bus = add_events(&mut fixture).await;
    std::fs::write(&fixture.config_file, fixture.config.to_string()).unwrap();
    let serving = Serving::from_owner_file(&fixture.config_file)
        .await
        .unwrap();
    for (token, owner) in [("good-token", "owner"), (claims.as_str(), "second-owner")] {
        let (status, body, _) = request(&serving, token, Fixture::call()).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["result"]["structuredContent"]["subject"], owner);
        assert_eq!(
            body["result"]["structuredContent"]
                .get("events_status")
                .is_some(),
            owner == "owner"
        );
    }
    for (token, selected) in [("good-token", true), (claims.as_str(), false)] {
        let (status, body, _) = request(
            &serving,
            token,
            json!({"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}}),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        for tool in body["result"]["tools"].as_array().unwrap() {
            assert_eq!(
                tool["securitySchemes"][0]["scopes"],
                if selected {
                    json!(["identity:read", "events:subscribe"])
                } else {
                    json!(["identity:read"])
                },
                "tool catalog borrowed another profile's scopes"
            );
        }
        let names: Vec<_> = body["result"]["tools"]
            .as_array()
            .unwrap()
            .iter()
            .filter_map(|tool| tool["name"].as_str())
            .collect();
        assert_eq!(names.contains(&"xmsg_inbox"), selected);
        assert_eq!(names.contains(&"xmsg_read_message"), selected);
        let (status, _, _) = request(&serving, token, json!({"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"xmsg_inbox","arguments":{}}})).await;
        assert_eq!(
            status,
            if selected {
                StatusCode::OK
            } else {
                StatusCode::FORBIDDEN
            }
        );
    }
    let (status, _, _) = request(&serving, claims.as_str(), json!({"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"xmsg_read_message","arguments":{"message_id":"absent"}}})).await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    let response = serving
        .router()
        .oneshot(
            Request::builder()
                .uri("/.well-known/oauth-protected-resource")
                .header("host", "gateway.example")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let body = axum::body::to_bytes(response.into_body(), 65536)
        .await
        .unwrap();
    let metadata: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(
        metadata["authorization_servers"],
        json!([fixture.binding.issuer, second_binding.issuer])
    );
    assert_eq!(metadata["resource"], fixture.binding.resource);
    bus.abort();
}
