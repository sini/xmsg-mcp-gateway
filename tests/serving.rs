use xmsg_mcp_gateway::serving::Serving;

#[tokio::test]
async fn serving_requires_an_owner_configuration_file() {
    let temp = tempfile::tempdir().unwrap();
    let missing = temp.path().join("missing.json");
    assert!(Serving::from_owner_file(&missing).await.is_err());
    assert!(!missing.exists());
    let invalid = temp.path().join("invalid.json");
    std::fs::write(&invalid, r#"{"verified":true,"subject":"forged"}"#).unwrap();
    assert!(Serving::from_owner_file(&invalid).await.is_err());
}

#[allow(dead_code)]
#[path = "common/serving_fixture.rs"]
mod fixture;
#[allow(dead_code)]
#[path = "common/provider.rs"]
mod provider;

use axum::http::StatusCode;
use fixture::{request, Fixture};
use serde_json::json;
use std::sync::atomic::Ordering;
use tower::ServiceExt;

#[tokio::test]
async fn approved_token_dispatches_the_real_identity_tool() {
    let fixture = Fixture::new();
    let serving = fixture.serving().await;
    let (status, body, probe) = request(&serving, "good-token", Fixture::call()).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["result"]["structuredContent"]["subject"], "owner");
    assert_eq!(
        body["result"]["structuredContent"]["resource"],
        fixture.binding.resource
    );
    assert_eq!(probe.dispatches.load(Ordering::SeqCst), 1);
    assert_eq!(probe.opens.load(Ordering::SeqCst), 1);
    assert_eq!(fixture.requests.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn invalid_token_is_refused_before_an_unavailable_store_is_opened() {
    let fixture = Fixture::new();
    let serving = fixture.serving().await;
    std::fs::remove_file(&fixture.store_file).unwrap();
    for token in ["invalid-token", "foreign-token"] {
        let (status, _, probe) = request(&serving, token, Fixture::call()).await;
        assert_eq!(
            status,
            StatusCode::UNAUTHORIZED,
            "policy lookup preceded authentication"
        );
        assert_eq!(
            probe.opens.load(Ordering::SeqCst),
            0,
            "policy lookup preceded authentication"
        );
        assert_eq!(probe.dispatches.load(Ordering::SeqCst), 0);
    }
}

#[tokio::test]
async fn approved_token_reports_an_unavailable_store_as_retryable() {
    let fixture = Fixture::new();
    let serving = fixture.serving().await;
    std::fs::remove_file(&fixture.store_file).unwrap();
    let (status, _, probe) = request(&serving, "good-token", Fixture::call()).await;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(probe.opens.load(Ordering::SeqCst), 1);
    assert_eq!(probe.dispatches.load(Ordering::SeqCst), 0);
    assert!(!fixture.store_file.exists());
}

#[tokio::test]
async fn caller_identity_fields_cannot_override_verified_identity() {
    let fixture = Fixture::new();
    let serving = fixture.serving().await;
    let (status, baseline, positive) = request(&serving, "good-token", Fixture::call()).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(positive.opens.load(Ordering::SeqCst), 1);
    assert_eq!(positive.dispatches.load(Ordering::SeqCst), 1);
    let expected = baseline["result"]["structuredContent"].clone();
    assert_eq!(expected["service"], "gateway");
    assert_eq!(expected["subject"], "owner");
    assert_eq!(expected["issuer"], fixture.binding.issuer);
    assert_eq!(expected["resource"], fixture.binding.resource);
    assert_eq!(expected["hosted_client"], fixture.binding.hosted_client);
    assert_eq!(expected["grant_revision"], 2);

    // Oracle 1: a benign nested `subject` key is accepted (where the removed blacklist returned 403).
    let mut benign_meta = Fixture::call();
    benign_meta["params"]["_meta"] = json!({"context": {"subject": "benign-topic"}});
    let (status, response, probe) = request(&serving, "good-token", benign_meta).await;
    assert_eq!(
        status,
        StatusCode::OK,
        "benign nested subject key was refused"
    );
    assert_eq!(
        response["result"]["structuredContent"], expected,
        "caller identity data overrode verified identity"
    );
    assert_eq!(probe.opens.load(Ordering::SeqCst), 1);
    assert_eq!(probe.dispatches.load(Ordering::SeqCst), 1);

    let init_with_nested_subject = json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "initialize",
        "params": {
            "protocolVersion": "2025-11-25",
            "capabilities": {"experimental": {"subject": "benign-capability"}},
            "clientInfo": {"name": "fixture", "version": "1"},
            "_meta": {"trace": {"subject": "benign-trace"}}
        }
    });
    let (status, response, _) = request(&serving, "good-token", init_with_nested_subject).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(response["result"]["protocolVersion"], "2025-11-25");

    // Oracle 2: request JSON carrying identity/claim keys (top-level, nested, _meta) never changes
    // VerifiedIdentity, the grant, or the owner a call runs as, while strict tool/RPC schemas hold.
    let identity_keys = [
        "subject",
        "issuer",
        "hosted_client",
        "resource",
        "verified",
        "active",
        "iss",
        "sub",
        "aud",
        "client_id",
    ];
    let forged_value = |field: &str| {
        if field == "verified" || field == "active" {
            json!(true)
        } else {
            json!("forged")
        }
    };

    for field in identity_keys {
        let value = forged_value(field);
        for meta in [
            json!({field: value.clone()}),
            json!({"nested": {field: value.clone()}, "items": [{field: value.clone()}]}),
        ] {
            let mut body = Fixture::call();
            body["params"]["_meta"] = meta;
            let (status, response, probe) = request(&serving, "good-token", body).await;
            assert_eq!(
                status,
                StatusCode::OK,
                "metadata key {field} caused HTTP refusal"
            );
            assert_eq!(
                response["result"]["structuredContent"], expected,
                "caller identity data overrode verified identity: {field} in _meta"
            );
            assert_eq!(probe.opens.load(Ordering::SeqCst), 1);
            assert_eq!(probe.dispatches.load(Ordering::SeqCst), 1);
        }

        for arguments in [
            json!({field: value.clone()}),
            json!({"nested": {field: value.clone()}}),
        ] {
            let mut body = Fixture::call();
            body["params"]["arguments"] = arguments;
            let (status, response, probe) = request(&serving, "good-token", body).await;
            assert_eq!(status, StatusCode::OK);
            assert_eq!(
                response["error"]["code"], -32602,
                "unknown tool argument {field} was not rejected as invalid params"
            );
            assert!(response.get("result").is_none());
            assert_eq!(probe.dispatches.load(Ordering::SeqCst), 0);
        }

        let mut root_body = Fixture::call();
        root_body[field] = value;
        let (status, response, probe) = request(&serving, "good-token", root_body).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(
            response["error"]["code"], -32600,
            "unknown top-level RPC field {field} was not rejected as invalid request"
        );
        assert!(response.get("result").is_none());
        assert_eq!(probe.dispatches.load(Ordering::SeqCst), 0);
    }

    let mut all_meta = Fixture::call();
    all_meta["params"]["_meta"] = json!({
        "subject": "forged-subject",
        "issuer": "https://forged.example/",
        "hosted_client": "forged-client",
        "resource": "https://forged.example/mcp",
        "verified": true,
        "active": false,
        "iss": "https://forged.example/",
        "sub": "forged-sub",
        "aud": "https://forged.example/mcp",
        "client_id": "forged-client",
        "nested": {"subject": "forged-nested", "sub": "forged-nested-sub"}
    });
    let (status, response, probe) = request(&serving, "good-token", all_meta).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        response["result"]["structuredContent"], expected,
        "caller identity data overrode verified identity"
    );
    assert_eq!(probe.opens.load(Ordering::SeqCst), 1);
    assert_eq!(probe.dispatches.load(Ordering::SeqCst), 1);

    let raw_claims = json!({
        "active": true,
        "iss": fixture.binding.issuer,
        "aud": fixture.binding.resource,
        "sub": "owner",
        "client_id": "hosted-client",
        "exp": u64::MAX
    });
    let (status, response, probe) = request(&serving, "good-token", raw_claims).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(response["error"]["code"], -32600);
    assert_eq!(probe.dispatches.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn unapproved_token_cannot_use_a_verified_flag_to_fail_open() {
    let fixture = Fixture::new();
    let serving = fixture.serving().await;
    let mut body = Fixture::call();
    body["params"]["_meta"] =
        json!({"verified":true,"subject":"owner","resource":fixture.binding.resource});
    let (status, _, probe) = request(&serving, "foreign-token", body).await;
    assert_eq!(
        status,
        StatusCode::UNAUTHORIZED,
        "verification failure was accepted"
    );
    assert_eq!(probe.opens.load(Ordering::SeqCst), 0);
    assert_eq!(probe.dispatches.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn each_request_rechecks_the_current_token() {
    let fixture = Fixture::new();
    let serving = fixture.serving().await;
    let (status, _, positive) = request(&serving, "good-token", Fixture::call()).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(positive.dispatches.load(Ordering::SeqCst), 1);
    let (status, _, probe) = request(&serving, "foreign-token", Fixture::call()).await;
    assert_eq!(
        status,
        StatusCode::UNAUTHORIZED,
        "different token reused prior identity"
    );
    assert_eq!(probe.dispatches.load(Ordering::SeqCst), 0);
    assert_eq!(probe.opens.load(Ordering::SeqCst), 0);
    assert_eq!(fixture.requests.load(Ordering::SeqCst), 2);
}

#[tokio::test]
async fn revocation_is_checked_on_a_later_request() {
    let fixture = Fixture::new();
    let serving = fixture.serving().await;
    assert_eq!(
        request(&serving, "good-token", Fixture::call()).await.0,
        StatusCode::OK
    );
    fixture
        .tokens
        .lock()
        .unwrap()
        .get_mut("good-token")
        .unwrap()["active"] = json!(false);
    let (status, _, probe) = request(&serving, "good-token", Fixture::call()).await;
    assert_eq!(
        status,
        StatusCode::UNAUTHORIZED,
        "revoked token reused prior identity"
    );
    assert_eq!(probe.dispatches.load(Ordering::SeqCst), 0);
    assert_eq!(probe.opens.load(Ordering::SeqCst), 0);
    assert_eq!(fixture.requests.load(Ordering::SeqCst), 2);
}

#[tokio::test]
async fn grant_is_rechecked_after_discovery() {
    let fixture = Fixture::new();
    let serving = fixture.serving().await;
    let list = json!({"jsonrpc":"2.0","id":1,"method":"tools/list","params":{}});
    let (status, body, _) = request(&serving, "good-token", list).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["result"]["tools"][0]["name"], "xmsg_identity");
    xmsg_mcp_gateway::grants::Store::open(&fixture.store_file)
        .unwrap()
        .set_enabled("grant", 2, false)
        .unwrap();
    let (status, _, probe) = request(&serving, "good-token", Fixture::call()).await;
    assert_eq!(status, StatusCode::FORBIDDEN, "disabled grant was accepted");
    assert_eq!(probe.opens.load(Ordering::SeqCst), 1);
    assert_eq!(probe.dispatches.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn request_data_cannot_select_a_different_owner_file() {
    let owner = Fixture::new();
    let other = Fixture::new();
    other
        .tokens
        .lock()
        .unwrap()
        .insert("foreign-token".into(), provider::claims(&other.binding));
    let serving = owner.serving().await;
    let mut body = Fixture::call();
    body["params"]["_meta"] = json!({"config_file":other.config_file});
    let (status, _, probe) = request(&serving, "foreign-token", body).await;
    assert_eq!(
        status,
        StatusCode::UNAUTHORIZED,
        "request selected a different owner config"
    );
    assert_eq!(probe.dispatches.load(Ordering::SeqCst), 0);
    assert_eq!(owner.requests.load(Ordering::SeqCst), 1);
    assert_eq!(other.requests.load(Ordering::SeqCst), 0);
    let (status, _, _) = request(&other.serving().await, "foreign-token", Fixture::call()).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(other.requests.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn protocol_metadata_and_unavailable_operations_are_honest() {
    let fixture = Fixture::new();
    let serving = fixture.serving().await;
    for version in ["2025-03-26", "2025-06-18", "2025-11-25", "unsupported"] {
        let body = json!({"jsonrpc":"2.0","id":1,"method":"initialize","params":{
            "protocolVersion":version,"capabilities":{},"clientInfo":{"name":"fixture","version":"1"},
            "_meta":{"progressToken":42}}});
        let (_, response, _) = request(&serving, "good-token", body).await;
        assert_eq!(
            response["result"]["protocolVersion"],
            if version == "unsupported" {
                "2025-11-25"
            } else {
                version
            }
        );
        assert!(response["result"]["capabilities"].get("events").is_none());
    }
    let mut body = Fixture::call();
    body["params"]["_meta"] = json!({"progressToken":"fixture-progress", "vendor":{"opaque":true}});
    let (status, response, probe) = request(&serving, "good-token", body.clone()).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(response["result"]["isError"], false);
    assert_eq!(probe.dispatches.load(Ordering::SeqCst), 1);
    let mut array_arguments = Fixture::call();
    array_arguments["params"]["arguments"] = json!([]);
    let (_, invalid, probe) = request(&serving, "good-token", array_arguments).await;
    assert_eq!(invalid["error"]["code"], -32602);
    assert_eq!(probe.dispatches.load(Ordering::SeqCst), 0);
    body["params"]["_meta"]["progressToken"] = json!(true);
    let (_, response, probe) = request(&serving, "good-token", body).await;
    assert_eq!(response["error"]["code"], -32602);
    assert_eq!(probe.dispatches.load(Ordering::SeqCst), 0);
    let (_, response, probe) = request(
        &serving,
        "good-token",
        json!({"jsonrpc":"2.0","id":1,"method":"events/list","params":{}}),
    )
    .await;
    assert_eq!(response["error"]["message"], "Events not yet available");
    assert!(response.get("result").is_none());
    assert_eq!(probe.dispatches.load(Ordering::SeqCst), 0);
    let mut body = Fixture::call();
    body["params"]["name"] = json!("xmsg_send");
    let (_, response, probe) = request(&serving, "good-token", body).await;
    assert_eq!(response["error"]["message"], "Tool not yet available");
    assert!(response.get("result").is_none());
    assert_eq!(probe.dispatches.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn resource_metadata_is_public_without_credentials_or_policy_io() {
    use axum::body::Body;
    use axum::http::Request;
    let fixture = Fixture::new();
    let serving = fixture.serving().await;
    for uri in [
        "/.well-known/oauth-protected-resource",
        "/.well-known/oauth-protected-resource/mcp",
        "/mcp/.well-known/oauth-protected-resource",
    ] {
        let request = Request::builder()
            .uri(uri)
            .header("host", "gateway.example")
            .body(Body::empty())
            .unwrap();
        let (status, metadata, probe) = fixture::raw_request(&serving, request).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(metadata["resource"], fixture.binding.resource);
        assert_eq!(
            metadata["authorization_servers"],
            json!([fixture.binding.issuer])
        );
        assert!(metadata.get("subject").is_none());
        assert_eq!(probe.opens.load(Ordering::SeqCst), 0);
        assert_eq!(probe.dispatches.load(Ordering::SeqCst), 0);
    }
    assert_eq!(fixture.requests.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn incomplete_or_exposed_serving_profiles_are_refused() {
    let mut fixture = Fixture::new();
    let _positive = fixture.serving().await;
    for (field, value) in [
        ("bind", json!("0.0.0.0:8080")),
        ("request_timeout_ms", json!(0)),
        ("allowed_hosts", json!([])),
    ] {
        let mut invalid = fixture.config.clone();
        invalid[field] = value;
        fixture::private_file(&fixture.config_file, &serde_json::to_vec(&invalid).unwrap());
        assert!(
            Serving::from_owner_file(&fixture.config_file)
                .await
                .is_err(),
            "unsafe serving profile accepted: {field}"
        );
    }
    fixture.config["grant_store"] = json!(fixture.keys._directory.path().join("missing.db"));
    fixture::private_file(
        &fixture.config_file,
        &serde_json::to_vec(&fixture.config).unwrap(),
    );
    assert!(Serving::from_owner_file(&fixture.config_file)
        .await
        .is_err());
    assert!(!fixture.keys._directory.path().join("missing.db").exists());
}

#[tokio::test]
async fn non_loopback_bind_requires_explicit_opt_in() {
    let mut fixture = Fixture::new();
    for bind in ["0.0.0.0:0", "[::]:0"] {
        fixture.config["bind"] = json!(bind);
        for flag in [None, Some(json!(false)), Some(json!(true))] {
            fixture
                .config
                .as_object_mut()
                .unwrap()
                .remove("allow_non_loopback_bind");
            if let Some(value) = &flag {
                fixture.config["allow_non_loopback_bind"] = value.clone();
            }
            fixture::private_file(
                &fixture.config_file,
                &serde_json::to_vec(&fixture.config).unwrap(),
            );
            assert_eq!(
                Serving::from_owner_file(&fixture.config_file).await.is_ok(),
                flag == Some(json!(true)),
                "non-loopback bind must require explicit opt-in: {bind} {flag:?}"
            );
        }
    }
}

#[tokio::test]
async fn opt_in_cli_listener_preserves_auth_grants_body_and_public_resource() {
    use std::process::Stdio;
    use tokio::io::{AsyncBufReadExt, BufReader};
    let mut fixture = Fixture::new();
    fixture.config["bind"] = json!("0.0.0.0:0");
    fixture.config["allow_non_loopback_bind"] = json!(true);
    fixture.config["max_request_body_bytes"] = json!(65536);
    fixture::private_file(
        &fixture.config_file,
        &serde_json::to_vec(&fixture.config).unwrap(),
    );
    let mut wrong_audience = provider::claims(&fixture.binding);
    wrong_audience["aud"] = json!("https://foreign.example/mcp");
    fixture
        .tokens
        .lock()
        .unwrap()
        .insert("wrong-audience".into(), wrong_audience);
    let mut child = tokio::process::Command::new(env!("CARGO_BIN_EXE_xmsg-mcp-gateway"))
        .arg("serve")
        .arg("--config")
        .arg(&fixture.config_file)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true)
        .spawn()
        .unwrap();
    let mut lines = BufReader::new(child.stdout.take().unwrap()).lines();
    let ready = tokio::time::timeout(std::time::Duration::from_secs(5), lines.next_line())
        .await
        .unwrap()
        .unwrap()
        .expect("opt-in non-loopback listener did not start");
    let address: std::net::SocketAddr = ready
        .strip_prefix("serving MCP at ")
        .unwrap()
        .parse()
        .unwrap();
    assert!(
        address.ip().is_unspecified(),
        "listener did not bind wildcard"
    );
    let base = format!("http://127.0.0.1:{}", address.port());
    let client = reqwest::Client::builder()
        // Early 413 closes must not race the next authorization assertion.
        .pool_max_idle_per_host(0)
        .no_proxy()
        .timeout(std::time::Duration::from_secs(3))
        .build()
        .unwrap();
    let response = client
        .post(format!("{base}/mcp"))
        .header("host", "gateway.example")
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), reqwest::StatusCode::UNAUTHORIZED);
    assert_eq!(response.headers()["www-authenticate"],
        "Bearer resource_metadata=\"https://gateway.example/mcp/.well-known/oauth-protected-resource\"");
    for path in [
        "/.well-known/oauth-protected-resource",
        "/.well-known/oauth-protected-resource/mcp",
        "/mcp/.well-known/oauth-protected-resource",
    ] {
        let response = client
            .get(format!("{base}{path}"))
            .header("host", "gateway.example")
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), reqwest::StatusCode::OK);
        let body: serde_json::Value =
            serde_json::from_slice(&response.bytes().await.unwrap()).unwrap();
        assert_eq!(body["resource"], fixture.binding.resource);
        assert_eq!(
            body["authorization_servers"],
            json!([fixture.binding.issuer])
        );
    }
    for (token, body, expected) in [
        (
            "good-token",
            Fixture::call().to_string(),
            reqwest::StatusCode::OK,
        ),
        (
            "wrong-audience",
            Fixture::call().to_string(),
            reqwest::StatusCode::UNAUTHORIZED,
        ),
        (
            "good-token",
            " ".repeat(65537),
            reqwest::StatusCode::PAYLOAD_TOO_LARGE,
        ),
    ] {
        let response = client
            .post(format!("{base}/mcp"))
            .header("host", "gateway.example")
            .bearer_auth(token)
            .header("content-type", "application/json")
            .body(body)
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), expected);
        if expected == reqwest::StatusCode::OK {
            let body: serde_json::Value =
                serde_json::from_slice(&response.bytes().await.unwrap()).unwrap();
            assert_eq!(
                body["result"]["structuredContent"]["resource"],
                fixture.binding.resource
            );
        }
    }
    xmsg_mcp_gateway::grants::Store::open(&fixture.store_file)
        .unwrap()
        .set_enabled("grant", 2, false)
        .unwrap();
    let response = client
        .post(format!("{base}/mcp"))
        .header("host", "gateway.example")
        .bearer_auth("good-token")
        .header("content-type", "application/json")
        .body(Fixture::call().to_string())
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), reqwest::StatusCode::FORBIDDEN);
    child.kill().await.unwrap();
    child.wait().await.unwrap();
}

#[tokio::test]
async fn unavailable_provider_is_retryable_and_never_opens_the_store() {
    let mut fixture = Fixture::new();
    let serving = fixture.serving().await;
    assert_eq!(
        request(&serving, "good-token", Fixture::call()).await.0,
        StatusCode::OK
    );
    fixture.stop_provider();
    let (status, _, probe) = request(&serving, "good-token", Fixture::call()).await;
    assert_eq!(
        status,
        StatusCode::SERVICE_UNAVAILABLE,
        "provider outage was misclassified"
    );
    assert_eq!(probe.opens.load(Ordering::SeqCst), 0);
    assert_eq!(probe.dispatches.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn body_read_is_bounded_before_any_credential_or_policy_io() {
    use axum::body::{Body, Bytes};
    use axum::http::Request;
    let mut fixture = Fixture::new();
    fixture.config["request_timeout_ms"] = json!(100);
    fixture::private_file(
        &fixture.config_file,
        &serde_json::to_vec(&fixture.config).unwrap(),
    );
    let serving = fixture.serving().await;
    let pending = futures_util::stream::pending::<Result<Bytes, std::io::Error>>();
    let input = Request::builder()
        .method("POST")
        .uri("/mcp")
        .header("host", "gateway.example")
        .header("authorization", "Bearer good-token")
        .header("content-type", "application/json")
        .body(Body::from_stream(pending))
        .unwrap();
    let response = tokio::time::timeout(
        std::time::Duration::from_millis(800),
        fixture::raw_request(&serving, input),
    )
    .await;
    assert!(response.is_ok(), "request body deadline was not enforced");
    let (status, _, probe) = response.unwrap();
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(probe.opens.load(Ordering::SeqCst), 0);
    assert_eq!(probe.dispatches.load(Ordering::SeqCst), 0);
    assert_eq!(fixture.requests.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn http_host_origin_body_and_method_guards_hold() {
    use axum::body::Body;
    use axum::http::Request;
    let mut fixture = Fixture::new();
    fixture.config["max_request_body_bytes"] = json!(65536);
    fixture::private_file(
        &fixture.config_file,
        &serde_json::to_vec(&fixture.config).unwrap(),
    );
    let serving = fixture.serving().await;
    for (host, origin) in [
        ("foreign.example", None),
        ("gateway.example", Some("https://foreign.example")),
    ] {
        let mut input = Request::builder()
            .method("POST")
            .uri("/mcp")
            .header("host", host)
            .header("authorization", "Bearer good-token")
            .header("content-type", "application/json");
        if let Some(origin) = origin {
            input = input.header("origin", origin);
        }
        let (status, _, probe) = fixture::raw_request(
            &serving,
            input.body(Body::from(Fixture::call().to_string())).unwrap(),
        )
        .await;
        assert_eq!(
            status,
            StatusCode::FORBIDDEN,
            "untrusted HTTP authority was accepted"
        );
        assert_eq!(probe.opens.load(Ordering::SeqCst), 0);
        assert_eq!(probe.dispatches.load(Ordering::SeqCst), 0);
    }
    let missing = Request::builder()
        .uri("/mcp")
        .header("host", "gateway.example")
        .body(Body::empty())
        .unwrap();
    let response = serving.router().oneshot(missing).await.unwrap();
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(response.headers()["www-authenticate"], "Bearer resource_metadata=\"https://gateway.example/mcp/.well-known/oauth-protected-resource\"");
    let get = Request::builder()
        .uri("/mcp")
        .header("host", "gateway.example")
        .header("authorization", "Bearer good-token")
        .body(Body::empty())
        .unwrap();
    let response = serving.router().oneshot(get).await.unwrap();
    assert_eq!(response.status(), StatusCode::METHOD_NOT_ALLOWED);
    assert_eq!(response.headers()["allow"], "POST");
    let oversized = Request::builder()
        .method("POST")
        .uri("/mcp")
        .header("host", "gateway.example")
        .header("authorization", "Bearer good-token")
        .header("content-type", "application/json")
        .body(Body::from(format!(
            "{}{}",
            " ".repeat(65_537),
            Fixture::call()
        )))
        .unwrap();
    let (status, _, probe) = fixture::raw_request(&serving, oversized).await;
    assert_eq!(
        status,
        StatusCode::PAYLOAD_TOO_LARGE,
        "oversized MCP request was accepted"
    );
    assert_eq!(probe.dispatches.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn owner_file_permissions_and_unknown_fields_are_checked() {
    let fixture = Fixture::new();
    let _positive = fixture.serving().await;
    let mut invalid = fixture.config.clone();
    invalid["verified"] = json!(true);
    fixture::private_file(&fixture.config_file, &serde_json::to_vec(&invalid).unwrap());
    assert!(
        Serving::from_owner_file(&fixture.config_file)
            .await
            .is_err(),
        "unknown owner config fields accepted"
    );
    fixture::private_file(
        &fixture.config_file,
        &serde_json::to_vec(&fixture.config).unwrap(),
    );
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&fixture.config_file, std::fs::Permissions::from_mode(0o444))
            .unwrap();
        assert!(
            Serving::from_owner_file(&fixture.config_file).await.is_ok(),
            "read-only 0444 owner configuration refused"
        );
        std::fs::set_permissions(&fixture.keys.secret, std::fs::Permissions::from_mode(0o444))
            .unwrap();
        assert!(
            Serving::from_owner_file(&fixture.config_file)
                .await
                .is_err(),
            "group/world-readable credential file accepted"
        );
        std::fs::set_permissions(&fixture.keys.secret, std::fs::Permissions::from_mode(0o600))
            .unwrap();
        for mode in [0o664, 0o666] {
            std::fs::set_permissions(&fixture.config_file, std::fs::Permissions::from_mode(mode))
                .unwrap();
            assert!(
                Serving::from_owner_file(&fixture.config_file)
                    .await
                    .is_err(),
                "public owner configuration accepted"
            );
        }
        std::fs::set_permissions(&fixture.config_file, std::fs::Permissions::from_mode(0o600))
            .unwrap();
    }
    let mut oversized = serde_json::to_vec(&fixture.config).unwrap();
    oversized.resize(65_537, b' ');
    fixture::private_file(&fixture.config_file, &oversized);
    assert!(
        Serving::from_owner_file(&fixture.config_file)
            .await
            .is_err(),
        "oversized owner configuration accepted"
    );
}

#[tokio::test]
async fn actual_cli_serves_only_the_owner_file_profile() {
    use std::process::Stdio;
    use tokio::io::{AsyncBufReadExt, BufReader};
    let fixture = Fixture::new();
    let rejected = tokio::process::Command::new(env!("CARGO_BIN_EXE_xmsg-mcp-gateway"))
        .arg("--state")
        .arg(&fixture.store_file)
        .arg("serve")
        .arg("--config")
        .arg(&fixture.config_file)
        .output()
        .await
        .unwrap();
    assert!(
        !rejected.status.success(),
        "CLI state override bypassed owner profile"
    );
    let mut child = tokio::process::Command::new(env!("CARGO_BIN_EXE_xmsg-mcp-gateway"))
        .arg("serve")
        .arg("--config")
        .arg(&fixture.config_file)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true)
        .spawn()
        .unwrap();
    let mut lines = BufReader::new(child.stdout.take().unwrap()).lines();
    let ready = tokio::time::timeout(std::time::Duration::from_secs(5), lines.next_line())
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    let address = ready.strip_prefix("serving MCP at ").unwrap();
    let response = reqwest::Client::builder()
        .no_proxy()
        .timeout(std::time::Duration::from_secs(3))
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
    let body: serde_json::Value = serde_json::from_slice(&response.bytes().await.unwrap()).unwrap();
    assert_eq!(body["result"]["structuredContent"]["subject"], "owner");
    child.kill().await.unwrap();
    child.wait().await.unwrap();
}

#[tokio::test]
async fn state_cannot_be_reused_for_another_service_resource_or_owner() {
    let fixture = Fixture::new();
    let _positive = fixture.serving().await;
    for field in ["service", "issuer", "resource", "subject"] {
        let mut other = fixture.config.clone();
        other["verifier"][field] = if field == "issuer" || field == "resource" {
            json!("https://foreign.example/")
        } else {
            json!("other")
        };
        fixture::private_file(&fixture.config_file, &serde_json::to_vec(&other).unwrap());
        assert!(
            Serving::from_owner_file(&fixture.config_file)
                .await
                .is_err(),
            "foreign authority profile was accepted: {field}"
        );
    }
    fixture::private_file(
        &fixture.config_file,
        &serde_json::to_vec(&fixture.config).unwrap(),
    );
    let mut mixed = fixture.binding.clone();
    mixed.subject = "different-owner".into();
    xmsg_mcp_gateway::grants::Store::open(&fixture.store_file)
        .unwrap()
        .enroll("mixed-profile", &mixed)
        .unwrap();
    assert!(
        Serving::from_owner_file(&fixture.config_file)
            .await
            .is_err(),
        "mixed authority profile was accepted"
    );
}

#[tokio::test]
async fn token_expiry_during_policy_wait_prevents_dispatch() {
    use axum::body::Body;
    use axum::http::Request;
    use std::time::{Duration, SystemTime, UNIX_EPOCH};
    use tracing::instrument::WithSubscriber;
    let fixture = Fixture::new();
    let serving = fixture.serving().await;
    let expires = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
        + 3;
    fixture
        .tokens
        .lock()
        .unwrap()
        .get_mut("good-token")
        .unwrap()["exp"] = json!(expires);
    let lock = rusqlite::Connection::open(&fixture.store_file).unwrap();
    lock.execute_batch("BEGIN EXCLUSIVE").unwrap();
    let probe = fixture::Probe::default();
    let input = Request::builder()
        .method("POST")
        .uri("/mcp")
        .header("host", "gateway.example")
        .header("content-type", "application/json")
        .header("authorization", "Bearer good-token")
        .body(Body::from(Fixture::call().to_string()))
        .unwrap();
    let pending = tokio::spawn(
        serving
            .router()
            .oneshot(input)
            .with_subscriber(probe.clone()),
    );
    tokio::time::timeout(Duration::from_secs(2), async {
        while probe.opens.load(Ordering::SeqCst) == 0 {
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await
    .unwrap();
    assert_eq!(fixture.requests.load(Ordering::SeqCst), 1);
    tokio::time::timeout(Duration::from_secs(4), async {
        while SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs()
            < expires
        {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .unwrap();
    lock.execute_batch("COMMIT").unwrap();
    let response = tokio::time::timeout(Duration::from_secs(3), pending)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    assert_eq!(
        response.status(),
        StatusCode::UNAUTHORIZED,
        "expired token reached dispatch"
    );
    assert_eq!(probe.opens.load(Ordering::SeqCst), 1);
    assert_eq!(probe.dispatches.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn relative_paths_belong_to_the_owner_configuration_directory() {
    let mut fixture = Fixture::new();
    fixture.config["grant_store"] = json!("grants.db");
    fixture.config["verifier"]["client_secret_file"] = json!("secret");
    fixture.config["verifier"]["root_certificate_file"] = json!("root.pem");
    fixture::private_file(
        &fixture.config_file,
        &serde_json::to_vec(&fixture.config).unwrap(),
    );
    let serving = Serving::from_owner_file(&fixture.config_file).await;
    assert!(
        serving.is_ok(),
        "relative path resolved outside owner configuration directory"
    );
    assert_eq!(
        request(&serving.unwrap(), "good-token", Fixture::call())
            .await
            .0,
        StatusCode::OK
    );
}
