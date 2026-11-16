#[allow(dead_code)]
#[path = "common/serving_fixture.rs"]
mod fixture;
#[allow(dead_code)]
#[path = "common/provider.rs"]
mod provider;

use axum::body::{to_bytes, Body};
use axum::http::{HeaderMap, Request, StatusCode};
use fixture::Fixture;
use serde_json::{json, Value};
use tower::ServiceExt;
use xmsg_mcp_gateway::{grants::Store, serving::Serving};

async fn post(
    serving: &Serving,
    token: Option<&str>,
    version: Option<&str>,
    body: Value,
) -> (StatusCode, HeaderMap, Value) {
    let mut request = Request::builder()
        .method("POST")
        .uri("/mcp")
        .header("host", "gateway.example")
        .header("content-type", "application/json");
    if let Some(token) = token {
        request = request.header("authorization", format!("Bearer {token}"));
    }
    if let Some(version) = version {
        request = request.header("mcp-protocol-version", version);
    }
    let response = serving
        .router()
        .oneshot(request.body(Body::from(body.to_string())).unwrap())
        .await
        .unwrap();
    let status = response.status();
    let headers = response.headers().clone();
    let bytes = to_bytes(response.into_body(), 100_000).await.unwrap();
    (
        status,
        headers,
        if bytes.is_empty() {
            Value::Null
        } else {
            serde_json::from_slice(&bytes).unwrap()
        },
    )
}
fn discover() -> Value {
    json!({"jsonrpc":"2.0","id":"bootstrap","method":"server/discover"})
}

#[tokio::test]
async fn discovery_preserves_legacy_fallback_answers() {
    let fixture = Fixture::new();
    let serving = fixture.serving().await;
    for version in [Some("2026-07-28"), None, Some("2025-11-25")] {
        for params in [None, Some(json!({})), Some(json!({"_meta":{}}))] {
            let mut body = discover();
            if let Some(params) = params {
                body["params"] = params;
            }
            let (status, headers, value) = post(&serving, Some("good-token"), version, body).await;
            if version == Some("2026-07-28") {
                assert_eq!(
                    status,
                    StatusCode::BAD_REQUEST,
                    "modern discovery must preserve the fallback response"
                );
                assert_eq!(value, Value::Null, "unsupported version has an empty body");
            } else {
                assert_eq!(status, StatusCode::OK);
                assert_eq!(value["id"], "bootstrap");
                assert_eq!(value["error"]["code"], -32601);
                assert_eq!(value["error"]["message"], "Method not found");
                assert!(value.get("result").is_none());
            }
            assert!(!headers.contains_key("mcp-session-id"));
        }
    }
}

#[tokio::test]
async fn discovery_requires_the_same_bearer_and_live_grant_as_the_catalog() {
    let fixture = Fixture::new();
    let serving = fixture.serving().await;
    for token in [None, Some("invalid-token"), Some("foreign-token")] {
        for method in ["server/discover", "tools/list"] {
            let mut body = discover();
            body["method"] = json!(method);
            let (status, _, value) = post(&serving, token, Some("2026-07-28"), body).await;
            assert_eq!(status, StatusCode::UNAUTHORIZED);
            assert!(
                value.get("result").is_none(),
                "unauthorized metadata exposed: {value}"
            );
        }
    }
    Store::open(&fixture.store_file)
        .unwrap()
        .set_enabled("grant", 2, false)
        .unwrap();
    for method in ["server/discover", "tools/list"] {
        let mut body = discover();
        body["method"] = json!(method);
        let (status, _, value) = post(&serving, Some("good-token"), Some("2026-07-28"), body).await;
        assert_eq!(status, StatusCode::FORBIDDEN);
        assert!(
            value.get("result").is_none(),
            "disabled grant exposed metadata: {value}"
        );
    }
}

#[tokio::test]
async fn unknown_discovery_keeps_generic_parameter_validation() {
    let fixture = Fixture::new();
    let serving = fixture.serving().await;
    for (params, expected) in [
        (json!({"unexpected":true}), -32601),
        (json!({"_meta":"invalid"}), -32602),
    ] {
        let mut body = discover();
        body["params"] = params;
        let (status, _, value) = post(&serving, Some("good-token"), None, body).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(value["error"]["code"], expected);
        assert!(value.get("result").is_none());
    }
}

#[tokio::test]
async fn legacy_initialize_catalog_and_call_keep_their_protocol_gate() {
    let fixture = Fixture::new();
    let serving = fixture.serving().await;
    for method in [
        "tools/list",
        "tools/call",
        "ping",
        "initialize",
        "unknown-method",
    ] {
        let body = json!({"jsonrpc":"2.0","id":1,"method":method,"params":{}});
        assert_eq!(
            post(&serving, Some("good-token"), Some("2026-07-28"), body)
                .await
                .0,
            StatusCode::BAD_REQUEST
        );
    }
    let malformed = Request::builder()
        .method("POST")
        .uri("/mcp")
        .header("host", "gateway.example")
        .header("content-type", "application/json")
        .header("authorization", "Bearer good-token")
        .header(
            "mcp-protocol-version",
            axum::http::HeaderValue::from_bytes(&[0xff]).unwrap(),
        )
        .body(Body::from(discover().to_string()))
        .unwrap();
    assert_eq!(
        serving.router().oneshot(malformed).await.unwrap().status(),
        StatusCode::BAD_REQUEST,
        "malformed version header must be refused"
    );
    let init = json!({"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-11-25","capabilities":{},"clientInfo":{"name":"fixture","version":"1"}}});
    let (status, _, value) = post(&serving, Some("good-token"), Some("2025-11-25"), init).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(value["result"]["protocolVersion"], "2025-11-25");
    assert_eq!(value["result"]["capabilities"], json!({"tools":{}}));
    let body = json!({"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}});
    let (status, _, value) = post(&serving, Some("good-token"), Some("2025-11-25"), body).await;
    assert_eq!(status, StatusCode::OK);
    assert!(value["result"]["tools"].is_array());
    let (status, _, value) = post(
        &serving,
        Some("good-token"),
        Some("2025-11-25"),
        Fixture::call(),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert!(
        value.get("error").is_none(),
        "legacy tool call failed: {value}"
    );
}
