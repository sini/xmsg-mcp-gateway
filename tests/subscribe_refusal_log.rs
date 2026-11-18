#![cfg(unix)]
#[allow(dead_code)]
#[path = "common/serving_fixture.rs"]
mod fixture;
#[allow(dead_code)]
#[path = "common/provider.rs"]
mod provider;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use base64::Engine;
use serde_json::{json, Value};
use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};
use tower::ServiceExt;
use tracing::field::{Field, Visit};
use tracing::instrument::WithSubscriber;
use tracing::{Event, Metadata, Subscriber};
use xmsg_mcp_gateway::auth::{Verifier, VerifierConfig};
use xmsg_mcp_gateway::event_store::EventKey;
use xmsg_mcp_gateway::events::{Events, Subscribe, EVENT_NAME};
use xmsg_mcp_gateway::grants::Store;
use xmsg_mcp_gateway::webhook::{self, Transport};

#[derive(Clone, Debug)]
struct CapturedEvent {
    target: String,
    fields: BTreeMap<String, String>,
}

#[derive(Default)]
struct FieldVisitor(BTreeMap<String, String>);

impl Visit for FieldVisitor {
    fn record_i64(&mut self, field: &Field, value: i64) {
        self.0.insert(field.name().to_string(), value.to_string());
    }
    fn record_u64(&mut self, field: &Field, value: u64) {
        self.0.insert(field.name().to_string(), value.to_string());
    }
    fn record_bool(&mut self, field: &Field, value: bool) {
        self.0.insert(field.name().to_string(), value.to_string());
    }
    fn record_str(&mut self, field: &Field, value: &str) {
        self.0.insert(field.name().to_string(), value.to_string());
    }
    fn record_debug(&mut self, field: &Field, value: &dyn std::fmt::Debug) {
        self.0
            .insert(field.name().to_string(), format!("{value:?}"));
    }
}

#[derive(Clone, Default)]
struct LogCapture {
    events: Arc<Mutex<Vec<CapturedEvent>>>,
}

impl LogCapture {
    fn take(&self) -> Vec<CapturedEvent> {
        std::mem::take(&mut *self.events.lock().unwrap())
    }
}

impl Subscriber for LogCapture {
    fn enabled(&self, metadata: &Metadata<'_>) -> bool {
        metadata.level() <= &tracing::Level::INFO
    }
    fn new_span(&self, _: &tracing::span::Attributes<'_>) -> tracing::span::Id {
        tracing::span::Id::from_u64(1)
    }
    fn record(&self, _: &tracing::span::Id, _: &tracing::span::Record<'_>) {}
    fn record_follows_from(&self, _: &tracing::span::Id, _: &tracing::span::Id) {}
    fn event(&self, event: &Event<'_>) {
        let mut visitor = FieldVisitor::default();
        event.record(&mut visitor);
        self.events.lock().unwrap().push(CapturedEvent {
            target: event.metadata().target().to_string(),
            fields: visitor.0,
        });
    }
    fn enter(&self, _: &tracing::span::Id) {}
    fn exit(&self, _: &tracing::span::Id) {}
}

fn signing_key() -> String {
    format!(
        "whsec_{}",
        base64::engine::general_purpose::STANDARD.encode([4; 32])
    )
}

struct GoodCallback;
impl Transport for GoodCallback {
    fn post<'a>(
        &'a self,
        _url: &'a str,
        headers: reqwest::header::HeaderMap,
        body: Vec<u8>,
    ) -> webhook::PostFuture<'a> {
        Box::pin(async move {
            standardwebhooks::Webhook::new(&signing_key())
                .unwrap()
                .verify(&body, &headers)
                .unwrap();
            let value: Value = serde_json::from_slice(&body).unwrap();
            Ok(webhook::Response {
                status: 200,
                body: serde_json::to_vec(&json!({"challenge": value["challenge"]})).unwrap(),
                retry_after: None,
            })
        })
    }
}

struct BadChallengeCallback;
impl Transport for BadChallengeCallback {
    fn post<'a>(
        &'a self,
        _url: &'a str,
        _headers: reqwest::header::HeaderMap,
        _body: Vec<u8>,
    ) -> webhook::PostFuture<'a> {
        Box::pin(async move {
            Ok(webhook::Response {
                status: 200,
                body: serde_json::to_vec(&json!({"challenge": "wrong-challenge"})).unwrap(),
                retry_after: None,
            })
        })
    }
}

fn subscribe_outcomes(events: &[CapturedEvent]) -> Vec<CapturedEvent> {
    events
        .iter()
        .filter(|e| {
            e.target == "gateway_events"
                && matches!(
                    e.fields.get("message").map(String::as_str),
                    Some("Events subscribe refused" | "Events subscribe accepted")
                )
        })
        .cloned()
        .collect()
}

fn assert_no_leaks(events: &[CapturedEvent], planted: &[&str]) {
    for ev in events {
        for (k, v) in &ev.fields {
            for secret in planted {
                assert!(
                    !v.contains(secret) && !k.contains(secret),
                    "leak detected in gateway_events field {k}={v:?}: matched {secret:?}"
                );
            }
        }
    }
}

fn make_request(url: &str, secret: &str, cursor: Option<&str>) -> Subscribe {
    serde_json::from_value(json!({
        "name": EVENT_NAME,
        "arguments": {},
        "delivery": {
            "mode": "webhook",
            "url": url,
            "secret": secret,
        },
        "cursor": cursor,
    }))
    .unwrap()
}

#[tokio::test]
async fn subscribe_logs_content_free_outcomes_for_accept_and_all_refusal_classes() {
    let mut fixture = fixture::Fixture::new();
    let planted_token = "planted-leak-token-xyz";
    {
        let mut tokens = fixture.tokens.lock().unwrap();
        for claims in tokens.values_mut() {
            claims["scope"] = json!("identity:read events:subscribe");
        }
        let planted_claims = tokens.get("good-token").unwrap().clone();
        tokens.insert(planted_token.into(), planted_claims);
    }
    fixture.config["verifier"]["required_scopes"] = json!(["identity:read", "events:subscribe"]);
    let verifier = Arc::new(
        Verifier::from_config(
            serde_json::from_value::<VerifierConfig>(fixture.config["verifier"].clone()).unwrap(),
        )
        .unwrap(),
    );
    let key_file = fixture.keys._directory.path().join("events.key");
    fixture::private_file(&key_file, &[7; 32]);
    let key = EventKey::load(&key_file).unwrap();
    let mut store = Store::open(&fixture.store_file).unwrap();
    store.migrate_profiles().unwrap();
    store.migrate_custody().unwrap();
    store.migrate_outbound().unwrap();
    store.migrate_retirement().unwrap();
    store.migrate_events(&key).unwrap();
    drop(store);

    let identity = verifier.verify("good-token").await.unwrap();
    let runtime = Events::with_transport(
        fixture.store_file.clone(),
        key.clone(),
        verifier.clone(),
        "grant".into(),
        Arc::new(GoodCallback),
    );

    let planted_url = "https://planted-leak-url.example/secret-callback-path";
    let planted_cursor = "planted-leak-cursor-999";
    let secret = signing_key();
    let planted_secrets = [planted_url, planted_cursor, planted_token, secret.as_str()];

    let capture = LogCapture::default();

    // 1. Successful initial subscribe -> reason="subscribed", generation=1
    runtime
        .subscribe(
            &identity,
            planted_token,
            "bus",
            "dot@bus",
            make_request(planted_url, &secret, None),
        )
        .with_subscriber(capture.clone())
        .await
        .unwrap();
    let evs = capture.take();
    assert_no_leaks(&evs, &planted_secrets);
    let outcomes = subscribe_outcomes(&evs);
    assert_no_leaks(&outcomes, &["planted-leak-url.example"]);
    assert_eq!(outcomes.len(), 1);
    assert_eq!(outcomes[0].fields["reason"], "subscribed");
    assert_eq!(outcomes[0].fields["generation"], "1");

    // 2. Successful renew -> reason="subscribed", generation=2
    runtime
        .subscribe(
            &identity,
            planted_token,
            "bus",
            "dot@bus",
            make_request(planted_url, &secret, None),
        )
        .with_subscriber(capture.clone())
        .await
        .unwrap();
    let evs = capture.take();
    assert_no_leaks(&evs, &planted_secrets);
    let outcomes = subscribe_outcomes(&evs);
    assert_no_leaks(&outcomes, &["planted-leak-url.example"]);
    assert_eq!(outcomes.len(), 1);
    assert_eq!(outcomes[0].fields["reason"], "subscribed");
    assert_eq!(outcomes[0].fields["generation"], "2");

    // 3. Callback URL changed -> callback_changed_rebind_required, rpc_code=-32009, generation=2
    let changed_url = "https://planted-other-url.example/rebind";
    let err = runtime
        .subscribe(
            &identity,
            planted_token,
            "bus",
            "dot@bus",
            make_request(changed_url, &secret, None),
        )
        .with_subscriber(capture.clone())
        .await
        .unwrap_err();
    assert!(matches!(err, xmsg_mcp_gateway::events::Error::Conflict));
    let evs = capture.take();
    assert_no_leaks(&evs, &[changed_url, planted_token, secret.as_str()]);
    let outcomes = subscribe_outcomes(&evs);
    assert_eq!(outcomes.len(), 1);
    assert_eq!(
        outcomes[0].fields["reason"],
        "callback_changed_rebind_required"
    );
    assert_eq!(outcomes[0].fields["rpc_code"], "-32009");
    assert_eq!(outcomes[0].fields["generation"], "2");

    // 4. Bad cursor -> bad_cursor, rpc_code=-32602, generation=2
    let err = runtime
        .subscribe(
            &identity,
            planted_token,
            "bus",
            "dot@bus",
            make_request(planted_url, &secret, Some(planted_cursor)),
        )
        .with_subscriber(capture.clone())
        .await
        .unwrap_err();
    assert!(matches!(err, xmsg_mcp_gateway::events::Error::Arguments));
    let evs = capture.take();
    assert_no_leaks(&evs, &planted_secrets);
    let outcomes = subscribe_outcomes(&evs);
    assert_no_leaks(&outcomes, &["planted-leak-url.example"]);
    assert_eq!(outcomes.len(), 1);
    assert_eq!(outcomes[0].fields["reason"], "bad_cursor");
    assert_eq!(outcomes[0].fields["rpc_code"], "-32602");
    assert_eq!(outcomes[0].fields["generation"], "2");

    // 5. Bad arguments (unknown mode) -> bad_arguments, rpc_code=-32602
    let mut bad_mode = make_request(planted_url, &secret, None);
    bad_mode.delivery.mode = "polling".to_string();
    let _ = runtime
        .subscribe(&identity, planted_token, "bus", "dot@bus", bad_mode)
        .with_subscriber(capture.clone())
        .await
        .unwrap_err();
    let evs = capture.take();
    assert_no_leaks(&evs, &planted_secrets);
    let outcomes = subscribe_outcomes(&evs);
    assert_no_leaks(&outcomes, &["planted-leak-url.example"]);
    assert_eq!(outcomes.len(), 1);
    assert_eq!(outcomes[0].fields["reason"], "bad_arguments");
    assert_eq!(outcomes[0].fields["rpc_code"], "-32602");

    // 6. Bad secret -> bad_secret, rpc_code=-32602
    let _ = runtime
        .subscribe(
            &identity,
            planted_token,
            "bus",
            "dot@bus",
            make_request(planted_url, "not-a-valid-secret", None),
        )
        .with_subscriber(capture.clone())
        .await
        .unwrap_err();
    let evs = capture.take();
    assert_no_leaks(&evs, &planted_secrets);
    let outcomes = subscribe_outcomes(&evs);
    assert_no_leaks(&outcomes, &["planted-leak-url.example"]);
    assert_eq!(outcomes.len(), 1);
    assert_eq!(outcomes[0].fields["reason"], "bad_secret");
    assert_eq!(outcomes[0].fields["rpc_code"], "-32602");

    // 7. Bad callback URL -> bad_callback_url, rpc_code=-32015
    let _ = runtime
        .subscribe(
            &identity,
            planted_token,
            "bus",
            "dot@bus",
            make_request("http://insecure.example/cb", &secret, None),
        )
        .with_subscriber(capture.clone())
        .await
        .unwrap_err();
    let evs = capture.take();
    assert_no_leaks(&evs, &["insecure.example", planted_token, secret.as_str()]);
    let outcomes = subscribe_outcomes(&evs);
    assert_eq!(outcomes.len(), 1);
    assert_eq!(outcomes[0].fields["reason"], "bad_callback_url");
    assert_eq!(outcomes[0].fields["rpc_code"], "-32015");

    // 8. Callback host not allowed -> callback_host_not_allowed, rpc_code=-32015
    let allowlisted_runtime = Events::with_transport(
        fixture.store_file.clone(),
        key.clone(),
        verifier.clone(),
        "grant".into(),
        Arc::new(GoodCallback),
    )
    .with_allowed_hosts(Some(vec!["allowed.example".to_string()]))
    .unwrap();
    let _ = allowlisted_runtime
        .subscribe(
            &identity,
            planted_token,
            "bus",
            "dot@bus",
            make_request(planted_url, &secret, None),
        )
        .with_subscriber(capture.clone())
        .await
        .unwrap_err();
    let evs = capture.take();
    assert_no_leaks(
        &evs,
        &[planted_url, planted_cursor, planted_token, secret.as_str()],
    );
    let outcomes = subscribe_outcomes(&evs);
    assert_eq!(outcomes.len(), 1);
    assert_eq!(outcomes[0].fields["reason"], "callback_host_not_allowed");
    assert_eq!(outcomes[0].fields["rpc_code"], "-32015");

    // 9. Callback challenge failed (different bus so it doesn't hit 5m verification cache) -> callback_challenge_failed, rpc_code=-32015
    let bad_challenge_runtime = Events::with_transport(
        fixture.store_file.clone(),
        key.clone(),
        verifier.clone(),
        "grant".into(),
        Arc::new(BadChallengeCallback),
    );
    let _ = bad_challenge_runtime
        .subscribe(
            &identity,
            planted_token,
            "bus-challenge",
            "dot@bus-challenge",
            make_request(planted_url, &secret, None),
        )
        .with_subscriber(capture.clone())
        .await
        .unwrap_err();
    let evs = capture.take();
    assert_no_leaks(&evs, &planted_secrets);
    let outcomes = subscribe_outcomes(&evs);
    assert_no_leaks(&outcomes, &["planted-leak-url.example"]);
    assert_eq!(outcomes.len(), 1);
    assert_eq!(outcomes[0].fields["reason"], "callback_challenge_failed");
    assert_eq!(outcomes[0].fields["rpc_code"], "-32015");

    // 10. Credential invalid during fresh() -> credential_invalid, generation=2
    let _ = runtime
        .subscribe(
            &identity,
            "bad-token",
            "bus",
            "dot@bus",
            make_request(planted_url, &secret, None),
        )
        .with_subscriber(capture.clone())
        .await
        .unwrap_err();
    let evs = capture.take();
    assert_no_leaks(&evs, &planted_secrets);
    let outcomes = subscribe_outcomes(&evs);
    assert_no_leaks(&outcomes, &["planted-leak-url.example"]);
    assert_eq!(outcomes.len(), 1);
    assert_eq!(outcomes[0].fields["reason"], "credential_invalid");
    assert_eq!(outcomes[0].fields["generation"], "2");
    assert!(!outcomes[0].fields.contains_key("rpc_code"));

    // 11. Busy (operation lease held) -> busy, rpc_code=-32004
    {
        let store = Store::open(&fixture.store_file).unwrap();
        let _held_lease = store
            .try_operation_lease(identity.service())
            .unwrap()
            .expect("acquire operation lease");
        let _ = runtime
            .subscribe(
                &identity,
                planted_token,
                "bus",
                "dot@bus",
                make_request(planted_url, &secret, None),
            )
            .with_subscriber(capture.clone())
            .await
            .unwrap_err();
    }
    let evs = capture.take();
    assert_no_leaks(&evs, &planted_secrets);
    let outcomes = subscribe_outcomes(&evs);
    assert_no_leaks(&outcomes, &["planted-leak-url.example"]);
    assert_eq!(outcomes.len(), 1);
    assert_eq!(outcomes[0].fields["reason"], "busy");
    assert_eq!(outcomes[0].fields["rpc_code"], "-32004");

    // 12. Authority denied (different grant_id) -> authority_denied
    let wrong_grant_runtime = Events::with_transport(
        fixture.store_file.clone(),
        key,
        verifier,
        "missing-grant".into(),
        Arc::new(GoodCallback),
    );
    let _ = wrong_grant_runtime
        .subscribe(
            &identity,
            planted_token,
            "bus",
            "dot@bus",
            make_request(planted_url, &secret, None),
        )
        .with_subscriber(capture.clone())
        .await
        .unwrap_err();
    let evs = capture.take();
    assert_no_leaks(&evs, &planted_secrets);
    let outcomes = subscribe_outcomes(&evs);
    assert_no_leaks(&outcomes, &["planted-leak-url.example"]);
    assert_eq!(outcomes.len(), 1);
    assert_eq!(outcomes[0].fields["reason"], "authority_denied");
    assert!(!outcomes[0].fields.contains_key("rpc_code"));
}

#[tokio::test]
async fn serving_malformed_subscribe_params_logs_bad_arguments_without_leaks() {
    use std::os::unix::fs::PermissionsExt;
    use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};

    let mut fixture = fixture::Fixture::new();
    for claims in fixture.tokens.lock().unwrap().values_mut() {
        claims["scope"] = json!("identity:read events:subscribe");
    }
    fixture.config["verifier"]["required_scopes"] = json!(["identity:read", "events:subscribe"]);

    let directory = fixture.keys._directory.path();
    std::fs::set_permissions(directory, std::fs::Permissions::from_mode(0o700)).unwrap();
    let socket = directory.join("register.sock");
    let listener = tokio::net::UnixListener::bind(&socket).unwrap();
    std::fs::set_permissions(&socket, std::fs::Permissions::from_mode(0o600)).unwrap();
    let _broker = tokio::spawn(async move {
        let mut connections = tokio::task::JoinSet::new();
        loop {
            let Ok((stream, _)) = listener.accept().await else {
                break;
            };
            connections.spawn(async move {
                let mut stream = BufReader::new(stream);
                let mut line = String::new();
                if stream.read_line(&mut line).await.unwrap_or(0) == 0 {
                    return;
                }
                let ready = json!({"status":"ok","address":"gateway@bus","node":"bus","reply_ttl_secs":604800,"idempotency_ttl_secs":604800,"svc_queue_cap":1000,"max_body_bytes":65536});
                let _ = stream
                    .get_mut()
                    .write_all(format!("{ready}\n").as_bytes())
                    .await;
                loop {
                    line.clear();
                    if stream.read_line(&mut line).await.unwrap_or(0) == 0 {
                        break;
                    }
                    let _ = stream
                        .get_mut()
                        .write_all(b"{\"action\":\"timeout\"}\n")
                        .await;
                }
            });
        }
    });

    let key_file = directory.join("events.key");
    fixture::private_file(&key_file, &[7; 32]);
    fixture.config["request_timeout_ms"] = json!(60000);
    fixture.config["events"] = json!({
        "grant_id": "grant",
        "key_file": key_file,
        "dispatch_timeout_ms": 13000,
    });
    fixture.config["messaging"] = json!({
        "xmsg": {
            "service": "gateway",
            "expected_node": "bus",
            "daemon_uid": xmsg::client::current_uid(),
            "register_socket": socket,
            "agent_socket": directory.join("unused.sock"),
            "operation_timeout_ms": 1000
        },
        "manifest": {
            "reply_ttl_secs": 604800,
            "idempotency_ttl_secs": 604800,
            "svc_queue_cap": 1000,
            "dedup_lifetime_secs": 604800,
            "max_framed_bytes": 65536
        },
        "result_recovery_secs": 604800,
        "submission_timeout_ms": 1000,
        "max_reservations": 100,
        "max_retained_bytes": 1048576
    });
    fixture::private_file(
        &fixture.config_file,
        &serde_json::to_vec(&fixture.config).unwrap(),
    );
    let mut store = Store::open(&fixture.store_file).unwrap();
    store.migrate_profiles().unwrap();
    store.migrate_custody().unwrap();
    store.migrate_outbound().unwrap();
    store.migrate_retirement().unwrap();
    let key = EventKey::load(&key_file).unwrap();
    store.migrate_events(&key).unwrap();
    drop(store);

    let app = fixture.serving().await;
    let capture = LogCapture::default();

    let planted_url = "https://planted-serving-leak.example/cb";
    let planted_cursor = "planted-serving-cursor-123";
    let req = Request::builder()
        .method("POST")
        .uri("/mcp")
        .header("host", "gateway.example")
        .header("origin", "https://gateway.example")
        .header("authorization", "Bearer good-token")
        .header("content-type", "application/json")
        .header("accept", "application/json, text/event-stream")
        .body(Body::from(
            json!({
                "jsonrpc": "2.0",
                "id": 1,
                "method": "events/subscribe",
                "params": {
                    "name": EVENT_NAME,
                    "unexpected": planted_url,
                    "cursor": planted_cursor
                }
            })
            .to_string(),
        ))
        .unwrap();

    let resp = app
        .router()
        .oneshot(req)
        .with_subscriber(capture.clone())
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    let evs = capture.take();
    assert_no_leaks(&evs, &[planted_url, planted_cursor, "good-token"]);
    let outcomes = subscribe_outcomes(&evs);
    assert_eq!(outcomes.len(), 1);
    assert_eq!(outcomes[0].fields["reason"], "bad_arguments");
    assert_eq!(outcomes[0].fields["rpc_code"], "-32602");
}
