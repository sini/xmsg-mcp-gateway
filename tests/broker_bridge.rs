use serde_json::json;
use xmsg_mcp_gateway::broker;

#[test]
fn typed_gist_requests_keep_metadata_file_names_as_data_and_fixed_destination() {
    let request = broker::parse("gist", json!({"request_id":"create-1","title":"example","body":"","files":{"resource":"content","subject":"more"}}), "genie@node").unwrap();
    assert_eq!(request.to, "genie@node");
    assert_eq!(
        serde_json::from_str::<serde_json::Value>(&request.text).unwrap()["files"]["resource"],
        "content"
    );
    for args in [
        json!({"request_id":"x","id":"abc","to":"other@node"}),
        json!({"request_id":"x","id":"abc","subject":"forged"}),
        json!({"request_id":"x","id":"abc","public":true}),
    ] {
        assert!(broker::parse("gist_read", args, "genie@node").is_err());
    }
}
#[test]
fn malformed_proposals_and_untrusted_results_are_not_broker_success() {
    assert!(broker::parse(
        "gist_comment",
        json!({"request_id":"x","id":"abc","body":" "}),
        "genie@node"
    )
    .is_err());
    assert!(broker::parse(
        "gist_update",
        json!({"request_id":"x","id":"abc","files":{}}),
        "genie@node"
    )
    .is_err());
    assert!(broker::parse("pr", json!({"request_id":"x"}), "genie@node").is_err());
}

#[allow(dead_code)]
#[path = "common/serving_fixture.rs"]
mod fixture;
#[allow(dead_code)]
#[path = "common/provider.rs"]
mod provider;
use serde_json::Value;
use std::collections::VecDeque;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::UnixListener;
use xmsg_mcp_gateway::{
    event_store::EventKey,
    grants::Store,
    outbound::{Permission, Policy},
    serving::Serving,
};

struct Bus {
    tasks: Vec<tokio::task::JoinHandle<()>>,
    sends: Arc<AtomicUsize>,
    pending: Arc<Mutex<VecDeque<Value>>>,
}
impl Drop for Bus {
    fn drop(&mut self) {
        for task in &self.tasks {
            task.abort();
        }
    }
}
async fn setup() -> (fixture::Fixture, Bus) {
    setup_mode(true).await
}
async fn setup_mode(auto_reply: bool) -> (fixture::Fixture, Bus) {
    setup_with_list_delay(auto_reply, std::time::Duration::ZERO).await
}
async fn setup_with_list_delay(
    auto_reply: bool,
    list_delay: std::time::Duration,
) -> (fixture::Fixture, Bus) {
    let mut fixture = fixture::Fixture::new();
    for claims in fixture.tokens.lock().unwrap().values_mut() {
        claims["scope"] = json!("identity:read events:subscribe");
    }
    fixture.config["verifier"]["required_scopes"] = json!(["identity:read", "events:subscribe"]);
    let directory = fixture.keys._directory.path();
    std::fs::set_permissions(directory, std::fs::Permissions::from_mode(0o700)).unwrap();
    let keyfile = directory.join("events-key");
    fixture::private_file(&keyfile, &[8; 32]);
    let key = EventKey::load(&keyfile).unwrap();
    let mut store = Store::open(&fixture.store_file).unwrap();
    store.migrate_custody().unwrap();
    store.migrate_outbound().unwrap();
    store.migrate_retirement().unwrap();
    store.migrate_events(&key).unwrap();
    store
        .set_outbound_policy(
            "grant",
            2,
            &Policy {
                send: Some(Permission {
                    targets: std::collections::BTreeSet::from(["genie@node".into()]),
                    required_scope: "identity:read".into(),
                }),
                reply: None,
            },
        )
        .unwrap();
    let register = directory.join("register.sock");
    let agent = directory.join("agent.sock");
    let service_listener = UnixListener::bind(&register).unwrap();
    let agent_listener = UnixListener::bind(&agent).unwrap();
    for socket in [&register, &agent] {
        std::fs::set_permissions(socket, std::fs::Permissions::from_mode(0o600)).unwrap();
    }
    let queued = Arc::new(Mutex::new(VecDeque::<Value>::new()));
    let queue = queued.clone();
    let service = tokio::spawn(async move {
        let mut children = tokio::task::JoinSet::new();
        loop {
            let (stream, _) = service_listener.accept().await.unwrap();
            let queued = queue.clone();
            children.spawn(async move{
            let mut stream=BufReader::new(stream);let mut line=String::new();stream.read_line(&mut line).await.unwrap();
            stream.get_mut().write_all(format!("{}\n",json!({"status":"ok","address":"gateway@bus","node":"bus","reply_ttl_secs":604800,"idempotency_ttl_secs":604800,"svc_queue_cap":1000,"max_body_bytes":65536})).as_bytes()).await.unwrap();
            loop {
                line.clear();
                let length = match stream.read_line(&mut line).await {
                    Ok(length) => length,
                    Err(error) if line.is_empty() && error.kind() == std::io::ErrorKind::ConnectionReset => break,
                    Err(error) => panic!("fake service request failed: {error}"),
                };
                if length == 0 { break; }
                let frame: Value = serde_json::from_str(&line).unwrap();
                let response=match frame["action"].as_str().unwrap(){"poll"=>queued.lock().unwrap().front().cloned().unwrap_or(json!({"action":"timeout"})),"ack"=>{queued.lock().unwrap().pop_front();json!({"status":"ok"})},other=>panic!("unexpected {other}")};
                stream.get_mut().write_all(format!("{response}\n").as_bytes()).await.unwrap();
            }
        });
        }
    });
    let sends = Arc::new(AtomicUsize::new(0));
    let counter = sends.clone();
    let pending = queued.clone();
    let agent_task = tokio::spawn(async move {
        loop {
            let (stream, _) = agent_listener.accept().await.unwrap();
            let mut stream = BufReader::new(stream);
            let mut line = String::new();
            stream.read_line(&mut line).await.unwrap();
            let frame: Value = serde_json::from_str(&line).unwrap();
            let response = match frame["action"].as_str().unwrap() {
                "list" => {
                    if !list_delay.is_zero() {
                        tokio::time::sleep(list_delay).await;
                    }
                    json!({"status":"ok","nodes":[{"node":"node","status":"ok"}],"recipients":[{"address":"genie@node","node":"node","kind":"service","harness":"svc","status":"live","user":"fixture"}]})
                }
                "send" => {
                    counter.fetch_add(1, Ordering::SeqCst);
                    assert_eq!(frame["to"], "genie@node");
                    let text = frame["text"].as_str().unwrap();
                    assert!(text
                        .starts_with("[External message via gateway@bus; gateway correlation gw-"));
                    let request: Value =
                        serde_json::from_str(text.split_once('\n').unwrap().1).unwrap();
                    assert!(matches!(
                        request["kind"].as_str(),
                        Some("gist_read" | "gist" | "gist_update" | "gist_comment")
                    ));
                    assert!(request.get("request_id").is_none());
                    let mut result = json!({"thread":"bridge","acted":true,"reason":"read","redactions":[],"url":"https://gist.github.com/abc","gist":{"untrusted":true,"id":"abc","url":"https://gist.github.com/abc","description":"example","owner":null,"revision":"revision","files":{"resource":"safe".repeat(2000)}}});
                    if request["kind"] != "gist_read" {
                        result.as_object_mut().unwrap().remove("gist");
                    }
                    if auto_reply {
                        queued.lock().unwrap().push_back(json!({"action":"deliver","messageId":"result-wire","fromName":"untrusted label","text":result.to_string(),"envelope":"peer data","origin":{"id":null,"service":"genie","node":"node"},"inReplyTo":"request-wire"}));
                    }
                    json!({"status":"ok","message_id":"request-wire","address":"genie@node","outcome":"queued"})
                }
                other => panic!("unexpected {other}"),
            };
            stream
                .get_mut()
                .write_all(format!("{response}\n").as_bytes())
                .await
                .unwrap();
        }
    });
    fixture.config["request_timeout_ms"] = json!(60000);
    fixture.config["events"] =
        json!({"grant_id":"grant","key_file":keyfile,"dispatch_timeout_ms":13000});
    fixture.config["broker"] = json!({"destination":"genie@node"});
    let dispatch_timeout_ms = if auto_reply { 5000 } else { 1000 };
    fixture.config["messaging"] = json!({"xmsg":{"service":"gateway","expected_node":"bus","daemon_uid":std::fs::metadata(directory).unwrap().uid(),"register_socket":register,"agent_socket":agent,"operation_timeout_ms":dispatch_timeout_ms},"manifest":{"reply_ttl_secs":604800,"idempotency_ttl_secs":604800,"svc_queue_cap":1000,"dedup_lifetime_secs":604800,"max_framed_bytes":65536},"result_recovery_secs":604800,"submission_timeout_ms":dispatch_timeout_ms,"max_reservations":100,"max_retained_bytes":1048576});
    fixture::private_file(
        &fixture.config_file,
        &serde_json::to_vec(&fixture.config).unwrap(),
    );
    (
        fixture,
        Bus {
            tasks: vec![service, agent_task],
            sends,
            pending,
        },
    )
}
fn rpc(method: &str, params: Value) -> Value {
    json!({"jsonrpc":"2.0","id":"broker-rpc","method":method,"params":params})
}
#[tokio::test]
async fn authenticated_mcp_gist_uses_existing_send_and_full_correlated_status() {
    let (fixture, bus) = setup().await;
    let serving = Serving::from_owner_file(&fixture.config_file)
        .await
        .unwrap();
    let request = rpc(
        "tools/call",
        json!({"name":"gist_read","arguments":{"request_id":"read-1","id":"abc"}}),
    );
    let (status, value, _) = fixture::request(&serving, "good-token", request.clone()).await;
    assert_eq!(status, axum::http::StatusCode::OK, "{value}");
    assert_eq!(value["id"], "broker-rpc");
    assert_eq!(
        value["result"]["structuredContent"]["broker"]["result"]["gist"]["files"]["resource"],
        "safe".repeat(2000),
        "full custody result was previewed, dropped or miscorrelated: {value}"
    );
    let (status, value, _) = fixture::request(
        &serving,
        "good-token",
        rpc(
            "tools/call",
            json!({"name":"xmsg_message_status","arguments":{"request_id":"read-1"}}),
        ),
    )
    .await;
    assert_eq!(status, axum::http::StatusCode::OK);
    assert_eq!(
        value["result"]["structuredContent"]["broker"]["state"],
        "confirmed"
    );
    let (status, _, _) = fixture::request(&serving, "good-token", request).await;
    assert_eq!(status, axum::http::StatusCode::OK);
    assert_eq!(bus.sends.load(Ordering::SeqCst), 1);
    let (status, value, _) = fixture::request(
        &serving,
        "good-token",
        rpc(
            "tools/call",
            json!({"name":"gist_read","arguments":{"request_id":"read-1","id":"def"}}),
        ),
    )
    .await;
    assert_eq!(status, axum::http::StatusCode::OK);
    assert_eq!(value["error"]["code"], -32009);
}
#[tokio::test]
async fn gist_advertising_and_dispatch_require_selected_grant_and_exact_current_target() {
    let (fixture, bus) = setup().await;
    let serving = Serving::from_owner_file(&fixture.config_file)
        .await
        .unwrap();
    let (_, value, _) =
        fixture::request(&serving, "good-token", rpc("tools/list", json!({}))).await;
    assert!(value["result"]["tools"]
        .as_array()
        .unwrap()
        .iter()
        .any(|t| t["name"] == "gist_read"));
    let mut store = Store::open(&fixture.store_file).unwrap();
    store
        .set_outbound_policy(
            "grant",
            3,
            &Policy {
                send: Some(Permission {
                    targets: std::collections::BTreeSet::from(["foreign@node".into()]),
                    required_scope: "identity:read".into(),
                }),
                reply: None,
            },
        )
        .unwrap();
    let (_, value, _) =
        fixture::request(&serving, "good-token", rpc("tools/list", json!({}))).await;
    assert!(!value["result"]["tools"]
        .as_array()
        .unwrap()
        .iter()
        .any(|t| t["name"] == "gist_read"));
    let request = rpc(
        "tools/call",
        json!({"name":"gist_read","arguments":{"request_id":"not-sent","id":"abc"}}),
    );
    let (status, _, _) = fixture::request(&serving, "good-token", request.clone()).await;
    assert_eq!(status, axum::http::StatusCode::FORBIDDEN);
    assert_eq!(bus.sends.load(Ordering::SeqCst), 0);
    store.set_enabled("grant", 4, false).unwrap();
    store.enroll("other", &fixture.binding).unwrap();
    store
        .set_outbound_policy(
            "other",
            1,
            &Policy {
                send: Some(Permission {
                    targets: std::collections::BTreeSet::from(["genie@node".into()]),
                    required_scope: "identity:read".into(),
                }),
                reply: None,
            },
        )
        .unwrap();
    store.set_enabled("other", 2, true).unwrap();
    let (_, value, _) =
        fixture::request(&serving, "good-token", rpc("tools/list", json!({}))).await;
    assert!(
        !value["result"]["tools"]
            .as_array()
            .unwrap()
            .iter()
            .any(|t| t["name"] == "gist_read"),
        "gist advertised for a grant that does not own Events custody"
    );
    let (status, _, _) = fixture::request(&serving, "good-token", request).await;
    assert_eq!(status, axum::http::StatusCode::FORBIDDEN);
    assert_eq!(bus.sends.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn broker_wait_is_bounded_and_late_result_survives_reconnect_without_resubmission() {
    let (fixture, bus) = setup_mode(false).await;
    let serving = Serving::from_owner_file(&fixture.config_file)
        .await
        .unwrap();
    let started = std::time::Instant::now();
    let request = rpc(
        "tools/call",
        json!({"name":"gist_read","arguments":{"request_id":"late-read","id":"abc"}}),
    );
    let (status, value, _) = fixture::request(&serving, "good-token", request.clone()).await;
    assert_eq!(status, axum::http::StatusCode::OK, "{value}");
    assert_eq!(value["result"]["structuredContent"]["state"], "pending");
    assert!(
        started.elapsed() < std::time::Duration::from_secs(11),
        "call exceeded its ten-second total wait"
    );
    assert!(started.elapsed() >= std::time::Duration::from_secs(9));
    drop(serving);
    let serving = Serving::from_owner_file(&fixture.config_file)
        .await
        .unwrap();
    let body = json!({"thread":"bridge","acted":false,"reason":"bounded refusal","redactions":[]})
        .to_string();
    bus.pending.lock().unwrap().push_back(json!({"action":"deliver","messageId":"late-result","fromName":"untrusted label","text":body,"envelope":"peer data","origin":{"id":null,"service":"genie","node":"node"},"inReplyTo":"request-wire"}));
    let (_, value, _) = fixture::request(&serving, "good-token", request).await;
    assert_eq!(
        value["result"]["structuredContent"]["broker"]["result"]["reason"], "bounded refusal",
        "{value}"
    );
    assert_eq!(
        bus.sends.load(Ordering::SeqCst),
        1,
        "late retry republished work"
    );
}

#[tokio::test]
async fn broker_startup_requires_events_and_rejects_unfixed_destinations() {
    let mut fixture = fixture::Fixture::new();
    for destination in [
        "genie@node",
        "genie",
        "genie@node@other",
        "genie@node with space",
    ] {
        fixture.config["broker"] = json!({"destination":destination});
        fixture::private_file(
            &fixture.config_file,
            &serde_json::to_vec(&fixture.config).unwrap(),
        );
        assert!(Serving::from_owner_file(&fixture.config_file)
            .await
            .is_err());
    }
}

#[tokio::test]
async fn broker_complete_encoded_request_bound_and_authentication_refuse_before_publication() {
    let (fixture, bus) = setup().await;
    let serving = Serving::from_owner_file(&fixture.config_file)
        .await
        .unwrap();
    let request = rpc(
        "tools/call",
        json!({"name":"gist","arguments":{"request_id":"too-large","title":"example","body":"","files":{"resource":"\n".repeat(40000),"subject":"data"}}}),
    );
    let (status, value, _) = fixture::request(&serving, "good-token", request.clone()).await;
    assert_eq!(status, axum::http::StatusCode::OK, "{value}");
    assert_eq!(
        value["error"]["code"], -32602,
        "serialized Proposal/preamble bound missing: {value}"
    );
    let (status, _, _) = fixture::request(&serving, "foreign-token", request).await;
    assert_eq!(status, axum::http::StatusCode::UNAUTHORIZED);
    assert_eq!(bus.sends.load(Ordering::SeqCst), 0);
}

#[allow(dead_code)]
#[path = "common/agent_stall.rs"]
mod agent_stall;
#[tokio::test]
async fn cancelling_broker_handler_keeps_the_accepted_submission_owned_by_the_worker() {
    let (fixture, bus) = setup().await;
    let config = serde_json::from_value(fixture.config["messaging"]["xmsg"].clone()).unwrap();
    let mut stall = agent_stall::AgentStall::install(&config, "send");
    let serving = Arc::new(
        Serving::from_owner_file(&fixture.config_file)
            .await
            .unwrap(),
    );
    let request = rpc(
        "tools/call",
        json!({"name":"gist_read","arguments":{"request_id":"cancelled-call","id":"abc"}}),
    );
    let task_serving = serving.clone();
    let task_request = request.clone();
    let task =
        tokio::spawn(
            async move { fixture::request(&task_serving, "good-token", task_request).await },
        );
    stall.reached().await;
    task.abort();
    let _ = task.await;
    stall.finish(true).await;
    tokio::time::timeout(std::time::Duration::from_secs(3),async {
        loop {let receipt:i64=rusqlite::Connection::open(&fixture.store_file).unwrap().query_row("SELECT COUNT(*) FROM outbound_reservations WHERE request_id='cancelled-call' AND receipt IS NOT NULL",[],|r|r.get(0)).unwrap();if receipt==1{break;}tokio::time::sleep(std::time::Duration::from_millis(10)).await;}
    }).await.unwrap();
    let (_, value, _) = fixture::request(&serving, "good-token", request).await;
    assert_eq!(
        value["result"]["structuredContent"]["broker"]["state"], "confirmed",
        "{value}"
    );
    assert_eq!(
        bus.sends.load(Ordering::SeqCst),
        1,
        "cancelled broker dispatch did not commit before retry"
    );
}

#[allow(dead_code)]
#[path = "common/outbound_observer.rs"]
mod outbound_observer;

#[tokio::test]
async fn broker_status_rechecks_send_ceiling_at_the_final_result_read() {
    use axum::body::Body;
    use axum::http::{Request, StatusCode};
    use tower::ServiceExt;
    use tracing::instrument::WithSubscriber;
    let (fixture, bus) = setup().await;
    let serving = Serving::from_owner_file(&fixture.config_file)
        .await
        .unwrap();
    let (_, initial, _) = fixture::request(
        &serving,
        "good-token",
        rpc(
            "tools/call",
            json!({"name":"gist_read","arguments":{"request_id":"status-race","id":"abc"}}),
        ),
    )
    .await;
    assert_eq!(
        initial["result"]["structuredContent"]["broker"]["state"],
        "confirmed"
    );
    let (_, initial_status, _) = fixture::request(
        &serving,
        "good-token",
        rpc(
            "tools/call",
            json!({"name":"xmsg_message_status","arguments":{"request_id":"status-race"}}),
        ),
    )
    .await;
    assert_eq!(
        initial_status["result"]["structuredContent"]["broker"]["state"],
        "confirmed"
    );
    let file = fixture.store_file.clone();
    let reached = Arc::new(AtomicUsize::new(0));
    let count = reached.clone();
    let barrier = outbound_observer::AtEvent {
        target: "gateway_broker_status_result",
        action: move || {
            assert_eq!(count.fetch_add(1, Ordering::SeqCst), 0);
            Store::open(&file)
                .unwrap()
                .set_outbound_policy("grant", 3, &Policy::default())
                .unwrap();
        },
    };
    let input = Request::builder()
        .method("POST")
        .uri("/mcp")
        .header("host", "gateway.example")
        .header("content-type", "application/json")
        .header("authorization", "Bearer good-token")
        .body(Body::from(
            rpc(
                "tools/call",
                json!({"name":"xmsg_message_status","arguments":{"request_id":"status-race"}}),
            )
            .to_string(),
        ))
        .unwrap();
    let response = serving
        .router()
        .oneshot(input)
        .with_subscriber(barrier)
        .await
        .unwrap();
    assert_eq!(
        reached.load(Ordering::SeqCst),
        1,
        "revocation barrier was not reached"
    );
    assert_eq!(
        response.status(),
        StatusCode::FORBIDDEN,
        "status returned a broker result after the send ceiling was revoked"
    );
    assert_eq!(
        bus.sends.load(Ordering::SeqCst),
        1,
        "read-only status published work"
    );
}

#[tokio::test]
async fn broker_result_survives_effect_expiry_until_result_retirement() {
    let (fixture, bus) = setup().await;
    let serving = Serving::from_owner_file(&fixture.config_file)
        .await
        .unwrap();
    let request = rpc(
        "tools/call",
        json!({"name":"gist_read","arguments":{"request_id":"separate-windows","id":"abc"}}),
    );
    let (_, value, _) = fixture::request(&serving, "good-token", request.clone()).await;
    assert_eq!(
        value["result"]["structuredContent"]["broker"]["state"], "confirmed",
        "{value}"
    );
    let database = rusqlite::Connection::open(&fixture.store_file).unwrap();
    database.execute(
        "UPDATE outbound_reservations SET retry_until=created_at WHERE request_id='separate-windows'",
        [],
    ).unwrap();
    let status_request = rpc(
        "tools/call",
        json!({"name":"xmsg_message_status","arguments":{"request_id":"separate-windows"}}),
    );
    let (_, value, _) = fixture::request(&serving, "good-token", status_request.clone()).await;
    assert_eq!(
        value["result"]["structuredContent"]["broker"]["result"]["gist"]["files"]["resource"],
        "safe".repeat(2000),
        "broker result was lost at the shorter effect horizon: {value}"
    );
    assert_eq!(bus.sends.load(Ordering::SeqCst), 1);
    database.execute(
        "UPDATE outbound_reservations SET recovery_until=created_at WHERE request_id='separate-windows'",
        [],
    ).unwrap();
    let (_, value, _) = fixture::request(&serving, "good-token", status_request).await;
    assert_eq!(
        value["result"]["structuredContent"]["state"], "expired",
        "{value}"
    );
    assert_eq!(value["result"]["structuredContent"]["not_reexecuted"], true);
    assert!(
        value["result"]["structuredContent"].get("broker").is_none(),
        "retired content reappeared: {value}"
    );
    drop(serving);
    let serving = Serving::from_owner_file(&fixture.config_file)
        .await
        .unwrap();
    let (_, value, _) = fixture::request(&serving, "good-token", request).await;
    assert_eq!(
        value["result"]["structuredContent"]["state"], "expired",
        "{value}"
    );
    assert_eq!(value["result"]["structuredContent"]["not_reexecuted"], true);
    assert_eq!(
        bus.sends.load(Ordering::SeqCst),
        1,
        "expired gist ID became a fresh effect"
    );
    let rows: i64 = database
        .query_row(
            "SELECT COUNT(*) FROM outbound_reservations WHERE request_id='separate-windows'",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(
        rows, 0,
        "retired broker proposal still consumes active quota"
    );
}

#[tokio::test]
async fn broker_fixture_covers_pre_send_shared_runner_delay() {
    let (fixture, bus) = setup_with_list_delay(true, std::time::Duration::from_millis(1500)).await;
    let serving = Serving::from_owner_file(&fixture.config_file)
        .await
        .unwrap();
    let started = std::time::Instant::now();
    let (status, value, probe) = fixture::request(&serving, "good-token", rpc("tools/call",json!({"name":"gist","arguments":{"request_id":"delayed-list","title":"fixture","body":"","files":{"example":"body"}}}))).await;
    eprintln!(
        "delayed-list-control: elapsed_us={} response={:?}",
        started.elapsed().as_micros(),
        probe.response.lock().unwrap()
    );
    assert_eq!(
        status,
        axum::http::StatusCode::OK,
        "delayed pre-send lookup failed: {value}"
    );
    assert_eq!(
        value["result"]["structuredContent"]["broker"]["state"], "confirmed",
        "delayed pre-send lookup failed: {value}"
    );
    assert_eq!(bus.sends.load(Ordering::SeqCst), 1);
    assert!(started.elapsed() >= std::time::Duration::from_millis(1500));
}

#[tokio::test]
async fn retirement_http_diagnostics_preserve_non_json_failure() {
    let (fixture, bus) = setup().await;
    let serving = Serving::from_owner_file(&fixture.config_file)
        .await
        .unwrap();
    let (status, value, probe) =
        fixture::request(&serving, "foreign-token", rpc("tools/list", json!({}))).await;
    assert_eq!(status, axum::http::StatusCode::UNAUTHORIZED);
    assert_eq!(value, Value::Null);
    let response = probe.response.lock().unwrap();
    let (code, raw, elapsed) = response.as_ref().unwrap();
    assert_eq!(*code, 401);
    assert_eq!(raw, "");
    assert!(*elapsed > 0);
    let timing = fixture.provider_timing.lock().unwrap();
    assert!(timing.iter().any(|(stage, _)| stage == "request-read"));
    assert!(timing.iter().any(|(stage, _)| stage == "response-written"));
    assert_eq!(bus.sends.load(Ordering::SeqCst), 0);
    eprintln!("retirement-diagnostics-control: non-JSON HTTP {code}, raw={raw:?}, elapsed_us={elapsed}, provider_timing_us={timing:?}");
}

#[tokio::test]
async fn retired_gist_write_request_id_never_reexecutes() {
    let started = std::time::Instant::now();
    let (fixture, bus) = setup().await;
    let setup_us = started.elapsed().as_micros();
    let serving = Serving::from_owner_file(&fixture.config_file)
        .await
        .unwrap();
    let ready_us = started.elapsed().as_micros();
    let request = rpc(
        "tools/call",
        json!({"name":"gist","arguments":{
            "request_id":"retired-write","title":"fixture","body":"","files":{"example":"body"}
        }}),
    );
    let request_started_us = started.elapsed().as_micros();
    let (status, value, probe) = fixture::request(&serving, "good-token", request.clone()).await;
    let (_, raw_body, request_elapsed_us) = probe.response.lock().unwrap().clone().unwrap();
    eprintln!(
        "retirement-request-diagnostics {}",
        json!({"provider_origin_us":fixture.started.duration_since(started).as_micros(),"setup_us":setup_us,"broker_ready_us":ready_us,"request_started_us":request_started_us,"request_elapsed_us":request_elapsed_us,"request_finished_us":started.elapsed().as_micros(),"http_status":status.as_u16(),"raw_body":raw_body,"provider_timing_us":fixture.provider_timing.lock().unwrap().clone(),"provider_requests":fixture.requests.load(Ordering::SeqCst),"bus_sends":bus.sends.load(Ordering::SeqCst)})
    );
    assert_eq!(
        value["result"]["structuredContent"]["broker"]["state"], "confirmed",
        "{value}"
    );
    assert_eq!(bus.sends.load(Ordering::SeqCst), 1);
    rusqlite::Connection::open(&fixture.store_file).unwrap().execute(
        "UPDATE outbound_reservations SET recovery_until=created_at WHERE request_id='retired-write'", [],
    ).unwrap();
    drop(serving);
    let serving = Serving::from_owner_file(&fixture.config_file)
        .await
        .unwrap();
    let (_, value, _) = fixture::request(&serving, "good-token", request).await;
    assert_eq!(
        bus.sends.load(Ordering::SeqCst),
        1,
        "retired gist write was published again"
    );
    assert_eq!(
        value["result"]["structuredContent"]["state"], "expired",
        "{value}"
    );
    assert_eq!(value["result"]["structuredContent"]["not_reexecuted"], true);
}

#[tokio::test]
async fn expired_broker_uncertainty_requires_reconciliation_without_retry_advice() {
    let (fixture, bus) = setup().await;
    let serving = Serving::from_owner_file(&fixture.config_file)
        .await
        .unwrap();
    let request = rpc(
        "tools/call",
        json!({"name":"gist_read","arguments":{
            "request_id":"expired-broker-unknown","id":"abc"
        }}),
    );
    let (_, value, _) = fixture::request(&serving, "good-token", request.clone()).await;
    assert_eq!(
        value["result"]["structuredContent"]["broker"]["state"], "confirmed",
        "{value}"
    );
    rusqlite::Connection::open(&fixture.store_file).unwrap().execute(
        "UPDATE outbound_reservations SET receipt=NULL,state='unknown',retry_until=created_at WHERE request_id='expired-broker-unknown'", [],
    ).unwrap();
    let (_, value, _) = fixture::request(&serving, "good-token", request).await;
    let result = &value["result"]["structuredContent"];
    assert_eq!(result["state"], "unknown", "{value}");
    assert_eq!(
        result["reconciliation_required"], true,
        "expired broker uncertainty must require reconciliation"
    );
    assert!(
        result.get("retry").is_none(),
        "expired broker result gave blind retry advice"
    );
    assert_eq!(
        bus.sends.load(Ordering::SeqCst),
        1,
        "expired broker request was resubmitted"
    );
}

struct ControlledClock(tokio::task::JoinHandle<()>);
impl ControlledClock {
    fn pause() -> Self {
        tokio::time::pause();
        Self(tokio::spawn(async {
            loop {
                tokio::task::yield_now().await;
            }
        }))
    }
}
impl Drop for ControlledClock {
    fn drop(&mut self) {
        self.0.abort();
        tokio::time::resume();
    }
}
async fn wall_bounded<T>(stage: &str, future: impl std::future::Future<Output = T>) -> T {
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(3);
    tokio::pin!(future);
    loop {
        assert!(
            std::time::Instant::now() < deadline,
            "controlled deadline fixture exceeded wall budget: {stage}"
        );
        match std::future::poll_fn(|cx| std::task::Poll::Ready(future.as_mut().poll(cx))).await {
            std::task::Poll::Ready(value) => return value,
            std::task::Poll::Pending => tokio::task::yield_now().await,
        }
    }
}

#[tokio::test]
async fn pre_send_deadline_has_json_rpc_safe_retry_without_submission() {
    for tool in ["gist_read", "xmsg_send"] {
        let (mut fixture, bus) = setup().await;
        fixture.config["messaging"]["submission_timeout_ms"] = json!(1000);
        fixture::private_file(
            &fixture.config_file,
            &serde_json::to_vec(&fixture.config).unwrap(),
        );
        let config = serde_json::from_value(fixture.config["messaging"]["xmsg"].clone()).unwrap();
        let mut stall = agent_stall::AgentStall::install(&config, "list");
        let serving = Arc::new(
            Serving::from_owner_file(&fixture.config_file)
                .await
                .unwrap(),
        );
        let arguments = if tool == "gist_read" {
            json!({"request_id":"pre-send-timeout","id":"abc"})
        } else {
            json!({"request_id":"pre-send-timeout","to":"genie@node","text":"ordinary message"})
        };
        let clock = ControlledClock::pause();
        let task_serving = serving.clone();
        let handler = tokio::spawn(async move {
            fixture::request(
                &task_serving,
                "good-token",
                rpc("tools/call", json!({"name":tool,"arguments":arguments})),
            )
            .await
        });
        wall_bounded("barrier", stall.reached()).await;
        tokio::time::advance(std::time::Duration::from_millis(1001)).await;
        let (status, value, _) = wall_bounded("response", handler).await.unwrap();
        wall_bounded("finish", stall.finish(true)).await;
        drop(clock);
        assert_eq!(
            status,
            axum::http::StatusCode::OK,
            "pre-send dispatch failure omitted JSON-RPC: {tool} {value}"
        );
        assert_eq!(value["id"], "broker-rpc");
        assert_eq!(value["error"]["code"], -32004);
        assert_eq!(
            value["error"]["data"],
            json!({"submitted":false,"retry":"same request_id"}),
            "pre-send failure lacks safe retry: {tool} {value}"
        );
        assert_eq!(bus.sends.load(Ordering::SeqCst), 0);
    }
}

#[tokio::test]
async fn post_send_deadline_is_unknown_and_status_never_resubmits() {
    let (mut fixture, bus) = setup().await;
    fixture.config["messaging"]["submission_timeout_ms"] = json!(1000);
    fixture::private_file(
        &fixture.config_file,
        &serde_json::to_vec(&fixture.config).unwrap(),
    );
    let config = serde_json::from_value(fixture.config["messaging"]["xmsg"].clone()).unwrap();
    let mut stall = agent_stall::AgentStall::install(&config, "send");
    let serving = Arc::new(
        Serving::from_owner_file(&fixture.config_file)
            .await
            .unwrap(),
    );
    let clock = ControlledClock::pause();
    let task_serving = serving.clone();
    let handler = tokio::spawn(async move {
        fixture::request(&task_serving,"good-token",rpc("tools/call",json!({"name":"gist_read","arguments":{"request_id":"post-send-timeout","id":"abc"}}))).await
    });
    wall_bounded("barrier", stall.reached()).await;
    tokio::time::advance(std::time::Duration::from_millis(1001)).await;
    let (status, value, _) = wall_bounded("response", handler).await.unwrap();
    wall_bounded("finish", stall.finish(false)).await;
    drop(clock);
    assert_eq!(status, axum::http::StatusCode::OK);
    assert_eq!(
        value["result"]["structuredContent"]["state"], "unknown",
        "post-send deadline falsely claimed no submission: {value}"
    );
    assert!(
        value.get("error").is_none(),
        "post-send deadline returned a pre-effect error: {value}"
    );
    assert_eq!(value["result"]["structuredContent"]["receipt"], Value::Null);
    assert_eq!(bus.sends.load(Ordering::SeqCst), 1);
    let (_, status, _) = fixture::request(
        &serving,
        "good-token",
        rpc(
            "tools/call",
            json!({"name":"xmsg_message_status","arguments":{"request_id":"post-send-timeout"}}),
        ),
    )
    .await;
    assert_eq!(
        status["result"]["structuredContent"]["results"][0]["state"], "unknown",
        "{status}"
    );
    assert_eq!(
        bus.sends.load(Ordering::SeqCst),
        1,
        "status duplicated a submitted operation"
    );
}

#[tokio::test]
async fn confirmed_broker_recovery_failures_never_claim_no_submission() {
    use axum::{
        body::{to_bytes, Body},
        http::{Request, StatusCode},
    };
    use tower::ServiceExt;
    use tracing::instrument::WithSubscriber;
    for failure in ["provider", "lookup", "revocation"] {
        let (fixture, bus) = setup().await;
        let serving = Serving::from_owner_file(&fixture.config_file)
            .await
            .unwrap();
        let status = fixture.response_status.clone();
        let file = fixture.store_file.clone();
        let reached = Arc::new(AtomicUsize::new(0));
        let count = reached.clone();
        let barrier = outbound_observer::AtEvent {
            target: "gateway_broker_submission_confirmed",
            action: move || {
                assert_eq!(count.fetch_add(1, Ordering::SeqCst), 0);
                match failure {
                    "provider" => status.store(503, Ordering::SeqCst),
                    "lookup" => rusqlite::Connection::open(&file)
                        .unwrap()
                        .execute_batch(
                            "ALTER TABLE custody_items RENAME TO unavailable_custody_items",
                        )
                        .unwrap(),
                    _ => {
                        Store::open(&file)
                            .unwrap()
                            .set_outbound_policy("grant", 3, &Policy::default())
                            .unwrap();
                    }
                }
            },
        };
        let request=Request::builder().method("POST").uri("/mcp").header("host","gateway.example").header("content-type","application/json").header("authorization","Bearer good-token").body(Body::from(rpc("tools/call",json!({"name":"gist_read","arguments":{"request_id":"confirmed-recovery","id":"abc"}})).to_string())).unwrap();
        let response = serving
            .router()
            .oneshot(request)
            .with_subscriber(barrier)
            .await
            .unwrap();
        let status = response.status();
        let bytes = to_bytes(response.into_body(), 100_000).await.unwrap();
        let value: Value = if bytes.is_empty() {
            Value::Null
        } else {
            serde_json::from_slice(&bytes).unwrap()
        };
        assert_eq!(
            reached.load(Ordering::SeqCst),
            1,
            "confirmed receipt barrier not reached"
        );
        assert_eq!(bus.sends.load(Ordering::SeqCst), 1);
        if failure == "revocation" {
            assert_eq!(
                status,
                StatusCode::FORBIDDEN,
                "revoked authority leaked broker result: {value}"
            );
        } else {
            assert_eq!(
                status,
                StatusCode::OK,
                "confirmed recovery hid pending outcome: {failure} {value}"
            );
            assert_eq!(
                value["result"]["structuredContent"]["state"], "pending",
                "confirmed recovery mislabeled submission: {failure} {value}"
            );
            assert!(
                value.get("error").is_none(),
                "confirmed recovery claimed pre-effect failure: {value}"
            );
        }
    }
}

#[tokio::test]
async fn authorized_ack_deadline_has_body_without_claiming_rollback() {
    use axum::{
        body::{to_bytes, Body},
        http::{Request, StatusCode},
    };
    use tower::ServiceExt;
    use tracing::instrument::WithSubscriber;
    let (fixture, _bus) = setup().await;
    let serving = Arc::new(
        Serving::from_owner_file(&fixture.config_file)
            .await
            .unwrap(),
    );
    let (_, initial, _) = fixture::request(
        &serving,
        "good-token",
        rpc(
            "tools/call",
            json!({"name":"gist_read","arguments":{"request_id":"ack-deadline-setup","id":"abc"}}),
        ),
    )
    .await;
    assert_eq!(
        initial["result"]["structuredContent"]["broker"]["state"],
        "confirmed"
    );
    let entered = Arc::new(AtomicUsize::new(0));
    let reached = entered.clone();
    let release = Arc::new((std::sync::Mutex::new(false), std::sync::Condvar::new()));
    let waiter = release.clone();
    let barrier = outbound_observer::AtEvent {
        target: "gateway_ack_before_commit",
        action: move || {
            reached.store(1, Ordering::SeqCst);
            let (lock, condition) = &*waiter;
            let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
            let mut released = lock.lock().unwrap();
            while !*released {
                let remaining = deadline.saturating_duration_since(std::time::Instant::now());
                assert!(!remaining.is_zero(), "owned ACK barrier was not released");
                released = condition.wait_timeout(released, remaining).unwrap().0;
            }
        },
    };
    let request = Request::builder()
        .method("POST")
        .uri("/mcp")
        .header("host", "gateway.example")
        .header("content-type", "application/json")
        .header("authorization", "Bearer good-token")
        .body(Body::from(
            rpc(
                "tools/call",
                json!({"name":"xmsg_ack","arguments":{"message_id":"result-wire"}}),
            )
            .to_string(),
        ))
        .unwrap();
    tokio::time::pause();
    let clock_guard = tokio::spawn(async {
        loop {
            tokio::task::yield_now().await;
        }
    });
    let handler = tokio::spawn(async move {
        serving
            .router()
            .oneshot(request)
            .with_subscriber(barrier)
            .await
            .unwrap()
    });
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(3);
    while entered.load(Ordering::SeqCst) == 0 {
        assert!(
            std::time::Instant::now() < deadline,
            "authorized ACK did not reach commit barrier"
        );
        tokio::task::yield_now().await;
    }
    tokio::time::advance(std::time::Duration::from_millis(60001)).await;
    let response = handler.await.unwrap();
    let status = response.status();
    let bytes = to_bytes(response.into_body(), 100_000).await.unwrap();
    {
        let (lock, condition) = &*release;
        *lock.lock().unwrap() = true;
        condition.notify_all();
    }
    clock_guard.abort();
    tokio::time::resume();
    let value: Value = if bytes.is_empty() {
        Value::Null
    } else {
        serde_json::from_slice(&bytes).unwrap()
    };
    assert_eq!(
        status,
        StatusCode::OK,
        "authorized ACK deadline omitted JSON-RPC: {value}"
    );
    assert_eq!(value["id"], "broker-rpc");
    assert_eq!(value["error"]["code"], -32004);
    assert!(
        value["error"].get("data").is_none(),
        "ACK timeout claimed rollback: {value}"
    );
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(3);
    loop {
        let count: i64 = rusqlite::Connection::open(&fixture.store_file)
            .unwrap()
            .query_row("SELECT COUNT(*) FROM event_observations", [], |r| r.get(0))
            .unwrap();
        if count == 1 {
            break;
        }
        assert!(
            std::time::Instant::now() < deadline,
            "owned ACK did not commit after response deadline"
        );
        tokio::time::sleep(std::time::Duration::from_millis(5)).await;
    }
}
