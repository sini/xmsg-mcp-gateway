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
            loop {line.clear();if stream.read_line(&mut line).await.unwrap()==0{break;}let frame:Value=serde_json::from_str(&line).unwrap();
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
    fixture.config["messaging"] = json!({"xmsg":{"service":"gateway","expected_node":"bus","daemon_uid":std::fs::metadata(directory).unwrap().uid(),"register_socket":register,"agent_socket":agent,"operation_timeout_ms":1000},"manifest":{"reply_ttl_secs":604800,"idempotency_ttl_secs":604800,"svc_queue_cap":1000,"dedup_lifetime_secs":604800,"max_framed_bytes":65536},"result_recovery_secs":604800,"submission_timeout_ms":1000,"max_reservations":100,"max_retained_bytes":1048576});
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
async fn retired_gist_write_request_id_never_reexecutes() {
    let (fixture, bus) = setup().await;
    let serving = Serving::from_owner_file(&fixture.config_file)
        .await
        .unwrap();
    let request = rpc(
        "tools/call",
        json!({"name":"gist","arguments":{
            "request_id":"retired-write","title":"fixture","body":"","files":{"example":"body"}
        }}),
    );
    let (_, value, _) = fixture::request(&serving, "good-token", request.clone()).await;
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
