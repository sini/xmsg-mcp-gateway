#[allow(dead_code)]
#[path = "common/serving_fixture.rs"]
mod fixture;
#[allow(dead_code)]
#[path = "common/provider.rs"]
mod provider;

use serde_json::{json, Value};
use std::collections::BTreeSet;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::UnixListener;
use xmsg::client::ListResult;
use xmsg_mcp_gateway::{
    grants::Store,
    outbound::{self, ListArguments, Permission, Policy},
    serving::Serving,
};

struct ListBus {
    tasks: Vec<tokio::task::JoinHandle<()>>,
    list_calls: Arc<AtomicUsize>,
    last_list_frame: Arc<Mutex<Option<Value>>>,
    list_response: Arc<Mutex<Value>>,
}

impl Drop for ListBus {
    fn drop(&mut self) {
        for task in &self.tasks {
            task.abort();
        }
    }
}

async fn setup_list_bus(policy: Policy) -> (fixture::Fixture, ListBus) {
    let mut fixture = fixture::Fixture::new();
    let directory = fixture.keys._directory.path();
    std::fs::set_permissions(directory, std::fs::Permissions::from_mode(0o700)).unwrap();
    let mut store = Store::open(&fixture.store_file).unwrap();
    store.migrate_custody().unwrap();
    store.migrate_outbound().unwrap();
    store.set_outbound_policy("grant", 2, &policy).unwrap();

    let register = directory.join("register.sock");
    let agent = directory.join("agent.sock");
    let service_listener = UnixListener::bind(&register).unwrap();
    let agent_listener = UnixListener::bind(&agent).unwrap();
    for socket in [&register, &agent] {
        std::fs::set_permissions(socket, std::fs::Permissions::from_mode(0o600)).unwrap();
    }

    let service_task = tokio::spawn(async move {
        let mut children = tokio::task::JoinSet::new();
        loop {
            let (stream, _) = service_listener.accept().await.unwrap();
            children.spawn(async move {
                let mut stream = BufReader::new(stream);
                let mut line = String::new();
                stream.read_line(&mut line).await.unwrap();
                stream
                    .get_mut()
                    .write_all(
                        format!(
                            "{}\n",
                            json!({
                                "status": "ok",
                                "address": "gateway@bus",
                                "node": "bus",
                                "reply_ttl_secs": 604800,
                                "idempotency_ttl_secs": 604800,
                                "svc_queue_cap": 1000,
                                "max_body_bytes": 65536
                            })
                        )
                        .as_bytes(),
                    )
                    .await
                    .unwrap();
                loop {
                    line.clear();
                    if stream.read_line(&mut line).await.unwrap() == 0 {
                        break;
                    }
                    let frame: Value = serde_json::from_str(&line).unwrap();
                    let response = match frame["action"].as_str().unwrap() {
                        "poll" => json!({"action": "timeout"}),
                        "ack" => json!({"status": "ok"}),
                        other => panic!("unexpected service action {other}"),
                    };
                    stream
                        .get_mut()
                        .write_all(format!("{response}\n").as_bytes())
                        .await
                        .unwrap();
                }
            });
        }
    });

    let list_calls = Arc::new(AtomicUsize::new(0));
    let list_calls_counter = list_calls.clone();
    let last_list_frame = Arc::new(Mutex::new(None));
    let last_frame_sink = last_list_frame.clone();
    let list_response = Arc::new(Mutex::new(json!({
        "status": "ok",
        "nodes": [
            {"node": "node", "status": "ok"},
            {"node": "peer.node", "status": "ok"},
            {"node": "down.node", "status": "unreachable: connection refused"}
        ],
        "recipients": [
            {
                "address": "alpha@node",
                "node": "node",
                "kind": "service",
                "harness": "svc",
                "status": "live",
                "user": "alice",
                "label": "internal-label"
            },
            {
                "address": "beta@peer.node",
                "node": "peer.node",
                "kind": "service",
                "harness": "svc",
                "status": "live",
                "user": "bob"
            },
            {
                "address": "unpermitted@node",
                "node": "node",
                "kind": "service",
                "harness": "svc",
                "status": "live",
                "user": "mallory"
            },
            {
                "address": "session@node",
                "node": "node",
                "kind": "instance",
                "harness": "claude",
                "status": "live",
                "user": "alice"
            }
        ]
    })));
    let response_source = list_response.clone();

    let agent_task = tokio::spawn(async move {
        loop {
            let (stream, _) = agent_listener.accept().await.unwrap();
            let mut stream = BufReader::new(stream);
            let mut line = String::new();
            stream.read_line(&mut line).await.unwrap();
            let frame: Value = serde_json::from_str(&line).unwrap();
            let response = match frame["action"].as_str().unwrap() {
                "list" => {
                    list_calls_counter.fetch_add(1, Ordering::SeqCst);
                    *last_frame_sink.lock().unwrap() = Some(frame);
                    response_source.lock().unwrap().clone()
                }
                other => panic!("unexpected agent action {other}"),
            };
            stream
                .get_mut()
                .write_all(format!("{response}\n").as_bytes())
                .await
                .unwrap();
        }
    });

    fixture.config["request_timeout_ms"] = json!(60000);
    fixture.config["messaging"] = json!({
        "xmsg": {
            "service": "gateway",
            "expected_node": "bus",
            "daemon_uid": std::fs::metadata(directory).unwrap().uid(),
            "register_socket": register,
            "agent_socket": agent,
            "operation_timeout_ms": 1000
        },
        "manifest": {
            "reply_ttl_secs": 604800,
            "idempotency_ttl_secs": 604800,
            "svc_queue_cap": 1000,
            "dedup_lifetime_secs": 604800,
            "max_framed_bytes": 65536
        },
        "submission_timeout_ms": 1000,
        "max_reservations": 100,
        "max_retained_bytes": 1048576
    });
    fixture::private_file(
        &fixture.config_file,
        &serde_json::to_vec(&fixture.config).unwrap(),
    );
    (
        fixture,
        ListBus {
            tasks: vec![service_task, agent_task],
            list_calls,
            last_list_frame,
            list_response,
        },
    )
}

fn rpc(method: &str, params: Value) -> Value {
    json!({"jsonrpc": "2.0", "id": "list-rpc", "method": method, "params": params})
}

#[tokio::test]
async fn xmsg_list_returns_only_permitted_send_targets_with_live_status_and_never_unpermitted() {
    let policy = Policy {
        send: Some(Permission {
            targets: BTreeSet::from(["alpha@node".into(), "beta@peer.node".into()]),
            required_scope: "identity:read".into(),
        }),
        reply: None,
    };
    let (fixture, bus) = setup_list_bus(policy).await;
    let serving = Serving::from_owner_file(&fixture.config_file)
        .await
        .unwrap();

    let (status, tools_value, _) =
        fixture::request(&serving, "good-token", rpc("tools/list", json!({}))).await;
    assert_eq!(status, axum::http::StatusCode::OK);
    let tools = tools_value["result"]["tools"].as_array().unwrap();
    let list_tool = tools
        .iter()
        .find(|tool| tool["name"] == "xmsg_list")
        .expect("xmsg_list tool must be advertised when send scope is held");
    assert_eq!(list_tool["inputSchema"]["additionalProperties"], false);

    let (status, value, _) = fixture::request(
        &serving,
        "good-token",
        rpc("tools/call", json!({"name": "xmsg_list", "arguments": {}})),
    )
    .await;
    assert_eq!(status, axum::http::StatusCode::OK, "{value}");
    assert_eq!(bus.list_calls.load(Ordering::SeqCst), 1);
    let structured = &value["result"]["structuredContent"];
    assert!(
        structured.get("nodes").is_none(),
        "xmsg_list must never expose fleet or node metadata: {structured}"
    );
    assert_eq!(
        structured,
        &json!({
            "recipients": [
                {
                    "address": "alpha@node",
                    "node": "node",
                    "kind": "service",
                    "status": "live"
                },
                {
                    "address": "beta@peer.node",
                    "node": "peer.node",
                    "kind": "service",
                    "status": "live"
                }
            ]
        })
    );

    *bus.list_response.lock().unwrap() = json!({
        "status": "ok",
        "nodes": [
            {"node": "node", "status": "ok"},
            {"node": "peer.node", "status": "unreachable: peer offline"}
        ],
        "recipients": [
            {
                "address": "alpha@node",
                "node": "node",
                "kind": "service",
                "harness": "svc",
                "status": "inactive",
                "last_seen": 120,
                "user": "alice"
            },
            {
                "address": "beta@peer.node",
                "node": "peer.node",
                "kind": "service",
                "harness": "svc",
                "status": "live",
                "user": "bob"
            },
            {
                "address": "unpermitted@node",
                "node": "node",
                "kind": "service",
                "harness": "svc",
                "status": "live",
                "user": "mallory"
            }
        ]
    });

    let (status, value, _) = fixture::request(
        &serving,
        "good-token",
        rpc("tools/call", json!({"name": "xmsg_list", "arguments": {}})),
    )
    .await;
    assert_eq!(status, axum::http::StatusCode::OK, "{value}");
    assert_eq!(
        value["result"]["structuredContent"],
        json!({"recipients": []})
    );
}

#[tokio::test]
async fn xmsg_list_empty_policy_returns_empty_without_node_metadata() {
    let listed: ListResult = serde_json::from_value(json!({
        "nodes": [{"node": "node", "status": "ok"}],
        "recipients": [{
            "address": "alpha@node",
            "node": "node",
            "kind": "service",
            "harness": "svc",
            "status": "live",
            "user": "alice",
            "label": "secret"
        }]
    }))
    .unwrap();
    let filtered =
        outbound::filter_recipients(&Policy::default(), &ListArguments::default(), listed).unwrap();
    let serialized = serde_json::to_value(&filtered).unwrap();
    assert_eq!(serialized, json!({"recipients": []}));
    assert!(serialized.get("nodes").is_none());

    let empty_targets_policy = Policy {
        send: Some(Permission {
            targets: BTreeSet::new(),
            required_scope: "identity:read".into(),
        }),
        reply: None,
    };
    let (fixture, bus) = setup_list_bus(empty_targets_policy).await;
    let serving = Serving::from_owner_file(&fixture.config_file)
        .await
        .unwrap();

    let (_, tools_value, _) =
        fixture::request(&serving, "good-token", rpc("tools/list", json!({}))).await;
    let tool_names: Vec<&str> = tools_value["result"]["tools"]
        .as_array()
        .unwrap()
        .iter()
        .map(|tool| tool["name"].as_str().unwrap())
        .collect();
    assert!(tool_names.contains(&"xmsg_list"));
    assert!(!tool_names.contains(&"xmsg_send"));

    let (status, value, _) = fixture::request(
        &serving,
        "good-token",
        rpc("tools/call", json!({"name": "xmsg_list", "arguments": {}})),
    )
    .await;
    assert_eq!(status, axum::http::StatusCode::OK, "{value}");
    assert_eq!(bus.list_calls.load(Ordering::SeqCst), 1);
    assert_eq!(
        value["result"]["structuredContent"],
        json!({"recipients": []})
    );
    assert!(value["result"]["structuredContent"].get("nodes").is_none());
}

#[tokio::test]
async fn xmsg_list_is_not_advertised_or_callable_without_send_scope() {
    let unpermitted_scope_policy = Policy {
        send: Some(Permission {
            targets: BTreeSet::from(["alpha@node".into()]),
            required_scope: "unconfigured:write".into(),
        }),
        reply: Some(Permission {
            targets: BTreeSet::from(["alpha@node".into()]),
            required_scope: "identity:read".into(),
        }),
    };
    let (fixture, bus) = setup_list_bus(unpermitted_scope_policy).await;
    let serving = Serving::from_owner_file(&fixture.config_file)
        .await
        .unwrap();

    let (status, tools_value, _) =
        fixture::request(&serving, "good-token", rpc("tools/list", json!({}))).await;
    assert_eq!(status, axum::http::StatusCode::OK);
    let tool_names: Vec<&str> = tools_value["result"]["tools"]
        .as_array()
        .unwrap()
        .iter()
        .map(|tool| tool["name"].as_str().unwrap())
        .collect();
    assert!(
        !tool_names.contains(&"xmsg_list"),
        "xmsg_list must not be advertised without send scope: {tool_names:?}"
    );
    assert!(tool_names.contains(&"xmsg_reply"));

    let (status, _, _) = fixture::request(
        &serving,
        "good-token",
        rpc("tools/call", json!({"name": "xmsg_list", "arguments": {}})),
    )
    .await;
    assert_eq!(status, axum::http::StatusCode::FORBIDDEN);
    assert_eq!(bus.list_calls.load(Ordering::SeqCst), 0);

    let mut store = Store::open(&fixture.store_file).unwrap();
    store
        .set_outbound_policy(
            "grant",
            3,
            &Policy {
                send: None,
                reply: Some(Permission {
                    targets: BTreeSet::from(["alpha@node".into()]),
                    required_scope: "identity:read".into(),
                }),
            },
        )
        .unwrap();
    let (status, tools_value, _) =
        fixture::request(&serving, "good-token", rpc("tools/list", json!({}))).await;
    assert_eq!(status, axum::http::StatusCode::OK);
    assert!(!tools_value["result"]["tools"]
        .as_array()
        .unwrap()
        .iter()
        .any(|tool| tool["name"] == "xmsg_list"));
    let (status, _, _) = fixture::request(
        &serving,
        "good-token",
        rpc("tools/call", json!({"name": "xmsg_list", "arguments": {}})),
    )
    .await;
    assert_eq!(status, axum::http::StatusCode::FORBIDDEN);
    assert_eq!(bus.list_calls.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn xmsg_list_filters_only_narrow_and_never_widen_policy_targets() {
    let policy = Policy {
        send: Some(Permission {
            targets: BTreeSet::from(["alpha@node".into(), "beta@peer.node".into()]),
            required_scope: "identity:read".into(),
        }),
        reply: None,
    };
    let (fixture, bus) = setup_list_bus(policy).await;
    let serving = Serving::from_owner_file(&fixture.config_file)
        .await
        .unwrap();

    let (status, value, _) = fixture::request(
        &serving,
        "good-token",
        rpc(
            "tools/call",
            json!({"name": "xmsg_list", "arguments": {"node": "peer.node"}}),
        ),
    )
    .await;
    assert_eq!(status, axum::http::StatusCode::OK, "{value}");
    assert_eq!(
        bus.last_list_frame.lock().unwrap().as_ref().unwrap()["node"],
        "peer.node"
    );
    assert_eq!(
        value["result"]["structuredContent"],
        json!({
            "recipients": [
                {
                    "address": "beta@peer.node",
                    "node": "peer.node",
                    "kind": "service",
                    "status": "live"
                }
            ]
        })
    );

    for empty_filter in [
        json!({"node": "other.node"}),
        json!({"kind": "instance"}),
        json!({"kind": "subagent"}),
        json!({"status": "inactive"}),
        json!({"status": "inactive", "within": 86400}),
    ] {
        let (status, value, _) = fixture::request(
            &serving,
            "good-token",
            rpc(
                "tools/call",
                json!({"name": "xmsg_list", "arguments": empty_filter}),
            ),
        )
        .await;
        assert_eq!(status, axum::http::StatusCode::OK, "{value}");
        assert_eq!(
            value["result"]["structuredContent"],
            json!({"recipients": []}),
            "filter {empty_filter} must only narrow and never widen"
        );
    }

    for matching_filter in [json!({"kind": "service"}), json!({"status": "live"})] {
        let (status, value, _) = fixture::request(
            &serving,
            "good-token",
            rpc(
                "tools/call",
                json!({"name": "xmsg_list", "arguments": matching_filter}),
            ),
        )
        .await;
        assert_eq!(status, axum::http::StatusCode::OK, "{value}");
        assert_eq!(
            value["result"]["structuredContent"]["recipients"]
                .as_array()
                .unwrap()
                .len(),
            2
        );
    }

    for invalid_arguments in [
        json!({"name": "alpha"}),
        json!({"node": "bad node"}),
        json!({"kind": "unknown"}),
        json!({"status": "unknown"}),
        json!({"within": 0}),
        json!({"within": 86400, "status": "live"}),
    ] {
        let (status, value, _) = fixture::request(
            &serving,
            "good-token",
            rpc(
                "tools/call",
                json!({"name": "xmsg_list", "arguments": invalid_arguments}),
            ),
        )
        .await;
        assert_eq!(status, axum::http::StatusCode::OK);
        assert_eq!(
            value["error"]["code"], -32602,
            "invalid arguments {invalid_arguments} should be rejected with -32602: {value}"
        );
    }
}
