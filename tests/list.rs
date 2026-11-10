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
    list_delay: Arc<Mutex<std::time::Duration>>,
    last_list_frame: Arc<Mutex<Option<Value>>>,
    list_response: Arc<Mutex<Value>>,
    sent_frames: Arc<Mutex<Vec<Value>>>,
    reply_frames: Arc<Mutex<Vec<Value>>>,
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
    store.migrate_retirement().unwrap();
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
    let list_delay = Arc::new(Mutex::new(std::time::Duration::ZERO));
    let delay_source = list_delay.clone();
    let sent_frames = Arc::new(Mutex::new(Vec::new()));
    let sent_sink = sent_frames.clone();
    let reply_frames = Arc::new(Mutex::new(Vec::new()));
    let reply_sink = reply_frames.clone();

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
                    let delay = *delay_source.lock().unwrap();
                    if !delay.is_zero() {
                        tokio::time::sleep(delay).await;
                    }
                    *last_frame_sink.lock().unwrap() = Some(frame);
                    response_source.lock().unwrap().clone()
                }
                "send" => {
                    let mut guard = sent_sink.lock().unwrap();
                    let idx = guard.len() + 1;
                    let address = frame["to"].clone();
                    guard.push(frame);
                    json!({
                        "status": "ok",
                        "message_id": format!("01ARZ3NDEKTSV4RRFFQ69G5S{idx:02}"),
                        "address": address,
                        "outcome": "delivered"
                    })
                }
                "reply" => {
                    let mut guard = reply_sink.lock().unwrap();
                    let idx = guard.len() + 1;
                    let message_id = frame["message_id"].clone();
                    let text = frame["text"].clone();
                    guard.push(frame);
                    json!({
                        "status": "ok",
                        "reply": {
                            "seq": idx as i64,
                            "messageId": message_id,
                            "createdAt": 1000 + idx as i64,
                            "replierSessionId": "gateway",
                            "text": text,
                            "pushOutcome": "delivered",
                            "pushedMessageId": format!("01ARZ3NDEKTSV4RRFFQ69G5R{idx:02}")
                        }
                    })
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
            "operation_timeout_ms": fixture::HAPPY_DISPATCH_TIMEOUT_MS
        },
        "manifest": {
            "reply_ttl_secs": 604800,
            "idempotency_ttl_secs": 604800,
            "svc_queue_cap": 1000,
            "dedup_lifetime_secs": 604800,
            "max_framed_bytes": 65536
        },
        "result_recovery_secs": 604800,
        "submission_timeout_ms": fixture::HAPPY_DISPATCH_TIMEOUT_MS,
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
            list_delay,
            last_list_frame,
            list_response,
            sent_frames,
            reply_frames,
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
    assert_eq!(
        list_tool["inputSchema"]["properties"]["within"],
        json!({"type": "integer", "minimum": 1, "maximum": 604800})
    );

    *bus.list_delay.lock().unwrap() = std::time::Duration::from_millis(1500);
    let (status, value, _) = fixture::request(
        &serving,
        "good-token",
        rpc("tools/call", json!({"name": "xmsg_list", "arguments": {}})),
    )
    .await;
    assert_eq!(status, axum::http::StatusCode::OK, "{value}");
    *bus.list_delay.lock().unwrap() = std::time::Duration::ZERO;
    assert!(
        value.get("error").is_none(),
        "delayed read-only list lookup failed: {value}"
    );
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

    *bus.list_response.lock().unwrap() = json!({"status": "error", "code": "internal_error"});
    let (status, value, _) = fixture::request(
        &serving,
        "good-token",
        rpc("tools/call", json!({"name": "xmsg_list", "arguments": {}})),
    )
    .await;
    assert_eq!(status, axum::http::StatusCode::OK, "{value}");
    assert_eq!(value["id"], "list-rpc");
    assert_eq!(value["error"]["code"], -32004);
    assert_eq!(value["error"]["message"], "Tool temporarily unavailable");
    assert!(
        value["error"].get("data").is_none(),
        "read-only xmsg_list unavailable error must not claim a submission status: {value}"
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
        json!({"within": 604801, "status": "inactive"}),
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

#[test]
fn set_outbound_policy_accepts_empty_send_targets_and_refuses_empty_reply_targets() {
    let fixture = fixture::Fixture::new();
    let directory = fixture.keys._directory.path();
    std::fs::set_permissions(directory, std::fs::Permissions::from_mode(0o700)).unwrap();
    let mut store = Store::open(&fixture.store_file).unwrap();
    store.migrate_custody().unwrap();
    store.migrate_outbound().unwrap();
    store.migrate_retirement().unwrap();

    let empty_send_file = directory.join("empty-send-policy.json");
    fixture::private_file(
        &empty_send_file,
        &serde_json::to_vec(&json!({
            "send": {"targets": [], "required_scope": "identity:read"},
            "reply": null
        }))
        .unwrap(),
    );
    let output = std::process::Command::new(env!("CARGO_BIN_EXE_xmsg-mcp-gateway"))
        .arg("--state")
        .arg(&fixture.store_file)
        .args(["set-outbound-policy", "grant", "2"])
        .arg(&empty_send_file)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "set-outbound-policy CLI rejected empty send targets: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(
        String::from_utf8_lossy(&output.stdout).trim(),
        "outbound policy changed at revision 3"
    );

    let empty_reply_file = directory.join("empty-reply-policy.json");
    fixture::private_file(
        &empty_reply_file,
        &serde_json::to_vec(&json!({
            "send": null,
            "reply": {"targets": [], "required_scope": "identity:read"}
        }))
        .unwrap(),
    );
    let refused = std::process::Command::new(env!("CARGO_BIN_EXE_xmsg-mcp-gateway"))
        .arg("--state")
        .arg(&fixture.store_file)
        .args(["set-outbound-policy", "grant", "3"])
        .arg(&empty_reply_file)
        .output()
        .unwrap();
    assert!(
        !refused.status.success(),
        "set-outbound-policy CLI accepted empty reply targets"
    );
    assert!(matches!(
        store.set_outbound_policy(
            "grant",
            3,
            &Policy {
                send: None,
                reply: Some(Permission {
                    targets: BTreeSet::new(),
                    required_scope: "identity:read".into(),
                }),
            },
        ),
        Err(outbound::Error::Configuration)
    ));
}

#[tokio::test]
async fn xmsg_list_with_node_scoped_wildcard_returns_node_sessions_subagents_and_services_only() {
    let policy = Policy {
        send: Some(Permission {
            targets: BTreeSet::from(["*@node".into(), "beta@peer.node".into()]),
            required_scope: "identity:read".into(),
        }),
        reply: Some(Permission {
            targets: BTreeSet::from(["*@node".into()]),
            required_scope: "identity:read".into(),
        }),
    };
    let (fixture, bus) = setup_list_bus(policy).await;
    {
        let mut store = Store::open(&fixture.store_file).unwrap();
        for invalid in [
            "foo*@node",
            "*foo@node",
            "*@*",
            "svc@*",
            "*@node*",
            "@node",
            "svc@",
        ] {
            assert!(
                matches!(
                    store.set_outbound_policy(
                        "grant",
                        3,
                        &Policy {
                            send: Some(Permission {
                                targets: BTreeSet::from([invalid.into()]),
                                required_scope: "identity:read".into(),
                            }),
                            reply: None,
                        },
                    ),
                    Err(outbound::Error::Configuration)
                ),
                "invalid target pattern {invalid} was accepted"
            );
        }
    }
    *bus.list_response.lock().unwrap() = json!({
        "status": "ok",
        "nodes": [
            {"node": "node", "status": "ok"},
            {"node": "peer.node", "status": "ok"},
            {"node": "other.node", "status": "ok"},
            {"node": "down.node", "status": "unreachable: connection refused"}
        ],
        "recipients": [
            {
                "address": "alpha@node",
                "node": "node",
                "kind": "service",
                "harness": "svc",
                "status": "live",
                "user": "alice"
            },
            {
                "address": "session@node",
                "node": "node",
                "kind": "instance",
                "harness": "claude",
                "status": "live",
                "user": "alice",
                "label": "work"
            },
            {
                "address": "session/sub-a@node",
                "node": "node",
                "kind": "subagent",
                "harness": "claude",
                "status": "live",
                "user": "alice",
                "label": "researcher"
            },
            {
                "address": "inactive-session@node",
                "node": "node",
                "kind": "instance",
                "harness": "claude",
                "status": "inactive",
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
                "address": "peer-session@peer.node",
                "node": "peer.node",
                "kind": "instance",
                "harness": "claude",
                "status": "live",
                "user": "bob"
            },
            {
                "address": "other-session@other.node",
                "node": "other.node",
                "kind": "instance",
                "harness": "claude",
                "status": "live",
                "user": "carol"
            },
            {
                "address": "down-session@down.node",
                "node": "down.node",
                "kind": "instance",
                "harness": "claude",
                "status": "live",
                "user": "dave"
            }
        ]
    });
    let serving = Serving::from_owner_file(&fixture.config_file)
        .await
        .unwrap();
    let (status, value, _) = fixture::request(
        &serving,
        "good-token",
        rpc("tools/call", json!({"name": "xmsg_list", "arguments": {}})),
    )
    .await;
    assert_eq!(status, axum::http::StatusCode::OK, "{value}");
    assert_eq!(
        value["result"]["structuredContent"],
        json!({
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
                },
                {
                    "address": "session/sub-a@node",
                    "node": "node",
                    "kind": "subagent",
                    "status": "live"
                },
                {
                    "address": "session@node",
                    "node": "node",
                    "kind": "instance",
                    "status": "live"
                }
            ]
        })
    );

    let (status, instances_only, _) = fixture::request(
        &serving,
        "good-token",
        rpc(
            "tools/call",
            json!({"name": "xmsg_list", "arguments": {"kind": "instance"}}),
        ),
    )
    .await;
    assert_eq!(status, axum::http::StatusCode::OK, "{instances_only}");
    assert_eq!(
        instances_only["result"]["structuredContent"],
        json!({
            "recipients": [
                {
                    "address": "session@node",
                    "node": "node",
                    "kind": "instance",
                    "status": "live"
                }
            ]
        })
    );
}

type RpcResponse = (axum::http::StatusCode, Value, fixture::Probe);
const FIRST_CALL_ATTEMPTS: usize = 3;
const FIRST_CALL_WALL_BUDGET: std::time::Duration = std::time::Duration::from_secs(20);

async fn confirmed_first_call(serving: &Serving, request: Value) -> RpcResponse {
    let started = std::time::Instant::now();
    let mut response = tokio::time::timeout(
        FIRST_CALL_WALL_BUDGET,
        fixture::request(serving, "good-token", request.clone()),
    )
    .await
    .expect("first-call confirmation wall budget exhausted");
    for attempt in 0..FIRST_CALL_ATTEMPTS {
        assert!(
            started.elapsed() < FIRST_CALL_WALL_BUDGET,
            "first-call confirmation wall budget exhausted"
        );
        let (status, value, _) = &response;
        assert_eq!(
            *status,
            axum::http::StatusCode::OK,
            "first-call transport refusal: {value}"
        );
        assert_eq!(value["id"], request["id"], "first-call response id changed");
        assert!(
            value.get("error").is_none(),
            "first-call RPC failure: {value}"
        );
        let result = &value["result"]["structuredContent"];
        if result["state"] == "confirmed" {
            return response;
        }
        assert!(
            matches!(result["state"].as_str(), Some("pending" | "unknown")),
            "first-call unexpected state: {value}"
        );
        assert!(
            attempt + 1 < FIRST_CALL_ATTEMPTS,
            "first-call confirmation attempts exhausted: {value}"
        );
        let remaining = FIRST_CALL_WALL_BUDGET
            .checked_sub(started.elapsed())
            .expect("first-call confirmation wall budget exhausted");
        response = tokio::time::timeout(
            remaining,
            fixture::request(serving, "good-token", request.clone()),
        )
        .await
        .expect("first-call confirmation wall budget exhausted");
    }
    unreachable!("fixed attempt loop returns or fails")
}

#[tokio::test]
async fn node_scoped_targets_send_to_sessions_and_subagents_and_enforce_reply_origin_policy() {
    let policy = Policy {
        send: Some(Permission {
            targets: BTreeSet::from(["*@sini.bitstream".into(), "genie@sini.other".into()]),
            required_scope: "identity:read".into(),
        }),
        reply: Some(Permission {
            targets: BTreeSet::from(["genie@sini.bitstream".into()]),
            required_scope: "identity:read".into(),
        }),
    };
    let (fixture, bus) = setup_list_bus(policy).await;
    *bus.list_response.lock().unwrap() = json!({
        "status": "ok",
        "nodes": [
            {"node": "sini.bitstream", "status": "ok"},
            {"node": "sini.other", "status": "ok"},
            {"node": "sini.unpermitted", "status": "ok"}
        ],
        "recipients": [
            {
                "address": "genie@sini.bitstream",
                "node": "sini.bitstream",
                "kind": "service",
                "harness": "svc",
                "status": "live",
                "user": "sini"
            },
            {
                "address": "sess-1@sini.bitstream",
                "node": "sini.bitstream",
                "kind": "instance",
                "harness": "claude",
                "status": "live",
                "user": "sini",
                "label": "work"
            },
            {
                "address": "sess-1/sub-a@sini.bitstream",
                "node": "sini.bitstream",
                "kind": "subagent",
                "harness": "claude",
                "status": "live",
                "user": "sini",
                "label": "researcher"
            },
            {
                "address": "sess-2@sini.bitstream",
                "node": "sini.bitstream",
                "kind": "instance",
                "harness": "claude",
                "status": "live",
                "user": "sini",
                "label": "dup-label"
            },
            {
                "address": "sess-3@sini.bitstream",
                "node": "sini.bitstream",
                "kind": "instance",
                "harness": "claude",
                "status": "live",
                "user": "sini",
                "label": "dup-label"
            },
            {
                "address": "genie@sini.other",
                "node": "sini.other",
                "kind": "service",
                "harness": "svc",
                "status": "live",
                "user": "sini"
            },
            {
                "address": "sess-1@sini.other",
                "node": "sini.other",
                "kind": "instance",
                "harness": "claude",
                "status": "live",
                "user": "sini",
                "label": "work"
            },
            {
                "address": "sess-1@sini.unpermitted",
                "node": "sini.unpermitted",
                "kind": "instance",
                "harness": "claude",
                "status": "live",
                "user": "sini",
                "label": "work"
            }
        ]
    });

    {
        let sql = rusqlite::Connection::open(&fixture.store_file).unwrap();
        let owner = fixture.binding.subject.as_str();
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;
        for (upstream_id, origin_json) in [
            (
                "01ARZ3NDEKTSV4RRFFQ69G5M01",
                json!({"id": "sess-1", "service": null, "node": "sini.bitstream"}).to_string(),
            ),
            (
                "01ARZ3NDEKTSV4RRFFQ69G5M02",
                json!({"id": "sess-1/sub-a", "service": null, "node": "sini.bitstream"})
                    .to_string(),
            ),
            (
                "01ARZ3NDEKTSV4RRFFQ69G5M03",
                json!({"id": "sess-1", "service": null, "node": "sini.unpermitted"}).to_string(),
            ),
            (
                "01ARZ3NDEKTSV4RRFFQ69G5M04",
                json!({"id": null, "service": "genie", "node": "sini.bitstream"}).to_string(),
            ),
        ] {
            for revision in [3i64, 4i64] {
                let id_for_rev = if revision == 3 {
                    upstream_id.to_string()
                } else {
                    format!("{upstream_id}-r4")
                };
                sql.execute(
                    "INSERT INTO custody_items (bus,upstream_id,event_id,grant_id,grant_revision,mailbox,owner,origin,text,envelope,in_reply_to,fingerprint,received_at,expires_at,held) VALUES ('bus',?1,?2,'grant',?3,'gateway@bus',?4,?5,'inbound text','{}',NULL,?6,?7,?8,1)",
                    rusqlite::params![
                        id_for_rev,
                        format!("ev-{id_for_rev}"),
                        revision,
                        owner,
                        origin_json,
                        format!("fp-{id_for_rev}"),
                        now,
                        now + 86400
                    ],
                )
                .unwrap();
            }
        }
    }

    let serving = Serving::from_owner_file(&fixture.config_file)
        .await
        .unwrap();

    // Oracle (1) + point (b): send to live session (by ID and by unique label) and to live subagent
    // (`<parent-id>/<child>@<node>` and `<parent-label>/<child>@<node>`) on admitted `*@sini.bitstream`,
    // plus exact service `genie@sini.other` (Oracle 5).
    for (req_id, to, body) in [
        (
            "send-session-id",
            "sess-1@sini.bitstream",
            "hello session id",
        ),
        (
            "send-session-label",
            "work@sini.bitstream",
            "hello session label",
        ),
        (
            "send-subagent-id",
            "sess-1/sub-a@sini.bitstream",
            "hello subagent id",
        ),
        (
            "send-subagent-label",
            "work/sub-a@sini.bitstream",
            "hello subagent via parent label",
        ),
        (
            "send-exact-service",
            "genie@sini.other",
            "hello exact service",
        ),
    ] {
        let before = bus.sent_frames.lock().unwrap().len();
        let (_, sent, _) = confirmed_first_call(
            &serving,
            rpc(
                "tools/call",
                json!({
                    "name": "xmsg_send",
                    "arguments": {"request_id": req_id, "to": to, "text": body}
                }),
            ),
        )
        .await;
        assert_eq!(sent["result"]["structuredContent"]["state"], "confirmed");
        let frames = bus.sent_frames.lock().unwrap();
        assert_eq!(frames.len(), before + 1);
        assert_eq!(frames.last().unwrap()["to"], to);
        assert!(frames.last().unwrap()["text"]
            .as_str()
            .unwrap()
            .ends_with(body));
    }

    // Ambiguous label on admitted node (`dup-label@sini.bitstream`) and Oracle (2): same session on
    // non-admitted node (`sess-1@sini.unpermitted`) or on node with only exact service policy
    // (`sess-1@sini.other`) are refused with no bus send.
    let sent_before_refusals = bus.sent_frames.lock().unwrap().len();
    for (req_id, refused_to) in [
        ("send-ambiguous-label", "dup-label@sini.bitstream"),
        ("send-unpermitted-node", "sess-1@sini.unpermitted"),
        ("send-unpermitted-label", "work@sini.unpermitted"),
        ("send-unpermitted-subagent", "sess-1/sub-a@sini.unpermitted"),
        ("send-session-on-service-only-node", "sess-1@sini.other"),
    ] {
        let (status, value, _) = fixture::request(
            &serving,
            "good-token",
            rpc(
                "tools/call",
                json!({
                    "name": "xmsg_send",
                    "arguments": {"request_id": req_id, "to": refused_to, "text": "must refuse"}
                }),
            ),
        )
        .await;
        assert_eq!(
            status,
            axum::http::StatusCode::FORBIDDEN,
            "target {refused_to} was not refused: {value}"
        );
    }
    assert_eq!(
        bus.sent_frames.lock().unwrap().len(),
        sent_before_refusals,
        "refused sends must not publish to agent.sock"
    );

    // Oracle (3) ruling cell: with `reply.targets = ["genie@sini.bitstream"]` only (revision 2),
    // a reply to a session origin or subagent origin on `sini.bitstream` is refused, whereas a
    // reply to the exact service `genie@sini.bitstream` is admitted.
    for (req_id, msg_id) in [
        (
            "reply-session-under-service-policy",
            "01ARZ3NDEKTSV4RRFFQ69G5M01",
        ),
        (
            "reply-subagent-under-service-policy",
            "01ARZ3NDEKTSV4RRFFQ69G5M02",
        ),
    ] {
        let (status, value, _) = fixture::request(
            &serving,
            "good-token",
            rpc(
                "tools/call",
                json!({
                    "name": "xmsg_reply",
                    "arguments": {"request_id": req_id, "message_id": msg_id, "text": "must refuse"}
                }),
            ),
        )
        .await;
        assert_eq!(
            status,
            axum::http::StatusCode::FORBIDDEN,
            "exact service reply policy admitted session origin {msg_id}: {value}"
        );
    }
    assert_eq!(bus.reply_frames.lock().unwrap().len(), 0);

    let (_, exact_reply, _) = confirmed_first_call(
        &serving,
        rpc(
            "tools/call",
            json!({
                "name": "xmsg_reply",
                "arguments": {
                    "request_id": "reply-exact-service",
                    "message_id": "01ARZ3NDEKTSV4RRFFQ69G5M04",
                    "text": "allowed service reply"
                }
            }),
        ),
    )
    .await;
    assert_eq!(
        exact_reply["result"]["structuredContent"]["state"],
        "confirmed"
    );
    assert_eq!(bus.reply_frames.lock().unwrap().len(), 1);

    // Switch reply policy to `["*@sini.bitstream"]` (revision 4): replies to session and subagent
    // origins on `sini.bitstream` succeed, while a reply to a session origin on `sini.unpermitted`
    // is refused.
    {
        let mut store = Store::open(&fixture.store_file).unwrap();
        store
            .set_outbound_policy(
                "grant",
                3,
                &Policy {
                    send: Some(Permission {
                        targets: BTreeSet::from([
                            "*@sini.bitstream".into(),
                            "genie@sini.other".into(),
                        ]),
                        required_scope: "identity:read".into(),
                    }),
                    reply: Some(Permission {
                        targets: BTreeSet::from(["*@sini.bitstream".into()]),
                        required_scope: "identity:read".into(),
                    }),
                },
            )
            .unwrap();
    }

    for (req_id, msg_id) in [
        ("reply-session-admitted", "01ARZ3NDEKTSV4RRFFQ69G5M01-r4"),
        ("reply-subagent-admitted", "01ARZ3NDEKTSV4RRFFQ69G5M02-r4"),
    ] {
        let before = bus.reply_frames.lock().unwrap().len();
        let (_, replied, _) = confirmed_first_call(
            &serving,
            rpc(
                "tools/call",
                json!({
                    "name": "xmsg_reply",
                    "arguments": {"request_id": req_id, "message_id": msg_id, "text": "hello back"}
                }),
            ),
        )
        .await;
        assert_eq!(replied["result"]["structuredContent"]["state"], "confirmed");
        let frames = bus.reply_frames.lock().unwrap();
        assert_eq!(frames.len(), before + 1);
        assert_eq!(frames.last().unwrap()["message_id"], msg_id);
    }

    let replies_before_refusal = bus.reply_frames.lock().unwrap().len();
    let (status, value, _) = fixture::request(
        &serving,
        "good-token",
        rpc(
            "tools/call",
            json!({
                "name": "xmsg_reply",
                "arguments": {
                    "request_id": "reply-session-unpermitted",
                    "message_id": "01ARZ3NDEKTSV4RRFFQ69G5M03-r4",
                    "text": "must refuse"
                }
            }),
        ),
    )
    .await;
    assert_eq!(
        status,
        axum::http::StatusCode::FORBIDDEN,
        "session reply on unpermitted node was not refused: {value}"
    );
    assert_eq!(
        bus.reply_frames.lock().unwrap().len(),
        replies_before_refusal
    );
}
