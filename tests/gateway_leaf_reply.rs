#![cfg(target_os = "linux")]
#[allow(dead_code)]
#[path = "common/serving_fixture.rs"]
mod fixture;
#[allow(dead_code)]
#[path = "common/provider.rs"]
mod provider;
#[allow(dead_code)]
#[path = "common/real_node.rs"]
mod real_node;
use base64::{engine::general_purpose::STANDARD, Engine};
use serde_json::{json, Value};
use std::{collections::BTreeSet, time::Duration};
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::{UnixListener, UnixStream};
use xmsg_mcp_gateway::{
    event_store::EventKey,
    grants::Store,
    outbound::{Permission, Policy},
    serving::Serving,
};
fn rpc(name: &str, args: Value) -> Value {
    json!({"jsonrpc":"2.0","id":"leaf-reply","method":"tools/call","params":{"name":name,"arguments":args}})
}

const FIRST_CALL_ATTEMPTS: usize = 3;
const FIRST_CALL_WALL_BUDGET: Duration = Duration::from_secs(20);

async fn confirmed_first_call(serving: &Serving, request: Value) -> Value {
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
        assert_eq!(*status, axum::http::StatusCode::OK, "{value}");
        assert!(value.get("error").is_none(), "{value}");
        let state = value["result"]["structuredContent"]["state"].as_str();
        if state == Some("confirmed") {
            return value.clone();
        }
        assert!(
            matches!(state, Some("pending" | "unknown")),
            "unexpected state: {value}"
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

fn self_proc_start() -> String {
    let stat = std::fs::read_to_string(format!("/proc/{}/stat", std::process::id())).unwrap();
    let after_comm = &stat[stat.rfind(')').unwrap() + 1..];
    after_comm.split_whitespace().nth(19).unwrap().to_owned()
}

async fn agent_frame(agent_sock: &std::path::Path, frame: Value) -> Value {
    let stream = UnixStream::connect(agent_sock).await.unwrap();
    let mut stream = BufReader::new(stream);
    stream
        .get_mut()
        .write_all(format!("{frame}\n").as_bytes())
        .await
        .unwrap();
    let mut line = String::new();
    stream.read_line(&mut line).await.unwrap();
    serde_json::from_str(&line).unwrap()
}

#[tokio::test]
#[ignore = "requires the pinned real leaf/hub daemon fixture"]
async fn mcp_leaf_send_reply_enters_owned_custody_with_attested_origin() {
    let binary = real_node::pinned_binary();
    let ca = real_node::Authority::generate();
    let leaf = real_node::Prepared::create("gateway", "leaf", Some(&ca));
    let hub = real_node::Prepared::create("receiver", "hub", Some(&ca));
    leaf.peer(&hub, json!({"principals": null, "targets": null}));
    hub.peer(
        &leaf,
        json!({"leaf":true,"principals":["gateway"],"targets": null}),
    );
    let hub = hub.launch(&binary).await;
    let leaf = leaf.launch_leaf(&binary).await;
    let mut receiver = hub.config.register().await.unwrap();
    let mut setup = fixture::Fixture::new();
    let dir = setup.keys._directory.path();
    for claims in setup.tokens.lock().unwrap().values_mut() {
        claims["scope"] = json!("identity:read events:subscribe");
    }
    setup.config["verifier"]["required_scopes"] = json!(["identity:read", "events:subscribe"]);
    let keyfile = dir.join("events-key");
    fixture::private_file(&keyfile, &[8; 32]);
    let key = EventKey::load(&keyfile).unwrap();
    let mut store = Store::open(&setup.store_file).unwrap();
    store.migrate_custody().unwrap();
    store.migrate_outbound().unwrap();
    store.migrate_retirement().unwrap();
    store.migrate_attachments().unwrap();
    store.migrate_events(&key).unwrap();
    store
        .set_outbound_policy(
            "grant",
            2,
            &Policy {
                send: Some(Permission {
                    targets: BTreeSet::from(["receiver@hub.fixture".into()]),
                    required_scope: "identity:read".into(),
                }),
                reply: None,
            },
        )
        .unwrap();
    drop(store);
    setup.config["request_timeout_ms"] = json!(60000);
    setup.config["events"] =
        json!({"grant_id":"grant","key_file":keyfile,"dispatch_timeout_ms":13000});
    let c = &leaf.config;
    setup.config["messaging"] = json!({"xmsg":{"service":c.service,"expected_node":c.expected_node,"daemon_uid":c.daemon_uid,"register_socket":c.register_socket,"agent_socket":c.agent_socket,"operation_timeout_ms":15000},"manifest":{"reply_ttl_secs":604800,"idempotency_ttl_secs":86400,"svc_queue_cap":100,"dedup_lifetime_secs":3600,"max_framed_bytes":65536},"submission_timeout_ms":fixture::HAPPY_DISPATCH_TIMEOUT_MS,"max_reservations":100,"max_retained_bytes":1048576});
    fixture::private_file(
        &setup.config_file,
        &serde_json::to_vec(&setup.config).unwrap(),
    );
    let serving = setup.serving().await;
    let sent = confirmed_first_call(
        &serving,
        rpc(
            "xmsg_send",
            json!({"request_id":"plain-leaf-read","to":"receiver@hub.fixture","text":"plain transport request"}),
        ),
    )
    .await;
    let original = sent["result"]["structuredContent"]["receipt"]["receipt"]["message_id"]
        .as_str()
        .unwrap()
        .to_owned();
    let delivery = receiver.poll(5).await.unwrap().unwrap();
    assert_eq!(delivery.message_id(), original);
    assert_eq!(delivery.origin().service.as_deref(), Some("gateway"));
    assert_eq!(delivery.origin().node, "leaf.fixture");
    receiver.ack(delivery.message_id()).await.unwrap();
    let reply = receiver
        .reply(
            &original,
            "plain correlated answer",
            Some("plain-reply-key"),
        )
        .await
        .unwrap();
    assert!(reply.pushed_message_id.is_some());
    let observed = tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            let (_, inbox, _) =
                fixture::request(&serving, "good-token", rpc("xmsg_inbox", json!({}))).await;
            if let Some(item) = inbox["result"]["structuredContent"]["items"]
                .as_array()
                .and_then(|items| items.iter().find(|i| i["in_reply_to"] == original))
                .cloned()
            {
                break item;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await;
    let item = observed.unwrap_or_else(|_| {
        panic!(
            "leaf correlated reply absent from owned custody; hub push outcome {:?}",
            reply.push_outcome
        )
    });
    assert_eq!(item["origin"]["service"], "receiver");
    assert_eq!(item["origin"]["node"], "hub.fixture");
    assert!(item["origin"]["id"].is_null());
    assert_eq!(item["mailbox"], "gateway@leaf.fixture");
    assert_eq!(item["preview"], "plain correlated answer");

    // Register a live session (`sess-hub`, label `hub-work`) and subagent (`sess-hub/sub-hub`) on `hub.fixture`.
    let session_sock_path = hub.sessions_dir().join("sess-hub.sock");
    let session_listener = UnixListener::bind(&session_sock_path).unwrap();
    let session_inbox = std::sync::Arc::new(std::sync::Mutex::new(Vec::<String>::new()));
    let inbox_sink = session_inbox.clone();
    tokio::spawn(async move {
        while let Ok((mut stream, _)) = session_listener.accept().await {
            let mut buf = String::new();
            let _ = stream.read_to_string(&mut buf).await;
            inbox_sink.lock().unwrap().push(buf);
        }
    });
    let pid = std::process::id();
    let session_id = "aaaa1111-1111-4111-8111-111111111111";
    let subagent_id = "sub-hub";
    std::fs::write(
        hub.sessions_dir().join(format!("{pid}-{session_id}.json")),
        json!({
            "pid": pid,
            "sessionId": session_id,
            "name": "hub-work",
            "cwd": "/workspace",
            "status": "idle",
            "kind": "interactive",
            "startedAt": 1000,
            "updatedAt": 2000,
            "procStart": self_proc_start(),
            "messagingSocketPath": session_sock_path.display().to_string()
        })
        .to_string(),
    )
    .unwrap();
    let sub_start = std::process::Command::new(&binary)
        .args([
            "register",
            "claude",
            "--hook",
            "--sock",
            hub.config.agent_socket.to_str().unwrap(),
        ])
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .spawn()
        .unwrap();
    {
        use std::io::Write;
        let mut child = sub_start;
        child
            .stdin
            .as_mut()
            .unwrap()
            .write_all(
                json!({
                    "hook_event_name": "SubagentStart",
                    "session_id": session_id,
                    "agent_id": subagent_id,
                    "agent_type": "research"
                })
                .to_string()
                .as_bytes(),
            )
            .unwrap();
        assert!(child.wait().unwrap().success());
    }

    // Have the session on `hub.fixture` send a message to `gateway@leaf.fixture` (at grant revision 3).
    let session_send = agent_frame(
        &hub.config.agent_socket,
        json!({
            "action": "send",
            "to": "gateway@leaf.fixture",
            "text": "inbound from hub session"
        }),
    )
    .await;
    assert_eq!(session_send["status"], "ok", "{session_send}");
    let session_msg_id = session_send["message_id"].as_str().unwrap().to_owned();
    let session_item = tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            let (_, inbox, _) =
                fixture::request(&serving, "good-token", rpc("xmsg_inbox", json!({}))).await;
            if let Some(found) = inbox["result"]["structuredContent"]["items"]
                .as_array()
                .and_then(|items| items.iter().find(|i| i["message_id"] == session_msg_id))
                .cloned()
            {
                break found;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await
    .expect("session inbound message did not arrive in owned custody");
    assert_eq!(session_item["origin"]["id"], session_id);
    assert!(session_item["origin"]["service"].is_null());
    assert_eq!(session_item["origin"]["node"], "hub.fixture");

    // Ruling cell: with `reply.targets = ["receiver@hub.fixture"]` only (revision 4),
    // replying to the session origin on `hub.fixture` is refused.
    {
        let mut store = Store::open(&setup.store_file).unwrap();
        store
            .set_outbound_policy(
                "grant",
                3,
                &Policy {
                    send: Some(Permission {
                        targets: BTreeSet::from(["*@hub.fixture".into()]),
                        required_scope: "identity:read".into(),
                    }),
                    reply: Some(Permission {
                        targets: BTreeSet::from(["receiver@hub.fixture".into()]),
                        required_scope: "identity:read".into(),
                    }),
                },
            )
            .unwrap();
    }
    let session_send_r4 = agent_frame(
        &hub.config.agent_socket,
        json!({
            "action": "send",
            "to": "gateway@leaf.fixture",
            "text": "inbound from hub session at rev 4"
        }),
    )
    .await;
    let session_msg_r4 = session_send_r4["message_id"].as_str().unwrap().to_owned();
    let mut latest_inbox = serde_json::Value::Null;
    tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            let (_, inbox, _) =
                fixture::request(&serving, "good-token", rpc("xmsg_inbox", json!({}))).await;
            latest_inbox = inbox.clone();
            if inbox["result"]["structuredContent"]["items"]
                .as_array()
                .is_some_and(|items| items.iter().any(|i| i["message_id"] == session_msg_r4))
            {
                break;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await
    .unwrap_or_else(|_| {
        panic!(
            "rev4 session mail absent; inbox={latest_inbox}; hub={} leaf={}",
            hub.diagnostics(),
            leaf.diagnostics()
        )
    });
    let (refused_status, refused_reply, _) = fixture::request(
        &serving,
        "good-token",
        rpc(
            "xmsg_reply",
            json!({
                "request_id": "reply-session-under-service-only",
                "message_id": session_msg_r4,
                "text": "must refuse"
            }),
        ),
    )
    .await;
    assert_eq!(
        refused_status,
        axum::http::StatusCode::FORBIDDEN,
        "service-only reply policy admitted session origin: {refused_reply}"
    );

    // Oracle (4): `xmsg_list` with `*@hub.fixture` returns the service, session, and subagent on `hub.fixture`.
    let (list_http, list_val, _) =
        fixture::request(&serving, "good-token", rpc("xmsg_list", json!({}))).await;
    assert_eq!(list_http, axum::http::StatusCode::OK, "{list_val}");
    assert_eq!(
        list_val["result"]["structuredContent"]["recipients"],
        json!([
            {
                "address": format!("{session_id}/{subagent_id}@hub.fixture"),
                "node": "hub.fixture",
                "kind": "subagent",
                "status": "live"
            },
            {
                "address": format!("{session_id}@hub.fixture"),
                "node": "hub.fixture",
                "kind": "instance",
                "status": "live"
            },
            {
                "address": "receiver@hub.fixture",
                "node": "hub.fixture",
                "kind": "service",
                "status": "live"
            }
        ])
    );

    // Oracle (1) + point (b): `xmsg_send` to the live session and live subagent on `hub.fixture` succeeds;
    // Oracle (2): `xmsg_send` to the same session on a non-admitted node is refused.
    let sent_to_session = confirmed_first_call(
        &serving,
        rpc(
            "xmsg_send",
            json!({
                "request_id": "leaf-send-session",
                "to": format!("{session_id}@hub.fixture"),
                "text": "hello real session"
            }),
        ),
    )
    .await;
    assert_eq!(
        sent_to_session["result"]["structuredContent"]["state"],
        "confirmed"
    );
    let sent_to_subagent = confirmed_first_call(
        &serving,
        rpc(
            "xmsg_send",
            json!({
                "request_id": "leaf-send-subagent",
                "to": format!("{session_id}/{subagent_id}@hub.fixture"),
                "text": "hello real subagent"
            }),
        ),
    )
    .await;
    assert_eq!(
        sent_to_subagent["result"]["structuredContent"]["state"],
        "confirmed"
    );
    let (unperm_http, unperm_val, _) = fixture::request(
        &serving,
        "good-token",
        rpc(
            "xmsg_send",
            json!({
                "request_id": "leaf-send-unpermitted-node",
                "to": format!("{session_id}@unpermitted.fixture"),
                "text": "must refuse"
            }),
        ),
    )
    .await;
    assert_eq!(
        unperm_http,
        axum::http::StatusCode::FORBIDDEN,
        "{unperm_val}"
    );

    // Oracle (3): with `reply.targets = ["*@hub.fixture"]` (revision 5), replying to an inbound message
    // from `sess-hub` on `hub.fixture` succeeds and reaches the session.
    {
        let mut store = Store::open(&setup.store_file).unwrap();
        store
            .set_outbound_policy(
                "grant",
                4,
                &Policy {
                    send: Some(Permission {
                        targets: BTreeSet::from(["*@hub.fixture".into()]),
                        required_scope: "identity:read".into(),
                    }),
                    reply: Some(Permission {
                        targets: BTreeSet::from(["*@hub.fixture".into()]),
                        required_scope: "identity:read".into(),
                    }),
                },
            )
            .unwrap();
    }
    let session_send_r5 = agent_frame(
        &hub.config.agent_socket,
        json!({
            "action": "send",
            "to": "gateway@leaf.fixture",
            "text": "inbound from hub session at rev 5"
        }),
    )
    .await;
    let session_msg_r5 = session_send_r5["message_id"].as_str().unwrap().to_owned();
    tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            let (_, inbox, _) =
                fixture::request(&serving, "good-token", rpc("xmsg_inbox", json!({}))).await;
            if inbox["result"]["structuredContent"]["items"]
                .as_array()
                .is_some_and(|items| items.iter().any(|i| i["message_id"] == session_msg_r5))
            {
                break;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await
    .unwrap();
    let replied_to_session = confirmed_first_call(
        &serving,
        rpc(
            "xmsg_reply",
            json!({
                "request_id": "reply-session-wildcard",
                "message_id": session_msg_r5,
                "text": "reply to real hub session"
            }),
        ),
    )
    .await;
    assert_eq!(
        replied_to_session["result"]["structuredContent"]["state"],
        "confirmed"
    );
    tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            if session_inbox
                .lock()
                .unwrap()
                .iter()
                .any(|frame| frame.contains("reply to real hub session"))
            {
                break;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .expect("reply to real hub session did not arrive on session socket");
    let sub_inbox = agent_frame(
        &hub.config.agent_socket,
        json!({
            "action": "inbox",
            "as_agent": subagent_id,
            "wait": 1
        }),
    )
    .await;
    assert_eq!(sub_inbox["status"], "ok", "{sub_inbox}");
    assert!(
        sub_inbox["messages"]
            .as_array()
            .is_some_and(|msgs| msgs.iter().any(|m| m["body"]
                .as_str()
                .is_some_and(|t| t.contains("hello real subagent")))),
        "subagent message not found in subagent inbox: {sub_inbox}"
    );
    // Remove the session fixture so raw agent calls attest the still-registered receiver service.
    std::fs::remove_file(hub.sessions_dir().join(format!("{pid}-{session_id}.json"))).unwrap();
    let outgoing_text = "gateway file: café → receiver";
    let outgoing_binary = [0x00_u8, 0x7f, 0x80, 0xff];
    let sent_file = confirmed_first_call(&serving, rpc("xmsg_send", json!({
        "request_id":"leaf-send-files", "to":"receiver@hub.fixture", "text":"file transport request",
        "attachments":[
            {"name":"outgoing.txt","media_type":"text/plain","text":outgoing_text},
            {"name":"outgoing.bin","media_type":"application/octet-stream","base64":STANDARD.encode(outgoing_binary)}
        ]
    }))).await;
    let sent_file_id = sent_file["result"]["structuredContent"]["receipt"]["receipt"]["message_id"]
        .as_str()
        .unwrap();
    let file_delivery = receiver.poll(5).await.unwrap().unwrap();
    assert_eq!(file_delivery.message_id(), sent_file_id);
    assert_eq!(file_delivery.origin().service.as_deref(), Some("gateway"));
    assert_eq!(file_delivery.origin().node, "leaf.fixture");
    assert_eq!(
        file_delivery.attachments().len(),
        2,
        "receiver lost MCP inline file refs"
    );
    assert_eq!(file_delivery.attachments()[0].name, "outgoing.txt");
    assert_eq!(file_delivery.attachments()[1].name, "outgoing.bin");
    let expected: [&[u8]; 2] = [outgoing_text.as_bytes(), &outgoing_binary];
    for (index, bytes) in expected.into_iter().enumerate() {
        let range = tokio::time::timeout(Duration::from_secs(20), agent_frame(&hub.config.agent_socket,
            json!({"action":"read_attachment","message_id":sent_file_id,"index":index,"offset":0,"length":128})))
            .await.expect("receiver raw attachment read timed out");
        assert_eq!(
            range["status"], "ok",
            "receiver must read files from undialable gateway leaf: {range}"
        );
        let read = match range["encoding"].as_str().unwrap() {
            "utf-8" => range["data"].as_str().unwrap().as_bytes().to_vec(),
            "base64" => STANDARD.decode(range["data"].as_str().unwrap()).unwrap(),
            other => panic!("unsupported actual attachment encoding {other}"),
        };
        assert_eq!(read, bytes, "receiver file bytes changed at index {index}");
    }
    receiver.ack(file_delivery.message_id()).await.unwrap();
    let answer_bytes = [0xfe_u8, 0x00, 0x81, 0x42];
    let staged = receiver
        .agent_client()
        .attach(xmsg::client::AttachRequest {
            name: Some("answer.bin".into()),
            media_type: Some("application/octet-stream".into()),
            data: Some(STANDARD.encode(answer_bytes)),
            ..Default::default()
        })
        .await
        .unwrap();
    let answer_ref: xmsg::client::AttachmentRef =
        serde_json::from_value(staged["attachment"].clone()).unwrap();
    let answer = receiver
        .agent_client()
        .reply_with_attachments(
            sent_file_id,
            "receiver file answer",
            Some("receiver-file-answer"),
            std::slice::from_ref(&answer_ref),
        )
        .await
        .unwrap();
    let answer_id = answer.pushed_message_id.as_deref().unwrap();
    let owned_answer = tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            let (_, inbox, _) =
                fixture::request(&serving, "good-token", rpc("xmsg_inbox", json!({}))).await;
            if let Some(item) = inbox["result"]["structuredContent"]["items"]
                .as_array()
                .and_then(|items| items.iter().find(|item| item["message_id"] == answer_id))
                .cloned()
            {
                break item;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await
    .expect("receiver file reply did not enter gateway owned custody");
    assert_eq!(owned_answer["in_reply_to"], sent_file_id);
    assert_eq!(owned_answer["origin"]["service"], "receiver");
    assert_eq!(owned_answer["origin"]["node"], "hub.fixture");
    assert_eq!(
        owned_answer["attachments"],
        json!([answer_ref]),
        "owned inbox lost reply file refs"
    );
    let (status, read_answer, _) = fixture::request(
        &serving,
        "good-token",
        rpc(
            "xmsg_read_attachment",
            json!({"message_id":answer_id,"index":0,"offset":0,"limit":128}),
        ),
    )
    .await;
    assert_eq!(status, axum::http::StatusCode::OK, "{read_answer}");
    let read_answer = &read_answer["result"]["structuredContent"];
    assert_eq!(read_answer["state"], "found", "{read_answer}");
    assert_eq!(read_answer["encoding"], "base64");
    assert_eq!(
        STANDARD
            .decode(read_answer["data"].as_str().unwrap())
            .unwrap(),
        answer_bytes
    );
    assert_eq!(read_answer["untrusted"], true);

    let followup_text = "gateway replies with a file";
    let file_followup = confirmed_first_call(&serving, rpc("xmsg_reply", json!({
        "request_id":"leaf-reply-files", "message_id":answer_id, "text":"gateway file followup",
        "attachments":[{"name":"followup.txt","media_type":"text/plain","text":followup_text}]
    }))).await;
    let followup_id = file_followup["result"]["structuredContent"]["receipt"]["receipt"]
        ["pushedMessageId"]
        .as_str()
        .unwrap();
    let followup = receiver.poll(5).await.unwrap().unwrap();
    assert_eq!(followup.message_id(), followup_id);
    assert_eq!(followup.in_reply_to(), Some(answer_id));
    assert_eq!(followup.attachments().len(), 1, "MCP reply lost file refs");
    assert_eq!(followup.attachments()[0].name, "followup.txt");
    let followup_read = tokio::time::timeout(Duration::from_secs(20), agent_frame(&hub.config.agent_socket,
        json!({"action":"read_attachment","message_id":followup_id,"index":0,"offset":0,"length":128})))
        .await.expect("receiver followup file read timed out");
    assert_eq!(followup_read["status"], "ok", "{followup_read}");
    assert_eq!(followup_read["data"], followup_text);
    receiver.ack(followup.message_id()).await.unwrap();
    println!("gateway-leaf-reply-complete:mcp-owned-custody-attested-origin");
    println!("gateway-leaf-attachments-complete:bidirectional-files");
}
