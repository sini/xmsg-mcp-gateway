use super::*;
use crate::custody;
use crate::event_callback_fixture as http_callback;
use crate::events_test_support::{fixture, Setup};
use std::collections::VecDeque;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::sync::{Arc, Mutex};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::UnixListener;

struct Bus {
    pending: Arc<Mutex<VecDeque<Value>>>,
    acked: Arc<Mutex<Vec<String>>>,
    handle: tokio::task::JoinHandle<()>,
}
impl Drop for Bus {
    fn drop(&mut self) {
        self.handle.abort();
    }
}
fn rpc(method: &str, params: Value) -> Value {
    json!({"jsonrpc":"2.0","id":"event-request","method":method,"params":params})
}
async fn call(serving: &Serving, method: &str, params: Value) -> Value {
    let (status, value, _) = fixture::request(serving, "good-token", rpc(method, params)).await;
    assert_eq!(status, StatusCode::OK, "{value}");
    assert_eq!(
        value["id"], "event-request",
        "Events changed JSON-RPC request ID"
    );
    assert!(value.get("error").is_none(), "{value}");
    value["result"].clone()
}
async fn start_bus(setup: &mut Setup) -> Bus {
    crate::grants::Store::open(&setup.provider.store_file)
        .unwrap()
        .migrate_retirement()
        .unwrap();
    let directory = setup.provider.keys._directory.path();
    std::fs::set_permissions(directory, std::fs::Permissions::from_mode(0o700)).unwrap();
    let socket = directory.join("register.sock");
    let listener = UnixListener::bind(&socket).unwrap();
    std::fs::set_permissions(&socket, std::fs::Permissions::from_mode(0o600)).unwrap();
    let pending = Arc::new(Mutex::new(VecDeque::new()));
    let acked = Arc::new(Mutex::new(Vec::new()));
    let queued = pending.clone();
    let acknowledgements = acked.clone();
    let file = setup.provider.store_file.clone();
    let handle = tokio::spawn(async move {
        let mut connections = tokio::task::JoinSet::new();
        loop {
            tokio::select! {
                accepted=listener.accept()=>{
                    let (stream,_)=accepted.unwrap();let queued=queued.clone();let acknowledgements=acknowledgements.clone();let file=file.clone();
                    connections.spawn(async move {
                        let mut stream=BufReader::new(stream);let mut line=String::new();stream.read_line(&mut line).await.unwrap();
                        let registration:Value=serde_json::from_str(&line).unwrap();assert_eq!(registration["harness"],"svc");assert_eq!(registration["name"],"gateway");
                        let ready=json!({"status":"ok","address":"gateway@bus","node":"bus","reply_ttl_secs":604800,"idempotency_ttl_secs":604800,"svc_queue_cap":1000,"max_body_bytes":65536});
                        stream.get_mut().write_all(format!("{ready}\n").as_bytes()).await.unwrap();
                        loop {
                            line.clear();if stream.read_line(&mut line).await.unwrap()==0 {break;}
                            let frame:Value=serde_json::from_str(&line).unwrap();
                            let reply=match frame["action"].as_str().unwrap() {
                                "poll"=>queued.lock().unwrap().front().cloned().unwrap_or(json!({"action":"timeout"})),
                                "ack"=>{
                                    let message=frame["messageId"].as_str().unwrap();
                                    // A separate connection can see only committed custody/outbox data.
                                    let db=rusqlite::Connection::open(&file).unwrap();
                                    let committed:i64=db.query_row("SELECT COUNT(*) FROM custody_items c JOIN custody_outbox b ON b.event_id=c.event_id WHERE c.upstream_id=?1 AND c.text IS NOT NULL",[message],|row|row.get(0)).unwrap();assert_eq!(committed,1,"upstream ACK preceded custody commit");
                                    acknowledgements.lock().unwrap().push(message.to_owned());queued.lock().unwrap().pop_front();json!({"status":"ok"})
                                },other=>panic!("unexpected service frame {other}"),
                            };
                            stream.get_mut().write_all(format!("{reply}\n").as_bytes()).await.unwrap();
                        }
                    });
                },
                _=connections.join_next(),if !connections.is_empty()=>{},
            }
        }
    });
    setup.provider.config["request_timeout_ms"] = json!(60000);
    setup.provider.config["events"] = json!({"grant_id":"grant","key_file":directory.join("events-key"),"dispatch_timeout_ms":13000});
    setup.provider.config["messaging"] = json!({"xmsg":{"service":"gateway","expected_node":"bus","daemon_uid":std::fs::metadata(directory).unwrap().uid(),"register_socket":socket,"agent_socket":directory.join("unused-agent.sock"),"operation_timeout_ms":1000},"manifest":{"reply_ttl_secs":604800,"idempotency_ttl_secs":604800,"svc_queue_cap":1000,"dedup_lifetime_secs":604800,"max_framed_bytes":65536},"result_recovery_secs":604800,"submission_timeout_ms":1000,"max_reservations":100,"max_retained_bytes":1048576});
    fixture::private_file(
        &setup.provider.config_file,
        &serde_json::to_vec(&setup.provider.config).unwrap(),
    );
    Bus {
        pending,
        acked,
        handle,
    }
}
#[tokio::test]
async fn production_rpc_and_session_poll_commit_ack_and_signed_owned_wake() {
    let mut setup = Setup::new();
    let bus = start_bus(&mut setup).await;
    let callback = http_callback::CallbackFixture::new(&crate::events_test_support::secret(4));
    let serving = Serving::from_owner_file_with_transport(
        &setup.provider.config_file,
        callback.transport.clone(),
    )
    .await
    .unwrap();
    let initialize=call(&serving,"initialize",json!({"protocolVersion":"2025-03-26","capabilities":{},"clientInfo":{"name":"fixture","version":"1"}})).await;
    assert!(initialize["capabilities"].get("events").is_some());
    let list = call(&serving, "events/list", json!({})).await;
    assert_eq!(list["events"][0]["name"], events::EVENT_NAME);
    let subscription=call(&serving,"events/subscribe",json!({"name":events::EVENT_NAME,"arguments":{},"delivery":{"mode":"webhook","url":callback.url,"secret":crate::events_test_support::secret(4)},"cursor":null})).await;
    assert!(!subscription["refreshBefore"].is_null());
    bus.pending.lock().unwrap().push_back(json!({"action":"deliver","messageId":"wire-message","fromName":"untrusted label","text":"addressed peer text","envelope":"peer data","origin":{"id":null,"service":"sender","node":"peer"},"inReplyTo":null}));
    tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            let accepted: i64 = setup
                .db()
                .query_row(
                    "SELECT COUNT(*) FROM custody_outbox WHERE state='accepted'",
                    [],
                    |row| row.get(0),
                )
                .unwrap();
            if !bus.acked.lock().unwrap().is_empty() && accepted == 1 {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("production ingress/dispatcher did not finish");
    assert_eq!(*bus.acked.lock().unwrap(), vec!["wire-message"]);
    {
        let callbacks = callback.received.lock().unwrap();
        assert_eq!(callbacks.len(), 1);
        let event = callbacks[0].value.clone();
        assert_eq!(event["data"]["message_id"], "wire-message");
        assert_eq!(event["data"]["mailbox"], "gateway@bus");
        assert_eq!(event["data"]["origin"]["service"], "sender");
    }
    let body = call(
        &serving,
        "tools/call",
        json!({"name":"xmsg_read_message","arguments":{"message_id":"wire-message"}}),
    )
    .await;
    assert_eq!(body["structuredContent"]["text"], "addressed peer text");
    assert_eq!(
        setup
            .db()
            .query_row("SELECT COUNT(*) FROM event_observations", [], |row| row
                .get::<_, i64>(0))
            .unwrap(),
        0,
        "G6 read mutated observation"
    );
    let ack = call(
        &serving,
        "tools/call",
        json!({"name":"xmsg_ack","arguments":{"message_id":"wire-message"}}),
    )
    .await;
    assert_eq!(ack["structuredContent"]["state"], "observed");
    let tools = call(&serving, "tools/list", json!({})).await;
    for name in ["xmsg_ack", "xmsg_message_status"] {
        assert!(tools["tools"]
            .as_array()
            .unwrap()
            .iter()
            .any(|tool| tool["name"] == name));
    }
    let identity = call(
        &serving,
        "tools/call",
        json!({"name":"xmsg_identity","arguments":{}}),
    )
    .await;
    assert_eq!(
        identity["structuredContent"]["events_status"]["subscription"]["state"],
        "active"
    );
    assert_eq!(
        identity["structuredContent"]["events_status"]["retained_events_by_state"]["accepted"],
        1
    );
    bus.handle.abort();
    tokio::time::timeout(Duration::from_secs(5), async {
        while serving
            .state
            .messaging
            .as_ref()
            .unwrap()
            .session
            .snapshot()
            .is_ok()
        {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .unwrap();
    let offline = call(
        &serving,
        "tools/call",
        json!({"name":"xmsg_read_message","arguments":{"message_id":"wire-message"}}),
    )
    .await;
    assert_eq!(
        offline["structuredContent"]["text"], "addressed peer text",
        "durable recovery depended on an online bus"
    );
    let (status,malformed,_)=fixture::request(&serving,"good-token",rpc("events/subscribe",json!({"name":events::EVENT_NAME,"arguments":{},"delivery":{"mode":"webhook","url":"https://callback.example/wake","secret":"whsec_invalid"},"cursor":null}))).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(malformed["error"]["code"], -32602);
    serving
        .state
        .event_worker
        .as_ref()
        .unwrap()
        .shutdown()
        .await;
    serving
        .state
        .messaging
        .as_ref()
        .unwrap()
        .session
        .shutdown()
        .await
        .unwrap();
}

#[cfg(target_os = "linux")]
#[allow(dead_code)]
#[path = "../tests/common/real_unix_node.rs"]
mod real_node;

#[cfg(target_os = "linux")]
#[tokio::test]
#[ignore = "mandatory private-node Events profile"]
async fn real_pinned_node_custody_wakes_https_and_recovers_owned_body() {
    let binary = real_node::pinned_binary();
    let mut node = real_node::Node::start(&binary).await;
    let mut setup = Setup::new();
    Store::open(&setup.provider.store_file)
        .unwrap()
        .migrate_retirement()
        .unwrap();
    let callback = http_callback::CallbackFixture::new(&crate::events_test_support::secret(4));
    let target = format!("{}@{}", node.config.service, node.config.expected_node);
    let policy: outbound::Policy = serde_json::from_value(
        json!({"send":{"targets":[target],"required_scope":"identity:read"},"reply":null}),
    )
    .unwrap();
    Store::open(&setup.provider.store_file)
        .unwrap()
        .set_outbound_policy("grant", 2, &policy)
        .unwrap();
    setup.provider.config["request_timeout_ms"] = json!(60000);
    setup.provider.config["events"] = json!({"grant_id":"grant","key_file":setup.provider.keys._directory.path().join("events-key"),"dispatch_timeout_ms":13000});
    let connection = &node.config;
    setup.provider.config["messaging"] = json!({"xmsg":{"service":connection.service,"expected_node":connection.expected_node,"daemon_uid":connection.daemon_uid,"register_socket":connection.register_socket,"agent_socket":connection.agent_socket,"max_frame_bytes":connection.max_frame_bytes,"operation_timeout_ms":connection.operation_timeout_ms},"manifest":{"reply_ttl_secs":604800,"idempotency_ttl_secs":86400,"svc_queue_cap":100,"dedup_lifetime_secs":3600,"max_framed_bytes":65536},"submission_timeout_ms":10000,"max_reservations":1000,"max_retained_bytes":67108864});
    fixture::private_file(
        &setup.provider.config_file,
        &serde_json::to_vec(&setup.provider.config).unwrap(),
    );
    let serving = Serving::from_owner_file_with_transport(
        &setup.provider.config_file,
        callback.transport.clone(),
    )
    .await
    .unwrap();
    call(&serving,"events/subscribe",json!({"name":events::EVENT_NAME,"arguments":{},"delivery":{"mode":"webhook","url":callback.url,"secret":crate::events_test_support::secret(4)},"cursor":null})).await;
    let sent=call(&serving,"tools/call",json!({"name":"xmsg_send","arguments":{"request_id":"events-real-node","to":target,"text":"actual addressed fixture text"}})).await;
    assert_eq!(sent["structuredContent"]["state"], "confirmed");
    let message = sent["structuredContent"]["receipt"]["receipt"]["message_id"]
        .as_str()
        .unwrap()
        .to_owned();
    tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            let accepted: i64 = setup
                .db()
                .query_row(
                    "SELECT COUNT(*) FROM custody_outbox WHERE state='accepted'",
                    [],
                    |row| row.get(0),
                )
                .unwrap();
            let pending: i64 = setup
                .db()
                .query_row("SELECT COUNT(*) FROM custody_pending", [], |row| row.get(0))
                .unwrap();
            if accepted == 1 && pending == 0 {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .unwrap();
    {
        let callbacks = callback.received.lock().unwrap();
        assert_eq!(callbacks.len(), 1);
        assert_eq!(callbacks[0].value["data"]["message_id"], message);
        assert_eq!(callbacks[0].value["data"]["mailbox"], target);
        assert_eq!(callbacks[0].value["data"]["origin"]["service"], "gateway");
    }
    let body = call(
        &serving,
        "tools/call",
        json!({"name":"xmsg_read_message","arguments":{"message_id":message}}),
    )
    .await;
    assert!(body["structuredContent"]["text"]
        .as_str()
        .unwrap()
        .ends_with("actual addressed fixture text"));
    serving
        .state
        .messaging
        .as_ref()
        .unwrap()
        .session
        .shutdown()
        .await
        .unwrap();
    let mut reopened = node.config.register().await.unwrap();
    assert!(
        reopened.poll(0).await.unwrap().is_none(),
        "upstream retained an acknowledged delivery"
    );
    drop(reopened);
    node.stop();
    tokio::time::timeout(Duration::from_secs(5), async {
        while serving
            .state
            .messaging
            .as_ref()
            .unwrap()
            .session
            .snapshot()
            .is_ok()
        {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .unwrap();
    let status = call(
        &serving,
        "tools/call",
        json!({"name":"xmsg_message_status","arguments":{"request_id":"events-real-node"}}),
    )
    .await;
    assert_eq!(
        status["structuredContent"]["results"][0]["state"],
        "confirmed"
    );
    let recovered = call(
        &serving,
        "tools/call",
        json!({"name":"xmsg_read_message","arguments":{"message_id":message}}),
    )
    .await;
    assert!(recovered["structuredContent"]["text"]
        .as_str()
        .unwrap()
        .ends_with("actual addressed fixture text"));
    serving
        .state
        .event_worker
        .as_ref()
        .unwrap()
        .shutdown()
        .await;
    serving
        .state
        .messaging
        .as_ref()
        .unwrap()
        .session
        .shutdown()
        .await
        .unwrap();
    println!("events-transport-complete:owned-custody-https");
}

#[tokio::test]
async fn summarized_gap_history_keeps_live_session_ready() {
    use std::time::{SystemTime, UNIX_EPOCH};
    for stale in [false, true] {
        let mut setup = Setup::new();
        let _bus = start_bus(&mut setup).await;
        let limits = custody::Limits {
            metadata_retention_secs: if stale { 10 } else { 604800 },
            ..custody::Limits::default()
        };
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let mut store = Store::open(&setup.provider.store_file).unwrap();
        if stale {
            store
                .record_bus_link(
                    "bus",
                    true,
                    &limits,
                    UNIX_EPOCH + Duration::from_secs(now - 45),
                )
                .unwrap();
            store
                .record_bus_link(
                    "bus",
                    true,
                    &limits,
                    UNIX_EPOCH + Duration::from_secs(now - 25),
                )
                .unwrap();
            for second in now - 24..now {
                store
                    .record_bus_link(
                        "bus",
                        true,
                        &limits,
                        UNIX_EPOCH + Duration::from_secs(second),
                    )
                    .unwrap();
            }
        } else {
            let mut second = now - 501502;
            store
                .record_bus_link(
                    "bus",
                    true,
                    &limits,
                    UNIX_EPOCH + Duration::from_secs(second),
                )
                .unwrap();
            for width in (1..=1001).rev() {
                second += width;
                store
                    .record_bus_link(
                        "bus",
                        true,
                        &limits,
                        UNIX_EPOCH + Duration::from_secs(second),
                    )
                    .expect("shrinking gap history blocked readiness");
            }
        }
        setup.provider.config["events"]["custody_limits"] = json!({"max_items":1000,"max_bytes":67108864,"max_item_bytes":262144,"content_retention_secs":604800,"max_metadata":1000,"metadata_retention_secs":limits.metadata_retention_secs,"max_gap_intervals":1000});
        fixture::private_file(
            &setup.provider.config_file,
            &serde_json::to_vec(&setup.provider.config).unwrap(),
        );
        let serving = Serving::from_owner_file(&setup.provider.config_file)
            .await
            .expect("coalesced history prevented session startup");
        assert_eq!(
            serving.state.messaging.as_ref().unwrap().session.status()["state"],
            "ready",
            "historical witness held readiness red"
        );
        let status = store
            .custody_status(
                &custody::Scope {
                    bus_instance: "bus".into(),
                    grant_id: "grant".into(),
                },
                &limits,
                SystemTime::now(),
                15,
            )
            .unwrap();
        assert!(
            status.offline_uncertainty,
            "summary forgot the widest interval"
        );
        assert!(
            status.coalesced_uncertainty,
            "historical evidence lost coalesced label"
        );
        if stale {
            let expired: bool = setup
                .db()
                .query_row(
                    "SELECT widest_expires_at<=?1 FROM custody_gap_summary WHERE bus='bus'",
                    [now as i64],
                    |r| r.get(0),
                )
                .unwrap();
            assert!(expired, "fixture did not pass widest interval's own expiry");
        }
        serving
            .state
            .messaging
            .as_ref()
            .unwrap()
            .session
            .shutdown()
            .await
            .unwrap();
    }
}
