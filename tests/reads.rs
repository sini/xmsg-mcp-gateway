#![cfg(unix)]

#[allow(dead_code)]
#[path = "common/serving_fixture.rs"]
mod fixture;
#[allow(dead_code)]
#[path = "common/provider.rs"]
mod provider;

use std::collections::VecDeque;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::sync::{Arc, Mutex};
use std::time::SystemTime;

use axum::http::StatusCode;
use fixture::{private_file, request, Fixture};
use rusqlite::Connection;
use serde_json::{json, Value};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::UnixListener;
use xmsg_mcp_gateway::custody::{Acceptance, Limits, Scope};
use xmsg_mcp_gateway::grants::Store;
use xmsg_mcp_gateway::serving::Serving;
use xmsg_mcp_gateway::xmsg_config::XmsgConfig;

struct Mailbox {
    provider: Fixture,
    config: XmsgConfig,
    deliveries: Arc<Mutex<VecDeque<Value>>>,
    worker: tokio::task::JoinHandle<()>,
}

impl Drop for Mailbox {
    fn drop(&mut self) {
        self.worker.abort();
    }
}

impl Mailbox {
    async fn new() -> Self {
        let mut provider = Fixture::new();
        let directory = provider.keys._directory.path();
        std::fs::set_permissions(directory, std::fs::Permissions::from_mode(0o700)).unwrap();
        let socket = directory.join("register.sock");
        let listener = UnixListener::bind(&socket).unwrap();
        std::fs::set_permissions(&socket, std::fs::Permissions::from_mode(0o600)).unwrap();
        let deliveries = Arc::new(Mutex::new(VecDeque::new()));
        let queued = deliveries.clone();
        let worker = tokio::spawn(async move {
            let mut connections = tokio::task::JoinSet::new();
            loop {
                tokio::select! {
                    accepted = listener.accept() => {
                        let (stream, _) = accepted.unwrap();
                        let queued = queued.clone();
                        connections.spawn(async move {
                            let mut stream = BufReader::new(stream);
                            let mut line = String::new();
                            stream.read_line(&mut line).await.unwrap();
                            let registration: Value = serde_json::from_str(&line).unwrap();
                            assert_eq!(registration["harness"], "svc");
                            let reply = json!({"status":"ok", "address":format!("{}@fixture-node", registration["name"].as_str().unwrap()),
                                "node":"fixture-node", "reply_ttl_secs":604800, "idempotency_ttl_secs":604800,
                                "svc_queue_cap":1000, "max_body_bytes":65536});
                            stream.get_mut().write_all(format!("{reply}\n").as_bytes()).await.unwrap();
                            loop {
                                line.clear();
                                if stream.read_line(&mut line).await.unwrap() == 0 { break; }
                                let frame: Value = serde_json::from_str(&line).unwrap();
                                assert_eq!(frame["action"], "poll");
                                let reply = queued.lock().unwrap().pop_front().unwrap_or(json!({"action":"timeout"}));
                                stream.get_mut().write_all(format!("{reply}\n").as_bytes()).await.unwrap();
                            }
                        });
                    }
                    _ = connections.join_next(), if !connections.is_empty() => {}
                }
            }
        });
        let config = XmsgConfig {
            service: "gateway".into(),
            expected_node: "fixture-node".into(),
            daemon_uid: std::fs::metadata(directory).unwrap().uid(),
            register_socket: socket,
            agent_socket: directory.join("unused-agent.sock"),
            max_frame_bytes: 1_048_576,
            operation_timeout_ms: 1000,
        };
        let mut store = Store::open(&provider.store_file).unwrap();
        store.migrate_custody().unwrap();
        store.migrate_outbound().unwrap();
        provider.config["request_timeout_ms"] = json!(40000);
        provider.config["messaging"] = json!({
            "xmsg":{"service":config.service,"expected_node":config.expected_node,"daemon_uid":config.daemon_uid,
                "register_socket":config.register_socket,"agent_socket":config.agent_socket,
                "operation_timeout_ms":config.operation_timeout_ms},
            "manifest":{"reply_ttl_secs":604800,"idempotency_ttl_secs":604800,"svc_queue_cap":1000,
                "dedup_lifetime_secs":604800,"max_framed_bytes":65536},
            "submission_timeout_ms":1000,"max_reservations":100,"max_retained_bytes":1048576,
        });
        private_file(
            &provider.config_file,
            &serde_json::to_vec(&provider.config).unwrap(),
        );
        Self {
            provider,
            config,
            deliveries,
            worker,
        }
    }

    fn db(&self) -> Connection {
        Connection::open(&self.provider.store_file).unwrap()
    }

    async fn accept(&self, name: &str, id: &str, text: &str, at: SystemTime) {
        let mut config = self.config.clone();
        config.service = name.into();
        let mut registered = config.register().await.unwrap();
        self.deliveries
            .lock()
            .unwrap()
            .push_back(json!({"action":"deliver","messageId":id,
            "fromName":"source", "text":text, "envelope":"external peer data",
            "origin":{"id":null,"service":"source","node":"source-node"},"inReplyTo":null}));
        let delivery = registered.poll(0).await.unwrap().unwrap();
        let mut store = Store::open(&self.provider.store_file).unwrap();
        let accepted = store
            .accept_delivery(
                &Scope {
                    bus_instance: "fixture-node".into(),
                    grant_id: "grant".into(),
                },
                &registered,
                &delivery,
                &Limits::default(),
                at,
            )
            .unwrap();
        assert!(matches!(accepted, Acceptance::Stored { .. }));
    }

    async fn serving(&self) -> Serving {
        self.provider.serving().await
    }
}

fn call(name: &str, arguments: Value) -> Value {
    json!({"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":name,"arguments":arguments}})
}

async fn tool(serving: &Serving, name: &str, args: Value) -> Value {
    let (status, response, _) = request(serving, "good-token", call(name, args)).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        response["id"],
        json!(1),
        "read response changed its JSON-RPC request ID"
    );
    assert!(response.get("error").is_none(), "{response}");
    response["result"]["structuredContent"].clone()
}

async fn not_found(serving: &Serving, id: &str) {
    let response = tool(serving, "xmsg_read_message", json!({"message_id":id})).await;
    assert_eq!(
        response,
        json!({"state":"not_found"}),
        "foreign or unavailable message escaped ownership scope"
    );
}

#[tokio::test]
async fn registered_mailbox_reads_only_owned_current_body() {
    let mailbox = Mailbox::new().await;
    mailbox
        .accept("gateway", "owned", "owned body", SystemTime::now())
        .await;
    mailbox
        .accept("other", "foreign", "foreign body", SystemTime::now())
        .await;
    let serving = mailbox.serving().await;
    let owned = tool(&serving, "xmsg_read_message", json!({"message_id":"owned"})).await;
    assert_eq!(owned["text"], "owned body");
    assert_eq!(owned["mailbox"], "gateway@fixture-node");
    not_found(&serving, "foreign").await;
    not_found(&serving, "unknown").await;
    let inbox = tool(&serving, "xmsg_inbox", json!({})).await;
    assert_eq!(
        inbox["items"].as_array().unwrap().len(),
        1,
        "inbox escaped mailbox scope"
    );
    assert_eq!(inbox["items"][0]["message_id"], "owned");
    assert!(inbox["next"].is_null());
    for (column, value) in [("bus", "foreign-node"), ("owner", "foreign-owner")] {
        mailbox
            .db()
            .execute(
                &format!("UPDATE custody_items SET {column}=?1 WHERE upstream_id='owned'"),
                [value],
            )
            .unwrap();
        not_found(&serving, "owned").await;
        assert!(tool(&serving, "xmsg_inbox", json!({})).await["items"]
            .as_array()
            .unwrap()
            .is_empty());
        let original = if column == "bus" {
            "fixture-node"
        } else {
            "owner"
        };
        mailbox
            .db()
            .execute(
                &format!("UPDATE custody_items SET {column}=?1 WHERE upstream_id='owned'"),
                [original],
            )
            .unwrap();
    }
    let held: String = mailbox.db().query_row("SELECT state FROM custody_outbox WHERE event_id=(SELECT event_id FROM custody_items WHERE upstream_id='owned')",[],|row|row.get(0)).unwrap();
    assert_eq!(held, "held", "reading changed the event delivery state");
}

#[tokio::test]
async fn bounded_pages_and_unicode_body_round_trip() {
    let mailbox = Mailbox::new().await;
    let body = "😀é\0界a".repeat(1300);
    mailbox
        .accept("gateway", "large", &body, SystemTime::now())
        .await;
    for i in 0..22 {
        mailbox
            .accept(
                "gateway",
                &format!("item-{i}"),
                "preview",
                SystemTime::now(),
            )
            .await;
    }
    let serving = mailbox.serving().await;
    let first = tool(&serving, "xmsg_inbox", json!({})).await;
    assert_eq!(first["items"].as_array().unwrap().len(), 20);
    assert_eq!(
        first["items"][0]["preview"]
            .as_str()
            .unwrap()
            .chars()
            .count(),
        256
    );
    let next = first["next"].as_str().unwrap();
    let second = tool(&serving, "xmsg_inbox", json!({"after":next})).await;
    assert_eq!(second["items"].as_array().unwrap().len(), 3);
    assert!(second["next"].is_null());
    let all = tool(&serving, "xmsg_inbox", json!({"limit":100})).await;
    assert_eq!(all["items"].as_array().unwrap().len(), 23);
    assert!(all["next"].is_null());
    let mut reconstructed = String::new();
    let mut offset = 0;
    loop {
        let part = tool(
            &serving,
            "xmsg_read_message",
            json!({"message_id":"large","offset":offset}),
        )
        .await;
        let text = part["text"].as_str().unwrap();
        assert!(text.chars().count() <= 4096 && text.len() <= 16384);
        reconstructed.push_str(text);
        if part["next_offset"].is_null() {
            break;
        }
        offset = part["next_offset"].as_u64().unwrap();
    }
    assert_eq!(reconstructed, body);
    let end = tool(
        &serving,
        "xmsg_read_message",
        json!({"message_id":"large","offset":100000}),
    )
    .await;
    assert_eq!(end["text"], "");
    assert!(end["next_offset"].is_null());
    for (name, args) in [
        ("xmsg_inbox", json!({"limit":0})),
        ("xmsg_inbox", json!({"limit":101})),
        (
            "xmsg_read_message",
            json!({"message_id":"large","limit":4097}),
        ),
        (
            "xmsg_read_message",
            json!({"message_id":"large","offset":-1}),
        ),
        ("xmsg_read_message", json!({"message_id":"large","limit":0})),
    ] {
        let (_, response, _) = request(&serving, "good-token", call(name, args)).await;
        assert_eq!(response["error"]["code"], -32602, "unbounded read accepted");
    }
}

#[tokio::test]
async fn cursor_is_bound_to_mailbox_revision_and_a_retained_anchor() {
    let mailbox = Mailbox::new().await;
    mailbox.accept("gateway", "a", "a", SystemTime::now()).await;
    mailbox.accept("gateway", "b", "b", SystemTime::now()).await;
    let serving = mailbox.serving().await;
    let first = tool(&serving, "xmsg_inbox", json!({"limit":1})).await;
    let cursor = first["next"].as_str().unwrap();
    let mut other_config = mailbox.provider.config.clone();
    other_config["messaging"]["xmsg"]["service"] = json!("other");
    private_file(
        &mailbox.provider.config_file,
        &serde_json::to_vec(&other_config).unwrap(),
    );
    let other_serving = mailbox.serving().await;
    let (_, response, _) = request(
        &other_serving,
        "good-token",
        call("xmsg_inbox", json!({"after":cursor})),
    )
    .await;
    assert_eq!(
        response["error"]["code"], -32602,
        "cursor reused by another registered mailbox"
    );
    private_file(
        &mailbox.provider.config_file,
        &serde_json::to_vec(&mailbox.provider.config).unwrap(),
    );
    for mutation in [
        "UPDATE custody_items SET mailbox='other@fixture-node' WHERE upstream_id='a'",
        "UPDATE custody_items SET expires_at=0 WHERE upstream_id='a'",
    ] {
        mailbox.db().execute(mutation, []).unwrap();
        let (_, response, _) = request(
            &serving,
            "good-token",
            call("xmsg_inbox", json!({"after":cursor})),
        )
        .await;
        assert_eq!(
            response["error"]["code"], -32602,
            "foreign or expired anchor accepted"
        );
        mailbox.db().execute("UPDATE custody_items SET mailbox='gateway@fixture-node',expires_at=9999999999 WHERE upstream_id='a'",[]).unwrap();
    }
    let db = mailbox.db();
    db.execute("UPDATE grants SET revision=revision+1", [])
        .unwrap();
    let (_, response, _) = request(
        &serving,
        "good-token",
        call("xmsg_inbox", json!({"after":cursor})),
    )
    .await;
    assert_eq!(
        response["error"]["code"], -32602,
        "cursor survived grant revision change"
    );
    db.execute("UPDATE grants SET revision=revision-1", [])
        .unwrap();
    db.execute("DELETE FROM custody_items WHERE upstream_id='a'", [])
        .unwrap();
    let (_, response, _) = request(
        &serving,
        "good-token",
        call("xmsg_inbox", json!({"after":cursor})),
    )
    .await;
    assert_eq!(response["error"]["code"], -32602, "purged anchor accepted");
    drop(db);
    mailbox.accept("gateway", "c", "c", SystemTime::now()).await;
    let page = tool(&serving, "xmsg_inbox", json!({"limit":1})).await;
    let surviving = page["next"].as_str().unwrap();
    mailbox.accept("gateway", "d", "d", SystemTime::now()).await;
    mailbox.db().execute("VACUUM", []).unwrap();
    let resumed = tool(&serving, "xmsg_inbox", json!({"after":surviving})).await;
    let ids: Vec<_> = resumed["items"]
        .as_array()
        .unwrap()
        .iter()
        .map(|item| item["message_id"].as_str().unwrap())
        .collect();
    assert_eq!(
        ids,
        ["c", "d"],
        "surviving anchor lost order across vacuum or append"
    );
    mailbox
        .db()
        .execute("DELETE FROM custody_items", [])
        .unwrap();
    mailbox
        .accept("gateway", "replacement", "replacement", SystemTime::now())
        .await;
    let (_, response, _) = request(
        &serving,
        "good-token",
        call("xmsg_inbox", json!({"after":surviving})),
    )
    .await;
    assert_eq!(
        response["error"]["code"], -32602,
        "recycled rowid revived a deleted cursor"
    );
    let mut rebound = Mailbox::new().await;
    rebound
        .accept("gateway", "first", "first", SystemTime::now())
        .await;
    rebound
        .accept("gateway", "second", "second", SystemTime::now())
        .await;
    let first_serving = rebound.serving().await;
    let first_page = tool(&first_serving, "xmsg_inbox", json!({"limit":1})).await;
    let old_cursor = first_page["next"].as_str().unwrap();
    let mut store = Store::open(&rebound.provider.store_file).unwrap();
    store.set_enabled("grant", 2, false).unwrap();
    let mut binding = rebound.provider.binding.clone();
    binding.hosted_client = "replacement-client".into();
    store.enroll("replacement", &binding).unwrap();
    store.set_enabled("replacement", 1, true).unwrap();
    rebound
        .provider
        .tokens
        .lock()
        .unwrap()
        .get_mut("good-token")
        .unwrap()["client_id"] = json!(binding.hosted_client);
    rebound.provider.config["verifier"]["hosted_client"] = json!(binding.hosted_client);
    private_file(
        &rebound.provider.config_file,
        &serde_json::to_vec(&rebound.provider.config).unwrap(),
    );
    let replacement_serving = rebound.serving().await;
    let (_, response, _) = request(
        &replacement_serving,
        "good-token",
        call("xmsg_inbox", json!({"after":old_cursor})),
    )
    .await;
    assert_eq!(
        response["error"]["code"], -32602,
        "cursor reused by a new authenticated binding"
    );
    not_found(&replacement_serving, "first").await;
}

#[tokio::test]
async fn pre_enable_old_revision_expired_and_redacted_bodies_stay_invisible() {
    let mailbox = Mailbox::new().await;
    let mut store = Store::open(&mailbox.provider.store_file).unwrap();
    assert_eq!(store.set_enabled("grant", 2, false).unwrap(), 3);
    mailbox
        .accept(
            "gateway",
            "before-enable",
            "private held body",
            SystemTime::now(),
        )
        .await;
    assert_eq!(store.set_enabled("grant", 3, true).unwrap(), 4);
    mailbox
        .accept(
            "gateway",
            "old-revision",
            "previous body",
            SystemTime::now(),
        )
        .await;
    assert_eq!(store.set_enabled("grant", 4, false).unwrap(), 5);
    assert_eq!(store.set_enabled("grant", 5, true).unwrap(), 6);
    mailbox
        .accept("gateway", "expired", "expired body", SystemTime::now())
        .await;
    mailbox
        .accept("gateway", "redacted", "redacted body", SystemTime::now())
        .await;
    mailbox
        .accept("gateway", "current", "current held body", SystemTime::now())
        .await;
    mailbox
        .db()
        .execute(
            "UPDATE custody_items SET expires_at=0 WHERE upstream_id='expired'",
            [],
        )
        .unwrap();
    mailbox
        .db()
        .execute(
            "UPDATE custody_items SET text=NULL WHERE upstream_id='redacted'",
            [],
        )
        .unwrap();
    let serving = mailbox.serving().await;
    let before: i64 = mailbox
        .db()
        .query_row(
            "SELECT COUNT(*) FROM custody_outbox WHERE state='held'",
            [],
            |row| row.get(0),
        )
        .unwrap();
    for id in ["before-enable", "old-revision", "expired", "redacted"] {
        not_found(&serving, id).await;
    }
    assert_eq!(
        tool(&serving, "xmsg_inbox", json!({})).await["items"]
            .as_array()
            .unwrap()
            .len(),
        1
    );
    assert_eq!(
        tool(
            &serving,
            "xmsg_read_message",
            json!({"message_id":"current"})
        )
        .await["text"],
        "current held body"
    );
    let rows: i64 = mailbox
        .db()
        .query_row(
            "SELECT COUNT(*) FROM custody_outbox WHERE state='held'",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(rows, before, "reads released held events");
}

#[tokio::test]
async fn disabled_grants_and_unknown_arguments_are_refused() {
    let mailbox = Mailbox::new().await;
    mailbox
        .accept("gateway", "owned", "body", SystemTime::now())
        .await;
    let serving = mailbox.serving().await;
    for (name, args) in [
        ("xmsg_inbox", json!({"mailbox":"other"})),
        (
            "xmsg_read_message",
            json!({"message_id":"owned","unexpected":true}),
        ),
    ] {
        let (_, response, _) = request(&serving, "good-token", call(name, args)).await;
        assert_eq!(
            response["error"]["code"], -32602,
            "unknown read arguments accepted"
        );
    }
    let mut store = Store::open(&mailbox.provider.store_file).unwrap();
    store.set_enabled("grant", 2, false).unwrap();
    mailbox
        .accept(
            "gateway",
            "disabled-current",
            "not released",
            SystemTime::now(),
        )
        .await;
    for (name, args) in [
        ("xmsg_inbox", json!({})),
        (
            "xmsg_read_message",
            json!({"message_id":"disabled-current"}),
        ),
    ] {
        let (status, _, _) = request(&serving, "good-token", call(name, args)).await;
        assert_eq!(
            status,
            StatusCode::FORBIDDEN,
            "disabled grant exposed custody"
        );
    }
}

#[tokio::test]
async fn reads_are_advertised_only_with_a_registered_mailbox() {
    let identity_only = Fixture::new();
    let serving = identity_only.serving().await;
    let list = json!({"jsonrpc":"2.0","id":1,"method":"tools/list","params":{}});
    let (_, body, _) = request(&serving, "good-token", list.clone()).await;
    assert_eq!(body["result"]["tools"].as_array().unwrap().len(), 1);
    let mailbox = Mailbox::new().await;
    let serving = mailbox.serving().await;
    let (_, body, _) = request(&serving, "good-token", list).await;
    let names: Vec<_> = body["result"]["tools"]
        .as_array()
        .unwrap()
        .iter()
        .map(|tool| tool["name"].as_str().unwrap())
        .collect();
    assert_eq!(names, ["xmsg_identity", "xmsg_inbox", "xmsg_read_message"]);
    let mut response_ids = Vec::new();
    let expected_ids = [json!("inbox-request"), json!(42)];
    for ((name, arguments), id) in [
        ("xmsg_inbox", json!({})),
        ("xmsg_read_message", json!({"message_id":"unknown"})),
    ]
    .into_iter()
    .zip(expected_ids.iter())
    {
        let mut body = call(name, arguments);
        body["id"] = id.clone();
        let (status, response, _) = request(&serving, "good-token", body).await;
        assert_eq!(status, StatusCode::OK);
        assert!(response.get("error").is_none(), "{response}");
        response_ids.push(response["id"].clone());
    }
    assert_eq!(
        response_ids, expected_ids,
        "read responses changed their JSON-RPC request IDs"
    );
}

#[tokio::test]
async fn events_first_enable_release_is_readable_without_read_side_effects() {
    let mailbox = Mailbox::new().await;
    let db = mailbox.db();
    db.execute("DELETE FROM grants WHERE id='grant'", [])
        .unwrap();
    let key_file = mailbox.provider.keys._directory.path().join("events-key");
    private_file(&key_file, &[9u8; 32]);
    let key = xmsg_mcp_gateway::event_store::EventKey::load(&key_file).unwrap();
    let mut store = Store::open(&mailbox.provider.store_file).unwrap();
    store.migrate_events(&key).unwrap();
    store.enroll("grant", &mailbox.provider.binding).unwrap();
    mailbox
        .accept(
            "gateway",
            "never-enabled",
            "retained before first enable",
            SystemTime::now(),
        )
        .await;
    assert_eq!(store.set_enabled("grant", 1, true).unwrap(), 2);
    let serving = mailbox.serving().await;
    let before: i64 = db
        .query_row("SELECT COUNT(*) FROM event_release_audit", [], |r| r.get(0))
        .unwrap();
    for _ in 0..2 {
        let result = tool(
            &serving,
            "xmsg_read_message",
            json!({"message_id":"never-enabled"}),
        )
        .await;
        assert_eq!(result["state"], "found");
        assert_eq!(result["text"], "retained before first enable");
    }
    assert_eq!(
        db.query_row("SELECT grant_revision FROM custody_items", [], |r| r
            .get::<_, i64>(0))
            .unwrap(),
        1
    );
    assert_eq!(
        db.query_row("SELECT COUNT(*) FROM event_release_audit", [], |r| r
            .get::<_, i64>(0))
            .unwrap(),
        before
    );
    assert_eq!(
        db.query_row("SELECT COUNT(*) FROM event_observations", [], |r| r
            .get::<_, i64>(0))
            .unwrap(),
        0
    );
    assert_eq!(store.set_enabled("grant", 2, false).unwrap(), 3);
    assert_eq!(store.set_enabled("grant", 3, true).unwrap(), 4);
    not_found(&serving, "never-enabled").await;
}

#[tokio::test]
async fn events_migration_does_not_infer_legacy_authority_from_matching_revision() {
    let mailbox = Mailbox::new().await;
    mailbox
        .accept(
            "gateway",
            "legacy-current",
            "legacy body",
            SystemTime::now(),
        )
        .await;
    let key_file = mailbox.provider.keys._directory.path().join("events-key");
    private_file(&key_file, &[10u8; 32]);
    let key = xmsg_mcp_gateway::event_store::EventKey::load(&key_file).unwrap();
    let mut store = Store::open(&mailbox.provider.store_file).unwrap();
    store.migrate_events(&key).unwrap();
    mailbox
        .accept(
            "gateway",
            "new-current",
            "current authority",
            SystemTime::now(),
        )
        .await;
    let serving = mailbox.serving().await;
    not_found(&serving, "legacy-current").await;
    assert_eq!(
        tool(
            &serving,
            "xmsg_read_message",
            json!({"message_id":"new-current"})
        )
        .await["state"],
        "found"
    );
    let inbox = tool(&serving, "xmsg_inbox", json!({})).await;
    assert_eq!(inbox["items"].as_array().unwrap().len(), 1);
    assert_eq!(inbox["items"][0]["message_id"], "new-current");
}
