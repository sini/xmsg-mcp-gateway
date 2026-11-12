#[allow(dead_code)]
#[path = "common/serving_fixture.rs"]
mod fixture;
#[allow(dead_code)]
#[path = "common/provider.rs"]
mod provider;

use base64::{engine::general_purpose::STANDARD, Engine};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::sync::{Arc, Mutex};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::UnixListener;
use xmsg::client::{ClientOptions, RegisteredService};
use xmsg_mcp_gateway::{
    auth::Verifier,
    grants::Store,
    outbound::{
        dispatch, Endpoint, Error, Limits, Outcome, Permission, Policy, Request, SendArguments,
    },
};

struct Bus {
    fixture: fixture::Fixture,
    service: RegisteredService,
    frames: Arc<Mutex<Vec<Value>>>,
    stage_rows: Arc<Mutex<Vec<i64>>>,
    // Change the grant after discovery or after the Nth attach response.
    revoke_at: Arc<Mutex<Option<usize>>>,
    corrupt_ref: Arc<Mutex<bool>>,
    drop_chunk_reply: Arc<Mutex<bool>>,
    chunk_conflicts: Arc<std::sync::atomic::AtomicUsize>,
    tasks: Vec<tokio::task::JoinHandle<()>>,
}
impl Drop for Bus {
    fn drop(&mut self) {
        for task in &self.tasks {
            task.abort();
        }
    }
}
impl Bus {
    async fn new(cap: Option<usize>, body: usize) -> (Self, Store, Verifier) {
        let fixture = fixture::Fixture::new();
        fixture
            .tokens
            .lock()
            .unwrap()
            .get_mut("good-token")
            .unwrap()["scope"] = json!("send:write reply:write");
        let mut config = fixture.config["verifier"].clone();
        config["required_scopes"] = json!(["send:write", "reply:write"]);
        let verifier = Verifier::from_config(serde_json::from_value(config).unwrap()).unwrap();
        let mut store = Store::open(&fixture.store_file).unwrap();
        store.migrate_custody().unwrap();
        store.migrate_outbound().unwrap();
        store.migrate_retirement().unwrap();
        store.migrate_attachments().unwrap();
        let permission = Permission {
            targets: ["receiver@node".into()].into(),
            required_scope: "send:write".into(),
        };
        store
            .set_outbound_policy(
                "grant",
                2,
                &Policy {
                    send: Some(permission),
                    reply: Some(Permission {
                        targets: ["receiver@node".into()].into(),
                        required_scope: "reply:write".into(),
                    }),
                },
            )
            .unwrap();
        let dir = fixture.keys._directory.path();
        std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700)).unwrap();
        let register = dir.join("register.sock");
        let agent = dir.join("agent.sock");
        let registration = UnixListener::bind(&register).unwrap();
        let listener = UnixListener::bind(&agent).unwrap();
        for file in [&register, &agent] {
            std::fs::set_permissions(file, std::fs::Permissions::from_mode(0o600)).unwrap();
        }
        let registration_task = tokio::spawn(async move {
            let mut connections = tokio::task::JoinSet::new();
            loop {
                tokio::select! {
                    accepted = registration.accept() => {
                        let (socket, _) = accepted.unwrap();
                        connections.spawn(async move {
                            let mut stream = BufReader::new(socket);
                            let mut line = String::new();
                            stream.read_line(&mut line).await.unwrap();
                            let mut response = json!({"status":"ok","address":"gateway@bus","node":"bus","reply_ttl_secs":86400,"idempotency_ttl_secs":86400,"svc_queue_cap":1000,"max_body_bytes":body});
                            if let Some(cap) = cap { response["max_attachment_bytes"] = json!(cap); }
                            stream.get_mut().write_all(format!("{response}\n").as_bytes()).await.unwrap();
                            loop {
                                line.clear();
                                if stream.read_line(&mut line).await.unwrap() == 0 { break; }
                                stream.get_mut().write_all(b"{\"action\":\"timeout\"}\n").await.unwrap();
                            }
                        });
                    },
                    _ = connections.join_next(), if !connections.is_empty() => {},
                }
            }
        });
        let frames = Arc::new(Mutex::new(Vec::new()));
        let sink = frames.clone();
        let stage_rows = Arc::new(Mutex::new(Vec::new()));
        let rows_sink = stage_rows.clone();
        let revoke_at = Arc::new(Mutex::new(None));
        let revocation = revoke_at.clone();
        let file = fixture.store_file.clone();
        let corrupt_ref = Arc::new(Mutex::new(false));
        let corrupt = corrupt_ref.clone();
        let drop_chunk_reply = Arc::new(Mutex::new(false));
        let drop_reply = drop_chunk_reply.clone();
        let chunk_conflicts = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let conflicts = chunk_conflicts.clone();
        let agent_task = tokio::spawn(async move {
            let mut chunks = HashMap::<(String, usize), Vec<u8>>::new();
            let mut uploads = HashMap::<String, Vec<u8>>::new();
            let mut attached = 0;
            loop {
                let (stream, _) = listener.accept().await.unwrap();
                let mut stream = BufReader::new(stream);
                let mut line = String::new();
                stream.read_line(&mut line).await.unwrap();
                let frame: Value = serde_json::from_str(&line).unwrap();
                let action = frame["action"].as_str().unwrap();
                let response = match action {
                    "list" => {
                        json!({"status":"ok","nodes":[{"node":"node","status":"ok"}],"recipients":[{"address":"receiver@node","node":"node","kind":"service","harness":"svc","status":"live","user":"owner"}]})
                    }
                    "attach" => {
                        attached += 1;
                        rows_sink.lock().unwrap().push(
                            rusqlite::Connection::open(&file)
                                .unwrap()
                                .query_row("SELECT count(*) FROM outbound_reservations", [], |r| {
                                    r.get(0)
                                })
                                .unwrap(),
                        );
                        if frame.get("offset").is_some() {
                            let data = STANDARD.decode(frame["data"].as_str().unwrap()).unwrap();
                            let upload = frame["upload"].as_str().unwrap().to_string();
                            let offset = frame["offset"].as_u64().unwrap() as usize;
                            let key = (upload.clone(), offset);
                            if chunks.get(&key).is_some_and(|held| held != &data) {
                                conflicts.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                                json!({"status":"error","error":"conflict","detail":"chunk differs"})
                            } else {
                                let entry = uploads.entry(upload).or_default();
                                if let std::collections::hash_map::Entry::Vacant(chunk) =
                                    chunks.entry(key)
                                {
                                    assert_eq!(
                                        offset,
                                        entry.len(),
                                        "new chunks must be contiguous"
                                    );
                                    entry.extend_from_slice(&data);
                                    chunk.insert(data);
                                }
                                json!({"status":"ok","size":entry.len()})
                            }
                        } else {
                            let data = if let Some(data) = frame.get("data") {
                                STANDARD.decode(data.as_str().unwrap()).unwrap()
                            } else {
                                let upload = frame["upload"].as_str().unwrap();
                                chunks.retain(|(held, _), _| held != upload);
                                uploads.remove(upload).unwrap()
                            };
                            let hash = if *corrupt.lock().unwrap() {
                                "0".repeat(64)
                            } else {
                                format!("{:x}", Sha256::digest(&data))
                            };
                            json!({"status":"ok","attachment":{"name":frame["name"],"size":data.len(),"media_type":frame["media_type"],"sha256":hash}})
                        }
                    }
                    "send" => {
                        json!({"status":"ok","message_id":"01ARZ3NDEKTSV4RRFFQ69G5S00","address":"receiver@node","outcome":"delivered"})
                    }
                    "reply" => {
                        json!({"status":"ok","reply":{"seq":1,"messageId":frame["message_id"],"createdAt":1000,"replierSessionId":"gateway","text":frame["text"],"pushOutcome":"delivered","pushedMessageId":"01ARZ3NDEKTSV4RRFFQ69G5R00"}})
                    }

                    other => panic!("unexpected attachment fixture action {other}"),
                };
                let revoke = *revocation.lock().unwrap();
                if (action == "list" && revoke == Some(0))
                    || (action == "attach" && revoke == Some(attached))
                {
                    rusqlite::Connection::open(&file)
                        .unwrap()
                        .execute("UPDATE grants SET revision=revision+1 WHERE id='grant'", [])
                        .unwrap();
                    *revocation.lock().unwrap() = None;
                }
                let interrupt = if action == "attach" && frame["offset"] == 0 {
                    let mut once = drop_reply.lock().unwrap();
                    std::mem::take(&mut *once)
                } else {
                    false
                };
                sink.lock().unwrap().push(frame);
                if interrupt {
                    continue;
                }
                stream
                    .get_mut()
                    .write_all(format!("{response}\n").as_bytes())
                    .await
                    .unwrap();
            }
        });
        let service = RegisteredService::register(ClientOptions {
            register_socket: register,
            agent_socket: agent,
            max_frame_bytes: 65536,
            operation_timeout: std::time::Duration::from_secs(3),
            service: "gateway".into(),
            expected_node: Some("bus".into()),
            daemon_uid: std::fs::metadata(dir).unwrap().uid(),
        })
        .await
        .unwrap();
        (
            Self {
                fixture,
                service,
                frames,
                stage_rows,
                revoke_at,
                corrupt_ref,
                drop_chunk_reply,
                chunk_conflicts,
                tasks: vec![registration_task, agent_task],
            },
            store,
            verifier,
        )
    }
    fn count(&self, action: &str) -> usize {
        self.frames
            .lock()
            .unwrap()
            .iter()
            .filter(|frame| frame["action"] == action)
            .count()
    }
    async fn run(
        &self,
        store: &mut Store,
        verifier: &Verifier,
        request: &Request,
        limits: &Limits,
    ) -> Result<Outcome, Error> {
        dispatch(
            store,
            &Endpoint::from_registered(&self.service).unwrap(),
            verifier,
            "good-token",
            "bus",
            request,
            limits,
        )
        .await
    }
}
fn limits() -> Limits {
    Limits {
        dedup_lifetime_secs: 86400,
        result_recovery_secs: 86400,
        max_framed_bytes: 65536,
        timeout: std::time::Duration::from_secs(3),
        max_reservations: 100,
        max_retained_bytes: 1048576,
    }
}
fn request(id: &str, data: &str) -> Request {
    Request::Send(serde_json::from_value::<SendArguments>(json!({"request_id":id,"to":"receiver@node","text":"message","attachments":[{"name":"report.txt","text":data}]})).unwrap())
}

#[tokio::test]
async fn attachment_retries_conflict_in_both_fingerprint_paths_and_store_only_refs() {
    let (bus, mut store, verifier) = Bus::new(Some(1024), 65536).await;
    let original = request("same", "FILE_BYTES_CANARY");
    assert!(matches!(
        bus.run(&mut store, &verifier, &original, &limits())
            .await
            .unwrap(),
        Outcome::Confirmed(_)
    ));
    assert_eq!(bus.count("attach"), 1);
    assert_eq!(bus.count("send"), 1);
    assert_eq!(
        *bus.stage_rows.lock().unwrap(),
        vec![0],
        "new reservation existed before attachment staging succeeded"
    );
    assert!(matches!(
        bus.run(&mut store, &verifier, &original, &limits())
            .await
            .unwrap(),
        Outcome::Confirmed(_)
    ));
    assert_eq!(bus.count("attach"), 1, "confirmed replay must not restage");
    let changed = request("same", "EVIL_BYTES_CANARY");
    assert!(
        matches!(
            bus.run(&mut store, &verifier, &changed, &limits()).await,
            Err(Error::Conflict)
        ),
        "M11: changed file reused a confirmed reservation"
    );
    let lease = store.try_operation_lease("gateway").unwrap().unwrap();
    assert!(
        matches!(
            bus.run(&mut store, &verifier, &original, &limits())
                .await
                .unwrap(),
            Outcome::Confirmed(_)
        ),
        "busy-lease same-file replay lost its receipt"
    );
    assert!(
        matches!(
            bus.run(&mut store, &verifier, &changed, &limits()).await,
            Err(Error::Conflict)
        ),
        "M11: busy-lease comparison ignored changed file"
    );
    drop(lease);
    let db = rusqlite::Connection::open(&bus.fixture.store_file).unwrap();
    let refs: String = db
        .query_row("SELECT attachments FROM outbound_reservations", [], |r| {
            r.get(0)
        })
        .unwrap();
    assert!(!refs.contains("FILE_BYTES_CANARY"));
    assert_eq!(serde_json::from_str::<Value>(&refs).unwrap()[0]["size"], 17);
}

#[tokio::test]
async fn grant_revocation_before_staging_or_after_staging_prevents_delivery() {
    for stage in [0, 1] {
        let (bus, mut store, verifier) = Bus::new(Some(1024), 65536).await;
        *bus.revoke_at.lock().unwrap() = Some(stage);
        assert!(bus
            .run(
                &mut store,
                &verifier,
                &request("revoked", "bytes"),
                &limits()
            )
            .await
            .is_err());
        assert_eq!(bus.count("attach"), stage);
        assert_eq!(bus.count("send"), 0);
        if stage == 0 {
            assert_eq!(
                rusqlite::Connection::open(&bus.fixture.store_file)
                    .unwrap()
                    .query_row("SELECT count(*) FROM outbound_reservations", [], |r| r
                        .get::<_, i64>(0))
                    .unwrap(),
                0
            );
        }
    }
}

#[tokio::test]
async fn chunk_and_finalize_each_require_fresh_authority() {
    for stage in [1, 3] {
        let (bus, mut store, verifier) = Bus::new(Some(4096), 2048).await;
        *bus.revoke_at.lock().unwrap() = Some(stage);
        assert!(bus
            .run(
                &mut store,
                &verifier,
                &request("chunk-revoked", &"x".repeat(2000)),
                &limits()
            )
            .await
            .is_err());
        assert_eq!(
            bus.count("attach"),
            stage,
            "a later chunk or finalization ran after revocation"
        );
        assert_eq!(bus.count("send"), 0);
    }
}

#[tokio::test]
async fn chunks_fit_frame_and_pending_restart_submits_stored_refs_and_key() {
    let (bus, mut store, verifier) = Bus::new(Some(4096), 2048).await;
    let original = request("restart", &"x".repeat(2000));
    assert!(matches!(
        bus.run(&mut store, &verifier, &original, &limits())
            .await
            .unwrap(),
        Outcome::Confirmed(_)
    ));
    assert_eq!(bus.count("attach"), 4);
    for frame in bus
        .frames
        .lock()
        .unwrap()
        .iter()
        .filter(|f| f["action"] == "attach")
    {
        assert!(serde_json::to_vec(frame).unwrap().len() < 2048);
    }
    let first = bus
        .frames
        .lock()
        .unwrap()
        .iter()
        .find(|f| f["action"] == "send")
        .unwrap()
        .clone();
    let db = rusqlite::Connection::open(&bus.fixture.store_file).unwrap();
    db.execute(
        "UPDATE outbound_reservations SET receipt=NULL,state='unknown'",
        [],
    )
    .unwrap();
    drop(db);
    drop(store);
    let mut store = Store::open(&bus.fixture.store_file).unwrap();
    assert!(matches!(
        bus.run(&mut store, &verifier, &original, &limits())
            .await
            .unwrap(),
        Outcome::Confirmed(_)
    ));
    let frames = bus.frames.lock().unwrap();
    let retried = frames.iter().rev().find(|f| f["action"] == "send").unwrap();
    assert_eq!(first["idempotency_key"], retried["idempotency_key"]);
    assert_eq!(first["attachments"], retried["attachments"]);
}

#[tokio::test]
async fn retained_capacity_counts_existing_and_new_reference_json() {
    let (bus, mut store, verifier) = Bus::new(Some(1024), 65536).await;
    bus.run(&mut store, &verifier, &request("first", "one"), &limits())
        .await
        .unwrap();
    let db = rusqlite::Connection::open(&bus.fixture.store_file).unwrap();
    let (text,refs):(i64,i64)=db.query_row("SELECT length(CAST(framed_text AS BLOB)),length(CAST(attachments AS BLOB)) FROM outbound_reservations",[],|r|Ok((r.get(0)?,r.get(1)?))).unwrap();
    let mut bound = limits();
    bound.max_retained_bytes = 2 * (text + refs) - 1;
    assert!(
        matches!(
            bus.run(&mut store, &verifier, &request("second", "two"), &bound)
                .await,
            Err(Error::Capacity)
        ),
        "reference bytes escaped retained capacity accounting"
    );
    assert_eq!(bus.count("send"), 1);
}

#[tokio::test]
async fn old_node_still_sends_plain_text_but_file_cap_and_returned_reference_fail_closed() {
    let (bus, mut store, verifier) = Bus::new(None, 65536).await;
    let plain = Request::Send(
        serde_json::from_value(json!({"request_id":"plain","to":"receiver@node","text":"hello"}))
            .unwrap(),
    );
    assert!(matches!(
        bus.run(&mut store, &verifier, &plain, &limits())
            .await
            .unwrap(),
        Outcome::Confirmed(_)
    ));
    assert!(bus
        .run(&mut store, &verifier, &request("file", "bytes"), &limits())
        .await
        .is_err());
    assert_eq!(bus.count("attach"), 0);
    let (bus, mut store, verifier) = Bus::new(Some(3), 65536).await;
    assert!(matches!(
        bus.run(&mut store, &verifier, &request("large", "four"), &limits())
            .await,
        Err(Error::Oversized)
    ));
    assert_eq!(bus.count("attach"), 0);
    *bus.corrupt_ref.lock().unwrap() = true;
    assert!(bus
        .run(&mut store, &verifier, &request("corrupt", "abc"), &limits())
        .await
        .is_err());
    assert_eq!(bus.count("send"), 0);
}

#[tokio::test]
async fn old_store_keeps_plain_sql_and_files_require_explicit_migration() {
    let (bus, mut store, verifier) = Bus::new(Some(1024), 65536).await;
    let db = rusqlite::Connection::open(&bus.fixture.store_file).unwrap();
    db.execute_batch("DROP TABLE attachment_schema; ALTER TABLE custody_items DROP COLUMN attachments; ALTER TABLE outbound_reservations DROP COLUMN attachments;").unwrap();
    let plain = Request::Send(
        serde_json::from_value(json!({"request_id":"legacy","to":"receiver@node","text":"hello"}))
            .unwrap(),
    );
    assert!(matches!(
        bus.run(&mut store, &verifier, &plain, &limits())
            .await
            .unwrap(),
        Outcome::Confirmed(_)
    ));
    assert!(matches!(
        bus.run(&mut store, &verifier, &request("file", "bytes"), &limits())
            .await,
        Err(Error::MigrationRequired)
    ));
    assert_eq!(bus.count("attach"), 0);
    store.migrate_attachments().unwrap();
    assert!(matches!(
        bus.run(&mut store, &verifier, &request("file", "bytes"), &limits())
            .await
            .unwrap(),
        Outcome::Confirmed(_)
    ));
}

#[tokio::test]
async fn reply_attachment_retries_bind_files_and_preserve_stored_correlation() {
    let (bus, mut store, verifier) = Bus::new(Some(1024), 65536).await;
    let db = rusqlite::Connection::open(&bus.fixture.store_file).unwrap();
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64;
    db.execute("INSERT INTO custody_items(bus,upstream_id,event_id,grant_id,grant_revision,mailbox,owner,origin,text,envelope,fingerprint,received_at,expires_at,held) VALUES ('bus','incoming','event','grant',3,'gateway@bus','owner',?1,'body','envelope','fingerprint',?2,?3,1)",rusqlite::params![r#"{"id":null,"service":"receiver","node":"node"}"#,now,now+3600]).unwrap();
    let make = |bytes: &str| {
        Request::Reply(serde_json::from_value(json!({"request_id":"reply","message_id":"incoming","text":"answer","attachments":[{"name":"answer.txt","text":bytes}]})).unwrap())
    };
    let original = make("same");
    assert!(matches!(
        bus.run(&mut store, &verifier, &original, &limits())
            .await
            .unwrap(),
        Outcome::Confirmed(_)
    ));
    assert_eq!(bus.count("reply"), 1);
    assert!(matches!(
        bus.run(&mut store, &verifier, &make("evil"), &limits())
            .await,
        Err(Error::Conflict)
    ));
    let held = store.try_operation_lease("gateway").unwrap().unwrap();
    assert!(matches!(
        bus.run(&mut store, &verifier, &original, &limits())
            .await
            .unwrap(),
        Outcome::Confirmed(_)
    ));
    assert!(matches!(
        bus.run(&mut store, &verifier, &make("evil"), &limits())
            .await,
        Err(Error::Conflict)
    ));
    drop(held);
    db.execute(
        "UPDATE outbound_reservations SET receipt=NULL,state='unknown'",
        [],
    )
    .unwrap();
    drop(store);
    let mut reopened = Store::open(&bus.fixture.store_file).unwrap();
    db.execute("UPDATE custody_items SET expires_at=0", [])
        .unwrap();
    let staged_before = bus.count("attach");
    assert!(bus
        .run(&mut reopened, &verifier, &original, &limits())
        .await
        .is_err());
    assert_eq!(
        bus.count("attach"),
        staged_before,
        "expired reply correlation staged bytes before ownership was checked"
    );
    db.execute("UPDATE custody_items SET expires_at=?1", [now + 3600])
        .unwrap();
    assert!(matches!(
        bus.run(&mut reopened, &verifier, &original, &limits())
            .await
            .unwrap(),
        Outcome::Confirmed(_)
    ));
    let frames = bus.frames.lock().unwrap();
    let replies: Vec<_> = frames
        .iter()
        .filter(|frame| frame["action"] == "reply")
        .collect();
    assert_eq!(replies.len(), 2);
    assert_eq!(replies[0]["idempotency_key"], replies[1]["idempotency_key"]);
    assert_eq!(replies[0]["attachments"], replies[1]["attachments"]);
    assert_eq!(replies[1]["message_id"], "incoming");
}

#[tokio::test]
async fn interrupted_upload_retries_after_client_frame_budget_changes() {
    let (mut bus, _store, _verifier) = Bus::new(Some(1_048_576), 65536).await;
    bus.fixture.config["verifier"]["required_scopes"] =
        json!(["identity:read", "send:write", "reply:write"]);
    bus.fixture
        .tokens
        .lock()
        .unwrap()
        .get_mut("good-token")
        .unwrap()["scope"] = json!("identity:read send:write reply:write");
    bus.fixture.config["request_timeout_ms"] = json!(60000);
    let dir = bus.fixture.keys._directory.path();
    bus.fixture.config["messaging"] = json!({
        "xmsg":{"service":"gateway","expected_node":"bus","daemon_uid":std::fs::metadata(dir).unwrap().uid(),
            "register_socket":dir.join("register.sock"),"agent_socket":dir.join("agent.sock"),
            "max_frame_bytes":65536,"operation_timeout_ms":15000},
        "manifest":{"reply_ttl_secs":86400,"idempotency_ttl_secs":86400,"svc_queue_cap":1000,
            "dedup_lifetime_secs":86400,"max_framed_bytes":32768},
        "submission_timeout_ms":5000,"max_reservations":100,"max_retained_bytes":1048576
    });
    fixture::private_file(
        &bus.fixture.config_file,
        &serde_json::to_vec(&bus.fixture.config).unwrap(),
    );
    let serving = bus.fixture.serving().await;
    let request = json!({"jsonrpc":"2.0","id":"geometry","method":"tools/call","params":{"name":"xmsg_send",
        "arguments":{"request_id":"geometry","to":"receiver@node","text":"message",
            "attachments":[{"name":"report.txt","text":"x".repeat(100000)}]}}});
    *bus.drop_chunk_reply.lock().unwrap() = true;
    let (_, first, _) = fixture::request(&serving, "good-token", request.clone()).await;
    assert_ne!(
        first["result"]["structuredContent"]["state"], "confirmed",
        "fault did not interrupt staging"
    );
    assert!(
        !*bus.drop_chunk_reply.lock().unwrap(),
        "fault must occur after first chunk commits"
    );
    let db = rusqlite::Connection::open(&bus.fixture.store_file).unwrap();
    let rows: i64 = db
        .query_row("SELECT count(*) FROM outbound_reservations", [], |r| {
            r.get(0)
        })
        .unwrap();
    assert_eq!(
        rows, 0,
        "interrupted staging created a business reservation"
    );
    assert_eq!(bus.count("send"), 0);
    assert_eq!(bus.count("attach"), 1);
    drop(serving);
    bus.fixture.config["messaging"]["xmsg"]["max_frame_bytes"] = json!(32768);
    fixture::private_file(
        &bus.fixture.config_file,
        &serde_json::to_vec(&bus.fixture.config).unwrap(),
    );
    let serving = bus.fixture.serving().await;
    let (status, retried, _) = fixture::request(&serving, "good-token", request.clone()).await;
    assert_eq!(status, axum::http::StatusCode::OK, "{retried}");
    assert_eq!(
        retried["result"]["structuredContent"]["state"], "confirmed",
        "retry after frame budget change collided with old upload geometry: {retried}"
    );
    assert_eq!(
        bus.chunk_conflicts
            .load(std::sync::atomic::Ordering::SeqCst),
        0,
        "new upload geometry reused an incompatible partial chunk key"
    );
    let (status, again, _) = fixture::request(&serving, "good-token", request).await;
    assert_eq!(status, axum::http::StatusCode::OK, "{again}");
    assert_eq!(
        again["result"]["structuredContent"], retried["result"]["structuredContent"],
        "same-key retry changed receipt"
    );
    assert_eq!(
        bus.count("send"),
        1,
        "frame-budget recovery duplicated delivery"
    );
}
