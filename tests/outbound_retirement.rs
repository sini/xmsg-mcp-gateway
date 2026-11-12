//! Retirement keeps a permanent owner/ID fence while releasing the active working set.
#[cfg(target_os = "linux")]
use std::collections::BTreeSet;
#[cfg(target_os = "linux")]
use xmsg_mcp_gateway::{
    auth::Verifier,
    outbound::{
        dispatch, Endpoint, Outcome, Permission, Policy, ReplyArguments, Request, RequestId,
        SendArguments,
    },
};
use xmsg_mcp_gateway::{
    grants::Store,
    outbound::{Error, Limits, Receipt},
};
#[cfg(target_os = "linux")]
#[path = "common/agent_stall.rs"]
mod agent_stall;
#[cfg(target_os = "linux")]
#[path = "common/custody_time.rs"]
mod custody_time;
#[allow(dead_code)]
#[path = "common/provider.rs"]
mod provider;
#[cfg(target_os = "linux")]
#[allow(dead_code)]
#[path = "common/real_node.rs"]
mod real_node;
#[allow(dead_code)]
#[path = "common/serving_fixture.rs"]
mod serving_fixture;

fn limits() -> Limits {
    Limits {
        dedup_lifetime_secs: 60,
        result_recovery_secs: 120,
        max_framed_bytes: 65_536,
        timeout: std::time::Duration::from_secs(5),
        max_reservations: 2,
        max_retained_bytes: 131_072,
    }
}
#[cfg(target_os = "linux")]
fn send(id: &str, target: &str, text: &str) -> Request {
    Request::Send(SendArguments {
        attachments: vec![],
        request_id: RequestId::parse(id).unwrap(),
        to: target.into(),
        text: text.into(),
    })
}
#[cfg(target_os = "linux")]
fn reply(id: &str, message_id: &str, text: &str) -> Request {
    Request::Reply(ReplyArguments {
        attachments: vec![],
        request_id: RequestId::parse(id).unwrap(),
        message_id: message_id.into(),
        text: text.into(),
    })
}
#[cfg(target_os = "linux")]
fn authority() -> (serving_fixture::Fixture, Store, Verifier) {
    let fixture = serving_fixture::Fixture::new();
    fixture
        .tokens
        .lock()
        .unwrap()
        .get_mut("good-token")
        .unwrap()["scope"] = serde_json::json!("send:write reply:write");
    let mut config = fixture.config["verifier"].clone();
    config["required_scopes"] = serde_json::json!(["send:write", "reply:write"]);
    let verifier = Verifier::from_config(serde_json::from_value(config).unwrap()).unwrap();
    let mut store = Store::open(&fixture.store_file).unwrap();
    store.migrate_custody().unwrap();
    store.migrate_outbound().unwrap();
    (fixture, store, verifier)
}
#[cfg(target_os = "linux")]
fn policy(store: &mut Store, target: &str) {
    store
        .set_outbound_policy(
            "grant",
            2,
            &Policy {
                send: Some(Permission {
                    targets: BTreeSet::from([target.into()]),
                    required_scope: "send:write".into(),
                }),
                reply: Some(Permission {
                    targets: BTreeSet::from([target.into()]),
                    required_scope: "reply:write".into(),
                }),
            },
        )
        .unwrap();
}

fn bare_store() -> (tempfile::TempDir, std::path::PathBuf, Store) {
    let directory = tempfile::tempdir().unwrap();
    let file = directory.path().join("authority.db");
    let mut store = Store::initialize(&file).unwrap();
    store
        .enroll(
            "grant",
            &xmsg_mcp_gateway::grants::Binding {
                service: "gateway".into(),
                issuer: "issuer".into(),
                resource: "resource".into(),
                subject: "owner".into(),
                hosted_client: "hosted".into(),
            },
        )
        .unwrap();
    store.migrate_custody().unwrap();
    store.migrate_outbound().unwrap();
    (directory, file, store)
}
fn now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64
}
fn seed(file: &std::path::Path, id: &str, op: &str, body: &str, created: i64, until: i64) {
    let receipt = match op {
        "send" => {
            serde_json::json!({"operation":"Send","receipt":{"message_id":format!("message-{id}"),"address":"receiver@node","outcome":"queued"}})
        }
        "reply" => {
            serde_json::json!({"operation":"Reply","receipt":{"seq":1,"messageId":format!("message-{id}"),"createdAt":created,"replierSessionId":"gateway@node","text":body,"pushOutcome":"queued","pushedMessageId":format!("pushed-{id}"),"replier":{"service":"gateway","node":"node"}}})
        }
        _ => panic!("invalid fixture operation"),
    };
    let _: Receipt = serde_json::from_value(receipt.clone()).unwrap();
    rusqlite::Connection::open(file).unwrap().execute(
        "INSERT INTO outbound_reservations(owner,operation,request_id,payload_hash,sender,grant_id,grant_revision,idempotency_key,target,framed_text,created_at,retry_until,state,receipt) VALUES ('owner',?1,?2,'payload','gateway@node','grant',1,?3,'receiver@node',?4,?5,?6,'confirmed',?7)",
        rusqlite::params![op,id,format!("key-{op}-{id}"),body,created,until,receipt.to_string()],
    ).unwrap();
}
fn count(file: &std::path::Path, table: &str) -> i64 {
    assert!(matches!(
        table,
        "outbound_reservations" | "outbound_retired" | "outbound_request_fences"
    ));
    rusqlite::Connection::open(file)
        .unwrap()
        .query_row(&format!("SELECT COUNT(*) FROM {table}"), [], |row| {
            row.get(0)
        })
        .unwrap()
}
fn expire(file: &std::path::Path, id: &str) {
    rusqlite::Connection::open(file).unwrap().execute(
        "UPDATE outbound_reservations SET created_at=1,retry_until=2,recovery_until=3 WHERE request_id=?1", [id],
    ).unwrap();
}

#[test]
fn retirement_migration_is_explicit_preserves_legacy_pairs_and_does_not_skip_events() {
    let (directory, file, mut store) = bare_store();
    let timestamp = now();
    seed(
        &file,
        "legacy-pair",
        "send",
        "legacy-send",
        timestamp,
        timestamp + 60,
    );
    seed(
        &file,
        "legacy-pair",
        "reply",
        "legacy-reply",
        timestamp,
        timestamp + 60,
    );
    store.migrate_retirement().unwrap();
    let sql = rusqlite::Connection::open(&file).unwrap();
    assert_eq!(
        sql.pragma_query_value::<i64, _>(None, "user_version", |r| r.get(0))
            .unwrap(),
        3
    );
    assert_eq!(
        sql.query_row::<i64, _, _>("SELECT version FROM outbound_retirement_schema", [], |r| r
            .get(0))
            .unwrap(),
        5
    );
    assert_eq!(
        count(&file, "outbound_reservations"),
        2,
        "migration erased a legacy outcome"
    );
    assert_eq!(
        count(&file, "outbound_request_fences"),
        1,
        "legacy operation pair did not share one owner/ID fence"
    );
    assert_eq!(
        sql.query_row::<i64, _, _>(
            "SELECT COUNT(*) FROM outbound_reservations WHERE recovery_until IS NULL",
            [],
            |r| r.get(0)
        )
        .unwrap(),
        2,
        "migration invented a legacy recovery deadline"
    );
    assert!(
        matches!(
            store.outbound_recovery_expired(
                "owner",
                "legacy-pair",
                "gateway@node",
                "grant",
                &limits()
            ),
            Err(Error::Busy)
        ),
        "read inferred an uninitialized recovery window"
    );
    let keyfile = directory.path().join("events-key");
    serving_fixture::private_file(&keyfile, &[8; 32]);
    let key = xmsg_mcp_gateway::event_store::EventKey::load(&keyfile).unwrap();
    store.migrate_events(&key).unwrap();
    assert_eq!(
        sql.pragma_query_value::<i64, _>(None, "user_version", |r| r.get(0))
            .unwrap(),
        4
    );
    store.retire_outbound("gateway", &limits()).unwrap();
    assert_eq!(count(&file, "outbound_reservations"), 2);
}

#[test]
fn retirement_requires_both_windows_and_keeps_a_bodyless_witness_across_reopen() {
    let (_directory, file, mut store) = bare_store();
    let timestamp = now();
    seed(
        &file,
        "windows",
        "send",
        "private request bytes",
        timestamp,
        timestamp + 60,
    );
    store.migrate_retirement().unwrap();
    let sql = rusqlite::Connection::open(&file).unwrap();
    sql.execute(
        "UPDATE outbound_reservations SET recovery_until=?1",
        [timestamp + 120],
    )
    .unwrap();
    store.retire_outbound("gateway", &limits()).unwrap();
    assert_eq!(
        count(&file, "outbound_reservations"),
        1,
        "open effect/recovery window was retired"
    );
    sql.execute("UPDATE outbound_reservations SET retry_until=2", [])
        .unwrap();
    store.retire_outbound("gateway", &limits()).unwrap();
    assert_eq!(
        count(&file, "outbound_reservations"),
        1,
        "closed effect window erased supported recovery"
    );
    expire(&file, "windows");
    store.retire_outbound("gateway", &limits()).unwrap();
    assert_eq!(count(&file, "outbound_reservations"), 0);
    assert_eq!(count(&file, "outbound_retired"), 1);
    assert_eq!(count(&file, "outbound_request_fences"), 1);
    let columns: Vec<String> = sql
        .prepare("PRAGMA table_info(outbound_retired)")
        .unwrap()
        .query_map([], |row| row.get(1))
        .unwrap()
        .map(Result::unwrap)
        .collect();
    assert!(
        !columns
            .iter()
            .any(|name| matches!(name.as_str(), "framed_text" | "receipt" | "text")),
        "retired archive retained body-bearing fields"
    );
    drop(store);
    let store = Store::open(&file).unwrap();
    assert_eq!(
        count(&file, "outbound_retired"),
        1,
        "reopen forgot the retired refusal witness"
    );
    drop(store);
}

#[test]
fn retirement_archive_failure_rolls_back_before_reclaiming_original_content() {
    let (_directory, file, mut store) = bare_store();
    seed(
        &file,
        "atomic",
        "send",
        "must survive archive failure",
        1,
        2,
    );
    store.migrate_retirement().unwrap();
    expire(&file, "atomic");
    let sql = rusqlite::Connection::open(&file).unwrap();
    sql.execute_batch("CREATE TRIGGER fail_archive BEFORE INSERT ON outbound_retired BEGIN SELECT RAISE(ABORT, 'forced archive failure'); END;").unwrap();
    assert!(store.retire_outbound("gateway", &limits()).is_err());
    assert_eq!(count(&file, "outbound_reservations"), 1);
    let body: String = sql
        .query_row(
            "SELECT framed_text FROM outbound_reservations WHERE request_id='atomic'",
            [],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(body, "must survive archive failure");
    assert_eq!(count(&file, "outbound_retired"), 0);
    sql.execute_batch("DROP TRIGGER fail_archive;").unwrap();
    store.retire_outbound("gateway", &limits()).unwrap();
    assert_eq!(count(&file, "outbound_reservations"), 0);
    assert_eq!(count(&file, "outbound_retired"), 1);
}

#[cfg(target_os = "linux")]
async fn nodes() -> (real_node::Node, real_node::Node) {
    let binary = real_node::pinned_binary();
    let ca = real_node::Authority::generate();
    let from = real_node::Prepared::create("gateway", "gateway", Some(&ca));
    let to = real_node::Prepared::create("receiver", "receiver", Some(&ca));
    from.peer(&to, serde_json::json!({}));
    to.peer(&from, serde_json::json!({}));
    (from.launch(&binary).await, to.launch(&binary).await)
}

#[cfg(target_os = "linux")]
async fn owned_message(
    store: &mut Store,
    service: &mut xmsg::client::RegisteredService,
    receiver: &xmsg::client::RegisteredService,
) -> String {
    let message = receiver
        .send(
            service.address().unwrap(),
            "owned reply correlation",
            Some("retirement-incoming"),
        )
        .await
        .unwrap();
    let delivery = service.poll(1).await.unwrap().unwrap();
    store
        .accept_delivery(
            &xmsg_mcp_gateway::custody::Scope {
                bus_instance: "private-bus".into(),
                grant_id: "grant".into(),
            },
            service,
            &delivery,
            &xmsg_mcp_gateway::custody::Limits::default(),
            custody_time::at(now()),
        )
        .unwrap();
    service.ack(delivery.message_id()).await.unwrap();
    message.message_id
}

#[cfg(target_os = "linux")]
#[tokio::test]
#[ignore = "mandatory private-node retirement profile"]
async fn retired_send_and_reply_ids_refuse_changed_and_cross_operation_retries_after_restart() {
    let (from, to) = nodes().await;
    let mut service = from.config.register().await.unwrap();
    let endpoint = Endpoint::from_registered(&service).unwrap();
    let mut receiver = to.config.register().await.unwrap();
    let target = receiver.address().unwrap().to_owned();
    let (fixture, mut store, verifier) = authority();
    policy(&mut store, &target);
    store.migrate_retirement().unwrap();
    let incoming = owned_message(&mut store, &mut service, &receiver).await;
    for (id, operation) in [
        ("send-id", send("send-id", &target, "first send")),
        ("reply-id", reply("reply-id", &incoming, "first reply")),
    ] {
        let outcome = dispatch(
            &mut store,
            &endpoint,
            &verifier,
            "good-token",
            "private-bus",
            &operation,
            &limits(),
        )
        .await
        .unwrap();
        assert!(matches!(outcome, Outcome::Confirmed(_)));
        let delivered = receiver.poll(1).await.unwrap().unwrap();
        if id == "reply-id" {
            assert_eq!(delivered.in_reply_to(), Some(incoming.as_str()));
        }
        receiver.ack(delivered.message_id()).await.unwrap();
        let cross = if id == "send-id" {
            reply(id, &incoming, "must not add a reply")
        } else {
            send(id, &target, "must not add a send")
        };
        assert!(
            matches!(
                dispatch(
                    &mut store,
                    &endpoint,
                    &verifier,
                    "good-token",
                    "private-bus",
                    &cross,
                    &limits()
                )
                .await,
                Err(Error::Conflict)
            ),
            "active raw ID authorized another operation"
        );
        expire(&fixture.store_file, id);
        store.retire_outbound("gateway", &limits()).unwrap();
        drop(store);
        store = Store::open(&fixture.store_file).unwrap();
        for attempt in [
            operation,
            cross,
            send(id, &target, "changed retired payload"),
            reply(id, &incoming, "changed retired reply"),
        ] {
            assert_eq!(
                dispatch(
                    &mut store,
                    &endpoint,
                    &verifier,
                    "good-token",
                    "private-bus",
                    &attempt,
                    &limits()
                )
                .await
                .unwrap(),
                Outcome::Expired,
                "retired ID became a fresh operation"
            );
        }
        assert!(
            receiver.poll(0).await.unwrap().is_none(),
            "retired retry published another effect"
        );
    }
    assert_eq!(count(&fixture.store_file, "outbound_reservations"), 0);
    assert_eq!(count(&fixture.store_file, "outbound_retired"), 2);
    println!("outbound-retirement-complete:send-reply-cross-operation-restart");
}

#[cfg(target_os = "linux")]
#[tokio::test]
#[ignore = "mandatory private-node retirement profile"]
async fn successful_gist_retirement_reclaims_quota_without_reexecuting_old_ids() {
    let (from, to) = nodes().await;
    let service = from.config.register().await.unwrap();
    let endpoint = Endpoint::from_registered(&service).unwrap();
    let mut receiver = to.config.register().await.unwrap();
    let target = receiver.address().unwrap().to_owned();
    let (fixture, mut store, verifier) = authority();
    policy(&mut store, &target);
    store.migrate_retirement().unwrap();
    let mut configured = limits();
    configured.max_reservations = 1;
    let arguments = serde_json::json!({"request_id":"gist-id","id":"abc","body":"one comment"});
    let original = Request::Send(
        xmsg_mcp_gateway::broker::parse("gist_comment", arguments.clone(), &target).unwrap(),
    );
    assert!(matches!(
        dispatch(
            &mut store,
            &endpoint,
            &verifier,
            "good-token",
            "private-bus",
            &original,
            &configured
        )
        .await
        .unwrap(),
        Outcome::Confirmed(_)
    ));
    let delivered = receiver.poll(1).await.unwrap().unwrap();
    let proposal: serde_json::Value =
        serde_json::from_str(delivered.text().split_once('\n').unwrap().1).unwrap();
    assert_eq!(proposal["kind"], "gist_comment");
    assert_eq!(proposal["body"], "one comment");
    receiver.ack(delivered.message_id()).await.unwrap();
    assert!(
        matches!(
            dispatch(
                &mut store,
                &endpoint,
                &verifier,
                "good-token",
                "private-bus",
                &send("fresh-id", &target, "new effect"),
                &configured
            )
            .await,
            Err(Error::Capacity)
        ),
        "active row bound was bypassed"
    );
    expire(&fixture.store_file, "gist-id");
    store.retire_outbound("gateway", &configured).unwrap();
    let bytes: i64 = rusqlite::Connection::open(&fixture.store_file)
        .unwrap()
        .query_row(
            "SELECT COALESCE(SUM(length(CAST(framed_text AS BLOB))),0) FROM outbound_reservations",
            [],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(
        bytes, 0,
        "retired gist file/body bytes still consume active quota"
    );
    for attempt in [
        original,
        Request::Send(
            xmsg_mcp_gateway::broker::parse(
                "gist_update",
                serde_json::json!({"request_id":"gist-id","id":"abc","files":{"note":"changed"}}),
                &target,
            )
            .unwrap(),
        ),
        send("gist-id", &target, "generic send under retired gist ID"),
    ] {
        assert_eq!(
            dispatch(
                &mut store,
                &endpoint,
                &verifier,
                "good-token",
                "private-bus",
                &attempt,
                &configured
            )
            .await
            .unwrap(),
            Outcome::Expired
        );
    }
    assert!(
        receiver.poll(0).await.unwrap().is_none(),
        "retired gist ID reached upstream again"
    );
    assert!(
        matches!(
            dispatch(
                &mut store,
                &endpoint,
                &verifier,
                "good-token",
                "private-bus",
                &send("fresh-id", &target, "new effect"),
                &configured
            )
            .await
            .unwrap(),
            Outcome::Confirmed(_)
        ),
        "retirement did not release active admission capacity"
    );
    let delivered = receiver.poll(1).await.unwrap().unwrap();
    assert!(delivered.text().ends_with("\nnew effect"));
    receiver.ack(delivered.message_id()).await.unwrap();
    assert!(receiver.poll(0).await.unwrap().is_none());
    println!("outbound-retirement-complete:gist-quota-reclaimed-old-id-fenced");
}

#[cfg(target_os = "linux")]
#[tokio::test]
#[ignore = "mandatory private-node retirement profile"]
async fn retirement_cannot_remove_an_inflight_accepted_operation_under_its_service_lease() {
    let (from, to) = nodes().await;
    let service = from.config.register().await.unwrap();
    let endpoint = Endpoint::from_registered(&service).unwrap();
    let mut receiver = to.config.register().await.unwrap();
    let target = receiver.address().unwrap().to_owned();
    let (fixture, mut store, verifier) = authority();
    policy(&mut store, &target);
    store.migrate_retirement().unwrap();
    let verifier = std::sync::Arc::new(verifier);
    let operation_verifier = verifier.clone();
    let file = fixture.store_file.clone();
    let operation_target = target.clone();
    let mut stall = agent_stall::AgentStall::install(&from.config, "send");
    let running = tokio::spawn(async move {
        dispatch(
            &mut Store::open(&file).unwrap(),
            &endpoint,
            &operation_verifier,
            "good-token",
            "private-bus",
            &send("inflight", &operation_target, "accepted exactly once"),
            &limits(),
        )
        .await
    });
    let accepted = tokio::time::timeout(std::time::Duration::from_secs(3), stall.reached())
        .await
        .unwrap();
    expire(&fixture.store_file, "inflight");
    store.retire_outbound("gateway", &limits()).unwrap();
    assert_eq!(
        count(&fixture.store_file, "outbound_reservations"),
        1,
        "retirement crossed the in-flight operation lease"
    );
    assert_eq!(count(&fixture.store_file, "outbound_retired"), 0);
    stall.finish(true).await;
    let finished = tokio::time::timeout(std::time::Duration::from_secs(5), running)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    let Outcome::Confirmed(Receipt::Send(receipt)) = finished else {
        panic!("accepted operation did not retain its outcome");
    };
    assert_eq!(receipt.message_id, accepted["message_id"]);
    let delivered = receiver.poll(1).await.unwrap().unwrap();
    assert_eq!(delivered.message_id(), receipt.message_id);
    receiver.ack(delivered.message_id()).await.unwrap();
    store.retire_outbound("gateway", &limits()).unwrap();
    assert_eq!(count(&fixture.store_file, "outbound_reservations"), 0);
    assert_eq!(count(&fixture.store_file, "outbound_retired"), 1);
    let endpoint = Endpoint::from_registered(&service).unwrap();
    assert_eq!(
        dispatch(
            &mut store,
            &endpoint,
            &verifier,
            "good-token",
            "private-bus",
            &send("inflight", &target, "accepted exactly once"),
            &limits()
        )
        .await
        .unwrap(),
        Outcome::Expired
    );
    assert!(
        receiver.poll(0).await.unwrap().is_none(),
        "retirement replay duplicated the accepted operation"
    );
    println!("outbound-retirement-complete:inflight-lease-and-outcome-preserved");
}

#[test]
fn retirement_rejects_short_recovery_and_never_reopens_archived_ids_on_config_growth() {
    let (_directory, file, mut store) = bare_store();
    seed(&file, "never-reopen", "send", "retired bytes", 1, 2);
    store.migrate_retirement().unwrap();
    expire(&file, "never-reopen");
    let mut invalid = limits();
    invalid.result_recovery_secs = invalid.dedup_lifetime_secs - 1;
    assert!(matches!(
        store.retire_outbound("gateway", &invalid),
        Err(Error::Configuration)
    ));
    assert_eq!(count(&file, "outbound_reservations"), 1);
    store.retire_outbound("gateway", &limits()).unwrap();
    let mut larger = limits();
    larger.dedup_lifetime_secs = 1000;
    larger.result_recovery_secs = 2000;
    store.retire_outbound("gateway", &larger).unwrap();
    assert!(store
        .retired_outbound("owner", "never-reopen", "gateway@node", "grant")
        .unwrap());
    assert!(!store
        .retired_outbound("foreign", "never-reopen", "gateway@node", "grant")
        .unwrap());
    assert!(!store
        .retired_outbound("owner", "never-reopen", "foreign@node", "grant")
        .unwrap());
    assert_eq!(count(&file, "outbound_reservations"), 0);
}

#[allow(dead_code)]
#[path = "common/custody_crash.rs"]
mod retirement_crash;

#[test]
fn retirement_crash_child() {
    let Ok(document) = std::env::var("RETIREMENT_CRASH_DOCUMENT") else {
        return;
    };
    let document: serde_json::Value =
        serde_json::from_slice(&std::fs::read(document).unwrap()).unwrap();
    let target = match document["cut"].as_str().unwrap() {
        "witness" => "gateway_outbound_retirement_witness",
        "reclaimed" => "gateway_outbound_retirement_reclaimed",
        _ => panic!("unknown retirement cut"),
    };
    tracing::subscriber::set_global_default(retirement_crash::Cut {
        target,
        marker: document["marker"].as_str().unwrap().into(),
    })
    .unwrap();
    Store::open(std::path::Path::new(document["store"].as_str().unwrap()))
        .unwrap()
        .retire_outbound("gateway", &limits())
        .unwrap();
    panic!("retirement child passed its crash cut");
}

#[test]
fn process_crash_before_retirement_commit_preserves_the_original_and_recovery() {
    use std::process::{Command, Stdio};
    use std::time::{Duration, Instant};
    for cut in ["witness", "reclaimed"] {
        let (directory, file, mut store) = bare_store();
        seed(
            &file,
            "crash-retire",
            "send",
            "original accepted bytes",
            1,
            2,
        );
        store.migrate_retirement().unwrap();
        expire(&file, "crash-retire");
        let marker = directory.path().join("cut");
        let document = directory.path().join("child.json");
        std::fs::write(
            &document,
            serde_json::to_vec(&serde_json::json!({
                "store":file,"marker":marker,"cut":cut
            }))
            .unwrap(),
        )
        .unwrap();
        let log = directory.path().join("child.log");
        let mut child = retirement_crash::Worker(
            Command::new(std::env::current_exe().unwrap())
                .args(["--exact", "retirement_crash_child", "--nocapture"])
                .env("RETIREMENT_CRASH_DOCUMENT", &document)
                .stdout(std::fs::File::create(&log).unwrap())
                .stderr(Stdio::inherit())
                .spawn()
                .unwrap(),
        );
        let deadline = Instant::now() + Duration::from_secs(5);
        while !marker.exists() {
            assert!(
                child.0.try_wait().unwrap().is_none(),
                "child missed {cut}: {}",
                std::fs::read_to_string(&log).unwrap()
            );
            assert!(
                Instant::now() < deadline,
                "retirement crash cut not reached: {cut}"
            );
            std::thread::sleep(Duration::from_millis(5));
        }
        child.0.kill().unwrap();
        child.0.wait().unwrap();
        drop(store);
        let mut reopened = Store::open(&file).unwrap();
        assert_eq!(
            count(&file, "outbound_reservations"),
            1,
            "crash lost accepted work at {cut}"
        );
        assert_eq!(
            count(&file, "outbound_retired"),
            0,
            "uncommitted archive survived {cut}"
        );
        assert_eq!(
            count(&file, "outbound_request_fences"),
            1,
            "crash forgot request identity"
        );
        reopened.retire_outbound("gateway", &limits()).unwrap();
        assert_eq!(count(&file, "outbound_reservations"), 0);
        assert_eq!(count(&file, "outbound_retired"), 1);
        assert!(reopened
            .retired_outbound("owner", "crash-retire", "gateway@node", "grant")
            .unwrap());
    }
}
