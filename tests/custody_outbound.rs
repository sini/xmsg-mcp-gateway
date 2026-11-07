#![cfg(target_os = "linux")]

#[path = "common/agent_stall.rs"]
mod agent_stall;
#[path = "common/custody_crash.rs"]
mod crash;
#[path = "common/outbound_observer.rs"]
mod observer;
#[allow(dead_code)]
#[path = "common/provider.rs"]
mod provider;
#[allow(dead_code)]
#[path = "common/real_node.rs"]
mod real_node;
#[allow(dead_code)]
#[path = "common/serving_fixture.rs"]
mod serving_fixture;

use xmsg_mcp_gateway::{
    auth::Verifier,
    grants::Store,
    outbound::{
        dispatch, Endpoint, Error, Limits, Outcome, Permission, Policy, Receipt, ReplyArguments,
        Request, RequestId, SendArguments,
    },
};

fn limits() -> Limits {
    Limits {
        dedup_lifetime_secs: 86400,
        max_framed_bytes: 65536,
        timeout: std::time::Duration::from_secs(5),
        max_reservations: 1000,
        max_retained_bytes: 64 * 1024 * 1024,
    }
}

fn request(id: &str, target: &str, text: &str) -> Request {
    Request::Send(SendArguments {
        request_id: RequestId::parse(id).unwrap(),
        to: target.into(),
        text: text.into(),
    })
}

fn unmigrated_authority() -> (serving_fixture::Fixture, Store, Verifier) {
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
    let store = Store::open(&fixture.store_file).unwrap();
    (fixture, store, verifier)
}

fn authority() -> (serving_fixture::Fixture, Store, Verifier) {
    let (fixture, mut store, verifier) = unmigrated_authority();
    store.migrate_custody().unwrap();
    store.migrate_outbound().unwrap();
    (fixture, store, verifier)
}

#[tokio::test]
#[ignore = "mandatory private-node outbound profile"]
async fn same_request_reuses_receipt_and_changed_payload_conflicts() {
    let binary = real_node::pinned_binary();
    let ca = real_node::Authority::generate();
    let from = real_node::Prepared::create("gateway", "gateway", Some(&ca));
    let to = real_node::Prepared::create("receiver", "receiver", Some(&ca));
    from.peer(&to, serde_json::json!({}));
    to.peer(&from, serde_json::json!({}));
    let from = from.launch(&binary).await;
    let to = to.launch(&binary).await;
    let service = from.config.register().await.unwrap();
    let mut receiver = to.config.register().await.unwrap();
    let target = receiver.address().unwrap().to_owned();
    let (fixture, mut store, verifier) = unmigrated_authority();
    let original = request("stable-request", &target, "original bytes");
    for version in [1, 2] {
        assert!(
            matches!(
                dispatch(
                    &mut store,
                    &Endpoint::from_registered(&service).unwrap(),
                    &verifier,
                    "good-token",
                    "private-bus",
                    &original,
                    &limits()
                )
                .await,
                Err(Error::MigrationRequired)
            ),
            "outbound dispatch accepted an unmigrated store"
        );
        if version == 1 {
            store.migrate_custody().unwrap();
        }
    }
    store.migrate_outbound().unwrap();
    assert!(
        matches!(
            dispatch(
                &mut store,
                &Endpoint::from_registered(&service).unwrap(),
                &verifier,
                "good-token",
                "private-bus",
                &original,
                &limits()
            )
            .await,
            Err(Error::Denied)
        ),
        "empty policy allowed a send"
    );
    assert!(receiver.poll(0).await.unwrap().is_none());
    store
        .set_outbound_policy(
            "grant",
            2,
            &Policy {
                send: Some(Permission {
                    targets: [target.clone()].into(),
                    required_scope: "send:write".into(),
                }),
                reply: None,
            },
        )
        .unwrap();
    let first = dispatch(
        &mut store,
        &Endpoint::from_registered(&service).unwrap(),
        &verifier,
        "good-token",
        "private-bus",
        &original,
        &limits(),
    )
    .await
    .unwrap();
    let Outcome::Confirmed(Receipt::Send(sent)) = &first else {
        panic!("send did not return original bus receipt: {first:?}");
    };
    let delivery = receiver.poll(1).await.unwrap().unwrap();
    assert_eq!(delivery.message_id(), sent.message_id);
    assert!(delivery.text().ends_with("\noriginal bytes"));
    assert!(delivery.text().contains(service.address().unwrap()));
    receiver.ack(delivery.message_id()).await.unwrap();
    store
        .set_outbound_policy(
            "grant",
            3,
            &Policy {
                send: Some(Permission {
                    targets: [target.clone()].into(),
                    required_scope: "send:write".into(),
                }),
                reply: Some(Permission {
                    targets: [target.clone()].into(),
                    required_scope: "reply:write".into(),
                }),
            },
        )
        .unwrap();
    let held = store.try_operation_lease("gateway").unwrap().unwrap();
    let again = dispatch(
        &mut store,
        &Endpoint::from_registered(&service).unwrap(),
        &verifier,
        "good-token",
        "private-bus",
        &original,
        &limits(),
    )
    .await
    .expect("same request lost its original receipt");
    assert_eq!(again, first, "same request lost its original receipt");
    drop(held);
    assert_eq!(
        dispatch(
            &mut store,
            &Endpoint::from_registered(&service).unwrap(),
            &verifier,
            "good-token",
            "private-bus",
            &original,
            &limits()
        )
        .await
        .expect("same request lost its original receipt"),
        first
    );
    assert!(
        receiver.poll(0).await.unwrap().is_none(),
        "same request delivered twice"
    );
    for changed in [
        request("stable-request", &target, "changed bytes"),
        request(
            "stable-request",
            service.address().unwrap(),
            "original bytes",
        ),
    ] {
        assert!(matches!(
            dispatch(
                &mut store,
                &Endpoint::from_registered(&service).unwrap(),
                &verifier,
                "good-token",
                "private-bus",
                &changed,
                &limits()
            )
            .await,
            Err(Error::Conflict)
        ));
    }
    let oversized = request("oversized", &target, &"é".repeat(32768));
    assert!(
        matches!(
            dispatch(
                &mut store,
                &Endpoint::from_registered(&service).unwrap(),
                &verifier,
                "good-token",
                "private-bus",
                &oversized,
                &limits()
            )
            .await,
            Err(Error::Oversized)
        ),
        "oversized framed text was submitted"
    );
    assert!(receiver.poll(0).await.unwrap().is_none());
    let identity_only =
        Verifier::from_config(serde_json::from_value(fixture.config["verifier"].clone()).unwrap())
            .unwrap();
    fixture
        .tokens
        .lock()
        .unwrap()
        .insert("identity-only".into(), provider::claims(&fixture.binding));
    assert!(
        matches!(
            dispatch(
                &mut store,
                &Endpoint::from_registered(&service).unwrap(),
                &identity_only,
                "identity-only",
                "private-bus",
                &original,
                &limits()
            )
            .await,
            Err(Error::Denied)
        ),
        "identity-only verifier admitted write scope"
    );
    let mut bounded = limits();
    bounded.max_reservations = 1;
    assert!(
        matches!(
            dispatch(
                &mut store,
                &Endpoint::from_registered(&service).unwrap(),
                &verifier,
                "good-token",
                "private-bus",
                &request("over-capacity", &target, "small"),
                &bounded
            )
            .await,
            Err(Error::Capacity)
        ),
        "outbound reservations exceeded their count budget"
    );
    let tokens = fixture.tokens.clone();
    let revoked = request("revoked-after-reserve", &target, "must not submit");
    use tracing::instrument::WithSubscriber;
    let endpoint = Endpoint::from_registered(&service).unwrap();
    let operation_limits = limits();
    let result = dispatch(
        &mut store,
        &endpoint,
        &verifier,
        "good-token",
        "private-bus",
        &revoked,
        &operation_limits,
    )
    .with_subscriber(observer::AtEvent {
        target: "gateway_outbound_reserved",
        action: move || {
            tokens.lock().unwrap().get_mut("good-token").unwrap()["active"] =
                serde_json::json!(false);
        },
    })
    .await;
    assert!(
        matches!(result, Err(Error::Authentication(_))),
        "revoked token was not rechecked before submission"
    );
    assert!(receiver.poll(0).await.unwrap().is_none());
    drop(store);
    Store::open(&fixture.store_file).unwrap();
    println!("gateway-outbound-complete:receipt-payload-policy-size");
}

#[test]
#[ignore = "subprocess crash fixture with mandatory inert control"]
fn outbound_crash_child() {
    let Ok(document) = std::env::var("OUTBOUND_CHILD_DOCUMENT") else {
        println!("gateway-outbound-complete:child-control");
        return;
    };
    let document: serde_json::Value =
        serde_json::from_slice(&std::fs::read(document).unwrap()).unwrap();
    let phase = document["phase"].as_str().unwrap();
    tracing::subscriber::set_global_default(crash::Cut {
        target: match phase {
            "before" => "gateway_outbound_reserved",
            "after" => "gateway_outbound_submitted",
            _ => panic!("unknown cut"),
        },
        marker: document["marker"].as_str().unwrap().into(),
    })
    .unwrap();
    let config: xmsg_mcp_gateway::xmsg_config::XmsgConfig =
        serde_json::from_value(document["node"].clone()).unwrap();
    let verifier =
        Verifier::from_config(serde_json::from_value(document["verifier"].clone()).unwrap())
            .unwrap();
    let mut store = Store::open(std::path::Path::new(document["store"].as_str().unwrap())).unwrap();
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap()
        .block_on(async {
            let service = config.register().await.unwrap();
            dispatch(
                &mut store,
                &Endpoint::from_registered(&service).unwrap(),
                &verifier,
                "good-token",
                "private-bus",
                &request(
                    "crash-request",
                    document["target"].as_str().unwrap(),
                    "crash-preserved bytes",
                ),
                &limits(),
            )
            .await
            .unwrap();
        });
    panic!("outbound crash cut not reached");
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Recovery {
    Resume,
    Expire,
    Disable,
    Reenable,
    ExpiredReenable,
}

async fn crash_at(phase: &str, recovery: Recovery) {
    let expire = matches!(recovery, Recovery::Expire | Recovery::ExpiredReenable);
    let disable = matches!(
        recovery,
        Recovery::Disable | Recovery::Reenable | Recovery::ExpiredReenable
    );
    use std::process::{Command, Stdio};
    use std::time::{Duration, Instant};
    let binary = real_node::pinned_binary();
    let ca = real_node::Authority::generate();
    let from = real_node::Prepared::create("gateway", "gateway", Some(&ca));
    let to = real_node::Prepared::create("receiver", "receiver", Some(&ca));
    from.peer(&to, serde_json::json!({}));
    to.peer(&from, serde_json::json!({}));
    let mut from = from.launch(&binary).await;
    let to = to.launch(&binary).await;
    let mut receiver = to.config.register().await.unwrap();
    let target = receiver.address().unwrap().to_owned();
    let (fixture, mut store, verifier) = authority();
    store
        .set_outbound_policy(
            "grant",
            2,
            &Policy {
                send: Some(Permission {
                    targets: [target.clone()].into(),
                    required_scope: "send:write".into(),
                }),
                reply: None,
            },
        )
        .unwrap();
    let marker = fixture.keys._directory.path().join("outbound-cut");
    let document_file = fixture.keys._directory.path().join("worker.json");
    let mut verifier_document = fixture.config["verifier"].clone();
    verifier_document["required_scopes"] = serde_json::json!(["send:write", "reply:write"]);
    serving_fixture::private_file(&document_file,&serde_json::to_vec(&serde_json::json!({
        "phase":phase,"marker":marker,"target":target,"store":fixture.store_file,"verifier":verifier_document,
        "node":{"service":from.config.service,"expected_node":from.config.expected_node,"daemon_uid":from.config.daemon_uid,"register_socket":from.config.register_socket,"agent_socket":from.config.agent_socket,"operation_timeout_ms":2000}
    })).unwrap());
    let log_file = fixture.keys._directory.path().join("worker.log");
    let mut child = crash::Worker(
        Command::new(std::env::current_exe().unwrap())
            .args([
                "outbound_crash_child",
                "--exact",
                "--ignored",
                "--nocapture",
            ])
            .env("OUTBOUND_CHILD_DOCUMENT", &document_file)
            .stdout(Stdio::null())
            .stderr(std::fs::File::create(&log_file).unwrap())
            .spawn()
            .unwrap(),
    );
    let deadline = Instant::now() + Duration::from_secs(10);
    while !marker.exists() {
        assert!(
            child.0.try_wait().unwrap().is_none(),
            "worker exited before cut: {}",
            std::fs::read_to_string(&log_file).unwrap()
        );
        assert!(Instant::now() < deadline, "outbound crash cut not observed");
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    let inspect = rusqlite::Connection::open(&fixture.store_file).unwrap();
    let (key, state, receipt): (String, String, Option<String>) = inspect
        .query_row(
            "SELECT idempotency_key,state,receipt FROM outbound_reservations",
            [],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
        )
        .unwrap();
    assert_eq!(
        state, "pending",
        "reservation was not durable before submission"
    );
    assert!(receipt.is_none());
    assert!(
        store.try_operation_lease("gateway").unwrap().is_none(),
        "live child did not hold the service lease"
    );
    let pending = dispatch(
        &mut store,
        &Endpoint::from_registered(&receiver).unwrap(),
        &verifier,
        "good-token",
        "private-bus",
        &request("crash-request", &target, "crash-preserved bytes"),
        &limits(),
    )
    .await
    .unwrap();
    assert_eq!(
        pending,
        Outcome::Pending,
        "live holder permitted a second submission"
    );
    let original_id = if phase == "after" {
        let delivered = receiver.poll(1).await.unwrap().unwrap();
        let id = delivered.message_id().to_owned();
        receiver.ack(&id).await.unwrap();
        Some(id)
    } else {
        assert!(
            receiver.poll(0).await.unwrap().is_none(),
            "reserved work submitted before crash cut"
        );
        None
    };
    let mut disable_child = if disable {
        Some(crash::Worker(
            Command::new(env!("CARGO_BIN_EXE_xmsg-mcp-gateway"))
                .arg("--state")
                .arg(&fixture.store_file)
                .args(["disable", "grant", "3"])
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .spawn()
                .unwrap(),
        ))
    } else {
        None
    };
    if let Some(disabler) = &mut disable_child {
        tokio::time::sleep(Duration::from_millis(200)).await;
        assert!(
            disabler.0.try_wait().unwrap().is_none(),
            "disable bypassed the held operation lease"
        );
        let enabled: bool = inspect
            .query_row("SELECT enabled FROM grants", [], |r| r.get(0))
            .unwrap();
        assert!(
            enabled,
            "disable committed before the guarded submission finished"
        );
    }
    child.0.kill().unwrap();
    child.0.wait().unwrap();
    if !disable {
        assert!(
            store.try_operation_lease("gateway").unwrap().is_some(),
            "crash did not release kernel lease"
        );
    }
    if let Some(mut disabler) = disable_child {
        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            if let Some(status) = disabler.0.try_wait().unwrap() {
                assert!(status.success());
                break;
            }
            assert!(
                Instant::now() < deadline,
                "disable did not finish after lease release"
            );
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    }
    from.restart(&binary).await;
    let service = from.config.register().await.unwrap();
    if matches!(recovery, Recovery::Reenable | Recovery::ExpiredReenable) {
        store.set_enabled("grant", 4, true).unwrap();
    }
    let mut recovery_limits = limits();
    if expire {
        recovery_limits.dedup_lifetime_secs = 1;
        tokio::time::sleep(Duration::from_millis(1100)).await;
    }
    let recovered = dispatch(
        &mut store,
        &Endpoint::from_registered(&service).unwrap(),
        &verifier,
        "good-token",
        "private-bus",
        &request("crash-request", &target, "crash-preserved bytes"),
        &recovery_limits,
    )
    .await;
    if recovery == Recovery::Reenable {
        assert!(
            matches!(recovered, Err(Error::Denied)),
            "old pending work escaped disable and re-enable"
        );
    } else if disable && !expire {
        assert!(
            matches!(
                recovered,
                Err(Error::Authority(xmsg_mcp_gateway::grants::Error::Denied))
            ),
            "authorized submission began after disable committed"
        );
    } else if expire {
        assert_eq!(
            recovered.expect("expired stale reservation was denied instead of becoming unknown"),
            Outcome::ExpiredUnknown,
            "expired uncertainty was blindly retried"
        );
        let state: String = inspect
            .query_row("SELECT state FROM outbound_reservations", [], |r| r.get(0))
            .unwrap();
        assert_eq!(state, "unknown");
    } else {
        let Outcome::Confirmed(Receipt::Send(receipt)) = recovered.unwrap() else {
            panic!("recovery did not return bus receipt");
        };
        if let Some(original_id) = original_id {
            assert_eq!(
                receipt.message_id, original_id,
                "recovery lost the original message ID"
            );
        } else {
            let delivered = receiver.poll(1).await.unwrap().unwrap();
            assert!(
                delivered.text().ends_with("\ncrash-preserved bytes"),
                "recovery changed the stored framed body"
            );
            assert_eq!(receipt.message_id, delivered.message_id());
            receiver.ack(delivered.message_id()).await.unwrap();
        }
        let recovered_key: String = inspect
            .query_row(
                "SELECT idempotency_key FROM outbound_reservations",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(
            key, recovered_key,
            "recovery replaced the stored idempotency key"
        );
    }
    assert!(
        receiver.poll(0).await.unwrap().is_none(),
        "recovery submitted a second delivery"
    );
}

#[tokio::test]
#[ignore = "mandatory private-node outbound profile"]
async fn crash_after_reservation_recovers_with_the_stored_key() {
    crash_at("before", Recovery::Resume).await;
    println!("gateway-outbound-complete:crash-before");
}

#[tokio::test]
#[ignore = "mandatory private-node outbound profile"]
async fn accepted_before_confirm_crash_returns_original_message_id() {
    crash_at("after", Recovery::Resume).await;
    println!("gateway-outbound-complete:crash-after");
}

#[tokio::test]
#[ignore = "mandatory private-node outbound profile"]
async fn expired_uncertainty_never_blindly_retries() {
    crash_at("after", Recovery::Expire).await;
    println!("gateway-outbound-complete:expired-unknown");
}

#[tokio::test]
#[ignore = "mandatory private-node outbound profile"]
async fn disable_waits_for_the_service_lease_and_prevents_later_submission() {
    crash_at("before", Recovery::Disable).await;
    println!("gateway-outbound-complete:disable-order");
}

#[tokio::test]
#[ignore = "mandatory private-node outbound profile"]
async fn pending_work_stays_held_across_disable_and_reenable() {
    crash_at("before", Recovery::Reenable).await;
    println!("gateway-outbound-complete:held-revision");
}

#[tokio::test]
#[ignore = "mandatory private-node outbound profile"]
async fn expired_pending_work_becomes_unknown_even_after_grant_revision_changes() {
    crash_at("before", Recovery::ExpiredReenable).await;
    println!("gateway-outbound-complete:expired-stale-revision");
}

#[tokio::test]
#[ignore = "mandatory private-node outbound profile"]
async fn dispatch_does_not_change_the_callers_custody_busy_wait() {
    let node = real_node::Node::start(&real_node::pinned_binary()).await;
    let service = node.config.register().await.unwrap();
    let endpoint = Endpoint::from_registered(&service).unwrap();
    let (fixture, mut store, verifier) = authority();
    let operation = request(
        "denied-request",
        service.address().unwrap(),
        "no write policy",
    );
    assert!(matches!(
        dispatch(
            &mut store,
            &endpoint,
            &verifier,
            "good-token",
            "private-bus",
            &operation,
            &limits()
        )
        .await,
        Err(Error::Denied)
    ));
    let file = fixture.store_file.clone();
    let (ready_tx, ready_rx) = std::sync::mpsc::channel();
    let writer = std::thread::spawn(move || {
        let sql = rusqlite::Connection::open(file).unwrap();
        sql.execute_batch("BEGIN IMMEDIATE").unwrap();
        ready_tx.send(()).unwrap();
        std::thread::sleep(std::time::Duration::from_millis(300));
        sql.execute_batch("COMMIT").unwrap();
    });
    ready_rx
        .recv_timeout(std::time::Duration::from_secs(2))
        .unwrap();
    let result = store.record_custody_link(
        &xmsg_mcp_gateway::custody::Scope {
            bus_instance: "private-bus".into(),
            grant_id: "grant".into(),
        },
        true,
        &xmsg_mcp_gateway::custody::Limits::default(),
        100,
    );
    writer.join().unwrap();
    result.expect("dispatch disabled the caller Store's custody busy wait");
    let target = service.address().unwrap().to_owned();
    store
        .set_outbound_policy(
            "grant",
            2,
            &Policy {
                send: Some(Permission {
                    targets: [target.clone()].into(),
                    required_scope: "send:write".into(),
                }),
                reply: None,
            },
        )
        .unwrap();
    let file = fixture.store_file.clone();
    let (ready_tx, ready_rx) = std::sync::mpsc::channel();
    let heartbeat = std::thread::spawn(move || {
        let sql = rusqlite::Connection::open(file).unwrap();
        sql.execute_batch("BEGIN IMMEDIATE; UPDATE custody_counters SET value=value WHERE name='expired_metadata'").unwrap();
        ready_tx.send(()).unwrap();
        std::thread::sleep(std::time::Duration::from_millis(100));
        sql.execute_batch("COMMIT").unwrap();
    });
    ready_rx
        .recv_timeout(std::time::Duration::from_secs(2))
        .unwrap();
    let sent = dispatch(
        &mut store,
        &endpoint,
        &verifier,
        "good-token",
        "private-bus",
        &request("heartbeat-overlap", &target, "short heartbeat contention"),
        &limits(),
    )
    .await;
    heartbeat.join().unwrap();
    assert!(
        matches!(sent, Ok(Outcome::Confirmed(_))),
        "short heartbeat write refused a send: {sent:?}"
    );
    println!("gateway-outbound-complete:isolated-connection");
}

#[tokio::test]
#[ignore = "mandatory private-node outbound profile"]
async fn timeout_before_reservation_is_a_transient_refusal_not_unknown() {
    use std::os::unix::fs::PermissionsExt;
    use tokio::io::{AsyncBufReadExt, BufReader};
    let node = real_node::Node::start(&real_node::pinned_binary()).await;
    let mut service = node.config.register().await.unwrap();
    let endpoint = Endpoint::from_registered(&service).unwrap();
    let (fixture, mut store, verifier) = authority();
    store
        .set_outbound_policy(
            "grant",
            2,
            &Policy {
                send: Some(Permission {
                    targets: [service.address().unwrap().to_owned()].into(),
                    required_scope: "send:write".into(),
                }),
                reply: None,
            },
        )
        .unwrap();
    let backend = node
        .config
        .agent_socket
        .with_file_name("agent.backend.sock");
    std::fs::rename(&node.config.agent_socket, backend).unwrap();
    let listener = tokio::net::UnixListener::bind(&node.config.agent_socket).unwrap();
    std::fs::set_permissions(
        &node.config.agent_socket,
        std::fs::Permissions::from_mode(0o600),
    )
    .unwrap();
    let (entered_tx, entered_rx) = tokio::sync::oneshot::channel();
    let (release_tx, release_rx) = tokio::sync::oneshot::channel();
    let proxy = tokio::spawn(async move {
        let (socket, _) = listener.accept().await.unwrap();
        let mut socket = BufReader::new(socket);
        let mut frame = String::new();
        socket.read_line(&mut frame).await.unwrap();
        let request: serde_json::Value = serde_json::from_str(&frame).unwrap();
        assert_eq!(request["action"], "list");
        entered_tx.send(()).unwrap();
        release_rx.await.unwrap();
    });
    let operation = request(
        "not-submitted",
        service.address().unwrap(),
        "must not become unknown",
    );
    let mut operation_limits = limits();
    operation_limits.timeout = std::time::Duration::from_secs(1);
    let result = dispatch(
        &mut store,
        &endpoint,
        &verifier,
        "good-token",
        "private-bus",
        &operation,
        &operation_limits,
    );
    tokio::pin!(result);
    tokio::select! {
        output=&mut result => panic!("deadline case did not reach discovery: {output:?}"),
        ready=entered_rx => ready.unwrap(),
    }
    let output = result.await;
    release_tx.send(()).unwrap();
    proxy.await.unwrap();
    assert!(
        matches!(output, Err(Error::Deadline)),
        "pre-reservation timeout was reported as unknown: {output:?}"
    );
    let sql = rusqlite::Connection::open(&fixture.store_file).unwrap();
    let count: i64 = sql
        .query_row("SELECT COUNT(*) FROM outbound_reservations", [], |r| {
            r.get(0)
        })
        .unwrap();
    assert_eq!(count, 0);
    assert!(service.poll(0).await.unwrap().is_none());
    println!("gateway-outbound-complete:deadline-before-submit");
}

#[tokio::test]
#[ignore = "mandatory private-node outbound profile"]
async fn pending_recovery_timeout_during_discovery_remains_unknown() {
    use tracing::instrument::WithSubscriber;
    let node = real_node::Node::start(&real_node::pinned_binary()).await;
    let mut service = node.config.register().await.unwrap();
    let endpoint = Endpoint::from_registered(&service).unwrap();
    let (fixture, mut store, verifier) = authority();
    let target = service.address().unwrap().to_owned();
    store
        .set_outbound_policy(
            "grant",
            2,
            &Policy {
                send: Some(Permission {
                    targets: [target.clone()].into(),
                    required_scope: "send:write".into(),
                }),
                reply: None,
            },
        )
        .unwrap();
    let operation = request("unconfirmed-recovery", &target, "existing pending bytes");
    let tokens = fixture.tokens.clone();
    let normal_limits = limits();
    let first = dispatch(
        &mut store,
        &endpoint,
        &verifier,
        "good-token",
        "private-bus",
        &operation,
        &normal_limits,
    )
    .with_subscriber(observer::AtEvent {
        target: "gateway_outbound_reserved",
        action: move || {
            tokens.lock().unwrap().get_mut("good-token").unwrap()["active"] =
                serde_json::json!(false);
        },
    })
    .await;
    assert!(matches!(first, Err(Error::Authentication(_))));
    fixture
        .tokens
        .lock()
        .unwrap()
        .get_mut("good-token")
        .unwrap()["active"] = serde_json::json!(true);
    let sql = rusqlite::Connection::open(&fixture.store_file).unwrap();
    let row: (String, Option<String>) = sql
        .query_row("SELECT state,receipt FROM outbound_reservations", [], |r| {
            Ok((r.get(0)?, r.get(1)?))
        })
        .unwrap();
    assert_eq!(row, ("pending".into(), None));
    let mut stall = agent_stall::AgentStall::install(&node.config, "list");
    let mut short = limits();
    short.timeout = std::time::Duration::from_secs(1);
    let recovery = dispatch(
        &mut store,
        &endpoint,
        &verifier,
        "good-token",
        "private-bus",
        &operation,
        &short,
    );
    tokio::pin!(recovery);
    tokio::select! {
        result=&mut recovery => panic!("recovery did not reach stalled discovery: {result:?}"),
        response=stall.reached() => assert_eq!(response["status"],"ok"),
    }
    let result = recovery.await;
    stall.finish(false).await;
    assert!(
        matches!(result, Ok(Outcome::Unknown)),
        "pending recovery deadline was reported as transient: {result:?}"
    );
    let state: String = sql
        .query_row("SELECT state FROM outbound_reservations", [], |r| r.get(0))
        .unwrap();
    assert_eq!(state, "unknown");
    assert!(service.poll(0).await.unwrap().is_none());
    println!("gateway-outbound-complete:pending-recovery-deadline");
}

#[tokio::test]
#[ignore = "mandatory private-node outbound profile"]
async fn deadline_after_send_begins_keeps_the_outcome_unknown() {
    let node = real_node::Node::start(&real_node::pinned_binary()).await;
    let mut service = node.config.register().await.unwrap();
    let endpoint = Endpoint::from_registered(&service).unwrap();
    let (fixture, mut store, verifier) = authority();
    let target = service.address().unwrap().to_owned();
    store
        .set_outbound_policy(
            "grant",
            2,
            &Policy {
                send: Some(Permission {
                    targets: [target.clone()].into(),
                    required_scope: "send:write".into(),
                }),
                reply: None,
            },
        )
        .unwrap();
    let mut stall = agent_stall::AgentStall::install(&node.config, "send");
    let operation = request("send-deadline", &target, "accepted before response timeout");
    let mut short = limits();
    short.timeout = std::time::Duration::from_secs(1);
    let submission = dispatch(
        &mut store,
        &endpoint,
        &verifier,
        "good-token",
        "private-bus",
        &operation,
        &short,
    );
    tokio::pin!(submission);
    let accepted = tokio::select! {
        result=&mut submission => panic!("send did not reach the stalled response: {result:?}"),
        response=stall.reached() => response,
    };
    assert_eq!(accepted["status"], "ok");
    let result = submission.await;
    stall.finish(false).await;
    assert!(
        matches!(result, Ok(Outcome::Unknown)),
        "in-flight send deadline was reported as transient: {result:?}"
    );
    let sql = rusqlite::Connection::open(&fixture.store_file).unwrap();
    let state: String = sql
        .query_row("SELECT state FROM outbound_reservations", [], |r| r.get(0))
        .unwrap();
    assert_eq!(state, "unknown");
    let delivery = service.poll(1).await.unwrap().unwrap();
    assert_eq!(Some(delivery.message_id()), accepted["message_id"].as_str());
    assert!(delivery
        .text()
        .ends_with("\naccepted before response timeout"));
    service.ack(delivery.message_id()).await.unwrap();
    assert!(service.poll(0).await.unwrap().is_none());
    println!("gateway-outbound-complete:send-in-flight-deadline");
}

#[tokio::test]
#[ignore = "mandatory private-node outbound profile"]
async fn confirmed_reply_replay_survives_policy_write_and_correlation_expiry() {
    let binary = real_node::pinned_binary();
    let ca = real_node::Authority::generate();
    let from = real_node::Prepared::create("gateway", "gateway", Some(&ca));
    let to = real_node::Prepared::create("receiver", "receiver", Some(&ca));
    from.peer(&to, serde_json::json!({}));
    to.peer(&from, serde_json::json!({}));
    let from = from.launch(&binary).await;
    let to = to.launch(&binary).await;
    let mut service = from.config.register().await.unwrap();
    let endpoint = Endpoint::from_registered(&service).unwrap();
    let mut receiver = to.config.register().await.unwrap();
    let target = receiver.address().unwrap().to_owned();
    let (fixture, mut store, verifier) = authority();
    let permission = Permission {
        targets: [target.clone()].into(),
        required_scope: "reply:write".into(),
    };
    store
        .set_outbound_policy(
            "grant",
            2,
            &Policy {
                send: None,
                reply: Some(permission.clone()),
            },
        )
        .unwrap();
    let timestamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64;
    let scope = xmsg_mcp_gateway::custody::Scope {
        bus_instance: "private-bus".into(),
        grant_id: "grant".into(),
    };
    let incoming = receiver
        .send(
            service.address().unwrap(),
            "retained reply correlation",
            Some("replay-correlation"),
        )
        .await
        .unwrap();
    let delivery = service.poll(1).await.unwrap().unwrap();
    let custody_limits = xmsg_mcp_gateway::custody::Limits::default();
    store
        .accept_delivery(&scope, &service, &delivery, &custody_limits, timestamp)
        .unwrap();
    service.ack(delivery.message_id()).await.unwrap();
    let operation = Request::Reply(ReplyArguments {
        request_id: RequestId::parse("confirmed-reply").unwrap(),
        message_id: incoming.message_id,
        text: "original reply bytes".into(),
    });
    let first = dispatch(
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
    assert!(matches!(first, Outcome::Confirmed(Receipt::Reply(_))));
    let delivery = receiver.poll(1).await.unwrap().unwrap();
    receiver.ack(delivery.message_id()).await.unwrap();
    store
        .set_outbound_policy(
            "grant",
            3,
            &Policy {
                send: Some(Permission {
                    targets: [target].into(),
                    required_scope: "send:write".into(),
                }),
                reply: Some(permission),
            },
        )
        .unwrap();
    let replay = dispatch(
        &mut store,
        &endpoint,
        &verifier,
        "good-token",
        "private-bus",
        &operation,
        &limits(),
    )
    .await
    .expect("confirmed reply was denied after a policy write");
    assert_eq!(replay, first);
    store
        .custody_status(
            &scope,
            &custody_limits,
            timestamp + custody_limits.content_retention_secs + 1,
            604800,
        )
        .unwrap();
    let sql = rusqlite::Connection::open(&fixture.store_file).unwrap();
    let expired: bool = sql
        .query_row("SELECT text IS NULL FROM custody_items", [], |r| r.get(0))
        .unwrap();
    assert!(expired);
    let replay = dispatch(
        &mut store,
        &endpoint,
        &verifier,
        "good-token",
        "private-bus",
        &operation,
        &limits(),
    )
    .await
    .expect("confirmed reply was denied after its correlation expired");
    assert_eq!(replay, first);
    assert!(
        receiver.poll(0).await.unwrap().is_none(),
        "confirmed reply replay submitted again"
    );
    println!("gateway-outbound-complete:confirmed-reply-replay");
}

#[tokio::test]
#[ignore = "mandatory private-node outbound profile"]
async fn inbound_commit_and_ack_complete_while_outbound_acceptance_is_stalled() {
    use std::os::unix::fs::PermissionsExt;
    use std::time::{Duration, Instant};
    use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
    use tokio::net::{UnixListener, UnixStream};
    let binary = real_node::pinned_binary();
    let ca = real_node::Authority::generate();
    let from = real_node::Prepared::create("gateway", "gateway", Some(&ca));
    let to = real_node::Prepared::create("receiver", "receiver", Some(&ca));
    from.peer(&to, serde_json::json!({}));
    to.peer(&from, serde_json::json!({}));
    let from = from.launch(&binary).await;
    let to = to.launch(&binary).await;
    let mut service = from.config.register().await.unwrap();
    let mut receiver = to.config.register().await.unwrap();
    let target = receiver.address().unwrap().to_owned();
    let (fixture, mut store, verifier) = authority();
    store
        .set_outbound_policy(
            "grant",
            2,
            &Policy {
                send: Some(Permission {
                    targets: [target.clone()].into(),
                    required_scope: "send:write".into(),
                }),
                reply: None,
            },
        )
        .unwrap();
    let incoming = receiver
        .send(
            service.address().unwrap(),
            "inbound must still commit",
            Some("inbound-during-outbound"),
        )
        .await
        .unwrap();
    let delivery = service.poll(1).await.unwrap().unwrap();
    assert_eq!(delivery.message_id(), incoming.message_id);
    let endpoint = Endpoint::from_registered(&service).unwrap();
    let backend = from
        .config
        .agent_socket
        .with_file_name("agent.backend.sock");
    std::fs::rename(&from.config.agent_socket, &backend).unwrap();
    let listener = UnixListener::bind(&from.config.agent_socket).unwrap();
    std::fs::set_permissions(
        &from.config.agent_socket,
        std::fs::Permissions::from_mode(0o600),
    )
    .unwrap();
    let (entered_tx, entered_rx) = tokio::sync::oneshot::channel();
    let (release_tx, release_rx) = tokio::sync::oneshot::channel();
    let proxy = tokio::spawn(async move {
        let mut entered = Some(entered_tx);
        let mut release = Some(release_rx);
        loop {
            let (socket, _) = listener.accept().await.unwrap();
            let mut socket = BufReader::new(socket);
            let mut frame = String::new();
            socket.read_line(&mut frame).await.unwrap();
            let value: serde_json::Value = serde_json::from_str(&frame).unwrap();
            let stalled = value["action"] == "send";
            if stalled {
                entered.take().unwrap().send(()).unwrap();
                release.take().unwrap().await.unwrap();
            }
            let mut upstream = BufReader::new(UnixStream::connect(&backend).await.unwrap());
            upstream
                .get_mut()
                .write_all(frame.as_bytes())
                .await
                .unwrap();
            let mut response = String::new();
            upstream.read_line(&mut response).await.unwrap();
            socket
                .get_mut()
                .write_all(response.as_bytes())
                .await
                .unwrap();
            if stalled {
                break;
            }
        }
    });
    let operation = request("stalled-submit", &target, "outbound waits");
    let operation_limits = limits();
    let submission = dispatch(
        &mut store,
        &endpoint,
        &verifier,
        "good-token",
        "private-bus",
        &operation,
        &operation_limits,
    );
    tokio::pin!(submission);
    tokio::select! {
        result=&mut submission => panic!("outbound did not stall at acceptance: {result:?}"),
        result=entered_rx => result.unwrap(),
        _=tokio::time::sleep(Duration::from_secs(3)) => panic!("outbound send did not reach acceptance fixture"),
    }
    let store_file = fixture.store_file.clone();
    let inbound = tokio::task::spawn_blocking(move || {
        let mut inbound = Store::open(&store_file).unwrap();
        let started = Instant::now();
        let result = inbound.accept_delivery(
            &xmsg_mcp_gateway::custody::Scope {
                bus_instance: "private-bus".into(),
                grant_id: "grant".into(),
            },
            &service,
            &delivery,
            &xmsg_mcp_gateway::custody::Limits::default(),
            100,
        );
        (
            result,
            service,
            delivery.message_id().to_owned(),
            started.elapsed(),
        )
    });
    tokio::pin!(inbound);
    let completed = tokio::time::timeout(Duration::from_millis(500), &mut inbound).await;
    let timely = completed.is_ok();
    let mut acknowledged_service = None;
    if let Ok(result) = completed {
        let (accepted, mut service, id, elapsed) = result.unwrap();
        assert!(accepted.is_ok());
        assert!(elapsed < Duration::from_millis(500));
        tokio::time::timeout(Duration::from_millis(500), service.ack(&id))
            .await
            .expect("inbound ACK blocked behind outbound lease")
            .unwrap();
        acknowledged_service = Some(service);
    }
    release_tx.send(()).unwrap();
    let result = submission.await;
    proxy.await.unwrap();
    drop(acknowledged_service);
    if !timely {
        let _ = inbound.await;
    }
    assert!(
        timely,
        "SQLite write guard blocked inbound custody during network submission"
    );
    assert!(
        matches!(result.as_ref().unwrap(), Outcome::Confirmed(_)),
        "stalled send returned {result:?}"
    );
    let delivered = receiver.poll(1).await.unwrap().unwrap();
    receiver.ack(delivered.message_id()).await.unwrap();
    println!("gateway-outbound-complete:inbound-concurrency");
}

#[tokio::test]
#[ignore = "mandatory private-node outbound profile"]
async fn replies_require_owned_current_correlations_and_preserve_bus_receipts() {
    let binary = real_node::pinned_binary();
    let ca = real_node::Authority::generate();
    let from = real_node::Prepared::create("gateway", "gateway", Some(&ca));
    let to = real_node::Prepared::create("receiver", "receiver", Some(&ca));
    from.peer(&to, serde_json::json!({}));
    to.peer(&from, serde_json::json!({}));
    let from = from.launch(&binary).await;
    let to = to.launch(&binary).await;
    let mut service = from.config.register().await.unwrap();
    let endpoint = Endpoint::from_registered(&service).unwrap();
    let mut receiver = to.config.register().await.unwrap();
    let target = receiver.address().unwrap().to_owned();
    let (fixture, mut store, verifier) = authority();
    store
        .set_outbound_policy(
            "grant",
            2,
            &Policy {
                send: None,
                reply: Some(Permission {
                    targets: [target.clone()].into(),
                    required_scope: "reply:write".into(),
                }),
            },
        )
        .unwrap();
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64;
    let original = receiver
        .send(
            service.address().unwrap(),
            "owned incoming correlation",
            Some("owned-incoming"),
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
            &service,
            &delivery,
            &xmsg_mcp_gateway::custody::Limits::default(),
            now,
        )
        .unwrap();
    service.ack(delivery.message_id()).await.unwrap();
    let operation = Request::Reply(ReplyArguments {
        request_id: RequestId::parse("owned-reply").unwrap(),
        message_id: original.message_id.clone(),
        text: "reply bytes".into(),
    });
    let first = dispatch(
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
    let Outcome::Confirmed(Receipt::Reply(receipt)) = &first else {
        panic!("reply did not return the original reply record");
    };
    assert_eq!(
        receipt.message_id, original.message_id,
        "reply record fabricated the original correlation"
    );
    let delivered = receiver.poll(1).await.unwrap().unwrap();
    assert_eq!(
        receipt.pushed_message_id.as_deref(),
        Some(delivered.message_id())
    );
    assert_eq!(delivered.in_reply_to(), Some(original.message_id.as_str()));
    assert!(delivered.text().ends_with("\nreply bytes"));
    receiver.ack(delivered.message_id()).await.unwrap();
    assert_eq!(
        dispatch(
            &mut store,
            &endpoint,
            &verifier,
            "good-token",
            "private-bus",
            &operation,
            &limits()
        )
        .await
        .unwrap(),
        first
    );
    assert!(
        receiver.poll(0).await.unwrap().is_none(),
        "same reply delivered twice"
    );
    let mut foreign = fixture.binding.clone();
    foreign.subject = "different-owner".into();
    store.enroll("foreign-grant", &foreign).unwrap();
    let foreign_message = receiver
        .send(
            service.address().unwrap(),
            "other owner's incoming correlation",
            Some("foreign-incoming"),
        )
        .await
        .unwrap();
    let delivery = service.poll(1).await.unwrap().unwrap();
    store
        .accept_delivery(
            &xmsg_mcp_gateway::custody::Scope {
                bus_instance: "private-bus".into(),
                grant_id: "foreign-grant".into(),
            },
            &service,
            &delivery,
            &xmsg_mcp_gateway::custody::Limits::default(),
            now,
        )
        .unwrap();
    service.ack(delivery.message_id()).await.unwrap();
    let foreign_reply = Request::Reply(ReplyArguments {
        request_id: RequestId::parse("foreign-reply").unwrap(),
        message_id: foreign_message.message_id,
        text: "must refuse".into(),
    });
    assert!(
        matches!(
            dispatch(
                &mut store,
                &endpoint,
                &verifier,
                "good-token",
                "private-bus",
                &foreign_reply,
                &limits()
            )
            .await,
            Err(Error::Denied)
        ),
        "foreign owner's correlation authorized a reply"
    );
    store.set_enabled("grant", 3, false).unwrap();
    store.set_enabled("grant", 4, true).unwrap();
    let held = Request::Reply(ReplyArguments {
        request_id: RequestId::parse("held-reply").unwrap(),
        message_id: original.message_id,
        text: "old work must remain held".into(),
    });
    assert!(
        matches!(
            dispatch(
                &mut store,
                &endpoint,
                &verifier,
                "good-token",
                "private-bus",
                &held,
                &limits()
            )
            .await,
            Err(Error::Denied)
        ),
        "old inbound work escaped its original grant revision"
    );
    assert!(receiver.poll(0).await.unwrap().is_none());
    println!("gateway-outbound-complete:owned-reply");
}

async fn busy_at_outcome(after_acceptance: bool) {
    use std::sync::{Arc, Mutex};
    use tracing::instrument::WithSubscriber;
    let binary = real_node::pinned_binary();
    let ca = real_node::Authority::generate();
    let from = real_node::Prepared::create("gateway", "gateway", Some(&ca));
    let to = real_node::Prepared::create("receiver", "receiver", Some(&ca));
    from.peer(&to, serde_json::json!({}));
    to.peer(&from, serde_json::json!({}));
    let from = from.launch(&binary).await;
    let to = to.launch(&binary).await;
    let service = from.config.register().await.unwrap();
    let endpoint = Endpoint::from_registered(&service).unwrap();
    let mut receiver = to.config.register().await.unwrap();
    let target = receiver.address().unwrap().to_owned();
    let (fixture, mut store, verifier) = authority();
    store
        .set_outbound_policy(
            "grant",
            2,
            &Policy {
                send: Some(Permission {
                    targets: [target.clone()].into(),
                    required_scope: "send:write".into(),
                }),
                reply: None,
            },
        )
        .unwrap();
    let writer = Arc::new(Mutex::new(None::<rusqlite::Connection>));
    let open_writer = |file: &std::path::Path| {
        let sql = rusqlite::Connection::open(file).unwrap();
        sql.busy_timeout(std::time::Duration::ZERO).unwrap();
        sql.execute_batch("BEGIN IMMEDIATE; UPDATE custody_counters SET value=value WHERE name='expired_metadata'").unwrap();
        sql
    };
    if !after_acceptance {
        *writer.lock().unwrap() = Some(open_writer(&fixture.store_file));
    }
    let lock = writer.clone();
    let file = fixture.store_file.clone();
    let operation = request(
        "busy-request",
        &target,
        "must survive a busy outcome commit",
    );
    let operation_limits = limits();
    let dispatch_started = std::time::Instant::now();
    let first = dispatch(
        &mut store,
        &endpoint,
        &verifier,
        "good-token",
        "private-bus",
        &operation,
        &operation_limits,
    )
    .with_subscriber(observer::AtEvent {
        target: "gateway_outbound_submitted",
        action: move || {
            if after_acceptance {
                *lock.lock().unwrap() = Some(open_writer(&file));
            }
        },
    })
    .await;
    if !after_acceptance {
        assert!(
            dispatch_started.elapsed() <= std::time::Duration::from_millis(750),
            "pre-submit BUSY exceeded its bounded wait: {:?}",
            dispatch_started.elapsed()
        );
    }
    let sql = rusqlite::Connection::open(&fixture.store_file).unwrap();
    sql.busy_timeout(std::time::Duration::ZERO).unwrap();
    let original_id = if after_acceptance {
        assert_eq!(
            first.expect("accepted send reported failure on a busy outcome commit"),
            Outcome::Pending,
            "busy outcome commit did not leave acceptance pending"
        );
        let row: (String, Option<String>) = sql
            .query_row("SELECT state,receipt FROM outbound_reservations", [], |r| {
                Ok((r.get(0)?, r.get(1)?))
            })
            .unwrap();
        assert_eq!(row, ("pending".into(), None));
        let delivered = receiver.poll(1).await.unwrap().unwrap();
        let id = delivered.message_id().to_owned();
        receiver.ack(&id).await.unwrap();
        Some(id)
    } else {
        assert!(
            matches!(first, Err(Error::Busy)),
            "pre-submit BUSY was not a transient refusal"
        );
        let count: i64 = sql
            .query_row("SELECT COUNT(*) FROM outbound_reservations", [], |r| {
                r.get(0)
            })
            .unwrap();
        assert_eq!(count, 0, "pre-submit BUSY left a reservation row");
        assert!(
            receiver.poll(0).await.unwrap().is_none(),
            "pre-submit BUSY still submitted"
        );
        let write=sql.execute("INSERT INTO outbound_reservations (owner,operation,request_id,payload_hash,sender,grant_id,grant_revision,idempotency_key,target,correlation,framed_text,created_at,retry_until,state) VALUES ('owner','send','forbidden','hash','sender','grant',3,'key','target',NULL,'body',1,2,'pending')",[]);
        assert!(
            matches!(write,Err(rusqlite::Error::SqliteFailure(code,_)) if code.code==rusqlite::ErrorCode::DatabaseBusy),
            "a reservation bypassed SQLite's write lock"
        );
        None
    };
    writer
        .lock()
        .unwrap()
        .take()
        .unwrap()
        .execute_batch("COMMIT")
        .unwrap();
    if after_acceptance {
        assert!(
            matches!(sql.execute("UPDATE outbound_reservations SET state='failed'", []), Err(rusqlite::Error::SqliteFailure(code,_)) if code.extended_code==rusqlite::ffi::SQLITE_CONSTRAINT_CHECK),
            "schema accepted a fabricated failure state"
        );
        let state: String = sql
            .query_row("SELECT state FROM outbound_reservations", [], |r| r.get(0))
            .unwrap();
        assert_eq!(state, "pending");
    }
    let Outcome::Confirmed(Receipt::Send(receipt)) = dispatch(
        &mut store,
        &endpoint,
        &verifier,
        "good-token",
        "private-bus",
        &operation,
        &limits(),
    )
    .await
    .unwrap() else {
        panic!("busy recovery did not return its bus receipt");
    };
    if let Some(id) = original_id {
        assert_eq!(
            receipt.message_id, id,
            "outcome BUSY lost the original message ID"
        );
    } else {
        let delivered = receiver.poll(1).await.unwrap().unwrap();
        assert_eq!(receipt.message_id, delivered.message_id());
        receiver.ack(delivered.message_id()).await.unwrap();
    }
    assert!(
        receiver.poll(0).await.unwrap().is_none(),
        "busy recovery produced a duplicate delivery"
    );
}

#[tokio::test]
#[ignore = "mandatory private-node outbound profile"]
async fn busy_reservation_refuses_transiently_without_a_row_or_submission() {
    busy_at_outcome(false).await;
    println!("gateway-outbound-complete:reservation-busy");
}

#[tokio::test]
#[ignore = "mandatory private-node outbound profile"]
async fn busy_outcome_commit_keeps_pending_and_recovers_original_message_id() {
    busy_at_outcome(true).await;
    println!("gateway-outbound-complete:outcome-busy");
}
