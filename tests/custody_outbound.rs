#![cfg(target_os = "linux")]

#[path = "common/custody_crash.rs"]
mod crash;
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
        dispatch, Endpoint, Error, Limits, Outcome, Permission, Policy, Receipt, Request,
        RequestId, SendArguments,
    },
};

fn limits() -> Limits {
    Limits {
        dedup_lifetime_secs: 86400,
        max_text_bytes: 65536,
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
    let (fixture, mut store, verifier) = authority();
    let original = request("stable-request", &target, "original bytes");
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
    .unwrap();
    assert_eq!(again, first, "same request lost its original receipt");
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

async fn crash_at(phase: &str, expire: bool, disable: bool) {
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
    if disable {
        assert!(
            matches!(
                recovered,
                Err(Error::Authority(xmsg_mcp_gateway::grants::Error::Denied))
            ),
            "authorized submission began after disable committed"
        );
    } else if expire {
        assert_eq!(
            recovered.unwrap(),
            Outcome::Unknown,
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
    crash_at("before", false, false).await;
    println!("gateway-outbound-complete:crash-before");
}

#[tokio::test]
#[ignore = "mandatory private-node outbound profile"]
async fn accepted_before_confirm_crash_returns_original_message_id() {
    crash_at("after", false, false).await;
    println!("gateway-outbound-complete:crash-after");
}

#[tokio::test]
#[ignore = "mandatory private-node outbound profile"]
async fn expired_uncertainty_never_blindly_retries() {
    crash_at("after", true, false).await;
    println!("gateway-outbound-complete:expired-unknown");
}

#[tokio::test]
#[ignore = "mandatory private-node outbound profile"]
async fn disable_waits_for_the_service_lease_and_prevents_later_submission() {
    crash_at("before", false, true).await;
    println!("gateway-outbound-complete:disable-order");
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
