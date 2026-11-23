#![cfg(unix)]
#[allow(dead_code)]
#[path = "common/provider.rs"]
mod provider;
#[allow(dead_code)]
#[path = "common/serving_fixture.rs"]
mod serving_fixture;

use base64::Engine;
use serde_json::{json, Value};
use std::collections::BTreeSet;
use std::os::unix::fs::PermissionsExt;
use std::sync::{
    atomic::{AtomicUsize, Ordering},
    Arc, Mutex,
};
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::UnixListener;
use xmsg_mcp_gateway::{
    auth::Verifier,
    grants::Store,
    outbound::{
        dispatch, Endpoint, Error, Limits, Outcome, Permission, Policy, Receipt, Request,
        RequestId, SendArguments,
    },
    xmsg_config::XmsgConfig,
};

fn token(claims: &Value) -> String {
    format!(
        "e30.{}.fixture",
        base64::engine::general_purpose::URL_SAFE_NO_PAD
            .encode(serde_json::to_vec(claims).unwrap())
    )
}

struct Harness {
    _fixture: serving_fixture::Fixture,
    _dir: tempfile::TempDir,
    store: Store,
    endpoint: Endpoint,
    verifier: Verifier,
    bearer: String,
    limits: Limits,
    list_calls: Arc<AtomicUsize>,
    send_calls: Arc<AtomicUsize>,
    server: tokio::task::JoinHandle<()>,
    _reg_server: tokio::task::JoinHandle<()>,
    _registration: xmsg::client::RegisteredService,
}

async fn setup_harness<F>(targets: BTreeSet<String>, responder: F) -> Harness
where
    F: Fn(&Value) -> Value + Send + Sync + 'static,
{
    let fixture = serving_fixture::Fixture::new();
    let mut verifier_cfg = fixture.config["verifier"].clone();
    verifier_cfg["required_scopes"] = json!(["send:write"]);
    let verifier =
        Verifier::from_profiles(vec![serde_json::from_value(verifier_cfg).unwrap()]).unwrap();
    let mut claims = provider::claims(&fixture.binding);
    claims["scope"] = json!("send:write");
    let bearer = token(&claims);
    fixture
        .tokens
        .lock()
        .unwrap()
        .insert(bearer.clone(), claims);

    let mut store = Store::open(&fixture.store_file).unwrap();
    store.migrate_profiles().unwrap();
    store.migrate_custody().unwrap();
    store.migrate_outbound().unwrap();
    store.migrate_retirement().unwrap();
    store
        .set_outbound_policy(
            "grant",
            2,
            &Policy {
                send: Some(Permission {
                    targets,
                    required_scope: "send:write".into(),
                }),
                reply: None,
            },
        )
        .unwrap();

    let dir = tempfile::tempdir().unwrap();
    std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    let config = XmsgConfig {
        service: "gateway".into(),
        expected_node: "fixture".into(),
        daemon_uid: xmsg::client::current_uid(),
        register_socket: dir.path().join("register.sock"),
        agent_socket: dir.path().join("agent.sock"),
        max_frame_bytes: 8192,
        operation_timeout_ms: 2000,
    };
    let reg_listener = UnixListener::bind(&config.register_socket).unwrap();
    let agent_listener = UnixListener::bind(&config.agent_socket).unwrap();
    std::fs::set_permissions(
        &config.register_socket,
        std::fs::Permissions::from_mode(0o600),
    )
    .unwrap();
    std::fs::set_permissions(&config.agent_socket, std::fs::Permissions::from_mode(0o600)).unwrap();

    let reg_server = tokio::spawn(async move {
        let mut stream = BufReader::new(reg_listener.accept().await.unwrap().0);
        let mut line = String::new();
        stream.read_line(&mut line).await.unwrap();
        stream
            .get_mut()
            .write_all(
                b"{\"status\":\"ok\",\"node\":\"fixture\",\"address\":\"gateway@fixture\"}\n",
            )
            .await
            .unwrap();
        let _ = stream.read(&mut [0]).await;
    });

    let list_calls = Arc::new(AtomicUsize::new(0));
    let send_calls = Arc::new(AtomicUsize::new(0));
    let list_calls_bg = Arc::clone(&list_calls);
    let send_calls_bg = Arc::clone(&send_calls);
    let responder = Arc::new(responder);

    let server = tokio::spawn(async move {
        while let Ok((stream, _)) = agent_listener.accept().await {
            let mut reader = BufReader::new(stream);
            let mut line = String::new();
            if reader.read_line(&mut line).await.unwrap_or(0) == 0 {
                continue;
            }
            let req: Value = serde_json::from_str(&line).unwrap();
            match req["action"].as_str() {
                Some("list") => {
                    list_calls_bg.fetch_add(1, Ordering::SeqCst);
                }
                Some("send") => {
                    send_calls_bg.fetch_add(1, Ordering::SeqCst);
                }
                _ => {}
            }
            let resp = responder(&req);
            let mut payload = serde_json::to_vec(&resp).unwrap();
            payload.push(b'\n');
            let _ = reader.get_mut().write_all(&payload).await;
        }
    });

    let registration = config.register().await.unwrap();
    let endpoint = Endpoint::from_registered(&registration).unwrap();

    Harness {
        _fixture: fixture,
        _dir: dir,
        store,
        endpoint,
        verifier,
        bearer,
        limits: Limits {
            dedup_lifetime_secs: 86400,
            result_recovery_secs: 86400,
            max_framed_bytes: 65536,
            timeout: std::time::Duration::from_secs(3),
            max_reservations: 1000,
            max_retained_bytes: 64 * 1024 * 1024,
        },
        list_calls,
        send_calls,
        server,
        _reg_server: reg_server,
        _registration: registration,
    }
}

fn send_req(id: &str, to: &str) -> Request {
    Request::Send(SendArguments {
        to: to.into(),
        text: "ping".into(),
        request_id: RequestId::parse(id).unwrap(),
        attachments: vec![],
    })
}

#[tokio::test]
async fn admitted_hub_routed_node_exact_address_proceeds_to_send() {
    let seen_targets = Arc::new(Mutex::new(Vec::<String>::new()));
    let seen_bg = Arc::clone(&seen_targets);
    let mut h = setup_harness(["*@sini.patch".into()].into(), move |req| {
        match req["action"].as_str() {
            Some("list") => {
                json!({"status":"error","error":"not_found","detail":"unknown node 'sini.patch'"})
            }
            Some("send") => {
                let to = req["to"].as_str().unwrap().to_string();
                seen_bg.lock().unwrap().push(to.clone());
                json!({"status":"ok","message_id":"msg-1","address":to,"outcome":"queued"})
            }
            other => panic!("unexpected action: {other:?}"),
        }
    })
    .await;

    let cases = [
        (
            "req-uuid",
            "0199cecf-a11c-7000-8000-0000000a11ce@sini.patch",
        ),
        (
            "req-sub",
            "0199cecf-a11c-7000-8000-0000000a11ce/0199cecf-b0b0-7000-8000-00000000b0b0@sini.patch",
        ),
        ("req-svc", "agy-patch@sini.patch"),
    ];
    for (req_id, target) in cases {
        let out = dispatch(
            &mut h.store,
            &h.endpoint,
            &h.verifier,
            &h.bearer,
            "bus",
            &send_req(req_id, target),
            &h.limits,
        )
        .await
        .expect("exact canonical target on admitted hub-routed node must proceed");
        assert_eq!(
            out,
            Outcome::Confirmed(Receipt::Send(xmsg::client::SendResult {
                message_id: "msg-1".into(),
                address: target.into(),
                outcome: "queued".into(),
            }))
        );
    }
    assert_eq!(h.list_calls.load(Ordering::SeqCst), 3);
    assert_eq!(h.send_calls.load(Ordering::SeqCst), 3);
    assert_eq!(
        *seen_targets.lock().unwrap(),
        vec![
            "0199cecf-a11c-7000-8000-0000000a11ce@sini.patch",
            "0199cecf-a11c-7000-8000-0000000a11ce/0199cecf-b0b0-7000-8000-00000000b0b0@sini.patch",
            "agy-patch@sini.patch",
        ]
    );
    h.server.abort();
}

#[tokio::test]
async fn admitted_hub_routed_node_label_or_parent_lookup_refused() {
    let mut h = setup_harness(["*@sini.patch".into()].into(), |req| {
        match req["action"].as_str() {
            Some("list") => {
                json!({"status":"error","error":"not_found","detail":"unknown node 'sini.patch'"})
            }
            other => panic!("send must not be called for {other:?}"),
        }
    })
    .await;

    let cases = [
        ("req-lbl-dot", "foo.bar@sini.patch"),
        ("req-lbl-reserved", "xmsg@sini.patch"),
        (
            "req-sub-lbl-child",
            "0199cecf-a11c-7000-8000-0000000a11ce/researcher@sini.patch",
        ),
        ("req-sub-lbl-parent", "Alice/researcher@sini.patch"),
    ];
    for (req_id, target) in cases {
        let err = dispatch(
            &mut h.store,
            &h.endpoint,
            &h.verifier,
            &h.bearer,
            "bus",
            &send_req(req_id, target),
            &h.limits,
        )
        .await
        .expect_err("non-canonical target must fail closed");
        assert!(
            matches!(err, Error::NotVerifiableViaHub),
            "expected NotVerifiableViaHub for {target}, got {err:?}"
        );
    }
    assert_eq!(h.list_calls.load(Ordering::SeqCst), 4);
    assert_eq!(h.send_calls.load(Ordering::SeqCst), 0);
    h.server.abort();
}

#[tokio::test]
async fn non_admitted_node_unknown_refusal_remains_denied() {
    let mut h = setup_harness(["agy-patch@sini.patch".into()].into(), |req| {
        match req["action"].as_str() {
            Some("list") => {
                json!({"status":"error","error":"not_found","detail":"unknown node 'sini.patch'"})
            }
            other => panic!("send must not be called for {other:?}"),
        }
    })
    .await;

    let err = dispatch(
        &mut h.store,
        &h.endpoint,
        &h.verifier,
        &h.bearer,
        "bus",
        &send_req("req-non-wildcard", "agy-patch@sini.patch"),
        &h.limits,
    )
    .await
    .expect_err("non-wildcard node must still fail on list not_found");
    assert!(
        matches!(
            err,
            Error::Transport(xmsg::client::ClientError::Refused { ref code }) if code == "not_found"
        ),
        "expected Refused(not_found), got {err:?}"
    );

    let denied = dispatch(
        &mut h.store,
        &h.endpoint,
        &h.verifier,
        &h.bearer,
        "bus",
        &send_req("req-unlisted", "agy-patch@other.node"),
        &h.limits,
    )
    .await
    .expect_err("unlisted node must be denied");
    assert!(matches!(denied, Error::Denied));
    assert_eq!(h.send_calls.load(Ordering::SeqCst), 0);
    h.server.abort();
}

#[tokio::test]
async fn admitted_hub_routed_node_other_list_error_fails_closed() {
    let mut h = setup_harness(["*@sini.patch".into()].into(), |req| {
        match req["action"].as_str() {
            Some("list") => {
                json!({"status":"error","error":"unavailable","detail":"sidecar busy"})
            }
            other => panic!("send must not be called for {other:?}"),
        }
    })
    .await;

    let err = dispatch(
        &mut h.store,
        &h.endpoint,
        &h.verifier,
        &h.bearer,
        "bus",
        &send_req("req-unavail", "agy-patch@sini.patch"),
        &h.limits,
    )
    .await
    .expect_err("non-not_found list error must fail closed");
    assert!(matches!(err, Error::Transport(_)), "got {err:?}");
    assert_eq!(h.list_calls.load(Ordering::SeqCst), 1);
    assert_eq!(h.send_calls.load(Ordering::SeqCst), 0);
    h.server.abort();
}

#[tokio::test]
async fn direct_peer_node_still_requires_node_scoped_send_admitted() {
    let mut h = setup_harness(["*@sini.patch".into()].into(), |req| {
        match req["action"].as_str() {
            Some("list") => {
                json!({"status":"ok","nodes":[{"node":"sini.patch","status":"ok"}],"recipients":[],"total":0,"truncated":false})
            }
            other => panic!("send must not be called for {other:?}"),
        }
    })
    .await;

    let err = dispatch(
        &mut h.store,
        &h.endpoint,
        &h.verifier,
        &h.bearer,
        "bus",
        &send_req("req-direct-missing", "agy-patch@sini.patch"),
        &h.limits,
    )
    .await
    .expect_err("direct peer without recipient in list must still deny");
    assert!(matches!(err, Error::Denied), "got {err:?}");
    assert_eq!(h.list_calls.load(Ordering::SeqCst), 1);
    assert_eq!(h.send_calls.load(Ordering::SeqCst), 0);
    h.server.abort();
}
