use super::*;
use crate::events_test_support::Setup;
use std::sync::atomic::Ordering;
fn ack(store: Store, identity: &VerifiedIdentity, key: &EventKey, id: &str) -> Value {
    dispatch(
        store,
        identity,
        "bus",
        "dot@bus",
        "grant",
        key,
        Request::Ack(AckArguments {
            message_id: id.into(),
        }),
    )
    .unwrap()
}
#[tokio::test]
async fn responsibility_ack_is_owned_idempotent_contiguous_and_independent_of_subscription() {
    let setup = Setup::new();
    let identity = setup.verifier.verify("good-token").await.unwrap();
    for id in ["one", "two", "three"] {
        setup.seed(id, "dot@bus", 2, i64::MAX);
    }
    setup.seed("foreign", "other@bus", 2, i64::MAX);
    setup.seed("old", "dot@bus", 1, i64::MAX);
    setup.seed("expired", "dot@bus", 2, 1);
    for id in ["foreign", "unknown", "old", "expired"] {
        assert_eq!(
            ack(
                Store::open(&setup.provider.store_file).unwrap(),
                &identity,
                &setup.key,
                id
            ),
            json!({"state":"not_found"})
        );
    }
    let owner = owner_key(&identity, "bus", "dot@bus", "grant");
    let out_of_order = ack(
        Store::open(&setup.provider.store_file).unwrap(),
        &identity,
        &setup.key,
        "three",
    );
    assert_eq!(
        crate::event_cursor::decode(
            &setup.key,
            &owner,
            out_of_order["checkpoint"].as_str().unwrap()
        )
        .unwrap(),
        0
    );
    assert_eq!(
        ack(
            Store::open(&setup.provider.store_file).unwrap(),
            &identity,
            &setup.key,
            "one"
        )["state"],
        "observed"
    );
    let final_ack = ack(
        Store::open(&setup.provider.store_file).unwrap(),
        &identity,
        &setup.key,
        "two",
    );
    assert_eq!(
        crate::event_cursor::decode(
            &setup.key,
            &owner,
            final_ack["checkpoint"].as_str().unwrap()
        )
        .unwrap(),
        3
    );
    let before: i64 = setup
        .db()
        .query_row(
            "SELECT observed_at FROM event_observations WHERE event_id='two'",
            [],
            |r| r.get(0),
        )
        .unwrap();
    ack(
        Store::open(&setup.provider.store_file).unwrap(),
        &identity,
        &setup.key,
        "two",
    );
    assert_eq!(
        setup
            .db()
            .query_row(
                "SELECT observed_at FROM event_observations WHERE event_id='two'",
                [],
                |r| r.get::<_, i64>(0)
            )
            .unwrap(),
        before
    );
    assert_eq!(
        setup
            .db()
            .query_row(
                "SELECT observation_checkpoint FROM event_checkpoints WHERE owner_key=?1",
                [owner],
                |r| r.get::<_, i64>(0)
            )
            .unwrap(),
        3,
        "checkpoint absent without subscription"
    );
    assert_eq!(
        setup
            .db()
            .query_row(
                "SELECT COUNT(*) FROM custody_outbox WHERE state='accepted'",
                [],
                |r| r.get::<_, i64>(0)
            )
            .unwrap(),
        0,
        "ack fabricated callback receipt"
    );
}
#[tokio::test]
async fn uncertain_status_never_submits_or_reserves_and_scopes_both_operations() {
    let setup = Setup::new();
    let identity = setup.verifier.verify("good-token").await.unwrap();
    let owner = crate::custody::fingerprint(&[
        identity.service(),
        identity.issuer(),
        identity.resource(),
        identity.subject(),
    ]);
    for (operation, state, until) in [("send", "pending", i64::MAX), ("reply", "unknown", 1)] {
        setup.db().execute("INSERT INTO outbound_reservations(owner,operation,request_id,payload_hash,sender,grant_id,grant_revision,idempotency_key,target,framed_text,created_at,retry_until,state) VALUES (?1,?2,'request','hash','dot@bus','grant',2,?2,'svc:receiver@peer','body',1,?3,?4)",params![owner,operation,until,state]).unwrap();
    }
    setup.db().execute("INSERT INTO outbound_reservations(owner,operation,request_id,payload_hash,sender,grant_id,grant_revision,idempotency_key,target,framed_text,created_at,retry_until,state) VALUES ('foreign','send','foreign','hash','dot@bus','grant',2,'foreign','svc:receiver@peer','body',1,9999999999,'pending')",[]).unwrap();
    let calls = setup.provider.requests.load(Ordering::SeqCst);
    let read = |id: &str| {
        dispatch(
            Store::open(&setup.provider.store_file).unwrap(),
            &identity,
            "bus",
            "dot@bus",
            "grant",
            &setup.key,
            Request::Status(StatusArguments {
                request_id: id.into(),
            }),
        )
        .unwrap()
    };
    let result = read("request");
    assert_eq!(result["results"].as_array().unwrap().len(), 2);
    assert_eq!(result["results"][0]["state"], "expired_unknown");
    assert_eq!(result["results"][1]["state"], "pending");
    for id in ["foreign", "unknown"] {
        assert_eq!(read(id), json!({"state":"not_found"}));
    }
    assert_eq!(
        setup.provider.requests.load(Ordering::SeqCst),
        calls,
        "status introspected or retried"
    );
    assert!(setup.callback.events.lock().unwrap().is_empty());
    assert_eq!(
        setup
            .db()
            .query_row("SELECT COUNT(*) FROM outbound_reservations", [], |r| r
                .get::<_, i64>(0))
            .unwrap(),
        3
    );
    assert_eq!(
        setup
            .db()
            .query_row(
                "SELECT COUNT(*) FROM outbound_reservations WHERE submission_revision IS NOT NULL",
                [],
                |r| r.get::<_, i64>(0)
            )
            .unwrap(),
        0
    );
}
#[tokio::test]
async fn retention_records_gaps_before_pruning_without_observing_or_accepting_expired_dead_letters()
{
    let setup = Setup::new();
    let identity = setup.subscribe().await;
    let expired = setup.seed("expired", "dot@bus", 2, 1);
    let live = setup.seed("live", "dot@bus", 2, i64::MAX);
    setup
        .db()
        .execute(
            "UPDATE custody_outbox SET state='dead' WHERE event_id='expired'",
            [],
        )
        .unwrap();
    Store::open(&setup.provider.store_file)
        .unwrap()
        .record_bus_link(
            "bus",
            true,
            &crate::custody::Limits::default(),
            std::time::SystemTime::now(),
        )
        .unwrap();
    let owner = owner_key(&identity, "bus", "dot@bus", "grant");
    assert_eq!(
        setup
            .db()
            .query_row(
                "SELECT unavailable_through FROM event_availability WHERE owner_key=?1",
                [&owner],
                |r| r.get::<_, i64>(0)
            )
            .unwrap(),
        expired
    );
    assert_eq!(
        setup
            .db()
            .query_row(
                "SELECT COUNT(*) FROM event_occurrences WHERE event_id='expired'",
                [],
                |r| r.get::<_, i64>(0)
            )
            .unwrap(),
        0,
        "expired tombstone never pruned"
    );
    assert_eq!(
        crate::event_dispatch::tick(&setup.runtime(), "bus", "dot@bus")
            .await
            .unwrap(),
        crate::event_dispatch::Tick::Accepted
    );
    let renewal = setup
        .runtime()
        .subscribe(
            &identity,
            "good-token",
            "bus",
            "dot@bus",
            crate::events_test_support::request(),
        )
        .await
        .unwrap();
    // A missing cursor uses the current safe receipt position; an old explicit cursor reports truncation.
    let mut resume = crate::events_test_support::request();
    resume.cursor = Some(crate::event_cursor::encode(&setup.key, &owner, 0).unwrap());
    let resumed = setup
        .runtime()
        .subscribe(&identity, "good-token", "bus", "dot@bus", resume)
        .await
        .unwrap();
    assert_eq!(resumed["truncated"], true);
    assert!(!renewal["refreshBefore"].is_null());
    assert_eq!(
        setup
            .db()
            .query_row("SELECT COUNT(*) FROM event_observations", [], |r| r
                .get::<_, i64>(0))
            .unwrap(),
        0
    );
    assert_eq!(
        setup
            .db()
            .query_row("SELECT callback_cursor FROM event_subscriptions", [], |r| r
                .get::<_, i64>(0))
            .unwrap(),
        expired,
        "replay must not claim expired item accepted"
    );
    assert!(live > expired);
}

use crate::event_observer_fixture as observer;
#[test]
#[ignore = "invoked only by the bounded crash fixture"]
fn ack_crash_child() {
    let Some(file) = std::env::var_os("GATEWAY_ACK_FIXTURE_DB") else {
        return;
    };
    let key = EventKey::load(std::path::Path::new(
        &std::env::var_os("GATEWAY_ACK_FIXTURE_KEY").unwrap(),
    ))
    .unwrap();
    let binding: crate::grants::Binding =
        serde_json::from_str(&std::env::var("GATEWAY_ACK_FIXTURE_BINDING").unwrap()).unwrap();
    let identity = crate::provider_fixture::verified(&binding);
    let target = std::env::var("GATEWAY_ACK_FIXTURE_TARGET").unwrap();
    let subscriber = observer::AtEvent {
        target: if target == "before" {
            "gateway_ack_before_commit"
        } else {
            "gateway_ack_after_commit"
        },
        action: || std::process::exit(75),
    };
    tracing::subscriber::with_default(subscriber, || {
        ack(
            Store::open(std::path::Path::new(&file)).unwrap(),
            &identity,
            &key,
            "message",
        );
    });
    panic!("crash marker not reached");
}
#[tokio::test]
async fn crashes_before_and_after_responsibility_commit_have_distinct_recovery() {
    for target in ["before", "after"] {
        let setup = Setup::new();
        let identity = setup.verifier.verify("good-token").await.unwrap();
        setup.seed("message", "dot@bus", 2, i64::MAX);
        let mut child=std::process::Command::new(std::env::current_exe().unwrap()).args(["--ignored","--exact","recovery::tests::ack_crash_child"])
            .env("GATEWAY_ACK_FIXTURE_DB",&setup.provider.store_file).env("GATEWAY_ACK_FIXTURE_KEY",setup.provider.keys._directory.path().join("events-key"))
            .env("GATEWAY_ACK_FIXTURE_BINDING",json!({"service":setup.provider.binding.service,"issuer":setup.provider.binding.issuer,"resource":setup.provider.binding.resource,"subject":setup.provider.binding.subject,"hosted_client":setup.provider.binding.hosted_client}).to_string()).env("GATEWAY_ACK_FIXTURE_TARGET",target)
            .stdout(std::process::Stdio::null()).stderr(std::process::Stdio::null()).spawn().unwrap();
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
        let status = loop {
            if let Some(status) = child.try_wait().unwrap() {
                break status;
            }
            if std::time::Instant::now() > deadline {
                child.kill().unwrap();
                child.wait().unwrap();
                panic!("ack child timed out")
            }
            std::thread::sleep(std::time::Duration::from_millis(5));
        };
        assert_eq!(status.code(), Some(75), "crash marker not reached");
        let count: i64 = setup
            .db()
            .query_row("SELECT COUNT(*) FROM event_observations", [], |r| r.get(0))
            .unwrap();
        assert_eq!(count, if target == "before" { 0 } else { 1 });
        ack(
            Store::open(&setup.provider.store_file).unwrap(),
            &identity,
            &setup.key,
            "message",
        );
        assert_eq!(
            setup
                .db()
                .query_row("SELECT COUNT(*) FROM event_observations", [], |r| r
                    .get::<_, i64>(0))
                .unwrap(),
            1
        );
    }
}

#[tokio::test]
async fn transaction_rechecks_selected_grant_for_ack_and_status() {
    let setup = Setup::new();
    let identity = setup.verifier.verify("good-token").await.unwrap();
    setup.seed("message", "dot@bus", 2, i64::MAX);
    for request in [
        Request::Ack(AckArguments {
            message_id: "message".into(),
        }),
        Request::Status(StatusArguments {
            request_id: "request".into(),
        }),
    ] {
        assert!(matches!(
            dispatch(
                Store::open(&setup.provider.store_file).unwrap(),
                &identity,
                "bus",
                "dot@bus",
                "wrong-selected-grant",
                &setup.key,
                request
            ),
            Err(Error::Authority(GrantError::Denied))
        ));
    }
    assert_eq!(
        setup
            .db()
            .query_row("SELECT COUNT(*) FROM event_observations", [], |row| row
                .get::<_, i64>(0))
            .unwrap(),
        0
    );
}
