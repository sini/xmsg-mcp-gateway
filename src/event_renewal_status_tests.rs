use crate::auth::VerifiedIdentity;
use crate::event_dispatch::{self, Tick};
use crate::events_test_support::{request, Behavior, Setup};
use crate::grants::Store;
use crate::reads::{self, InboxArguments, ReadArguments, Request};
use serde_json::{json, Value};

fn statuses(setup: &Setup, identity: &VerifiedIdentity, id: &str) -> [Value; 2] {
    [
        Request::Inbox(InboxArguments {
            after: None,
            limit: None,
        }),
        Request::Read(ReadArguments {
            message_id: id.into(),
            offset: None,
            limit: None,
        }),
    ]
    .map(|request| {
        reads::dispatch(
            Store::open(&setup.provider.store_file).unwrap(),
            identity,
            "bus",
            "dot@bus",
            request,
        )
        .unwrap()["events_status"]["subscription"]
            .clone()
    })
}

fn outbox(setup: &Setup, id: &str) -> (String, i64, Option<Vec<u8>>) {
    setup
        .db()
        .query_row(
            "SELECT event_id,attempts,body FROM custody_outbox WHERE event_id=?1",
            [id],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .unwrap()
}

fn subscription_row(setup: &Setup) -> Vec<rusqlite::types::Value> {
    let db = setup.db();
    let mut statement = db.prepare("SELECT * FROM event_subscriptions").unwrap();
    let columns = statement.column_count();
    statement
        .query_row([], |row| {
            (0..columns)
                .map(|column| row.get(column))
                .collect::<Result<Vec<_>, _>>()
        })
        .unwrap()
}

#[tokio::test]
async fn credential_park_requires_renewal_in_inbox_and_read_then_success_resumes() {
    let setup = Setup::new();
    let identity = setup.subscribe().await;
    setup.seed("parked-owned", "dot@bus", 2, i64::MAX);
    setup
        .callback
        .behaviors
        .lock()
        .unwrap()
        .push_back(Behavior::Response(503, None));
    assert_eq!(
        event_dispatch::tick(&setup.runtime(), "bus", "dot@bus")
            .await
            .unwrap(),
        Tick::Retry
    );
    let retained = outbox(&setup, "parked-owned");
    assert_eq!(retained.1, 1);
    assert!(retained.2.is_some());
    setup
        .db()
        .execute("UPDATE custody_outbox SET next_attempt=0", [])
        .unwrap();
    {
        let mut tokens = setup.provider.tokens.lock().unwrap();
        let mut fresh = tokens["good-token"].clone();
        fresh["active"] = json!(true);
        tokens.insert("fresh-token".into(), fresh);
        tokens.get_mut("good-token").unwrap()["active"] = json!(false);
    }
    assert_eq!(
        event_dispatch::tick(&setup.runtime(), "bus", "dot@bus")
            .await
            .unwrap(),
        Tick::CredentialRequired
    );
    assert_eq!(
        outbox(&setup, "parked-owned"),
        retained,
        "credential park changed attempt/body/id"
    );
    for status in statuses(&setup, &identity, "parked-owned") {
        assert_eq!(
            status["state"], "renewal_required",
            "credential park still advertised active"
        );
        assert_eq!(status["reason"], "credential_required");
    }
    let fresh = setup.verifier.verify("fresh-token").await.unwrap();
    assert!(setup
        .runtime()
        .with_allowed_hosts(Some(vec![]))
        .unwrap()
        .subscribe(&fresh, "fresh-token", "bus", "dot@bus", request())
        .await
        .is_err());
    for status in statuses(&setup, &fresh, "parked-owned") {
        assert_eq!(
            status["state"], "renewal_required",
            "failed renewal cleared the credential park"
        );
        assert_eq!(status["reason"], "credential_required");
    }
    setup
        .runtime()
        .subscribe(&fresh, "fresh-token", "bus", "dot@bus", request())
        .await
        .unwrap();
    for status in statuses(&setup, &fresh, "parked-owned") {
        assert_eq!(
            status["state"], "active",
            "successful renewal did not clear credential park"
        );
        assert!(status.get("reason").is_none() || status["reason"].is_null());
    }
    assert_eq!(
        outbox(&setup, "parked-owned"),
        retained,
        "renewal reset delivery state"
    );
    let observed: i64 = setup
        .db()
        .query_row("SELECT count(*) FROM event_observations", [], |row| {
            row.get(0)
        })
        .unwrap();
    assert_eq!(observed, 0, "renewal fabricated consumer observation");
    assert_eq!(
        event_dispatch::tick(&setup.runtime(), "bus", "dot@bus")
            .await
            .unwrap(),
        Tick::Accepted
    );
    let callbacks = setup.callback.events.lock().unwrap();
    assert_eq!(callbacks.len(), 2);
    assert_eq!(
        callbacks[0].1, callbacks[1].1,
        "resumed delivery changed immutable event bytes"
    );
}

#[tokio::test]
async fn credential_park_does_not_override_expired_or_disabled_subscription() {
    let setup = Setup::new();
    let identity = setup.subscribe().await;
    setup.seed("precedence-owned", "dot@bus", 2, i64::MAX);
    setup
        .provider
        .tokens
        .lock()
        .unwrap()
        .get_mut("good-token")
        .unwrap()["active"] = json!(false);
    assert_eq!(
        event_dispatch::tick(&setup.runtime(), "bus", "dot@bus")
            .await
            .unwrap(),
        Tick::CredentialRequired
    );
    setup
        .db()
        .execute("UPDATE event_subscriptions SET expires=1", [])
        .unwrap();
    for status in statuses(&setup, &identity, "precedence-owned") {
        assert_eq!(status["state"], "expired");
    }
    setup
        .db()
        .execute(
            "UPDATE event_subscriptions SET status='disabled',expires=9223372036854775807",
            [],
        )
        .unwrap();
    for status in statuses(&setup, &identity, "precedence-owned") {
        assert_eq!(status["state"], "disabled");
    }
}

#[tokio::test]
async fn failed_callback_renewal_preserves_old_binding_and_delivery() {
    let setup = Setup::new();
    let identity = setup.subscribe().await;
    let before = subscription_row(&setup);
    let mut renewal = request();
    renewal.delivery.secret = crate::events_test_support::secret(5);
    assert!(setup
        .runtime()
        .subscribe(&identity, "good-token", "bus", "dot@bus", renewal)
        .await
        .is_err());
    assert_eq!(
        subscription_row(&setup),
        before,
        "failed callback renewal replaced the active binding"
    );
    setup.seed("old-binding-delivery", "dot@bus", 2, i64::MAX);
    assert_eq!(
        event_dispatch::tick(&setup.runtime(), "bus", "dot@bus")
            .await
            .unwrap(),
        Tick::Accepted,
        "old binding stopped delivering after failed renewal"
    );
    let callbacks = setup.callback.events.lock().unwrap();
    assert_eq!(callbacks.len(), 1);
    let body: Value = serde_json::from_slice(&callbacks[0].1).unwrap();
    assert_eq!(body["data"]["message_id"], "old-binding-delivery");
}

#[tokio::test]
async fn credential_park_status_is_scoped_to_the_subscription_custody() {
    for change in [
        "UPDATE custody_items SET bus='foreign-bus' WHERE event_id='foreign-park'",
        "UPDATE custody_items SET mailbox='foreign@bus' WHERE event_id='foreign-park'",
        "UPDATE custody_items SET owner='foreign-owner' WHERE event_id='foreign-park'",
        "UPDATE custody_items SET grant_id='foreign-grant' WHERE event_id='foreign-park'",
    ] {
        let setup = Setup::new();
        let identity = setup.subscribe().await;
        setup.seed("owned-visible", "dot@bus", 2, i64::MAX);
        setup.seed("foreign-park", "dot@bus", 2, i64::MAX);
        setup.db().execute(change, []).unwrap();
        setup.db().execute("UPDATE custody_outbox SET last_error='credential_required' WHERE event_id='foreign-park'", []).unwrap();
        for status in statuses(&setup, &identity, "owned-visible") {
            assert_eq!(
                status["state"], "active",
                "foreign credential park affected this subscription: {change}"
            );
        }
        setup
            .runtime()
            .subscribe(&identity, "good-token", "bus", "dot@bus", request())
            .await
            .unwrap();
        let reason: Option<String> = setup
            .db()
            .query_row(
                "SELECT last_error FROM custody_outbox WHERE event_id='foreign-park'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(
            reason.as_deref(),
            Some("credential_required"),
            "renewal cleared foreign custody evidence: {change}"
        );
    }
}

struct RevokeRenewalCredential {
    callback: std::sync::Arc<crate::events_test_support::Callback>,
    tokens: std::sync::Arc<std::sync::Mutex<std::collections::HashMap<String, Value>>>,
}
impl crate::webhook::Transport for RevokeRenewalCredential {
    fn post<'a>(
        &'a self,
        url: &'a str,
        headers: reqwest::header::HeaderMap,
        body: Vec<u8>,
    ) -> crate::webhook::PostFuture<'a> {
        Box::pin(async move {
            let value: Value = serde_json::from_slice(&body).unwrap();
            if value["type"] == "verification" {
                self.tokens
                    .lock()
                    .unwrap()
                    .get_mut("renewal-token")
                    .unwrap()["active"] = json!(false);
            }
            crate::webhook::Transport::post(self.callback.as_ref(), url, headers, body).await
        })
    }
}

#[tokio::test]
async fn post_challenge_credential_failure_preserves_old_binding_and_delivery() {
    let setup = Setup::new();
    setup.subscribe().await;
    {
        let mut tokens = setup.provider.tokens.lock().unwrap();
        let claims = tokens["good-token"].clone();
        tokens.insert("renewal-token".into(), claims);
    }
    let renewal_identity = setup.verifier.verify("renewal-token").await.unwrap();
    setup
        .db()
        .execute("UPDATE event_subscriptions SET verified_at=0", [])
        .unwrap();
    let before = subscription_row(&setup);
    let runtime = crate::events::Events::with_transport(
        setup.provider.store_file.clone(),
        setup.key.clone(),
        setup.verifier.clone(),
        "grant".into(),
        std::sync::Arc::new(RevokeRenewalCredential {
            callback: setup.callback.clone(),
            tokens: setup.provider.tokens.clone(),
        }),
    );
    assert!(matches!(
        runtime
            .subscribe(
                &renewal_identity,
                "renewal-token",
                "bus",
                "dot@bus",
                request()
            )
            .await,
        Err(crate::events::Error::Credentials(_))
    ));
    assert_eq!(
        setup.provider.tokens.lock().unwrap()["renewal-token"]["active"],
        false,
        "callback verification did not execute"
    );
    assert_eq!(
        subscription_row(&setup),
        before,
        "post-challenge credential failure replaced the active binding"
    );
    setup.seed("credential-old-binding", "dot@bus", 2, i64::MAX);
    assert_eq!(
        event_dispatch::tick(&setup.runtime(), "bus", "dot@bus")
            .await
            .unwrap(),
        Tick::Accepted,
        "old credential binding stopped after failed renewal"
    );
    let callbacks = setup.callback.events.lock().unwrap();
    assert_eq!(callbacks.len(), 1);
    let body: Value = serde_json::from_slice(&callbacks[0].1).unwrap();
    assert_eq!(body["data"]["message_id"], "credential-old-binding");
}

#[tokio::test]
async fn late_custody_failure_rolls_back_the_verified_subscription_replacement() {
    let setup = Setup::new();
    let identity = setup.subscribe().await;
    setup.seed("late-fault", "dot@bus", 2, i64::MAX);
    setup
        .db()
        .execute(
            "UPDATE custody_outbox SET state='held' WHERE event_id='late-fault'",
            [],
        )
        .unwrap();
    let before = subscription_row(&setup);
    setup.db().execute_batch("CREATE TRIGGER abort_custody_release BEFORE UPDATE OF state ON custody_outbox WHEN OLD.event_id='late-fault' AND NEW.state='pending' BEGIN SELECT RAISE(ABORT,'forced late failure'); END;").unwrap();
    let mut renewal = request();
    renewal.ttl_ms = Some(60_000);
    assert!(setup
        .runtime()
        .subscribe(&identity, "good-token", "bus", "dot@bus", renewal)
        .await
        .is_err());
    assert_eq!(
        subscription_row(&setup),
        before,
        "late custody failure committed the subscription replacement"
    );
    let state: String = setup
        .db()
        .query_row(
            "SELECT state FROM custody_outbox WHERE event_id='late-fault'",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(state, "held");
}
