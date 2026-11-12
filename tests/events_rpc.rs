#![cfg(unix)]
#[allow(dead_code)]
#[path = "common/serving_fixture.rs"]
mod fixture;
#[allow(dead_code)]
#[path = "common/provider.rs"]
mod provider;
use base64::Engine;
use serde_json::{json, Value};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use xmsg_mcp_gateway::auth::{Verifier, VerifierConfig};
use xmsg_mcp_gateway::event_store::EventKey;
use xmsg_mcp_gateway::events::{Events, Subscribe, EVENT_NAME};
use xmsg_mcp_gateway::grants::Store;
use xmsg_mcp_gateway::webhook::{self, Transport};

struct Callback {
    calls: AtomicUsize,
    status: AtomicUsize,
    action: Mutex<Option<Box<dyn FnOnce() + Send>>>,
}
impl Transport for Callback {
    fn post<'a>(
        &'a self,
        _url: &'a str,
        headers: reqwest::header::HeaderMap,
        body: Vec<u8>,
    ) -> webhook::PostFuture<'a> {
        Box::pin(async move {
            self.calls.fetch_add(1, Ordering::SeqCst);
            assert!(
                (4..=7).any(|byte| standardwebhooks::Webhook::new(&key(byte))
                    .unwrap()
                    .verify(&body, &headers)
                    .is_ok()),
                "lifecycle challenge must verify with a supplied fixture signing key"
            );
            let value: Value = serde_json::from_slice(&body).unwrap();
            assert_eq!(value["type"], "verification");
            if let Some(action) = self.action.lock().unwrap().take() {
                action()
            }
            Ok(webhook::Response {
                status: self.status.load(Ordering::SeqCst) as u16,
                body: serde_json::to_vec(&json!({"challenge":value["challenge"]})).unwrap(),
                retry_after: None,
            })
        })
    }
}
fn key(byte: u8) -> String {
    format!(
        "whsec_{}",
        base64::engine::general_purpose::STANDARD.encode([byte; 32])
    )
}
fn request(secret: u8) -> Subscribe {
    serde_json::from_value(json!({"name":EVENT_NAME,"arguments":{},"delivery":{"mode":"webhook","url":"https://callback.example/events","secret":key(secret)},"cursor":null})).unwrap()
}
struct Setup {
    provider: fixture::Fixture,
    key: EventKey,
    verifier: Arc<Verifier>,
    callback: Arc<Callback>,
}
impl Setup {
    fn new() -> Self {
        let mut provider = fixture::Fixture::new();
        for claims in provider.tokens.lock().unwrap().values_mut() {
            claims["scope"] = json!("identity:read events:subscribe");
        }
        provider.config["verifier"]["required_scopes"] =
            json!(["identity:read", "events:subscribe"]);
        let verifier = Arc::new(
            Verifier::from_config(
                serde_json::from_value::<VerifierConfig>(provider.config["verifier"].clone())
                    .unwrap(),
            )
            .unwrap(),
        );
        let file = provider.keys._directory.path().join("event.key");
        fixture::private_file(&file, &[3; 32]);
        let key = EventKey::load(&file).unwrap();
        let mut store = Store::open(&provider.store_file).unwrap();
        store.migrate_custody().unwrap();
        store.migrate_outbound().unwrap();
        store.migrate_retirement().unwrap();
        store.migrate_events(&key).unwrap();
        let callback = Arc::new(Callback {
            calls: AtomicUsize::new(0),
            status: AtomicUsize::new(200),
            action: Mutex::new(None),
        });
        Self {
            provider,
            key,
            verifier,
            callback,
        }
    }
    fn runtime(&self) -> Events {
        Events::with_transport(
            self.provider.store_file.clone(),
            self.key.clone(),
            self.verifier.clone(),
            "grant".into(),
            self.callback.clone(),
        )
    }
}
#[tokio::test]
async fn subscription_renewal_restart_and_expiry_are_durable() {
    let setup = Setup::new();
    let identity = setup.verifier.verify("good-token").await.unwrap();
    let first = setup
        .runtime()
        .subscribe(&identity, "good-token", "bus", "dot@bus", request(4))
        .await
        .unwrap();
    assert!(first["id"].as_str().unwrap().starts_with("sub_"));
    assert!(!first["refreshBefore"].is_null());
    let second = setup
        .runtime()
        .subscribe(&identity, "good-token", "bus", "dot@bus", request(4))
        .await
        .unwrap();
    assert_eq!(first["id"], second["id"]);
    assert_eq!(setup.callback.calls.load(Ordering::SeqCst), 1);
    let connection = rusqlite::Connection::open(&setup.provider.store_file).unwrap();
    let (expires, status): (i64, String) = connection
        .query_row("SELECT expires,status FROM event_subscriptions", [], |r| {
            Ok((r.get(0)?, r.get(1)?))
        })
        .unwrap();
    assert_eq!(status, "active");
    assert!(
        expires > identity.expires_at() as i64,
        "subscription lifetime must be separate from access-token expiry"
    );
    let mut conflict = request(4);
    conflict.delivery.url = "https://another.example/events".into();
    assert!(setup
        .runtime()
        .subscribe(&identity, "good-token", "bus", "dot@bus", conflict)
        .await
        .is_err());
}
#[tokio::test]
async fn revoked_credential_during_challenge_never_activates() {
    let setup = Setup::new();
    let identity = setup.verifier.verify("good-token").await.unwrap();
    let tokens = setup.provider.tokens.clone();
    *setup.callback.action.lock().unwrap() = Some(Box::new(move || {
        tokens.lock().unwrap().get_mut("good-token").unwrap()["active"] = json!(false)
    }));
    assert!(setup
        .runtime()
        .subscribe(&identity, "good-token", "bus", "dot@bus", request(4))
        .await
        .is_err());
    assert!(
        subscription_rows(&setup).is_empty(),
        "failed first subscribe must not persist provisional credentials"
    );
}
#[tokio::test]
async fn third_secret_rotation_conflicts_inside_the_dual_sign_window() {
    let setup = Setup::new();
    let identity = setup.verifier.verify("good-token").await.unwrap();
    setup
        .runtime()
        .subscribe(&identity, "good-token", "bus", "dot@bus", request(4))
        .await
        .unwrap();
    setup
        .runtime()
        .subscribe(&identity, "good-token", "bus", "dot@bus", request(5))
        .await
        .unwrap();
    assert!(setup
        .runtime()
        .subscribe(&identity, "good-token", "bus", "dot@bus", request(6))
        .await
        .is_err());
}

#[tokio::test]
async fn generation_race_and_foreign_identity_do_not_activate() {
    let setup = Setup::new();
    let identity = setup.verifier.verify("good-token").await.unwrap();
    setup
        .runtime()
        .subscribe(&identity, "good-token", "bus", "dot@bus", request(4))
        .await
        .unwrap();
    let file = setup.provider.store_file.clone();
    *setup.callback.action.lock().unwrap() = Some(Box::new(move || {
        rusqlite::Connection::open(file)
            .unwrap()
            .execute("UPDATE event_subscriptions SET generation=generation+1", [])
            .unwrap();
    }));
    assert!(setup
        .runtime()
        .subscribe(&identity, "good-token", "bus", "dot@bus", request(5))
        .await
        .is_err());
    let status: String = rusqlite::Connection::open(&setup.provider.store_file)
        .unwrap()
        .query_row("SELECT status FROM event_subscriptions", [], |r| r.get(0))
        .unwrap();
    assert_eq!(
        status, "active",
        "a lost generation race must preserve the old active binding"
    );
    let mut other = setup.provider.binding.clone();
    other.subject = "another-owner".into();
    let foreign = tokio::task::spawn_blocking(move || {
        provider::verify_response(&other, provider::claims(&other), 200).unwrap()
    })
    .await
    .unwrap();
    assert!(setup
        .runtime()
        .subscribe(&foreign, "good-token", "bus", "dot@bus", request(4))
        .await
        .is_err());
}

#[tokio::test]
async fn unsubscribe_and_explicit_rebind_are_generation_checked() {
    let setup = Setup::new();
    let identity = setup.verifier.verify("good-token").await.unwrap();
    let first = setup
        .runtime()
        .subscribe(&identity, "good-token", "bus", "dot@bus", request(4))
        .await
        .unwrap();
    let connection = rusqlite::Connection::open(&setup.provider.store_file).unwrap();
    let generation: i64 = connection
        .query_row("SELECT generation FROM event_subscriptions", [], |r| {
            r.get(0)
        })
        .unwrap();
    assert!(setup
        .runtime()
        .rebind(
            first["id"].as_str().unwrap(),
            generation + 1,
            "https://replacement.example/",
            None,
            "operator",
            "move callback"
        )
        .is_err());
    let replacement = setup
        .runtime()
        .rebind(
            first["id"].as_str().unwrap(),
            generation,
            "https://replacement.example/",
            None,
            "operator",
            "move callback",
        )
        .unwrap();
    assert_ne!(first["id"], replacement["id"]);
    assert_eq!(replacement["state"], "verification_required");
    assert!(setup
        .runtime()
        .subscribe(&identity, "good-token", "bus", "dot@bus", request(4))
        .await
        .is_err());
    let mut new_request = request(7);
    new_request.delivery.url = "https://replacement.example/".into();
    let active = setup
        .runtime()
        .subscribe(&identity, "good-token", "bus", "dot@bus", new_request)
        .await
        .unwrap();
    assert_eq!(active["id"], replacement["id"]);
    let stop=serde_json::from_value(json!({"name":EVENT_NAME,"arguments":{},"delivery":{"mode":"webhook","url":"https://replacement.example/"}})).unwrap();
    setup
        .runtime()
        .unsubscribe(&identity, "good-token", "bus", "dot@bus", stop)
        .await
        .unwrap();
    let status: String = connection
        .query_row("SELECT status FROM event_subscriptions", [], |r| r.get(0))
        .unwrap();
    assert_eq!(status, "disabled");
    assert_eq!(
        connection
            .query_row("SELECT COUNT(*) FROM event_binding_audit", [], |r| r
                .get::<_, i64>(0))
            .unwrap(),
        1
    );
}

#[tokio::test]
async fn same_scope_revocation_does_not_revoke_the_grant() {
    let setup = Setup::new();
    let identity = setup.verifier.verify("good-token").await.unwrap();
    setup
        .runtime()
        .subscribe(&identity, "good-token", "bus", "dot@bus", request(4))
        .await
        .unwrap();
    setup
        .provider
        .tokens
        .lock()
        .unwrap()
        .get_mut("good-token")
        .unwrap()["active"] = json!(false);
    assert!(setup
        .runtime()
        .subscribe(&identity, "good-token", "bus", "dot@bus", request(4))
        .await
        .is_err());
    assert!(Store::open(&setup.provider.store_file)
        .unwrap()
        .authorize(&identity)
        .is_ok());
}

#[test]
fn subscribe_future_is_send() {
    fn assert_send<T: Send>(_: T) {}
    let setup = Setup::new();
    let identity = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap()
        .block_on(setup.verifier.verify("good-token"))
        .unwrap();
    let runtime = setup.runtime();
    assert_send(runtime.subscribe(&identity, "good-token", "bus", "dot@bus", request(4)));
}

#[tokio::test]
async fn rotation_window_reseals_old_and_current_keys_for_the_new_generation() {
    let setup = Setup::new();
    let identity = setup.verifier.verify("good-token").await.unwrap();
    setup
        .runtime()
        .subscribe(&identity, "good-token", "bus", "dot@bus", request(4))
        .await
        .unwrap();
    setup
        .runtime()
        .subscribe(&identity, "good-token", "bus", "dot@bus", request(5))
        .await
        .unwrap();
    let connection = rusqlite::Connection::open(&setup.provider.store_file).unwrap();
    let (owner, _generation, current, old): (String, i64, Vec<u8>, Vec<u8>) = connection
        .query_row(
            "SELECT owner_key,generation,secret,old_secret FROM event_subscriptions",
            [],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)),
        )
        .unwrap();
    assert_eq!(
        setup
            .key
            .open(&format!("events/subscription/v1/{owner}/secret"), &current)
            .unwrap(),
        key(5).as_bytes()
    );
    assert_eq!(
        setup
            .key
            .open(&format!("events/subscription/v1/{owner}/old_secret"), &old)
            .unwrap(),
        key(4).as_bytes()
    );
    connection
        .execute("UPDATE event_subscriptions SET rotation_until=0", [])
        .unwrap();
    setup
        .runtime()
        .subscribe(&identity, "good-token", "bus", "dot@bus", request(6))
        .await
        .unwrap();
}

#[tokio::test]
async fn retention_floor_does_not_skip_an_earlier_live_pending_item() {
    let setup = Setup::new();
    let identity = setup.verifier.verify("good-token").await.unwrap();
    let first = setup
        .runtime()
        .subscribe(&identity, "good-token", "bus", "dot@bus", request(4))
        .await
        .unwrap();
    let connection = rusqlite::Connection::open(&setup.provider.store_file).unwrap();
    let owner: String = connection
        .query_row("SELECT owner_key FROM event_subscriptions", [], |r| {
            r.get(0)
        })
        .unwrap();
    let now = webhook::signing_time().unwrap();
    connection.execute("INSERT INTO custody_items(bus,upstream_id,event_id,grant_id,grant_revision,mailbox,owner,origin,text,fingerprint,received_at,expires_at,held) VALUES ('bus','live','event-live','grant',2,'dot@bus','owner','{}','retained','fixture',?1,?2,1)",rusqlite::params![now,now+3600]).unwrap();
    connection.execute("INSERT INTO event_occurrences(seq,event_id) VALUES (1,'event-live'),(2,'event-expired')",[]).unwrap();
    connection.execute("INSERT INTO event_authorizations(event_id,acceptance_enabled,acceptance_ever_enabled,acceptance_class,dispatch_revision) VALUES ('event-live',1,1,'current',2)",[]).unwrap();
    connection
        .execute(
            "INSERT INTO custody_outbox(event_id,state) VALUES ('event-live','pending')",
            [],
        )
        .unwrap();
    connection
        .execute(
            "INSERT INTO event_availability(owner_key,unavailable_through) VALUES (?1,2)",
            [&owner],
        )
        .unwrap();
    let mut renew = request(4);
    renew.cursor = Some(first["cursor"].as_str().unwrap().into());
    let result = setup
        .runtime()
        .subscribe(&identity, "good-token", "bus", "dot@bus", renew)
        .await
        .unwrap();
    assert_eq!(result["truncated"], true);
    let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(result["cursor"].as_str().unwrap())
        .unwrap();
    let raw = setup
        .key
        .open(&format!("events/cursor/v1/{owner}"), &bytes)
        .unwrap();
    assert_eq!(
        i64::from_be_bytes(raw.try_into().unwrap()),
        0,
        "expiry of sequence2 must not skip live sequence1"
    );
}

#[tokio::test]
async fn selected_grant_and_cursor_ownership_are_enforced() {
    let setup = Setup::new();
    let identity = setup.verifier.verify("good-token").await.unwrap();
    let wrong = Events::with_transport(
        setup.provider.store_file.clone(),
        setup.key.clone(),
        setup.verifier.clone(),
        "another-grant".into(),
        setup.callback.clone(),
    );
    assert!(wrong
        .subscribe(&identity, "good-token", "bus", "dot@bus", request(4))
        .await
        .is_err());
    assert_eq!(setup.callback.calls.load(Ordering::SeqCst), 0);
    let first = setup
        .runtime()
        .subscribe(&identity, "good-token", "bus", "dot@bus", request(4))
        .await
        .unwrap();
    let mut foreign_cursor = request(4);
    foreign_cursor.cursor = Some(first["cursor"].as_str().unwrap().into());
    assert!(setup
        .runtime()
        .subscribe(
            &identity,
            "good-token",
            "bus",
            "different-mailbox@bus",
            foreign_cursor
        )
        .await
        .is_err());
}

#[tokio::test]
async fn explicit_resume_rewinds_callback_checkpoint_and_replays_unobserved_acceptance() {
    let setup = Setup::new();
    let identity = setup.verifier.verify("good-token").await.unwrap();
    let first = setup
        .runtime()
        .subscribe(&identity, "good-token", "bus", "dot@bus", request(4))
        .await
        .unwrap();
    let connection = rusqlite::Connection::open(&setup.provider.store_file).unwrap();
    let now = webhook::signing_time().unwrap();
    connection.execute("INSERT INTO custody_items(bus,upstream_id,event_id,grant_id,grant_revision,mailbox,owner,origin,text,fingerprint,received_at,expires_at,held) VALUES ('bus','accepted','event-accepted','grant',2,'dot@bus','owner','{}','retained','fixture',?1,?2,1)",rusqlite::params![now,now+3600]).unwrap();
    connection
        .execute(
            "INSERT INTO event_occurrences(seq,event_id) VALUES (1,'event-accepted')",
            [],
        )
        .unwrap();
    connection.execute("INSERT INTO event_authorizations(event_id,acceptance_enabled,acceptance_ever_enabled,acceptance_class,dispatch_revision) VALUES ('event-accepted',1,1,'current',2)",[]).unwrap();
    connection
        .execute(
            "INSERT INTO custody_outbox(event_id,state) VALUES ('event-accepted','accepted')",
            [],
        )
        .unwrap();
    connection
        .execute("UPDATE event_subscriptions SET callback_cursor=1", [])
        .unwrap();
    let mut resume = request(4);
    resume.cursor = Some(first["cursor"].as_str().unwrap().into());
    setup
        .runtime()
        .subscribe(&identity, "good-token", "bus", "dot@bus", resume)
        .await
        .unwrap();
    let cursor: i64 = connection
        .query_row(
            "SELECT callback_cursor FROM event_subscriptions",
            [],
            |row| row.get(0),
        )
        .unwrap();
    let state: String = connection
        .query_row("SELECT state FROM custody_outbox", [], |row| row.get(0))
        .unwrap();
    assert_eq!(cursor, 0);
    assert_eq!(state, "pending");
}

#[tokio::test]
async fn owner_revision_changes_fence_without_destroying_encrypted_subscription() {
    let setup = Setup::new();
    let identity = setup.verifier.verify("good-token").await.unwrap();
    setup
        .runtime()
        .subscribe(&identity, "good-token", "bus", "dot@bus", request(4))
        .await
        .unwrap();
    let connection = rusqlite::Connection::open(&setup.provider.store_file).unwrap();
    let now = webhook::signing_time().unwrap();
    connection.execute("INSERT INTO custody_items(bus,upstream_id,event_id,grant_id,grant_revision,mailbox,owner,origin,text,fingerprint,received_at,expires_at,held) VALUES ('bus','old','event-old','grant',2,'dot@bus','owner','{}','retained','fixture',?1,?2,1)",rusqlite::params![now,now+3600]).unwrap();
    connection
        .execute(
            "INSERT INTO event_occurrences(seq,event_id) VALUES (1,'event-old')",
            [],
        )
        .unwrap();
    connection.execute("INSERT INTO event_authorizations(event_id,acceptance_enabled,acceptance_ever_enabled,acceptance_class,dispatch_revision) VALUES ('event-old',1,1,'current',2)",[]).unwrap();
    connection
        .execute(
            "INSERT INTO custody_outbox(event_id,state) VALUES ('event-old','pending')",
            [],
        )
        .unwrap();
    let mut store = Store::open(&setup.provider.store_file).unwrap();
    assert_eq!(store.set_enabled("grant", 2, false).unwrap(), 3);
    assert_eq!(store.set_enabled("grant", 3, true).unwrap(), 4);
    setup
        .runtime()
        .subscribe(&identity, "good-token", "bus", "dot@bus", request(4))
        .await
        .unwrap();
    let state: String = connection
        .query_row(
            "SELECT state FROM custody_outbox WHERE event_id='event-old'",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(state, "held");
    assert_eq!(
        store
            .set_outbound_policy("grant", 4, &xmsg_mcp_gateway::outbound::Policy::default())
            .unwrap(),
        5
    );
    let active = setup
        .runtime()
        .subscribe(&identity, "good-token", "bus", "dot@bus", request(4))
        .await
        .unwrap();
    let generation: i64 = connection
        .query_row("SELECT generation FROM event_subscriptions", [], |r| {
            r.get(0)
        })
        .unwrap();
    let rebound = setup
        .runtime()
        .rebind(
            active["id"].as_str().unwrap(),
            generation,
            "https://replacement.example/",
            None,
            "operator",
            "move callback after policy change",
        )
        .unwrap();
    assert_eq!(rebound["state"], "verification_required");
    let mut replacement = request(5);
    replacement.delivery.url = "https://replacement.example/".into();
    setup
        .runtime()
        .subscribe(&identity, "good-token", "bus", "dot@bus", replacement)
        .await
        .unwrap();
    assert_eq!(
        connection
            .query_row(
                "SELECT state FROM custody_outbox WHERE event_id='event-old'",
                [],
                |row| row.get::<_, String>(0)
            )
            .unwrap(),
        "held"
    );
}

#[tokio::test]
async fn verification_cache_deadline_does_not_slide_on_renewal() {
    let setup = Setup::new();
    let identity = setup.verifier.verify("good-token").await.unwrap();
    setup
        .runtime()
        .subscribe(&identity, "good-token", "bus", "dot@bus", request(4))
        .await
        .unwrap();
    let connection = rusqlite::Connection::open(&setup.provider.store_file).unwrap();
    let actual_verification = webhook::signing_time().unwrap() - 150;
    connection
        .execute(
            "UPDATE event_subscriptions SET verified_at=?1",
            [actual_verification],
        )
        .unwrap();
    setup
        .runtime()
        .subscribe(&identity, "good-token", "bus", "dot@bus", request(4))
        .await
        .unwrap();
    assert_eq!(setup.callback.calls.load(Ordering::SeqCst), 1);
    assert_eq!(
        connection
            .query_row("SELECT verified_at FROM event_subscriptions", [], |r| r
                .get::<_, i64>(0))
            .unwrap(),
        actual_verification,
        "a cache hit must preserve the actual verification time"
    );
    connection
        .execute(
            "UPDATE event_subscriptions SET verified_at=?1",
            [webhook::signing_time().unwrap() - 600],
        )
        .unwrap();
    setup
        .runtime()
        .subscribe(&identity, "good-token", "bus", "dot@bus", request(4))
        .await
        .unwrap();
    assert_eq!(
        setup.callback.calls.load(Ordering::SeqCst),
        2,
        "the original verification window elapsed"
    );
    assert!(
        connection
            .query_row("SELECT verified_at FROM event_subscriptions", [], |r| r
                .get::<_, i64>(0))
            .unwrap()
            > actual_verification
    );
}

#[tokio::test]
async fn configured_grant_cannot_rebind_or_replay_another_grants_subscription() {
    let setup = Setup::new();
    let identity = setup.verifier.verify("good-token").await.unwrap();
    let subscription = setup
        .runtime()
        .subscribe(&identity, "good-token", "bus", "dot@bus", request(4))
        .await
        .unwrap();
    let connection = rusqlite::Connection::open(&setup.provider.store_file).unwrap();
    connection.execute("INSERT INTO custody_items(bus,upstream_id,event_id,grant_id,grant_revision,mailbox,owner,origin,text,envelope,fingerprint,received_at,expires_at,held) VALUES ('bus','recover','recover','grant',2,'dot@bus','owner','{}','body','envelope','hash',1,9999999999,1)",[]).unwrap();
    connection.execute("INSERT INTO event_authorizations(event_id,acceptance_class,dispatch_revision) VALUES ('recover','current',2)",[]).unwrap();
    connection
        .execute(
            "INSERT INTO event_occurrences(event_id) VALUES ('recover')",
            [],
        )
        .unwrap();
    connection
        .execute(
            "INSERT INTO custody_outbox(event_id,state) VALUES ('recover','accepted')",
            [],
        )
        .unwrap();
    connection
        .execute("UPDATE event_subscriptions SET callback_cursor=1", [])
        .unwrap();
    let wrong = Events::with_transport(
        setup.provider.store_file.clone(),
        setup.key.clone(),
        setup.verifier.clone(),
        "another-grant".into(),
        setup.callback.clone(),
    );
    let id = subscription["id"].as_str().unwrap();
    assert!(wrong
        .rebind(
            id,
            1,
            "https://replacement.example/wake",
            None,
            "fixture",
            "wrong scope"
        )
        .is_err());
    assert!(wrong
        .replay(
            id,
            1,
            subscription["cursor"].as_str(),
            "fixture",
            "wrong scope"
        )
        .is_err());
    let db = rusqlite::Connection::open(&setup.provider.store_file).unwrap();
    assert_eq!(
        db.query_row("SELECT generation FROM event_subscriptions", [], |row| row
            .get::<_, i64>(
            0
        ))
        .unwrap(),
        1
    );
    assert_eq!(
        db.query_row("SELECT COUNT(*) FROM event_binding_audit", [], |row| row
            .get::<_, i64>(0))
            .unwrap(),
        0
    );
    assert!(
        setup
            .runtime()
            .replay(
                id,
                1,
                subscription["cursor"].as_str(),
                "fixture",
                "owned control"
            )
            .is_ok(),
        "owned replay control must actually change an eligible row"
    );
}

#[tokio::test]
async fn failed_rotation_refresh_cannot_discard_a_still_valid_previous_key() {
    let setup = Setup::new();
    let identity = setup.verifier.verify("good-token").await.unwrap();
    setup
        .runtime()
        .subscribe(&identity, "good-token", "bus", "dot@bus", request(4))
        .await
        .unwrap();
    setup
        .runtime()
        .subscribe(&identity, "good-token", "bus", "dot@bus", request(5))
        .await
        .unwrap();
    rusqlite::Connection::open(&setup.provider.store_file)
        .unwrap()
        .execute("UPDATE event_subscriptions SET verified_at=0", [])
        .unwrap();
    let before = subscription_rows(&setup);
    let tokens = setup.provider.tokens.clone();
    *setup.callback.action.lock().unwrap() = Some(Box::new(move || {
        tokens.lock().unwrap().get_mut("good-token").unwrap()["active"] = json!(false)
    }));
    assert!(setup
        .runtime()
        .subscribe(&identity, "good-token", "bus", "dot@bus", request(5))
        .await
        .is_err());
    assert_eq!(
        subscription_rows(&setup),
        before,
        "failed cached-key refresh changed the active rotation window"
    );
    setup
        .provider
        .tokens
        .lock()
        .unwrap()
        .get_mut("good-token")
        .unwrap()["active"] = json!(true);
    assert!(
        matches!(
            setup
                .runtime()
                .subscribe(&identity, "good-token", "bus", "dot@bus", request(6))
                .await,
            Err(xmsg_mcp_gateway::events::Error::Conflict)
        ),
        "failed refresh discarded a still-valid rotation key"
    );
    setup
        .runtime()
        .subscribe(&identity, "good-token", "bus", "dot@bus", request(5))
        .await
        .unwrap();
}

#[tokio::test]
async fn callback_host_allowlist_refuses_before_any_outbound_request() {
    let mut violations = Vec::new();
    for host in [
        "off-list.example",
        "receiver.example.com.attacker.example",
        "evilreceiver.example.com",
        "sub.receiver.example.com",
    ] {
        let setup = Setup::new();
        let identity = setup.verifier.verify("good-token").await.unwrap();
        let events = setup
            .runtime()
            .with_allowed_hosts(Some(vec!["receiver.example.com".into()]))
            .unwrap();
        let mut input = request(4);
        input.delivery.url = format!("https://{host}/events");
        let result = events
            .subscribe(&identity, "good-token", "bus", "dot@bus", input)
            .await;
        let calls = setup.callback.calls.load(Ordering::SeqCst);
        let rows: i64 = rusqlite::Connection::open(&setup.provider.store_file)
            .unwrap()
            .query_row("SELECT count(*) FROM event_subscriptions", [], |row| {
                row.get(0)
            })
            .unwrap();
        if !matches!(
            result,
            Err(xmsg_mcp_gateway::events::Error::Callback(
                webhook::Error::HostNotAllowed
            ))
        ) || calls != 0
            || rows != 0
        {
            violations.push(format!(
                "{host}: not refused before I/O (calls={calls}, rows={rows})"
            ));
        }
    }
    assert!(
        violations.is_empty(),
        "callback host boundary violations: {violations:?}"
    );
}

#[tokio::test]
async fn callback_host_allowlist_renew_refusal_preserves_active_subscription() {
    let setup = Setup::new();
    let identity = setup.verifier.verify("good-token").await.unwrap();
    let mut input = request(4);
    input.delivery.url = "https://receiver.example.com/events".into();
    setup
        .runtime()
        .with_allowed_hosts(Some(vec!["receiver.example.com".into()]))
        .unwrap()
        .subscribe(&identity, "good-token", "bus", "dot@bus", input)
        .await
        .unwrap();
    assert_eq!(setup.callback.calls.load(Ordering::SeqCst), 1);
    let connection = rusqlite::Connection::open(&setup.provider.store_file).unwrap();
    let snapshot = || {
        let mut statement = connection
            .prepare("SELECT * FROM event_subscriptions")
            .unwrap();
        let columns = statement.column_count();
        statement
            .query_row([], |row| {
                (0..columns)
                    .map(|index| row.get::<_, rusqlite::types::Value>(index))
                    .collect::<Result<Vec<_>, _>>()
            })
            .unwrap()
    };
    let before = snapshot();
    let mut renewal = request(5);
    renewal.delivery.url = "https://receiver.example.com/events".into();
    renewal.ttl_ms = Some(60_000);
    let error = setup
        .runtime()
        .with_allowed_hosts(Some(vec!["replacement.example.com".into()]))
        .unwrap()
        .subscribe(&identity, "good-token", "bus", "dot@bus", renewal)
        .await
        .unwrap_err();
    assert!(matches!(
        error,
        xmsg_mcp_gateway::events::Error::Callback(webhook::Error::HostNotAllowed)
    ));
    assert_eq!(setup.callback.calls.load(Ordering::SeqCst), 1);
    assert_eq!(snapshot(), before, "refused renew changed the active row");
    let status: String = connection
        .query_row("SELECT status FROM event_subscriptions", [], |row| {
            row.get(0)
        })
        .unwrap();
    assert_eq!(status, "active");
}

#[derive(Clone)]
struct CallbackLog(Arc<Mutex<Vec<u8>>>);
impl std::io::Write for CallbackLog {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(bytes);
        Ok(bytes.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

#[tokio::test]
async fn callback_host_log_excludes_path_query_port_and_signing_secret() {
    use tracing::instrument::WithSubscriber;
    for hosts in [
        None,
        Some(vec!["receiver.example.com".into()]),
        Some(vec!["different.example.com".into()]),
        Some(Vec::new()),
    ] {
        let setup = Setup::new();
        let identity = setup.verifier.verify("good-token").await.unwrap();
        let denied = hosts
            .as_ref()
            .is_some_and(|hosts| !hosts.iter().any(|host| host == "receiver.example.com"));
        let events = setup.runtime().with_allowed_hosts(hosts).unwrap();
        let captured = CallbackLog(Arc::new(Mutex::new(Vec::new())));
        let writer = captured.clone();
        let subscriber = tracing_subscriber::fmt()
            .without_time()
            .with_ansi(false)
            .with_max_level(tracing::Level::INFO)
            .with_writer(move || writer.clone())
            .finish();
        let mut input = request(7);
        let secret = input.delivery.secret.clone();
        input.delivery.url =
            "https://RECEIVER.example.com:443/PATH_CANARY?query=QUERY_CANARY".into();
        let result = events
            .subscribe(&identity, "good-token", "bus", "dot@bus", input)
            .with_subscriber(subscriber)
            .await;
        assert_eq!(result.is_err(), denied);
        assert_eq!(
            setup.callback.calls.load(Ordering::SeqCst),
            usize::from(!denied)
        );
        let log = String::from_utf8(captured.0.lock().unwrap().clone()).unwrap();
        let lines: Vec<_> = log
            .lines()
            .filter(|line| line.contains("gateway_events") && line.contains("callback_host="))
            .collect();
        assert_eq!(lines.len(), 1, "one Events host log is required: {log}");
        assert!(lines[0].contains("receiver.example.com"), "{log}");
        assert_eq!(lines[0].contains("callback_host_not_allowed"), denied);
        for canary in [
            "PATH_CANARY",
            "QUERY_CANARY",
            secret.as_str(),
            ":443",
            "https://",
        ] {
            assert!(!log.contains(canary), "callback log leaked {canary}: {log}");
        }
    }
}

fn subscription_rows(setup: &Setup) -> Vec<Vec<rusqlite::types::Value>> {
    let connection = rusqlite::Connection::open(&setup.provider.store_file).unwrap();
    let mut statement = connection
        .prepare("SELECT * FROM event_subscriptions ORDER BY owner_key")
        .unwrap();
    let columns = statement.column_count();
    statement
        .query_map([], |row| (0..columns).map(|index| row.get(index)).collect())
        .unwrap()
        .collect::<Result<_, _>>()
        .unwrap()
}

#[tokio::test]
async fn atomic_renewal_callback_failure_preserves_every_active_row_column() {
    let setup = Setup::new();
    let identity = setup.verifier.verify("good-token").await.unwrap();
    setup
        .runtime()
        .subscribe(&identity, "good-token", "bus", "dot@bus", request(4))
        .await
        .unwrap();
    let before = subscription_rows(&setup);
    setup.callback.status.store(503, Ordering::SeqCst);
    let mut renewal = request(5);
    renewal.ttl_ms = Some(60_000);
    assert!(matches!(
        setup
            .runtime()
            .subscribe(&identity, "good-token", "bus", "dot@bus", renewal)
            .await,
        Err(xmsg_mcp_gateway::events::Error::Callback(
            webhook::Error::Challenge
        ))
    ));
    assert_eq!(
        subscription_rows(&setup),
        before,
        "failed callback renewal overwrote the active binding"
    );
    assert_eq!(setup.callback.calls.load(Ordering::SeqCst), 2);
}

#[tokio::test]
async fn atomic_renewal_credential_failure_preserves_every_active_row_column() {
    let setup = Setup::new();
    let identity = setup.verifier.verify("good-token").await.unwrap();
    setup
        .runtime()
        .subscribe(&identity, "good-token", "bus", "dot@bus", request(4))
        .await
        .unwrap();
    let before = subscription_rows(&setup);
    let tokens = setup.provider.tokens.clone();
    let claims = tokens.lock().unwrap()["good-token"].clone();
    tokens
        .lock()
        .unwrap()
        .insert("renewal-token".into(), claims);
    let renewal_identity = setup.verifier.verify("renewal-token").await.unwrap();
    *setup.callback.action.lock().unwrap() = Some(Box::new(move || {
        tokens.lock().unwrap().get_mut("renewal-token").unwrap()["active"] = json!(false);
    }));
    assert!(setup
        .runtime()
        .subscribe(
            &renewal_identity,
            "renewal-token",
            "bus",
            "dot@bus",
            request(5)
        )
        .await
        .is_err());
    assert_eq!(
        subscription_rows(&setup),
        before,
        "failed credential renewal overwrote the active binding"
    );
    assert!(
        setup.verifier.verify("good-token").await.is_ok(),
        "the old stored bearer must remain valid"
    );
}

#[tokio::test]
async fn atomic_first_subscribe_failure_leaves_no_provisional_row() {
    for credential_failure in [false, true] {
        let setup = Setup::new();
        let identity = setup.verifier.verify("good-token").await.unwrap();
        if credential_failure {
            let tokens = setup.provider.tokens.clone();
            *setup.callback.action.lock().unwrap() = Some(Box::new(move || {
                tokens.lock().unwrap().get_mut("good-token").unwrap()["active"] = json!(false);
            }));
        } else {
            setup.callback.status.store(503, Ordering::SeqCst);
        }
        assert!(setup
            .runtime()
            .subscribe(&identity, "good-token", "bus", "dot@bus", request(4))
            .await
            .is_err());
        assert!(subscription_rows(&setup).is_empty(),"failed first subscribe persisted provisional credentials (credential_failure={credential_failure})");
    }
}

#[tokio::test]
async fn atomic_renewal_transaction_failure_preserves_every_active_row_column() {
    let setup = Setup::new();
    let identity = setup.verifier.verify("good-token").await.unwrap();
    setup
        .runtime()
        .subscribe(&identity, "good-token", "bus", "dot@bus", request(4))
        .await
        .unwrap();
    let before = subscription_rows(&setup);
    rusqlite::Connection::open(&setup.provider.store_file).unwrap().execute_batch(
        "CREATE TRIGGER abort_subscription_activation BEFORE UPDATE OF status ON event_subscriptions WHEN NEW.status='active' BEGIN SELECT RAISE(ABORT,'forced activation failure'); END;"
    ).unwrap();
    assert!(setup
        .runtime()
        .subscribe(&identity, "good-token", "bus", "dot@bus", request(5))
        .await
        .is_err());
    assert_eq!(
        subscription_rows(&setup),
        before,
        "failed transaction left a partial subscription replacement"
    );
}
