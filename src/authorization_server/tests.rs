use super::liveness::{decision, Attribute};
use super::store::{Cutover, Pair};
use super::*;
use crate::grants::{Binding, Store};
use base64::Engine;
use serde_json::json;
use sha2::{Digest, Sha256};
use std::sync::atomic::{AtomicI64, Ordering};

struct TestClock(AtomicI64);
impl Clock for TestClock {
    fn wall(&self) -> i64 {
        self.0.load(Ordering::SeqCst)
    }
}
struct Setup {
    _files: tempfile::TempDir,
    server: Arc<Server>,
    clock: Arc<TestClock>,
    fake: super::test_provider::Fake,
}
impl Setup {
    fn new() -> Self {
        static TRACE_BASELINE: std::sync::Once = std::sync::Once::new();
        TRACE_BASELINE.call_once(crate::events_test_support::fixture::initialize_tracing_baseline);
        use std::os::unix::fs::PermissionsExt;
        let fake = super::test_provider::Fake::new();
        let files = tempfile::tempdir().unwrap();
        let file = |name: &str, data: &[u8]| {
            let p = files.path().join(name);
            std::fs::write(&p, data).unwrap();
            std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o600)).unwrap();
            p
        };
        let secret = file("client", b"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
        let lookup = file("lookup", b"fixture-lookup");
        let reader = file("reader", b"fixture-reader");
        let key = file("events", &[7; 32]);
        let db = files.path().join("state.db");
        let mut store = Store::initialize(&db).unwrap();
        let binding = Binding {
            service: "gateway".into(),
            issuer: "https://gateway.example".into(),
            resource: "https://gateway.example/mcp".into(),
            subject: "owner".into(),
            hosted_client: "dot".into(),
        };
        store.enroll("local", &binding).unwrap();
        store.set_enabled("local", 1, true).unwrap();
        store.migrate_profiles().unwrap();
        store.migrate_custody().unwrap();
        store.migrate_outbound().unwrap();
        store.migrate_retirement().unwrap();
        store
            .migrate_events(&crate::event_store::EventKey::load(&key).unwrap())
            .unwrap();
        store.migrate_authorization_server().unwrap();
        let config:Config=serde_json::from_value(json!({"issuer":binding.issuer,"client":{"id":"dot","secret_file":secret,"redirect_uris":["https://chat.example/callback"]},"upstream":{"authorization_endpoint":format!("{}/auth",fake.origin),"token_endpoint":format!("{}/token",fake.origin),"client_id":"login","redirect_uri":"https://gateway.example/oauth/callback","verify":{"service":"gateway","issuer":"https://provider.example/issuer","resource":binding.resource,"audience":"login","subject":"owner","hosted_client":"login","introspection_url":format!("{}/introspect",fake.origin),"introspection_client":"lookup","client_secret_file":lookup,"required_scopes":["openid"],"timeout_ms":5000,"root_certificate_file":fake.keys.roots}},"liveness":{"api_url":fake.origin,"person":"owner","group":"login.access@test","canary_person":"canary","token_file":reader}})).unwrap();
        let clock = Arc::new(TestClock(AtomicI64::new(
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs() as i64,
        )));
        let server = Server::from_config(
            config,
            db,
            binding,
            vec!["identity:read".into(), "events:subscribe".into()],
            clock.clone(),
        )
        .unwrap();
        Self {
            _files: files,
            server,
            clock,
            fake,
        }
    }
    fn pair(&self) -> Pair {
        let verifier = "p".repeat(43);
        let challenge = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .encode(Sha256::digest(verifier.as_bytes()));
        let grant = self.server.local_authority().unwrap();
        let code = self
            .server
            .issue_code(
                &grant,
                "https://chat.example/callback",
                &challenge,
                "identity:read events:subscribe",
                self.clock.wall(),
            )
            .unwrap();
        self.server
            .exchange(&code, "https://chat.example/callback", &verifier, None)
            .unwrap()
    }
    fn db(&self) -> rusqlite::Connection {
        rusqlite::Connection::open(&self.server.file).unwrap()
    }
}

#[test]
fn migration_is_explicit_preserves_grants_and_requires_profiles_and_events() {
    let setup = Setup::new();
    let store = setup.server.store().unwrap();
    store.require_authorization_server_ready().unwrap();
    assert!(store
        .migration_applied(crate::grants::Migration::AuthorizationServer)
        .unwrap());
    assert!(!store
        .pending_migrations()
        .unwrap()
        .contains(&"migrate-authorization-server"));
    let db = setup.db();
    assert_eq!(
        db.query_row("SELECT revision FROM grants WHERE id='local'", [], |r| r
            .get::<_, i64>(0))
            .unwrap(),
        2
    );
    let dir = tempfile::tempdir().unwrap();
    let mut old = Store::initialize(&dir.path().join("old")).unwrap();
    assert!(old.migrate_authorization_server().is_err());
    let mut store = setup.server.store().unwrap();
    assert!(store.migrate_authorization_server().is_err());
}
#[test]
fn admission_marks_successor_once_and_rechecks_revoked_expired_idle_absolute_and_grant() {
    let setup = Setup::new();
    let pair = setup.pair();
    let admitted = setup.server.admit(&pair.access_token).unwrap();
    assert_eq!(admitted.authority.grant_id, "local");
    let used: i64 = setup
        .db()
        .query_row("SELECT first_used_at FROM oauth_access_tokens", [], |r| {
            r.get(0)
        })
        .unwrap();
    assert_eq!(used, setup.clock.wall());
    setup.server.admit(&pair.access_token).unwrap();
    for sql in [
        "UPDATE oauth_access_tokens SET revoked_at=1",
        "UPDATE oauth_access_tokens SET expires_at=0",
        "UPDATE oauth_families SET absolute_expires_at=0",
        "UPDATE oauth_families SET last_refresh_at=0",
        "UPDATE grants SET enabled=0",
    ] {
        let sample = Setup::new();
        let p = sample.pair();
        sample.db().execute_batch(sql).unwrap();
        assert!(
            sample.server.admit(&p.access_token).is_err(),
            "admission accepted {sql}"
        );
    }
}
#[test]
fn failed_exchange_rolls_back_code_use_but_successful_replay_revokes_family() {
    let setup = Setup::new();
    let verifier = "p".repeat(43);
    let challenge = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .encode(Sha256::digest(verifier.as_bytes()));
    let authority = setup.server.local_authority().unwrap();
    let code = setup
        .server
        .issue_code(
            &authority,
            "https://chat.example/callback",
            &challenge,
            "identity:read events:subscribe",
            setup.clock.wall(),
        )
        .unwrap();
    assert!(setup
        .server
        .exchange(
            &code,
            "https://chat.example/callback",
            &"q".repeat(43),
            None
        )
        .is_err());
    assert_eq!(
        setup
            .db()
            .query_row("SELECT used_at FROM oauth_codes", [], |r| r
                .get::<_, Option<i64>>(0))
            .unwrap(),
        None
    );
    let pair = setup
        .server
        .exchange(&code, "https://chat.example/callback", &verifier, None)
        .unwrap();
    assert!(setup
        .server
        .exchange(&code, "https://chat.example/callback", &verifier, None)
        .is_err());
    assert!(
        setup.server.admit(&pair.access_token).is_err(),
        "replayed code left its minted family usable"
    );
}
#[test]
fn liveness_negative_first_and_null_visibility_matrix() {
    use Attribute::*;
    let positive = [Null, Null, Strings(vec!["login@test".into()])];
    let canary = [Date(0), Date(i64::MAX)];
    assert_eq!(
        decision(&positive, &canary, true, "login@test", 100),
        Outcome::Positive
    );
    for i in 0..3 {
        let mut denied = positive.clone();
        denied[i] = match i {
            0 => Date(101),
            1 => Date(100),
            _ => Strings(vec![]),
        };
        assert_eq!(
            decision(&denied, &[Null, Unavailable], false, "login@test", 100),
            Outcome::Negative
        );
        let mut unavailable = positive.clone();
        unavailable[i] = Unavailable;
        assert_eq!(
            decision(&unavailable, &canary, true, "login@test", 100),
            Outcome::Unavailable
        );
    }
    assert_eq!(
        decision(&positive, &[Null, Date(9)], true, "login@test", 100),
        Outcome::Indeterminate
    );
    assert_eq!(
        decision(&positive, &canary, false, "login@test", 100),
        Outcome::Indeterminate
    );
    let mut hidden = positive;
    hidden[2] = Null;
    assert_eq!(
        decision(&hidden, &canary, true, "login@test", 100),
        Outcome::Indeterminate
    );
}
#[test]
fn stale_liveness_never_replaces_newer_evidence_or_revives_revoked_family() {
    let setup = Setup::new();
    let pair = setup.pair();
    let id = setup.server.admit(&pair.access_token).unwrap().family;
    let (first, start) = setup.server.claim(&id, false).unwrap().unwrap();
    setup.clock.0.fetch_add(20, Ordering::SeqCst);
    let (second, later) = setup.server.claim(&id, false).unwrap().unwrap();
    setup
        .server
        .apply_liveness(&id, second, later, Outcome::Unavailable)
        .unwrap();
    setup
        .server
        .apply_liveness(&id, first, start, Outcome::Positive)
        .unwrap();
    let row: (String, i64) = setup
        .db()
        .query_row(
            "SELECT last_liveness_outcome,liveness_applied FROM oauth_families",
            [],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .unwrap();
    assert_eq!(row, ("unavailable".into(), second));
    setup
        .server
        .apply_liveness(&id, first, start, Outcome::Negative)
        .unwrap();
    setup
        .server
        .apply_liveness(&id, second + 1, later + 1, Outcome::Positive)
        .unwrap();
    assert!(setup.server.verify_family(&id).is_err());
    assert_eq!(
        setup
            .db()
            .query_row("SELECT liveness_ok_at FROM oauth_families", [], |r| r
                .get::<_, i64>(0))
            .unwrap(),
        start,
        "positive result changed evidence after family revocation"
    );
}
#[test]
fn rollback_revokes_persistently_and_mints_wait_for_catchup() {
    let setup = Setup::new();
    let pair = setup.pair();
    let before = setup.clock.wall();
    setup.clock.0.store(before - 600, Ordering::SeqCst);
    assert!(setup.server.admit(&pair.access_token).is_err());
    assert_eq!(
        setup
            .db()
            .query_row("SELECT revoked_reason FROM oauth_families", [], |r| r
                .get::<_, String>(0))
            .unwrap(),
        "clock_rollback"
    );
    assert!(setup.server.clock.mint(&setup.db()).is_err());
    setup.clock.0.store(before, Ordering::SeqCst);
    assert!(setup.server.clock.mint(&setup.db()).is_ok());
    assert!(setup.server.admit(&pair.access_token).is_err());
}
#[test]
fn repeated_small_clock_steps_document_accumulation_without_invented_bound() {
    let setup = Setup::new();
    let pair = setup.pair();
    let start = setup.clock.wall();
    let mut real = start;
    for _ in 0..50 {
        real += 5;
        setup.clock.0.fetch_add(5, Ordering::SeqCst);
        setup.server.clock.observe(&setup.db(), false).unwrap();
        setup.clock.0.fetch_sub(4, Ordering::SeqCst);
        setup.server.clock.observe(&setup.db(), false).unwrap();
    }
    assert_eq!(real - setup.clock.wall(), 200);
    let expiry: i64 = setup
        .db()
        .query_row("SELECT expires_at FROM oauth_access_tokens", [], |r| {
            r.get(0)
        })
        .unwrap();
    let age = expiry - 1 - setup.clock.wall();
    real += age;
    setup.clock.0.fetch_add(age, Ordering::SeqCst);
    assert_eq!(
        real,
        expiry + 199,
        "real time control did not exceed access expiry"
    );

    assert!(setup.server.admit(&pair.access_token).is_ok());
    assert_eq!(
        setup
            .db()
            .query_row("SELECT revoked_at FROM oauth_families", [], |r| r
                .get::<_, Option<i64>>(0))
            .unwrap(),
        None
    );
    setup.clock.0.fetch_add(1, Ordering::SeqCst);
    assert!(
        setup.server.admit(&pair.access_token).is_err(),
        "wall-time expiry was ignored"
    );
}
#[test]
fn grant_disable_revokes_family_without_breaking_legacy_store() {
    let setup = Setup::new();
    let pair = setup.pair();
    let mut store = setup.server.store().unwrap();
    store.set_enabled("local", 2, false).unwrap();
    store.set_enabled("local", 3, true).unwrap();
    assert!(setup.server.admit(&pair.access_token).is_err());
    let dir = tempfile::tempdir().unwrap();
    let mut legacy = Store::initialize(&dir.path().join("old")).unwrap();
    legacy.enroll("old", &setup.server.binding).unwrap();
    legacy.set_enabled("old", 1, true).unwrap();
    legacy.set_enabled("old", 2, false).unwrap();
}
#[test]
fn store_contains_hashes_and_no_minted_tokens() {
    let setup = Setup::new();
    let pair = setup.pair();
    let bytes = std::fs::read(&setup.server.file).unwrap();
    for secret in [
        &pair.access_token,
        &pair.refresh_token,
        &setup.server.client_secret,
    ] {
        assert!(
            !bytes.windows(secret.len()).any(|w| w == secret.as_bytes()),
            "durable store retained raw secret"
        );
    }
    assert_eq!(
        setup
            .db()
            .query_row("SELECT length(hash) FROM oauth_access_tokens", [], |r| r
                .get::<_, i64>(0))
            .unwrap(),
        64
    );
}
#[test]
fn cutover_busy_unread_observed_and_abandon_guard() {
    let setup = Setup::new();
    let mut store = setup.server.store().unwrap();
    let mut other = setup.server.binding.clone();
    other.issuer = "https://old.example".into();
    store.enroll("old", &other).unwrap();
    let lease = store.try_operation_lease("gateway").unwrap().unwrap();
    assert_eq!(
        store
            .cutover_events("old", "local", "owner", "move", false, setup.clock.wall())
            .unwrap(),
        Cutover::Busy
    );
    drop(lease);
    setup.db().execute("INSERT INTO custody_items(bus,upstream_id,event_id,grant_id,grant_revision,mailbox,owner,origin,text,envelope,fingerprint,received_at,expires_at,held) VALUES('bus','one','one','old',1,'gateway@bus','owner','{}','text','{}','hash',0,9999999999,1)",[]).unwrap();
    assert_eq!(
        store
            .cutover_events("old", "local", "owner", "move", false, setup.clock.wall())
            .unwrap(),
        Cutover::Unread { from: 1, to: 0 }
    );
    assert_eq!(
        store
            .cutover_events("old", "local", "owner", "move", true, setup.clock.wall())
            .unwrap(),
        Cutover::Complete
    );
    assert_eq!(
        store.selected_cutover_grant().unwrap().as_deref(),
        Some("local")
    );
    assert_eq!(
        setup
            .db()
            .query_row(
                "SELECT COUNT(*) FROM event_release_audit WHERE reason='cutover-abandon'",
                [],
                |r| r.get::<_, i64>(0)
            )
            .unwrap(),
        1
    );
    setup
        .db()
        .execute("INSERT INTO event_observations VALUES('one',1)", [])
        .unwrap();
    assert_eq!(
        store
            .cutover_events(
                "local",
                "old",
                "owner",
                "rollback",
                false,
                setup.clock.wall()
            )
            .unwrap(),
        Cutover::Complete
    );
}

#[tokio::test]
async fn refresh_retry_supersedes_successor_and_reuse_revokes_whole_family() {
    let setup = Setup::new();
    let first = setup.pair();
    let second = setup.server.refresh(&first.refresh_token).await.unwrap();
    setup.clock.0.fetch_add(29, Ordering::SeqCst);
    let third = setup.server.refresh(&first.refresh_token).await.unwrap();
    assert!(
        setup.server.admit(&second.access_token).is_err(),
        "retry retained superseded access"
    );
    assert!(setup.server.admit(&third.access_token).is_ok());
    assert!(
        setup.server.refresh(&first.refresh_token).await.is_err(),
        "second retry accepted"
    );
    assert!(
        setup.server.admit(&third.access_token).is_err(),
        "reuse left successor family usable"
    );
    assert_eq!(
        setup
            .db()
            .query_row("SELECT COUNT(*) FROM oauth_rotation_log", [], |r| r
                .get::<_, i64>(0))
            .unwrap(),
        2,
        "retry not counted as rotation"
    );
    assert_eq!(
        setup
            .db()
            .query_row("SELECT last_refresh_at FROM oauth_families", [], |r| r
                .get::<_, i64>(0))
            .unwrap(),
        setup.clock.wall(),
        "retry did not refresh idle timestamp"
    );
}
#[tokio::test]
async fn superseded_refresh_is_reuse_and_old_rotated_refresh_expires_at_31_seconds() {
    for superseded in [false, true] {
        let setup = Setup::new();
        let first = setup.pair();
        let second = setup.server.refresh(&first.refresh_token).await.unwrap();
        let current = if superseded {
            setup.server.refresh(&first.refresh_token).await.unwrap()
        } else {
            setup.clock.0.fetch_add(31, Ordering::SeqCst);
            second.clone()
        };
        let offender = if superseded {
            setup
                .db()
                .query_row(
                    "SELECT hash FROM oauth_refresh_tokens WHERE superseded_at IS NOT NULL",
                    [],
                    |r| r.get::<_, String>(0),
                )
                .unwrap();
            None
        } else {
            Some(first.refresh_token.as_str())
        };
        if let Some(offender) = offender {
            assert!(setup.server.refresh(offender).await.is_err())
        } else {
            assert!(setup.server.refresh(&second.refresh_token).await.is_err())
        }
        assert!(
            setup.server.admit(&current.access_token).is_err(),
            "reuse did not revoke current pair"
        );
    }
}
#[tokio::test]
async fn successor_access_use_prevents_lost_response_retry() {
    let setup = Setup::new();
    let first = setup.pair();
    let second = setup.server.refresh(&first.refresh_token).await.unwrap();
    setup.server.admit(&second.access_token).unwrap();
    assert!(setup.server.refresh(&first.refresh_token).await.is_err());
    assert!(setup.server.admit(&second.access_token).is_err());
}
#[tokio::test]
async fn liveness_https_exact_read_set_null_canary_and_negative_precedence() {
    let setup = Setup::new();
    assert_eq!(
        setup.server.liveness.read(setup.clock.wall()).await,
        Outcome::Positive
    );
    let routes = setup.fake.requests.lock().unwrap().clone();
    assert_eq!(routes.len(), 5);
    assert!(routes
        .iter()
        .all(|r| !r.contains("consent") && r.contains("/_attr/")));
    assert!(!routes.contains(&"/v1/person/canary/_attr/memberof".into()));
    setup.fake.set(
        "/v1/person/canary/_attr/account_expire",
        200,
        serde_json::Value::Null,
    );
    assert_eq!(
        setup.server.liveness.read(setup.clock.wall()).await,
        Outcome::Indeterminate
    );
    setup.fake.set(
        "/v1/person/owner/_attr/account_expire",
        200,
        json!(["2020-01-01T00:00:00Z"]),
    );
    setup
        .fake
        .set("/v1/person/owner/_attr/memberof", 503, json!({}));
    assert_eq!(
        setup.server.liveness.read(setup.clock.wall()).await,
        Outcome::Negative,
        "visibility/unavailable hid readable denial"
    );
}
#[tokio::test]
async fn grace_is_bounded_freezes_positive_time_and_preserves_current_on_refusal() {
    let setup = Setup::new();
    let first = setup.pair();
    let live = setup.clock.wall();
    setup
        .fake
        .set("/v1/person/owner", 200, serde_json::Value::Null);
    setup.clock.0.fetch_add(3600, Ordering::SeqCst);
    let graced = setup.server.refresh(&first.refresh_token).await.unwrap();
    assert_eq!(graced.expires_in, 900);
    assert_eq!(
        setup
            .db()
            .query_row("SELECT liveness_ok_at FROM oauth_families", [], |r| r
                .get::<_, i64>(0))
            .unwrap(),
        live
    );
    setup.clock.0.fetch_add(841, Ordering::SeqCst);
    assert!(
        matches!(
            setup.server.refresh(&graced.refresh_token).await,
            Err(Error::Unavailable)
        ),
        "mint under60 seconds of grace was accepted"
    );
    let still_current: bool = setup
        .db()
        .query_row(
            "SELECT rotated_at IS NULL FROM oauth_refresh_tokens WHERE hash=?1",
            [hash(&graced.refresh_token)],
            |r| r.get(0),
        )
        .unwrap();
    assert!(still_current, "503 rotated the current refresh");
}
#[tokio::test]
async fn grace_exact_60_seconds_refuses_while_61_seconds_can_mint() {
    for remaining in [60, 61] {
        let setup = Setup::new();
        let pair = setup.pair();
        setup
            .fake
            .set("/v1/person/owner", 200, serde_json::Value::Null);
        setup.clock.0.fetch_add(4500 - remaining, Ordering::SeqCst);
        let result = setup.server.refresh(&pair.refresh_token).await;
        if remaining == 60 {
            assert!(
                matches!(result, Err(Error::Unavailable)),
                "exact60 grace mint was accepted"
            );
        } else {
            assert_eq!(result.unwrap().expires_in, 61);
        }
    }
}

#[tokio::test]
async fn pruning_refresh_rows_never_resets_rolling_rotation_cap() {
    let mut setup = Setup::new();
    let server = Arc::get_mut(&mut setup.server).unwrap();
    server.config.max_refresh_rows = 1;
    server.config.rotations_per_hour = 2;
    let a = setup.pair();
    let b = setup.server.refresh(&a.refresh_token).await.unwrap();
    let c = setup.server.refresh(&b.refresh_token).await.unwrap();
    assert_eq!(setup.db().query_row("SELECT COUNT(*) FROM oauth_refresh_tokens WHERE rotated_at IS NOT NULL OR superseded_at IS NOT NULL",[],|r|r.get::<_,i64>(0)).unwrap(),1);
    assert!(
        matches!(
            setup.server.refresh(&c.refresh_token).await,
            Err(Error::RateLimited)
        ),
        "pruned rows reset rolling cap"
    );
    setup.clock.0.fetch_add(3601, Ordering::SeqCst);
    assert!(setup.server.refresh(&c.refresh_token).await.is_ok());
}
#[tokio::test]
async fn concurrent_presentations_allow_one_rotation_one_retry_then_revoke() {
    let setup = Setup::new();
    let first = setup.pair();
    let mut tasks = Vec::new();
    let start = Arc::new(tokio::sync::Barrier::new(8));
    for _ in 0..8 {
        let server = setup.server.clone();
        let token = first.refresh_token.clone();
        let start = start.clone();
        tasks.push(tokio::spawn(async move {
            start.wait().await;
            server.refresh(&token).await.is_ok()
        }));
    }
    let mut successful = 0;
    for task in tasks {
        successful += usize::from(task.await.unwrap());
    }
    assert_eq!(successful, 2, "parallel rotation/retry count drift");
    assert_eq!(
        setup
            .db()
            .query_row("SELECT revoked_reason FROM oauth_families", [], |r| r
                .get::<_, String>(0))
            .unwrap(),
        "refresh_reuse"
    );
}
#[tokio::test]
async fn authorize_exact_redirect_pkce_metadata_basic_and_upstream_callback() {
    let setup = Setup::new();
    let verifier = "v".repeat(43);
    let challenge = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .encode(Sha256::digest(verifier.as_bytes()));
    let query=format!("client_id=dot&redirect_uri=https%3A%2F%2Fchat.example%2Fcallback&response_type=code&resource=https%3A%2F%2Fgateway.example%2Fmcp&code_challenge={challenge}&code_challenge_method=S256&state=roundtrip");
    let rejected = setup
        .server
        .handle(
            "/oauth/authorize",
            "GET",
            &query.replace("%2Fcallback", "%2Fother"),
            None,
            "",
        )
        .await;
    assert_eq!(rejected.status, 400);
    assert!(rejected.location.is_none());
    let reply = setup
        .server
        .handle("/oauth/authorize", "GET", &query, None, "")
        .await;
    assert_eq!(reply.status, 302);
    let destination = reqwest::Url::parse(reply.location.as_ref().unwrap()).unwrap();
    let state = destination
        .query_pairs()
        .find(|(k, _)| k == "state")
        .unwrap()
        .1
        .into_owned();
    let callback = setup
        .server
        .handle(
            "/oauth/callback",
            "GET",
            &format!("state={state}&code=upstream"),
            None,
            "",
        )
        .await;
    assert_eq!(callback.status, 302);
    let destination = reqwest::Url::parse(callback.location.as_ref().unwrap()).unwrap();
    let code = destination
        .query_pairs()
        .find(|(k, _)| k == "code")
        .expect("upstream callback failed")
        .1
        .into_owned();
    assert!(!destination.query_pairs().any(|(k, _)| k == "iss"));
    let body=format!("grant_type=authorization_code&code={code}&redirect_uri=https%3A%2F%2Fchat.example%2Fcallback&code_verifier={verifier}");
    let denied = setup
        .server
        .handle("/oauth/token", "POST", "", Some("Basic bad"), &body)
        .await;
    assert_eq!(denied.status, 401);
    assert!(denied.basic);
    let auth = format!(
        "Basic {}",
        base64::engine::general_purpose::STANDARD
            .encode(format!("dot:{}", setup.server.client_secret))
    );
    let pair = setup
        .server
        .handle("/oauth/token", "POST", "", Some(&auth), &body)
        .await;
    assert_eq!(pair.status, 200);
    assert!(setup
        .server
        .admit(pair.body["access_token"].as_str().unwrap())
        .is_ok());
    let metadata = setup.server.metadata();
    assert!(metadata
        .get("authorization_response_iss_parameter_supported")
        .is_none());
    assert!(metadata.get("registration_endpoint").is_none());
    assert_eq!(
        metadata["token_endpoint_auth_methods_supported"],
        json!(["client_secret_basic"])
    );
}

struct SequenceClock {
    values: std::sync::Mutex<std::collections::VecDeque<i64>>,
    last: AtomicI64,
}
impl Clock for SequenceClock {
    fn wall(&self) -> i64 {
        if let Some(value) = self.values.lock().unwrap().pop_front() {
            self.last.store(value, Ordering::SeqCst);
        }
        self.last.load(Ordering::SeqCst)
    }
}
#[test]
fn rollback_between_outer_check_and_transaction_commits_revocation() {
    for admission in [true, false] {
        let mut setup = Setup::new();
        let pair = setup.pair();
        let at = setup.clock.wall();
        let sequence = Arc::new(SequenceClock {
            values: std::sync::Mutex::new([at, at - 600, at - 600].into()),
            last: AtomicI64::new(at - 600),
        });
        let fence = super::clock::Fence::new(sequence, &setup.db()).unwrap();
        Arc::get_mut(&mut setup.server).unwrap().clock = fence;
        if admission {
            assert!(setup.server.admit(&pair.access_token).is_err())
        } else {
            let id = setup
                .db()
                .query_row("SELECT id FROM oauth_families", [], |r| {
                    r.get::<_, String>(0)
                })
                .unwrap();
            assert!(setup.server.claim(&id, false).is_err())
        }
        assert_eq!(
            setup
                .db()
                .query_row("SELECT revoked_reason FROM oauth_families", [], |r| r
                    .get::<_, String>(0))
                .unwrap(),
            "clock_rollback",
            "rollback during transaction lost revocation"
        );
        assert_eq!(
            setup
                .db()
                .query_row("SELECT rollback_until FROM clock_hw", [], |r| r
                    .get::<_, i64>(0))
                .unwrap(),
            at
        );
    }
}
#[test]
fn rollback_of_clock_persistence_does_not_advance_committed_cache() {
    let setup = Setup::new();
    setup.pair();
    let before = setup.clock.wall();
    setup.clock.0.fetch_add(11, Ordering::SeqCst);
    let mut store = setup.server.store().unwrap();
    let tx = store.connection.transaction().unwrap();
    setup.server.clock.observe(&tx, true).unwrap();
    drop(tx);
    assert_eq!(
        setup
            .db()
            .query_row("SELECT value FROM clock_hw", [], |r| r.get::<_, i64>(0))
            .unwrap(),
        before
    );
    setup.server.clock.observe(&setup.db(), false).unwrap();
    assert_eq!(
        setup
            .db()
            .query_row("SELECT value FROM clock_hw", [], |r| r.get::<_, i64>(0))
            .unwrap(),
        before + 11,
        "rolled-back write poisoned persistence cache"
    );
}
#[tokio::test]
async fn tolerated_three_second_step_allows_refresh_and_code_exchange() {
    let setup = Setup::new();
    let pair = setup.pair();
    setup.clock.0.fetch_sub(3, Ordering::SeqCst);
    let refreshed = setup.server.refresh(&pair.refresh_token).await;
    assert!(refreshed.is_ok(), "tolerated clock step blocked refresh");
    let refreshed = refreshed.unwrap();
    assert!(setup.server.admit(&refreshed.access_token).is_ok());
    let code_pair = setup.pair();
    assert!(setup.server.admit(&code_pair.access_token).is_ok());
    assert_eq!(
        setup
            .db()
            .query_row(
                "SELECT COUNT(*) FROM oauth_families WHERE revoked_at IS NOT NULL",
                [],
                |r| r.get::<_, i64>(0)
            )
            .unwrap(),
        0
    );
}
#[test]
fn dispatcher_liveness_trigger_includes_exactly_600_seconds() {
    let setup = Setup::new();
    let pair = setup.pair();
    let id = setup.server.admit(&pair.access_token).unwrap().family;
    setup.clock.0.fetch_add(2999, Ordering::SeqCst);
    assert!(
        !setup.server.delivery_read_due(&id).unwrap(),
        "601 seconds triggered early read"
    );
    setup.clock.0.fetch_add(1, Ordering::SeqCst);
    assert!(
        setup.server.delivery_read_due(&id).unwrap(),
        "600 second boundary omitted"
    );
}
fn events(
    setup: &Setup,
) -> (
    crate::events::Events,
    Arc<crate::events_test_support::Callback>,
) {
    use std::collections::VecDeque;
    use std::sync::atomic::AtomicUsize;
    use std::sync::Mutex;
    let callback = Arc::new(crate::events_test_support::Callback {
        events: Mutex::new(vec![]),
        behaviors: Mutex::new(VecDeque::new()),
        secret: Mutex::new(crate::events_test_support::secret(4)),
        invalid: AtomicUsize::new(0),
    });
    let verifier = Arc::new(crate::auth::Verifier::local_only(
        setup.server.clone(),
        true,
    ));
    let key = crate::event_store::EventKey::load(&setup._files.path().join("events")).unwrap();
    (
        crate::events::Events::with_transport(
            setup.server.file.clone(),
            key,
            verifier,
            "local".into(),
            callback.clone(),
        ),
        callback,
    )
}
fn seed(setup: &Setup, id: &str) {
    let db = setup.db();
    db.execute("INSERT INTO custody_items(bus,upstream_id,event_id,grant_id,grant_revision,mailbox,owner,origin,text,envelope,fingerprint,received_at,expires_at,held) VALUES('bus',?1,?1,'local',2,'gateway@bus','owner','{\"service\":\"sender\",\"id\":null,\"node\":\"peer\"}','message','{}',?1,1,9999999999,1)",[id]).unwrap();
    db.execute("INSERT INTO event_authorizations(event_id,acceptance_enabled,acceptance_ever_enabled,acceptance_class,dispatch_revision) VALUES(?1,1,1,'current',2)",[id]).unwrap();
    db.execute("INSERT INTO event_occurrences(event_id) VALUES(?1)", [id])
        .unwrap();
    db.execute(
        "INSERT INTO custody_outbox(event_id,state) VALUES(?1,'pending')",
        [id],
    )
    .unwrap();
}
#[tokio::test]
async fn dead_family_never_follows_live_same_owner_family_without_explicit_renewal() {
    for failure in ["revoked", "idle", "absolute"] {
        let setup = Setup::new();
        let first = setup.pair();
        let (events, callback) = events(&setup);
        let verifier = crate::auth::Verifier::local_only(setup.server.clone(), true);
        let first_identity = verifier.verify(&first.access_token).await.unwrap();
        let family = first_identity.token_family().unwrap().to_owned();
        events
            .subscribe(
                &first_identity,
                &first.access_token,
                "bus",
                "gateway@bus",
                crate::events_test_support::request(),
            )
            .await
            .unwrap();
        assert!(setup
            .db()
            .query_row(
                "SELECT bearer IS NULL AND token_family=?1 FROM event_subscriptions",
                [&family],
                |r| r.get::<_, bool>(0)
            )
            .unwrap());
        seed(&setup, "pending-family");
        let second = setup.pair();
        let second_identity = verifier.verify(&second.access_token).await.unwrap();
        assert_ne!(second_identity.token_family(), Some(family.as_str()));
        match failure {
            "revoked" => setup.server.revoke(&first.access_token).unwrap(),
            "idle" => {
                setup
                    .db()
                    .execute(
                        "UPDATE oauth_families SET last_refresh_at=0 WHERE id=?1",
                        [&family],
                    )
                    .unwrap();
            }
            _ => {
                setup
                    .db()
                    .execute(
                        "UPDATE oauth_families SET absolute_expires_at=0 WHERE id=?1",
                        [&family],
                    )
                    .unwrap();
            }
        }
        assert_eq!(
            crate::event_dispatch::tick(&events, "bus", "gateway@bus")
                .await
                .unwrap(),
            crate::event_dispatch::Tick::Expired,
            "dead family silently followed another live family"
        );
        assert!(callback.events.lock().unwrap().is_empty());
        assert_eq!(
            setup
                .db()
                .query_row("SELECT state FROM custody_outbox", [], |r| r
                    .get::<_, String>(0))
                .unwrap(),
            "pending"
        );
        assert_eq!(
            setup
                .db()
                .query_row("SELECT token_family FROM event_subscriptions", [], |r| {
                    r.get::<_, String>(0)
                })
                .unwrap(),
            family
        );
        events
            .subscribe(
                &second_identity,
                &second.access_token,
                "bus",
                "gateway@bus",
                crate::events_test_support::request(),
            )
            .await
            .unwrap();
        assert_eq!(
            crate::event_dispatch::tick(&events, "bus", "gateway@bus")
                .await
                .unwrap(),
            crate::event_dispatch::Tick::Accepted,
            "explicit new-token renewal failed to recover delivery"
        );
        assert_eq!(callback.events.lock().unwrap().len(), 1);
    }
}
#[tokio::test]
async fn expired_access_still_wakes_through_bounded_family_liveness() {
    let setup = Setup::new();
    let pair = setup.pair();
    let (events, callback) = events(&setup);
    let verifier = crate::auth::Verifier::local_only(setup.server.clone(), true);
    let identity = verifier.verify(&pair.access_token).await.unwrap();
    let mut request = crate::events_test_support::request();
    request.ttl_ms = Some(crate::events::MAX_TTL_MS);
    events
        .subscribe(&identity, &pair.access_token, "bus", "gateway@bus", request)
        .await
        .unwrap();
    seed(&setup, "idle-wake");
    setup.clock.0.fetch_add(3601, Ordering::SeqCst);
    assert!(verifier.verify(&pair.access_token).await.is_err());
    assert_eq!(
        crate::event_dispatch::tick(&events, "bus", "gateway@bus")
            .await
            .unwrap(),
        crate::event_dispatch::Tick::Accepted
    );
    assert_eq!(callback.events.lock().unwrap().len(), 1);
    assert_eq!(setup.fake.requests.lock().unwrap().len(), 5);
    assert_eq!(
        setup
            .db()
            .query_row("SELECT last_error FROM custody_outbox", [], |r| r
                .get::<_, Option<String>>(0))
            .unwrap(),
        None
    );
}
#[tokio::test]
async fn family_liveness_runs_outside_operation_lease_and_rate_caps_attempts() {
    let setup = Setup::new();
    let pair = setup.pair();
    let (events, _) = events(&setup);
    let verifier = crate::auth::Verifier::local_only(setup.server.clone(), true);
    let identity = verifier.verify(&pair.access_token).await.unwrap();
    let family = identity.token_family().unwrap().to_owned();
    events
        .subscribe(
            &identity,
            &pair.access_token,
            "bus",
            "gateway@bus",
            crate::events_test_support::request(),
        )
        .await
        .unwrap();
    seed(&setup, "lease-wake");
    setup.clock.0.fetch_add(3000, Ordering::SeqCst);
    let store = setup.server.store().unwrap();
    let lease = store.try_operation_lease("gateway").unwrap().unwrap();
    assert_eq!(
        crate::event_dispatch::tick(&events, "bus", "gateway@bus")
            .await
            .unwrap(),
        crate::event_dispatch::Tick::Contended
    );
    assert_eq!(
        setup.fake.requests.lock().unwrap().len(),
        5,
        "held operation lease blocked liveness read"
    );
    assert!(
        setup.server.claim(&family, true).unwrap().is_none(),
        "dispatcher 300-second cap omitted"
    );
    setup.clock.0.fetch_add(300, Ordering::SeqCst);
    assert!(setup.server.claim(&family, true).unwrap().is_some());
    drop(lease);
}

fn owner_file(setup: &Setup) -> std::path::PathBuf {
    use std::os::unix::fs::PermissionsExt;
    let file = setup._files.path().join("owner.json");
    let value = json!({"bind":"127.0.0.1:0","grant_store":setup.server.file,"request_timeout_ms":60000,"allowed_hosts":["gateway.example"],"allowed_origins":["https://chat.example"],"verifier_profiles":[{"local":true,"opaque_default":true,"advertised":true,"service":"gateway","issuer":setup.server.binding.issuer,"resource":"https://gateway.example/mcp","subject":"owner","hosted_client":"dot","required_scopes":["identity:read","events:subscribe"]}],"authorization_server":serde_json::to_value(&setup.server.config).unwrap()});
    std::fs::write(&file, value.to_string()).unwrap();
    std::fs::set_permissions(&file, std::fs::Permissions::from_mode(0o600)).unwrap();
    file
}
async fn http_call(
    serving: &crate::serving::Serving,
    method: &str,
    uri: &str,
    auth: Option<&str>,
    body: &str,
) -> (
    axum::http::StatusCode,
    axum::http::HeaderMap,
    serde_json::Value,
) {
    use axum::{
        body::{to_bytes, Body},
        http::Request,
    };
    use tower::ServiceExt;
    let mut request = Request::builder()
        .method(method)
        .uri(uri)
        .header("host", "gateway.example")
        .header(
            "content-type",
            if uri == "/mcp" {
                "application/json"
            } else {
                "application/x-www-form-urlencoded"
            },
        );
    if let Some(auth) = auth {
        request = request.header("authorization", auth);
    }
    let response = serving
        .router()
        .oneshot(request.body(Body::from(body.to_owned())).unwrap())
        .await
        .unwrap();
    let status = response.status();
    let headers = response.headers().clone();
    let bytes = to_bytes(response.into_body(), 65536).await.unwrap();
    (
        status,
        headers,
        serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null),
    )
}
#[tokio::test]
async fn actual_listener_serves_as_metadata_host_guards_no_store_and_local_identity() {
    let setup = Setup::new();
    let pair = setup.pair();
    let serving = crate::serving::Serving::from_owner_file(&owner_file(&setup))
        .await
        .unwrap();
    let (status, headers, metadata) = http_call(
        &serving,
        "GET",
        "/.well-known/oauth-authorization-server",
        None,
        "",
    )
    .await;
    assert_eq!(status, 200);
    assert_eq!(headers["cache-control"], "no-store");
    assert_eq!(metadata["issuer"], "https://gateway.example");
    assert!(metadata
        .get("authorization_response_iss_parameter_supported")
        .is_none());
    let (status, _, prm) = http_call(
        &serving,
        "GET",
        "/.well-known/oauth-protected-resource",
        None,
        "",
    )
    .await;
    assert_eq!(status, 200);
    assert_eq!(
        prm["authorization_servers"],
        json!(["https://gateway.example"])
    );
    let (status, headers, error) = http_call(
        &serving,
        "POST",
        "/oauth/token",
        Some("Basic bad"),
        "grant_type=refresh_token&refresh_token=unknown",
    )
    .await;
    assert_eq!(status, 401);
    assert_eq!(error["error"], "invalid_client");
    assert_eq!(headers["cache-control"], "no-store");
    assert_eq!(headers["www-authenticate"], "Basic");
    let bearer = format!("Bearer {}", pair.access_token);
    let (status,_,identity)=http_call(&serving,"POST","/mcp",Some(&bearer),r#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"xmsg_identity","arguments":{}}}"#).await;
    assert_eq!(status, 200);
    assert_eq!(identity["result"]["structuredContent"]["subject"], "owner");
    use axum::{body::Body, http::Request};
    use tower::ServiceExt;
    let foreign = Request::builder()
        .uri("/.well-known/oauth-authorization-server")
        .header("host", "foreign.example")
        .body(Body::empty())
        .unwrap();
    assert_eq!(
        serving.router().oneshot(foreign).await.unwrap().status(),
        403
    );
    let origin = Request::builder()
        .uri("/.well-known/oauth-authorization-server")
        .header("host", "gateway.example")
        .header("origin", "https://foreign.example")
        .body(Body::empty())
        .unwrap();
    assert_eq!(
        serving.router().oneshot(origin).await.unwrap().status(),
        403
    );
}
#[tokio::test]
async fn actual_local_disabled_grant_is_403_then_reenable_does_not_revive_family() {
    let setup = Setup::new();
    let pair = setup.pair();
    let serving = crate::serving::Serving::from_owner_file(&owner_file(&setup))
        .await
        .unwrap();
    let mut store = setup.server.store().unwrap();
    store.set_enabled("local", 2, false).unwrap();
    let bearer = format!("Bearer {}", pair.access_token);
    let body = r#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"xmsg_identity","arguments":{}}}"#;
    assert_eq!(
        http_call(&serving, "POST", "/mcp", Some(&bearer), body)
            .await
            .0,
        403
    );
    store.set_enabled("local", 3, true).unwrap();
    assert_eq!(
        http_call(&serving, "POST", "/mcp", Some(&bearer), body)
            .await
            .0,
        401
    );
}
#[tokio::test]
async fn redirects_are_byte_exact_and_resource_mismatch_never_consumes_code() {
    let setup = Setup::new();
    let v = "v".repeat(43);
    let challenge =
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(Sha256::digest(v.as_bytes()));
    let valid = "https://chat.example/callback";
    for foreign in [
        "https://CHAT.example/callback",
        "https://chat.example:443/callback",
        "https://chat.example/%2Fcallback",
        "https://chat.example/other",
        "https://evil.example/callback",
    ] {
        let mut url = reqwest::Url::parse("https://form.invalid").unwrap();
        url.query_pairs_mut()
            .append_pair("client_id", "dot")
            .append_pair("redirect_uri", foreign)
            .append_pair("response_type", "code")
            .append_pair("resource", "https://gateway.example/mcp")
            .append_pair("code_challenge", &challenge)
            .append_pair("code_challenge_method", "S256");
        let reply = setup
            .server
            .handle("/oauth/authorize", "GET", url.query().unwrap(), None, "")
            .await;
        assert_eq!(reply.status, 400, "normalized or foreign redirect accepted");
        assert!(reply.location.is_none());
    }
    let code = setup
        .server
        .issue_code(
            &setup.server.local_authority().unwrap(),
            valid,
            &challenge,
            "identity:read events:subscribe",
            setup.clock.wall(),
        )
        .unwrap();
    for resource in [
        "https://gateway.example/other",
        "https://gateway.example/mcp#fragment",
    ] {
        assert!(setup
            .server
            .exchange(&code, valid, &v, Some(resource))
            .is_err());
        assert_eq!(
            setup
                .db()
                .query_row("SELECT used_at FROM oauth_codes", [], |r| r
                    .get::<_, Option<i64>>(0))
                .unwrap(),
            None
        );
    }
    assert!(setup
        .server
        .exchange(&code, valid, &v, Some("https://gateway.example/mcp"))
        .is_ok());
}
#[tokio::test]
async fn pending_eviction_rate_bucket_and_code_pkce_boundaries() {
    let mut setup = Setup::new();
    {
        let server = Arc::get_mut(&mut setup.server).unwrap();
        server.config.authorize_rate_per_min = 65;
    }
    let challenge = "a".repeat(43);
    let query=format!("client_id=dot&redirect_uri=https%3A%2F%2Fchat.example%2Fcallback&response_type=code&resource=https%3A%2F%2Fgateway.example%2Fmcp&code_challenge={challenge}&code_challenge_method=S256");
    let mut states = Vec::new();
    for _ in 0..65 {
        let reply = setup
            .server
            .handle("/oauth/authorize", "GET", &query, None, "")
            .await;
        assert_eq!(reply.status, 302);
        assert!(
            reply
                .location
                .as_deref()
                .is_some_and(|u| u.starts_with(setup.fake.origin.as_str())),
            "pending cap refused new login instead of evicting oldest"
        );
        states.push(
            reqwest::Url::parse(reply.location.as_ref().unwrap())
                .unwrap()
                .query_pairs()
                .find(|(k, _)| k == "state")
                .unwrap()
                .1
                .into_owned(),
        );
    }
    assert_eq!(
        setup
            .server
            .handle(
                "/oauth/callback",
                "GET",
                &format!("state={}&code=fake", states[0]),
                None,
                ""
            )
            .await
            .status,
        400
    );
    let last = setup
        .server
        .handle(
            "/oauth/callback",
            "GET",
            &format!("state={}&code=fake", states[64]),
            None,
            "",
        )
        .await;
    assert!(
        last.location
            .as_deref()
            .is_some_and(|l| l.contains("code=")),
        "65th authorize did not survive eviction"
    );
    let setup = Setup::new();
    for _ in 0..10 {
        assert_eq!(
            setup
                .server
                .handle("/oauth/authorize", "GET", &query, None, "")
                .await
                .status,
            302
        )
    }
    assert_eq!(
        setup
            .server
            .handle("/oauth/authorize", "GET", &query, None, "")
            .await
            .status,
        429
    );
}

fn authorize_query() -> String {
    format!("client_id=dot&redirect_uri=https%3A%2F%2Fchat.example%2Fcallback&response_type=code&resource=https%3A%2F%2Fgateway.example%2Fmcp&code_challenge={}&code_challenge_method=S256&state=fixture-state","a".repeat(43))
}
async fn begin(setup: &Setup) -> String {
    let reply = setup
        .server
        .handle("/oauth/authorize", "GET", &authorize_query(), None, "")
        .await;
    assert_eq!(reply.status, 302);
    reqwest::Url::parse(reply.location.as_ref().unwrap())
        .unwrap()
        .query_pairs()
        .find(|(k, _)| k == "state")
        .unwrap()
        .1
        .into_owned()
}
fn basic(setup: &Setup) -> String {
    format!(
        "Basic {}",
        base64::engine::general_purpose::STANDARD
            .encode(format!("dot:{}", setup.server.client_secret))
    )
}
#[tokio::test]
async fn exact_client_authentication_applies_to_token_and_revoke() {
    let setup = Setup::new();
    let pair = setup.pair();
    let wrong_secret = format!(
        "Basic {}",
        base64::engine::general_purpose::STANDARD.encode(format!("dot:{}", "b".repeat(43)))
    );
    let wrong_id = format!(
        "Basic {}",
        base64::engine::general_purpose::STANDARD
            .encode(format!("other:{}", setup.server.client_secret))
    );
    for route in ["/oauth/token", "/oauth/revoke"] {
        for header in [
            None,
            Some("Basic invalid"),
            Some(wrong_secret.as_str()),
            Some(wrong_id.as_str()),
        ] {
            let reply = setup
                .server
                .handle(
                    route,
                    "POST",
                    "",
                    header,
                    "grant_type=refresh_token&refresh_token=unknown&token=unknown",
                )
                .await;
            assert_eq!(reply.status, 401, "client authentication bypassed");
            assert!(reply.basic);
        }
    }
    assert!(setup.server.admit(&pair.access_token).is_ok());
    let reply = setup
        .server
        .handle(
            "/oauth/revoke",
            "POST",
            "",
            Some(&basic(&setup)),
            "token=unknown",
        )
        .await;
    assert_eq!(reply.status, 200);
    assert!(setup.server.admit(&pair.access_token).is_ok());
    let reply = setup
        .server
        .handle(
            "/oauth/revoke",
            "POST",
            "",
            Some(&basic(&setup)),
            &format!("token={}", pair.refresh_token),
        )
        .await;
    assert_eq!(reply.status, 200);
    assert!(setup.server.admit(&pair.access_token).is_err());
}
#[tokio::test]
async fn upstream_denials_and_unavailability_never_create_local_authority() {
    for (key, value) in [
        ("sub", json!("other")),
        ("active", json!(false)),
        ("client_id", json!("other")),
        ("aud", json!(["login", "extra"])),
        ("scope", json!("other")),
    ] {
        let setup = Setup::new();
        let state = begin(&setup).await;
        let mut claims = setup.fake.routes.lock().unwrap()["/introspect"].1.clone();
        claims[key] = value;
        setup.fake.set("/introspect", 200, claims);
        let reply = setup
            .server
            .handle(
                "/oauth/callback",
                "GET",
                &format!("state={state}&code=fake"),
                None,
                "",
            )
            .await;
        assert!(
            reply
                .location
                .as_deref()
                .is_some_and(|s| s.contains("error=access_denied")),
            "bad upstream binding authorized callback"
        );
        assert_eq!(
            setup
                .db()
                .query_row("SELECT COUNT(*) FROM oauth_codes", [], |r| r
                    .get::<_, i64>(0))
                .unwrap(),
            0
        );
        assert!(
            !setup
                .fake
                .requests
                .lock()
                .unwrap()
                .iter()
                .any(|u| u.contains("/v1/person/")),
            "bad upstream identity reached liveness"
        );
    }
    for failure in ["token", "introspection", "liveness-null", "liveness-denied"] {
        let setup = Setup::new();
        let state = begin(&setup).await;
        match failure {
            "token" => setup.fake.set("/token", 503, json!({})),
            "introspection" => setup.fake.set("/introspect", 503, json!({})),
            "liveness-null" => setup
                .fake
                .set("/v1/person/canary", 200, serde_json::Value::Null),
            _ => setup
                .fake
                .set("/v1/person/owner/_attr/memberof", 200, json!([])),
        }
        let reply = setup
            .server
            .handle(
                "/oauth/callback",
                "GET",
                &format!("state={state}&code=fake"),
                None,
                "",
            )
            .await;
        let expected = if failure == "liveness-denied" {
            "error=access_denied"
        } else {
            "error=temporarily_unavailable"
        };
        assert!(
            reply
                .location
                .as_deref()
                .is_some_and(|s| s.contains(expected)),
            "wrong callback failure class"
        );
        assert_eq!(
            setup
                .db()
                .query_row("SELECT COUNT(*) FROM oauth_codes", [], |r| r
                    .get::<_, i64>(0))
                .unwrap(),
            0
        );
    }
}
#[tokio::test]
async fn pending_state_is_single_use_revision_bound_and_lost_on_restart() {
    for scenario in ["revision", "expired", "restart", "state"] {
        let setup = Setup::new();
        let state = begin(&setup).await;
        let target = match scenario {
            "revision" => {
                let mut store = setup.server.store().unwrap();
                store.set_enabled("local", 2, false).unwrap();
                store.set_enabled("local", 3, true).unwrap();
                setup.server.clone()
            }
            "expired" => {
                setup.clock.0.fetch_add(601, Ordering::SeqCst);
                setup.server.clone()
            }
            "restart" => Server::from_config(
                serde_json::from_value(serde_json::to_value(&setup.server.config).unwrap())
                    .unwrap(),
                setup.server.file.clone(),
                setup.server.binding.clone(),
                setup.server.scopes.clone(),
                setup.clock.clone(),
            )
            .unwrap(),
            _ => setup.server.clone(),
        };
        let supplied = if scenario == "state" {
            "foreign-state"
        } else {
            state.as_str()
        };
        let reply = target
            .handle(
                "/oauth/callback",
                "GET",
                &format!("state={supplied}&code=fake"),
                None,
                "",
            )
            .await;
        assert!(
            reply
                .location
                .as_deref()
                .is_none_or(|s| !s.contains("code=")),
            "stale/foreign pending login minted a code"
        );
        assert_eq!(
            setup
                .db()
                .query_row("SELECT COUNT(*) FROM oauth_codes", [], |r| r
                    .get::<_, i64>(0))
                .unwrap(),
            0
        );
    }
    let setup = Setup::new();
    let state = begin(&setup).await;
    let input = format!("state={state}&code=fake");
    assert_eq!(
        setup
            .server
            .handle("/oauth/callback", "GET", &input, None, "")
            .await
            .status,
        302
    );
    assert_eq!(
        setup
            .server
            .handle("/oauth/callback", "GET", &input, None, "")
            .await
            .status,
        400
    );
}
#[test]
fn code_expiry_and_revision_fence_fail_without_consumption() {
    for revision in [false, true] {
        let setup = Setup::new();
        let verifier = "v".repeat(43);
        let challenge = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .encode(Sha256::digest(verifier.as_bytes()));
        let authority = setup.server.local_authority().unwrap();
        let code = setup
            .server
            .issue_code(
                &authority,
                "https://chat.example/callback",
                &challenge,
                "identity:read events:subscribe",
                setup.clock.wall(),
            )
            .unwrap();
        if revision {
            setup
                .server
                .store()
                .unwrap()
                .set_outbound_policy(
                    "local",
                    2,
                    &crate::outbound::Policy {
                        send: Some(crate::outbound::Permission {
                            targets: ["receiver@peer".into()].into(),
                            required_scope: "identity:read".into(),
                        }),
                        reply: None,
                    },
                )
                .unwrap();
        } else {
            setup.clock.0.fetch_add(60, Ordering::SeqCst);
        }
        assert!(setup
            .server
            .exchange(&code, "https://chat.example/callback", &verifier, None)
            .is_err());
        assert_eq!(
            setup
                .db()
                .query_row("SELECT used_at FROM oauth_codes", [], |r| r
                    .get::<_, Option<i64>>(0))
                .unwrap(),
            None
        );
    }
}
#[test]
fn concurrent_code_exchanges_mint_exactly_once_then_replay_revokes() {
    let setup = Setup::new();
    let verifier = "v".repeat(43);
    let challenge = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .encode(Sha256::digest(verifier.as_bytes()));
    let code = setup
        .server
        .issue_code(
            &setup.server.local_authority().unwrap(),
            "https://chat.example/callback",
            &challenge,
            "identity:read events:subscribe",
            setup.clock.wall(),
        )
        .unwrap();
    let mut workers = Vec::new();
    for _ in 0..8 {
        let server = setup.server.clone();
        let code = code.clone();
        let verifier = verifier.clone();
        workers.push(std::thread::spawn(move || {
            server
                .exchange(&code, "https://chat.example/callback", &verifier, None)
                .is_ok()
        }));
    }
    assert_eq!(
        workers
            .into_iter()
            .map(|w| w.join().unwrap())
            .filter(|success| *success)
            .count(),
        1
    );
    assert_eq!(
        setup
            .db()
            .query_row("SELECT COUNT(*) FROM oauth_families", [], |r| r
                .get::<_, i64>(0))
            .unwrap(),
        1
    );
    assert_eq!(
        setup
            .db()
            .query_row("SELECT revoked_reason FROM oauth_families", [], |r| r
                .get::<_, String>(0))
            .unwrap(),
        "code_replay"
    );
}
#[test]
fn atomic_admission_holds_snapshot_until_mark_and_admits_no_post_change_snapshot() {
    use std::sync::Mutex;
    for change in ["revoke", "disable", "expiry"] {
        let setup = Setup::new();
        let pair = setup.pair();
        let before = setup.clock.wall();
        if change == "expiry" {
            setup
                .db()
                .execute(
                    "UPDATE oauth_families SET absolute_expires_at=?1",
                    [before + 10],
                )
                .unwrap();
        }
        let (entered_tx, entered_rx) = std::sync::mpsc::sync_channel(0);
        let (release_tx, release_rx) = std::sync::mpsc::sync_channel(0);
        let release = Mutex::new(release_rx);
        let server = setup.server.clone();
        let token = pair.access_token.clone();
        *setup.server.admission_barrier.lock().unwrap() = Some(Arc::new(move |_| {
            entered_tx.send(()).unwrap();
            release
                .lock()
                .unwrap()
                .recv_timeout(std::time::Duration::from_secs(5))
                .unwrap();
        }));
        let worker = std::thread::spawn(move || server.admit(&token));
        if entered_rx
            .recv_timeout(std::time::Duration::from_secs(5))
            .is_err()
        {
            panic!(
                "{change}: admission finished before barrier: {:?}",
                worker.join().unwrap().err()
            );
        }
        let db = setup.db();
        db.busy_timeout(std::time::Duration::ZERO).unwrap();
        if change == "expiry" {
            setup.clock.0.store(before + 11, Ordering::SeqCst);
        } else {
            let result = db.execute(
                if change == "revoke" {
                    "UPDATE oauth_families SET revoked_at=1,revoked_reason='revocation_endpoint'"
                } else {
                    "UPDATE grants SET enabled=0,revision=revision+1"
                },
                [],
            );
            assert!(
                matches!(result,Err(rusqlite::Error::SqliteFailure(code,_)) if matches!(code.code,rusqlite::ErrorCode::DatabaseBusy|rusqlite::ErrorCode::DatabaseLocked)),
                "first-use check/mark split permitted competing commit"
            );
        }
        release_tx.send(()).unwrap();
        assert!(
            worker.join().unwrap().is_ok(),
            "pre-change snapshot did not complete its admission"
        );
        *setup.server.admission_barrier.lock().unwrap() = None;
        if change == "revoke" {
            setup.server.revoke(&pair.access_token).unwrap();
        } else if change == "disable" {
            setup
                .server
                .store()
                .unwrap()
                .set_enabled("local", 2, false)
                .unwrap();
        }
        assert!(
            setup.server.admit(&pair.access_token).is_err(),
            "post-change snapshot admitted stale authority"
        );
    }
}
#[test]
fn form_decoding_keeps_fragment_bytes_and_rejects_malformed_or_duplicate_values() {
    // Exercise the public endpoint parser with a body which must not be treated as a URL fragment.
    let setup = Setup::new();
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    for query in [
        authorize_query().replace("&resource=https%3A%2F%2Fgateway.example%2Fmcp", "")
            + "&resource=https%3A%2F%2Fgateway.example%2Fmcp#ignored",
        authorize_query() + "&client_id=dot",
        authorize_query().replace("client_id=dot", "client_id=%ff"),
        authorize_query().replace("client_id=dot", "client_id=%"),
    ] {
        let reply = rt.block_on(
            setup
                .server
                .handle("/oauth/authorize", "GET", &query, None, ""),
        );
        assert!(
            reply
                .location
                .as_deref()
                .is_none_or(|s| s.contains("error=")),
            "malformed query was accepted"
        );
    }
}

#[test]
fn clock_fence_never_holds_memory_lock_across_sqlite_wait() {
    use std::sync::Mutex;
    let setup = Setup::new();
    setup.pair();
    setup.clock.0.fetch_add(11, Ordering::SeqCst);
    let mut store = setup.server.store().unwrap();
    let transaction = store
        .connection
        .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)
        .unwrap();
    let (entered_tx, entered_rx) = std::sync::mpsc::sync_channel(0);
    let (resume_tx, resume_rx) = std::sync::mpsc::sync_channel(0);
    let resume = Mutex::new(resume_rx);
    let server = setup.server.clone();
    let worker = std::thread::spawn(move || {
        let store = server.store().unwrap();
        server.clock.set_hook(
            false,
            Arc::new(move || {
                entered_tx.send(()).unwrap();
                resume
                    .lock()
                    .unwrap()
                    .recv_timeout(std::time::Duration::from_secs(5))
                    .unwrap();
            }),
        );
        server.clock.observe(&store.connection, false)
    });
    entered_rx
        .recv_timeout(std::time::Duration::from_secs(5))
        .unwrap();
    let available = setup.server.clock.memory_available();
    resume_tx.send(()).unwrap();
    drop(transaction);
    worker.join().unwrap().unwrap();
    assert!(available, "clock memory mutex was held across SQLite I/O");
}
#[test]
fn delayed_sqlite_observer_samples_fresh_wall_after_shared_high_water_advances() {
    use std::sync::Mutex;
    let setup = Setup::new();
    let pair = setup.pair();
    let at = setup.clock.wall();
    let (entered_tx, entered_rx) = std::sync::mpsc::sync_channel(0);
    let (resume_tx, resume_rx) = std::sync::mpsc::sync_channel(0);
    let resume = Mutex::new(resume_rx);
    let server = setup.server.clone();
    let worker = std::thread::spawn(move || {
        let store = server.store().unwrap();
        server.clock.set_hook(
            true,
            Arc::new(move || {
                entered_tx.send(()).unwrap();
                resume
                    .lock()
                    .unwrap()
                    .recv_timeout(std::time::Duration::from_secs(5))
                    .unwrap();
            }),
        );
        server.clock.observe(&store.connection, false)
    });
    entered_rx
        .recv_timeout(std::time::Duration::from_secs(5))
        .unwrap();
    setup.clock.0.store(at + 11, Ordering::SeqCst);
    setup.server.clock.observe(&setup.db(), true).unwrap();
    resume_tx.send(()).unwrap();
    worker.join().unwrap().unwrap();
    assert!(
        setup.server.admit(&pair.access_token).is_ok(),
        "delayed healthy observation falsely revoked family"
    );
}

#[derive(Clone, Default)]
struct SecretCapture(Arc<std::sync::Mutex<Vec<u8>>>);
impl std::io::Write for SecretCapture {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(bytes);
        Ok(bytes.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}
impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for SecretCapture {
    type Writer = Self;
    fn make_writer(&'a self) -> Self::Writer {
        self.clone()
    }
}
fn sqlite_text_and_blobs(db: &rusqlite::Connection) -> Vec<u8> {
    let tables = db
        .prepare("SELECT name FROM sqlite_master WHERE type='table'")
        .unwrap()
        .query_map([], |r| r.get::<_, String>(0))
        .unwrap()
        .collect::<Result<Vec<_>, _>>()
        .unwrap();
    let mut bytes = Vec::new();
    for table in tables {
        let sql = format!("SELECT * FROM \"{}\"", table.replace('"', "\"\""));
        let mut statement = db.prepare(&sql).unwrap();
        let columns = statement.column_count();
        let mut rows = statement.query([]).unwrap();
        while let Some(row) = rows.next().unwrap() {
            for column in 0..columns {
                match row.get_ref(column).unwrap() {
                    rusqlite::types::ValueRef::Text(value)
                    | rusqlite::types::ValueRef::Blob(value) => {
                        bytes.extend_from_slice(value);
                        bytes.push(0)
                    }
                    _ => {}
                }
            }
        }
    }
    bytes
}
fn bytes_contain(bytes: &[u8], value: &str) -> bool {
    !value.is_empty() && bytes.windows(value.len()).any(|w| w == value.as_bytes())
}
#[tokio::test]
async fn authorization_flow_secret_census_covers_trace_sql_values_and_sqlite_file_bytes() {
    use tracing::instrument::WithSubscriber;
    let setup = Setup::new();
    let db = setup.db();
    db.execute_batch("PRAGMA journal_mode=WAL; PRAGMA wal_autocheckpoint=0;")
        .unwrap();
    let serving = crate::serving::Serving::from_owner_file(&owner_file(&setup))
        .await
        .unwrap();
    let capture = SecretCapture::default();
    let subscriber = tracing_subscriber::fmt()
        .with_target(true)
        .with_ansi(false)
        .without_time()
        .with_max_level(tracing::Level::TRACE)
        .with_writer(capture.clone())
        .finish();
    let log_marker = random("log-control-").unwrap();
    let sql_marker = random("sql-control-").unwrap();
    let blob_marker = random("blob-control-").unwrap();
    let raw_marker = random("raw-control-").unwrap();
    let mut sensitive = vec![
        setup.server.client_secret.clone(),
        "fixture-access".into(),
        "fixture-id".into(),
        "fixture-refresh".into(),
        "fixture-reader".into(),
        crate::events_test_support::secret(4),
    ];
    let flow = async {
        tracing::callsite::rebuild_interest_cache();
        tracing::trace!(target:"gateway_oauth_census",marker=log_marker.as_str(),"positive control");
        let (status, _, _) = http_call(
            &serving,
            "POST",
            "/oauth/token",
            Some("Basic ZmFrZTpmYWtl"),
            "grant_type=refresh_token",
        )
        .await;
        assert_eq!(status, 401);
        let (status, _, _) = http_call(
            &serving,
            "POST",
            "/mcp",
            Some("Bearer xgw_at_unknown"),
            "{}",
        )
        .await;
        assert_eq!(status, 401);

        let verifier = random("").unwrap();
        sensitive.push(verifier.clone());
        let challenge = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .encode(Sha256::digest(verifier.as_bytes()));
        let client_state = random("client-state-").unwrap();
        sensitive.push(client_state.clone());
        let mut query = reqwest::Url::parse("https://form.invalid").unwrap();
        query
            .query_pairs_mut()
            .append_pair("client_id", "dot")
            .append_pair("redirect_uri", "https://chat.example/callback")
            .append_pair("response_type", "code")
            .append_pair("resource", "https://gateway.example/mcp")
            .append_pair("code_challenge", &challenge)
            .append_pair("code_challenge_method", "S256")
            .append_pair("state", &client_state);
        let (status, headers, _) = http_call(
            &serving,
            "GET",
            &format!("/oauth/authorize?{}", query.query().unwrap()),
            None,
            "",
        )
        .await;
        assert_eq!(status, 302);
        let upstream = reqwest::Url::parse(headers["location"].to_str().unwrap()).unwrap();
        let kstate = upstream
            .query_pairs()
            .find(|(k, _)| k == "state")
            .unwrap()
            .1
            .into_owned();
        sensitive.push(kstate.clone());
        let kanidm_code = random("kanidm-code-").unwrap();
        sensitive.push(kanidm_code.clone());
        let (status, headers, _) = http_call(
            &serving,
            "GET",
            &format!("/oauth/callback?state={kstate}&code={kanidm_code}"),
            None,
            "",
        )
        .await;
        assert_eq!(status, 302);
        let downstream = reqwest::Url::parse(headers["location"].to_str().unwrap()).unwrap();
        let code = downstream
            .query_pairs()
            .find(|(k, _)| k == "code")
            .unwrap()
            .1
            .into_owned();
        sensitive.push(code.clone());
        let authorization = basic(&setup);
        sensitive.push(authorization.clone());
        sensitive.push(authorization.split_once(' ').unwrap().1.to_owned());
        let lookup =
            super::private_text(&setup.server.config.upstream.verify.client_secret_file).unwrap();
        sensitive.push(lookup.clone());
        sensitive.push(format!(
            "Basic {}",
            base64::engine::general_purpose::STANDARD.encode(format!(
                "{}:{lookup}",
                setup.server.config.upstream.verify.introspection_client
            ))
        ));

        let body=format!("grant_type=authorization_code&code={code}&redirect_uri=https%3A%2F%2Fchat.example%2Fcallback&code_verifier={verifier}");
        let (status, _, first) = http_call(
            &serving,
            "POST",
            "/oauth/token",
            Some(&authorization),
            &body,
        )
        .await;
        assert_eq!(status, 200);
        let a = first["refresh_token"].as_str().unwrap().to_owned();
        sensitive.push(a.clone());
        sensitive.push(first["access_token"].as_str().unwrap().into());
        let body = format!("grant_type=refresh_token&refresh_token={a}");
        let (status, _, second) = http_call(
            &serving,
            "POST",
            "/oauth/token",
            Some(&authorization),
            &body,
        )
        .await;
        assert_eq!(status, 200);
        sensitive.push(second["refresh_token"].as_str().unwrap().into());
        sensitive.push(second["access_token"].as_str().unwrap().into());
        let (status, _, third) = http_call(
            &serving,
            "POST",
            "/oauth/token",
            Some(&authorization),
            &body,
        )
        .await;
        assert_eq!(status, 200);
        sensitive.push(third["refresh_token"].as_str().unwrap().into());
        sensitive.push(third["access_token"].as_str().unwrap().into());
        let (events, callback) = events(&setup);
        let local = crate::auth::Verifier::local_only(setup.server.clone(), true);
        let identity = local
            .verify(third["access_token"].as_str().unwrap())
            .await
            .unwrap();
        events
            .subscribe(
                &identity,
                third["access_token"].as_str().unwrap(),
                "bus",
                "gateway@bus",
                crate::events_test_support::request(),
            )
            .await
            .unwrap();
        seed(&setup, "secret-census-delivery");
        assert_eq!(
            crate::event_dispatch::tick(&events, "bus", "gateway@bus")
                .await
                .unwrap(),
            crate::event_dispatch::Tick::Accepted
        );
        assert_eq!(callback.events.lock().unwrap().len(), 1);
        let (status, _, _) = http_call(
            &serving,
            "POST",
            "/oauth/token",
            Some(&authorization),
            &format!(
                "grant_type=refresh_token&refresh_token={}",
                second["refresh_token"].as_str().unwrap()
            ),
        )
        .await;
        assert_eq!(status, 400);
        let (status, _, _) = http_call(
            &serving,
            "POST",
            "/oauth/revoke",
            Some(&authorization),
            &format!("token={}", third["refresh_token"].as_str().unwrap()),
        )
        .await;
        assert_eq!(status, 200);
    };
    flow.with_subscriber(subscriber).await;
    for form in setup.fake.forms.lock().unwrap().iter() {
        let mut url = reqwest::Url::parse("https://form.invalid").unwrap();
        url.set_query(Some(form));
        if let Some(verifier) = url.query_pairs().find(|(k, _)| k == "code_verifier") {
            sensitive.push(verifier.1.into_owned());
        }
    }
    assert_eq!(
        setup.fake.forms.lock().unwrap().len(),
        1,
        "upstream token exchange form capture missing"
    );
    assert!(
        setup.fake.forms.lock().unwrap()[0].contains("code_verifier="),
        "upstream PKCE verifier was not captured by fixture"
    );
    db.execute_batch("CREATE TABLE census_fixture(text_value TEXT,blob_value BLOB);")
        .unwrap();
    db.execute(
        "INSERT INTO census_fixture VALUES(?1,?2)",
        rusqlite::params![sql_marker, blob_marker.as_bytes()],
    )
    .unwrap();
    db.execute(
        "INSERT INTO census_fixture(text_value) VALUES(?1)",
        [&raw_marker],
    )
    .unwrap();
    db.execute(
        "DELETE FROM census_fixture WHERE text_value=?1",
        [&raw_marker],
    )
    .unwrap();
    for value in sensitive.clone() {
        let mut encoded = reqwest::Url::parse("https://form.invalid").unwrap();
        encoded.query_pairs_mut().append_pair("v", &value);
        sensitive.push(encoded.query().unwrap()[2..].to_owned());
    }
    let logs = capture.0.lock().unwrap().clone();
    assert!(
        bytes_contain(&logs, &log_marker),
        "TRACE positive control missing"
    );
    assert!(
        bytes_contain(&logs, "/oauth/callback"),
        "HTTP path control missing"
    );
    for class in ["invalid_client", "invalid_token"] {
        assert!(
            String::from_utf8_lossy(&logs)
                .lines()
                .any(|line| line.contains("gateway_oauth_authentication") && line.contains(class)),
            "authentication class observation missing: {class}"
        );
    }
    for class in ["rotate", "retry", "reuse"] {
        assert!(
            String::from_utf8_lossy(&logs)
                .lines()
                .any(|line| line.contains("gateway_oauth_refresh") && line.contains(class)),
            "postcommit refresh class observation missing: {class}; target lines={}",
            String::from_utf8_lossy(&logs)
                .lines()
                .filter(|line| line.contains("gateway_oauth_refresh"))
                .count()
        );
    }
    let values = sqlite_text_and_blobs(&db);
    assert!(
        bytes_contain(&values, &sql_marker),
        "live SQL TEXT control missing"
    );
    assert!(
        bytes_contain(&values, &blob_marker),
        "live SQL BLOB control missing"
    );
    let mut files = Vec::new();
    for suffix in ["", "-journal", "-wal"] {
        let file = std::path::PathBuf::from(format!("{}{suffix}", setup.server.file.display()));
        if file.exists() {
            files.extend_from_slice(&std::fs::read(file).unwrap());
        }
    }
    assert!(
        std::path::PathBuf::from(format!("{}-wal", setup.server.file.display())).exists(),
        "WAL census control missing"
    );
    assert!(
        bytes_contain(&files, &raw_marker),
        "deleted raw-file marker missing"
    );
    for secret in &sensitive {
        assert!(
            !bytes_contain(&logs, secret),
            "secret appeared in TRACE capture"
        );
        assert!(
            !bytes_contain(&values, secret),
            "secret appeared in SQL value census"
        );
        assert!(
            !bytes_contain(&files, secret),
            "secret appeared in SQLite file bytes"
        );
    }
}

fn data_census(db: &rusqlite::Connection) -> Vec<u8> {
    sqlite_text_and_blobs(db)
}
#[tokio::test]
async fn custody_read_and_ack_recheck_effect_authority_without_partial_state() {
    let setup = Setup::new();
    let pair = setup.pair();
    let verifier = crate::auth::Verifier::local_only(setup.server.clone(), true);
    let identity = verifier.verify(&pair.access_token).await.unwrap();
    seed(&setup, "custody-fence");
    let read = || {
        crate::reads::Request::Read(crate::reads::ReadArguments {
            message_id: "custody-fence".into(),
            offset: None,
            limit: None,
        })
    };
    assert_eq!(
        crate::reads::dispatch(
            setup.server.store().unwrap(),
            &identity,
            "bus",
            "gateway@bus",
            read()
        )
        .unwrap()["text"],
        "message"
    );
    seed(&setup, "ack-positive-control");
    let positive_key =
        crate::event_store::EventKey::load(&setup._files.path().join("events")).unwrap();
    let observed = crate::recovery::dispatch(
        setup.server.store().unwrap(),
        &identity,
        "bus",
        "gateway@bus",
        "local",
        &positive_key,
        crate::recovery::Request::Ack(crate::recovery::AckArguments {
            message_id: "ack-positive-control".into(),
        }),
        &limits(),
    )
    .unwrap();
    assert_eq!(
        observed["state"], "observed",
        "ordinary local ACK positive control failed"
    );
    assert_eq!(
        setup
            .db()
            .query_row(
                "SELECT COUNT(*) FROM event_observations WHERE event_id='ack-positive-control'",
                [],
                |r| r.get::<_, i64>(0)
            )
            .unwrap(),
        1
    );
    setup
        .server
        .store()
        .unwrap()
        .set_enabled("local", 2, false)
        .unwrap();
    let before = data_census(&setup.db());
    assert!(
        matches!(
            crate::reads::dispatch(
                setup.server.store().unwrap(),
                &identity,
                "bus",
                "gateway@bus",
                read()
            ),
            Err(crate::reads::Error::Authority(crate::grants::Error::Denied))
        ),
        "admitted custody read ignored effect-point revoke"
    );
    let key = crate::event_store::EventKey::load(&setup._files.path().join("events")).unwrap();
    assert!(
        matches!(
            crate::recovery::dispatch(
                setup.server.store().unwrap(),
                &identity,
                "bus",
                "gateway@bus",
                "local",
                &key,
                crate::recovery::Request::Ack(crate::recovery::AckArguments {
                    message_id: "custody-fence".into()
                }),
                &limits()
            ),
            Err(crate::recovery::Error::Authority(
                crate::grants::Error::Denied
            ))
        ),
        "admitted custody ACK ignored effect-point revoke"
    );
    assert_eq!(
        data_census(&setup.db()),
        before,
        "refused custody operation partially changed state"
    );
}
#[tokio::test]
async fn current_enabled_grant_cannot_read_or_ack_fenced_prior_revision() {
    let setup = Setup::new();
    seed(&setup, "fenced-prior");
    let mut store = setup.server.store().unwrap();
    store.set_enabled("local", 2, false).unwrap();
    store.set_enabled("local", 3, true).unwrap();
    let pair = setup.pair();
    let verifier = crate::auth::Verifier::local_only(setup.server.clone(), true);
    let identity = verifier.verify(&pair.access_token).await.unwrap();
    let read = crate::reads::dispatch(
        setup.server.store().unwrap(),
        &identity,
        "bus",
        "gateway@bus",
        crate::reads::Request::Read(crate::reads::ReadArguments {
            message_id: "fenced-prior".into(),
            offset: None,
            limit: None,
        }),
    )
    .unwrap();
    assert_eq!(
        read["state"], "not_found",
        "current grant revived old fenced custody"
    );
    let key = crate::event_store::EventKey::load(&setup._files.path().join("events")).unwrap();
    let ack = crate::recovery::dispatch(
        setup.server.store().unwrap(),
        &identity,
        "bus",
        "gateway@bus",
        "local",
        &key,
        crate::recovery::Request::Ack(crate::recovery::AckArguments {
            message_id: "fenced-prior".into(),
        }),
        &limits(),
    )
    .unwrap();
    assert_eq!(ack["state"], "not_found", "ACK revived old fenced custody");
    assert_eq!(
        setup
            .db()
            .query_row("SELECT COUNT(*) FROM event_observations", [], |r| r
                .get::<_, i64>(0))
            .unwrap(),
        0
    );
}
struct RevokeChallenge {
    server: Arc<Server>,
    access: String,
    revoke: std::sync::atomic::AtomicBool,
    callback: Arc<crate::events_test_support::Callback>,
}
impl crate::webhook::Transport for RevokeChallenge {
    fn post<'a>(
        &'a self,
        url: &'a str,
        headers: reqwest::header::HeaderMap,
        body: Vec<u8>,
    ) -> crate::webhook::PostFuture<'a> {
        Box::pin(async move {
            let challenge = serde_json::from_slice::<serde_json::Value>(&body)
                .is_ok_and(|v| v["type"] == "verification");
            let reply = self.callback.post(url, headers, body).await?;
            if challenge && self.revoke.load(Ordering::SeqCst) {
                self.server.revoke(&self.access).unwrap();
            }
            Ok(reply)
        })
    }
}
#[tokio::test]
async fn subscribe_and_renew_keep_fresh_revalidation_and_verify_then_write() {
    for renewal in [false, true] {
        let setup = Setup::new();
        let pair = setup.pair();
        let (ordinary, callback) = events(&setup);
        let verifier = Arc::new(crate::auth::Verifier::local_only(
            setup.server.clone(),
            true,
        ));
        let identity = verifier.verify(&pair.access_token).await.unwrap();
        let transport = Arc::new(RevokeChallenge {
            server: setup.server.clone(),
            access: pair.access_token.clone(),
            revoke: std::sync::atomic::AtomicBool::new(false),
            callback,
        });
        let events = crate::events::Events::with_transport(
            setup.server.file.clone(),
            ordinary.key.clone(),
            verifier,
            "local".into(),
            transport.clone(),
        );
        if renewal {
            events
                .subscribe(
                    &identity,
                    &pair.access_token,
                    "bus",
                    "gateway@bus",
                    crate::events_test_support::request(),
                )
                .await
                .unwrap();
            setup
                .db()
                .execute("UPDATE event_subscriptions SET verified_at=0", [])
                .unwrap();
        }
        let before = subscription_census(&setup.db());
        transport.revoke.store(true, Ordering::SeqCst);
        assert!(
            events
                .subscribe(
                    &identity,
                    &pair.access_token,
                    "bus",
                    "gateway@bus",
                    crate::events_test_support::request()
                )
                .await
                .is_err(),
            "revoked token bypassed subscription fresh check"
        );
        assert_eq!(
            subscription_census(&setup.db()),
            before,
            "failed verification changed subscription row"
        );
        assert_eq!(
            setup
                .db()
                .query_row("SELECT COUNT(*) FROM event_subscriptions", [], |r| r
                    .get::<_, i64>(0))
                .unwrap(),
            i64::from(renewal)
        );
    }
}
fn subscription_census(db: &rusqlite::Connection) -> Vec<String> {
    let mut statement = db
        .prepare("SELECT * FROM event_subscriptions ORDER BY rowid")
        .unwrap();
    let columns = statement.column_count();
    let mut rows = statement.query([]).unwrap();
    let mut values = Vec::new();
    while let Some(row) = rows.next().unwrap() {
        for column in 0..columns {
            values.push(format!("{:?}", row.get_ref(column).unwrap()));
        }
    }
    values
}
fn limits() -> crate::outbound::Limits {
    crate::outbound::Limits {
        dedup_lifetime_secs: 86400,
        result_recovery_secs: 86400,
        max_framed_bytes: 65536,
        timeout: std::time::Duration::from_secs(5),
        max_reservations: 1000,
        max_retained_bytes: 64 * 1024 * 1024,
    }
}

type AttachmentReadHook = Arc<std::sync::Mutex<Option<Box<dyn FnOnce() + Send>>>>;

struct Bus {
    _directory: tempfile::TempDir,
    registered: xmsg::client::RegisteredService,
    frames: Arc<std::sync::Mutex<Vec<serde_json::Value>>>,
    pending: Arc<std::sync::Mutex<std::collections::VecDeque<serde_json::Value>>>,
    acked: Arc<std::sync::atomic::AtomicUsize>,
    stop: tokio::sync::oneshot::Sender<()>,
    on_attachment_read: AttachmentReadHook,
    register_task: tokio::task::JoinHandle<()>,
    agent_task: tokio::task::JoinHandle<()>,
}
impl Bus {
    async fn new() -> Self {
        use std::os::unix::fs::PermissionsExt;
        use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
        let directory = tempfile::tempdir().unwrap();
        std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        let config = crate::xmsg_config::XmsgConfig {
            service: "gateway".into(),
            expected_node: "bus".into(),
            daemon_uid: xmsg::client::current_uid(),
            register_socket: directory.path().join("register.sock"),
            agent_socket: directory.path().join("agent.sock"),
            max_frame_bytes: 65536,
            operation_timeout_ms: 2000,
        };
        let register = tokio::net::UnixListener::bind(&config.register_socket).unwrap();
        let agent = tokio::net::UnixListener::bind(&config.agent_socket).unwrap();
        for socket in [&config.register_socket, &config.agent_socket] {
            std::fs::set_permissions(socket, std::fs::Permissions::from_mode(0o600)).unwrap();
        }
        let pending = Arc::new(std::sync::Mutex::new(std::collections::VecDeque::<
            serde_json::Value,
        >::new()));
        let polled = pending.clone();
        let acked = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let upstream_acked = acked.clone();
        let register_task = tokio::spawn(async move {
            let mut stream = BufReader::new(register.accept().await.unwrap().0);
            let mut line = String::new();
            stream.read_line(&mut line).await.unwrap();
            assert_eq!(
                serde_json::from_str::<serde_json::Value>(&line).unwrap()["name"],
                "gateway"
            );
            stream
                .get_mut()
                .write_all(b"{\"status\":\"ok\",\"node\":\"bus\",\"address\":\"gateway@bus\",\"reply_ttl_secs\":604800,\"idempotency_ttl_secs\":604800,\"svc_queue_cap\":1000,\"max_body_bytes\":65536,\"max_attachment_bytes\":8388608}\n")
                .await
                .unwrap();
            loop {
                line.clear();
                if stream.read_line(&mut line).await.unwrap() == 0 {
                    break;
                }
                let frame: serde_json::Value = serde_json::from_str(&line).unwrap();
                let reply = match frame["action"].as_str().unwrap() {
                    "poll" => polled
                        .lock()
                        .unwrap()
                        .front()
                        .cloned()
                        .unwrap_or(json!({"action":"timeout"})),
                    "ack" => {
                        upstream_acked.fetch_add(1, Ordering::SeqCst);
                        polled.lock().unwrap().pop_front();
                        json!({"status":"ok"})
                    }
                    _ => panic!("unexpected service control"),
                };
                stream
                    .get_mut()
                    .write_all(format!("{reply}\n").as_bytes())
                    .await
                    .unwrap();
            }
        });
        let registered = config.register().await.unwrap();
        let frames = Arc::new(std::sync::Mutex::new(Vec::new()));
        let record = frames.clone();
        let on_attachment_read: AttachmentReadHook = Arc::new(std::sync::Mutex::new(None));
        let read_hook = on_attachment_read.clone();
        let (stop, mut done) = tokio::sync::oneshot::channel();
        let agent_task = tokio::spawn(async move {
            loop {
                tokio::select! {_=&mut done=>break,accepted=agent.accept()=>{
                    let mut stream=BufReader::new(accepted.unwrap().0);let mut line=String::new();stream.read_line(&mut line).await.unwrap();let request:serde_json::Value=serde_json::from_str(&line).unwrap();record.lock().unwrap().push(request.clone());
                    let response=match request["action"].as_str().unwrap(){
                        "list"=>json!({"status":"ok","nodes":[{"node":"peer","status":"ok"}],"recipients":[{"address":"receiver@peer","node":"peer","kind":"service","harness":"svc","status":"live","user":"fixture"},{"address":"sender@peer","node":"peer","kind":"service","harness":"svc","status":"live","user":"fixture"}]}),
                        "send"=>json!({"status":"ok","message_id":"01ARZ3NDEKTSV4RRFFQ69G5FAV","address":request["to"],"outcome":"delivered"}),
                        "read_attachment"=>{
                            let hook=read_hook.lock().unwrap().take();if let Some(hook)=hook {hook();}
                            json!({"status":"ok","attachment":{"name":"file.txt","size":4,"media_type":"text/plain","sha256":format!("{:x}",Sha256::digest(b"file"))},"offset":0,"length":4,"next":null,"encoding":"utf-8","data":"file"})
                        },
                        "reply"=>json!({"status":"ok","reply":{"seq":1,"messageId":request["message_id"],"createdAt":1,"replierSessionId":"gateway@bus","text":request["text"],"pushOutcome":"delivered"}}),
                        _=>panic!("unexpected local bus action"),
                    };
                    stream.get_mut().write_all(format!("{response}\n").as_bytes()).await.unwrap();
                }}
            }
        });
        Self {
            _directory: directory,
            registered,
            frames,
            on_attachment_read,
            pending,
            acked,
            stop,
            register_task,
            agent_task,
        }
    }
    fn endpoint(&self) -> crate::outbound::Endpoint {
        crate::outbound::Endpoint::from_registered(&self.registered).unwrap()
    }
    async fn close(self) {
        let Self {
            registered,
            stop,
            register_task,
            agent_task,
            ..
        } = self;
        drop(registered);
        let _ = stop.send(());
        tokio::time::timeout(std::time::Duration::from_secs(3), register_task)
            .await
            .unwrap()
            .unwrap();
        tokio::time::timeout(std::time::Duration::from_secs(3), agent_task)
            .await
            .unwrap()
            .unwrap();
    }
}
fn send_policy(target: &str) -> crate::outbound::Policy {
    crate::outbound::Policy {
        send: Some(crate::outbound::Permission {
            targets: [target.into()].into(),
            required_scope: "identity:read".into(),
        }),
        reply: None,
    }
}
#[tokio::test]
async fn admitted_send_uses_its_policy_snapshot_after_policy_changes() {
    let setup = Setup::new();
    let mut store = setup.server.store().unwrap();
    store
        .set_outbound_policy("local", 2, &send_policy("receiver@peer"))
        .unwrap();
    let pair = setup.pair();
    let verifier = crate::auth::Verifier::local_only(setup.server.clone(), true);
    let identity = Arc::new(verifier.verify(&pair.access_token).await.unwrap());
    let captured = identity.admitted_authority().unwrap();
    assert_eq!(captured.revision, 3);
    let context = crate::auth::VerifiedContext::new(identity, captured);
    store
        .set_outbound_policy("local", 3, &send_policy("other@peer"))
        .unwrap();
    let bus = Bus::new().await;
    let request = crate::outbound::Request::Send(crate::outbound::SendArguments {
        request_id: crate::outbound::RequestId::parse("snapshot-send").unwrap(),
        to: "receiver@peer".into(),
        text: "admitted policy bytes".into(),
        attachments: vec![],
    });
    let result = crate::outbound::dispatch_verified(
        &mut store,
        &bus.endpoint(),
        &verifier,
        &context,
        "bus",
        &request,
        &limits(),
    )
    .await
    .unwrap();
    assert!(
        matches!(result, crate::outbound::Outcome::Confirmed(_)),
        "policy edit cancelled a previously admitted send"
    );
    assert_eq!(
        bus.frames
            .lock()
            .unwrap()
            .iter()
            .filter(|f| f["action"] == "send")
            .count(),
        1
    );
    assert_eq!(
        setup
            .db()
            .query_row(
                "SELECT grant_revision FROM outbound_reservations",
                [],
                |r| r.get::<_, i64>(0)
            )
            .unwrap(),
        3,
        "send borrowed newer grant authority"
    );
    assert!(setup
        .db()
        .query_row(
            "SELECT revision_changed FROM outbound_reservations",
            [],
            |r| r.get::<_, bool>(0)
        )
        .unwrap());
    drop(context);
    bus.close().await;
}
#[tokio::test]
async fn reply_lookup_refuses_after_disable_before_reservation_or_effect() {
    for disabled in [false, true] {
        let setup = Setup::new();
        let mut store = setup.server.store().unwrap();
        store
            .set_outbound_policy(
                "local",
                2,
                &crate::outbound::Policy {
                    send: None,
                    reply: Some(crate::outbound::Permission {
                        targets: ["sender@peer".into()].into(),
                        required_scope: "identity:read".into(),
                    }),
                },
            )
            .unwrap();
        seed(&setup, "01ARZ3NDEKTSV4RRFFQ69G5FAV");
        setup
            .db()
            .execute("UPDATE custody_items SET grant_revision=3", [])
            .unwrap();
        setup
            .db()
            .execute("UPDATE event_authorizations SET dispatch_revision=3", [])
            .unwrap();
        let pair = setup.pair();
        let verifier = crate::auth::Verifier::local_only(setup.server.clone(), true);
        let identity = Arc::new(verifier.verify(&pair.access_token).await.unwrap());
        let context = crate::auth::VerifiedContext::new(
            identity.clone(),
            identity.admitted_authority().unwrap(),
        );
        if disabled {
            store.set_enabled("local", 3, false).unwrap();
        }
        let bus = Bus::new().await;
        let request = crate::outbound::Request::Reply(crate::outbound::ReplyArguments {
            request_id: crate::outbound::RequestId::parse("fenced-reply").unwrap(),
            message_id: "01ARZ3NDEKTSV4RRFFQ69G5FAV".into(),
            text: "must refuse".into(),
            attachments: vec![],
        });
        let result = crate::outbound::dispatch_verified(
            &mut store,
            &bus.endpoint(),
            &verifier,
            &context,
            "bus",
            &request,
            &limits(),
        )
        .await;
        if disabled {
            assert!(
                matches!(result, Err(crate::outbound::Error::Denied)),
                "reply ownership lookup ignored effect-point disable"
            );
            assert!(bus.frames.lock().unwrap().is_empty());
            assert_eq!(
                setup
                    .db()
                    .query_row("SELECT COUNT(*) FROM outbound_reservations", [], |r| r
                        .get::<_, i64>(0))
                    .unwrap(),
                0
            );
        } else {
            assert!(
                matches!(result, Ok(crate::outbound::Outcome::Confirmed(_))),
                "ordinary local reply positive control failed: {:?}",
                result.as_ref().err().map(ToString::to_string)
            );
            assert_eq!(
                bus.frames
                    .lock()
                    .unwrap()
                    .iter()
                    .filter(|frame| frame["action"] == "reply")
                    .count(),
                1
            );
            let sent = bus.frames.lock().unwrap().len();
            store.set_enabled("local", 3, false).unwrap();
            let recovered = crate::outbound::dispatch_verified(
                &mut store,
                &bus.endpoint(),
                &verifier,
                &context,
                "bus",
                &request,
                &limits(),
            )
            .await;
            assert!(
                matches!(recovered, Ok(crate::outbound::Outcome::Confirmed(_))),
                "stored reply receipt lost entry snapshot"
            );
            assert_eq!(
                bus.frames.lock().unwrap().len(),
                sent,
                "receipt recovery repeated reply effect"
            );
        }
        bus.close().await;
    }
}

#[tokio::test]
async fn admitted_status_retains_reservation_metadata_but_not_custody_authority() {
    let setup = Setup::new();
    let pair = setup.pair();
    let verifier = crate::auth::Verifier::local_only(setup.server.clone(), true);
    let identity = verifier.verify(&pair.access_token).await.unwrap();
    let owner = crate::custody::fingerprint(&[
        identity.service(),
        identity.issuer(),
        identity.resource(),
        identity.subject(),
    ]);
    let at = setup.clock.wall();
    setup.db().execute("INSERT INTO outbound_reservations(owner,operation,request_id,payload_hash,sender,grant_id,grant_revision,idempotency_key,target,framed_text,created_at,retry_until,state,receipt,recovery_until) VALUES(?1,'send','status-admitted','hash','gateway@bus','local',2,'key','receiver@peer','message',?2,?3,'confirmed','{\"message_id\":\"receipt\"}',?3)",rusqlite::params![owner,at,at+86400]).unwrap();
    setup
        .server
        .store()
        .unwrap()
        .set_enabled("local", 2, false)
        .unwrap();
    let key = crate::event_store::EventKey::load(&setup._files.path().join("events")).unwrap();
    let result = crate::recovery::dispatch(
        setup.server.store().unwrap(),
        &identity,
        "bus",
        "gateway@bus",
        "local",
        &key,
        crate::recovery::Request::Status(crate::recovery::StatusArguments {
            request_id: "status-admitted".into(),
        }),
        &limits(),
    )
    .unwrap();
    assert_eq!(
        result["results"][0]["state"], "confirmed",
        "immutable receipt metadata lost admitted snapshot"
    );
    assert!(identity
        .custody_authority(&setup.server.store().unwrap())
        .is_err());
}

#[tokio::test]
async fn issuer_is_root_without_query_and_trailing_root_slash_composes_working_endpoints() {
    for issuer in [
        "https://gateway.example/subpath",
        "https://gateway.example?query=value",
        "https://gateway.example/#fragment",
    ] {
        let setup = Setup::new();
        let mut config: Config =
            serde_json::from_value(serde_json::to_value(&setup.server.config).unwrap()).unwrap();
        config.issuer = issuer.into();
        let mut binding = setup.server.binding.clone();
        binding.issuer = issuer.into();
        assert!(
            Server::from_config(
                config,
                setup.server.file.clone(),
                binding,
                setup.server.scopes.clone(),
                setup.clock.clone()
            )
            .is_err(),
            "nonroot issuer accepted"
        );
    }
    let mut setup = Setup::new();
    let server = Arc::get_mut(&mut setup.server).unwrap();
    server.config.issuer.push('/');
    server.binding.issuer.push('/');
    setup
        .db()
        .execute("UPDATE grants SET issuer='https://gateway.example/'", [])
        .unwrap();
    let serving = crate::serving::Serving::from_owner_file(&owner_file(&setup))
        .await
        .unwrap();
    let (_, _, metadata) = http_call(
        &serving,
        "GET",
        "/.well-known/oauth-authorization-server",
        None,
        "",
    )
    .await;
    assert_eq!(metadata["issuer"], "https://gateway.example/");
    for endpoint in [
        "authorization_endpoint",
        "token_endpoint",
        "revocation_endpoint",
    ] {
        assert!(
            !metadata[endpoint].as_str().unwrap().contains("example//"),
            "root issuer composed a missing double-slash route"
        );
    }
    assert_eq!(
        metadata["authorization_endpoint"],
        "https://gateway.example/oauth/authorize"
    );
    assert_eq!(
        http_call(&serving, "POST", "/oauth/token", None, "")
            .await
            .0,
        401,
        "advertised root endpoint not routable"
    );
}

#[test]
fn cold_tracing_initialization_stress_preserves_all_postcommit_refresh_classes() {
    const CHILD: &str = "XMSG_AS_COLD_TRACE_TEST_CHILD";
    if std::env::var_os(CHILD).is_some() {
        assert!(
            !crate::events_test_support::fixture::tracing_baseline_initialized(),
            "control was not a cold process"
        );
        let start = Arc::new(std::sync::Barrier::new(8));
        let mut workers = Vec::new();
        for _ in 0..8 {
            let start = start.clone();
            workers.push(std::thread::spawn(move || {
                use tracing::instrument::WithSubscriber;
                start.wait();
                let setup = Setup::new();
                assert!(crate::events_test_support::fixture::tracing_baseline_initialized());
                let rt = tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                    .unwrap();
                let capture = SecretCapture::default();
                let subscriber = tracing_subscriber::fmt()
                    .with_target(true)
                    .with_ansi(false)
                    .without_time()
                    .with_max_level(tracing::Level::TRACE)
                    .with_writer(capture.clone())
                    .finish();
                rt.block_on(
                    async {
                        let first = setup.pair();
                        let second = setup.server.refresh(&first.refresh_token).await.unwrap();
                        setup.server.refresh(&first.refresh_token).await.unwrap();
                        assert!(setup.server.refresh(&second.refresh_token).await.is_err());
                    }
                    .with_subscriber(subscriber),
                );
                let logs = capture.0.lock().unwrap();
                for class in ["rotate", "retry", "reuse"] {
                    assert!(
                        String::from_utf8_lossy(&logs)
                            .lines()
                            .any(|line| line.contains("gateway_oauth_refresh")
                                && line.contains(class)),
                        "cold concurrent refresh trace class missing"
                    );
                }
            }));
        }
        for worker in workers {
            worker.join().unwrap();
        }
        eprintln!("authorization-server-cold-trace-control:8/8");
        return;
    }
    let mut child=std::process::Command::new(std::env::current_exe().unwrap()).args(["--exact","authorization_server::tests::cold_tracing_initialization_stress_preserves_all_postcommit_refresh_classes","--nocapture"]).env(CHILD,"child").stdout(std::process::Stdio::piped()).stderr(std::process::Stdio::piped()).spawn().unwrap();
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(30);
    loop {
        if child.try_wait().unwrap().is_some() {
            break;
        }
        if std::time::Instant::now() >= deadline {
            child.kill().unwrap();
            child.wait().unwrap();
            panic!("cold tracing control exceeded its bounded deadline")
        }
        std::thread::sleep(std::time::Duration::from_millis(2));
    }
    let output = child.wait_with_output().unwrap();
    assert!(output.status.success(), "cold tracing subprocess failed");
    assert!(
        String::from_utf8_lossy(&output.stderr)
            .contains("authorization-server-cold-trace-control:8/8"),
        "cold tracing control completion missing"
    );
}

fn liveness_row(setup: &Setup, owner: [char; 3], canary: char) {
    for (index, name) in ["account_expire", "account_valid_from", "memberof"]
        .iter()
        .enumerate()
    {
        let (status, value) = match owner[index] {
            'P' => (
                200,
                match index {
                    0 => json!(["2099-12-31T00:00:00Z"]),
                    1 => json!(["2000-01-01T00:00:00Z"]),
                    _ => json!(["login.access@test"]),
                },
            ),
            'N' => (
                200,
                match index {
                    0 => json!(["2000-01-01T00:00:00Z"]),
                    1 => json!(["2099-12-31T00:00:00Z"]),
                    _ => json!([]),
                },
            ),
            '0' => (200, serde_json::Value::Null),
            'U' => (503, json!({})),
            _ => panic!("unknown liveness row"),
        };
        setup
            .fake
            .set(&format!("/v1/person/owner/_attr/{name}"), status, value);
    }
    match canary {
        '0' => setup.fake.set(
            "/v1/person/canary/_attr/account_expire",
            200,
            serde_json::Value::Null,
        ),
        'U' => setup
            .fake
            .set("/v1/person/canary/_attr/account_expire", 503, json!({})),
        'A' => setup
            .fake
            .set("/v1/person/owner", 200, serde_json::Value::Null),
        'C' => setup
            .fake
            .set("/v1/person/canary", 200, serde_json::Value::Null),
        'D' => {
            setup.fake.set(
                "/v1/person/canary/_attr/account_expire",
                200,
                json!(["2020-01-01T00:00:00Z"]),
            );
            setup
                .fake
                .set("/v1/person/canary/_attr/memberof", 503, json!({}));
        }
        'P' => {}
        _ => panic!("unknown canary row"),
    }
}
#[tokio::test]
async fn complete_liveness_table_is_consistent_at_callback_and_refresh() {
    use Outcome::*;
    let rows = [
        ("PPP", 'P', Positive),
        ("0PP", 'P', Positive),
        ("P0P", 'P', Positive),
        ("00P", 'P', Positive),
        ("NPP", 'P', Negative),
        ("PNP", 'P', Negative),
        ("PPN", 'P', Negative),
        ("PP0", 'P', Indeterminate),
        ("000", 'P', Indeterminate),
        ("UPP", 'P', Unavailable),
        ("PUP", 'P', Unavailable),
        ("PPU", 'P', Unavailable),
        ("N0P", 'P', Negative),
        ("NUP", 'P', Negative),
        ("U0P", 'P', Unavailable),
        ("PPP", '0', Indeterminate),
        ("PPP", 'U', Unavailable),
        ("NPP", '0', Negative),
        ("NP0", 'P', Negative),
        ("PPP", 'A', Indeterminate),
        ("PPP", 'C', Indeterminate),
        ("PPP", 'D', Positive),
    ];
    for (owner, canary, expected) in rows {
        let owner: [char; 3] = owner.chars().collect::<Vec<_>>().try_into().unwrap();
        let callback = Setup::new();
        liveness_row(&callback, owner, canary);
        let state = begin(&callback).await;
        let response = callback
            .server
            .handle(
                "/oauth/callback",
                "GET",
                &format!("state={state}&code=fixture"),
                None,
                "",
            )
            .await;
        let location = response.location.unwrap();
        assert!(
            location.contains(match expected {
                Positive => "code=",
                Negative => "error=access_denied",
                _ => "error=temporarily_unavailable",
            }),
            "callback liveness row misclassified: {owner:?}/{canary}"
        );
        assert_eq!(
            callback
                .db()
                .query_row("SELECT COUNT(*) FROM oauth_codes", [], |r| r
                    .get::<_, i64>(0))
                .unwrap(),
            i64::from(expected == Positive)
        );
        assert_eq!(
            callback
                .db()
                .query_row("SELECT COUNT(*) FROM oauth_families", [], |r| r
                    .get::<_, i64>(0))
                .unwrap(),
            0
        );
        let refresh = Setup::new();
        let pair = refresh.pair();
        let original = refresh.clock.wall();
        liveness_row(&refresh, owner, canary);
        refresh.clock.0.fetch_add(3600, Ordering::SeqCst);
        let result = refresh.server.refresh(&pair.refresh_token).await;
        if expected == Negative {
            assert!(
                matches!(result, Err(Error::InvalidGrant)),
                "negative refresh was not denied"
            );
            assert_eq!(
                refresh
                    .db()
                    .query_row("SELECT revoked_reason FROM oauth_families", [], |r| r
                        .get::<_, String>(0))
                    .unwrap(),
                "kanidm_denied"
            );
        } else {
            assert!(
                result.is_ok(),
                "passing/graced refresh was refused: {owner:?}/{canary}"
            );
            let pair = result.unwrap();
            assert_eq!(
                pair.expires_in,
                if expected == Positive { 3600 } else { 900 }
            );
            let (last, graced, revoked): (i64, bool, Option<i64>) = refresh
                .db()
                .query_row(
                    "SELECT liveness_ok_at,last_mint_graced,revoked_at FROM oauth_families",
                    [],
                    |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
                )
                .unwrap();
            assert_eq!(
                last,
                if expected == Positive {
                    original + 3600
                } else {
                    original
                }
            );
            assert_eq!(graced, expected != Positive);
            assert_eq!(revoked, None);
        }
    }
}
#[tokio::test]
async fn grace_and_denial_bounds_stop_tokens_and_delivery_without_inventing_deletion() {
    for scenario in [
        "expire",
        "validity",
        "membership",
        "owner-null",
        "canary-null",
        "member-null",
        "unavailable",
    ] {
        let setup = Setup::new();
        let pair = setup.pair();
        let (events, callback) = events(&setup);
        let verifier = crate::auth::Verifier::local_only(setup.server.clone(), true);
        let identity = verifier.verify(&pair.access_token).await.unwrap();
        let mut request = crate::events_test_support::request();
        request.ttl_ms = Some(crate::events::MAX_TTL_MS);
        events
            .subscribe(&identity, &pair.access_token, "bus", "gateway@bus", request)
            .await
            .unwrap();
        seed(&setup, "bound-message");
        let negative = matches!(scenario, "expire" | "validity" | "membership");
        match scenario {
            "expire" => setup.fake.set(
                "/v1/person/owner/_attr/account_expire",
                200,
                json!(["2020-01-01T00:00:00Z"]),
            ),
            "validity" => setup.fake.set(
                "/v1/person/owner/_attr/account_valid_from",
                200,
                json!(["2099-01-01T00:00:00Z"]),
            ),
            "membership" => setup
                .fake
                .set("/v1/person/owner/_attr/memberof", 200, json!([])),
            "owner-null" => setup
                .fake
                .set("/v1/person/owner", 200, serde_json::Value::Null),
            "canary-null" => setup
                .fake
                .set("/v1/person/canary", 200, serde_json::Value::Null),
            "member-null" => setup.fake.set(
                "/v1/person/owner/_attr/memberof",
                200,
                serde_json::Value::Null,
            ),
            _ => setup
                .fake
                .set("/v1/person/owner/_attr/memberof", 503, json!({})),
        }
        let before = setup.clock.wall();
        setup.clock.0.fetch_add(3600, Ordering::SeqCst);
        assert!(verifier.verify(&pair.access_token).await.is_err());
        if negative {
            assert!(
                setup.server.refresh(&pair.refresh_token).await.is_err(),
                "readable negative was grace-minted"
            );
            assert_eq!(
                crate::event_dispatch::tick(&events, "bus", "gateway@bus")
                    .await
                    .unwrap(),
                crate::event_dispatch::Tick::Expired
            );
            assert!(callback.events.lock().unwrap().is_empty());
        } else {
            let graced = setup.server.refresh(&pair.refresh_token).await.unwrap();
            assert_eq!(graced.expires_in, 900);
            callback
                .behaviors
                .lock()
                .unwrap()
                .push_back(crate::events_test_support::Behavior::Response(503, None));
            assert_eq!(
                crate::event_dispatch::tick(&events, "bus", "gateway@bus")
                    .await
                    .unwrap(),
                crate::event_dispatch::Tick::Retry
            );
            assert_eq!(callback.events.lock().unwrap().len(), 1);
            setup.clock.0.fetch_add(900, Ordering::SeqCst);
            setup
                .db()
                .execute("UPDATE custody_outbox SET next_attempt=0", [])
                .unwrap();
            assert!(verifier.verify(&graced.access_token).await.is_err());
            assert_eq!(
                crate::event_dispatch::tick(&events, "bus", "gateway@bus")
                    .await
                    .unwrap(),
                crate::event_dispatch::Tick::Expired
            );
            assert_eq!(
                callback.events.lock().unwrap().len(),
                1,
                "delivery crossed grace bound"
            );
            let (last, revoked): (i64, Option<i64>) = setup
                .db()
                .query_row(
                    "SELECT liveness_ok_at,revoked_at FROM oauth_families",
                    [],
                    |r| Ok((r.get(0)?, r.get(1)?)),
                )
                .unwrap();
            assert_eq!(last, before);
            assert_eq!(
                revoked, None,
                "visibility uncertainty invented deletion revocation"
            );
        }
    }
}
#[tokio::test]
async fn exact_30_second_retry_once_only_and_pruned_predecessor_rules() {
    let setup = Setup::new();
    let first = setup.pair();
    setup.server.refresh(&first.refresh_token).await.unwrap();
    setup.clock.0.fetch_add(30, Ordering::SeqCst);
    let current = setup.server.refresh(&first.refresh_token).await.unwrap();
    assert!(
        setup.server.refresh(&first.refresh_token).await.is_err(),
        "a second lost-response retry was accepted before successor use"
    );
    assert!(setup.server.admit(&current.access_token).is_err());
    let mut setup = Setup::new();
    Arc::get_mut(&mut setup.server)
        .unwrap()
        .config
        .max_refresh_rows = 1;
    let a = setup.pair();
    let b = setup.server.refresh(&a.refresh_token).await.unwrap();
    let c = setup.server.refresh(&b.refresh_token).await.unwrap();
    let before = data_census(&setup.db());
    assert!(matches!(
        setup.server.refresh(&a.refresh_token).await,
        Err(Error::InvalidGrant)
    ));
    assert_eq!(
        data_census(&setup.db()),
        before,
        "unknown/pruned token changed family state"
    );
    assert!(setup.server.admit(&c.access_token).is_ok());
}
#[tokio::test]
async fn family_subscription_expiry_is_clamped_to_absolute_and_idle_bounds() {
    for absolute in [false, true] {
        let setup = Setup::new();
        let pair = setup.pair();
        let (events, _) = events(&setup);
        let verifier = crate::auth::Verifier::local_only(setup.server.clone(), true);
        let now = setup.clock.wall();
        setup
            .db()
            .execute(
                if absolute {
                    "UPDATE oauth_families SET absolute_expires_at=?1"
                } else {
                    "UPDATE oauth_families SET last_refresh_at=?1"
                },
                [if absolute {
                    now + 120
                } else {
                    now - setup.server.config.refresh_idle_secs + 120
                }],
            )
            .unwrap();
        let identity = verifier.verify(&pair.access_token).await.unwrap();
        let mut request = crate::events_test_support::request();
        request.ttl_ms = Some(crate::events::MAX_TTL_MS);
        events
            .subscribe(&identity, &pair.access_token, "bus", "gateway@bus", request)
            .await
            .unwrap();
        assert_eq!(
            setup
                .db()
                .query_row("SELECT expires FROM event_subscriptions", [], |r| r
                    .get::<_, i64>(0))
                .unwrap(),
            now + 120,
            "subscription escaped family bound"
        );
    }
}
#[tokio::test]
async fn latest_outage_controls_delivery_grace_even_without_a_new_mint() {
    let setup = Setup::new();
    let pair = setup.pair();
    let (events, callback) = events(&setup);
    let verifier = crate::auth::Verifier::local_only(setup.server.clone(), true);
    let identity = verifier.verify(&pair.access_token).await.unwrap();
    let mut request = crate::events_test_support::request();
    request.ttl_ms = Some(crate::events::MAX_TTL_MS);
    events
        .subscribe(&identity, &pair.access_token, "bus", "gateway@bus", request)
        .await
        .unwrap();
    seed(&setup, "latest-outcome");
    setup
        .fake
        .set("/v1/person/owner", 200, serde_json::Value::Null);
    setup.clock.0.fetch_add(3601, Ordering::SeqCst);
    assert_eq!(
        crate::event_dispatch::tick(&events, "bus", "gateway@bus")
            .await
            .unwrap(),
        crate::event_dispatch::Tick::Accepted,
        "dispatcher used stale mint classification instead of latest evidence"
    );
    assert_eq!(callback.events.lock().unwrap().len(), 1);
    let (graced, outcome): (bool, String) = setup
        .db()
        .query_row(
            "SELECT last_mint_graced,last_liveness_outcome FROM oauth_families",
            [],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .unwrap();
    assert!(!graced);
    assert_eq!(outcome, "indeterminate");
}

#[tokio::test]
async fn restart_keeps_retry_state_and_never_revives_revoked_or_absolute_family() {
    let setup = Setup::new();
    let a = setup.pair();
    let b = setup.server.refresh(&a.refresh_token).await.unwrap();
    setup.clock.0.fetch_add(20, Ordering::SeqCst);
    let restarted = Server::from_config(
        serde_json::from_value(serde_json::to_value(&setup.server.config).unwrap()).unwrap(),
        setup.server.file.clone(),
        setup.server.binding.clone(),
        setup.server.scopes.clone(),
        setup.clock.clone(),
    )
    .unwrap();
    let c = restarted.refresh(&a.refresh_token).await.unwrap();
    assert!(restarted.admit(&b.access_token).is_err());
    assert!(restarted.admit(&c.access_token).is_ok());
    restarted.revoke(&c.refresh_token).unwrap();
    let before = data_census(&setup.db());
    assert!(restarted.refresh(&a.refresh_token).await.is_err());
    assert_eq!(
        data_census(&setup.db()),
        before,
        "revoked family changed after restart/replay"
    );
    let setup = Setup::new();
    let pair = setup.pair();
    setup
        .db()
        .execute(
            "UPDATE oauth_families SET absolute_expires_at=?1",
            [setup.clock.wall()],
        )
        .unwrap();
    assert!(setup.server.refresh(&pair.refresh_token).await.is_err());
    assert_eq!(
        setup
            .db()
            .query_row("SELECT revoked_reason FROM oauth_families", [], |r| r
                .get::<_, String>(0))
            .unwrap(),
        "absolute"
    );
}
#[tokio::test]
async fn older_predecessor_reuse_and_concurrent_retries_end_the_family() {
    let setup = Setup::new();
    let a = setup.pair();
    let b = setup.server.refresh(&a.refresh_token).await.unwrap();
    let c = setup.server.refresh(&b.refresh_token).await.unwrap();
    assert!(setup.server.refresh(&a.refresh_token).await.is_err());
    assert!(setup.server.admit(&c.access_token).is_err());
    let setup = Setup::new();
    let a = setup.pair();
    setup.server.refresh(&a.refresh_token).await.unwrap();
    let barrier = Arc::new(tokio::sync::Barrier::new(2));
    let mut workers = Vec::new();
    for _ in 0..2 {
        let server = setup.server.clone();
        let token = a.refresh_token.clone();
        let barrier = barrier.clone();
        workers.push(tokio::spawn(async move {
            barrier.wait().await;
            server.refresh(&token).await.is_ok()
        }));
    }
    let mut successes = 0;
    for worker in workers {
        successes += usize::from(worker.await.unwrap());
    }
    assert_eq!(successes, 1);
    assert_eq!(
        setup
            .db()
            .query_row("SELECT revoked_reason FROM oauth_families", [], |r| r
                .get::<_, String>(0))
            .unwrap(),
        "refresh_reuse"
    );
}
#[tokio::test]
async fn family_cap_evicts_least_recently_refreshed_not_oldest_created() {
    let mut setup = Setup::new();
    Arc::get_mut(&mut setup.server).unwrap().config.max_families = 2;
    let a = setup.pair();
    setup.clock.0.fetch_add(1, Ordering::SeqCst);
    let b = setup.pair();
    setup.clock.0.fetch_add(1, Ordering::SeqCst);
    let a = setup.server.refresh(&a.refresh_token).await.unwrap();
    setup.clock.0.fetch_add(1, Ordering::SeqCst);
    let c = setup.pair();
    assert!(setup.server.admit(&a.access_token).is_ok());
    assert!(
        setup.server.admit(&b.access_token).is_err(),
        "family eviction ignored last refresh order"
    );
    assert!(setup.server.admit(&c.access_token).is_ok());
    assert_eq!(
        setup
            .db()
            .query_row(
                "SELECT COUNT(*) FROM oauth_families WHERE revoked_reason='evicted'",
                [],
                |r| r.get::<_, i64>(0)
            )
            .unwrap(),
        1
    );
}
#[tokio::test]
async fn first_code_and_access_expiry_use_liveness_start_not_completion_time() {
    let setup = Setup::new();
    let at = setup.clock.wall();
    let verifier = "v".repeat(43);
    let challenge = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .encode(Sha256::digest(verifier.as_bytes()));
    let query = authorize_query().replace(
        &format!("code_challenge={}", "a".repeat(43)),
        &format!("code_challenge={challenge}"),
    );
    let response = setup
        .server
        .handle("/oauth/authorize", "GET", &query, None, "")
        .await;
    let state = reqwest::Url::parse(response.location.as_ref().unwrap())
        .unwrap()
        .query_pairs()
        .find(|(k, _)| k == "state")
        .unwrap()
        .1
        .into_owned();
    let clock = setup.clock.clone();
    *setup.fake.arrival.lock().unwrap() = Some(Arc::new(move |route| {
        if route == "/v1/person/owner/_attr/memberof" {
            clock.0.fetch_add(10, Ordering::SeqCst);
        }
    }));
    let response = setup
        .server
        .handle(
            "/oauth/callback",
            "GET",
            &format!("state={state}&code=fixture"),
            None,
            "",
        )
        .await;
    let code = reqwest::Url::parse(response.location.as_ref().unwrap())
        .unwrap()
        .query_pairs()
        .find(|(k, _)| k == "code")
        .unwrap()
        .1
        .into_owned();
    assert_eq!(
        setup
            .db()
            .query_row("SELECT liveness_ok_at FROM oauth_codes", [], |r| r
                .get::<_, i64>(0))
            .unwrap(),
        at,
        "callback recorded completion instead of observation start"
    );
    let pair = setup
        .server
        .exchange(&code, "https://chat.example/callback", &verifier, None)
        .unwrap();
    assert_eq!(pair.expires_in, 3590);
    assert_eq!(
        setup
            .db()
            .query_row("SELECT expires_at FROM oauth_access_tokens", [], |r| r
                .get::<_, i64>(0))
            .unwrap(),
        at + 3600
    );
}
#[tokio::test]
async fn upstream_logout_and_consent_state_do_not_revoke_local_family() {
    let setup = Setup::new();
    let pair = setup.pair();
    setup.fake.set("/introspect", 200, json!({"active":false}));
    setup
        .fake
        .set("/token", 401, json!({"error":"invalid_grant"}));
    let refreshed = setup.server.refresh(&pair.refresh_token).await.unwrap();
    assert!(setup.server.admit(&refreshed.access_token).is_ok());
    assert!(
        setup
            .fake
            .requests
            .lock()
            .unwrap()
            .iter()
            .all(|u| u.contains("/_attr/")),
        "local refresh regained upstream session dependency"
    );
    let legacy =
        crate::auth::Verifier::from_config(setup.server.config.upstream.verify.clone()).unwrap();
    assert!(
        matches!(
            legacy.verify("fixture-access").await,
            Err(crate::auth::Error::InvalidToken)
        ),
        "legacy introspection did not retain upstream revocation semantics"
    );
}
#[test]
fn family_binding_scope_and_steady_state_readonly_admission_are_enforced() {
    for sql in [
        "UPDATE oauth_families SET client_id='foreign'",
        "UPDATE oauth_families SET subject='foreign'",
        "UPDATE oauth_families SET resource='https://foreign.example/mcp'",
        "UPDATE oauth_families SET scope='foreign'",
    ] {
        let setup = Setup::new();
        let pair = setup.pair();
        setup.db().execute_batch(sql).unwrap();
        assert!(
            setup.server.admit(&pair.access_token).is_err(),
            "family binding or scope mismatch accepted"
        );
    }
    let setup = Setup::new();
    let pair = setup.pair();
    setup.server.admit(&pair.access_token).unwrap();
    let before = std::fs::read(&setup.server.file).unwrap();
    setup.server.admit(&pair.access_token).unwrap();
    assert_eq!(
        std::fs::read(&setup.server.file).unwrap(),
        before,
        "steady-state admission wrote durable state"
    );
}

#[tokio::test]
async fn competing_liveness_results_follow_ticket_order_and_negative_never_loses() {
    for second in [
        "negative",
        "unavailable",
        "indeterminate",
        "positive",
        "older-negative",
    ] {
        let setup = Setup::new();
        let first = setup.pair();
        let family = setup
            .db()
            .query_row("SELECT id FROM oauth_families", [], |r| {
                r.get::<_, String>(0)
            })
            .unwrap();
        let initial = setup.clock.wall();
        if second == "older-negative" {
            setup
                .fake
                .set("/v1/person/owner/_attr/memberof", 200, json!([]));
        }
        let (entered_tx, entered_rx) = std::sync::mpsc::sync_channel(0);
        let (release_tx, release_rx) = std::sync::mpsc::sync_channel(0);
        let release = std::sync::Mutex::new(release_rx);
        *setup.server.liveness_barrier.lock().unwrap() = Some(Arc::new(move |ticket, _, _| {
            if ticket == 1 {
                entered_tx.send(()).unwrap();
                release
                    .lock()
                    .unwrap()
                    .recv_timeout(std::time::Duration::from_secs(10))
                    .unwrap();
            }
        }));
        let server = setup.server.clone();
        let token = first.refresh_token.clone();
        let worker = std::thread::spawn(move || {
            tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap()
                .block_on(server.refresh(&token))
        });
        entered_rx
            .recv_timeout(std::time::Duration::from_secs(10))
            .unwrap();
        setup.clock.0.fetch_add(20, Ordering::SeqCst);
        match second {
            "negative" => setup
                .fake
                .set("/v1/person/owner/_attr/memberof", 200, json!([])),
            "unavailable" => setup
                .fake
                .set("/v1/person/owner/_attr/memberof", 503, json!({})),
            "indeterminate" => setup.fake.set(
                "/v1/person/owner/_attr/memberof",
                200,
                serde_json::Value::Null,
            ),
            _ => setup.fake.set(
                "/v1/person/owner/_attr/memberof",
                200,
                json!(["login.access@test"]),
            ),
        }
        setup
            .server
            .check_liveness(&family, second == "unavailable")
            .await
            .unwrap();
        release_tx.send(()).unwrap();
        let outcome = worker.join().unwrap();
        *setup.server.liveness_barrier.lock().unwrap() = None;
        let (applied,last,classification,revoked):(i64,i64,String,Option<i64>)=setup.db().query_row("SELECT liveness_applied,liveness_ok_at,last_liveness_outcome,revoked_at FROM oauth_families",[],|r|Ok((r.get(0)?,r.get(1)?,r.get(2)?,r.get(3)?))).unwrap();
        assert_eq!(applied, 2, "older read replaced newer ticket");
        if matches!(second, "negative" | "older-negative") {
            assert!(outcome.is_err());
            assert!(revoked.is_some());
            assert_eq!(
                setup
                    .db()
                    .query_row("SELECT COUNT(*) FROM oauth_refresh_tokens", [], |r| r
                        .get::<_, i64>(0))
                    .unwrap(),
                1,
                "revoked refresh minted a new pair"
            );
        } else if second == "positive" {
            assert!(outcome.is_ok());
            assert_eq!(last, initial + 20);
            assert_eq!(classification, "positive");
            assert_eq!(revoked, None);
        } else {
            assert!(outcome.is_ok());
            assert_eq!(last, initial, "stale positive changed observation time");
            assert_eq!(classification, second);
            assert!(
                setup
                    .db()
                    .query_row("SELECT last_mint_graced FROM oauth_families", [], |r| r
                        .get::<_, bool>(0))
                    .unwrap(),
                "refresh used its own older positive instead of latest evidence"
            );
            assert_eq!(revoked, None);
        }
    }
}
#[tokio::test]
async fn retry_and_first_access_admission_have_one_atomic_winner() {
    let setup = Setup::new();
    let a = setup.pair();
    let b = setup.server.refresh(&a.refresh_token).await.unwrap();
    let (entered_tx, entered_rx) = std::sync::mpsc::sync_channel(0);
    let (release_tx, release_rx) = std::sync::mpsc::sync_channel(0);
    let release = std::sync::Mutex::new(release_rx);
    *setup.server.admission_barrier.lock().unwrap() = Some(Arc::new(move |_| {
        entered_tx.send(()).unwrap();
        release
            .lock()
            .unwrap()
            .recv_timeout(std::time::Duration::from_secs(10))
            .unwrap();
    }));
    let server = setup.server.clone();
    let access = b.access_token.clone();
    let admission = std::thread::spawn(move || server.admit(&access));
    entered_rx
        .recv_timeout(std::time::Duration::from_secs(10))
        .unwrap();
    let db = setup.db();
    db.busy_timeout(std::time::Duration::ZERO).unwrap();
    assert!(
        db.execute(
            "UPDATE oauth_refresh_tokens SET successor_used_at=0 WHERE successor_hash IS NOT NULL",
            []
        )
        .is_err(),
        "competing write crossed first-use snapshot"
    );
    release_tx.send(()).unwrap();
    assert!(admission.join().unwrap().is_ok());
    *setup.server.admission_barrier.lock().unwrap() = None;
    assert!(
        setup.server.refresh(&a.refresh_token).await.is_err(),
        "retry ignored completed successor admission"
    );
    assert!(setup.server.admit(&b.access_token).is_err());
    let setup = Setup::new();
    let a = setup.pair();
    let b = setup.server.refresh(&a.refresh_token).await.unwrap();
    let (entered_tx, entered_rx) = std::sync::mpsc::sync_channel(0);
    let (resume_tx, resume_rx) = std::sync::mpsc::sync_channel(0);
    let resume = std::sync::Mutex::new(resume_rx);
    *setup.server.upgrade_barrier.lock().unwrap() = Some(Arc::new(move || {
        entered_tx.send(()).unwrap();
        resume
            .lock()
            .unwrap()
            .recv_timeout(std::time::Duration::from_secs(10))
            .unwrap();
    }));
    let server = setup.server.clone();
    let token = b.access_token.clone();
    let blocked = std::thread::spawn(move || server.admit(&token));
    entered_rx
        .recv_timeout(std::time::Duration::from_secs(10))
        .unwrap();
    let c = setup.server.refresh(&a.refresh_token).await.unwrap();
    resume_tx.send(()).unwrap();
    assert!(
        blocked.join().unwrap().is_err(),
        "first-use upgrade accepted superseded access after retry commit"
    );
    *setup.server.upgrade_barrier.lock().unwrap() = None;
    assert!(setup.server.admit(&c.access_token).is_ok());
}

#[tokio::test]
async fn cutover_acceptance_defers_old_scope_without_ack_then_accepts_same_delivery_on_new_scope() {
    let setup = Setup::new();
    let mut store = setup.server.store().unwrap();
    let mut binding = setup.server.binding.clone();
    binding.issuer = "https://old.example".into();
    store.enroll("old", &binding).unwrap();
    store.set_enabled("old", 1, true).unwrap();
    let mut bus = Bus::new().await;
    let scope = |grant: &str| crate::custody::Scope {
        bus_instance: "bus".into(),
        grant_id: grant.into(),
    };
    let at = std::time::UNIX_EPOCH + std::time::Duration::from_secs(setup.clock.wall() as u64);
    let delivery = |id: &str| json!({"action":"deliver","messageId":id,"fromName":"sender@peer","text":"cutover message","envelope":"{}","origin":{"service":"sender","id":null,"node":"peer"},"inReplyTo":null});
    bus.pending
        .lock()
        .unwrap()
        .push_back(delivery("old-positive"));
    let accepted = crate::custody::receive_one(
        &mut store,
        &mut bus.registered,
        &scope("old"),
        &crate::custody::Limits::default(),
        at,
    )
    .await
    .unwrap()
    .unwrap();
    assert!(matches!(
        accepted,
        crate::custody::Acceptance::Stored { .. }
    ));
    assert_eq!(bus.acked.load(Ordering::SeqCst), 1);
    setup
        .db()
        .execute(
            "INSERT INTO event_observations SELECT event_id,1 FROM custody_items",
            [],
        )
        .unwrap();
    assert_eq!(
        store
            .cutover_events(
                "old",
                "local",
                "owner",
                "cutover",
                false,
                setup.clock.wall()
            )
            .unwrap(),
        Cutover::Complete
    );
    assert!(store.validate_cutover_selection(Some("old")).is_err());
    assert!(store.validate_cutover_selection(None).is_err());
    store.validate_cutover_selection(Some("local")).unwrap();
    bus.pending
        .lock()
        .unwrap()
        .push_back(delivery("new-after-marker"));
    let deferred = crate::custody::receive_one(
        &mut store,
        &mut bus.registered,
        &scope("old"),
        &crate::custody::Limits::default(),
        at,
    )
    .await
    .unwrap()
    .unwrap();
    assert_eq!(deferred, crate::custody::Acceptance::Deferred);
    assert_eq!(
        bus.acked.load(Ordering::SeqCst),
        1,
        "mismatched scope ACKed queued delivery"
    );
    assert_eq!(bus.pending.lock().unwrap().len(), 1);
    assert_eq!(
        setup
            .db()
            .query_row(
                "SELECT COUNT(*) FROM custody_items WHERE grant_id='old'",
                [],
                |r| r.get::<_, i64>(0)
            )
            .unwrap(),
        1,
        "old scope stored a post-cutover item"
    );
    assert!(matches!(
        crate::custody::receive_one(
            &mut store,
            &mut bus.registered,
            &scope("local"),
            &crate::custody::Limits::default(),
            at
        )
        .await
        .unwrap(),
        Some(crate::custody::Acceptance::Stored { .. })
    ));
    assert_eq!(bus.acked.load(Ordering::SeqCst), 2);
    assert!(bus.pending.lock().unwrap().is_empty());
    bus.close().await;
}
#[test]
fn seeded_admission_change_schedules_preserve_both_snapshot_paths() {
    use std::sync::Mutex;
    let mut earlier = 0;
    let mut later = 0;
    let mut marking = 0;
    let mut readonly = 0;
    for seed in [13u64, 29, 71, 113] {
        let mut state = seed;
        for _ in 0..8 {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            let before_change = state & 1 == 0;
            let used = state & 2 == 0;
            let change = (state >> 2) % 3;
            let setup = Setup::new();
            let pair = setup.pair();
            if used {
                setup.server.admit(&pair.access_token).unwrap();
                readonly += 1
            } else {
                marking += 1
            }
            let at = setup.clock.wall();
            if change == 2 {
                setup
                    .db()
                    .execute(
                        "UPDATE oauth_families SET absolute_expires_at=?1",
                        [at + 10],
                    )
                    .unwrap();
            }
            if !before_change {
                later += 1;
                match change {
                    0 => setup.server.revoke(&pair.refresh_token).unwrap(),
                    1 => {
                        setup
                            .server
                            .store()
                            .unwrap()
                            .set_enabled("local", 2, false)
                            .unwrap();
                    }
                    _ => {
                        setup.clock.0.store(at + 11, Ordering::SeqCst);
                    }
                }
                assert!(
                    setup.server.admit(&pair.access_token).is_err(),
                    "snapshot after committed change admitted"
                );
                continue;
            }
            earlier += 1;
            let (entered_tx, entered_rx) = std::sync::mpsc::sync_channel(0);
            let (resume_tx, resume_rx) = std::sync::mpsc::sync_channel(0);
            let resume = Mutex::new(resume_rx);
            *setup.server.admission_barrier.lock().unwrap() = Some(Arc::new(move |sampled| {
                entered_tx.send(sampled).unwrap();
                resume
                    .lock()
                    .unwrap()
                    .recv_timeout(std::time::Duration::from_secs(5))
                    .unwrap();
            }));
            let server = setup.server.clone();
            let token = pair.access_token.clone();
            let worker = std::thread::spawn(move || server.admit(&token));
            assert_eq!(
                entered_rx
                    .recv_timeout(std::time::Duration::from_secs(5))
                    .unwrap(),
                at
            );
            if change == 2 {
                setup.clock.0.store(at + 11, Ordering::SeqCst);
            } else {
                let db = setup.db();
                db.busy_timeout(std::time::Duration::ZERO).unwrap();
                assert!(db.execute(if change==0{"UPDATE oauth_families SET revoked_at=1,revoked_reason='revocation_endpoint'"}else{"UPDATE grants SET enabled=0,revision=revision+1"},[]).is_err(),"change committed through a pinned admission snapshot");
            }
            resume_tx.send(()).unwrap();
            assert!(worker.join().unwrap().is_ok());
            *setup.server.admission_barrier.lock().unwrap() = None;
        }
    }
    assert!(
        earlier > 0 && later > 0 && marking > 0 && readonly > 0,
        "seeded admission schedules were vacuous"
    );
}

#[tokio::test]
async fn nonpositive_liveness_status_timeout_and_malformed_arms_never_refresh_evidence() {
    for failure in [
        "403",
        "404",
        "500",
        "timeout",
        "malformed",
        "null-validity-canary",
    ] {
        let mut setup = Setup::new();
        if failure == "timeout" {
            let server = Arc::get_mut(&mut setup.server).unwrap();
            server.config.liveness.timeout_ms = 50;
            server.liveness = Liveness::new_with_root(
                &server.config.liveness,
                server
                    .config
                    .upstream
                    .verify
                    .root_certificate_file
                    .as_deref(),
            )
            .unwrap();
        }
        let pair = setup.pair();
        let before = setup.clock.wall();
        let route = "/v1/person/canary/_attr/account_valid_from";
        match failure {
            "timeout" => {
                setup
                    .fake
                    .delays
                    .lock()
                    .unwrap()
                    .insert(route.into(), std::time::Duration::from_millis(150));
            }
            "malformed" => setup.fake.set(route, 200, json!(["not-a-date"])),
            "null-validity-canary" => setup.fake.set(route, 200, serde_json::Value::Null),
            value => setup.fake.set(route, value.parse().unwrap(), json!({})),
        }
        setup.clock.0.fetch_add(3600, Ordering::SeqCst);
        let pair = setup.server.refresh(&pair.refresh_token).await.unwrap();
        assert_eq!(pair.expires_in, 900);
        assert_eq!(
            setup
                .db()
                .query_row("SELECT liveness_ok_at FROM oauth_families", [], |r| r
                    .get::<_, i64>(0))
                .unwrap(),
            before,
            "failure advanced liveness_ok_at"
        );
        assert_eq!(
            setup
                .db()
                .query_row("SELECT revoked_at FROM oauth_families", [], |r| r
                    .get::<_, Option<i64>>(0))
                .unwrap(),
            None
        );
    }
}
#[test]
fn rollback_state_survives_restart_and_a_later_within_tolerance_catchup_step() {
    let setup = Setup::new();
    let pair = setup.pair();
    let at = setup.clock.wall();
    setup.clock.0.store(at - 600, Ordering::SeqCst);
    assert!(setup.server.admit(&pair.access_token).is_err());
    setup.clock.0.store(at - 3, Ordering::SeqCst);
    let restarted = Server::from_config(
        serde_json::from_value(serde_json::to_value(&setup.server.config).unwrap()).unwrap(),
        setup.server.file.clone(),
        setup.server.binding.clone(),
        setup.server.scopes.clone(),
        setup.clock.clone(),
    )
    .unwrap();
    assert!(
        restarted.clock.mint(&setup.db()).is_err(),
        "restart forgot a detected rollback during catchup"
    );
    setup.clock.0.store(at, Ordering::SeqCst);
    assert!(restarted.clock.mint(&setup.db()).is_ok());
    assert!(
        restarted.admit(&pair.access_token).is_err(),
        "catchup resurrected old family"
    );
}

#[tokio::test]
async fn refused_local_admission_opens_once_without_second_grant_query_or_dispatch() {
    use crate::events_test_support::fixture;
    let body = json!({"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"xmsg_identity","arguments":{}}});
    let positive = Setup::new();
    let pair = positive.pair();
    let serving = crate::serving::Serving::from_owner_file(&owner_file(&positive))
        .await
        .unwrap();
    let (status, _, probe) = fixture::request(&serving, &pair.access_token, body.clone()).await;
    assert_eq!(status, 200);
    assert!(probe.opens.load(Ordering::SeqCst) > 0);
    assert_eq!(probe.dispatches.load(Ordering::SeqCst), 1);
    assert_eq!(
        probe.grant_queries.load(Ordering::SeqCst),
        0,
        "local success repeated atomic grant lookup"
    );
    let verifier = crate::auth::Verifier::local_only(positive.server.clone(), true);
    let identity = verifier.verify(&pair.access_token).await.unwrap();
    let lookup = fixture::Probe::default();
    tracing::subscriber::with_default(lookup.clone(), || {
        positive.server.store().unwrap().authorize(&identity)
    })
    .unwrap();
    assert_eq!(
        lookup.grant_queries.load(Ordering::SeqCst),
        1,
        "grant-query positive control did not fire"
    );
    for failure in ["access", "revoked", "absolute"] {
        let setup = Setup::new();
        let pair = setup.pair();
        let serving = crate::serving::Serving::from_owner_file(&owner_file(&setup))
            .await
            .unwrap();
        match failure {
            "access" => {
                setup
                    .db()
                    .execute(
                        "UPDATE oauth_access_tokens SET expires_at=?1",
                        [setup.clock.wall()],
                    )
                    .unwrap();
            }
            "absolute" => {
                setup
                    .db()
                    .execute(
                        "UPDATE oauth_families SET absolute_expires_at=?1",
                        [setup.clock.wall()],
                    )
                    .unwrap();
            }
            _ => setup.server.revoke(&pair.refresh_token).unwrap(),
        }
        let (status, _, probe) = fixture::request(&serving, &pair.access_token, body.clone()).await;
        assert_eq!(status, 401, "local refusal status wrong: {failure}");
        assert_eq!(
            probe.opens.load(Ordering::SeqCst),
            1,
            "refused local token did not open exactly once"
        );
        assert_eq!(
            probe.grant_queries.load(Ordering::SeqCst),
            0,
            "refused local token performed second grant query"
        );
        assert_eq!(
            probe.dispatches.load(Ordering::SeqCst),
            0,
            "refused local token dispatched"
        );
    }
    let (status, _, probe) = fixture::request(&serving, "xgw_rt_invalid", body).await;
    assert_eq!(status, 401);
    assert_eq!(
        probe.opens.load(Ordering::SeqCst),
        0,
        "wrong token kind touched store"
    );
}
#[tokio::test]
async fn local_configuration_requires_exactly_one_backend_and_advertised_controls_only_discovery() {
    for scenario in [
        "missing-as",
        "missing-local",
        "two-local",
        "local-not-default",
        "mixed-forms",
    ] {
        let setup = Setup::new();
        let file = owner_file(&setup);
        let mut value: serde_json::Value =
            serde_json::from_slice(&std::fs::read(&file).unwrap()).unwrap();
        match scenario {
            "missing-as" => {
                value
                    .as_object_mut()
                    .unwrap()
                    .remove("authorization_server");
            }
            "missing-local" => {
                value["verifier_profiles"] = json!([]);
            }
            "two-local" => {
                let local = value["verifier_profiles"][0].clone();
                value["verifier_profiles"]
                    .as_array_mut()
                    .unwrap()
                    .push(local);
            }
            "local-not-default" => value["verifier_profiles"][0]["opaque_default"] = json!(false),
            _ => {
                value["verifier"] =
                    serde_json::to_value(&setup.server.config.upstream.verify).unwrap()
            }
        }
        std::fs::write(&file, value.to_string()).unwrap();
        assert!(
            crate::serving::Serving::from_owner_file(&file)
                .await
                .is_err(),
            "invalid local configuration accepted: {scenario}"
        );
    }
    let setup = Setup::new();
    let pair = setup.pair();
    let file = owner_file(&setup);
    let mut value: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&file).unwrap()).unwrap();
    value["verifier_profiles"][0]["advertised"] = json!(false);
    std::fs::write(&file, value.to_string()).unwrap();
    let serving = crate::serving::Serving::from_owner_file(&file)
        .await
        .unwrap();
    let (_, _, prm) = http_call(
        &serving,
        "GET",
        "/.well-known/oauth-protected-resource",
        None,
        "",
    )
    .await;
    assert_eq!(prm["authorization_servers"], json!([]));
    let request = json!({"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"xmsg_identity","arguments":{}}});
    let (status, _, _) =
        crate::events_test_support::fixture::request(&serving, &pair.access_token, request).await;
    assert_eq!(status, 200, "advertised=false disabled accepted profile");
}

#[path = "property_tests.rs"]
mod properties;

#[test]
fn first_clock_detection_revokes_every_live_family_before_any_later_token_check() {
    let setup = Setup::new();
    let a = setup.pair();
    let b = setup.pair();
    setup.server.admit(&a.access_token).unwrap();
    setup.server.admit(&b.access_token).unwrap();
    assert_eq!(
        setup
            .db()
            .query_row(
                "SELECT COUNT(*) FROM oauth_families WHERE revoked_at IS NULL",
                [],
                |r| r.get::<_, i64>(0)
            )
            .unwrap(),
        2
    );
    let at = setup.clock.wall();
    setup.clock.0.store(at - 600, Ordering::SeqCst);
    setup.server.clock.observe(&setup.db(), false).unwrap();
    assert_eq!(
        setup
            .db()
            .query_row(
                "SELECT COUNT(*) FROM oauth_families WHERE revoked_at IS NULL",
                [],
                |r| r.get::<_, i64>(0)
            )
            .unwrap(),
        0,
        "first detection left a live family; later checks must not mask partial revoke"
    );
    setup.clock.0.store(at, Ordering::SeqCst);
    assert!(setup.server.admit(&a.access_token).is_err());
    assert!(setup.server.admit(&b.access_token).is_err());
}
#[tokio::test]
async fn mandatory_s256_and_distinct_token_kinds_refuse_without_authority_or_pending_state() {
    let setup = Setup::new();
    assert_eq!(setup.server.pending_count(), 0);
    for query in [
        authorize_query().replace("code_challenge_method=S256", "code_challenge_method=plain"),
        authorize_query().replace(&format!("&code_challenge={}", "a".repeat(43)), ""),
    ] {
        let reply = setup
            .server
            .handle("/oauth/authorize", "GET", &query, None, "")
            .await;
        assert!(reply
            .location
            .as_deref()
            .is_some_and(|u| u.contains("error=invalid_request")));
        assert_eq!(
            setup.server.pending_count(),
            0,
            "invalid PKCE authorize created pending state"
        );
    }
    let pair = setup.pair();
    assert!(setup.server.admit(&pair.refresh_token).is_err());
    assert!(setup.server.refresh(&pair.access_token).await.is_err());
    assert!(setup
        .server
        .exchange(
            &pair.access_token,
            "https://chat.example/callback",
            &"v".repeat(43),
            None
        )
        .is_err());
    let v = "v".repeat(43);
    let challenge =
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(Sha256::digest(v.as_bytes()));
    let code = setup
        .server
        .issue_code(
            &setup.server.local_authority().unwrap(),
            "https://chat.example/callback",
            &challenge,
            "identity:read events:subscribe",
            setup.clock.wall(),
        )
        .unwrap();
    let response=setup.server.handle("/oauth/token","POST","",Some(&basic(&setup)),&format!("grant_type=authorization_code&code={code}&redirect_uri=https%3A%2F%2Fchat.example%2Fcallback")).await;
    assert_eq!(response.status, 400);
    assert_eq!(response.body["error"], "invalid_grant");
    assert_eq!(
        setup
            .db()
            .query_row(
                "SELECT used_at FROM oauth_codes WHERE code_hash=?1",
                [hash(&code)],
                |r| r.get::<_, Option<i64>>(0)
            )
            .unwrap(),
        None
    );
    assert!(
        setup.server.admit(&pair.access_token).is_ok(),
        "token-kind refusal changed live family"
    );
}
#[tokio::test]
async fn all_redirect_difference_arms_refuse_and_token_redirect_is_bound_to_code() {
    let setup = Setup::new();
    let v = "v".repeat(43);
    let challenge =
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(Sha256::digest(v.as_bytes()));
    for uri in [
        Some("https://chat.example/callback/"),
        Some("https://chat.example/callback?extra=1"),
        Some("https://chat.example/Callback"),
        Some("https://CHAT.example/callback"),
        Some("https://chat.example:443/callback"),
        Some("https://chat.example%2Fcallback"),
        Some("https://foreign.example/callback"),
        Some("https://chat.example/call"),
        Some("https://chat.example/callback-extra"),
        None,
    ] {
        let mut query = reqwest::Url::parse("https://form.invalid").unwrap();
        {
            let mut fields = query.query_pairs_mut();
            fields
                .append_pair("client_id", "dot")
                .append_pair("response_type", "code")
                .append_pair("resource", "https://gateway.example/mcp")
                .append_pair("code_challenge", &challenge)
                .append_pair("code_challenge_method", "S256");
            if let Some(uri) = uri {
                fields.append_pair("redirect_uri", uri);
            }
        }
        let reply = setup
            .server
            .handle("/oauth/authorize", "GET", query.query().unwrap(), None, "")
            .await;
        assert_eq!(reply.status, 400);
        assert!(
            reply.location.is_none(),
            "unapproved redirect received a Location"
        );
    }
    let code = setup
        .server
        .issue_code(
            &setup.server.local_authority().unwrap(),
            "https://chat.example/callback",
            &challenge,
            "identity:read events:subscribe",
            setup.clock.wall(),
        )
        .unwrap();
    assert!(setup
        .server
        .exchange(&code, "https://chat.example/callback/", &v, None)
        .is_err());
    assert_eq!(
        setup
            .db()
            .query_row("SELECT used_at FROM oauth_codes", [], |r| r
                .get::<_, Option<i64>>(0))
            .unwrap(),
        None
    );
    assert!(setup
        .server
        .exchange(&code, "https://chat.example/callback", &v, None)
        .is_ok());
}
#[tokio::test]
async fn as_routes_stay_absent_without_feature_and_legacy_resource_metadata_is_positive_control() {
    let setup = Setup::new();
    let file = owner_file(&setup);
    let mut value: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&file).unwrap()).unwrap();
    value
        .as_object_mut()
        .unwrap()
        .remove("authorization_server");
    value.as_object_mut().unwrap().remove("verifier_profiles");
    let mut verifier = setup.server.config.upstream.verify.clone();
    verifier.issuer = setup.server.binding.issuer.clone();
    verifier.hosted_client = setup.server.binding.hosted_client.clone();
    verifier.audience = Some(setup.server.binding.resource.clone());
    verifier.required_scopes = vec!["identity:read".into()];
    value["verifier"] = serde_json::to_value(verifier).unwrap();
    std::fs::write(&file, value.to_string()).unwrap();
    let serving = crate::serving::Serving::from_owner_file(&file)
        .await
        .unwrap();
    assert_eq!(
        http_call(
            &serving,
            "GET",
            "/.well-known/oauth-protected-resource",
            None,
            ""
        )
        .await
        .0,
        200
    );
    for route in [
        "/.well-known/oauth-authorization-server",
        "/oauth/authorize",
        "/oauth/callback",
        "/oauth/token",
        "/oauth/revoke",
    ] {
        assert_eq!(
            http_call(&serving, "GET", route, None, "").await.0,
            404,
            "disabled AS exposed an endpoint"
        );
    }
}

#[test]
fn restart_before_first_rollback_detection_uses_persisted_clock_and_revokes_all_families() {
    let setup = Setup::new();
    let first = setup.pair();
    let second = setup.pair();
    let before = setup.clock.wall();
    assert!(setup.server.admit(&first.access_token).is_ok());
    assert!(setup.server.admit(&second.access_token).is_ok());
    setup.clock.0.store(before - 600, Ordering::SeqCst);
    let restarted = Server::from_config(
        serde_json::from_value(serde_json::to_value(&setup.server.config).unwrap()).unwrap(),
        setup.server.file.clone(),
        setup.server.binding.clone(),
        setup.server.scopes.clone(),
        setup.clock.clone(),
    )
    .unwrap();
    assert!(restarted.admit(&first.access_token).is_err());
    let live: i64 = setup
        .db()
        .query_row(
            "SELECT COUNT(*) FROM oauth_families WHERE revoked_at IS NULL",
            [],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(
        live, 0,
        "restart failed to detect persisted high-water rollback globally"
    );
    setup.clock.0.store(before, Ordering::SeqCst);
    assert!(restarted.admit(&second.access_token).is_err());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn slow_family_liveness_allows_disable_to_complete_and_due_tick_rate_caps_reads() {
    let setup = Setup::new();
    let pair = setup.pair();
    let (slow, callback) = events(&setup);
    let identity = slow.verifier.verify(&pair.access_token).await.unwrap();
    slow.subscribe(
        &identity,
        &pair.access_token,
        "bus",
        "gateway@bus",
        crate::events_test_support::request(),
    )
    .await
    .unwrap();
    seed(&setup, "slow-liveness");
    setup.clock.0.fetch_add(3000, Ordering::SeqCst);
    let (arrived_tx, arrived_rx) = tokio::sync::oneshot::channel();
    let arrived = std::sync::Mutex::new(Some(arrived_tx));
    let (release_tx, release_rx) = std::sync::mpsc::sync_channel(0);
    let release = std::sync::Mutex::new(release_rx);
    *setup.fake.arrival.lock().unwrap() = Some(Arc::new(move |route| {
        if route == "/v1/person/owner/_attr/memberof" {
            if let Some(tx) = arrived.lock().unwrap().take() {
                tx.send(()).unwrap();
            }
            release
                .lock()
                .unwrap()
                .recv_timeout(std::time::Duration::from_secs(5))
                .unwrap();
        }
    }));
    let slow_events = Arc::new(slow);
    let running = slow_events.clone();
    let tick =
        tokio::spawn(
            async move { crate::event_dispatch::tick(&running, "bus", "gateway@bus").await },
        );
    tokio::time::timeout(std::time::Duration::from_secs(2), arrived_rx)
        .await
        .unwrap()
        .unwrap();
    let file = setup.server.file.clone();
    let disable = tokio::task::spawn_blocking(move || {
        Store::open(&file).unwrap().set_enabled("local", 2, false)
    });
    let completed = tokio::time::timeout(std::time::Duration::from_secs(1), disable).await;
    release_tx.send(()).unwrap();
    let outcome = tick.await.unwrap().unwrap();
    assert!(
        completed.is_ok(),
        "slow liveness held operation lease or SQLite write lock"
    );
    assert_eq!(completed.unwrap().unwrap().unwrap(), 3);
    assert_ne!(outcome, crate::event_dispatch::Tick::Accepted);
    assert!(callback.events.lock().unwrap().is_empty());

    let setup = Setup::new();
    let pair = setup.pair();
    let (events, callback) = events(&setup);
    let identity = events.verifier.verify(&pair.access_token).await.unwrap();
    let mut subscription = crate::events_test_support::request();
    subscription.ttl_ms = Some(crate::events::MAX_TTL_MS);
    events
        .subscribe(
            &identity,
            &pair.access_token,
            "bus",
            "gateway@bus",
            subscription,
        )
        .await
        .unwrap();
    seed(&setup, "rate-liveness");
    callback
        .behaviors
        .lock()
        .unwrap()
        .push_back(crate::events_test_support::Behavior::Response(503, None));
    setup.clock.0.fetch_add(3900, Ordering::SeqCst);
    setup
        .fake
        .set("/v1/person/owner/_attr/memberof", 500, json!({}));
    crate::event_dispatch::tick(&events, "bus", "gateway@bus")
        .await
        .unwrap();
    assert_eq!(setup.fake.requests.lock().unwrap().len(), 5);
    assert!(
        setup
            .server
            .delivery_read_due(identity.token_family().unwrap())
            .unwrap(),
        "second tick was not actually due under grace"
    );
    setup
        .db()
        .execute("UPDATE custody_outbox SET next_attempt=0", [])
        .unwrap();
    crate::event_dispatch::tick(&events, "bus", "gateway@bus")
        .await
        .unwrap();
    assert_eq!(
        setup.fake.requests.lock().unwrap().len(),
        5,
        "second due tick repeated liveness before 300 seconds"
    );
}

#[tokio::test]
async fn hidden_legacy_jws_and_local_opaque_coexist_without_cross_grant_authority() {
    use crate::events_test_support::fixture;
    let setup = Setup::new();
    let pair = setup.pair();
    let remote = &setup.server.config.upstream.verify;
    let binding = Binding {
        service: remote.service.clone(),
        issuer: remote.issuer.clone(),
        resource: remote.resource.clone(),
        subject: remote.subject.clone(),
        hosted_client: remote.hosted_client.clone(),
    };
    let mut store = setup.server.store().unwrap();
    store.enroll("legacy", &binding).unwrap();
    store.set_enabled("legacy", 1, true).unwrap();
    let file = owner_file(&setup);
    let mut value: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&file).unwrap()).unwrap();
    let mut legacy = serde_json::to_value(remote).unwrap();
    legacy["advertised"] = json!(false);
    legacy["opaque_default"] = json!(false);
    legacy["required_scopes"] = json!(["identity:read"]);
    let mut upstream_claims = crate::provider_fixture::claims(&binding);
    upstream_claims["aud"] = json!("login");
    setup.fake.set("/introspect", 200, upstream_claims);
    value["verifier_profiles"]
        .as_array_mut()
        .unwrap()
        .push(legacy);
    std::fs::write(&file, value.to_string()).unwrap();
    let serving = crate::serving::Serving::from_owner_file(&file)
        .await
        .unwrap();
    let (_, _, prm) = http_call(
        &serving,
        "GET",
        "/.well-known/oauth-protected-resource",
        None,
        "",
    )
    .await;
    assert_eq!(
        prm["authorization_servers"],
        json!([setup.server.binding.issuer])
    );
    let claims = json!({"iss":binding.issuer,"aud":"login","client_id":"login"});
    let token = format!(
        "e30.{}.signature",
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(claims.to_string())
    );
    let request = json!({"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"xmsg_identity","arguments":{}}});
    assert_eq!(
        fixture::request(&serving, &token, request.clone()).await.0,
        200
    );
    assert_eq!(
        fixture::request(&serving, &pair.access_token, request.clone())
            .await
            .0,
        200
    );
    store.set_enabled("legacy", 2, false).unwrap();
    assert_eq!(
        fixture::request(&serving, &token, request.clone()).await.0,
        403,
        "legacy credential borrowed enabled local grant"
    );
    assert_eq!(
        fixture::request(&serving, &pair.access_token, request.clone())
            .await
            .0,
        200
    );
    store.set_enabled("legacy", 3, true).unwrap();
    store.set_enabled("local", 2, false).unwrap();
    assert_eq!(
        fixture::request(&serving, &token, request.clone()).await.0,
        200
    );
    assert_eq!(
        fixture::request(&serving, &pair.access_token, request)
            .await
            .0,
        403,
        "local credential borrowed enabled legacy grant"
    );
}

#[tokio::test]
async fn verified_foreign_login_cannot_be_mapped_to_local_owner() {
    let mut setup = Setup::new();
    let mut config: Config =
        serde_json::from_value(serde_json::to_value(&setup.server.config).unwrap()).unwrap();
    config.upstream.verify.subject = "foreign-owner".into();
    setup.fake.set("/introspect",200,json!({"active":true,"iss":"https://provider.example/issuer","aud":"login","client_id":"login","sub":"foreign-owner","scope":"openid","exp":setup.clock.wall()+3600}));
    setup.server = Server::from_config(
        config,
        setup.server.file.clone(),
        setup.server.binding.clone(),
        setup.server.scopes.clone(),
        setup.clock.clone(),
    )
    .unwrap();
    let state = begin(&setup).await;
    let reply = setup
        .server
        .handle(
            "/oauth/callback",
            "GET",
            &format!("state={state}&code=fixture-code"),
            None,
            "",
        )
        .await;
    assert!(
        reply
            .location
            .as_deref()
            .is_some_and(|u| u.contains("error=access_denied")),
        "verified foreign login gained local owner's authority"
    );
    assert_eq!(
        setup
            .db()
            .query_row("SELECT COUNT(*) FROM oauth_codes", [], |r| r
                .get::<_, i64>(0))
            .unwrap(),
        0
    );
    assert_eq!(
        setup
            .db()
            .query_row("SELECT COUNT(*) FROM oauth_families", [], |r| r
                .get::<_, i64>(0))
            .unwrap(),
        0
    );
    assert!(
        setup
            .fake
            .requests
            .lock()
            .unwrap()
            .iter()
            .any(|r| r == "/introspect"),
        "verified provider positive control missing"
    );
}

#[tokio::test]
async fn enabled_new_grant_cannot_reply_to_fenced_prior_custody() {
    let setup = Setup::new();
    let mut store = setup.server.store().unwrap();
    store
        .set_outbound_policy(
            "local",
            2,
            &crate::outbound::Policy {
                send: None,
                reply: Some(crate::outbound::Permission {
                    targets: ["sender@peer".into()].into(),
                    required_scope: "identity:read".into(),
                }),
            },
        )
        .unwrap();
    seed(&setup, "01ARZ3NDEKTSV4RRFFQ69G5FAV");
    store.set_enabled("local", 3, false).unwrap();
    store.set_enabled("local", 4, true).unwrap();
    let pair = setup.pair();
    let verifier = crate::auth::Verifier::local_only(setup.server.clone(), true);
    let identity = Arc::new(verifier.verify(&pair.access_token).await.unwrap());
    let context =
        crate::auth::VerifiedContext::new(identity.clone(), identity.admitted_authority().unwrap());
    let bus = Bus::new().await;
    let request = crate::outbound::Request::Reply(crate::outbound::ReplyArguments {
        request_id: crate::outbound::RequestId::parse("old-custody-reply").unwrap(),
        message_id: "01ARZ3NDEKTSV4RRFFQ69G5FAV".into(),
        text: "must refuse".into(),
        attachments: vec![],
    });
    let result = crate::outbound::dispatch_verified(
        &mut store,
        &bus.endpoint(),
        &verifier,
        &context,
        "bus",
        &request,
        &limits(),
    )
    .await;
    assert!(
        matches!(result, Err(crate::outbound::Error::Denied)),
        "enabled new grant revived fenced old reply target"
    );
    assert!(bus.frames.lock().unwrap().is_empty());
    assert_eq!(
        setup
            .db()
            .query_row("SELECT COUNT(*) FROM outbound_reservations", [], |r| r
                .get::<_, i64>(0))
            .unwrap(),
        0
    );
    bus.close().await;
}

#[tokio::test]
async fn actual_http_dispatch_finishes_captured_snapshot_after_committed_change() {
    use axum::{
        body::{to_bytes, Body},
        http::Request,
    };
    use tower::ServiceExt;
    use tracing::instrument::WithSubscriber;
    use tracing_subscriber::prelude::*;
    struct Commit {
        server: Arc<Server>,
        change: &'static str,
        snapshot: Arc<std::sync::Mutex<Option<i64>>>,
        order: Arc<std::sync::Mutex<Vec<&'static str>>>,
        changed: std::sync::atomic::AtomicBool,
    }
    impl<S: tracing::Subscriber> tracing_subscriber::Layer<S> for Commit {
        fn on_event(
            &self,
            event: &tracing::Event<'_>,
            _: tracing_subscriber::layer::Context<'_, S>,
        ) {
            if event.metadata().target() == "gateway_oauth_admission" {
                struct Sample(Option<i64>);
                impl tracing::field::Visit for Sample {
                    fn record_i64(&mut self, f: &tracing::field::Field, v: i64) {
                        if f.name() == "sampled_now" {
                            self.0 = Some(v)
                        }
                    }
                    fn record_debug(&mut self, _: &tracing::field::Field, _: &dyn std::fmt::Debug) {
                    }
                }
                let mut sample = Sample(None);
                event.record(&mut sample);
                *self.snapshot.lock().unwrap() = sample.0;
                self.order.lock().unwrap().push("snapshot");
            }
            if event.metadata().target() == "gateway_dispatch"
                && !self.changed.swap(true, Ordering::SeqCst)
            {
                assert!(
                    self.snapshot.lock().unwrap().is_some(),
                    "dispatch had no captured admission snapshot"
                );
                let db = rusqlite::Connection::open(&self.server.file).unwrap();
                match self.change {
                    "revoke" => {
                        db.execute("UPDATE oauth_families SET revoked_at=1,revoked_reason='revocation_endpoint'",[]).unwrap();
                    }
                    "disable" => {
                        self.server
                            .store()
                            .unwrap()
                            .set_enabled("local", 2, false)
                            .unwrap();
                    }
                    _ => {
                        db.execute("UPDATE oauth_families SET absolute_expires_at=0", [])
                            .unwrap();
                    }
                }
                self.order.lock().unwrap().push("change_committed");
            }
        }
    }
    for change in ["revoke", "disable", "expiry"] {
        let setup = Setup::new();
        let pair = setup.pair();
        let serving = crate::serving::Serving::from_owner_file(&owner_file(&setup))
            .await
            .unwrap();
        let snapshot = Arc::new(std::sync::Mutex::new(None));
        let order = Arc::new(std::sync::Mutex::new(Vec::new()));
        let layer = Commit {
            server: setup.server.clone(),
            change,
            snapshot: snapshot.clone(),
            order: order.clone(),
            changed: std::sync::atomic::AtomicBool::new(false),
        };
        let subscriber = tracing_subscriber::registry().with(layer);
        let body = json!({"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"xmsg_identity","arguments":{}}});
        let request = Request::builder()
            .method("POST")
            .uri("/mcp")
            .header("host", "gateway.example")
            .header("content-type", "application/json")
            .header("authorization", format!("Bearer {}", pair.access_token))
            .body(Body::from(body.to_string()))
            .unwrap();
        let response = serving
            .router()
            .oneshot(request)
            .with_subscriber(subscriber)
            .await
            .unwrap();
        assert_eq!(
            response.status(),
            200,
            "pre-change captured HTTP dispatch did not finish: {change}"
        );
        let response = to_bytes(response.into_body(), 100_000).await.unwrap();
        let value: serde_json::Value = serde_json::from_slice(&response).unwrap();
        assert_eq!(value["result"]["structuredContent"]["grant_revision"], 2);
        order.lock().unwrap().push("response");
        assert_eq!(
            *order.lock().unwrap(),
            ["snapshot", "change_committed", "response"]
        );
        assert!(snapshot.lock().unwrap().is_some());
        let (status, _, probe) =
            crate::events_test_support::fixture::request(&serving, &pair.access_token, body).await;
        assert_eq!(status, if change == "disable" { 403 } else { 401 });
        assert_eq!(
            probe.dispatches.load(Ordering::SeqCst),
            0,
            "post-change HTTP request dispatched"
        );
    }
}

#[tokio::test]
async fn refresh_of_successor_does_not_implicitly_revoke_its_unused_access() {
    let setup = Setup::new();
    let a = setup.pair();
    let b = setup.server.refresh(&a.refresh_token).await.unwrap();
    setup.clock.0.fetch_add(2, Ordering::SeqCst);
    let c = setup.server.refresh(&b.refresh_token).await.unwrap();
    let original_used: i64 = setup
        .db()
        .query_row(
            "SELECT successor_used_at FROM oauth_refresh_tokens WHERE hash=?1",
            [hash(&a.refresh_token)],
            |r| r.get(0),
        )
        .unwrap();
    setup.clock.0.fetch_add(7, Ordering::SeqCst);
    assert!(setup.server.admit(&c.access_token).is_ok());
    assert!(
        setup.server.admit(&b.access_token).is_ok(),
        "ordinary refresh implicitly invalidated unrevoked access token"
    );
    assert_eq!(
        setup
            .db()
            .query_row(
                "SELECT successor_used_at FROM oauth_refresh_tokens WHERE hash=?1",
                [hash(&a.refresh_token)],
                |r| r.get::<_, i64>(0)
            )
            .unwrap(),
        original_used,
        "idempotent predecessor mark replaced its original timestamp"
    );
}

#[test]
fn first_use_upgrade_rechecks_now_before_marking_access() {
    let setup = Setup::new();
    let pair = setup.pair();
    let before = setup.clock.wall();
    setup
        .db()
        .execute(
            "UPDATE oauth_families SET absolute_expires_at=?1",
            [before + 10],
        )
        .unwrap();
    let clock = setup.clock.clone();
    *setup.server.upgrade_barrier.lock().unwrap() = Some(Arc::new(move || {
        clock.0.store(before + 11, Ordering::SeqCst);
    }));
    assert!(
        setup.server.admit(&pair.access_token).is_err(),
        "mark reused read-transaction time after absolute expiry"
    );
    let used: Option<i64> = setup
        .db()
        .query_row("SELECT first_used_at FROM oauth_access_tokens", [], |r| {
            r.get(0)
        })
        .unwrap();
    assert_eq!(used, None, "refused expired upgrade marked access used");
}

#[tokio::test]
async fn eleven_rotations_plus_retry_fill_the_twelve_per_hour_budget() {
    let setup = Setup::new();
    let mut pair = setup.pair();
    let mut predecessor = pair.refresh_token.clone();
    for _ in 0..11 {
        predecessor = pair.refresh_token.clone();
        pair = setup.server.refresh(&predecessor).await.unwrap();
    }
    let retry = setup.server.refresh(&predecessor).await.unwrap();
    assert_eq!(
        setup
            .db()
            .query_row("SELECT COUNT(*) FROM oauth_rotation_log", [], |r| r
                .get::<_, i64>(0))
            .unwrap(),
        12
    );
    assert!(
        matches!(
            setup.server.refresh(&retry.refresh_token).await,
            Err(Error::RateLimited)
        ),
        "retry did not consume rolling rotation budget"
    );
    let rotated: Option<i64> = setup
        .db()
        .query_row(
            "SELECT rotated_at FROM oauth_refresh_tokens WHERE hash=?1",
            [hash(&retry.refresh_token)],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(rotated, None, "rate refusal consumed current refresh token");
}

#[tokio::test]
async fn suppressed_predecessor_mark_refuses_and_rolls_back_first_use() {
    let setup = Setup::new();
    let a = setup.pair();
    let b = setup.server.refresh(&a.refresh_token).await.unwrap();
    setup.db().execute_batch("CREATE TRIGGER suppress_successor_mark BEFORE UPDATE OF successor_used_at ON oauth_refresh_tokens BEGIN SELECT RAISE(IGNORE); END;").unwrap();
    assert!(
        setup.server.admit(&b.access_token).is_err(),
        "suppressed predecessor write was admitted despite zero changed rows"
    );
    let used: Option<i64> = setup
        .db()
        .query_row(
            "SELECT first_used_at FROM oauth_access_tokens WHERE hash=?1",
            [hash(&b.access_token)],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(
        used, None,
        "refused predecessor write partially marked access first use"
    );
    setup
        .db()
        .execute_batch("DROP TRIGGER suppress_successor_mark;")
        .unwrap();
    assert!(
        setup.server.admit(&b.access_token).is_ok(),
        "ordinary predecessor mark positive control failed"
    );
}

#[tokio::test]
async fn rollback_between_liveness_ticket_claims_revokes_without_second_network_read() {
    let setup = Setup::new();
    let pair = setup.pair();
    let family = setup.server.admit(&pair.access_token).unwrap().family;
    setup.server.check_liveness(&family, false).await.unwrap();
    assert_eq!(setup.fake.requests.lock().unwrap().len(), 5);
    let evidence: i64 = setup
        .db()
        .query_row("SELECT liveness_ok_at FROM oauth_families", [], |r| {
            r.get(0)
        })
        .unwrap();
    setup.clock.0.fetch_sub(600, Ordering::SeqCst);
    assert!(
        setup.server.check_liveness(&family, false).await.is_err(),
        "rollback ticket claim proceeded"
    );
    assert_eq!(
        setup.fake.requests.lock().unwrap().len(),
        5,
        "rollback claim performed network read"
    );
    let row: (Option<String>, i64) = setup
        .db()
        .query_row(
            "SELECT revoked_reason,liveness_ok_at FROM oauth_families",
            [],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .unwrap();
    assert_eq!(row, (Some("clock_rollback".into()), evidence));
}

#[tokio::test]
async fn dispatcher_positive_mints_no_access_and_negative_revokes_without_send_or_credential_park()
{
    for negative in [false, true] {
        let setup = Setup::new();
        let pair = setup.pair();
        let (events, callback) = events(&setup);
        let identity = events.verifier.verify(&pair.access_token).await.unwrap();
        let mut request = crate::events_test_support::request();
        request.ttl_ms = Some(crate::events::MAX_TTL_MS);
        events
            .subscribe(&identity, &pair.access_token, "bus", "gateway@bus", request)
            .await
            .unwrap();
        seed(&setup, "dispatcher-evidence");
        let before: i64 = setup
            .db()
            .query_row("SELECT COUNT(*) FROM oauth_access_tokens", [], |r| r.get(0))
            .unwrap();
        setup.clock.0.fetch_add(3600, Ordering::SeqCst);
        if negative {
            setup
                .fake
                .set("/v1/person/owner/_attr/memberof", 200, json!([]));
        }
        let tick = crate::event_dispatch::tick(&events, "bus", "gateway@bus")
            .await
            .unwrap();
        assert_eq!(
            setup
                .db()
                .query_row("SELECT COUNT(*) FROM oauth_access_tokens", [], |r| r
                    .get::<_, i64>(0))
                .unwrap(),
            before,
            "dispatcher minted access token"
        );
        let state: (String, Option<String>) = setup
            .db()
            .query_row("SELECT state,last_error FROM custody_outbox", [], |r| {
                Ok((r.get(0)?, r.get(1)?))
            })
            .unwrap();
        assert_ne!(state.1.as_deref(), Some("credential_required"));
        if negative {
            assert_eq!(tick, crate::event_dispatch::Tick::Expired);
            assert!(callback.events.lock().unwrap().is_empty());
            assert_eq!(state.0, "pending");
            assert_eq!(
                setup
                    .db()
                    .query_row("SELECT revoked_reason FROM oauth_families", [], |r| r
                        .get::<_, Option<String>>(0))
                    .unwrap(),
                Some("kanidm_denied".into())
            );
        } else {
            assert_eq!(tick, crate::event_dispatch::Tick::Accepted);
            assert_eq!(callback.events.lock().unwrap().len(), 1);
            assert_eq!(
                setup
                    .db()
                    .query_row("SELECT liveness_ok_at FROM oauth_families", [], |r| r
                        .get::<_, i64>(0))
                    .unwrap(),
                setup.clock.wall()
            );
        }
    }
}

#[tokio::test]
async fn every_oauth_error_redirect_omits_issuer_parameter() {
    for scenario in [
        "authorize-invalid",
        "authorize-denied",
        "callback-user-denied",
        "callback-inactive",
        "callback-unavailable",
    ] {
        let setup = Setup::new();
        let reply = match scenario {
            "authorize-invalid" => {
                setup
                    .server
                    .handle(
                        "/oauth/authorize",
                        "GET",
                        &authorize_query()
                            .replace("code_challenge_method=S256", "code_challenge_method=plain"),
                        None,
                        "",
                    )
                    .await
            }
            "authorize-denied" => {
                setup
                    .server
                    .store()
                    .unwrap()
                    .set_enabled("local", 2, false)
                    .unwrap();
                setup
                    .server
                    .handle("/oauth/authorize", "GET", &authorize_query(), None, "")
                    .await
            }
            _ => {
                let state = begin(&setup).await;
                if scenario == "callback-inactive" {
                    setup.fake.set("/introspect", 200, json!({"active":false}));
                }
                if scenario == "callback-unavailable" {
                    setup
                        .fake
                        .set("/v1/person/owner/_attr/memberof", 500, json!({}));
                }
                let query = if scenario == "callback-user-denied" {
                    format!("state={state}&error=access_denied")
                } else {
                    format!("state={state}&code=fixture-code")
                };
                setup
                    .server
                    .handle("/oauth/callback", "GET", &query, None, "")
                    .await
            }
        };
        assert_eq!(
            reply.status, 302,
            "error did not reach redirect arm: {scenario}"
        );
        let url = reqwest::Url::parse(reply.location.as_deref().unwrap()).unwrap();
        assert!(
            url.query_pairs().any(|(k, _)| k == "error"),
            "error positive control missing: {scenario}"
        );
        assert!(
            !url.query_pairs().any(|(k, _)| k == "iss"),
            "OAuth error redirect included issuer: {scenario}"
        );
    }
}

#[test]
fn failed_clock_revoke_write_stays_pending_through_catchup_and_repeated_sql_errors() {
    for scenario in ["retry-below", "catchup", "catchup-write-fails-again"] {
        let setup = Setup::new();
        let pair = setup.pair();
        let at = setup.clock.wall();
        assert!(setup.server.admit(&pair.access_token).is_ok());
        let blocker = setup.db();
        blocker.execute_batch("BEGIN IMMEDIATE").unwrap();
        let writer = setup.db();
        writer.busy_timeout(std::time::Duration::ZERO).unwrap();
        assert_eq!(
            writer
                .query_row("SELECT value FROM clock_hw", [], |r| r.get::<_, i64>(0))
                .unwrap(),
            at
        );
        setup.clock.0.store(at - 600, Ordering::SeqCst);
        assert!(
            matches!(
                setup.server.clock.observe(&writer, true),
                Err(Error::Database(_))
            ),
            "forced busy revoke write was not exercised"
        );
        if scenario == "catchup-write-fails-again" {
            setup.clock.0.store(at, Ordering::SeqCst);
            assert!(
                matches!(
                    setup.server.clock.observe(&writer, true),
                    Err(Error::Database(_))
                ),
                "pending revoke was cleared during second busy write"
            );
        }
        blocker.execute_batch("ROLLBACK").unwrap();
        assert_eq!(
            setup
                .db()
                .query_row("SELECT revoked_reason FROM oauth_families", [], |r| r
                    .get::<_, Option<String>>(0))
                .unwrap(),
            None,
            "failed write unexpectedly revoked family"
        );
        if scenario == "retry-below" {
            setup.server.clock.observe(&writer, true).unwrap();
        }
        setup.clock.0.store(at, Ordering::SeqCst);
        assert!(
            setup.server.admit(&pair.access_token).is_err(),
            "detected rollback forgotten after failed revoke write and catchup: {scenario}"
        );
        assert_eq!(
            setup
                .db()
                .query_row("SELECT revoked_reason FROM oauth_families", [], |r| r
                    .get::<_, Option<String>>(0))
                .unwrap()
                .as_deref(),
            Some("clock_rollback")
        );
        setup.clock.0.store(at - 3, Ordering::SeqCst);
        assert!(
            setup.server.clock.mint(&writer).is_ok(),
            "completed catchup left stale durable fault marker"
        );
    }
}

#[test]
fn failed_clock_marker_write_rolls_back_global_revoke_and_retries_after_catchup() {
    let setup = Setup::new();
    let pair = setup.pair();
    let at = setup.clock.wall();
    setup.db().execute_batch("CREATE TRIGGER fail_clock_marker BEFORE UPDATE ON clock_hw WHEN NEW.rollback_until>0 BEGIN SELECT RAISE(ABORT,'fixture suppressed clock marker'); END;").unwrap();
    setup.clock.0.store(at - 600, Ordering::SeqCst);
    assert!(
        matches!(
            setup.server.clock.observe(&setup.db(), true),
            Err(Error::Database(_))
        ),
        "marker-write failure control did not fire"
    );
    assert_eq!(
        setup
            .db()
            .query_row("SELECT revoked_at FROM oauth_families", [], |r| r
                .get::<_, Option<i64>>(0))
            .unwrap(),
        None,
        "failed clock transaction partially revoked family"
    );
    setup
        .db()
        .execute_batch("DROP TRIGGER fail_clock_marker;")
        .unwrap();
    setup.clock.0.store(at, Ordering::SeqCst);
    assert!(
        setup.server.admit(&pair.access_token).is_err(),
        "failed marker write lost pending family revocation"
    );
    let row: (Option<String>, i64) = setup
        .db()
        .query_row(
            "SELECT f.revoked_reason,c.rollback_until FROM oauth_families f CROSS JOIN clock_hw c",
            [],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .unwrap();
    assert_eq!(row, (Some("clock_rollback".into()), 0));
}

#[test]
fn handled_stale_clock_observer_never_revokes_a_post_catchup_new_family() {
    let setup = Setup::new();
    let old = setup.pair();
    let at = setup.clock.wall();
    assert!(setup.server.admit(&old.access_token).is_ok());
    setup.clock.0.store(at - 600, Ordering::SeqCst);
    let (entered_tx, entered_rx) = std::sync::mpsc::sync_channel(0);
    let (release_tx, release_rx) = std::sync::mpsc::sync_channel(0);
    let release = std::sync::Mutex::new(release_rx);
    let server = setup.server.clone();
    let worker = std::thread::spawn(move || {
        server.clock.set_revoke_hook(Arc::new(move || {
            entered_tx.send(()).unwrap();
            release
                .lock()
                .unwrap()
                .recv_timeout(std::time::Duration::from_secs(5))
                .unwrap();
        }));
        server
            .clock
            .observe(&server.store().unwrap().connection, true)
    });
    entered_rx
        .recv_timeout(std::time::Duration::from_secs(5))
        .unwrap();
    setup.server.clock.observe(&setup.db(), true).unwrap();
    setup.clock.0.store(at, Ordering::SeqCst);
    setup.server.clock.observe(&setup.db(), true).unwrap();
    let fresh = setup.pair();
    assert!(
        setup.server.admit(&fresh.access_token).is_ok(),
        "post-catchup reconnect positive control failed"
    );
    release_tx.send(()).unwrap();
    assert!(worker.join().unwrap().is_ok());
    assert!(
        setup.server.admit(&fresh.access_token).is_ok(),
        "stale handled rollback observer revoked post-catchup fresh family"
    );
    assert!(setup.server.admit(&old.access_token).is_err());
    assert_eq!(
        setup
            .db()
            .query_row(
                "SELECT COUNT(*) FROM oauth_families WHERE revoked_at IS NULL",
                [],
                |r| r.get::<_, i64>(0)
            )
            .unwrap(),
        1
    );
    assert_eq!(
        setup
            .db()
            .query_row("SELECT rollback_until FROM clock_hw", [], |r| r
                .get::<_, i64>(0))
            .unwrap(),
        0,
        "stale observer restored handled fault marker"
    );
}

#[tokio::test]
async fn registered_redirects_reject_decoded_oauth_query_collisions_and_preserve_other_queries() {
    for key in [
        "code",
        "state",
        "iss",
        "error",
        "error_description",
        "error_uri",
        "co%64e",
        "%73tate",
        "i%73s",
        "%65rror",
        "error%5fdescription",
        "error%5Furi",
    ] {
        let setup = Setup::new();
        let file = owner_file(&setup);
        let mut value: serde_json::Value =
            serde_json::from_slice(&std::fs::read(&file).unwrap()).unwrap();
        value["authorization_server"]["client"]["redirect_uris"] = json!([format!(
            "https://chat.example/callback?tenant=one&{key}=existing"
        )]);
        std::fs::write(&file, value.to_string()).unwrap();
        let before = std::fs::read(&setup.server.file).unwrap();
        assert!(
            crate::serving::Serving::from_owner_file(&file)
                .await
                .is_err(),
            "reserved decoded OAuth redirect query key accepted: {key}"
        );
        assert_eq!(
            std::fs::read(&setup.server.file).unwrap(),
            before,
            "startup refusal wrote authority state"
        );
    }
    let mut setup = Setup::new();
    let registered = "https://chat.example/callback?tenant=one%2Ftwo&lang=en";
    let mut config: Config =
        serde_json::from_value(serde_json::to_value(&setup.server.config).unwrap()).unwrap();
    config.client.redirect_uris = vec![registered.into()];
    setup.server = Server::from_config(
        config,
        setup.server.file.clone(),
        setup.server.binding.clone(),
        setup.server.scopes.clone(),
        setup.clock.clone(),
    )
    .unwrap();
    let mut url = reqwest::Url::parse("https://form.invalid").unwrap();
    url.set_query(Some(&authorize_query()));
    let fields: Vec<_> = url
        .query_pairs()
        .map(|(k, v)| (k.into_owned(), v.into_owned()))
        .collect();
    url.set_query(None);
    for (key, value) in fields {
        url.query_pairs_mut().append_pair(
            &key,
            if key == "redirect_uri" {
                registered
            } else {
                &value
            },
        );
    }

    for error in [false, true] {
        let reply = setup
            .server
            .handle("/oauth/authorize", "GET", url.query().unwrap(), None, "")
            .await;
        assert_eq!(reply.status, 302);
        let upstream = reqwest::Url::parse(reply.location.as_deref().unwrap()).unwrap();
        let state = upstream
            .query_pairs()
            .find(|(k, _)| k == "state")
            .unwrap()
            .1
            .into_owned();
        let query = if error {
            format!("state={state}&error=access_denied")
        } else {
            format!("state={state}&code=fixture-code")
        };
        let reply = setup
            .server
            .handle("/oauth/callback", "GET", &query, None, "")
            .await;
        assert_eq!(reply.status, 302);
        let destination = reqwest::Url::parse(reply.location.as_deref().unwrap()).unwrap();
        assert!(
            destination.as_str().starts_with(registered),
            "registered noncolliding query was normalized or discarded"
        );
        assert!(destination
            .query_pairs()
            .any(|(k, v)| k == "tenant" && v == "one/two"));
        assert!(destination
            .query_pairs()
            .any(|(k, v)| k == "lang" && v == "en"));
        assert!(destination
            .query_pairs()
            .any(|(k, _)| k == if error { "error" } else { "code" }));
        assert!(!destination.query_pairs().any(|(k, _)| k == "iss"));
    }
}

#[tokio::test]
async fn consent_and_canary_membership_never_enter_liveness_requests_or_authority() {
    for consent in [serde_json::Value::Null, json!([]), json!(["removed"])] {
        let setup = Setup::new();
        let pair = setup.pair();
        setup.fake.set(
            "/v1/person/owner/_attr/oauth2_consent_scope_map",
            200,
            consent,
        );
        setup
            .fake
            .set("/v1/person/canary/_attr/memberof", 200, json!([]));
        assert_eq!(
            setup.server.liveness.read(setup.clock.wall()).await,
            Outcome::Positive,
            "irrelevant consent or canary membership denied passing owner"
        );
        let requests = setup.fake.requests.lock().unwrap().clone();
        assert_eq!(
            requests.len(),
            5,
            "liveness read forbidden consent/canary membership attribute"
        );
        assert!(requests
            .iter()
            .all(|r| !r.contains("consent") && r != "/v1/person/canary/_attr/memberof"));
        setup.clock.0.fetch_add(3600, Ordering::SeqCst);
        let refreshed = setup.server.refresh(&pair.refresh_token).await;
        assert!(
            refreshed.is_ok(),
            "irrelevant consent or canary membership refused passing refresh"
        );
        assert_eq!(refreshed.unwrap().expires_in, 3600);
    }
    let setup = Setup::new();
    setup.fake.set(
        "/v1/person/canary/_attr/memberof",
        200,
        json!(["login.access@test"]),
    );
    setup
        .fake
        .set("/v1/person/owner/_attr/memberof", 200, json!([]));
    assert_eq!(
        setup.server.liveness.read(setup.clock.wall()).await,
        Outcome::Negative,
        "canary membership authorized denying owner"
    );
}

#[tokio::test]
async fn common_liveness_application_uses_network_observation_start_not_completion() {
    let setup = Setup::new();
    let pair = setup.pair();
    setup.clock.0.fetch_add(20, Ordering::SeqCst);
    let started = setup.clock.wall();
    let completed = started + 123;
    let clock = setup.clock.clone();
    *setup.fake.arrival.lock().unwrap() = Some(Arc::new(move |route| {
        if route == "/v1/person/owner/_attr/memberof" {
            clock.0.store(completed, Ordering::SeqCst);
        }
    }));
    let refreshed = setup.server.refresh(&pair.refresh_token).await.unwrap();
    assert_eq!(
        setup.clock.wall(),
        completed,
        "network completion clock control did not fire"
    );
    assert_eq!(setup.fake.requests.lock().unwrap().len(), 5);
    let row: (i64, i64) = setup
        .db()
        .query_row(
            "SELECT liveness_ok_at,access_expires_at FROM oauth_families",
            [],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .unwrap();
    assert_eq!(
        row.0, started,
        "common liveness applied completion time instead of observation start"
    );
    assert_eq!(row.1, started + 3600);
    assert_eq!(refreshed.expires_in, 3600 - 123);
}

async fn local_as_attachment_union_case(scenario: &'static str) {
    let setup = Setup::new();
    setup.server.store().unwrap().migrate_attachments().unwrap();
    let pair = setup.pair();
    let verifier = crate::auth::Verifier::local_only(setup.server.clone(), true);
    let identity = Arc::new(verifier.verify(&pair.access_token).await.unwrap());
    let context =
        crate::auth::VerifiedContext::new(identity.clone(), identity.admitted_authority().unwrap());
    seed(&setup, "local-file");
    let reference = json!({"name":"file.txt","size":4,"media_type":"text/plain","sha256":format!("{:x}",Sha256::digest(b"file"))});
    setup
        .db()
        .execute(
            "UPDATE custody_items SET attachments=?1",
            [json!([reference]).to_string()],
        )
        .unwrap();
    let bus = Bus::new().await;
    let file = setup.server.file.clone();
    let change = move || {
        let mut store = Store::open(&file).unwrap();
        if scenario.ends_with("disable") {
            store.set_enabled("local", 2, false).unwrap();
        } else {
            store
                .set_outbound_policy("local", 2, &send_policy("receiver@peer"))
                .unwrap();
            rusqlite::Connection::open(&file)
                .unwrap()
                .execute("UPDATE event_authorizations SET dispatch_revision=3", [])
                .unwrap();
        }
    };
    if scenario.starts_with("pre") {
        change();
    } else if scenario.starts_with("post") {
        *bus.on_attachment_read.lock().unwrap() = Some(Box::new(change));
    }
    let result = crate::attachments::read(
        setup.server.store().unwrap(),
        &context,
        &bus.endpoint(),
        "bus",
        "gateway@bus",
        crate::attachments::ReadArguments {
            message_id: "local-file".into(),
            index: 0,
            offset: None,
            limit: None,
        },
    )
    .await;
    if scenario == "valid" {
        assert_eq!(
            result.unwrap()["data"],
            "file",
            "valid local AS attachment body was not readable"
        );
    } else {
        assert!(
            matches!(
                result,
                Err(crate::outbound::Error::Denied
                    | crate::outbound::Error::Authority(crate::grants::Error::Denied))
            ),
            "local AS attachment read returned body under changed custody authority: {scenario}"
        );
    }
    let reads = bus
        .frames
        .lock()
        .unwrap()
        .iter()
        .filter(|f| f["action"] == "read_attachment")
        .count();
    assert_eq!(
        reads,
        usize::from(!scenario.starts_with("pre")),
        "attachment pre-effect guard did not prevent bus read"
    );
    assert_eq!(
        setup
            .db()
            .pragma_query_value(None, "user_version", |r| r.get::<_, i64>(0))
            .unwrap(),
        5
    );
    bus.close().await;
}
#[tokio::test]
async fn local_as_attachment_union_preserves_success_and_pre_effect_custody_fence() {
    for scenario in ["valid", "pre-disable", "pre-revision"] {
        local_as_attachment_union_case(scenario).await;
    }
}
#[tokio::test]
async fn local_as_attachment_union_rechecks_custody_after_bus_read() {
    for scenario in ["post-disable", "post-revision"] {
        local_as_attachment_union_case(scenario).await;
    }
}
