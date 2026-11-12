use super::*;
use rusqlite::types::ValueRef;
use std::collections::BTreeMap;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Evidence {
    Positive,
    Unavailable,
    Indeterminate,
    Negative,
}

#[derive(Clone, Copy, Debug)]
enum Action {
    Advance(i64),
    Set(Evidence),
    Refresh,
    Retry,
    Admit,
    Superseded,
    Tick,
    Revoke,
    ToggleGrant,
}

struct Previous {
    refresh: String,
    rotated_at: i64,
    used: bool,
    retried: bool,
}

struct Model {
    family: String,
    current: Pair,
    previous: Option<Previous>,
    superseded: Vec<String>,
    now: i64,
    positive_at: i64,
    refreshed: i64,
    access_end: i64,
    absolute: i64,
    outcome: Evidence,
    provider: Evidence,
    revoked: Option<&'static str>,
    grant_enabled: bool,
    revision: i64,
    dispatch_read: Option<i64>,
}

impl Model {
    fn active(&self) -> bool {
        self.revoked.is_none()
            && self.grant_enabled
            && self.now < self.absolute
            && self.now < self.refreshed + 86400
    }

    fn observe(&mut self) {
        if self.provider == Evidence::Negative {
            self.revoked.get_or_insert("kanidm_denied");
        } else {
            self.outcome = self.provider;
            if self.provider == Evidence::Positive {
                self.positive_at = self.now;
            }
        }
    }

    fn mint_end(&self) -> Option<i64> {
        if !self.active() {
            return None;
        }
        let graced = self.outcome != Evidence::Positive;
        let end = if graced {
            (self.now + 3600).min(self.positive_at + 3600 + 900)
        } else {
            self.positive_at + 3600
        }
        .min(self.absolute);
        (end > self.now && (!graced || end > self.now + 60)).then_some(end)
    }

    fn delivery_end(&self) -> i64 {
        self.access_end
            .max(
                self.positive_at
                    + 3600
                    + if self.outcome == Evidence::Positive {
                        0
                    } else {
                        900
                    },
            )
            .min(self.refreshed + 86400)
            .min(self.absolute)
    }

    fn check(&self, setup: &Setup, seed: u64, step: usize) {
        let row: (i64, i64, i64, String, Option<String>) = setup.db().query_row(
            "SELECT liveness_ok_at,last_refresh_at,access_expires_at,last_liveness_outcome,revoked_reason FROM oauth_families WHERE id=?1",
            [&self.family],
            |r| Ok((r.get(0)?,r.get(1)?,r.get(2)?,r.get(3)?,r.get(4)?)),
        ).unwrap();
        assert_eq!(
            row.0, self.positive_at,
            "seed={seed:x} step={step}: observation start drift"
        );
        assert_eq!(
            row.1, self.refreshed,
            "seed={seed:x} step={step}: idle timestamp drift"
        );
        assert_eq!(
            row.2, self.access_end,
            "seed={seed:x} step={step}: last access bound drift"
        );
        let outcome = match self.outcome {
            Evidence::Positive => "positive",
            Evidence::Unavailable => "unavailable",
            Evidence::Indeterminate => "indeterminate",
            Evidence::Negative => unreachable!(),
        };
        assert_eq!(
            row.3, outcome,
            "seed={seed:x} step={step}: latest evidence drift"
        );
        assert_eq!(
            row.4.as_deref(),
            self.revoked,
            "seed={seed:x} step={step}: revocation drift"
        );
        let (current, retained): (i64, i64) = setup.db().query_row(
            "SELECT SUM(rotated_at IS NULL AND superseded_at IS NULL), SUM(rotated_at IS NOT NULL OR superseded_at IS NOT NULL) FROM oauth_refresh_tokens WHERE family_id=?1",
            [&self.family], |r| Ok((r.get(0)?,r.get(1)?)),
        ).unwrap();
        assert_eq!(
            current, 1,
            "seed={seed:x} step={step}: not exactly one current refresh row"
        );
        assert!(
            retained <= 8,
            "seed={seed:x} step={step}: retained refresh bound escaped"
        );
    }
}

fn count(stats: &mut BTreeMap<&'static str, u64>, key: &'static str) {
    *stats.entry(key).or_default() += 1;
}

fn rows(db: &rusqlite::Connection, table: &str) -> i64 {
    db.query_row(&format!("SELECT COUNT(*) FROM {table}"), [], |r| r.get(0))
        .unwrap()
}

fn all_rows_digest(db: &rusqlite::Connection) -> [u8; 32] {
    let tables = db
        .prepare("SELECT name FROM sqlite_master WHERE type='table' ORDER BY name")
        .unwrap()
        .query_map([], |r| r.get::<_, String>(0))
        .unwrap()
        .collect::<Result<Vec<_>, _>>()
        .unwrap();
    let mut digest = Sha256::new();
    for table in tables {
        digest.update((table.len() as u64).to_le_bytes());
        digest.update(table.as_bytes());
        let mut statement = db
            .prepare(&format!(
                "SELECT * FROM \"{}\" ORDER BY rowid",
                table.replace('"', "\"\"")
            ))
            .unwrap();
        let columns = statement.column_count();
        let mut values = statement.query([]).unwrap();
        while let Some(row) = values.next().unwrap() {
            digest.update([255]);
            for column in 0..columns {
                match row.get_ref(column).unwrap() {
                    ValueRef::Null => digest.update([0]),
                    ValueRef::Integer(n) => {
                        digest.update([1]);
                        digest.update(n.to_le_bytes());
                    }
                    ValueRef::Real(n) => {
                        digest.update([2]);
                        digest.update(n.to_bits().to_le_bytes());
                    }
                    ValueRef::Text(value) | ValueRef::Blob(value) => {
                        digest.update([
                            if matches!(row.get_ref(column).unwrap(), ValueRef::Text(_)) {
                                3
                            } else {
                                4
                            },
                        ]);
                        digest.update((value.len() as u64).to_le_bytes());
                        digest.update(value);
                    }
                }
            }
        }
    }
    digest.finalize().into()
}

fn provider(setup: &Setup, evidence: Evidence) {
    setup.fake.set("/v1/person/owner", 200, json!({"attrs":{}}));
    setup
        .fake
        .set("/v1/person/canary", 200, json!({"attrs":{}}));
    liveness_row(setup, ['P'; 3], 'P');
    match evidence {
        Evidence::Positive => {}
        Evidence::Unavailable => {
            setup
                .fake
                .set("/v1/person/owner/_attr/account_expire", 503, json!({}))
        }
        Evidence::Indeterminate => setup.fake.set(
            "/v1/person/canary/_attr/account_expire",
            200,
            serde_json::Value::Null,
        ),
        Evidence::Negative => setup
            .fake
            .set("/v1/person/owner/_attr/memberof", 200, json!([])),
    }
}

fn random(state: &mut u64) -> u64 {
    *state ^= *state << 13;
    *state ^= *state >> 7;
    *state ^= *state << 17;
    *state
}

fn schedule(seed: u64) -> Vec<Action> {
    let mut actions = vec![
        Action::Tick,
        Action::Advance(3100),
        Action::Set(Evidence::Unavailable),
        Action::Tick,
        Action::Refresh,
        Action::Advance(30),
        Action::Retry,
        Action::Superseded,
        Action::Set(Evidence::Positive),
        Action::Refresh,
        Action::Admit,
        Action::Advance(300),
        Action::Tick,
    ];
    let mut rng = seed;
    while actions.len() < 61 {
        let value = random(&mut rng);
        actions.push(match value % 9 {
            0 => Action::Advance([0, 1, 29, 300, 600, 3100, 4500][(value >> 8) as usize % 7]),
            1 => Action::Set(
                [
                    Evidence::Positive,
                    Evidence::Unavailable,
                    Evidence::Indeterminate,
                    Evidence::Negative,
                ][(value >> 8) as usize % 4],
            ),
            2 => Action::Refresh,
            3 => Action::Retry,
            4 => Action::Admit,
            5 => Action::Superseded,
            6 => Action::Tick,
            7 => Action::Revoke,
            _ => Action::ToggleGrant,
        });
    }
    actions.extend([
        Action::Revoke,
        Action::Set(Evidence::Positive),
        Action::Refresh,
    ]);
    actions
}

struct Epoch {
    setup: Setup,
    model: Model,
    events: crate::events::Events,
    callback: Arc<crate::events_test_support::Callback>,
}

async fn fresh_authorized_epoch() -> Epoch {
    let mut setup = Setup::new();
    {
        let server = Arc::get_mut(&mut setup.server).unwrap();
        server.config.refresh_idle_secs = 86400;
        server.config.refresh_absolute_secs = 86400;
        server.config.rotations_per_hour = 512;
        server.config.max_refresh_rows = 8;
    }
    let now = setup.clock.wall();
    let first = setup.pair();
    let family = setup
        .db()
        .query_row(
            "SELECT family_id FROM oauth_access_tokens WHERE hash=?1",
            [hash(&first.access_token)],
            |r| r.get(0),
        )
        .unwrap();
    let model = Model {
        family,
        current: first,
        previous: None,
        superseded: vec![],
        now,
        positive_at: now,
        refreshed: now,
        access_end: now + 3600,
        absolute: now + 86400,
        outcome: Evidence::Positive,
        provider: Evidence::Positive,
        revoked: None,
        grant_enabled: true,
        revision: 2,
        dispatch_read: None,
    };
    let (events, callback) = events(&setup);
    let verifier = crate::auth::Verifier::local_only(setup.server.clone(), true);
    let identity = verifier.verify(&model.current.access_token).await.unwrap();
    let mut request = crate::events_test_support::request();
    request.ttl_ms = Some(crate::events::MAX_TTL_MS);
    events
        .subscribe(
            &identity,
            &model.current.access_token,
            "bus",
            "gateway@bus",
            request,
        )
        .await
        .unwrap();
    Epoch {
        setup,
        model,
        events,
        callback,
    }
}

#[tokio::test]
async fn seeded_mixed_family_schedules_match_independent_bounds_and_never_revive_dead_state() {
    let mut total = BTreeMap::new();
    for seed_value in [0x1ad5_00a1, 0x5eed_0013, 0xc0ff_ee53, 0x9e37_79b9] {
        let mut epoch = fresh_authorized_epoch().await;
        let mut stats = BTreeMap::new();
        count(&mut stats, "authorized_epoch");
        for (step, action) in schedule(seed_value).into_iter().enumerate() {
            if !epoch.model.active() {
                provider(&epoch.setup, Evidence::Positive);
                if !epoch.model.grant_enabled {
                    let mut store = epoch.setup.server.store().unwrap();
                    store
                        .set_enabled("local", epoch.model.revision, true)
                        .unwrap();
                    count(&mut stats, "reenable_dead_epoch");
                }
                assert!(
                    epoch
                        .setup
                        .server
                        .admit(&epoch.model.current.access_token)
                        .is_err(),
                    "dead epoch admitted after positive evidence/re-enable"
                );
                assert!(epoch
                    .setup
                    .server
                    .refresh(&epoch.model.current.refresh_token)
                    .await
                    .is_err());
                epoch.setup.server.effective_now().unwrap();
                let before = all_rows_digest(&epoch.setup.db());
                let calls = epoch.setup.fake.requests.lock().unwrap().len();
                assert!(
                    epoch
                        .setup
                        .server
                        .refresh(&epoch.model.current.refresh_token)
                        .await
                        .is_err(),
                    "dead epoch refresh revived after positive evidence/re-enable"
                );
                assert_eq!(
                    all_rows_digest(&epoch.setup.db()),
                    before,
                    "dead epoch probe wrote SQLite state"
                );
                assert_eq!(
                    epoch.setup.fake.requests.lock().unwrap().len(),
                    calls,
                    "dead epoch called upstream liveness"
                );
                count(&mut stats, "terminal_admit_refused");
                count(&mut stats, "terminal_refresh_refused");
                count(&mut stats, "terminal_refresh_refused");
                count(&mut stats, "terminal_no_revival");
                epoch = fresh_authorized_epoch().await;
                count(&mut stats, "authorized_epoch");
            }
            let Epoch {
                setup,
                model,
                events,
                callback,
            } = &mut epoch;
            assert!(
                model.active(),
                "seed={seed_value:x} step={step}: tail resumed without fresh authorization"
            );
            count(&mut stats, "live_action");
            let before_stats = stats.clone();
            let calls = setup.fake.requests.lock().unwrap().len();
            let mut expected_reads = 0;
            match action {
                Action::Advance(seconds) => {
                    count(&mut stats, "advance");
                    model.now += seconds;
                    setup.clock.0.store(model.now, Ordering::SeqCst);
                }
                Action::Set(mode) => {
                    count(&mut stats, "provider_change");
                    model.provider = mode;
                    provider(setup, mode);
                }
                Action::Refresh | Action::Retry => {
                    let retry = matches!(action, Action::Retry);
                    let token = if retry {
                        let Some(previous) = &model.previous else {
                            count(&mut stats, "retry_without_predecessor");
                            continue;
                        };
                        previous.refresh.clone()
                    } else {
                        model.current.refresh_token.clone()
                    };
                    count(&mut stats, if retry { "retry" } else { "refresh" });
                    let active = model.active();
                    if active {
                        expected_reads = 5;
                        model.observe();
                        if retry && model.revoked.is_none() {
                            let previous = model.previous.as_ref().unwrap();
                            if previous.used
                                || previous.retried
                                || model.now - previous.rotated_at > 30
                            {
                                model.revoked = Some("refresh_reuse");
                            }
                        }
                    } else if model.revoked.is_none() && model.now >= model.absolute {
                        model.revoked = Some("absolute");
                    }
                    let expected_end = model.mint_end();
                    let before = (
                        rows(&setup.db(), "oauth_access_tokens"),
                        rows(&setup.db(), "oauth_refresh_tokens"),
                    );
                    let result = setup.server.refresh(&token).await;
                    if let Some(end) = expected_end {
                        let pair = result.unwrap_or_else(|_| panic!("seed={seed_value:x} step={step} action={action:?}: contract-valid mint refused"));
                        assert_eq!(
                            pair.expires_in,
                            end - model.now,
                            "seed={seed_value:x} step={step}: mint exceeded reference bound"
                        );
                        let stored: i64 = setup
                            .db()
                            .query_row(
                                "SELECT expires_at FROM oauth_access_tokens WHERE hash=?1",
                                [hash(&pair.access_token)],
                                |r| r.get(0),
                            )
                            .unwrap();
                        assert_eq!(stored, end);
                        if retry {
                            model.superseded.push(model.current.access_token.clone());
                            model.previous.as_mut().unwrap().retried = true;
                        } else {
                            model.previous = Some(Previous {
                                refresh: model.current.refresh_token.clone(),
                                rotated_at: model.now,
                                used: false,
                                retried: false,
                            });
                        }
                        count(
                            &mut stats,
                            if model.outcome == Evidence::Positive {
                                "mint_positive"
                            } else {
                                "mint_graced"
                            },
                        );
                        model.current = pair;
                        model.access_end = end;
                        model.refreshed = model.now;
                    } else {
                        assert!(
                            result.is_err(),
                            "seed={seed_value:x} step={step}: forbidden mint succeeded"
                        );
                        assert_eq!(
                            (
                                rows(&setup.db(), "oauth_access_tokens"),
                                rows(&setup.db(), "oauth_refresh_tokens")
                            ),
                            before,
                            "refused mint added or removed token rows"
                        );
                        count(
                            &mut stats,
                            if model.revoked.is_some() {
                                "dead_refresh_refused"
                            } else {
                                "bounded_refresh_refused"
                            },
                        );
                    }
                }
                Action::Admit => {
                    count(&mut stats, "admit");
                    let allowed = model.active() && model.now < model.access_end;
                    let result = setup.server.admit(&model.current.access_token);
                    assert_eq!(result.is_ok(), allowed, "seed={seed_value:x} step={step}: admission disagreed with reference bounds");
                    if allowed {
                        if let Some(previous) = &mut model.previous {
                            previous.used = true;
                        }
                    } else {
                        count(&mut stats, "admit_refused");
                    }
                }
                Action::Superseded => {
                    count(&mut stats, "superseded_probe");
                    setup.server.effective_now().unwrap();
                    let before = all_rows_digest(&setup.db());
                    for access in &model.superseded {
                        count(&mut stats, "superseded_access_refused");
                        assert!(
                            setup.server.admit(access).is_err(),
                            "seed={seed_value:x} step={step}: superseded access was admitted"
                        );
                    }
                    assert_eq!(
                        all_rows_digest(&setup.db()),
                        before,
                        "superseded access probe changed SQLite state"
                    );
                }
                Action::Tick => {
                    count(&mut stats, "tick");
                    seed(setup, &format!("property-{seed_value:x}-{step}"));
                    let due = model.active() && model.delivery_end() - model.now <= 600;
                    let can_read = model
                        .dispatch_read
                        .is_none_or(|previous| model.now - previous >= 300);
                    if due && can_read {
                        expected_reads = 5;
                        if let Some(previous) = model.dispatch_read {
                            assert!(model.now - previous >= 300);
                        }
                        model.dispatch_read = Some(model.now);
                        model.observe();
                    }
                    let delivered = callback.events.lock().unwrap().len();
                    let access_rows = rows(&setup.db(), "oauth_access_tokens");
                    let _ = crate::event_dispatch::tick(events, "bus", "gateway@bus")
                        .await
                        .unwrap();
                    let sent = callback.events.lock().unwrap().len() - delivered;
                    assert!(sent <= 1);
                    if sent == 1 {
                        assert!(model.active() && model.now < model.delivery_end(), "seed={seed_value:x} step={step}: delivery escaped reference family bound");
                        count(&mut stats, "callback_sent");
                    }
                    assert_eq!(
                        rows(&setup.db(), "oauth_access_tokens"),
                        access_rows,
                        "dispatcher minted an access token"
                    );
                    assert_eq!(setup.db().query_row("SELECT COUNT(*) FROM custody_outbox WHERE last_error='credential_required'", [], |r| r.get::<_, i64>(0)).unwrap(), 0);
                }
                Action::Revoke => {
                    count(&mut stats, "revoke");
                    setup.server.revoke(&model.current.refresh_token).unwrap();
                    model.revoked.get_or_insert("revocation_endpoint");
                }
                Action::ToggleGrant => {
                    count(&mut stats, "toggle_grant");
                    let mut store = setup.server.store().unwrap();
                    model.revision = store
                        .set_enabled("local", model.revision, !model.grant_enabled)
                        .unwrap();
                    model.grant_enabled = !model.grant_enabled;
                    if !model.grant_enabled {
                        model.revoked.get_or_insert("grant_disabled");
                    }
                }
            }
            let actual_reads = setup.fake.requests.lock().unwrap().len() - calls;
            assert_eq!(actual_reads, expected_reads, "seed={seed_value:x} step={step} action={action:?}: liveness request schedule drift");
            if actual_reads > 0 {
                count(&mut stats, "provider_read");
            }
            model.check(setup, seed_value, step);
            if step >= 13 {
                for (operation, tail) in [
                    ("mint_positive", "tail_mint_positive"),
                    ("mint_graced", "tail_mint_graced"),
                    ("callback_sent", "tail_callback_sent"),
                    ("provider_read", "tail_provider_read"),
                ] {
                    let delta = stats.get(operation).copied().unwrap_or(0)
                        - before_stats.get(operation).copied().unwrap_or(0);
                    *stats.entry(tail).or_default() += delta;
                }
            }
        }
        assert!(
            stats.get("live_action").copied().unwrap_or(0) >= 56,
            "seed={seed_value:x}: mixed tail became terminal/vacuous"
        );
        for (key, value) in &stats {
            *total.entry(*key).or_insert(0) += value;
        }
        println!("ng150-property seed={seed_value:016x} actions=64 counters={stats:?}");
    }
    for required in [
        "mint_positive",
        "mint_graced",
        "callback_sent",
        "provider_read",
        "retry",
        "admit_refused",
        "dead_refresh_refused",
        "toggle_grant",
        "terminal_no_revival",
        "tail_mint_positive",
        "tail_mint_graced",
        "tail_callback_sent",
        "tail_provider_read",
    ] {
        assert!(
            total.get(required).copied().unwrap_or(0) > 0,
            "vacuous seeded coverage: {required}"
        );
    }
    println!("ng150-property totals={total:?}");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn thirty_two_current_presentations_keep_one_current_row_and_revoke_after_one_retry() {
    const N: usize = 32;
    let setup = Setup::new();
    let first = setup.pair();
    let start = Arc::new(tokio::sync::Barrier::new(N));
    let mut workers = Vec::new();
    for _ in 0..N {
        let server = setup.server.clone();
        let token = first.refresh_token.clone();
        let start = start.clone();
        workers.push(tokio::spawn(async move {
            start.wait().await;
            server.refresh(&token).await
        }));
    }
    let mut successes = Vec::new();
    let mut refusals = 0;
    for worker in workers {
        match worker.await.unwrap() {
            Ok(pair) => successes.push(pair),
            Err(_) => refusals += 1,
        }
    }
    assert_eq!(
        successes.len(),
        2,
        "N32 allowed other than one rotation and one retry"
    );
    assert_eq!(refusals, N - 2);
    assert_eq!(rows(&setup.db(), "oauth_rotation_log"), 2);
    assert_eq!(rows(&setup.db(), "oauth_refresh_tokens"), 3);
    assert_eq!(rows(&setup.db(), "oauth_access_tokens"), 3);
    assert_eq!(setup.db().query_row("SELECT COUNT(*) FROM oauth_refresh_tokens WHERE rotated_at IS NULL AND superseded_at IS NULL", [], |r| r.get::<_, i64>(0)).unwrap(), 1);
    assert_eq!(
        setup
            .db()
            .query_row("SELECT revoked_reason FROM oauth_families", [], |r| r
                .get::<_, Option<String>>(0))
            .unwrap(),
        Some("refresh_reuse".into())
    );
    setup.server.effective_now().unwrap();
    let before = all_rows_digest(&setup.db());
    for pair in successes {
        assert!(
            setup.server.admit(&pair.access_token).is_err(),
            "post-revoke access succeeded"
        );
        assert!(
            setup.server.refresh(&pair.refresh_token).await.is_err(),
            "post-revoke refresh succeeded"
        );
    }
    assert_eq!(
        all_rows_digest(&setup.db()),
        before,
        "dead family changed after N32 stress"
    );
    println!("ng150-property stress_N={N} rotations=1 retries=1 refused={refusals} current_rows=1 access_rows=3 refresh_rows=3 family=revoked");
}

#[tokio::test]
async fn retention_statistics_preserve_rate_caps_and_pruned_tokens_do_not_revoke_or_write() {
    let mut setup = Setup::new();
    Arc::get_mut(&mut setup.server)
        .unwrap()
        .config
        .max_refresh_rows = 4;
    let first = setup.pair();
    let oldest = first.refresh_token.clone();
    let mut current = first;
    for rotation in 1..=12 {
        current = setup.server.refresh(&current.refresh_token).await.unwrap();
        let retained = setup.db().query_row("SELECT COUNT(*) FROM oauth_refresh_tokens WHERE rotated_at IS NOT NULL OR superseded_at IS NOT NULL", [], |r| r.get::<_, i64>(0)).unwrap();
        assert_eq!(retained, rotation.min(4));
        assert_eq!(setup.db().query_row("SELECT COUNT(*) FROM oauth_refresh_tokens WHERE rotated_at IS NULL AND superseded_at IS NULL", [], |r| r.get::<_, i64>(0)).unwrap(), 1);
    }
    assert_eq!(rows(&setup.db(), "oauth_refresh_tokens"), 5);
    assert_eq!(rows(&setup.db(), "oauth_access_tokens"), 13);
    assert_eq!(rows(&setup.db(), "oauth_rotation_log"), 12);
    let before = all_rows_digest(&setup.db());
    let requests = setup.fake.requests.lock().unwrap().len();
    assert!(matches!(
        setup.server.refresh(&oldest).await,
        Err(Error::InvalidGrant)
    ));
    assert_eq!(
        all_rows_digest(&setup.db()),
        before,
        "pruned predecessor wrote or revoked a live family"
    );
    assert_eq!(
        setup.fake.requests.lock().unwrap().len(),
        requests,
        "unknown predecessor triggered liveness I/O"
    );
    assert!(matches!(
        setup.server.refresh(&current.refresh_token).await,
        Err(Error::RateLimited)
    ));
    assert_eq!(
        all_rows_digest(&setup.db()),
        before,
        "rate-cap refusal changed SQLite state"
    );
    assert!(
        setup.server.admit(&current.access_token).is_ok(),
        "pruned predecessor or cap refusal revoked current family"
    );
    setup.clock.0.fetch_add(3601, Ordering::SeqCst);
    current = setup.server.refresh(&current.refresh_token).await.unwrap();
    assert_eq!(rows(&setup.db(), "oauth_rotation_log"), 1);
    assert_eq!(rows(&setup.db(), "oauth_codes"), 0);
    setup.clock.0.fetch_add(30, Ordering::SeqCst);
    setup.server.refresh(&current.refresh_token).await.unwrap();
    assert_eq!(
        rows(&setup.db(), "oauth_access_tokens"),
        2,
        "expired access rows outlived retention cleanup"
    );
    assert_eq!(rows(&setup.db(), "oauth_refresh_tokens"), 5);
    println!("ng150-property retention rotations_before_cap=12 retained_rotated=4 current=1 pruned_predecessor_no_write=1 post_window_log=1 retained_access_after_expiry=2");
}
