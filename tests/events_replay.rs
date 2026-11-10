#![cfg(unix)]
#[allow(dead_code)]
#[path = "common/serving_fixture.rs"]
mod fixture;
#[allow(dead_code)]
#[path = "common/provider.rs"]
mod provider;
use base64::Engine;
use rusqlite::{params, Connection};
use serde_json::{json, Value};
use std::sync::Arc;
use xmsg_mcp_gateway::auth::{Verifier, VerifierConfig};
use xmsg_mcp_gateway::event_store::EventKey;
use xmsg_mcp_gateway::events::{Events, Subscribe, EVENT_NAME};
use xmsg_mcp_gateway::grants::Store;
use xmsg_mcp_gateway::webhook::{self, Transport};

struct Callback;
fn signing_key() -> String {
    format!(
        "whsec_{}",
        base64::engine::general_purpose::STANDARD.encode([4; 32])
    )
}
impl Transport for Callback {
    fn post<'a>(
        &'a self,
        _url: &'a str,
        headers: reqwest::header::HeaderMap,
        body: Vec<u8>,
    ) -> webhook::PostFuture<'a> {
        Box::pin(async move {
            standardwebhooks::Webhook::new(&signing_key())
                .unwrap()
                .verify(&body, &headers)
                .unwrap();
            let value: Value = serde_json::from_slice(&body).unwrap();
            assert_eq!(value["type"], "verification");
            Ok(webhook::Response {
                status: 200,
                body: serde_json::to_vec(&json!({"challenge":value["challenge"]})).unwrap(),
                retry_after: None,
            })
        })
    }
}
struct Setup {
    fixture: fixture::Fixture,
    runtime: Events,
    id: String,
    generation: i64,
}
impl Setup {
    async fn new() -> Self {
        let mut fixture = fixture::Fixture::new();
        for claims in fixture.tokens.lock().unwrap().values_mut() {
            claims["scope"] = json!("identity:read events:subscribe");
        }
        fixture.config["verifier"]["required_scopes"] =
            json!(["identity:read", "events:subscribe"]);
        let verifier = Arc::new(
            Verifier::from_config(
                serde_json::from_value::<VerifierConfig>(fixture.config["verifier"].clone())
                    .unwrap(),
            )
            .unwrap(),
        );
        let key_file = fixture.keys._directory.path().join("events.key");
        fixture::private_file(&key_file, &[7; 32]);
        let key = EventKey::load(&key_file).unwrap();
        let mut store = Store::open(&fixture.store_file).unwrap();
        store.migrate_custody().unwrap();
        store.migrate_outbound().unwrap();
        store.migrate_events(&key).unwrap();
        let identity = verifier.verify("good-token").await.unwrap();
        let runtime = Events::with_transport(
            fixture.store_file.clone(),
            key,
            verifier,
            "grant".into(),
            Arc::new(Callback),
        );
        let request:Subscribe=serde_json::from_value(json!({"name":EVENT_NAME,"arguments":{},"delivery":{"mode":"webhook","url":"https://callback.example/","secret":signing_key()},"cursor":null})).unwrap();
        let subscription = runtime
            .subscribe(&identity, "good-token", "bus", "dot@bus", request)
            .await
            .unwrap();
        let id = subscription["id"].as_str().unwrap().into();
        let generation = Connection::open(&fixture.store_file)
            .unwrap()
            .query_row("SELECT generation FROM event_subscriptions", [], |row| {
                row.get(0)
            })
            .unwrap();
        Self {
            fixture,
            runtime,
            id,
            generation,
        }
    }
    fn db(&self) -> Connection {
        Connection::open(&self.fixture.store_file).unwrap()
    }
    fn seed(&self, id: &str, state: &str, mailbox: &str, dispatch: Option<i64>) {
        let db = self.db();
        let now = webhook::signing_time().unwrap();
        let event = format!("event-{id}");
        db.execute("INSERT INTO custody_items(bus,upstream_id,event_id,grant_id,grant_revision,mailbox,owner,origin,text,envelope,fingerprint,received_at,expires_at,held) VALUES ('bus',?1,?2,'grant',1,?3,'owner','{\"id\":\"peer\",\"node\":\"remote\"}','retained original','original envelope','original hash',?4,?5,1)",params![id,event,mailbox,now,now+3600]).unwrap();
        db.execute(
            "INSERT INTO event_occurrences(event_id) VALUES (?1)",
            [&event],
        )
        .unwrap();
        db.execute("INSERT INTO event_authorizations(event_id,acceptance_enabled,acceptance_ever_enabled,acceptance_class,dispatch_revision) VALUES (?1,0,1,'previous',?2)",params![event,dispatch]).unwrap();
        db.execute("INSERT INTO custody_outbox(event_id,state,attempts,next_attempt,body,last_error) VALUES (?1,?2,3,999999,CAST('original exact bytes' AS BLOB),'past failure')",params![event,state]).unwrap();
    }
    fn snapshot(&self, id: &str) -> (i64, String, String, String, String) {
        self.db().query_row("SELECT c.grant_revision,c.text,c.envelope,c.fingerprint,a.acceptance_class FROM custody_items c JOIN event_authorizations a ON a.event_id=c.event_id WHERE c.upstream_id=?1",[id],|r|Ok((r.get(0)?,r.get(1)?,r.get(2)?,r.get(3)?,r.get(4)?))).unwrap()
    }
}

#[tokio::test]
async fn selected_old_held_and_accepted_rows_gain_audited_current_dispatch_only() {
    let setup = Setup::new().await;
    setup.seed("held", "held", "dot@bus", Some(1));
    setup.seed("accepted", "accepted", "dot@bus", Some(1));
    setup.seed("dead", "dead", "dot@bus", None);
    setup.db().execute("UPDATE event_authorizations SET acceptance_class='unknown',acceptance_enabled=NULL,acceptance_ever_enabled=NULL WHERE event_id='event-dead'",[]).unwrap();
    let before = setup.snapshot("held");
    let db = setup.db();
    db.execute(
        "INSERT INTO event_observations(event_id,observed_at) VALUES ('event-accepted',1)",
        [],
    )
    .unwrap();
    db.execute(
        "UPDATE event_subscriptions SET callback_cursor=10,observation_checkpoint=10",
        [],
    )
    .unwrap();
    let result = setup
        .runtime
        .release_selected(
            &setup.id,
            setup.generation,
            &["held".into(), "accepted".into(), "dead".into()],
            "operator",
            "selected old work",
        )
        .unwrap();
    assert_eq!(result["released"], 3);
    assert_eq!(result["grant_revision"], 2);
    assert_eq!(setup.snapshot("held"), before);
    assert_eq!(db.query_row("SELECT COUNT(*) FROM event_release_audit WHERE old_revision=1 AND new_revision=2 AND operator='operator' AND reason='selected old work'",[],|r|r.get::<_,i64>(0)).unwrap(),3);
    assert_eq!(db.query_row("SELECT COUNT(*) FROM custody_outbox WHERE state='pending' AND attempts=0 AND next_attempt=0 AND body=CAST('original exact bytes' AS BLOB) AND last_error='past failure'",[],|r|r.get::<_,i64>(0)).unwrap(),3);
    assert_eq!(
        db.query_row(
            "SELECT acceptance_class FROM event_authorizations WHERE event_id='event-dead'",
            [],
            |r| r.get::<_, String>(0)
        )
        .unwrap(),
        "unknown"
    );
    assert_eq!(
        db.query_row(
            "SELECT acceptance_enabled FROM event_authorizations WHERE event_id='event-dead'",
            [],
            |r| r.get::<_, Option<i64>>(0)
        )
        .unwrap(),
        None
    );
    assert_eq!(
        db.query_row("SELECT COUNT(*) FROM event_observations", [], |r| r
            .get::<_, i64>(0))
            .unwrap(),
        1
    );
    assert_eq!(
        db.query_row(
            "SELECT observation_checkpoint FROM event_subscriptions",
            [],
            |r| r.get::<_, i64>(0)
        )
        .unwrap(),
        0
    );
    assert_eq!(
        db.query_row("SELECT callback_cursor FROM event_subscriptions", [], |r| r
            .get::<_, i64>(0))
            .unwrap(),
        0
    );
    assert!(setup
        .runtime
        .release_selected(
            &setup.id,
            setup.generation,
            &["held".into()],
            "operator",
            "no-op retry"
        )
        .is_err());
    assert_eq!(
        db.query_row("SELECT COUNT(*) FROM event_release_audit", [], |r| r
            .get::<_, i64>(0))
            .unwrap(),
        3
    );
}

#[tokio::test]
async fn foreign_unknown_expired_and_current_items_roll_back_the_whole_selection() {
    for bad in [
        "foreign",
        "unknown",
        "expired",
        "current",
        "inconsistent-pending",
    ] {
        let setup = Setup::new().await;
        setup.seed("owned", "held", "dot@bus", Some(1));
        match bad {
            "foreign" => setup.seed(bad, "held", "another@bus", Some(1)),
            "expired" => {
                setup.seed(bad, "held", "dot@bus", Some(1));
                setup
                    .db()
                    .execute(
                        "UPDATE custody_items SET expires_at=0 WHERE upstream_id='expired'",
                        [],
                    )
                    .unwrap();
            }
            "current" => setup.seed(bad, "held", "dot@bus", Some(2)),
            "inconsistent-pending" => setup.seed(bad, "pending", "dot@bus", Some(1)),
            _ => {}
        }
        assert!(
            setup
                .runtime
                .release_selected(
                    &setup.id,
                    setup.generation,
                    &["owned".into(), bad.into()],
                    "operator",
                    "atomic selection"
                )
                .is_err(),
            "{bad}"
        );
        let db = setup.db();
        assert_eq!(
            db.query_row(
                "SELECT state FROM custody_outbox WHERE event_id='event-owned'",
                [],
                |r| r.get::<_, String>(0)
            )
            .unwrap(),
            "held"
        );
        assert_eq!(
            db.query_row(
                "SELECT dispatch_revision FROM event_authorizations WHERE event_id='event-owned'",
                [],
                |r| r.get::<_, i64>(0)
            )
            .unwrap(),
            1
        );
        assert_eq!(
            db.query_row("SELECT COUNT(*) FROM event_release_audit", [], |r| r
                .get::<_, i64>(0))
                .unwrap(),
            0
        );
    }
}

#[tokio::test]
async fn selected_release_requires_current_full_binding_and_generation() {
    for mutation in [
        "stale-generation",
        "disabled-grant",
        "stale-subscription",
        "wrong-client",
        "wrong-issuer",
        "wrong-resource",
        "wrong-subject",
        "wrong-service",
        "inactive-subscription",
        "expired-subscription",
    ] {
        let setup = Setup::new().await;
        setup.seed("owned", "held", "dot@bus", Some(1));
        let db = setup.db();
        let expected = if mutation == "stale-generation" {
            setup.generation + 1
        } else {
            setup.generation
        };
        let sql = match mutation {
            "disabled-grant" => Some("UPDATE grants SET enabled=0"),
            "stale-subscription" => Some("UPDATE event_subscriptions SET grant_revision=99"),
            "wrong-client" => Some("UPDATE event_subscriptions SET hosted_client='another'"),
            "wrong-issuer" => {
                Some("UPDATE event_subscriptions SET issuer='https://other.example/'")
            }
            "wrong-resource" => {
                Some("UPDATE event_subscriptions SET resource='https://other.example/mcp'")
            }
            "wrong-subject" => Some("UPDATE event_subscriptions SET subject='another'"),
            "wrong-service" => Some("UPDATE event_subscriptions SET service='another'"),
            "inactive-subscription" => Some("UPDATE event_subscriptions SET status='verifying'"),
            "expired-subscription" => Some("UPDATE event_subscriptions SET expires=0"),
            _ => None,
        };
        if let Some(sql) = sql {
            db.execute(sql, []).unwrap();
        }
        assert!(
            setup
                .runtime
                .release_selected(
                    &setup.id,
                    expected,
                    &["owned".into()],
                    "operator",
                    "current binding required"
                )
                .is_err(),
            "{mutation}"
        );
        assert_eq!(
            db.query_row("SELECT COUNT(*) FROM event_release_audit", [], |r| r
                .get::<_, i64>(0))
                .unwrap(),
            0
        );
    }
}

#[tokio::test]
async fn selected_release_rejects_duplicate_empty_and_oversized_selections() {
    let setup = Setup::new().await;
    setup.seed("owned", "held", "dot@bus", Some(1));
    for items in [
        vec![],
        vec!["owned".into(), "owned".into()],
        vec![String::new()],
        vec!["x".repeat(4097)],
        (0..101).map(|i| i.to_string()).collect(),
    ] {
        assert!(setup
            .runtime
            .release_selected(
                &setup.id,
                setup.generation,
                &items,
                "operator",
                "bounded selection"
            )
            .is_err());
    }
    assert!(setup
        .runtime
        .release_selected(&setup.id, setup.generation, &["owned".into()], "", "reason")
        .is_err());
    assert!(setup
        .runtime
        .release_selected(
            &setup.id,
            setup.generation,
            &["owned".into()],
            "operator",
            ""
        )
        .is_err());
}

#[tokio::test]
async fn a_later_audit_write_failure_rolls_back_earlier_selected_changes() {
    let setup = Setup::new().await;
    setup.seed("first", "held", "dot@bus", Some(1));
    setup.seed("second", "held", "dot@bus", Some(1));
    let db = setup.db();
    db.execute_batch("CREATE TRIGGER fail_second_release BEFORE INSERT ON event_release_audit WHEN NEW.event_id='event-second' BEGIN SELECT RAISE(ABORT,'fixture storage failure'); END;").unwrap();
    assert!(setup
        .runtime
        .release_selected(
            &setup.id,
            setup.generation,
            &["first".into(), "second".into()],
            "operator",
            "atomic storage failure"
        )
        .is_err());
    assert_eq!(
        db.query_row(
            "SELECT COUNT(*) FROM custody_outbox WHERE state='held' AND attempts=3",
            [],
            |row| row.get::<_, i64>(0)
        )
        .unwrap(),
        2
    );
    assert_eq!(
        db.query_row(
            "SELECT COUNT(*) FROM event_authorizations WHERE dispatch_revision=1",
            [],
            |row| row.get::<_, i64>(0)
        )
        .unwrap(),
        2
    );
    assert_eq!(
        db.query_row("SELECT COUNT(*) FROM event_release_audit", [], |row| row
            .get::<_, i64>(0))
            .unwrap(),
        0
    );
}

#[tokio::test]
async fn newly_authorized_unobserved_history_rebases_both_responsibility_checkpoints() {
    let setup = Setup::new().await;
    setup.seed("historical", "held", "dot@bus", Some(1));
    setup.seed("observed-later", "accepted", "dot@bus", Some(2));
    let db = setup.db();
    db.execute(
        "UPDATE event_occurrences SET seq=50 WHERE event_id='event-historical'",
        [],
    )
    .unwrap();
    db.execute(
        "UPDATE event_occurrences SET seq=100 WHERE event_id='event-observed-later'",
        [],
    )
    .unwrap();
    db.execute(
        "INSERT INTO event_observations(event_id,observed_at) VALUES ('event-observed-later',17)",
        [],
    )
    .unwrap();
    db.execute(
        "UPDATE event_subscriptions SET callback_cursor=100,observation_checkpoint=100",
        [],
    )
    .unwrap();
    db.execute("INSERT INTO event_checkpoints(owner_key,observation_checkpoint) SELECT owner_key,100 FROM event_subscriptions",[]).unwrap();
    setup
        .runtime
        .release_selected(
            &setup.id,
            setup.generation,
            &["historical".into()],
            "operator",
            "authorize earlier history",
        )
        .unwrap();
    assert_eq!(
        db.query_row(
            "SELECT observation_checkpoint FROM event_subscriptions",
            [],
            |row| row.get::<_, i64>(0)
        )
        .unwrap(),
        49
    );
    assert_eq!(
        db.query_row(
            "SELECT observation_checkpoint FROM event_checkpoints",
            [],
            |row| row.get::<_, i64>(0)
        )
        .unwrap(),
        49
    );
    assert_eq!(
        db.query_row(
            "SELECT observed_at FROM event_observations WHERE event_id='event-observed-later'",
            [],
            |row| row.get::<_, i64>(0)
        )
        .unwrap(),
        17
    );
    assert_eq!(
        db.query_row("SELECT COUNT(*) FROM event_observations", [], |row| row
            .get::<_, i64>(0))
            .unwrap(),
        1
    );
    assert_eq!(
        db.query_row(
            "SELECT callback_cursor FROM event_subscriptions",
            [],
            |row| row.get::<_, i64>(0)
        )
        .unwrap(),
        49
    );
}

#[tokio::test]
async fn already_observed_selected_history_does_not_rewind_responsibility() {
    let setup = Setup::new().await;
    setup.seed("already-observed", "accepted", "dot@bus", Some(1));
    let db = setup.db();
    db.execute(
        "INSERT INTO event_observations(event_id,observed_at) VALUES ('event-already-observed',17)",
        [],
    )
    .unwrap();
    db.execute(
        "UPDATE event_subscriptions SET callback_cursor=100,observation_checkpoint=100",
        [],
    )
    .unwrap();
    db.execute("INSERT INTO event_checkpoints(owner_key,observation_checkpoint) SELECT owner_key,100 FROM event_subscriptions",[]).unwrap();
    setup
        .runtime
        .release_selected(
            &setup.id,
            setup.generation,
            &["already-observed".into()],
            "operator",
            "repeat an observed hint",
        )
        .unwrap();
    assert_eq!(
        db.query_row(
            "SELECT observation_checkpoint FROM event_subscriptions",
            [],
            |row| row.get::<_, i64>(0)
        )
        .unwrap(),
        100
    );
    assert_eq!(
        db.query_row(
            "SELECT observation_checkpoint FROM event_checkpoints",
            [],
            |row| row.get::<_, i64>(0)
        )
        .unwrap(),
        100
    );
    assert_eq!(
        db.query_row("SELECT observed_at FROM event_observations", [], |row| row
            .get::<_, i64>(
            0
        ))
        .unwrap(),
        17
    );
    assert_eq!(
        db.query_row(
            "SELECT callback_cursor FROM event_subscriptions",
            [],
            |row| row.get::<_, i64>(0)
        )
        .unwrap(),
        0
    );
}
