#![cfg(unix)]
#[allow(dead_code)]
#[path = "common/event_callback.rs"]
mod callback;
#[allow(dead_code)]
#[path = "common/serving_fixture.rs"]
mod fixture;
#[allow(dead_code)]
#[path = "common/provider.rs"]
mod provider;
use base64::Engine;
use serde_json::{json, Value};
use std::process::{Command, Output};
use std::sync::Arc;
use xmsg_mcp_gateway::auth::{Verifier, VerifierConfig};
use xmsg_mcp_gateway::event_store::EventKey;
use xmsg_mcp_gateway::events::{Events, EVENT_NAME};
use xmsg_mcp_gateway::grants::Store;

struct Setup {
    provider: fixture::Fixture,
    _callback: callback::CallbackFixture,
    id: String,
}
impl Setup {
    async fn new() -> Self {
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
        let key_file = provider.keys._directory.path().join("event.key");
        fixture::private_file(&key_file, &[9; 32]);
        let key = EventKey::load(&key_file).unwrap();
        let mut store = Store::open(&provider.store_file).unwrap();
        store.migrate_custody().unwrap();
        store.migrate_outbound().unwrap();
        store.migrate_retirement().unwrap();
        store.migrate_events(&key).unwrap();
        provider.config["events"] =
            json!({"key_file":key_file,"grant_id":"grant","dispatch_timeout_ms":13000});
        fixture::private_file(
            &provider.config_file,
            &serde_json::to_vec(&provider.config).unwrap(),
        );
        let secret = format!(
            "whsec_{}",
            base64::engine::general_purpose::STANDARD.encode([7; 32])
        );
        let callback = callback::CallbackFixture::new(&secret);
        let events = Events::with_transport(
            provider.store_file.clone(),
            key,
            verifier.clone(),
            "grant".into(),
            callback.transport.clone(),
        );
        let identity = verifier.verify("good-token").await.unwrap();
        let result=events.subscribe(&identity,"good-token","bus","dot@bus",serde_json::from_value(json!({"name":EVENT_NAME,"arguments":{},"delivery":{"mode":"webhook","url":callback.url,"secret":secret},"cursor":null})).unwrap()).await.unwrap();
        Self {
            provider,
            _callback: callback,
            id: result["id"].as_str().unwrap().into(),
        }
    }
    fn run(&self, command: &str, id: &str, generation: &str, extra: &[&str]) -> Output {
        Command::new(env!("CARGO_BIN_EXE_xmsg-mcp-gateway"))
            .args([command, "--config"])
            .arg(&self.provider.config_file)
            .args([
                id,
                generation,
                "--operator",
                "fixture-owner",
                "--reason",
                "fixture-recovery",
            ])
            .args(extra)
            .output()
            .unwrap()
    }
    fn db(&self) -> rusqlite::Connection {
        rusqlite::Connection::open(&self.provider.store_file).unwrap()
    }
}
#[tokio::test]
async fn owner_rebind_uses_private_file_and_refuses_unknown_stale_and_noop_changes() {
    let setup = Setup::new().await;
    let file = setup.provider.keys._directory.path().join("callback");
    fixture::private_file(&file, setup._callback.url.as_bytes());
    let file_text = file.to_str().unwrap();
    assert!(!setup
        .run(
            "events-rebind",
            "unknown",
            "1",
            &["--callback-file", file_text]
        )
        .status
        .success());
    assert!(!setup
        .run(
            "events-rebind",
            &setup.id,
            "99",
            &["--callback-file", file_text]
        )
        .status
        .success());
    assert!(!setup
        .run(
            "events-rebind",
            &setup.id,
            "1",
            &["--callback-file", file_text]
        )
        .status
        .success());
    assert_eq!(
        setup
            .db()
            .query_row("SELECT COUNT(*) FROM event_binding_audit", [], |r| r
                .get::<_, i64>(0))
            .unwrap(),
        0
    );
    fixture::private_file(&file, b"https://replacement.example/events");
    let changed = setup.run(
        "events-rebind",
        &setup.id,
        "1",
        &["--callback-file", file_text],
    );
    assert!(
        changed.status.success(),
        "{}",
        String::from_utf8_lossy(&changed.stderr)
    );
    let text = String::from_utf8(changed.stdout).unwrap();
    assert!(!text.contains("replacement.example"));
    assert!(!text.contains("whsec_"));
    assert!(!text.contains("good-token"));
    let value: Value = serde_json::from_str(&text).unwrap();
    assert_eq!(value["state"], "verification_required");
    assert_eq!(
        setup
            .db()
            .query_row("SELECT COUNT(*) FROM event_binding_audit", [], |r| r
                .get::<_, i64>(0))
            .unwrap(),
        1
    );
}
#[tokio::test]
async fn selected_owner_release_is_explicit_and_cannot_override_configuration_state() {
    let setup = Setup::new().await;
    let db = setup.db();
    db.execute("INSERT INTO custody_items(bus,upstream_id,event_id,grant_id,grant_revision,mailbox,owner,origin,text,envelope,fingerprint,received_at,expires_at,held) VALUES ('bus','old','event-old','grant',1,'dot@bus','owner','{}','body','envelope','hash',1,9999999999,1)",[]).unwrap();
    db.execute("INSERT INTO event_authorizations(event_id,acceptance_class) VALUES ('event-old','unknown')",[]).unwrap();
    db.execute(
        "INSERT INTO event_occurrences(event_id) VALUES ('event-old')",
        [],
    )
    .unwrap();
    db.execute(
        "INSERT INTO custody_outbox(event_id,state) VALUES ('event-old','held')",
        [],
    )
    .unwrap();
    let ids = setup.provider.keys._directory.path().join("selected.json");
    fixture::private_file(&ids, b"[\"old\"]");
    let result = setup.run(
        "events-replay",
        &setup.id,
        "1",
        &["--release-items-file", ids.to_str().unwrap()],
    );
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    assert_eq!(
        db.query_row(
            "SELECT state FROM custody_outbox WHERE event_id='event-old'",
            [],
            |r| r.get::<_, String>(0)
        )
        .unwrap(),
        "pending"
    );
    assert_eq!(
        db.query_row(
            "SELECT grant_revision FROM custody_items WHERE event_id='event-old'",
            [],
            |r| r.get::<_, i64>(0)
        )
        .unwrap(),
        1
    );
    assert!(
        !setup
            .run(
                "events-replay",
                &setup.id,
                "1",
                &["--release-items-file", ids.to_str().unwrap()]
            )
            .status
            .success(),
        "ineligible repeated release printed success"
    );
    let other = setup.provider.keys._directory.path().join("other.db");
    let output = Command::new(env!("CARGO_BIN_EXE_xmsg-mcp-gateway"))
        .args(["--state"])
        .arg(&other)
        .args(["events-replay", "--config"])
        .arg(&setup.provider.config_file)
        .args([
            &setup.id,
            "1",
            "--operator",
            "fixture",
            "--reason",
            "fixture",
        ])
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert!(!other.exists());
}
