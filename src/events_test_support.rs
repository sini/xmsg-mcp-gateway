#![allow(dead_code)]
use crate::provider_fixture as provider;
#[path = "../tests/common/serving_fixture.rs"]
pub(crate) mod fixture;
use crate::auth::{VerifiedIdentity, Verifier, VerifierConfig};
use crate::event_store::EventKey;
use crate::events::{Events, Subscribe, EVENT_NAME};
use crate::grants::Store;
use crate::webhook::{self, Transport};
use base64::Engine;
use serde_json::{json, Value};
use std::collections::VecDeque;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

pub(crate) enum Behavior {
    Response(u16, Option<String>),
    TimeoutAfterAccept,
    GenerationChange(std::path::PathBuf),
}
pub(crate) struct Callback {
    pub(crate) events: Mutex<Vec<(reqwest::header::HeaderMap, Vec<u8>)>>,
    pub(crate) behaviors: Mutex<VecDeque<Behavior>>,
    pub(crate) secret: Mutex<String>,
    pub(crate) invalid: AtomicUsize,
}
impl Transport for Callback {
    fn post<'a>(
        &'a self,
        _url: &'a str,
        headers: reqwest::header::HeaderMap,
        body: Vec<u8>,
    ) -> webhook::PostFuture<'a> {
        Box::pin(async move {
            let valid = standardwebhooks::Webhook::new(&self.secret.lock().unwrap())
                .unwrap()
                .verify(&body, &headers)
                .is_ok();
            if !valid {
                self.invalid.fetch_add(1, Ordering::SeqCst);
                return Ok(webhook::Response {
                    status: 401,
                    body: vec![],
                    retry_after: None,
                });
            }
            let value: Value = serde_json::from_slice(&body).unwrap();
            if value["type"] == "verification" {
                return Ok(webhook::Response {
                    status: 200,
                    body: serde_json::to_vec(&json!({"challenge":value["challenge"]})).unwrap(),
                    retry_after: None,
                });
            }
            assert_eq!(headers["webhook-id"], value["eventId"].as_str().unwrap());
            self.events.lock().unwrap().push((headers, body));
            match self.behaviors.lock().unwrap().pop_front() {
                Some(Behavior::Response(status, retry_after)) => Ok(webhook::Response {
                    status,
                    body: vec![],
                    retry_after,
                }),
                Some(Behavior::TimeoutAfterAccept) => Err(webhook::Error::Timeout),
                Some(Behavior::GenerationChange(file)) => {
                    rusqlite::Connection::open(file)
                        .unwrap()
                        .execute("UPDATE event_subscriptions SET generation=generation+1", [])
                        .unwrap();
                    Ok(webhook::Response {
                        status: 200,
                        body: vec![],
                        retry_after: None,
                    })
                }
                None => Ok(webhook::Response {
                    status: 200,
                    body: vec![],
                    retry_after: None,
                }),
            }
        })
    }
}
pub(crate) fn secret(byte: u8) -> String {
    format!(
        "whsec_{}",
        base64::engine::general_purpose::STANDARD.encode([byte; 32])
    )
}
pub(crate) fn request() -> Subscribe {
    serde_json::from_value(json!({"name":EVENT_NAME,"arguments":{},"delivery":{"mode":"webhook","url":"https://callback.example/wake","secret":secret(4)},"cursor":null})).unwrap()
}
pub(crate) struct Setup {
    pub(crate) provider: fixture::Fixture,
    pub(crate) key: EventKey,
    pub(crate) verifier: Arc<Verifier>,
    pub(crate) callback: Arc<Callback>,
}
impl Setup {
    pub(crate) fn new() -> Self {
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
        let file = provider.keys._directory.path().join("events-key");
        fixture::private_file(&file, &[8; 32]);
        let key = EventKey::load(&file).unwrap();
        let mut store = Store::open(&provider.store_file).unwrap();
        store.migrate_custody().unwrap();
        store.migrate_outbound().unwrap();
        store.migrate_events(&key).unwrap();
        let callback = Arc::new(Callback {
            events: Mutex::new(vec![]),
            behaviors: Mutex::new(VecDeque::new()),
            secret: Mutex::new(secret(4)),
            invalid: AtomicUsize::new(0),
        });
        Self {
            provider,
            key,
            verifier,
            callback,
        }
    }
    pub(crate) fn runtime(&self) -> Events {
        Events::with_transport(
            self.provider.store_file.clone(),
            self.key.clone(),
            self.verifier.clone(),
            "grant".into(),
            self.callback.clone(),
        )
    }
    pub(crate) async fn subscribe(&self) -> VerifiedIdentity {
        let identity = self.verifier.verify("good-token").await.unwrap();
        self.runtime()
            .subscribe(&identity, "good-token", "bus", "dot@bus", request())
            .await
            .unwrap();
        identity
    }
    pub(crate) fn db(&self) -> rusqlite::Connection {
        rusqlite::Connection::open(&self.provider.store_file).unwrap()
    }
    pub(crate) fn seed(&self, id: &str, mailbox: &str, revision: i64, expires: i64) -> i64 {
        let db = self.db();
        db.execute("INSERT INTO custody_items(bus,upstream_id,event_id,grant_id,grant_revision,mailbox,owner,origin,text,envelope,in_reply_to,fingerprint,received_at,expires_at,held) VALUES ('bus',?1,?1,'grant',?2,?3,'owner','{\"service\":\"sender\",\"id\":null,\"node\":\"peer\"}','untrusted message','fixture',NULL,?1,1,?4,1)",rusqlite::params![id,revision,mailbox,expires]).unwrap();
        db.execute("INSERT INTO event_authorizations(event_id,acceptance_enabled,acceptance_ever_enabled,acceptance_class,dispatch_revision) VALUES (?1,1,1,'current',?2)",rusqlite::params![id,revision]).unwrap();
        db.execute("INSERT INTO event_occurrences(event_id) VALUES (?1)", [id])
            .unwrap();
        let sequence = db.last_insert_rowid();
        db.execute(
            "INSERT INTO custody_outbox(event_id,state) VALUES (?1,'pending')",
            [id],
        )
        .unwrap();
        sequence
    }
}
