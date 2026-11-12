//! Durable serial wake hints. Receipt never records consumer observation or task completion.
use crate::events::Events;
use crate::grants::Store;
use rusqlite::{params, OptionalExtension};
use serde_json::{json, Value};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

#[derive(Debug, thiserror::Error)]
pub(crate) enum Error {
    #[error("Events store unavailable")]
    Database(#[from] rusqlite::Error),
    #[error(transparent)]
    Authority(#[from] crate::grants::Error),
    #[error(transparent)]
    Key(#[from] crate::event_store::Error),
    #[error("Events record unavailable")]
    Encoding(#[from] serde_json::Error),
    #[error("Events clock unavailable")]
    Clock,
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Tick {
    Idle,
    Contended,
    CredentialRequired,
    Accepted,
    Retry,
    Dead,
    Expired,
}

struct Subscription {
    id: String,
    owner: String,
    service: String,
    issuer: String,
    resource: String,
    subject: String,
    client: String,
    grant: String,
    revision: i64,
    generation: i64,
    expires: i64,
    url: Vec<u8>,
    secret: Vec<u8>,
    previous: Option<Vec<u8>>,
    bearer: Option<Vec<u8>>,
    family: Option<String>,
    rotation: i64,
    cursor: i64,
}
struct Candidate {
    id: String,
    sequence: i64,
    attempts: i64,
    body: Option<Vec<u8>>,
}

fn now() -> Result<i64, Error> {
    i64::try_from(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| Error::Clock)?
            .as_secs(),
    )
    .map_err(|_| Error::Clock)
}

fn subscription(
    store: &Store,
    bus: &str,
    mailbox: &str,
    selected_grant: &str,
    at: i64,
) -> Result<Option<Subscription>, Error> {
    let mut selected=store.connection.query_row("SELECT s.id,s.owner_key,s.service,s.issuer,s.resource,s.subject,s.hosted_client,s.grant_id,s.grant_revision,s.generation,s.expires,s.url,s.secret,s.old_secret,s.bearer,s.rotation_until,s.callback_cursor FROM event_subscriptions s JOIN grants g ON g.id=s.grant_id WHERE s.bus=?1 AND s.mailbox=?2 AND s.grant_id=?4 AND s.status='active' AND s.expires>?3 AND g.enabled=1 AND g.revision=s.grant_revision AND g.service=s.service AND g.issuer=s.issuer AND g.resource=s.resource AND g.subject=s.subject AND g.hosted_client=s.hosted_client",params![bus,mailbox,at,selected_grant], |r| Ok(Subscription {id:r.get(0)?,owner:r.get(1)?,service:r.get(2)?,issuer:r.get(3)?,resource:r.get(4)?,subject:r.get(5)?,client:r.get(6)?,grant:r.get(7)?,revision:r.get(8)?,generation:r.get(9)?,expires:r.get(10)?,url:r.get(11)?,secret:r.get(12)?,previous:r.get(13)?,bearer:r.get(14)?,family:None,rotation:r.get(15)?,cursor:r.get(16)?})).optional()?;
    if let Some(sub) = &mut selected {
        if sub.bearer.is_none() {
            sub.family = store.connection.query_row(
                "SELECT token_family FROM event_subscriptions WHERE id=?1",
                [&sub.id],
                |r| r.get(0),
            )?;
        }
    }
    Ok(selected)
}

fn candidate(
    store: &Store,
    sub: &Subscription,
    bus: &str,
    mailbox: &str,
    at: i64,
) -> Result<Option<Candidate>, Error> {
    // Dead/backoff heads block later work; only explicit replay or retention clears the gap.
    let row = store.connection.query_row("SELECT b.event_id,o.seq,b.attempts,b.body,b.state,b.next_attempt FROM custody_outbox b JOIN event_occurrences o ON o.event_id=b.event_id JOIN custody_items c ON c.event_id=b.event_id JOIN event_authorizations a ON a.event_id=c.event_id WHERE c.bus=?1 AND c.mailbox=?2 AND c.owner=?3 AND c.grant_id=?4 AND a.dispatch_revision=?5 AND c.text IS NOT NULL AND c.expires_at>?6 AND b.state IN ('pending','dispatching','dead') ORDER BY o.seq LIMIT 1",params![bus,mailbox,sub.subject,sub.grant,sub.revision,at], |r| Ok((Candidate{id:r.get(0)?,sequence:r.get(1)?,attempts:r.get(2)?,body:r.get(3)?},r.get::<_,String>(4)?,r.get::<_,i64>(5)?))).optional()?;
    Ok(row.and_then(|(candidate, state, due)| (state != "dead" && due <= at).then_some(candidate)))
}

fn open_text(
    events: &Events,
    sub: &Subscription,
    field: &str,
    sealed: &[u8],
) -> Result<String, Error> {
    let aad = crate::events::aad(&sub.owner, field, sub.generation);
    String::from_utf8(events.key.open(&aad, sealed)?)
        .map_err(|_| Error::Key(crate::event_store::Error::Key))
}

fn expire_history(
    store: &Store,
    sub: &Subscription,
    bus: &str,
    mailbox: &str,
    at: i64,
) -> Result<(), Error> {
    let floor:Option<i64> = store.connection.query_row("SELECT MAX(o.seq) FROM event_occurrences o JOIN custody_items c ON c.event_id=o.event_id JOIN event_authorizations a ON a.event_id=c.event_id WHERE c.bus=?1 AND c.mailbox=?2 AND c.owner=?3 AND c.grant_id=?4 AND a.dispatch_revision=?5 AND (c.expires_at<=?6 OR c.text IS NULL)",params![bus,mailbox,sub.subject,sub.grant,sub.revision,at],|r|r.get(0))?;
    if let Some(floor) = floor {
        let tx = store.connection.unchecked_transaction()?;
        tx.execute("INSERT INTO event_availability(owner_key,unavailable_through) VALUES (?1,?2) ON CONFLICT(owner_key) DO UPDATE SET unavailable_through=MAX(unavailable_through,excluded.unavailable_through)",params![sub.owner,floor])?;
        tx.execute("UPDATE custody_outbox SET state='expired',last_error='content_expired' WHERE state!='accepted' AND event_id IN (SELECT c.event_id FROM custody_items c WHERE c.bus=?1 AND c.mailbox=?2 AND c.owner=?3 AND c.grant_id=?4 AND (c.expires_at<=?5 OR c.text IS NULL))",params![bus,mailbox,sub.subject,sub.grant,at])?;
        tx.execute("UPDATE custody_outbox SET body=NULL WHERE event_id IN (SELECT c.event_id FROM custody_items c WHERE c.bus=?1 AND c.mailbox=?2 AND c.owner=?3 AND c.grant_id=?4 AND (c.expires_at<=?5 OR c.text IS NULL))",params![bus,mailbox,sub.subject,sub.grant,at])?;
        tx.commit()?;
    }
    Ok(())
}

fn payload(
    events: &Events,
    store: &Store,
    sub: &Subscription,
    item: &Candidate,
) -> Result<Vec<u8>, Error> {
    if let Some(body) = &item.body {
        return Ok(body.clone());
    }
    let (upstream,mailbox,origin,reply,text,received):(String,String,String,Option<String>,String,i64)=store.connection.query_row("SELECT upstream_id,mailbox,origin,in_reply_to,text,received_at FROM custody_items WHERE event_id=?1",[&item.id],|r|Ok((r.get(0)?,r.get(1)?,r.get(2)?,r.get(3)?,r.get(4)?,r.get(5)?)))?;
    let timestamp = time::OffsetDateTime::from_unix_timestamp(received)
        .map_err(|_| Error::Clock)?
        .format(&time::format_description::well_known::Rfc3339)
        .map_err(|_| Error::Clock)?;
    let origin: Value = serde_json::from_str(&origin)?;
    let cursor = crate::event_cursor::encode(&events.key, &sub.owner, sub.cursor)?;
    Ok(serde_json::to_vec(
        &json!({"eventId":item.id,"name":crate::events::EVENT_NAME,"timestamp":timestamp,"cursor":cursor,
        "data":{"message_id":upstream,"mailbox":mailbox,"origin":origin,"in_reply_to":reply,
            "preview":text.chars().take(256).collect::<String>(),"body_available":true,"sequence":item.sequence}}),
    )?)
}

fn retry_delay(attempt: i64) -> Result<u64, Error> {
    let base = (1u64.checked_shl(attempt.min(8) as u32).unwrap_or(300)).min(300);
    let mut random = [0u8; 8];
    getrandom::fill(&mut random).map_err(|_| Error::Clock)?;
    Ok((base + u64::from_be_bytes(random) % (base + 1)).min(300))
}

fn retry_deadline(
    completed: SystemTime,
    delay: u64,
    retry_after: Option<&str>,
) -> Result<i64, Error> {
    let elapsed = completed
        .duration_since(UNIX_EPOCH)
        .map_err(|_| Error::Clock)?;
    let base = elapsed
        .as_secs()
        .saturating_add(u64::from(elapsed.subsec_nanos() > 0));
    let requested = retry_after
        .and_then(|value| crate::webhook::retry_after_seconds(value, completed))
        .unwrap_or(0);
    Ok(i64::try_from(base.saturating_add(delay.max(requested))).unwrap_or(i64::MAX))
}

fn park_credential(db: &rusqlite::Connection, item: &Candidate, at: i64) -> Result<Tick, Error> {
    let parked: bool = db.query_row(
        "SELECT COALESCE(last_error='credential_required',0) FROM custody_outbox WHERE event_id=?1",
        [&item.id],
        |r| r.get(0),
    )?;
    db.execute("UPDATE custody_outbox SET last_error='credential_required',next_attempt=?2 WHERE event_id=?1",params![item.id,at.saturating_add(5)])?;
    if !parked {
        crate::event_diagnostic::delivery(
            "token_parked",
            Some("credential_required"),
            item.attempts,
        );
    }
    Ok(Tick::CredentialRequired)
}
fn event_now(events: &Events) -> Result<i64, Error> {
    match events.verifier.local_server() {
        Some(server) => server.effective_now().map_err(|_| Error::Clock),
        None => now(),
    }
}

pub(crate) async fn tick(events: &Events, bus: &str, mailbox: &str) -> Result<Tick, Error> {
    let store = Store::open_for_dispatch(&events.file)?;
    store.require_events_ready(&events.key)?;
    let at = event_now(events)?;
    let Some(sub) = subscription(&store, bus, mailbox, &events.selected_grant, at)? else {
        return Ok(Tick::Idle);
    };
    if sub.grant != events.selected_grant {
        return Ok(Tick::Idle);
    }
    expire_history(&store, &sub, bus, mailbox, at)?;
    let Some(_selected) = candidate(&store, &sub, bus, mailbox, at)? else {
        return Ok(Tick::Idle);
    };
    tracing::debug!(target:"gateway_events_selected", "due candidate selected");
    if let Some(family) = &sub.family {
        let Some(server) = events.verifier.local_server() else {
            return Ok(Tick::Expired);
        };
        match server.delivery_read_due(family) {
            Ok(true) => {
                if server.check_liveness(family, true).await.is_err() {
                    return Ok(Tick::Expired);
                }
            }
            Ok(false) => {}
            Err(_) => return Ok(Tick::Expired),
        }
    }

    let Some(_lease) = store.try_operation_lease(&sub.service)? else {
        return Ok(Tick::Contended);
    };
    // Selection precedes introspection, but due/state must be re-read inside the lease.
    let at = event_now(events)?;
    let Some(sub) = subscription(&store, bus, mailbox, &events.selected_grant, at)? else {
        return Ok(Tick::Idle);
    };
    if sub.grant != events.selected_grant {
        return Ok(Tick::Idle);
    }
    let Some(item) = candidate(&store, &sub, bus, mailbox, at)? else {
        return Ok(Tick::Idle);
    };
    if item.attempts >= 5 {
        store.connection.execute("UPDATE custody_outbox SET state='dead',last_error='attempts_exhausted' WHERE event_id=?1",[&item.id])?;
        crate::event_diagnostic::delivery("dead", Some("attempts_exhausted"), item.attempts);
        return Ok(Tick::Dead);
    }
    let identity = if let Some(family) = &sub.family {
        match events.verifier.verify_family(family) {
            Ok(identity) => identity,
            Err(_) => return Ok(Tick::Expired),
        }
    } else {
        let Some(sealed) = &sub.bearer else {
            return Ok(Tick::Expired);
        };
        let bearer = open_text(events, &sub, "bearer", sealed)?;
        match events.verifier.verify(&bearer).await {
            Ok(identity) => identity,
            Err(_) => {
                return park_credential(&store.connection, &item, at);
            }
        }
    };
    if identity.service() != sub.service
        || identity.issuer() != sub.issuer
        || identity.resource() != sub.resource
        || identity.subject() != sub.subject
        || identity.hosted_client() != sub.client
        || !events
            .verifier
            .requires_scope_for(&identity, "events:subscribe")
    {
        return park_credential(&store.connection, &item, at);
    }
    let authority = store.authorize(&identity)?;
    if authority.grant_id != sub.grant || authority.revision != sub.revision {
        return Ok(Tick::Idle);
    }
    let at = event_now(events)?;
    if at >= sub.expires || at as u64 >= identity.expires_at() {
        return Ok(Tick::Expired);
    }
    let Some(current_item) = candidate(&store, &sub, bus, mailbox, at)? else {
        return Ok(Tick::Idle);
    };
    if current_item.id != item.id || current_item.attempts != item.attempts {
        return Ok(Tick::Idle);
    }
    let body = payload(events, &store, &sub, &current_item)?;
    if body.len() > crate::webhook::MAX_EVENT_BYTES {
        store.connection.execute("UPDATE custody_outbox SET state='dead',last_error='payload_protocol_error' WHERE event_id=?1",[&item.id])?;
        crate::event_diagnostic::delivery("dead", Some("payload_protocol_error"), item.attempts);
        return Ok(Tick::Dead);
    }
    let url = open_text(events, &sub, "url", &sub.url)?;
    let secret = open_text(events, &sub, "secret", &sub.secret)?;
    let previous = if sub.rotation > at {
        sub.previous
            .as_ref()
            .map(|raw| open_text(events, &sub, "old_secret", raw))
            .transpose()?
    } else {
        None
    };
    let attempt = item.attempts + 1;
    let delay = retry_delay(attempt)?;
    let due = retry_deadline(SystemTime::now(), delay.saturating_add(10), None)?;
    let changed=store.connection.execute("UPDATE custody_outbox SET state='dispatching',attempts=?2,next_attempt=?3,body=COALESCE(body,?4),subscription_generation=?5 WHERE event_id=?1 AND attempts=?6 AND state IN ('pending','dispatching') AND next_attempt<=?7",params![item.id,attempt,due,body,sub.generation,item.attempts,at])?;
    if changed != 1 {
        return Ok(Tick::Idle);
    }
    tracing::debug!(target:"gateway_event_before_webhook", "durable attempt committed");
    // No SQLite transaction is held during either provider lookup or webhook I/O.
    let result = crate::webhook::signed_post(
        events.transport.as_ref(),
        &url,
        body,
        &item.id,
        &sub.id,
        &secret,
        previous.as_deref(),
    )
    .await;
    if result
        .as_ref()
        .is_ok_and(|response| (200..300).contains(&response.status))
    {
        tracing::debug!(target:"gateway_event_after_webhook", "callback accepted; receipt not yet committed");
    }
    let completed = SystemTime::now();
    let local_due = retry_deadline(completed, delay, None)?;
    let (state, reason, next, outcome) = match result {
        Ok(response) if (200..300).contains(&response.status) => {
            ("accepted", None, local_due, Tick::Accepted)
        }
        Ok(response) => {
            let retryable = matches!(response.status, 408 | 429 | 500..=599);
            let retry_after = if matches!(response.status, 429 | 503) {
                response.retry_after.as_deref()
            } else {
                None
            };
            let next = retry_deadline(completed, delay, retry_after)?;
            if retryable && attempt < 5 {
                ("pending", Some("callback_retryable"), next, Tick::Retry)
            } else {
                (
                    "dead",
                    Some(if response.status == 413 {
                        "payload_protocol_error"
                    } else if response.status == 410 {
                        "delivery_gone"
                    } else {
                        "callback_terminal"
                    }),
                    next,
                    Tick::Dead,
                )
            }
        }
        Err(_) => {
            if attempt < 5 {
                (
                    "pending",
                    Some("callback_transport"),
                    local_due,
                    Tick::Retry,
                )
            } else {
                ("dead", Some("attempts_exhausted"), local_due, Tick::Dead)
            }
        }
    };
    let tx = store.connection.unchecked_transaction()?;
    let changed=tx.execute("UPDATE custody_outbox SET state=?2,last_error=?3,next_attempt=?4 WHERE event_id=?1 AND state='dispatching' AND attempts=?5 AND subscription_generation=?6 AND EXISTS(SELECT 1 FROM event_subscriptions s JOIN grants g ON g.id=s.grant_id WHERE s.id=?7 AND s.generation=?6 AND g.enabled=1 AND g.revision=?8)",params![item.id,state,reason,next,attempt,sub.generation,sub.id,sub.revision])?;
    if changed != 1 {
        return Ok(Tick::Idle);
    }
    if state == "accepted" {
        tx.execute("UPDATE event_subscriptions SET callback_cursor=MAX(callback_cursor,?2) WHERE id=?1 AND generation=?3",params![sub.id,item.sequence,sub.generation])?;
    }
    tx.commit()?;
    crate::event_diagnostic::delivery(
        if state == "pending" {
            if next > local_due {
                "backoff"
            } else {
                "retry"
            }
        } else {
            state
        },
        reason,
        attempt,
    );
    Ok(outcome)
}

pub(crate) fn interval() -> Duration {
    Duration::from_millis(250)
}

#[derive(Default)]
pub(crate) struct ExpiryObservation {
    last: Option<(String, i64)>,
}
impl ExpiryObservation {
    pub(crate) fn observe(
        &mut self,
        events: &Events,
        bus: &str,
        mailbox: &str,
    ) -> Result<(), Error> {
        let store = Store::open_for_dispatch(&events.file)?;
        let at = event_now(events)?;
        let expired: Option<(String,i64)> = store.connection.query_row(
            "SELECT s.id,s.generation FROM event_subscriptions s JOIN grants g ON g.id=s.grant_id
             WHERE s.bus=?1 AND s.mailbox=?2 AND s.grant_id=?3 AND s.status='active' AND s.expires<=?4
               AND g.enabled=1 AND g.revision=s.grant_revision AND g.service=s.service AND g.issuer=s.issuer
               AND g.resource=s.resource AND g.subject=s.subject AND g.hosted_client=s.hosted_client",
            params![bus,mailbox,events.selected_grant,at], |row|Ok((row.get(0)?,row.get(1)?)),
        ).optional()?;
        if let Some(expired) = expired {
            if self.last.as_ref() != Some(&expired) {
                self.last = Some(expired);
                crate::event_diagnostic::expired();
            }
        }
        Ok(())
    }
}

pub(crate) struct Worker {
    stop: std::sync::Arc<tokio::sync::Notify>,
    handle: std::sync::Mutex<Option<tokio::task::JoinHandle<()>>>,
}

impl Worker {
    pub(crate) fn start(
        events: std::sync::Arc<Events>,
        bus: String,
        mailbox: String,
        budget: Duration,
    ) -> Self {
        let stop = std::sync::Arc::new(tokio::sync::Notify::new());
        let stopped = stop.clone();
        let handle = tokio::spawn(async move {
            let mut expiry = ExpiryObservation::default();
            loop {
                tokio::select! {
                    _=stopped.notified()=>return,
                    result=tokio::time::timeout(budget,async {
                        expiry.observe(&events,&bus,&mailbox)?;
                        tick(&events,&bus,&mailbox).await
                    })=>{
                        if !matches!(result,Ok(Ok(_))) {
                            tracing::warn!(target:"gateway_events", "Events worker temporarily unavailable; retained custody is unchanged");
                        }
                    }
                }
                tokio::select! {
                    _=stopped.notified()=>return,
                    _=tokio::time::sleep(interval())=>{},
                }
            }
        });
        Self {
            stop,
            handle: std::sync::Mutex::new(Some(handle)),
        }
    }
    pub(crate) async fn shutdown(&self) {
        let handle = self
            .handle
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .take();
        if let Some(handle) = handle {
            self.stop.notify_one();
            let _ = handle.await;
        }
    }
}

impl Drop for Worker {
    fn drop(&mut self) {
        if let Some(handle) = self
            .handle
            .get_mut()
            .unwrap_or_else(|error| error.into_inner())
            .take()
        {
            handle.abort();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::events_test_support::{Behavior, Setup};
    #[tokio::test]
    async fn cutover_selects_new_subscription_while_both_grants_remain_enabled() {
        use crate::auth::Verifier;
        use crate::events_test_support::request;
        use std::sync::Arc;
        let setup = Setup::new();
        setup.subscribe().await;
        let mut binding = setup.provider.binding.clone();
        binding.hosted_client = "new-client".into();
        let mut claims = crate::provider_fixture::claims(&binding);
        claims["scope"] = serde_json::json!("identity:read events:subscribe");
        setup
            .provider
            .tokens
            .lock()
            .unwrap()
            .insert("new-token".into(), claims);
        let mut config = setup.provider.config["verifier"].clone();
        config["hosted_client"] = serde_json::json!(binding.hosted_client);
        let verifier =
            Arc::new(Verifier::from_config(serde_json::from_value(config).unwrap()).unwrap());
        let mut store = Store::open(&setup.provider.store_file).unwrap();
        store.migrate_profiles().unwrap();
        store.enroll("new-grant", &binding).unwrap();
        store.set_enabled("new-grant", 1, true).unwrap();
        let selected = Events::with_transport(
            setup.provider.store_file.clone(),
            setup.key.clone(),
            verifier.clone(),
            "new-grant".into(),
            setup.callback.clone(),
        );
        let identity = verifier.verify("new-token").await.unwrap();
        selected
            .subscribe(&identity, "new-token", "bus", "dot@bus", request())
            .await
            .unwrap();
        let db = setup.db();
        assert_eq!(
            db.query_row("SELECT COUNT(*) FROM grants WHERE enabled=1", [], |r| r
                .get::<_, i64>(0))
                .unwrap(),
            2
        );
        assert_eq!(
            db.query_row(
                "SELECT COUNT(*) FROM event_subscriptions WHERE status='active'",
                [],
                |r| r.get::<_, i64>(0)
            )
            .unwrap(),
            2
        );
        assert_eq!(db.query_row("SELECT grant_id FROM event_subscriptions WHERE bus='bus' AND mailbox='dot@bus' ORDER BY rowid LIMIT 1", [], |r| r.get::<_,String>(0)).unwrap(), "grant", "old subscription must predate the cutover");
        setup.seed("old-event", "dot@bus", 2, i64::MAX);
        setup.seed("new-event", "dot@bus", 2, i64::MAX);
        db.execute(
            "UPDATE custody_items SET grant_id='new-grant' WHERE event_id='new-event'",
            [],
        )
        .unwrap();
        assert_eq!(
            tick(&selected, "bus", "dot@bus").await.unwrap(),
            Tick::Accepted,
            "old enabled subscription starved selected new grant"
        );
        {
            let delivered = setup.callback.events.lock().unwrap();
            assert_eq!(delivered.len(), 1);
            assert_eq!(
                serde_json::from_slice::<Value>(&delivered[0].1).unwrap()["eventId"],
                "new-event"
            );
        }
        assert_eq!(
            db.query_row(
                "SELECT state FROM custody_outbox WHERE event_id='old-event'",
                [],
                |r| r.get::<_, String>(0)
            )
            .unwrap(),
            "pending"
        );
        assert_eq!(
            tick(&setup.runtime(), "bus", "dot@bus").await.unwrap(),
            Tick::Accepted
        );
        let delivered = setup.callback.events.lock().unwrap();
        assert_eq!(delivered.len(), 2);
        assert_eq!(
            serde_json::from_slice::<Value>(&delivered[1].1).unwrap()["eventId"],
            "old-event"
        );
    }

    #[tokio::test]
    async fn expiry_redacts_cached_previews_without_inventing_receipt_or_observation() {
        let setup = Setup::new();
        setup.subscribe().await;
        let cutoff = now().unwrap() - 1;
        setup.seed("expired-pending", "dot@bus", 2, cutoff);
        setup.seed("expired-accepted", "dot@bus", 2, cutoff);
        let db = setup.db();
        db.execute(
            "UPDATE custody_outbox SET body=?1",
            [b"retained plaintext preview".as_slice()],
        )
        .unwrap();
        db.execute(
            "UPDATE custody_outbox SET state='accepted' WHERE event_id='expired-accepted'",
            [],
        )
        .unwrap();
        assert_eq!(
            tick(&setup.runtime(), "bus", "dot@bus").await.unwrap(),
            Tick::Idle
        );
        let bodies: i64 = db
            .query_row(
                "SELECT COUNT(*) FROM custody_outbox WHERE body IS NOT NULL",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(
            bodies, 0,
            "dispatcher expiry retained a cached plaintext preview"
        );
        assert_eq!(
            db.query_row(
                "SELECT state FROM custody_outbox WHERE event_id='expired-accepted'",
                [],
                |row| row.get::<_, String>(0)
            )
            .unwrap(),
            "accepted",
            "expiry invented a different historical callback outcome"
        );
        // Exercise ordinary custody expiry independently of the dispatcher's earlier wipe.
        db.execute(
            "UPDATE custody_outbox SET body=?1",
            [b"legacy cached preview".as_slice()],
        )
        .unwrap();
        let mut store = Store::open(&setup.provider.store_file).unwrap();
        store
            .custody_status(
                &crate::custody::Scope {
                    bus_instance: "bus".into(),
                    grant_id: "grant".into(),
                },
                &crate::custody::Limits::default(),
                SystemTime::now(),
                604800,
            )
            .unwrap();
        assert_eq!(db.query_row("SELECT COUNT(*) FROM custody_items c JOIN custody_outbox box ON box.event_id=c.event_id WHERE c.text IS NOT NULL OR c.envelope IS NOT NULL OR box.body IS NOT NULL",[],|row|row.get::<_,i64>(0)).unwrap(),0,"expired content remains in custody or the outbox preview cache");
        assert_eq!(
            db.query_row("SELECT COUNT(*) FROM event_observations", [], |row| row
                .get::<_, i64>(0))
                .unwrap(),
            0,
            "expiry invented consumer observation"
        );
        assert!(
            setup.callback.events.lock().unwrap().is_empty(),
            "expired content left custody"
        );
    }

    #[tokio::test]
    async fn signed_retry_preserves_identity_body_and_never_observes_work() {
        let setup = Setup::new();
        setup.subscribe().await;
        setup.seed("message", "dot@bus", 2, i64::MAX);
        setup
            .callback
            .behaviors
            .lock()
            .unwrap()
            .push_back(Behavior::TimeoutAfterAccept);
        assert_eq!(
            tick(&setup.runtime(), "bus", "dot@bus").await.unwrap(),
            Tick::Retry
        );
        setup
            .db()
            .execute("UPDATE custody_outbox SET next_attempt=0", [])
            .unwrap();
        assert_eq!(
            tick(&setup.runtime(), "bus", "dot@bus").await.unwrap(),
            Tick::Accepted
        );
        assert_eq!(
            tick(&setup.runtime(), "bus", "dot@bus").await.unwrap(),
            Tick::Idle
        );
        let received = setup.callback.events.lock().unwrap();
        assert_eq!(received.len(), 2);
        assert_eq!(received[0].1, received[1].1, "retry body/ID changed");
        let value: Value = serde_json::from_slice(&received[0].1).unwrap();
        assert_eq!(value["eventId"], "message");
        assert_eq!(value["data"]["mailbox"], "dot@bus");
        let count: i64 = setup
            .db()
            .query_row("SELECT COUNT(*) FROM event_observations", [], |r| r.get(0))
            .unwrap();
        assert_eq!(count, 0, "callback acceptance claimed observation");
    }
    #[tokio::test]
    async fn mailbox_revision_expiry_and_due_head_are_enforced_before_provider_calls() {
        let setup = Setup::new();
        setup.subscribe().await;
        setup.seed("foreign", "foreign@bus", 2, i64::MAX);
        setup.seed("old", "dot@bus", 1, i64::MAX);
        setup.seed("expired", "dot@bus", 2, 1);
        setup.seed("owned", "dot@bus", 2, i64::MAX);
        assert_eq!(
            tick(&setup.runtime(), "bus", "dot@bus").await.unwrap(),
            Tick::Accepted
        );
        {
            let received = setup.callback.events.lock().unwrap();
            assert_eq!(received.len(), 1);
            let value: Value = serde_json::from_slice(&received[0].1).unwrap();
            assert_eq!(value["eventId"], "owned");
        }
        let calls = setup
            .provider
            .requests
            .load(std::sync::atomic::Ordering::SeqCst);
        assert_eq!(
            tick(&setup.runtime(), "bus", "dot@bus").await.unwrap(),
            Tick::Idle
        );
        assert_eq!(
            setup
                .provider
                .requests
                .load(std::sync::atomic::Ordering::SeqCst),
            calls,
            "idle tick introspected"
        );
        let observed: i64 = setup
            .db()
            .query_row("SELECT COUNT(*) FROM event_observations", [], |r| r.get(0))
            .unwrap();
        assert_eq!(observed, 0);
    }
    #[tokio::test]
    async fn retry_after_and_terminal_delivery_statuses_are_distinct() {
        for status in [429, 503] {
            let setup = Setup::new();
            setup.subscribe().await;
            setup.seed("message", "dot@bus", 2, i64::MAX);
            setup
                .callback
                .behaviors
                .lock()
                .unwrap()
                .push_back(Behavior::Response(status, Some("120".into())));
            let before = now().unwrap();
            assert_eq!(
                tick(&setup.runtime(), "bus", "dot@bus").await.unwrap(),
                Tick::Retry
            );
            let due: i64 = setup
                .db()
                .query_row("SELECT next_attempt FROM custody_outbox", [], |r| r.get(0))
                .unwrap();
            assert!(due >= before + 120, "Retry-After ignored");
            let count = setup.callback.events.lock().unwrap().len();
            assert_eq!(
                tick(&setup.runtime(), "bus", "dot@bus").await.unwrap(),
                Tick::Idle
            );
            assert_eq!(setup.callback.events.lock().unwrap().len(), count);
        }
        for (status, reason) in [(410, "delivery_gone"), (413, "payload_protocol_error")] {
            let setup = Setup::new();
            setup.subscribe().await;
            setup.seed("message", "dot@bus", 2, i64::MAX);
            setup
                .callback
                .behaviors
                .lock()
                .unwrap()
                .push_back(Behavior::Response(status, None));
            assert_eq!(
                tick(&setup.runtime(), "bus", "dot@bus").await.unwrap(),
                Tick::Dead
            );
            let (last, state): (String, String) = setup
                .db()
                .query_row(
                    "SELECT b.last_error,s.status FROM custody_outbox b,event_subscriptions s",
                    [],
                    |r| Ok((r.get(0)?, r.get(1)?)),
                )
                .unwrap();
            assert_eq!(last, reason);
            assert_eq!(state, "active", "terminal delivery disabled subscription");
        }
    }
    #[tokio::test]
    async fn expiry_revocation_and_generation_fence_stop_dispatch_or_outcome() {
        let setup = Setup::new();
        setup.subscribe().await;
        setup.seed("message", "dot@bus", 2, i64::MAX);
        setup
            .db()
            .execute("UPDATE event_subscriptions SET expires=1", [])
            .unwrap();
        assert_eq!(
            tick(&setup.runtime(), "bus", "dot@bus").await.unwrap(),
            Tick::Idle
        );
        assert!(setup.callback.events.lock().unwrap().is_empty());
        setup
            .db()
            .execute("UPDATE event_subscriptions SET expires=9999999999", [])
            .unwrap();
        setup
            .provider
            .tokens
            .lock()
            .unwrap()
            .get_mut("good-token")
            .unwrap()["active"] = json!(false);
        assert_eq!(
            tick(&setup.runtime(), "bus", "dot@bus").await.unwrap(),
            Tick::CredentialRequired
        );
        assert!(setup.callback.events.lock().unwrap().is_empty());
        setup
            .provider
            .tokens
            .lock()
            .unwrap()
            .get_mut("good-token")
            .unwrap()["active"] = json!(true);
        setup
            .db()
            .execute("UPDATE custody_outbox SET next_attempt=0", [])
            .unwrap();
        setup
            .callback
            .behaviors
            .lock()
            .unwrap()
            .push_back(Behavior::GenerationChange(
                setup.provider.store_file.clone(),
            ));
        assert_eq!(
            tick(&setup.runtime(), "bus", "dot@bus").await.unwrap(),
            Tick::Idle
        );
        let accepted: i64 = setup
            .db()
            .query_row(
                "SELECT COUNT(*) FROM custody_outbox WHERE state='accepted'",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(accepted, 0, "stale generation committed receipt");
    }
    #[test]
    fn jitter_is_bounded_positive_and_attempt_limited() {
        for attempt in 1..=5 {
            for _ in 0..20 {
                let delay = retry_delay(attempt).unwrap();
                assert!(delay >= (1 << attempt));
                assert!(delay <= 300);
            }
        }
    }
}

#[cfg(test)]
use crate::event_observer_fixture as selection_observer;

#[cfg(test)]
mod concurrent_tests {
    use super::*;
    use crate::events_test_support::Setup;
    use std::sync::atomic::Ordering;
    use std::sync::{Arc, Mutex};
    #[tokio::test]
    async fn stale_selection_is_rechecked_after_lease_before_introspection() {
        let setup = Arc::new(Setup::new());
        setup.subscribe().await;
        setup.seed("message", "dot@bus", 2, i64::MAX);
        let (selected_tx, selected_rx) = std::sync::mpsc::sync_channel(0);
        let (release_tx, release_rx) = std::sync::mpsc::sync_channel(0);
        let release_rx = Mutex::new(release_rx);
        let first = setup.clone();
        let worker = std::thread::spawn(move || {
            let subscriber = selection_observer::AtEvent {
                target: "gateway_events_selected",
                action: move || {
                    selected_tx.send(()).unwrap();
                    release_rx
                        .lock()
                        .unwrap()
                        .recv_timeout(Duration::from_secs(10))
                        .unwrap();
                },
            };
            tracing::subscriber::with_default(subscriber, || {
                tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                    .unwrap()
                    .block_on(tick(&first.runtime(), "bus", "dot@bus"))
            })
        });
        selected_rx.recv_timeout(Duration::from_secs(10)).unwrap();
        assert_eq!(
            tick(&setup.runtime(), "bus", "dot@bus").await.unwrap(),
            Tick::Accepted
        );
        let calls = setup.provider.requests.load(Ordering::SeqCst);
        release_tx.send(()).unwrap();
        assert_eq!(worker.join().unwrap().unwrap(), Tick::Idle);
        assert_eq!(
            setup.provider.requests.load(Ordering::SeqCst),
            calls,
            "stale post-lease selection reached introspection"
        );
        assert_eq!(
            setup.callback.events.lock().unwrap().len(),
            1,
            "concurrent candidate submitted twice"
        );
    }
}

#[cfg(test)]
mod retry_clock_tests {
    use super::*;
    #[test]
    fn fractional_failures_dates_and_large_retry_after_never_retry_early() {
        let completed = UNIX_EPOCH + Duration::from_millis(100_900);
        assert_eq!(retry_deadline(completed, 2, None).unwrap(), 103);
        assert_eq!(retry_deadline(completed, 2, Some("120")).unwrap(), 221);
        let date = httpdate::fmt_http_date(UNIX_EPOCH + Duration::from_secs(103));
        assert!(retry_deadline(completed, 2, Some(&date)).unwrap() >= 103);
        assert_eq!(
            retry_deadline(completed, 2, Some("9999999999999999999999999999999999")).unwrap(),
            i64::MAX
        );
    }
}

#[cfg(test)]
mod authority_race_tests {
    use super::*;
    use crate::events_test_support::{request, Behavior, Setup};
    use std::sync::atomic::Ordering;
    use std::sync::{Arc, Mutex};
    #[tokio::test]
    async fn selected_grant_is_rechecked_when_owner_switches_before_lease() {
        let setup = Arc::new(Setup::new());
        let identity = setup.subscribe().await;
        setup.seed("a", "dot@bus", 2, i64::MAX);
        let (selected_tx, selected_rx) = std::sync::mpsc::sync_channel(0);
        let (release_tx, release_rx) = std::sync::mpsc::sync_channel(0);
        let release_rx = Mutex::new(release_rx);
        let first = setup.clone();
        let worker = std::thread::spawn(move || {
            let observer = super::selection_observer::AtEvent {
                target: "gateway_events_selected",
                action: move || {
                    selected_tx.send(()).unwrap();
                    release_rx
                        .lock()
                        .unwrap()
                        .recv_timeout(Duration::from_secs(10))
                        .unwrap();
                },
            };
            tracing::subscriber::with_default(observer, || {
                tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                    .unwrap()
                    .block_on(tick(&first.runtime(), "bus", "dot@bus"))
            })
        });
        selected_rx.recv_timeout(Duration::from_secs(10)).unwrap();
        let mut store = Store::open(&setup.provider.store_file).unwrap();
        store.set_enabled("grant", 2, false).unwrap();
        store.enroll("other", &setup.provider.binding).unwrap();
        store.set_enabled("other", 1, true).unwrap();
        let other = Events::with_transport(
            setup.provider.store_file.clone(),
            setup.key.clone(),
            setup.verifier.clone(),
            "other".into(),
            setup.callback.clone(),
        );
        other
            .subscribe(&identity, "good-token", "bus", "dot@bus", request())
            .await
            .unwrap();
        setup.seed("b", "dot@bus", 2, i64::MAX);
        setup
            .db()
            .execute(
                "UPDATE custody_items SET grant_id='other' WHERE event_id='b'",
                [],
            )
            .unwrap();
        let calls = setup.provider.requests.load(Ordering::SeqCst);
        release_tx.send(()).unwrap();
        assert_eq!(worker.join().unwrap().unwrap(), Tick::Idle);
        assert!(
            setup.callback.events.lock().unwrap().is_empty(),
            "runtime dispatched a different selected grant"
        );
        assert_eq!(setup.provider.requests.load(Ordering::SeqCst), calls);
    }
    #[tokio::test]
    async fn cached_body_is_not_delivered_if_content_expires_during_introspection() {
        let setup = Arc::new(Setup::new());
        setup.subscribe().await;
        setup.seed("message", "dot@bus", 2, i64::MAX);
        setup
            .callback
            .behaviors
            .lock()
            .unwrap()
            .push_back(Behavior::Response(503, None));
        assert_eq!(
            tick(&setup.runtime(), "bus", "dot@bus").await.unwrap(),
            Tick::Retry
        );
        setup
            .db()
            .execute("UPDATE custody_outbox SET next_attempt=0", [])
            .unwrap();
        let tokens = setup.provider.tokens.clone();
        let (held_tx, held_rx) = std::sync::mpsc::sync_channel(0);
        let (release_tx, release_rx) = std::sync::mpsc::sync_channel(0);
        let blocker = std::thread::spawn(move || {
            let _guard = tokens.lock().unwrap();
            held_tx.send(()).unwrap();
            release_rx.recv_timeout(Duration::from_secs(10)).unwrap();
        });
        held_rx.recv_timeout(Duration::from_secs(10)).unwrap();
        let calls = setup.provider.requests.load(Ordering::SeqCst);
        let runtime = setup.runtime();
        let worker = tokio::spawn(async move { tick(&runtime, "bus", "dot@bus").await });
        tokio::time::timeout(Duration::from_secs(2), async {
            while setup.provider.requests.load(Ordering::SeqCst) == calls {
                tokio::time::sleep(Duration::from_millis(1)).await;
            }
        })
        .await
        .unwrap();
        // Force the expiry boundary while the real provider is holding the response.
        setup
            .db()
            .execute(
                "UPDATE custody_items SET expires_at=1 WHERE event_id='message'",
                [],
            )
            .unwrap();
        release_tx.send(()).unwrap();
        blocker.join().unwrap();
        assert_eq!(worker.await.unwrap().unwrap(), Tick::Idle);
        assert_eq!(
            setup.callback.events.lock().unwrap().len(),
            1,
            "expired cached content left custody after provider wait"
        );
    }
}

#[cfg(test)]
#[path = "event_crash_tests.rs"]
mod crash_tests;

#[cfg(test)]
mod policy_tests {
    use super::*;
    use crate::events_test_support::{Behavior, Setup};
    use crate::outbound::{Permission, Policy};
    use std::sync::{Arc, Mutex};

    #[tokio::test]
    async fn policy_edit_preserves_subscription_pending_wakes_and_inflight_callback_outcome() {
        let setup = Setup::new();
        setup.subscribe().await;
        setup.seed("old-pending", "dot@bus", 2, i64::MAX);
        let lifecycle = || {
            setup.db().query_row("SELECT status,generation,expires,url,secret,bearer,callback_cursor,observation_checkpoint FROM event_subscriptions",[],|row|Ok((row.get::<_,String>(0)?,row.get::<_,i64>(1)?,row.get::<_,i64>(2)?,row.get::<_,Vec<u8>>(3)?,row.get::<_,Vec<u8>>(4)?,row.get::<_,Vec<u8>>(5)?,row.get::<_,i64>(6)?,row.get::<_,i64>(7)?))).unwrap()
        };
        let before = lifecycle();
        let first = Policy {
            send: Some(Permission {
                targets: ["first@peer".into()].into(),
                required_scope: "identity:read".into(),
            }),
            reply: None,
        };
        let mut store = Store::open(&setup.provider.store_file).unwrap();
        assert_eq!(store.set_outbound_policy("grant", 2, &first).unwrap(), 3);
        assert_eq!(
            lifecycle(),
            before,
            "policy edit invalidated subscription or reset lifecycle"
        );
        assert_eq!(
            setup
                .db()
                .query_row("SELECT grant_revision FROM event_subscriptions", [], |r| {
                    r.get::<_, i64>(0)
                })
                .unwrap(),
            3
        );
        assert_eq!(
            tick(&setup.runtime(), "bus", "dot@bus").await.unwrap(),
            Tick::Accepted,
            "policy edit stranded an old pending wake"
        );
        setup.seed("new-wake", "dot@bus", 3, i64::MAX);
        assert_eq!(
            tick(&setup.runtime(), "bus", "dot@bus").await.unwrap(),
            Tick::Accepted,
            "policy edit stranded a new wake"
        );
        setup.seed("inflight", "dot@bus", 3, i64::MAX);
        let (entered, received) = tokio::sync::oneshot::channel();
        let (resume, released) = tokio::sync::oneshot::channel();
        setup
            .callback
            .behaviors
            .lock()
            .unwrap()
            .push_back(Behavior::Pause {
                entered,
                resume: released,
            });
        let runtime = setup.runtime();
        let delivery = tokio::spawn(async move { tick(&runtime, "bus", "dot@bus").await });
        tokio::time::timeout(Duration::from_secs(3), received)
            .await
            .unwrap()
            .unwrap();
        let (waiting, waited) = tokio::sync::oneshot::channel();
        let waiting = Arc::new(Mutex::new(Some(waiting)));
        let file = setup.provider.store_file.clone();
        let next = Policy {
            send: Some(Permission {
                targets: ["next@peer".into()].into(),
                required_scope: "identity:read".into(),
            }),
            reply: None,
        };
        let policy = tokio::task::spawn_blocking(move || {
            tracing::subscriber::with_default(
                selection_observer::AtEvent {
                    target: "gateway_operation_wait",
                    action: move || {
                        if let Some(sender) = waiting.lock().unwrap().take() {
                            let _ = sender.send(());
                        }
                    },
                },
                || {
                    Store::open(&file)
                        .unwrap()
                        .set_outbound_policy("grant", 3, &next)
                },
            )
        });
        tokio::time::timeout(Duration::from_secs(3), waited)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            setup
                .db()
                .query_row("SELECT revision FROM grants WHERE id='grant'", [], |r| r
                    .get::<_, i64>(0))
                .unwrap(),
            3,
            "policy writer bypassed callback lease"
        );
        resume.send(()).unwrap();
        assert_eq!(delivery.await.unwrap().unwrap(), Tick::Accepted);
        assert_eq!(
            tokio::time::timeout(Duration::from_secs(3), policy)
                .await
                .unwrap()
                .unwrap()
                .unwrap(),
            4
        );
        assert_eq!(
            setup
                .db()
                .query_row(
                    "SELECT state FROM custody_outbox WHERE event_id='inflight'",
                    [],
                    |r| r.get::<_, String>(0)
                )
                .unwrap(),
            "accepted",
            "policy edit lost an accepted callback outcome"
        );
        assert_eq!(
            setup
                .db()
                .query_row(
                    "SELECT status,generation,grant_revision FROM event_subscriptions",
                    [],
                    |r| Ok((
                        r.get::<_, String>(0)?,
                        r.get::<_, i64>(1)?,
                        r.get::<_, i64>(2)?
                    ))
                )
                .unwrap(),
            ("active".into(), 1, 4)
        );
        setup.seed("fenced", "dot@bus", 4, i64::MAX);
        store.set_enabled("grant", 4, false).unwrap();
        store.set_enabled("grant", 5, true).unwrap();
        store
            .set_outbound_policy("grant", 6, &Policy::default())
            .unwrap();
        assert_eq!(
            tick(&setup.runtime(), "bus", "dot@bus").await.unwrap(),
            Tick::Idle
        );
        assert_eq!(
            setup
                .db()
                .query_row(
                    "SELECT state FROM custody_outbox WHERE event_id='fenced'",
                    [],
                    |r| r.get::<_, String>(0)
                )
                .unwrap(),
            "held"
        );
        assert_eq!(
            setup
                .db()
                .query_row(
                    "SELECT dispatch_revision FROM event_authorizations WHERE event_id='fenced'",
                    [],
                    |r| r.get::<_, i64>(0)
                )
                .unwrap(),
            4,
            "policy edit revived authority fenced by disable/reenable"
        );
        assert_eq!(setup.callback.events.lock().unwrap().len(), 3);
    }
}
