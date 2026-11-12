use crate::auth::VerifiedIdentity;
use crate::events::{owner_key, Error, Events};
use crate::grants::Store;
use rusqlite::{params, OptionalExtension};
use serde_json::{json, Map, Value};
impl Events {
    pub(crate) fn health(
        &self,
        identity: &VerifiedIdentity,
        bus: &str,
        mailbox: &str,
    ) -> Result<Value, Error> {
        let store = Store::open_for_dispatch(&self.file)?;
        store.require_events_ready(&self.key)?;
        let _tx = store.connection.unchecked_transaction()?;
        let authority = store.authorize(identity)?;
        let now = crate::webhook::signing_time()?;
        if authority.grant_id != self.selected_grant || identity.expires_at() <= now as u64 {
            return Err(crate::grants::Error::Denied.into());
        }
        let owner = owner_key(identity, bus, mailbox, &authority.grant_id);
        let subscription:Option<(String,i64,i64,i64,i64)>=store.connection.query_row("SELECT status,generation,expires,callback_cursor,observation_checkpoint FROM event_subscriptions WHERE owner_key=?1",[&owner],|row|Ok((row.get(0)?,row.get(1)?,row.get(2)?,row.get(3)?,row.get(4)?))).optional()?;
        let effective_state = subscription_state(&store.connection, &owner, now)?;
        let observed: i64 = store
            .connection
            .query_row(
                "SELECT observation_checkpoint FROM event_checkpoints WHERE owner_key=?1",
                [&owner],
                |row| row.get(0),
            )
            .optional()?
            .unwrap_or(0);
        let observation_checkpoint = crate::event_cursor::encode(&self.key, &owner, observed)?;
        let subscription=subscription.map(|(_state,generation,expires,callback,observed)| ->Result<Value,Error> {
            let mut value = json!({"state":effective_state,"generation":generation,"refresh_before_unix":expires,
                "callback_cursor":crate::event_cursor::encode(&self.key,&owner,callback)?,"observation_checkpoint":crate::event_cursor::encode(&self.key,&owner,observed)?});
            add_renewal_reason(&mut value, effective_state);
            Ok(value)
        }).transpose()?.unwrap_or(json!({"state":"not_subscribed"}));
        let mut states = Map::new();
        let mut statement=store.connection.prepare("SELECT b.state,COUNT(*) FROM custody_outbox b JOIN custody_items c ON c.event_id=b.event_id WHERE c.bus=?1 AND c.mailbox=?2 AND c.owner=?3 AND c.grant_id=?4 GROUP BY b.state")?;
        for row in statement.query_map(
            params![bus, mailbox, identity.subject(), authority.grant_id],
            |row| Ok((row.get::<_, String>(0)?, row.get::<_, i64>(1)?)),
        )? {
            let (state, count) = row?;
            states.insert(state, json!(count));
        }
        let mut failures = Map::new();
        let mut errors=store.connection.prepare("SELECT b.last_error,COUNT(*) FROM custody_outbox b JOIN custody_items c ON c.event_id=b.event_id WHERE c.bus=?1 AND c.mailbox=?2 AND c.owner=?3 AND c.grant_id=?4 AND b.last_error IS NOT NULL GROUP BY b.last_error")?;
        for row in errors.query_map(
            params![bus, mailbox, identity.subject(), authority.grant_id],
            |row| Ok((row.get::<_, String>(0)?, row.get::<_, i64>(1)?)),
        )? {
            let (reason, count) = row?;
            failures.insert(reason, json!(count));
        }
        let oldest:Option<i64>=store.connection.query_row("SELECT MIN(c.received_at) FROM custody_items c JOIN custody_outbox b ON b.event_id=c.event_id WHERE c.bus=?1 AND c.mailbox=?2 AND c.owner=?3 AND c.grant_id=?4 AND c.text IS NOT NULL AND c.expires_at>?5 AND b.state IN ('pending','held','dead','dispatching')",params![bus,mailbox,identity.subject(),authority.grant_id,now],|row|row.get(0))?;
        let missing: i64 = store
            .connection
            .query_row(
                "SELECT unavailable_through FROM event_availability WHERE owner_key=?1",
                [owner],
                |row| row.get(0),
            )
            .optional()?
            .unwrap_or(0);
        Ok(
            json!({"subscription":subscription,"retained_events_by_state":states,"delivery_failures_by_reason":failures,"oldest_backlog_age_seconds":oldest.map(|first|now.saturating_sub(first)),"history_truncated":missing>0,"observation_checkpoint":observation_checkpoint}),
        )
    }
}

pub(crate) fn subscription_state(
    db: &rusqlite::Connection,
    owner: &str,
    now: i64,
) -> Result<&'static str, rusqlite::Error> {
    let row: Option<(String, i64)> = db
        .query_row(
            "SELECT status,expires FROM event_subscriptions WHERE owner_key=?1",
            [owner],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .optional()?;
    Ok(match row {
        Some((state, expires)) if state == "active" && expires <= now => "expired",
        Some((state, _)) if state == "active" => {
            let parked: bool = db.query_row("SELECT EXISTS(SELECT 1 FROM custody_outbox b JOIN custody_items c ON c.event_id=b.event_id JOIN event_authorizations a ON a.event_id=c.event_id JOIN event_subscriptions s ON s.owner_key=?1 WHERE b.state IN ('pending','dispatching') AND b.last_error='credential_required' AND c.bus=s.bus AND c.mailbox=s.mailbox AND c.owner=s.subject AND c.grant_id=s.grant_id AND a.dispatch_revision=s.grant_revision AND c.text IS NOT NULL AND c.expires_at>?2)", params![owner, now], |row| row.get(0))?;
            if parked {
                "renewal_required"
            } else {
                "active"
            }
        }
        Some((state, _)) if state == "verifying" => "verifying",
        Some((state, _)) if state == "disabled" => "disabled",
        Some(_) => "unrecognized",
        None => "not_subscribed",
    })
}

pub(crate) fn add_renewal_reason(value: &mut Value, state: &str) {
    if state == "renewal_required" {
        value["reason"] = json!("credential_required");
    }
}
