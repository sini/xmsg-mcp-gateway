//! Explicit consumer responsibility and read-only uncertain-send lookup.
use crate::auth::VerifiedIdentity;
use crate::event_store::EventKey;
use crate::grants::{Error as GrantError, Store};
use rusqlite::{params, OptionalExtension};
use serde::Deserialize;
use serde_json::{json, Value};

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct AckArguments {
    pub(crate) message_id: String,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct StatusArguments {
    pub(crate) request_id: String,
}

pub(crate) enum Request {
    Ack(AckArguments),
    Status(StatusArguments),
}

#[derive(Debug, thiserror::Error)]
pub(crate) enum Error {
    #[error("invalid recovery arguments")]
    Arguments,
    #[error(transparent)]
    Authority(#[from] GrantError),
    #[error("recovery store unavailable")]
    Database(#[from] rusqlite::Error),
    #[error(transparent)]
    Events(#[from] crate::event_store::Error),
    #[error("recovery record encoding unavailable")]
    Encoding(#[from] serde_json::Error),
    #[error("broker result unavailable")]
    Broker(#[from] crate::outbound::Error),
}

pub(crate) fn expired_result(request_id: &str) -> Value {
    json!({"state":"expired","request_id":request_id,
        "not_reexecuted":true,"reconciliation_required":true})
}

pub(crate) fn owner_key(
    identity: &VerifiedIdentity,
    bus: &str,
    mailbox: &str,
    grant: &str,
) -> String {
    crate::events::owner_key(identity, bus, mailbox, grant)
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn dispatch(
    store: Store,
    identity: &VerifiedIdentity,
    bus: &str,
    mailbox: &str,
    selected_grant: &str,
    key: &EventKey,
    request: Request,
    limits: &crate::outbound::Limits,
) -> Result<Value, Error> {
    store.require_events_ready(key)?;
    let tx = store.connection.unchecked_transaction()?;
    let authority = store.authorize(identity)?;
    if authority.grant_id != selected_grant {
        return Err(crate::grants::Error::Denied.into());
    }
    let now = crate::webhook::signing_time().map_err(|_| Error::Arguments)?;
    match request {
        Request::Status(args) => {
            crate::outbound::RequestId::parse(&args.request_id).map_err(|_| Error::Arguments)?;
            let owner = crate::custody::fingerprint(&[
                identity.service(),
                identity.issuer(),
                identity.resource(),
                identity.subject(),
            ]);
            if store.outbound_recovery_expired(
                &owner,
                &args.request_id,
                mailbox,
                &authority.grant_id,
                limits,
            )? {
                return Ok(expired_result(&args.request_id));
            }
            let mut statement = tx.prepare("SELECT operation,state,receipt,retry_until,recovery_until FROM outbound_reservations WHERE owner=?1 AND request_id=?2 AND sender=?3 AND grant_id=?4 ORDER BY operation")?;
            let mut matches = Vec::new();
            for row in statement.query_map(
                params![owner, args.request_id, mailbox, authority.grant_id],
                |r| {
                    Ok((
                        r.get::<_, String>(0)?,
                        r.get::<_, String>(1)?,
                        r.get::<_, Option<String>>(2)?,
                        r.get::<_, i64>(3)?,
                        r.get::<_, Option<i64>>(4)?,
                    ))
                },
            )? {
                let (operation, state, receipt, retry_until, recovery_until) = row?;
                if recovery_until.ok_or(crate::outbound::Error::Busy)? <= now {
                    let mut value = expired_result(&args.request_id);
                    value["operation"] = json!(operation);
                    matches.push(value);
                    continue;
                }
                let effective = if receipt.is_some() {
                    "confirmed"
                } else if retry_until <= now {
                    "expired_unknown"
                } else {
                    state.as_str()
                };
                let receipt = receipt
                    .map(|raw| serde_json::from_str::<Value>(&raw))
                    .transpose()?;
                let mut value = json!({"operation":operation,"state":effective,"receipt":receipt});
                if effective == "expired_unknown" {
                    value["reconciliation_required"] = json!(true);
                }
                matches.push(value);
            }
            if matches.is_empty() {
                if store.retired_outbound(&owner, &args.request_id, mailbox, &authority.grant_id)? {
                    return Ok(expired_result(&args.request_id));
                }
                return Ok(json!({"state":"not_found"}));
            }
            Ok(json!({"request_id":args.request_id,"results":matches}))
        }
        Request::Ack(args) => {
            crate::event_store::record_expiry(&tx, now)?;
            if args.message_id.is_empty() || args.message_id.len() > 4096 {
                return Err(Error::Arguments);
            }
            let event: Option<String> = tx.query_row("SELECT c.event_id FROM custody_items c JOIN event_authorizations a ON a.event_id=c.event_id WHERE c.bus=?1 AND c.mailbox=?2 AND c.owner=?3 AND c.grant_id=?4 AND a.dispatch_revision=?5 AND c.upstream_id=?6 AND c.text IS NOT NULL AND c.expires_at>?7",params![bus,mailbox,identity.subject(),authority.grant_id,authority.revision,args.message_id,now],|r|r.get(0)).optional()?;
            let Some(event) = event else {
                return Ok(json!({"state":"not_found"}));
            };
            let owner = owner_key(identity, bus, mailbox, &authority.grant_id);
            tx.execute(
                "INSERT OR IGNORE INTO event_observations(event_id,observed_at) VALUES (?1,?2)",
                params![event, now],
            )?;
            let next_unobserved:Option<i64> = tx.query_row("SELECT MIN(o.seq) FROM event_occurrences o JOIN custody_items c ON c.event_id=o.event_id JOIN event_authorizations a ON a.event_id=c.event_id LEFT JOIN event_observations seen ON seen.event_id=c.event_id WHERE c.bus=?1 AND c.mailbox=?2 AND c.owner=?3 AND c.grant_id=?4 AND a.dispatch_revision=?5 AND c.text IS NOT NULL AND c.expires_at>?6 AND seen.event_id IS NULL",params![bus,mailbox,identity.subject(),authority.grant_id,authority.revision,now],|r|r.get(0))?;
            // Sequence gaps belong to other mailboxes or unavailable history, not an observation.
            let observed_checkpoint:i64 = tx.query_row("SELECT COALESCE(MAX(o.seq),0) FROM event_occurrences o JOIN custody_items c ON c.event_id=o.event_id JOIN event_authorizations a ON a.event_id=c.event_id JOIN event_observations seen ON seen.event_id=c.event_id WHERE c.bus=?1 AND c.mailbox=?2 AND c.owner=?3 AND c.grant_id=?4 AND a.dispatch_revision=?5 AND (?6 IS NULL OR o.seq<?6)",params![bus,mailbox,identity.subject(),authority.grant_id,authority.revision,next_unobserved],|r|r.get(0))?;
            let previous: i64 = tx
                .query_row(
                    "SELECT observation_checkpoint FROM event_checkpoints WHERE owner_key=?1",
                    [&owner],
                    |row| row.get(0),
                )
                .optional()?
                .unwrap_or(0);
            let checkpoint = observed_checkpoint.max(
                previous.min(
                    next_unobserved
                        .map(|sequence| sequence.saturating_sub(1))
                        .unwrap_or(i64::MAX),
                ),
            );
            let unavailable: i64 = tx
                .query_row(
                    "SELECT unavailable_through FROM event_availability WHERE owner_key=?1",
                    [&owner],
                    |row| row.get(0),
                )
                .optional()?
                .unwrap_or(0);
            tx.execute("INSERT INTO event_checkpoints(owner_key,observation_checkpoint) VALUES (?1,?2) ON CONFLICT(owner_key) DO UPDATE SET observation_checkpoint=MAX(observation_checkpoint,excluded.observation_checkpoint)",params![owner,checkpoint])?;
            tx.execute("UPDATE event_subscriptions SET observation_checkpoint=MAX(observation_checkpoint,?1) WHERE owner_key=?2 AND grant_revision=?3",params![checkpoint,owner,authority.revision])?;
            let cursor = crate::event_cursor::encode(key, &owner, checkpoint)?;
            tracing::debug!(target:"gateway_ack_before_commit", "responsibility acknowledgement prepared");
            tx.commit()?;
            tracing::debug!(target:"gateway_ack_after_commit", "responsibility acknowledgement committed");
            Ok(
                json!({"message_id":args.message_id,"state":"observed","checkpoint":cursor,"truncated":unavailable>0,"meaning":"durable acceptance of responsibility; not task completion"}),
            )
        }
    }
}

#[cfg(test)]
#[path = "recovery_tests.rs"]
mod tests;

#[cfg(test)]
mod retirement_surface_tests {
    #[test]
    fn expired_requests_require_reconciliation_without_retry_advice() {
        let value = super::expired_result("old-request");
        assert_eq!(value["state"], "expired");
        assert_eq!(value["not_reexecuted"], true);
        assert_eq!(value["reconciliation_required"], true);
        assert!(value.get("retry").is_none());
        assert!(value.get("receipt").is_none());
    }
}
