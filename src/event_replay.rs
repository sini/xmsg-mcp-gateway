//! Local owner-selected release. Ordinary enable, refresh and rebind never release old authority.
use std::collections::BTreeSet;

use rusqlite::{params, OptionalExtension, TransactionBehavior};
use serde_json::{json, Value};

use crate::events::{Error, Events};
use crate::grants::Store;

struct Binding {
    owner: String,
    service: String,
    grant: String,
    revision: i64,
    generation: i64,
    bus: String,
    mailbox: String,
    subject: String,
}

impl Events {
    /// Item IDs are upstream message IDs, scoped by the subscription's registered mailbox.
    /// This is an owner API, never an MCP tool or a refresh side effect.
    pub fn release_selected(
        &self,
        id: &str,
        expected_generation: i64,
        items: &[String],
        operator: &str,
        reason: &str,
    ) -> Result<Value, Error> {
        if id.is_empty()
            || expected_generation < 1
            || items.is_empty()
            || items.len() > 100
            || items
                .iter()
                .any(|item| item.is_empty() || item.len() > 4096)
            || items.iter().collect::<BTreeSet<_>>().len() != items.len()
            || operator.trim().is_empty()
            || operator.len() > 256
            || reason.trim().is_empty()
            || reason.len() > 1024
        {
            return Err(Error::Arguments);
        }
        let mut store = Store::open_for_dispatch(&self.file)?;
        store.require_events_ready(&self.key)?;
        let service: String = store
            .connection
            .query_row(
                "SELECT service FROM event_subscriptions WHERE id=?1 AND grant_id=?2",
                params![id, self.selected_grant],
                |row| row.get(0),
            )
            .optional()?
            .ok_or(Error::Conflict)?;
        let _lease = store.try_operation_lease(&service)?.ok_or(Error::Busy)?;
        let tx = store
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let now = crate::webhook::signing_time()?;
        let binding: Binding = tx.query_row(
            "SELECT s.owner_key,s.service,s.grant_id,g.revision,s.generation,s.bus,s.mailbox,s.subject
             FROM event_subscriptions s JOIN grants g ON g.id=s.grant_id
             WHERE s.id=?1 AND s.grant_id=?2 AND s.status='active' AND s.expires>?3 AND g.enabled=1
               AND s.grant_revision=g.revision AND s.service=g.service AND s.issuer=g.issuer
               AND s.resource=g.resource AND s.subject=g.subject AND s.hosted_client=g.hosted_client",
            params![id,self.selected_grant,now],
            |row|Ok(Binding{owner:row.get(0)?,service:row.get(1)?,grant:row.get(2)?,revision:row.get(3)?,generation:row.get(4)?,bus:row.get(5)?,mailbox:row.get(6)?,subject:row.get(7)?}),
        ).optional()?.ok_or(Error::Conflict)?;
        if binding.generation != expected_generation || binding.service != service {
            return Err(Error::Conflict);
        }
        let mut selected = Vec::with_capacity(items.len());
        for item in items {
            let record: Option<(String, i64, Option<i64>, String)> = tx
                .query_row(
                    "SELECT c.event_id,c.grant_revision,a.dispatch_revision,box.state
                 FROM custody_items c JOIN event_authorizations a ON a.event_id=c.event_id
                 JOIN custody_outbox box ON box.event_id=c.event_id
                 WHERE c.bus=?1 AND c.mailbox=?2 AND c.owner=?3 AND c.grant_id=?4
                   AND c.upstream_id=?5 AND c.text IS NOT NULL AND c.expires_at>?6",
                    params![
                        binding.bus,
                        binding.mailbox,
                        binding.subject,
                        binding.grant,
                        item,
                        now
                    ],
                    |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
                )
                .optional()?;
            let Some((event_id, original_revision, dispatch_revision, state)) = record else {
                return Err(Error::Conflict);
            };
            if !matches!(state.as_str(), "held" | "accepted" | "dead")
                || dispatch_revision == Some(binding.revision)
            {
                return Err(Error::Conflict);
            }
            selected.push((event_id, original_revision));
        }
        for (event_id, original_revision) in &selected {
            if tx.execute(
                "UPDATE event_authorizations SET dispatch_revision=?1 WHERE event_id=?2
                   AND (dispatch_revision IS NULL OR dispatch_revision!=?1)",
                params![binding.revision, event_id],
            )? != 1
            {
                return Err(Error::Conflict);
            }
            if tx.execute(
                "UPDATE custody_outbox SET state='pending',attempts=0,next_attempt=0
                 WHERE event_id=?1 AND state IN ('held','accepted','dead')",
                [event_id],
            )? != 1
            {
                return Err(Error::Conflict);
            }
            tx.execute(
                "INSERT INTO event_release_audit(event_id,grant_id,old_revision,new_revision,operator,reason)
                 VALUES (?1,?2,?3,?4,?5,?6)",
                params![event_id,binding.grant,original_revision,binding.revision,operator,reason],
            )?;
        }
        // Newly authorized historical work can precede both transport and responsibility
        // cursors. Rebase the cursors, never the immutable per-item observation history.
        let earliest: i64 = tx.query_row(
            "SELECT MIN(o.seq) FROM event_occurrences o JOIN custody_outbox box ON box.event_id=o.event_id
             JOIN custody_items c ON c.event_id=o.event_id JOIN event_authorizations a ON a.event_id=c.event_id
             WHERE c.bus=?1 AND c.mailbox=?2 AND c.owner=?3 AND c.grant_id=?4
               AND a.dispatch_revision=?5 AND box.state IN ('pending','dispatching','dead')
               AND c.text IS NOT NULL AND c.expires_at>?6",
            params![binding.bus,binding.mailbox,binding.subject,binding.grant,binding.revision,now],
            |row| row.get(0),
        )?;
        tx.execute(
            "UPDATE event_subscriptions SET callback_cursor=MIN(callback_cursor,?1)
             WHERE owner_key=?2 AND generation=?3",
            params![
                earliest.saturating_sub(1),
                binding.owner,
                binding.generation
            ],
        )?;
        let mut earliest_unobserved: Option<i64> = None;
        for (event_id, _) in &selected {
            let sequence:Option<i64>=tx.query_row(
                "SELECT o.seq FROM event_occurrences o LEFT JOIN event_observations seen ON seen.event_id=o.event_id WHERE o.event_id=?1 AND seen.event_id IS NULL",
                [event_id],|row|row.get(0)).optional()?;
            if let Some(sequence) = sequence {
                earliest_unobserved =
                    Some(earliest_unobserved.map_or(sequence, |earliest| earliest.min(sequence)));
            }
        }
        if let Some(sequence) = earliest_unobserved {
            let boundary = sequence.saturating_sub(1);
            tx.execute("UPDATE event_subscriptions SET observation_checkpoint=MIN(observation_checkpoint,?1) WHERE owner_key=?2 AND generation=?3",params![boundary,binding.owner,binding.generation])?;
            tx.execute("UPDATE event_checkpoints SET observation_checkpoint=MIN(observation_checkpoint,?1) WHERE owner_key=?2",params![boundary,binding.owner])?;
        }
        tx.commit()?;
        crate::event_diagnostic::transition("release", 0, 0, selected.len());
        Ok(json!({"id":id,"released":selected.len(),"grant_revision":binding.revision}))
    }
}
