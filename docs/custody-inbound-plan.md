# Inbound custody unit

This unit adds durable inbound acceptance, deduplication, quarantine, bounded
content-free refusal records and explicit ACK integration through xmsg::client.
It reuses the existing grant Store and rusqlite transaction boundary. It does
not expose a worker startup command, MCP messaging, outbound submission or a
callback dispatcher.

The implementation must preserve existing authority during an explicit schema
migration. Opening state does not migrate it, recreate it or enroll authority.
A delivery is keyed by the configured bus-instance identity and upstream message
ID. Its original grant ID/revision, mailbox owner, attested origin, correlation,
stored body and event identity survive restart. A matching redelivery returns
the stored event; a changed origin/body/correlation is durably quarantined before
ACK. An oversized delivery or exhausted queue persists a content-free refusal
before returning without ACK. Failure to persist custody, quarantine or refusal
must never ACK.

All accepted work remains held in this unit. In particular, legacy unbound work
and work accepted before first enable cannot select a first-subscription policy.
Disable and re-enable cannot turn an old acceptance snapshot into a new one.
Later dispatch and selected replay must use the reviewed grant guard and audit
contract; this unit provides no dispatch path.

Acceptance oracles use isolated real-node fixtures, not fleet services:

- Crash before commit retains upstream redelivery; after commit/before ACK it
  retains the same gateway event and stored bytes without a second occurrence.
- Conflicting duplicates commit quarantine before ACK; repeated conflicts cannot
  exhaust the node's 100-slot service queue.
- After ACK, restart the daemon again and prove zero redelivery (transport P3).
- Oversized/full acceptance refuses without ACK, and a content-free refusal
  survives restart and upstream expiry.
- Refusal/quarantine metadata has configurable age and count bounds, expiry
  counters and a visible failure when a new required record cannot be stored.
- Known outstanding message age, rather than downtime alone, drives possible-loss
  warnings; offline intervals record uncertainty without inventing message IDs.
- Each safety oracle has a single-site source mutant. Build errors, absent tests
  and timeouts never count as kills.

Startup and Q1 remain pending the upstream effective-limits capability. The
registration response must report reply_ttl_secs, idempotency_ttl_secs and
svc_queue_cap from values actually in force. The gateway will compare its windows
against those values after re-pinning; it will not parse daemon arguments or
copy the manifest into a second purported source of truth. Each reported limit
needs its own acceptance cell and mutant in that follow-up. No activation is
permitted in the meantime.
