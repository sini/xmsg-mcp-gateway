# Inbound custody unit

This unit adds durable inbound acceptance, deduplication, quarantine, bounded
content-free refusal records and explicit ACK integration through xmsg::client.
It reuses the existing grant Store and rusqlite transaction boundary. It does
not expose a worker startup command or callback dispatcher. Configured MCP
send/reply is implemented separately by the [serving profile](serving.md#optional-messaging-profile)
and [outbound layer](outbound.md). That does not activate this inbound worker or
release held inbound work.

The implementation must preserve existing authority during an explicit schema
migration. Opening state does not migrate it, recreate it or enroll authority.
A delivery is keyed by the configured bus-instance identity and upstream message
ID. Its original grant ID/revision, mailbox owner, attested origin, correlation,
stored body and event identity survive restart. A matching redelivery returns
the stored event; a changed origin/body/correlation is durably quarantined before
ACK. A deterministic refusal (including oversized input) persists a content-free
record carrying actual bounded byte size before ACK. Transient admission-capacity
and store/rollback failures remain unacknowledged. Failure to persist custody,
quarantine or refusal must never ACK.

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
- About 150 oversized messages produce 150 content-free refusal records and
  leave no pending upstream slots; a following valid message is delivered.
  Transient full admission or store failure remains unacknowledged.
- Refusal/quarantine metadata has configurable age and count bounds, expiry
  counters and a visible failure when a new required record cannot be stored.
- Known outstanding message age, rather than downtime alone, drives possible-loss
  warnings; offline intervals record uncertainty without inventing message IDs.
- Each safety oracle has a single-site source mutant. Build errors, absent tests
  and timeouts never count as kills.

Messaging startup now compares its manifest against reply TTL, idempotency TTL,
service queue capacity and body bounds reported by the actual registration. It
also checks the gateway retry lifetime against the node's deduplication TTL.
The [serving profile](serving.md#optional-messaging-profile) describes those checks
and their acceptance cells; the gateway does not derive effective limits from
daemon arguments or treat its manifest as the node's source of truth.

Inbound worker activation remains pending. It must reuse the validated
registration and the session's configured custody limits, and preserve the
[owner-decision boundaries](serving.md#deployment-boundaries). The implemented
outbound startup checks do not select a first-subscription policy or authorize
release of held inbound work.
