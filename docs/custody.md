# Inbound custody

A configured lifetime L guarantees eligibility for at least L seconds and expires
observable access before L+1 seconds, using one checked ceiling of the sub-second
observation instant. Repeated access never extends an existing stored expiry.
Physical reclaim follows the existing access/heartbeat cadence, which bounds its
lag; no background purger is introduced.

Inbound acceptance uses `xmsg::client::RegisteredService` and `receive_one`.
With a configured [Rust Events profile](events.md), the session polls incoming
service deliveries and the dispatcher sends signed mailbox wake hints. Without
Events configuration, the listener retains its identity/messaging behavior and
starts neither inbound polling nor callback delivery.

Custody commits before upstream ACK. Callback acceptance, explicit consumer
responsibility and application completion are separate states. Recovery
[inbox/body reads](serving.md#mailbox-recovery-reads) remain read-only. First enable
can audit release of proven never-enabled traffic. Earlier-revision or ambiguous
legacy custody stays held until explicit local owner selection; ordinary
re-enable, subscription renewal and callback rebind do not release it.

Run the owner command `xmsg-mcp-gateway --state FILE migrate-custody` to migrate
an existing authority database from schema 1 to 2. Migration is explicit and
transactional; opening a database never creates missing state or silently
migrates it. Existing subjects, grant revisions and disabled enrollment survive.
An unchanged migration exits nonzero. Missing custody tables in schema 2 fail
closed. `receive_one` checks readiness before polling and returns
`MigrationRequired` for v1 without consuming or acknowledging a message.
There is no NixOS custody startup hook in this foundation: deployment must run
the separate owner migration commands explicitly before a worker can start.
[Events migration](events.md#configure-and-migrate) follows custody and outbound
migrations and must precede enrollment when a new grant needs proven
never-enabled history. Legacy disabled history is unknown, never inferred.
The current configured versus identity-only `serve` behavior is documented and
linked to its real-node acceptance cells in the
[messaging profile](serving.md#optional-messaging-profile).
The existing grant Store and its FULL-synchronous SQLite connection are
reused; there is no second storage implementation.

The configured bus-instance namespace and upstream ID identify a message. Set
that namespace for the dedicated node database, keep it stable across restarts,
and change it if the node database is replaced. The local owner selects a grant
row. Its subject and revision are copied at acceptance. With Events migrated,
acceptance also records enable state and known first-enable history atomically;
separate dispatch authorization records any later audited release. The logical profile name
in `Binding.service` need not equal the registration name in `XmsgConfig.service`.
The mailbox comes only from the actual registered handle; configuration cannot
supply a mailbox override.

One transaction commits the message and one deduplicated outbox event.
Current enabled-revision traffic is pending for an eligible subscription;
never-enabled, earlier-disabled and unknown-history traffic is held according to
its recorded authorization. Pending work without a subscription remains durable. An event ID is a
length-delimited SHA-256 derivation of the namespace and upstream ID. A matching
redelivery returns that stored event ID. The duplicate fingerprint covers the
attested origin, text, stored envelope and exact optional correlation. Display
labels provide no authority. Conflicts never replace original content: a durable,
content-free quarantine record precedes their ACK.

Only oversized input is a deterministic refusal in this unit. Malformed frames
currently surface as transport failures; malformed, wrong-origin and policy
refusal handling needs the later serving/policy unit and its acceptance cells.

Permanent oversized refusals commit a content-free record and then ACK. A
payload that cannot fit even an empty byte quota is also permanently oversized.
Records contain ID, attested origin, actual byte size, reason and first-seen time,
with no body. Size means the UTF-8 bytes of text, envelope, attested-origin JSON
and correlation; it is not a reconstructed wire-frame length. Transient aggregate
item/byte capacity, metadata capacity and database/rollback failures remain
unacknowledged. The ACK response can be unknown on transport failure; committed
custody remains recoverable. Confirmed ACKs remove only the known pending ledger.

Defaults are 1000 custody item/tombstone slots, 64 MiB retained message data,
256 KiB per item, 7-day content retention, and 1000 refusal/quarantine records
with 7-day metadata retention. Expired content is redacted while its acceptance
snapshot and fingerprint remain a tombstone for another metadata-retention
window. Tombstones consume item slots until reclaimed, so their count is bounded.
Known pending IDs and per-bus link summaries each have a separate 1000-record
bound using the metadata limit. Expiry counters retain content-free totals.
Admission refuses when required durable metadata cannot be stored; it does not
silently drop a required audit record to acknowledge a message. About 1000
unique oversized sends within 7 days can therefore exhaust the refusal budget.
Further permanent refusals then remain unacknowledged, filling the upstream queue
and starving inbound traffic until records expire. This is the explicit cost of
the bounded, mandatory durable refusal ledger. Transient capacity deferrals use
only the separate pending ledger and consume no refusal budget.

Acceptance, status queries and idle receive polls apply retention. Every observed
poll persists its per-bus timestamp, including when connection state is unchanged.
Observed intervals form a bounded per-bus ledger. An older interval is removed
when a later interval has at least its duration and expiry; that later interval
preserves every TTL warning the older one could produce. Other intervals expire
at the metadata-retention bound. The default global gap budget is 1000 intervals
(`max_gap_intervals`); exhaustion fails visibly without ACK, independently of the
refusal budget. Healthy equal-sized poll intervals replace one another instead
of accumulating a record for every poll.
Steadily shrinking poll gaps do not replace earlier intervals. With the default
budget, this can exhaust the gap ledger after roughly 5.8 days of polling,
without any peer causing the pressure. Once exhausted, receive stops before
acceptance: nothing is ACKed and the upstream queue can starve until expired
gap records free capacity.
A later first poll records process downtime without a synthetic disconnect call.
Status compares recorded intervals and a currently unobserved/disconnected span
against the effective reply TTL; an outage count alone never sets uncertainty.
Sub-TTL gaps do not warn, and old intervals expire.
The historical warning expires with its gap record at metadata retention
(default 7 days); shortening retention shortens that warning's visibility.
An ongoing unobserved gap and known outstanding-message uncertainty are separate
status inputs.

Status distinguishes offline uncertainty from possible loss of a known outstanding
message. Known age is a lower bound from first observation, not a fabricated
upstream timestamp. When pending IDs expire, a bounded per-bus summary preserves
uncertainty without inventing expired message records. A brief outage does not
reset an already old message's age; unknown downtime does not create known IDs.

The status library accepts an effective reply TTL for this comparison. Messaging
startup now validates reply TTL, idempotency TTL, service queue capacity and body
bound against the actual registration, including the dedup lifetime comparison.
The Events receiver reuses that registration and shares
`events.custody_limits` with the session, including retention and gap budgets.
Messaging configuration uses the shared service-name validator.

CI builds revision-verified private daemon fixtures, then requires 22 custody
cases with zero ignored/filtered tests and all 22 completion markers. The crash
fixture kills an owned worker process while a content-free tracing subscriber
stops it immediately before or after the real acceptance commit. It reopens the
same database and proves redelivery, one stored event, original bytes and durable
ACK after a further daemon restart. Other cases drive 150 permanent refusals,
150 conflicting redeliveries, valid traffic afterward, real upstream expiry,
retention, transient failures and mailbox selection. No fleet endpoints or
credentials are used. Missing-binary and source-edited early-return controls must
refuse. The source-mutant job rejects compile failures, cached library artifacts,
timeouts and failures outside the named assertion; all 33 mutants must be killed.

The messaging session samples non-consuming health at most one second apart, but
writes healthy observations only every `min(reply_ttl / 2, 60 seconds)`. Down/up
transitions are still persisted before readiness. Downtime is over-estimated by
at most the observation interval; at production defaults that is 60 seconds.
A graceful SIGTERM/Ctrl-C drain writes a final healthy observation and disconnect
record, giving a clean stop its actual boundary instead of the coalesced one.
This does not relax the restart-gap or message-age loss checks.

Without an Events profile, session health uses `custody::Limits::default()`.
With Events, session health and ingestion share the configured limits described in
[Events setup](events.md). Events also retain opaque occurrence sequences,
responsibility checkpoints and an explicit unavailable-history floor; retention
does not fabricate callback receipt or consumer observation.
