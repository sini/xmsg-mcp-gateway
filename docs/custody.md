# Inbound custody

A configured lifetime L guarantees eligibility for at least L seconds and expires
observable access before L+1 seconds, using one checked ceiling of the sub-second
observation instant. Repeated access never extends an accepted item or an identical last gap's stored expiry. New summary observations use the rolling retention contract below.
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
Existing custody databases also require the explicit command
`xmsg-mcp-gateway --state FILE migrate-custody-summaries`. Stop **all** gateway
processes before backing up the SQLite database and running this migration; then
restart with the new binary. The transaction folds every existing refusal and
gap detail into bounded summaries and changes the application format marker.
Previously released binaries refuse to open the migrated format. This fences
new opens, not a process that already holds the database open. Rollback requires
the backup made before migration. New `migrate-custody` databases already include
summaries; opening an older database never silently upgrades it. The summary
migration preserves the outbound/Events schema version and retirement state;
later retirement migration cannot downgrade the summary format marker.

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

Permanent oversized refusals and conflicting redeliveries commit a content-free
summary observation before ACK. A payload that cannot fit even an empty byte
quota is permanently oversized. Each admitted bus has at most two fixed classes:
`refusal` and `conflict`. They retain saturating observation counts, first/last
observation times, maximum observed byte size and a retained-until deadline.
These are **recorded observations, not unique messages**: repeated delivery after
an uncertain ACK can increase a count. Legacy non-conflict reasons fold into the
general refusal class without claiming they were oversized. No refusal ID,
origin, body or per-message fingerprint is retained in these summaries. Accepted
content and its original fingerprint remain in their existing custody records.
Size still counts UTF-8 bytes of text, envelope, attested-origin JSON and
correlation, rather than reconstructed wire-frame length.

Defaults remain 1000 custody item/tombstone slots, 64 MiB retained message data,
256 KiB per item, and 7-day content and metadata retention. Accepted content is
redacted at expiry while the original fingerprint and acceptance snapshot remain
for another metadata-retention window. Known pending IDs and admitted per-bus
link rows retain their separate 1000-row bounds (`max_metadata`). Permanent
refusal observations no longer exhaust a per-message refusal-detail budget.
Transient aggregate item/byte capacity remains Deferred and unacknowledged.
Required summary, pending or database writes still fail closed: rollback or a
failed summary commit never authorizes an ACK. Confirmed ACKs remove only the
exact known pending ID; an ACK transport error can leave its outcome uncertain.

Each admitted bus also has one rolling gap summary: a saturating observation
count, first/last bounds, maximum **individual** interval width and retained-until
deadline. The span from first to last is not treated as one outage. New interval
observations retain the maximum expiry, so continuous observation can retain an
older widest witness beyond that witness's own expiry. Repeating the identical
last interval keeps the minimum stored expiry and cannot renew it. There are no
expiry buckets. `max_gap_intervals` remains a validated positive compatibility
option; storage is now fixed at one summary per admitted bus regardless of it.

Acceptance, status and idle polls apply retention. A rolling cohort is removed
when its retained-until deadline expires. Until then its counts and widest
interval conservatively overreport history; they never claim precise distinct
messages or exact outage histories. Counts saturate at signed 64-bit maximum,
including expired-summary totals. `custody_status` exposes `gap_observations`,
`gap_first_seen`, `gap_last_seen`, `widest_gap_secs` and
`coalesced_uncertainty`. `offline_uncertainty` compares the retained widest
interval and the currently unobserved/disconnected span against the effective
reply TTL. It may remain true for a coalesced historical witness. Such a witness
never holds readiness or health red: readiness still requires a successful
current ledger commit, actual registration health and the current manifest.
A failed live ledger commit remains a readiness failure. Offline uncertainty and
known outstanding-message uncertainty remain separate inputs.

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

CI builds revision-verified private daemon fixtures, then requires the custody
cases with zero ignored/filtered tests and all completion markers. The crash
fixture kills an owned worker process while a content-free tracing subscriber
stops it immediately before or after the real acceptance commit. It reopens the
same database and proves redelivery, one stored event, original bytes and durable
ACK after a further daemon restart. Other cases drive 150 permanent refusals,
150 conflicting redeliveries, 1001 distinct refusals and valid traffic afterward, real upstream expiry,
retention, transient failures and mailbox selection. No fleet endpoints or
credentials are used. Missing-binary and source-edited early-return controls must
refuse. The source-mutant job rejects compile failures, cached library artifacts,
timeouts and failures outside the named assertion; all configured mutants must be killed.

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


## File reference custody (planned)

`migrate-attachments` explicitly adds reference JSON to custody and outbound reservations.
It requires outbound schema readiness and leaves the global schema version unchanged.
Without the extension, incoming file metadata is not acknowledged or silently discarded;
plain deliveries retain their existing behavior. Migration is atomic and rejects partial or
unrecognized attachment metadata schemas.

A delivery fingerprint binds canonical file references as well as its existing origin,
text, envelope and correlation. Identical redelivery stays a duplicate; changed references
under the same upstream ID are quarantined as a conflict. Both per-item and aggregate
custody bounds include reference metadata. Expiry clears references with retained body
content; no blob bytes are stored in the gateway. Inbox and message reads expose references
only under the existing complete ownership and dispatch-revision predicate. The file read
adds fresh effect-point checks before asking xmsg and before releasing the returned data.

With the planned authorization-server profile, attachment byte reads retain the same custody revision fence as other owned reads: both before and after the bus read, the current grant/revision must match the captured admission. A change refuses the response rather than returning bytes under stale custody authority.
