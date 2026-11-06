# Inbound custody foundation

This unit receives through `xmsg::client::RegisteredService`. It adds no MCP
messaging, callback dispatcher, outbound submission or worker startup command.
All accepted messages and outbox occurrences remain held. The first-subscription
policy has no default, and disable/re-enable never rebinds an old acceptance.

Run the owner command `xmsg-mcp-gateway --state FILE migrate-custody` to migrate
an existing authority database from schema 1 to 2. Migration is explicit and
transactional; opening a database never creates missing state or silently
migrates it. Existing subjects, grant revisions and disabled enrollment survive.
An unchanged migration exits nonzero. Missing custody tables in schema 2 fail
closed. `receive_one` checks readiness before polling and returns
`MigrationRequired` for v1 without consuming or acknowledging a message.
There is no NixOS custody startup hook in this foundation: deployment must run
the separate owner migration command explicitly before a future worker can start.
The existing `serve` command still exposes only the earlier identity surface.
The existing grant Store and its FULL-synchronous SQLite connection are
reused; there is no second storage implementation.

The configured bus-instance namespace and upstream ID identify a message. Set
that namespace for the dedicated node database, keep it stable across restarts,
and change it if the node database is replaced. The local owner selects a grant
row. Its subject and revision are copied at acceptance. The logical profile name
in `Binding.service` need not equal the registration name in `XmsgConfig.service`.
The mailbox comes only from the actual registered handle; configuration cannot
supply a mailbox override.

One transaction commits the message and one held outbox event. An event ID is a
length-delimited SHA-256 derivation of the namespace and upstream ID. A matching
redelivery returns that stored event ID. The duplicate fingerprint covers the
attested origin, text, stored envelope and exact optional correlation. Display
labels provide no authority. Conflicts never replace original content: a durable,
content-free quarantine record precedes their ACK.

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
silently drop a required audit record to acknowledge a message.

Acceptance, status queries and idle receive polls apply retention. Disconnect
and reconnect observations are durable. Status distinguishes offline uncertainty
from possible loss of a known outstanding message. Known age is a lower bound
from first observation, not a fabricated upstream timestamp. When pending IDs
expire, a bounded per-bus summary preserves uncertainty without inventing expired
message records. A brief outage does not reset the age of an already old message;
an outage without known messages does not invent known-message loss.

The status library accepts an effective reply TTL for this comparison. No
configuration or startup path exposes that input. Before worker activation, the
XR5 follow-up must obtain reply TTL, idempotency TTL and queue capacity from the
actual registration response, enforce the reviewed window comparisons, and test
each mismatch. This foundation remains pinned to the reviewed daemon until that
follow-up. XR4's shared service-name validator and all other activation gates also
remain prerequisites.

CI builds revision-verified private daemon fixtures, then requires 18 custody
cases with zero ignored/filtered tests and all 18 completion markers. The crash
fixture kills an owned worker process while a content-free tracing subscriber
stops it immediately before or after the real acceptance commit. It reopens the
same database and proves redelivery, one stored event, original bytes and durable
ACK after a further daemon restart. Other cases drive 150 permanent refusals,
150 conflicting redeliveries, valid traffic afterward, real upstream expiry,
retention, transient failures and mailbox selection. No fleet endpoints or
credentials are used. Missing-binary and source-edited early-return controls must
refuse. The source-mutant job rejects compile failures, cached library artifacts,
timeouts and failures outside the named assertion; all 24 mutants must be killed.
