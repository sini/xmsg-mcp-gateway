# Outbound custody foundation

A configured lifetime L guarantees eligibility for at least L seconds and expires
observable access before L+1 seconds, using one checked ceiling of the sub-second
observation instant. Repeated access never extends an existing stored expiry.
Physical reclaim follows the existing access/heartbeat cadence, which bounds its
lag; no background purger is introduced.

This library reserves and submits sends and replies using the pinned shared
xmsg client. The MCP serving configuration and listener do not expose it yet.
Send/reply tools still return "not yet available". The later startup unit must
wire the real registration limits and run the end-to-end MCP request-ID cells.

The owner runs `migrate-custody` (schema 1 to 2), then `migrate-outbound`
(2 to 3), each with `--state FILE`. Opening state never migrates it. Outbound
operations refuse a pre-migration store; inbound custody remains valid at 2 or 3.
`set-outbound-policy GRANT REVISION FILE` is an owner CLI verb, with a matching
Store API. Policy is empty until explicitly written; writing policy increments
the grant revision and never enables it. There is no MCP policy mutation tool,
automatic population, or fixture-only constructor.

For example, an owner policy document can allow one exact destination:

```json
{"send":{"targets":["receiver@example.node"],"required_scope":"xmsg:send"},"reply":null}
```

The configured verifier must require `xmsg:send` too. This policy file is an owner
input to the CLI, not an MCP argument or listener activation switch.

Policy has optional `send` and `reply` permissions, each naming exact service
addresses in `targets` and a `required_scope`. The verifier must require that
scope and verify it on the actual token. Anonymous, instance and label matches
cannot satisfy service discovery. Reply targets come from an owned, attested
inbound correlation in this store, rather than caller-selected reply addresses.

`RequestId` is required and explicitly parsed. It accepts 1 to 128 ASCII letters,
digits and `.`, `_`, `:`, `-`. Missing, null, numeric and unknown arguments refuse.
There is no default or conversion from a JSON-RPC value. The dispatcher has no
JSON-RPC ID input. Reservations are unique on the verified owner profile,
operation and request ID, with a canonical payload fingerprint. Changed payloads
conflict. A confirmed duplicate returns the stored original xmsg receipt even
after a policy revision or expiry of its inbound reply correlation, provided
current authority still permits that operation and target. Expired unresolved
work becomes unknown before stale acceptance revisions are considered.

The reservation commits as pending before submission. Its stable key and framed
bytes survive a process crash. Pending means possibly submitted; unknown means
no confirmed receipt is available. Recovery can retry only the same stored key
before the conservative deadline anchored at reservation. An elapsed deadline
requires reconciliation; it never authorizes a blind new send. These states do
not promise exactly-once execution or recipient processing. Send and reply
receipts preserve xmsg's fields and outcome vocabulary, including stored replies.

Retry deadlines round the reservation time plus the configured lifetime up to a
whole second, so a fractional creation time cannot shorten that lifetime. Stored
creation times remain floored for clock-rollback detection. Existing reservations
keep their recorded deadline; changing the rounding never extends an old row.
The boundary guard pins the reviewed upstream retention rule and must be reviewed
again when the xmsg pin changes.

An endpoint captures the address and AgentClient only from a RegisteredService.
The registration handle stays alive for the operation; its separate poll/ACK
channel can continue while outbound AgentClient I/O waits. The fixed external
message preamble names that actual sender and the stable gateway correlation.
The entire UTF-8 text, including this preamble, must fit both the supplied bound
and 65536 bytes, the pinned daemon's default ceiling. Nothing is truncated.

The durable operation guard is an OS file lease per logical service profile,
independent of SQLite. Submitters acquire it nonblocking; contention returns
pending without a second submission. The private 0600 regular file is opened
with O_NOFOLLOW, checked for owner and single-link custody, and never removed.
Different profiles have different leases. Kernel release permits recovery after
process death. Disable and owner policy changes acquire the same lease before
committing, so no later authorized submission begins after disable commits.
An in-flight accepted submission cannot be recalled by disabling the grant.

The dispatcher accepts a total asynchronous operation budget of at most 25 seconds
for verification, discovery and submission. It opens a dedicated SQLite connection
with no busy wait; the caller's Store retains its own custody wait behavior.
Owner disable/policy changes wait at most 30 seconds for the lease, then
fail visibly without changing authority. Synchronous filesystem/database I/O is
not a hard real-time guarantee. No SQLite transaction spans network I/O, and
inbound custody commits and ACKs never acquire this lease. Outcome commit records
the grant revision at submission and whether it changed afterward.
If SQLite is busy before reservation, the dispatcher returns a transient busy
refusal with no row or submission; retry uses the same request ID. If the outcome
commit is busy after xmsg accepted, it returns pending rather than reporting a
failed send. The existing durable pending row recovers with its stored key and
original upstream message ID. The schema permits no fabricated failed state.
An asynchronous deadline before any possible submission is a transient refusal,
not unknown. A resumed unconfirmed reservation is already possibly submitted;
its deadline cannot be treated as proof of refusal.

The caller supplies explicit dedup lifetime and reservation count/byte bounds.
There is no automatic ledger eviction that could forget an old request ID and
turn a repeat into a fresh send. Exhaustion refuses new reservations; reconciliation
and archival require a later owner workflow. The actual daemon TTL/queue checks
remain the prerequisite startup work rather than guessed manifest values.

The mandatory private-node profile runs 17 named cases with completion markers,
missing-fixture and early-return refusals. It covers both process-crash cuts,
same-ID receipts and payload conflicts, expired uncertainty, held revisions,
owned replies, disable ordering, inbound progress during stalled acceptance, and
both SQLite BUSY phases. Portable tests cover the explicit migrations, strict
request IDs (including a committed trybuild snapshot), per-service lease custody
and the real owner's 30-second timeout. Recovery that stalls while an unconfirmed
reservation exists remains unknown, as does a new send whose accepted response
is withheld beyond its budget. The 36 single-site source mutants must
fail their named assertions; compile failures, cached artifacts and harness
timeouts do not count as kills. A source control advances the supported schema
ceiling while requiring outbound schema 3 to remain usable. The later serving unit owns the end-to-end MCP
JSON-RPC-ID, missing-request-ID and default-empty-policy acceptance cells.
