# Outbound custody foundation

A configured lifetime L guarantees eligibility for at least L seconds and expires
observable access before L+1 seconds, using one checked ceiling of the sub-second
observation instant. Repeated access never extends an existing stored expiry.
Physical reclaim follows the existing access/heartbeat cadence, which bounds its
lag; no background purger is introduced.

The Rust listener exposes this library through `xmsg_list`, `xmsg_send` and `xmsg_reply` when
an owner-file `messaging` profile is configured and the verifier scopes and
owner-set grant policy permit each operation. Without that section the listener
serves identity only. Invalid or incomplete messaging configuration refuses
startup; it does not fall back to identity-only serving. Registration, effective
node limits and explicit schema migrations are checked before readiness. See the
[current messaging profile](serving.md#optional-messaging-profile).

Real-node MCP behavior is covered by
[`real_mcp_send_keeps_request_identity_and_owner_policy`](../tests/messaging.rs),
[`mcp_replies_use_owned_custody_and_the_original_bus_receipt`](../tests/messaging.rs)
and [`absent_messaging_is_identity_only_and_partial_messaging_is_not`](../tests/messaging.rs).
These local cells do not select a live deployment, start an inbound worker or
implement Rust Events. The [deployment boundaries](serving.md#deployment-boundaries)
remain in force.

The owner runs `migrate-custody` (schema 1 to 2), then `migrate-outbound`
(2 to 3), then `migrate-retirement`, each with `--state FILE`. The retirement
migration is explicit and works before or after the separate Events migration.
Opening state never migrates it. Take a database backup before migrating.
The retirement migration changes the database application marker atomically.
Older gateway binaries refuse to open the migrated database. Rolling back to an
older gateway binary requires restoring a pre-migration database backup; the
migrated database cannot be used by that older binary. Outbound
operations refuse a pre-migration store; inbound custody remains valid at 2 or 3.
`set-outbound-policy GRANT REVISION FILE` is an owner CLI verb, with a matching
Store API. Policy is empty until explicitly written; writing policy increments
the grant revision and never enables it. There is no MCP policy mutation tool,
automatic population, or fixture-only constructor.

For repeatable configuration, use the idempotent owner command:

```sh
xmsg-mcp-gateway --state FILE apply --id GRANT --policy POLICY.json --enabled
```

Omit both state flags to preserve the grant's current enablement. Use `--disabled`
to explicitly disable it; `--enabled` and `--disabled` conflict. An already matching
policy and requested state print `unchanged at revision N` and exit successfully.
Policies are compared as typed values, so JSON key order, whitespace, target order
and duplicate targets do not cause a write. A policy change on an enabled grant
keeps it enabled unless `--disabled` is specified.

Each actual policy change writes policy once and advances the revision by one;
an enablement change advances it by one more. Thus policy-only and enable-only
changes are +1, both changes are +2, and an unchanged apply is +0. All changes,
including Events transitions, commit atomically under the existing service lease.
Apply snapshots the revision before waiting on that lease and rechecks it even
for a prospective no-op. Invalid policy, missing grants, a concurrent revision
change or an enable-uniqueness conflict refuse without changing business state.
Retry a refused concurrent apply after inspecting the winning configuration.
The existing `set-outbound-policy`, `enable` and `disable` commands remain
available with their explicit revision arguments and existing behavior.

For example, an owner policy document can allow one exact destination:

```json
{"send":{"targets":["receiver@example.node"],"required_scope":"xmsg:send"},"reply":null}
```

The configured verifier must require `xmsg:send` too. This policy file is an owner
input to the CLI, not an MCP argument or listener activation switch.

Policy has optional `send` and `reply` permissions, each naming exact service
addresses (`<service>@<node>`) or node-scoped wildcards (`*@<node>`) in `targets`
and a `required_scope`. Partial globs (`foo*@node`, `*@*`) are refused. A node-scoped
`*@<node>` entry admits any live recipient on `<node>` (an `svc` service, an `instance`,
or a `subagent`). The verifier must require that
scope and verify it on the actual token. In `Policy::validate`, `send.targets`
may be empty (an empty allowlist is valid: `xmsg_send` is not advertised or
callable, while `xmsg_list` is advertised when `send.required_scope` is held
and returns `{"recipients": []}`), whereas `reply.targets` must still be
non-empty:

```rust
if self
    .reply
    .as_ref()
    .is_some_and(|permission| permission.targets.is_empty())
{
    return Err(Error::Configuration);
}
```

`xmsg_list(node?, kind?, status?, within?)` is gated by `send.required_scope`
(no new scope). It queries the leaf's existing `xmsg list` and filters the
returned recipients to `send.targets` with live status on healthy nodes: exact
`<service>@<node>` entries admit only `svc` services, while `*@<node>` entries
admit that node's live `svc` services, `instance` sessions and `subagent`s.
Optional filters (`node`, `kind`, `status`, `within` in `1..=604800` when
`status` is `"inactive"`) only narrow that permitted set and never widen it,
and an empty policy returns `{"recipients": []}` with no fleet or node
metadata. For `xmsg_send`, exact `<service>@<node>` entries admit only live
`svc` services; `*@<node>` entries resolve `<instance-id or label>@<node>`,
`<parent>/<child>@<node>` and `<service>@<node>` through the leaf's live
`xmsg list` view on healthy `<node>`, refusing ambiguous labels (`> 1` live
matches). Reply targets come from an owned, attested inbound correlation in
this store, rather than caller-selected reply addresses: an inbound service
origin (`origin.service` set, `origin.id` unset) is admitted by either exact
`<service>@<origin.node>` or `*@<origin.node>` in `reply.targets`, whereas an
inbound session or subagent origin (`origin.id` set, `origin.service` unset)
requires `*@<origin.node>` specifically in `reply.targets` (exact
`<service>@<node>` never admits replies to sessions on that node).

`RequestId` is required and explicitly parsed. It accepts 1 to 128 ASCII letters,
digits and `.`, `_`, `:`, `-`. Missing, null, numeric and unknown arguments refuse.
There is no default or conversion from a JSON-RPC value. The dispatcher has no
JSON-RPC ID input. Reservations are unique on the verified owner profile,
and raw request ID across operations, with a canonical payload fingerprint. Changed payloads
conflict. A confirmed duplicate returns the stored original xmsg receipt even
through its result recovery deadline, including after a policy revision or expiry
of its inbound reply correlation, provided
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

## Reservation retirement

New effect retries are covered by the registered xmsg idempotency TTL. The
manifest's `dedup_lifetime_secs` remains accepted for configuration compatibility;
it cannot extend that TTL. Existing stored effect deadlines are never extended.
`messaging.result_recovery_secs` defaults to 86400 seconds (24 hours) and must be
at least the registered idempotency TTL. A node with a longer TTL requires an
explicitly longer result recovery setting; otherwise startup refuses.

Effect retry and result recovery are separate lifetimes anchored at acceptance.
Configuration shrink can shorten persisted deadlines; later increases, duplicate
requests and status reads cannot reopen them. Clock rollback conservatively closes
effect retries. Expiry never cancels an original operation already accepted upstream.

Retirement runs on demand during messaging and recovery, without a new daemon.
It shares the operation lease with publishers, so an in-flight publisher cannot
lose its reservation before recording its receipt or uncertainty. One SQLite
transaction records the refusal witness and removes retired large request/receipt
content. Crashes leave either the original record or the witness. An unavailable
archive is an error, never permission to treat an old ID as new.

The permanent witness is keyed by authenticated owner and raw `request_id`, across
send, reply and gist operations. Reusing an ID for a different operation is not a
new request. Migration preserves both already-recorded outcomes when a legacy
send and reply shared an ID, while fencing further effects under that ID.

After result recovery expires, retry and status return `state: "expired"` with
`not_reexecuted: true` and an explicit reconciliation requirement. This describes
the retry: it does not mean the original operation failed or was cancelled. No
new upstream call occurs. The gateway never silently substitutes a new ID.

The broker keeps the accepted proposal and its send receipt/correlation linkage
through the result recovery window, independently of the shorter retry window.
Result reads still require current authority and an attested, owned correlated
reply. A bus receipt does not prove GitHub processing. Once content is retired,
an old ID stays refusable even though its original result is unavailable.

`max_reservations` and `max_retained_bytes` bound the active working set, not the
lifetime number of accepted IDs. Retired large content no longer consumes those
quotas. The exact permanent ID archive grows with historical requests: total
metadata storage is unbounded over an unlimited lifetime. SQLite pages, indexes
and WAL overhead also remain outside the framed-content byte limit. Archive
capacity failures fail closed; deleting its witnesses is not a safe cleanup.

A policy-only edit carries only this grant's currently authorized Events custody
and current subscription revision to the new revision. It keeps the subscription
active without rotating its generation or secrets, resetting expiry/cursors, or
holding pending wakes. Older or NULL authority, foreign grants, and original
acceptance snapshots remain unchanged. Existing callback verification and delivery
hold the service lease through receipt commit, so a concurrent policy edit cannot
lose an accepted callback outcome. `apply` followed by an actual enablement change
still performs that enablement transition and its existing fences atomically.

Events replies still require exact current authorization, ownership and current
reply targets, including same-request-ID receipt replay. Carry-forward preserves
reply eligibility across policy-only edits; disable/re-enable cycles, new bindings
and explicit rebinds retain their fences. Legacy custody has no Events authority
witness, so its conservative exact accepted-revision guard remains unchanged.
Recovery item visibility survives policy-only edits, but revision-bound inbox
pagination cursors must be restarted. Recovery reads do not mutate custody.
