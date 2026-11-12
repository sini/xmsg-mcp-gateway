# Rust mailbox Events

The Rust gateway can receive messages addressed to its registered xmsg service,
commit custody before acknowledging xmsg, and deliver signed
`xmsg.message.received.v1` wake hints to the authenticated owner's subscription.
It retains the mailbox for repeatable reads and recovery. The shipped gateway
has no Python dependency. The [synthetic hosted probe](hosted-dots-setup.md) and
Python reference are separate examples; their results do not establish a deployed
Rust integration.

## Configure and migrate

Start with the [OAuth listener configuration](serving.md#owner-configuration),
a compatible [OAuth provider](provider-setup.md), and the
[messaging profile](serving.md#optional-messaging-profile). Events require both
`messaging` and an `events` section. The selected grant must match the verifier's
service, issuer, resource, subject and approved hosted client. The registered
service supplies the bus and mailbox; callers cannot choose either.

Provision a separate, persistent Events key: exactly 32 random bytes in a regular
mode-0600 file, owned by the state directory's account. Its directory must not be
writable by other users. Generate it once, keep it outside the database, and back
it up with the database. For a new local state directory:

```sh
install -d -m 700 .state
(umask 077; set -C; dd if=/dev/urandom bs=32 count=1 2>/dev/null > .state/events.key)
chmod 600 .state/events.key
```

The noclobber redirection refuses an existing key file. Replacing a key does not
rotate the encrypted data: the wrong or missing key prevents Events activation.
URLs, delivery secrets and retained legacy access tokens are encrypted with authenticated
owner/field binding. This keeps a copied database from exposing those values;
the gateway account still needs access to its key. Do not reuse a node, tunnel or
introspection credential as the encryption key.

For a **new Events grant**, migrate before enrollment so its never-enabled history
is explicit. After building the Rust binary with `cargo build --locked --release`:

```sh
target/release/xmsg-mcp-gateway --state .state/grants.db init
target/release/xmsg-mcp-gateway --state .state/grants.db migrate-custody
target/release/xmsg-mcp-gateway --state .state/grants.db migrate-outbound
target/release/xmsg-mcp-gateway --state .state/grants.db migrate-retirement
target/release/xmsg-mcp-gateway --state .state/grants.db migrate-events --key-file .state/events.key
target/release/xmsg-mcp-gateway --state .state/grants.db enroll grant-id binding.json
```

Supply the exact [binding document](../README.md#rust-grant-store-foundation).
Enrollment creates disabled revision 1. A first enable is an owner command:

```sh
target/release/xmsg-mcp-gateway --state .state/grants.db enable grant-id 1
```

It advances the revision and audits release of custody proven to have arrived
before that grant's first enable. An existing store needs only its outstanding
migrations; initialization never overwrites it. Migrations are explicit and
transactional, and no-op migrations fail. Migrated disabled grants have **unknown**
enable history. Legacy custody remains held even if its recorded revision happens
to match today's grant. Neither timestamps nor revision parity prove its history.
New arrivals under an unknown disabled grant also remain held. Use the explicit
selected release below to authorize retained historical items.

Merge this fragment into the complete owner configuration; it is not a complete
listener profile:

```json
{
  "request_timeout_ms": 60000,
  "events": {
    "key_file": "events.key",
    "grant_id": "grant-id",
    "dispatch_timeout_ms": 16000,
    "webhook_allowed_hosts": ["receiver.example.com"]
  }
}
```

**Planned, not yet released:** `events.webhook_allowed_hosts` optionally limits
subscribe/renew callbacks to exact DNS hostnames (ASCII or punycode, matched
case-insensitively). Wildcards, URLs, IP literals, ports and trailing dots are
invalid entries. An empty list denies every callback; an absent or `null` list is
**permissive**, preserving today's callback-host behavior and emitting a startup
warning. An unset list is not SSRF protection. Existing HTTPS, public-address,
connection-pinning and no-redirect checks still apply independently.

A host refusal returns `CallbackEndpointError` with reason
`callback_host_not_allowed` before callback verification or network I/O, and leaves
the prior subscription unchanged. The allowlist applies at subscribe and renew.
An already-active subscription to an off-list host can keep delivering until it
expires, subject to existing authorization and delivery checks. A
refused renewal leaves that old subscription active and does not extend its expiry.
The default TTL is 1 hour; a requested TTL is capped at 24 hours.
Setting the list does not cut delivery immediately. Use the existing owner
controls when an immediate stop is required.
At subscribe/renew the `gateway_events` info diagnostic records only the normalized
`callback_host` and a static reason, never the URL's scheme, port, path, query or
signing secret. Operators can initially omit the list, observe the host, then set
an exact list. No ChatGPT hostname pattern is assumed or published by this gateway.
For example, replace `receiver.example.com` above with the observed approved host.

Set `verifier.required_scopes` to include `identity:read` and `events:subscribe`.
Send/reply policies may require additional scopes. With `verifier.timeout_ms: 5000`,
the fragment's budgets meet the Events requirements:

| Budget | Startup requirement |
|---|---|
| `events.dispatch_timeout_ms` | At least `verifier.timeout_ms + 11000`, at most 60000 |
| `request_timeout_ms` | At least `2 * verifier.timeout_ms + 41000`, at most 60000 |

The request bound covers the post-challenge credential recheck as well as initial
verification, callback work and existing store waits. The messaging profile's
submission/store-wait requirement also applies. Owner operations and submissions
share a per-service OS file lease, so an in-flight bounded submission can delay
another operation. No SQLite transaction stays open across network I/O.

The optional `events.custody_limits` defaults to:

```json
{
  "max_items": 1000,
  "max_bytes": 67108864,
  "max_item_bytes": 262144,
  "content_retention_secs": 604800,
  "max_metadata": 1000,
  "metadata_retention_secs": 604800,
  "max_gap_intervals": 1000
}
```

If supplied, all seven positive fields are required. Ingestion and session health
use this same configuration. Relative state, credential, root-certificate and
Events-key paths resolve against the owner configuration's directory. For example,
`.state/serving.json` with `grant_store: "grants.db"` and `key_file: "events.key"`
uses the files created above.

```sh
target/release/xmsg-mcp-gateway serve --config .state/serving.json
```

Startup validates the real registered node and its declared limits before
readiness. An invalid Events profile refuses startup; it does not silently become
a messaging-only server. Without Events configuration, no inbound poller or
webhook worker starts. The listener remains OAuth-only and loopback-bound; use
the existing hosted setup guide for exposure and provider setup rather than the
example's no-authentication mode.

## Subscription and delivery contract

`initialize` advertises Events for the configured Events grant. The same authenticated `/mcp`
endpoint serves `events/list`, `events/subscribe` and `events/unsubscribe`.
Discovery returns one event, empty subscription arguments and webhook delivery.
The subscription request shape is:

```json
{
  "name": "xmsg.message.received.v1",
  "arguments": {},
  "delivery": {
    "mode": "webhook",
    "url": "https://receiver.example/events",
    "secret": "whsec_<base64-encoded-signing-key>"
  },
  "cursor": null
}
```

This shows the wire shape, not a literal usable secret. The decoded signing key
must contain 24–64 bytes. The returned subscription ID is deterministic for the
logical owner, event, arguments and callback. A different callback conflicts;
ordinary subscribe cannot take over the mailbox. The optional `ttlMs` requests a
lifetime: default one hour, minimum 60 seconds, maximum 24 hours. Omitted or null
requests receive a finite grant. `refreshBefore` is the granted subscription
expiry, separate from the current access token's expiry.

Before activating a callback, the gateway sends a signed, short-lived random
challenge and requires a successful response echoing it. Successful verification
is cached for 300 seconds for the same binding and key. Cache hits preserve the
actual verification time; repeated renewal cannot extend that window indefinitely.

**Planned, not yet released:** failed subscribe/renew requests leave an existing
subscription byte-for-byte unchanged, including its encrypted credential, keys,
expiry, generation and cursors. Callback verification (or its bounded cache) and
the final credential/grant check happen before a single transaction replaces the
subscription and releases eligible custody. No database transaction spans network
I/O. A failed first subscribe creates no provisional row. An old binding can keep
delivering after a refused renewal if its own credential and grant remain valid.

A replacement signing key is verified again. For 300 seconds the gateway signs
with both old and new keys; a third rotation during that window conflicts.
Subscription state, rotation and encrypted credentials survive gateway restart.

For a legacy bearer subscription, a due delivery introspects the stored access token and checks exact identity,
Events scope, current grant/revision, item eligibility and subscription generation
under the operation lease. Empty, held, accepted, dead and backoff ticks do not
introspect. An expired or revoked access token parks delivery until the same
logical owner renews through `events/subscribe` with a valid credential. It does
not delete the subscription or revoke the local grant. The gateway implements no
OAuth refresh flow on behalf of the hosted client. Subscription expiry itself
stops delivery until renewed.

**Planned, not yet released:** once a delivery parks for a credential, the
subscription in `events_status` reports `state: "renewal_required"` and
`reason: "credential_required"` immediately, including in `xmsg_inbox` and
`xmsg_read_message`. Expired and disabled states take precedence. A failed renewal
does not clear this signal. A successful renewal atomically clears the scoped
credential park and makes the delivery due again; existing attempt counts, event
IDs, saved payloads and consumer observations remain intact. Status reads do not
introspect credentials or mutate the subscription. Recovery requires a successful
`events/subscribe` renewal; an ordinary tool call does not replace the stored
credential.


Each request contains one event object with a stable event ID, first durable
observation timestamp, mailbox-bound cursor, and `data` containing message ID,
mailbox, attested origin, correlation, a preview of at most 256 Unicode characters,
`body_available` and sequence. Fetch full text with `xmsg_read_message`. The exact
serialized body and event ID survive retries; each attempt gets a fresh signing
time and Standard Webhooks signature, plus `X-MCP-Subscription-Id`. Complete event
bodies are limited to 256 KiB, callback responses to 64 KiB, and callback requests
to ten seconds.

Callbacks require public HTTPS. Every DNS answer must be public; the connection
is pinned to the checked addresses with the original TLS hostname. Redirects and
proxy routing are disabled for callbacks. TLS uses the platform trust store;
`SSL_CERT_FILE` and `SSL_CERT_DIR` are honored and, when supplied, replace native
root discovery. Configure the real CA bundle for NixOS, macOS or a container as
needed. Provider private-address pins and provider proxy policy remain separate;
they do not relax callback validation.

The worker checks eligible work immediately, then polls at 250 ms intervals.
Delivery is serial per mailbox. There are at most five attempts, including an
attempt durably reserved before a crash. After a retryable failure, the local delay
is `min(2^attempt + jitter, 300)` seconds, where jitter is randomly selected from
zero through `min(2^attempt, 300)`. HTTP 408, 429, 5xx and transport failures retry
within that budget. On 429 or 503, a valid `Retry-After` seconds value or HTTP date
is honored if it requires a later attempt; fractional completion time is rounded
up so retry never starts early.

HTTP 410 makes the **delivery** dead with `delivery_gone`; it does not disable the
subscription. HTTP 413 makes it dead with `payload_protocol_error`. Other terminal
responses and exhausted attempts also enter an explicit dead-letter state. A
backoff or dead-letter head blocks later deliveries and cursor advancement until
selected replay or retention clears the gap. Mailbox reads remain available.

## Receipt, responsibility and recovery

These states have different meanings:

| State | Meaning |
|---|---|
| xmsg acknowledged | The gateway committed durable custody |
| callback accepted | The hosted endpoint returned 2xx; processing is asynchronous |
| `xmsg_ack` observed | The consumer durably accepted responsibility for this message |
| domain result or correlated reply | Application-specific evidence of the work's result |

`xmsg_inbox` and `xmsg_read_message` are repeatable, read-only and bounded. They do
not release work or record an acknowledgement. `xmsg_message_status(request_id)`
reads the owned outbound ledger without reserving or submitting anything. It
returns operation-labelled send/reply results, distinguishing pending, unknown,
expired unknown and confirmed receipts; an unknown or foreign ID is not-found.
Uncertain sends must keep their original request ID and identical arguments.
After upstream deduplication protection expires, reconcile instead of blindly
resending.

`xmsg_ack(message_id)` is idempotent. Use it only after durably taking responsibility:
a single durable drainer can record the message locally before ACK, or concurrent
consumers can deduplicate by message ID and make their effects idempotent. ACK
is neither a work lease nor proof of task completion. Its response includes
`state: "observed"`, an opaque `checkpoint`, and a `truncated` flag. It does not
acknowledge xmsg again. Foreign, unknown, expired or ineligible items are not-found.

One logical owner can have several concurrent tasks; no conversation is an
exclusive owner. Duplicate and out-of-order wake hints are possible, especially
if a callback accepts before the gateway records its response. ChatGPT may batch
separately delivered events into a task. Use message-ID deduplication and the
existing send/reply request IDs rather than treating a wake as an instruction or
an exactly-once execution guarantee.

Callback receipt and consumer responsibility have separate durable checkpoints.
Events cursors survive content-anchor deletion, are opaque and mailbox-bound,
and never skip earlier eligible undelivered work. The observation checkpoint does
not pass earlier eligible retained unobserved work. Acknowledgement returns `truncated: true`
when unavailable history has been recorded; the checkpoint does not turn those missing records
into observations. Selected historical release can rebase either cursor position while preserving
all per-message responsibility records. An unavailable-history floor records
retention gaps separately: expiry never claims receipt or observation. Reconnect
and explicit resume report truncation when requested history is unavailable.
Earlier live items remain recoverable even if later items expired. The inbox
cursor has its own [retained-anchor semantics](serving.md#mailbox-recovery-reads).

During a temporary xmsg daemon outage, recovery reads and status use the last
validated registered mailbox; they do not need a new live handle to read retained
custody. Initial startup still requires successful registration and manifest
validation. Sends and replies require a healthy registration. Disable/re-enable
cycles and explicit rebinds retain their existing fences; renewal does not
silently authorize earlier-revision work. A policy-only edit atomically carries
that grant's current item authorizations and subscription revision forward. It
preserves subscription status, generation, secrets, expiry and cursors, and every
pending or completed wake outcome. NULL and older authorization revisions and
other grants are never promoted. The same service lease serializes policy writes
with callback verification and delivery through their receipt commits.

Replies remain gated by current enablement, the same grant and owner, and current
reply targets. Policy-only edits preserve eligible reply custody; disable/re-enable
does not. Recovery reads remain read-only and retain item visibility after a
policy edit. Their revision-bound pagination cursors must be restarted after the
revision changes.

`xmsg_identity` includes `events_status`: subscription state/generation/expiry,
opaque callback and observation cursors, retained counts by state, categorized
failure counts, oldest backlog age and a truncation indication. It exposes no
callback URL, signing key, token or message content. Use this health data and
bounded recovery tools to investigate failed delivery, rather than raw HTTP logs.

## Consumer wake and session recipe

At session start and on every wake, call `xmsg_inbox` and inspect
`events_status.subscription.state`. Successful inbox and message reads expose this
small, owned subscription state in the same read-only transaction as the content.
`xmsg_identity` remains available for the fuller Events status. If the state is
`disabled`, `expired` or `not_subscribed`, subscribe again through the existing
Events method. The planned `renewal_required` state specifically requires a
successful renewal with a valid credential; reading the inbox does not supply one.
If it is `verifying`, check state again before creating another subscription. A ChatGPT subscribe/task-service error can still complete later;
check for `active` before deleting the automation or replacing it.

Drain the current inbox view to its end, following `next` pagination and reading
full message bodies when needed. Deduplicate by durable message ID, including
across duplicate or reordered wakes. Process each new item, then call `xmsg_ack`
after handling it and durably recording responsibility. ACK is not a completion receipt
and does not delete retained inbox entries: an empty page or the end of pagination
means there is no more content in that view, while already-handled entries are
skipped using the consumer's durable deduplication/checkpoint state. Serialize or
coordinate concurrent wakes for the same logical mailbox owner.

An optional bounded periodic inbox/state check can reconcile independently of
webhook wakes. It is useful after a session restart or missed wake, and is not
proof that a callback was processed. Use the existing resubscribe and replay
mechanisms; there is no terminal fencing webhook or new consumer tool.

At the default filter, `gateway_events` INFO records subscription transitions,
delivery outcomes and held/released counts using closed static reasons and
numeric fields. They contain no callback URLs, cursors, message IDs, secrets or
bodies. Expiry is observed once for the current subscription generation per worker
lifetime without changing stored state; a worker restart may repeat that observation. Inspect these records together with owned subscription state; do not
collect raw credential-bearing request logs. An explicit `RUST_LOG` filter replaces
the default, so `RUST_LOG=warn` hides these INFO records.

## Local owner rebind and replay

These commands read state and key paths from `--config`. A global `--state` override
is refused. Obtain the current subscription ID from the subscribe result and its
generation from `xmsg_identity` health. Unknown IDs, stale generations and no-op
mutations fail rather than printing success. Operator and reason are recorded in
the audit; keep their text free of credentials and message content.

To replace a callback, place its URL in an owner-private file and run:

```sh
target/release/xmsg-mcp-gateway events-rebind --config .state/serving.json SUBSCRIPTION_ID GENERATION \
  --callback-file .state/callback-url --cursor OPAQUE_SAFE_CURSOR \
  --operator local-owner --reason 'replace callback'
```

The command preserves custody, fences the old binding and returns a replacement
ID with `verification_required`. The client must subscribe to the replacement
callback and pass verification before delivery starts. `--cursor` is optional;
without it, replay selection starts at the prior safe callback checkpoint.

Retry retained dead/accepted events already authorized for the current revision:

```sh
target/release/xmsg-mcp-gateway events-replay --config .state/serving.json SUBSCRIPTION_ID GENERATION \
  --cursor OPAQUE_SAFE_CURSOR --operator local-owner --reason 'retry selected range'
```

A cursor replays the eligible retained range after that position. This does not
change earlier-revision authority. To explicitly authorize particular historical
items, instead supply a private JSON file containing 1–100 distinct upstream
message IDs:

```json
["retained-message-id-one", "retained-message-id-two"]
```

```sh
target/release/xmsg-mcp-gateway events-replay --config .state/serving.json SUBSCRIPTION_ID GENERATION \
  --release-items-file .state/release-items.json \
  --operator local-owner --reason 'authorize retained historical messages'
```

`--cursor` and `--release-items-file` are mutually exclusive. Callback and release
files must be regular owner-private files (for example mode 0600). Selected release requires an active,
current authorized subscription and an enabled grant. It can reauthorize the
owner's retained old held, accepted, dead or unknown-history items; foreign,
expired, unknown IDs and already-current items refuse the entire selection.
Every release appends an audit with original and current authorization. Original
message/event IDs, body and acceptance snapshots stay unchanged. Callback and
responsibility checkpoint positions are rebased when needed to include newly
eligible historical work, without deleting per-item observation records.

After the audited first-enable transition, ordinary re-enable, credential renewal,
subscribe, rebind and reads do not release earlier-revision or ambiguous legacy
custody. No MCP tool performs these local
owner administration operations.

## Failure boundaries and fixture coverage

The tests use disposable local nodes, stores and callbacks, not a production hosted
deployment. The matrix distinguishes tested handoffs from the durable mechanism;
a simulated uncertain callback response is not a process-crash measurement. Dedicated child-process
cuts additionally cover durable-attempt and accepted-response handoffs:

| Failure or handoff | Durable behavior | Fixture source |
|---|---|---|
| Crash before custody commit | No upstream ACK; delivery can be offered again | [custody inbound](../tests/custody_inbound.rs) |
| Commit before upstream ACK | Redelivery keeps one message/event and original bytes | [custody inbound](../tests/custody_inbound.rs) |
| Custody ACK to callback dispatch | The wired session commits and ACKs before the signed owned wake; persisted pending custody survives interruption | [production session integration](../src/serving_events_tests.rs), [dispatcher mechanism](../src/event_dispatch.rs) |
| Process exits after durable attempt, before webhook | Attempt/body/ID remain stored; restart may retry within the remaining budget | [Events process-crash cuts](../src/event_crash_tests.rs) |
| Callback accepts, receipt is uncertain | Retry preserves body/ID; duplicate wake permitted; no observation implied | [dispatcher](../src/event_dispatch.rs), [accepted-response crash cut](../src/event_crash_tests.rs), [HTTPS receiver](../tests/events_https.rs) |
| Stale selection or competing worker | Work and authority are re-read after acquiring the operation lease | [dispatcher](../src/event_dispatch.rs) |
| Worker exits while holding the operation lease | The OS releases its file lock; the next worker rechecks durable state before submission | [Events process-crash cuts](../src/event_crash_tests.rs), [lease mechanism](../src/outbound_lease.rs) |
| Disable, grant switch or generation change | Stale authorization cannot submit or commit an outcome | [dispatcher](../src/event_dispatch.rs), [subscription lifecycle](../tests/events_rpc.rs) |
| Token revoked during verification | Subscription never activates | [subscription lifecycle](../tests/events_rpc.rs) |
| Repeated cache hits or secret rotation | Actual verification deadline remains bounded; signing keys retain their rotation window | [subscription lifecycle](../tests/events_rpc.rs) |
| Crash before/after responsibility commit | Only a committed observation survives; retry is idempotent | [responsibility recovery](../src/recovery_tests.rs) |
| Duplicate/out-of-order or receiver-batched wakes | Repeatable reads, message-ID responsibility records and request-ID effects preserve recovery semantics | [responsibility recovery](../src/recovery_tests.rs), [outbound custody](../tests/custody_outbound.rs); batching is performed by the receiver |
| Mixed live/expired history | Explicit gap/truncation, without skipping earlier live work or inventing observation | [subscription lifecycle](../tests/events_rpc.rs), [responsibility recovery](../src/recovery_tests.rs) |
| Selected historical release fails midway | Entire selection rolls back; original snapshots and observations survive | [selected replay](../tests/events_replay.rs) |
| Uncertain send/reply | Stable request key inside the protection window; reconciliation after expiry | [outbound custody](../tests/custody_outbound.rs) |

The mailbox boundary prevents unrelated bus content from becoming callback data.
Existing current grants, owned reply destinations and outbound policy remain
necessary when a wake leads to a tool call. Those checks address the concrete
outside-facing authority change without adding a second target policy or a
conversation-specific identity.

Protocol reference: [MCP Events](https://developers.openai.com/plugins/build/mcp-events).

## Planned AS family subscriptions and renewal

The [gateway authorization server](authorization-server.md) adds family-bound Events. A subscription authenticated by the local profile stores `token_family` instead of an encrypted bearer; exactly one credential form is retained. Callback URL/signing-secret encryption and the exact hostname allowlist still apply. Other accepted verifier profiles do not acquire custody/Events rights; `events.grant_id` remains the explicit selection.

`ttlMs` still defaults to one hour and clamps to 60 seconds through 24 hours. The family subscription is further clamped to its absolute expiry and idle end, **not** to the current access-token expiry. Dispatcher liveness can extend delivery eligibility across access-token expiry without minting a token, but cannot extend the subscription's own requested TTL. Renew before `refreshBefore`; refresh of an OAuth token pair alone is insufficient.

Subscribe and renew freshly verify the presented token and grant at the effect point before writing durable future wake authority. A revocation after initial admission but before that verification refuses the operation and leaves the prior subscription unchanged. Custody read/ACK and reply-target ownership lookup with its pre-effect recheck retain the current grant/revision fence. A disable after admission but before reply-target lookup refuses the new reply without a reservation or bus effect. There is no eligibility-history table restoring earlier custody rights. Normal local sends, broker calls and stored reply receipt/reservation recovery retain their admitted snapshot within budget. That snapshot includes the outbound policy in memory; a later policy edit does not alter the admitted send. No policy snapshot is stored durably.

When a family becomes invalid, delivery stays pending and is retried later; the local family path does not write legacy `credential_required`. The client must renew/re-subscribe with a live token to bind its new family. A new authorization, successful MCP call, shared subject or another live family never automatically changes the existing subscription. Automatic follow-on could revive a revoked callback owned by a thief. In the legacy path a reconnect can restore MCP while Events remains `credential_required` on the old retained bearer until renewal.

Local-family delivery uses the latest liveness outcome and the minimum of the delivery, family absolute and idle bounds. A due item triggers a read when that bound is within 600 seconds or past, at most once per family every 300 seconds, before taking the operation lease. Readable denials revoke; unavailable/indeterminate evidence permits only bounded grace. See [liveness, visibility and trusted-clock limits](authorization-server.md#lifetimes-and-liveness). Kanidm UI logout and consent removal alone do not disconnect local families.

For an issuer/grant move, use the owner-run [offline cutover guard and rollback](authorization-server.md#owner-run-migration-cutover-and-rollback). Changing `events.grant_id` alone neither transfers old custody nor updates the connector's stored family. This AS capability is planned; the legacy hosted OAuth/Events observations from 2026-11-10 do not certify the new flow.
