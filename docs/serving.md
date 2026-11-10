# Rust MCP listener

The Rust listener serves OAuth-protected MCP identity reads with durable local
grants. Its public resource metadata advertises the canonical resource and issuer
from the owner's configuration. `initialize`, `ping`, `tools/list`,
`notifications/initialized` and `xmsg_identity` are implemented. Standard `_meta`
progress tokens are accepted but unused. An optional owner-file messaging section
enables authorized `xmsg_send` and `xmsg_reply`, plus mailbox-scoped
`xmsg_inbox` and `xmsg_read_message` recovery reads. An optional [Events profile](events.md)
adds subscription methods, inbound polling, signed callback delivery,
`xmsg_message_status` and `xmsg_ack`. An optional [gist broker](#optional-gist-broker)
profile exposes typed gist operations through the configured service destination.

The existing xmsg MCP entry point is a harness-associated stdio adapter behind its
daemon feature. Service-node I/O belongs to the shared `xmsg::client` boundary.
Without a messaging section, serving opens no xmsg socket. The identity
result describes the verified OAuth service profile and grant revision; it claims
no bus registration or node address.

The optional owner-file `max_connections` defaults to 128 and must be a positive
integer no larger than the runtime semaphore capacity. The bound covers complete
TCP connections, including idle sockets and HTTP keepalive, rather than individual
requests. At capacity the listener promptly closes excess sockets before spawning
a handler; admitted connections remain usable. Closing an admitted connection
releases its slot. Capacity refusals have the typed `ConnectionCapacityRefusal`
reason and never include request content. Invalid values refuse startup with
`StartupError::Configuration`.

## Optional messaging profile

The owner-file constructor is asynchronous: registration, manifest validation and
schema readiness finish before a router is returned. A broken messaging section
refuses startup; it never degrades to identity-only serving. A present `null` messaging section
is invalid. No request can supply messaging configuration or choose a mailbox.

`messaging` denies unknown fields. Every manifest value that must agree with the
node is required: reply TTL, idempotency TTL, service queue capacity, gateway dedup
lifetime and complete framed bound. The other fields in the table are also required.
Gateway-local connection tunables retain their existing documented defaults:
`xmsg.max_frame_bytes` is 1,048,576 bytes and `xmsg.operation_timeout_ms` is 10,000 ms.
These are transport limits, distinct from the required node-bound manifest values.

| Field | Meaning |
|---|---|
| `xmsg` | Existing strict connection configuration: service, expected node, daemon UID and socket paths |
| `manifest.reply_ttl_secs` | Declared effective reply TTL |
| `manifest.idempotency_ttl_secs` | Declared effective upstream deduplication TTL |
| `manifest.svc_queue_cap` | Declared effective service queue capacity |
| `manifest.dedup_lifetime_secs` | Positive gateway retry lifetime, at most the effective upstream deduplication TTL |
| `manifest.max_framed_bytes` | Complete framed message including the gateway preamble, in bytes |
| `submission_timeout_ms` | Positive dispatcher deadline, at most 25 seconds |
| `max_reservations` | Positive retained outbound-operation limit |
| `max_retained_bytes` | Positive outbound-ledger byte limit |

The service name uses xmsg's shared validator. The retained registration supplies
the actual mailbox, node and effective TTL/capacity values; config supplies no bus
address. Explicit custody and outbound migrations are required before messaging.
Only the owner CLI/store changes per-grant policy. Empty send/reply policy
advertises no send/reply tools and refuses those calls. An enabled grant with
a registered mailbox still exposes its scoped recovery reads.

The real-node cells
[`real_mcp_send_keeps_request_identity_and_owner_policy`](../tests/messaging.rs),
[`mcp_replies_use_owned_custody_and_the_original_bus_receipt`](../tests/messaging.rs)
and [`absent_messaging_is_identity_only_and_partial_messaging_is_not`](../tests/messaging.rs)
cover configured sends, owned replies and the identity-only/invalid-profile
boundary respectively.

The handler budget must cover initial verification, the store's actual SQLite
busy wait and the submission deadline, within the existing 60-second ceiling.
The dispatcher uses a dedicated connection with a 250 ms SQLite busy wait for each
short transaction, within that budget. A longer lock yields a retryable refusal
before submission; after acceptance the durable reservation stays pending.
Dispatch runs in a separate task that owns its store and registration context.
Handler timeout returns pending with the same request ID; disconnect does not
cancel the outcome commit. Accepted packets cannot be recalled by disconnect.

The complete framed bound must fit the node's reported `max_body_bytes` as well
as the gateway's 65536-byte ceiling. A missing report or a smaller effective limit
refuses startup; the gateway never guesses it from launch arguments. The committed Cargo lockfile pins the shared xmsg client, including registration
health and socket activation. Live activation and exposure requirements below
still apply.

When messaging is configured, one session owner retains the registration. It
samples non-consuming registration health at most one second apart. Healthy bus
observations are coalesced in the existing bounded custody ledger to
`min(reply_ttl / 2, 60 seconds)`, while disconnect/reconnect transitions remain
durable before readiness. A disconnect invalidates the
old handle and withdraws dispatch snapshots. Re-registration uses the same
identity validation and Q1 checks, with a one-second backoff doubling to at most
30 seconds. Readiness is published only after a durable reconnect record and a
final health check. Changed limits or ledger failure keep messaging unavailable;
the manifest is never adapted automatically. While blocked on changed limits, the
owner keeps trying registration and drops each rejected handle, eventually once
every 30 seconds. The status remains blocked throughout that register/drop cycle.

`xmsg_identity` includes `messaging_status` only in this profile: `ready` with the
registered mailbox, `reconnecting`, or `blocked` with a reason. Sends and replies
return 503 while unavailable. Retained mailbox reads, Events status and explicit
consumer ACKs use the last validated registered mailbox during a temporary outage.
Recovery reads never poll or ACK xmsg, submit work, mint an idempotency key,
or authorize replay. A caller retries uncertain
work with its original request ID. Link records retain the custody ledger's
existing seven-day / 1000-gap bounds and capacity costs; an exhausted ledger also
blocks messaging until a durable update can succeed.

The detached task's `Send` requirement statically rejects a SQLite Transaction
held across an await. A trybuild refusal and commit-before-await positive control
cover that boundary. The runtime ordering mutant instead submits before opening
the reservation transaction; the crash cell detects the premature delivery.

## Optional Events profile

An `events` section requires messaging, an explicit Events schema migration and an
owner-private 32-byte key. It selects `grant_id`, `key_file`,
`dispatch_timeout_ms` and optional `custody_limits`. Required verifier scopes
include `identity:read` and `events:subscribe`. The configured custody limits are
shared by the session and incoming receiver.

Startup requires `dispatch_timeout_ms >= verifier.timeout_ms + 11000` and
`request_timeout_ms >= 2 * verifier.timeout_ms + 41000`; both are at most 60000 ms.
The ordinary messaging submission/store-wait budget also applies. No Events
worker starts when the section is absent. See [Events setup](events.md) for the
exact migration order, key provisioning, subscription lifecycle, bounded retries,
status, responsibility checkpoints and local owner commands.

## Optional gist broker

An optional owner-file section fixes the broker service destination:

```json
"broker": { "destination": "genie@example.node" }
```

This requires both messaging and Events configuration. The selected Events grant
owns the reply mailbox. The four tools `gist`, `gist_read`, `gist_update` and
`gist_comment` are advertised only to that current grant when its send policy
allows the exact broker destination and required scope. Calls repeat those checks
before publication. Granting a gateway principal send to the broker service grants
it the broker's gist operations. The broker must separately allowlist the gateway's
attested service and node; body labels do not identify the caller.

Arguments are the existing typed gist proposal fields plus `request_id`; callers
cannot choose a destination, identity or credential. Creation defaults to an
unlisted gist unless `public` is explicitly true. Requests use the ordinary Send
reservation, framing, complete UTF-8 byte bound and grant ceiling. Retrying requires
identical arguments and the same request ID. A conflicting payload is refused.

The call waits at most ten seconds including submission, then returns `pending` or
`unknown`. A timeout or disconnect does not cancel work already submitted. Retry
the identical call or use the read-only `xmsg_message_status`. A confirmed bus
receipt proves submission, not that GitHub processed the operation. A completed
broker result appears under `broker.result`; gist-read data retains `untrusted:
true` and may exceed the ordinary message preview length. The gateway accepts
only a retained, currently authorized mailbox reply with the exact correlation
and configured service/node origin, and validates its Action shape against the
reserved proposal. Conflicting authenticated result bodies yield `unknown` and
require reconciliation. Expired or oversized result content is unavailable; it is
never silently truncated or automatically republished. Earlier grant revisions
remain held until explicitly released by the owner.

## Owner configuration

`serve --config FILE` is the only serving configuration entry. Request arguments,
metadata, sessions and connection headers cannot select or replace it. The nonsecret
configuration file may be read-only world-readable (such as mode 0444 in the Nix
store) or owner-private (mode 0600 or 0400), and must not be group- or world-writable
on Unix; credential files remain owner-private (mode 0600 or 0400). Unknown fields are refused.
Relative state, lookup-secret, root-certificate and Events-key paths resolve against its
containing directory. The current listener binds only loopback; it accepts OAuth
credentials and has no local bearer/no-authentication mode.

Example identity-only `.state/serving.json`, with every provider/client/owner value replaced by
the values from the actual provider setup:

```json
{
  "bind": "127.0.0.1:8787",
  "grant_store": "grants.db",
  "request_timeout_ms": 10000,
  "allowed_hosts": ["127.0.0.1", "localhost", "gateway.example"],
  "allowed_origins": [],
  "verifier": {
    "service": "gateway",
    "issuer": "https://issuer.example/",
    "resource": "https://gateway.example/mcp",
    "subject": "owner-subject",
    "hosted_client": "approved-hosted-client",
    "introspection_url": "https://issuer.example/introspect",
    "introspection_client": "lookup-client",
    "client_secret_file": "lookup-secret",
    "provider_addresses": ["192.0.2.10"],
    "required_scopes": ["identity:read"],
    "timeout_ms": 5000
  }
}
```

Optional `verifier.audience` selects the expected introspection `aud` value;
when omitted, it defaults to `verifier.resource`. An override must be nonempty
and contain no whitespace. Only an exact string or singleton array is accepted,
and the returned `client_id` must still equal `verifier.hosted_client`. This
changes only the audience comparison: resource metadata, verified identity and
grant enrollment continue to use the canonical resource URL. If the audience is
a different identifier, require a dedicated one-to-one OAuth client for that
resource, with its origin set to the resource origin and no reuse for other
applications. See [provider setup](provider-setup.md) for direct Kanidm 1.11.2 and
the separate, unchanged strict-resource Python reference.

An optional `verifier.root_certificate_file` supplies a PEM root for private PKI.
Optional `verifier.provider_addresses` supply explicit connection pins, independent of
callback policy; when omitted or empty, standard DNS resolution and `HTTPS_PROXY`/`NO_PROXY`
environment settings apply, while configured pins connect directly (`.no_proxy()`).
Lookup credentials stay in the private secret file. The introspection client and
approved hosted client have separate roles. See [provider setup](provider-setup.md)
and [verified-token foundation](verified-identity.md).

Initialize and enroll the matching service/issuer/resource/owner profile through
the existing owner CLI before starting. Enrollment remains disabled at revision 1;
only an explicit owner enable admits authenticated requests. The loader rejects
empty or mixed service/resource/owner stores and never creates or resets one.
Disabled records for earlier hosted clients can remain in the same profile.

```sh
chmod 600 .state/serving.json .state/lookup-secret
cargo run --locked -- serve --config .state/serving.json
```

The `--state` grant-management override is refused with `serve`, `events-rebind`
and `events-replay`; their store paths come from the owner file. Editing provider settings requires restarting the
listener. Origins must be explicitly listed when an Origin header is present.

## Request enforcement

The optional `max_request_body_bytes` defaults to 1,048,576 bytes and must be positive.
An advertised Content-Length above this bound receives 413 before body reading;
streaming requests retain the same byte ceiling. An unreadable body receives 400;
only a size violation receives 413. The owner-file read bound stays
64 KiB independently. With messaging configured, startup requires
`max_request_body_bytes >= 6 * max_framed_bytes + 16384`, using checked arithmetic.
The envelope allowance assumes typical id/_meta sizes; larger metadata counts
against max_request_body_bytes.

The handler bounds the request body at that limit and the handler, once headers are
parsed, at the configured deadline (1–60000 ms). This covers body reading,
verification, policy lookup and dispatch. The separate `header_read_timeout_ms`
bounds HTTP header reads, including the next header read while a keep-alive
connection is idle. After reading the body, each request obtains a fresh verified
identity from the configured provider and reads the current grant from the store. SQL runs off the async reactor with tracing context preserved.
Expiry is checked again after the policy read, so waiting on a store lock cannot
carry an expired credential into dispatch. No identity is cached per session or
connection.

Invalid or unapproved credentials receive 401 with the protected-resource metadata
challenge. Disabled/missing grants and identity-spoofing arguments or metadata
receive 403. Provider/store failures and request deadlines receive retryable 503.
A content-free event marks each real store-open attempt and identity-tool dispatch;
no token, request content, subject or secret is logged by these events.

The six privacy arms include a handler module compiled beside the real verifier
source. Public-field mutation must make both the external and same-crate mint arms
compile unexpectedly. Runtime misuse cells cover fail-open responses, changed and
revoked credentials, caller-data precedence, and policy lookup before token
verification. The order fixture requires 401/zero opens for an invalid credential
with unavailable state, 503/one open for a valid credential with unavailable state,
and success/one open for a valid credential with available state.

## Deployment boundaries

Local fixtures establish Rust custody, subscription, delivery and recovery behavior;
they do not establish a deployed hosted OAuth, tunnel or federation configuration.
Provision a compatible provider or broker, dedicated identities and grants, and
hosted workspace/tunnel credentials before rollout. The [hosted probe guide](hosted-dots-setup.md)
describes the synthetic reference separately; [Rust Events setup](events.md)
describes the production implementation's configuration and migration.

Events ingestion starts only with an explicit Events profile. First enable audits
release of proven never-enabled traffic. Earlier-revision and ambiguous legacy
custody stays held until an explicit local owner-selected release. Subscription
renewal, rebind and read tools cannot authorize that release.

## Exposure and request protection

The listener remains OAuth-only and loopback-bound, including when reached through
a tunnel. Header deadlines and a connection cap bound admission and idle keepalive.
A declared Content-Length above the request limit returns 413 before body reading,
provider requests or dispatch. Streamed bodies retain the configured byte bound.

Resource metadata uses the RFC 9728 path insertion form and must match the
configured `/mcp` resource. Unsupported resource paths refuse configuration rather
than assuming a path-rewriting tunnel. SQLite waits and the handler deadline
bound request work; a store lock produces a retryable unavailable result.

The real CLI cells in [header timeout tests](../tests/header_timeout.rs),
[connection cap tests](../tests/connection_cap.rs), and
[serving tests](../tests/serving.rs) exercise these boundaries. The provider,
transport, custody and actual hosted rollout checks remain distinct.

Registration health errors do not prove that an operation was never submitted.
The session owner withdraws an unhealthy handle and re-registers through the
same identity and effective-limit checks, regardless of the original transport
error. A health probe can replace that error, so recovery never uses its exact
variant to infer acceptance. Once submission may have begun, every transport
error, including `Disconnected`, leaves the durable reservation unknown. A
retry uses its stored idempotency key within the dedup lifetime; after expiry
it requires reconciliation. Successful receipts remain confirmed.

Inside the stored dedup lifetime, an unknown result has
`reconciliation_required: false` and instructs the caller to retry with the same
`request_id` and identical arguments. Once the stored deadline expires, or cannot
be read, it has `reconciliation_required: true` and offers no blind retry. Either
response remains uncertain; neither fabricates a receipt.

SIGTERM and Ctrl-C drain HTTP handlers and detached dispatch tasks before stopping
the registration owner. A healthy stop writes a final observation and disconnect
record, so a clean restart measures the stopped interval without the normal
coalescing over-estimate. A failure to persist that observation exits visibly.

`header_read_timeout_ms` defaults to 5000 and accepts integers from 1 through
60000. Each HTTP/1 request must complete its headers within this absolute deadline;
receiving another byte does not renew it. Expiry closes the connection with the
typed `HeaderReadTimeout` reason on stderr. Completed headers release the
deadline, so it does not limit request body delivery or response work. Hyper
re-arms it for the next request, bounding idle keep-alive with the same setting
rather than a separate idle deadline.

`cargo test --test header_timeout` exercises this bound through the real CLI and
listener, including a delayed-body positive control. Run
`python3 scripts/header_timeout_mutants.py` to fresh-build the control and source
mutants that disable the header deadline, remove its diagnostic, make accept
errors fatal, or prevent shutdown from interrupting accept-error backoff. The driver requires the intended slow-header, idle keep-alive,
diagnostic and descriptor-exhaustion assertions to reject their mutants. It
records source, library, app and test hashes plus an executed nonce per arm.
The descriptor-exhaustion cell runs on Linux with `prlimit` available; it holds
100 connections against a 64-descriptor limit, then releases them and requires
normal requests to succeed again.

The Linux `shutdown_is_not_delayed_by_accept_backoff` cell confirms accept
backoff through stderr under the same descriptor pressure, releases the held
clients and sends SIGTERM to its owned CLI process. Shutdown must succeed within
750 ms, below the one-second backoff; replacing the shutdown select with an
uninterruptible sleep must fail that cell.


## Mailbox recovery reads

With a registered messaging profile, `xmsg_inbox(after?, limit?)` returns
`items` containing message IDs, mailbox, attested origin, correlation, the durable
observation time, previews of at most 256 Unicode characters and
`body_available: true`. The default page is 20 items; valid limits are 1 through
100. `next` is an opaque cursor only when another eligible item exists; otherwise
it is null. Query order follows custody insertion order, not upstream IDs or
client-supplied timestamps.

`xmsg_read_message(message_id, offset?, limit?)` returns `state: "found"`, the
same identity metadata, `offset`, `text` and `next_offset`. Offsets count Unicode
scalar values, starting at zero. The default and maximum page is 4096 characters
(at most 16 KiB of UTF-8 text); valid limits are 1 through 4096. Embedded NULs and
other valid JSON string characters survive reads. An offset at or past the end
returns an empty text and null next offset. A foreign, expired, redacted,
unreleased pre-enable, earlier-revision or unknown message returns `state: "not_found"`
without metadata. No upstream read-by-ID operation is performed.

Every read reauthorizes the verified OAuth binding against the currently enabled
grant in the same SQLite read transaction as the custody query. The mailbox and
bus come from the validated registered handle, cached for reads during a temporary
daemon outage. Startup still requires a live registration and manifest check. Ownership also requires the stored
owner, service, issuer, resource, hosted client and grant ID to match. Eligibility
requires the current grant revision, or a separate audited dispatch authorization
created by first enable or explicit local selected release. The original acceptance
snapshot is never rewritten. Reads may expose held custody accepted under the
current enabled grant revision. They never release events, authorize a subscription,
or record consumer responsibility. Disable/re-enable changes the revision and
does not rebind prior custody. The [Events profile](events.md) starts ingestion
and implements the explicit release/replay policy.

Cursors bind their event anchor to that mailbox, bus, identity binding and grant
revision. They resolve the anchor's current insertion position, so deleting earlier
rows or vacuuming the database does not change the anchor identity. An expired,
purged, foreign or differently bound anchor returns JSON-RPC invalid params
(-32602). Restart `xmsg_inbox` without `after` in that case. This intentionally does
not promise that a cursor survives retention; it prevents a recycled SQLite row ID
from silently skipping later messages. Unknown arguments and limits outside the
advertised bounds also return -32602.

Portable tests in `tests/reads.rs` exercise the real OAuth verifier over a local
TLS introspection fixture and actual service registration/poll over a fixture Unix
socket. They verify ownership through real `accept_delivery` calls, without a
private daemon binary or a deployed service.
