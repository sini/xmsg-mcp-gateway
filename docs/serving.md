# Rust MCP listener

The Rust listener serves OAuth-protected MCP identity reads with durable local
grants. Its public resource metadata advertises the canonical resource and issuer
from the owner's configuration. `initialize`, `ping`, `tools/list`,
`notifications/initialized` and `xmsg_identity` are implemented. Standard `_meta`
progress tokens are accepted but unused. An optional owner-file messaging section
enables authorized `xmsg_send` and `xmsg_reply`. Events remain unavailable.

The existing xmsg MCP entry point is a harness-associated stdio adapter behind its
daemon feature. Service-node I/O belongs to the shared `xmsg::client` boundary.
Without a messaging section, serving opens no xmsg socket. The identity
result describes the verified OAuth service profile and grant revision; it claims
no bus registration or node address.

## Optional messaging profile

The owner-file constructor is asynchronous: registration, manifest validation and
schema readiness finish before a router is returned. A broken messaging section
refuses startup; it never degrades to identity-only serving. A present `null` section
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
Only the owner CLI/store changes per-grant policy. Empty policy advertises no
messaging tools and refuses messaging calls.

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
refuses startup; the gateway never guesses it from launch arguments. The final pin is xmsg main `7d9d1ed`, including registration health and socket
activation. Live activation
and exposure gates below still apply.

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
return 503 while unavailable. Recovery never polls or ACKs the mailbox, submits
work, mints an idempotency key, or authorizes a replay. A caller retries uncertain
work with its original request ID. Link records retain the custody ledger's
existing seven-day / 1000-gap bounds and capacity costs; an exhausted ledger also
blocks messaging until a durable update can succeed.

The detached task's `Send` requirement statically rejects a SQLite Transaction
held across an await. A trybuild refusal and commit-before-await positive control
cover that boundary. The runtime ordering mutant instead submits before opening
the reservation transaction; the crash cell detects the premature delivery.

## Owner configuration

`serve --config FILE` is the only serving configuration entry. Request arguments,
metadata, sessions and connection headers cannot select or replace it. The file
must be private to its owner (mode 0600 or 0400 on Unix). Unknown fields are refused.
Relative state, lookup-secret and root-certificate paths resolve against its
containing directory. The current listener binds only loopback; it accepts OAuth
credentials and has no local bearer/no-authentication mode.

Example `.state/serving.json`, with every provider/client/owner value replaced by
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

An optional `verifier.root_certificate_file` supplies a PEM root for private PKI.
Provider addresses are explicit connection pins, independent of callback policy.
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

The `--state` grant-management override is refused with `serve`; its store path
comes from the owner file. Editing provider settings requires restarting the
listener. Origins must be explicitly listed when an Origin header is present.

## Request enforcement

The optional `max_request_body_bytes` defaults to 1,048,576 bytes and must be positive.
An advertised Content-Length above this bound receives 413 before body reading;
streaming requests retain the same byte ceiling. The owner-file read bound stays
64 KiB independently. With messaging configured, startup requires
`max_request_body_bytes >= 6 * max_framed_bytes + 16384`, using checked arithmetic.
The envelope allowance assumes typical id/_meta sizes; larger metadata counts
against max_request_body_bytes.

The handler bounds the request body at that limit and the handler, once headers are
parsed, at the configured deadline (1–60000 ms). This covers body reading,
verification, policy lookup and dispatch. It does not bound the HTTP header phase
or idle keep-alive connections. After reading the body, each request obtains a
fresh verified identity from the configured provider and reads the current grant
from the store. SQL runs off the async reactor with tracing context preserved.
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

This listener is an implementation unit, not evidence of hosted OAuth, tunnel or
federation compatibility. The live provider/broker and deployment choices, queued
custody, callbacks, and actual xmsg operations retain their separate gates.


## Activation preconditions and next serving unit

P1 and P5 block exposure beyond the current local loopback use, including exposure
through a tunnel even when the listener still binds loopback. They must pass
before such activation:

- **P1 — connection admission and lifetime:** enforce a header-read deadline, an
  idle keep-alive deadline and a connection cap. Real TCP oracles send partial
  headers and park an idle keep-alive connection; both must close within their
  configured bounds. Occupying the cap must prevent additional admitted work,
  with zero additional provider requests, store opens or dispatches. A complete
  authenticated request below the cap must succeed, and releasing a slot must
  admit another request. Source mutants removing each timer or the cap must turn
  its named oracle red.
- **P5 — declared oversized bodies:** with headers declaring a Content-Length
  above the configured request-body limit and no body bytes sent, return 413 promptly, before the handler
  deadline, with zero provider requests, store opens or dispatches. A permitted
  declared length and complete valid request must succeed. Removing the early
  length check must fail the named oracle; waiting for the handler deadline is
  not an acceptable 413.

The next serving unit also carries these findings:

- **P2:** advertise the RFC 9728 insertion form
  `/.well-known/oauth-protected-resource{resource-path}` in WWW-Authenticate;
  fetch the advertised URL and verify its resource matches the configured URI.
- **P3:** enforce consistency between the configured resource path and the served
  MCP endpoint. Test matching paths and refuse an unsupported mismatch at load
  time; do not silently assume a path-rewriting tunnel.
- **P4:** pin the intended serving mutation case count and completion. Removing a
  case or returning before completion must fail CI.
- **P6:** bound serving SQLite lock waits by the remaining handler budget, so a
  503 cannot leave a 30-second blocking task behind. Hold a real store lock, let
  the request deadline expire, and prove the worker exits within the budget;
  unlocking the store must permit a subsequent valid request. A source mutant
  restoring the longer wait must fail this oracle.

The provider/broker, transport, custody and hosted feasibility gates above remain
required independently of these connection and serving checks.

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
