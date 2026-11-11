# xmsg-mcp-gateway

The Rust gateway serves OAuth-protected MCP tools with durable local grants,
mailbox custody and optional signed [Events](docs/events.md). A messaging profile
supports authorized send/reply and repeatable inbox/body reads. An Events profile
adds service polling, durable webhook delivery, consumer responsibility ACKs and
read-only outbound status. An optional [gist broker](docs/serving.md#optional-gist-broker)
profile composes those paths for typed gist operations without a gateway GitHub
credential. The shipped product is Rust and has no Python runtime
dependency.

The Python reference’s authenticated Streamable HTTP endpoint is `/mcp`. It offers one tool,
`xmsg_identity`, and `events/list`, `events/subscribe`, `events/unsubscribe` for
`xmsg.message.received.v1`. There are no messaging or discovery tools.

The Rust [MCP listener](docs/serving.md) runs with
`cargo run --locked -- serve --config FILE`. Its owner file supplies provider
credentials and profile settings. Without a `messaging` section it serves identity
only. With messaging configured, explicit migrations, node registration and limit
checks finish before readiness. Tool advertising and dispatch also require the
configured scopes and owner-set grant policy. An invalid profile refuses startup
instead of falling back to identity-only use.
Local acceptance does not authorize a hosted deployment: the
[deployment and exposure requirements](docs/serving.md#deployment-boundaries)
still apply.

## Rust grant-store foundation

The Rust library and local owner CLI persist disabled enrollment, exact service /
issuer / resource / subject / hosted-client bindings, and revision-checked enable
and disable operations. The [outbound custody foundation](docs/outbound.md) adds
durable send/reply reservations and a per-service operation lease shared with
owner policy and disable commands. The listener integrates these operations with
request and retention bounds and 401/403/503 mapping. [Events setup](docs/events.md) describes explicit migration, first-enable release,
subscription verification, and local audited rebind/replay.
The Python reference uses its separate state store.

Build with the toolchain in `rust-toolchain.toml` and the committed Cargo lockfile:

```sh
cargo test --locked -j 4
cargo clippy --locked --all-targets -j 4 -- -D warnings
python3 scripts/grant_mutants.py
install -d -m 700 .state
cargo run --locked -- --state .state/grants.db init
cargo run --locked -- --state .state/grants.db migrate-custody
cargo run --locked -- --state .state/grants.db migrate-outbound
cargo run --locked -- --state .state/grants.db migrate-retirement
cargo run --locked -- --state .state/grants.db enroll grant-id binding.json
cargo run --locked -- --state .state/grants.db enable grant-id 1
cargo run --locked -- --state .state/grants.db disable grant-id 2
```

Existing custody databases from earlier releases also require `migrate-custody-summaries`.
Stop every gateway process and back up the database first; see the
[explicit migration and rollback procedure](docs/custody.md). Fresh
`migrate-custody` databases already include summaries.

The owner supplies `binding.json` with exactly these fields:

```json
{"service":"gateway","issuer":"https://issuer.example/","resource":"https://gateway.example/mcp","subject":"owner-subject","hosted_client":"approved-hosted-client"}
```

The subject and hosted client refer to the intended verified token recipient,
separate from any introspection caller. Enrollment starts disabled at revision 1;
each state change advances the revision. Unknown, stale and unchanged IDs fail
with a nonzero exit and no success output. An enabled-binding conflict has a
specific diagnostic, distinct from an unavailable store. Missing or unrecognized state fails
closed; initialization is explicit and never overwrites an existing store.

The Rust token-verification boundary is described in [verified-token foundation](docs/verified-identity.md). The identity listener consumes this boundary.
Optional `verifier.audience` selects the exact token audience, defaulting to the
canonical resource URL. An override does not change resource metadata or the
service grant, and `client_id` must still match the approved `hosted_client`.
[Provider setup](docs/provider-setup.md#direct-kanidm-1112) describes direct Kanidm
1.11.2 with a dedicated one-to-one client audience; do not reuse that registration
for another resource or application.

## Python reference setup

Requires Linux, Python 3.12 or newer, and uv. This uses a fresh repository, not a
worktree of the infrastructure or fleet repositories.

```sh
uv sync --locked --link-mode copy
uv run pytest -q
uv run ruff check phase1 tests scripts
uv run python scripts/mutations.py
uv run phase1 --config config.local-test.toml issue-local-test --output .state/test-token
uv run phase1 --config config.local-test.toml serve
```

The listener defaults to loopback. `config.local-test.toml` enables only local
fixture authentication; the generated high-entropy token is written directly to
a file, and only its SHA-256 verifier is stored in the credential table. This
mode cannot bind externally and is not a supported hosted connection method.
Tests create credentials in temporary directories; never commit credential files.
The `.state/` directory is gitignored and private to its OS account.

The server returns JSON Streamable HTTP responses and advertises Events during
`initialize`. It supports initialized MCP versions 2025-03-26, 2025-06-18 and
2025-11-25. It does not implement MCP 2.0 `server/discover`, SSE subscriptions, or
MCP batch requests. An authenticated GET receives 405; notifications receive 202.
Standard `params._meta` is accepted separately from strict tool arguments and
subscription filters. Progress token types are validated, but metadata is otherwise unused and no
progress notifications are emitted. Idle/backoff worker ticks do not introspect tokens;
a due delivery rechecks authorization before reserving its attempt and sending.

## Python reference configuration and OAuth

Use `config.oauth.example.toml` as the field reference. Save the real configuration
and generated credentials under `.state/`. Run:

```sh
uv run phase1 --config .state/oauth.toml serve
```

OAuth is the default. Incomplete configuration refuses startup. The server is an
OAuth resource server, not an authorization server. An owner must provision a
compatible provider and its dedicated introspection client. Every request and
every dispatch checks access-token activity, exact issuer, exact resource audience,
owner subject, expiration, not-before and both declared scopes:
`identity:read events:subscribe`. There is one principal:
`dot@phase1-synthetic`. No argument can select a sender or another mailbox.

Public protected-resource metadata is available at the standard well-known path
and the resource-path variant, including the URL advertised in a 401 challenge.
The provider must supply authorization-server metadata, authorization code with
PKCE S256, and an appropriate client-registration method. This server never
rewrites a token audience to make an incompatible provider appear compatible.

The repository includes no live provider configuration or credentials. Direct
Kanidm 1.11.2 returns a client-name audience, which does not satisfy this Python
reference's strict-resource predicate. The Rust verifier separately supports a
dedicated-client audience override. Read the [provider setup guide](docs/provider-setup.md)
before registering a client. A dedicated client, compatible reference-server
resource audience and accessible OAuth endpoints must be verified first.
Do not reuse another application's client registration.

OAuth tokens retained for delivery-time introspection are Fernet encrypted;
connection fixture tokens are stored only as verifiers. Signing secrets are also
encrypted. The local key is outside the database, in the private state directory.
This protects a copied database, not a compromised OS account. Back up the state
directory and key together. Do not enable raw HTTP or proxy credential logging.

## Python reference administration and custody

Admin commands are executable only through the local CLI; no HTTP admin trigger
exists. One invocation emits one occurrence; reuse its occurrence ID to retry the
same logical occurrence without adding a row:

```sh
uv run phase1 --state .state emit review-occurrence-one
uv run phase1 --state .state status
uv run phase1 --state .state revoke '<credential-verifier-id>'
uv run phase1 --state .state retry-dead '<event-id>'
uv run phase1 --state .state reset-binding
```

The verifier ID identifies a local-test fixture credential. `revoke` explicitly
refuses OAuth credentials: revoking one access-token digest cannot disable a
refreshed token. Revoke OAuth authorization at the provider. The Python reference
does not use the Rust grant store; Rust service grants are disabled through the
owner CLI described above. Unknown revoke or retry IDs exit nonzero. An already
initiated request cannot be recalled.

The worker holds the operation lock across online introspection and callback
submission. Each network operation has a bounded resolver/request budget, so
local administration may wait roughly 26 seconds for those two operations. This
orders local revocation after an already started submission; it does not make
remote provider revocation instantaneous.

SQLite uses full synchronous commits. A committed outbox occurrence survives
process exit before its callback. Attempts are reserved durably before sending.
The event ID and exact body survive retries; signing metadata is generated per
attempt. A callback might receive the event twice if it accepted a request before
the server recorded that acceptance. HTTP receipt does not prove dot ran a task.

There are five attempts, with exponential delays of 2, 4, 8 and 16 seconds before
subsequent retries. Only transport failures, HTTP 408, HTTP 429 and server errors
retry; redirects and other client errors are terminal, including 410 and 413.
`status` and `xmsg_identity` expose pending, accepted and dead-letter counts;
`status` lists individual event IDs, states and categorized errors. Manual
`retry-dead` preserves the original ID and explicitly resets its attempt budget.

The hard quota is 1,000 retained occurrences, including accepted/dead entries.
There is no automatic garbage collection or expiry deletion in this phase.
Exhaustion refuses new custody. Keep this synthetic test small; retention design
belongs before production use. No body-fetch tool exists, so `body_available`
is false. Protocol replay is not implemented: cursors are always null and a
non-null resume cursor is rejected. Persisted pending work still survives restart.

Subscription identity is deterministic. A callback cannot silently replace an
existing binding, including after unsubscribe. `reset-binding` is an explicit
local migration operation; it retains pending events for the next verified binding.
Refresh is idempotent, with finite expiry bounded by the OAuth token lifetime.
The default subscription lifetime is one hour, capped at one day; null lifetime
requests receive a finite grant. Verification is cached for five minutes only
for the same binding and key. Rotating a key verifies again and signs with the
previous and current key for five minutes. A restart preserves that window.

Callbacks require HTTPS, public addresses, hostname-verified TLS and no redirects.
DNS is checked on every connection, and the dial uses the checked IP. A mixed
public/private answer is refused. DNS has a three-second deadline and four
resolver slots; HTTP has a ten-second socket timeout and response watchdog.
Responses are bounded to 64 KiB. Requests are capped at 64 KiB, event bodies at
256 KiB by contract (this fixed synthetic payload is much smaller).

## Owner steps: private tunnel

These hosted feasibility steps apply to the Python reference server. They do not
activate the Rust listener or establish production Rust hosted compatibility. For
Rust operation, use [Events setup](docs/events.md); for the synthetic probe and the
current connection form, use [hosted setup](docs/hosted-dots-setup.md).

1. Resolve the authorization-provider compatibility checks in the [provider setup guide](docs/provider-setup.md). Configure
   a dedicated OAuth client using the exact redirect URI shown by ChatGPT for this
   connection, with PKCE enabled, the two scopes, and only the owner account allowed.
   Configure the provider to issue tokens for the exact MCP resource URI.
2. Ensure the browser can reach login/consent, and the hosted OAuth exchange can
   reach discovery and token endpoints. Tunnel transport does not automatically
   expose the authorization server. Provision the introspection secret directly
   into the private file referenced by `.state/oauth.toml`.
3. In Platform tunnel settings, obtain an authorized tunnel and associate it with
   the intended ChatGPT workspace and Platform organization. Tunnel management
   requires Read + Manage; the runtime and operator need Read + Use.
4. Obtain the official tunnel-client release from Platform or the official release
   page. Record the selected version and checksum, run `tunnel-client help quickstart`,
   and follow its current HTTP profile instructions with the local `/mcp` endpoint.
   Provide its runtime credential through secure local input/environment, never
   arguments or committed config. Keep its credential separate from OAuth credentials.
5. With `CONTROL_PLANE_API_KEY` securely supplied and `CONTROL_PLANE_TUNNEL_ID`
   set to the authorized tunnel ID, the documented environment-based HTTP binding is:

   ```sh
   export MCP_SERVER_URL="http://localhost:8765/mcp"
   tunnel-client doctor --explain
   tunnel-client run
   ```

   Confirm these flags against the selected release's help. Run the client under
   a separate restricted account/unit. It needs access only to the MCP listener
   and OpenAI control plane, not fleet sockets. Check the protected-resource
   metadata as seen through the tunnel: the token audience must match the exact
   resource identifier the hosted OAuth flow requests.
6. In ChatGPT Plugins, choose **+ → Add custom MCP server → Connection: Tunnel**,
   select that tunnel, and choose **OAuth**. Enter the dedicated client ID/secret
   through supported secure fields if using predefined client registration.
   Complete the owner's review and create/install the private plugin.
7. Rescan and confirm exactly one tool and one event. Call `xmsg_identity`.
8. Ask dot to monitor the synthetic event and report its preview once. Verify that
   subscription creation, signed callback challenge and durable state all succeed.
9. Run the local `emit` command once. Observe callback acceptance locally and the
   event-triggered response in the intended idle dot conversation. Record these as
   separate observations. Stop monitoring and verify unsubscribe prevents delivery.
10. Repeat hosted expiry/refresh/revocation and restart checks before declaring the
    hosted feasibility gate passed. An independent reviewer gates phase 2.

## Owner steps: public HTTPS fallback

If the combined private-tunnel flow is unsupported, the owner may configure a
stable HTTPS reverse proxy for this new MCP endpoint and its public discovery
metadata. Keep the listener on loopback where possible. Set `exposure` to
`public-https` and `public_url` to the canonical HTTPS MCP URL; OAuth remains
mandatory. A non-loopback bind is refused unless this fallback is explicit.

Preserve Host and Authorization headers, enforce TLS and request bounds, and keep
credentials and callback URLs out of access logs. Add the custom MCP server by URL
with OAuth, then perform the same hosted lifecycle test. This project does not
provision DNS, certificates, proxies, public ingress, tailnet membership or tunnels.

References: [MCP Events](https://developers.openai.com/plugins/build/mcp-events),
[Secure MCP Tunnel](https://developers.openai.com/api/docs/guides/secure-mcp-tunnels),
[OAuth](https://developers.openai.com/plugins/build/auth),
[custom MCP setup](https://developers.openai.com/api/docs/guides/custom-mcp-server).

Public operational setup is documented above and in [provider setup](docs/provider-setup.md).
Run the tests and mutation command from a fresh checkout to reproduce local checks;
fresh mutation output is written to the gitignored `.artifacts/mutations/` directory.

Planned authentication extension: [multiple verifier profiles and issuer cutover](docs/auth-profiles.md).
