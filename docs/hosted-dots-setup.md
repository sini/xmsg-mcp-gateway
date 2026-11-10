# Connecting a hosted ChatGPT dot: production and feasibility runbook

This runbook covers two paths for connecting a hosted ChatGPT dot through
OpenAI's Secure MCP Tunnel:

1. **Part I — Production path ([below](#part-i-production-hosted-dot-setup)):**
   the shipped Rust `xmsg-mcp-gateway` binary (or `ghcr.io/sini/xmsg-mcp-gateway`
   OCI image) paired with an `xmsg --leaf` daemon, persistent SQLite grants and
   Standard Webhooks Events ([events.md](events.md)), and `tunnel-client`
   (`v0.0.20`+) configured with its Harpoon OAuth shim so a private LAN/tailnet
   authorization server need not be exposed to the public internet.
2. **Part II — Step 0 synthetic feasibility probe ([below](#part-ii-step-0-synthetic-feasibility-probe)):**
   the throwaway synthetic Python server (`examples/step0_spike.py`, with no
   `xmsg` behind it) used to verify tunnel transport, connection-form options and
   signed webhook wakeup before building the production gateway.

Read [OAuth provider setup](provider-setup.md), [serving configuration](serving.md),
and [Rust mailbox Events](events.md) first. Upstream references:
[Secure MCP Tunnel](https://developers.openai.com/api/docs/guides/secure-mcp-tunnels),
[MCP Events](https://developers.openai.com/plugins/build/mcp-events),
[plugin authentication](https://developers.openai.com/plugins/build/auth).

Never paste the tunnel runtime key, an OAuth access token, a client secret, an
Events encryption key, a webhook signing secret or a callback URL into chat, an
issue or a shared log. Record only references to them (a file path or secret
resource name).

## Verification status (measured vs. cutover)

| Surface | Status | Evidence / scope |
| --- | --- | --- |
| Step 0 synthetic tunnel connection, `events/subscribe` signed challenge, and idle dot wakeup | **MEASURED** | Verified live over Secure MCP Tunnel using the Step 0 synthetic probe ([Part II](#part-ii-step-0-synthetic-feasibility-probe)); observed the ChatGPT connection form offering **OAuth** or **No Authentication**. |
| Rust `xmsg-mcp-gateway` + `xmsg --leaf` registration (with and without `/proc`), `xmsg_send` / `xmsg_reply` / `xmsg_inbox` / `xmsg_read_message`, durable custody, and Standard Webhooks Events | **MEASURED** | Verified locally and in CI against pinned `xmsg` (`ci/xmsg-pin.toml`), including crash/restart handoff cells and mutation suites. |
| Direct OAuth audience override (`verifier.audience` for Kanidm `1.11.2`) and Keycloak `26.8.1` OAuth 2.1 broker fallback (standalone and Kanidm-federated) | **MEASURED** | Verified locally against the unmodified Rust `xmsg-mcp-gateway` verifier (`HTTP 200` on valid PKCE `S256` + refresh tokens, `HTTP 401` on multi-audience and revoked tokens; see [provider-setup.md](provider-setup.md) and [oauth-keycloak.md](oauth-keycloak.md)). |
| OCI image (`ghcr.io/sini/xmsg-mcp-gateway`) non-root `User`, ELF entrypoint, and absence of Python / `phase1` / `/bin/sh` | **MEASURED** | Enforced on every build by `nix/check_image.py` (`checks.x86_64-linux.image` in `.github/workflows/oci.yml`). |
| Live hosted ChatGPT **OAuth** connection through `tunnel-client`'s Harpoon OAuth shim (`mcp.oauth_trusted_origins` + `harpoon.oauth_forward_origins`) and live cutover gates | **NOT YET MEASURED** | Executed by the operator at deployment cutover ([Section P4](#p4-cutover-checks-to-record)); confirm the authorization server's `/token` access log and live hosted Events wakeup before enabling outbound send/reply policy. |

---

# Part I: Production hosted-dot setup

All hostnames, tunnel IDs, node names and UUIDs below (`https://auth.example`,
`https://gateway.example/mcp`, `tunnel_0123456789abcdef0123456789abcdef`,
`00000000-0000-4000-8000-000000000001`) are generic placeholders.

## P0. Production prerequisites

- **OpenAI Platform roles:** Tunnels **Read + Manage** to create/associate the
  tunnel, and Tunnels **Read + Use** for both the `tunnel-client` runtime API key
  and the ChatGPT operator account. Associate the tunnel with the target ChatGPT
  workspace (`platform.openai.com/settings/organization/tunnels`).
- **OAuth 2.1 authorization server (private LAN/tailnet HTTPS or public HTTPS):**
  - **Direct path (recommended when supported):** Kanidm `1.11.2` (or another
    OAuth/OIDC provider that emits its dedicated client name as `aud`) configured
    with a dedicated one-to-one OAuth client whose origin matches
    `https://gateway.example`, paired with `verifier.audience`
    ([provider-setup.md](provider-setup.md#direct-kanidm-1112)).
  - **Broker fallback:** Keycloak `26.8.1` (standalone or federated to Kanidm /
    OIDC) emitting singleton `aud == "https://gateway.example/mcp"` via
    `oidc-audience-mapper` ([oauth-keycloak.md](oauth-keycloak.md)).
  - In either case, pre-register the hosted OAuth client with **PKCE `S256`**,
    scopes `openid profile email identity:read events:subscribe`, and the
    redirect URI `https://chatgpt.com/connector_platform_oauth_redirect` (confirm
    the exact callback URI displayed by the ChatGPT connection UI during
    [Section P3](#p3-connect-in-chatgpt-and-verify-events-delivery-cutover--not-yet-measured)). Provision a
    separate confidential client for RFC 7662 token introspection.
- **Host or Kubernetes Pod runtime:**
  - `xmsg` (`ghcr.io/sini/xmsg:latest` or release binary) running in `--leaf`
    mode with outbound mTLS to the `xmsg` hub (`allow` and `targets` scoped to
    this leaf's service and approved peers).
  - `xmsg-mcp-gateway` (`ghcr.io/sini/xmsg-mcp-gateway:latest` or release binary
    built with `cargo build --locked --release`), sharing a `0700` runtime socket
    directory with `xmsg --leaf` under the same non-root numeric UID (for example
    `10001:10001` or `65532:65532`) and backed by persistent storage for
    `.state/grants.db` and `.state/events.key`.
  - `tunnel-client` (`v0.0.20` or newer, verified by checksum or pinned image
    digest) reaching `xmsg-mcp-gateway` over loopback (`http://127.0.0.1:18787/mcp`),
    the private or public OAuth issuer (`https://auth.example`), and
    `https://api.openai.com`. Event webhook deliveries go out directly from
    `xmsg-mcp-gateway` to ChatGPT's public HTTPS callback endpoint on port `443`.

## P1. Start `xmsg --leaf` and initialize `xmsg-mcp-gateway`

1. **Start the `xmsg --leaf` sidecar or host service** bound to the gateway's
   dedicated service principal (`svc:gateway`), sharing an owner-only (`0700`)
   socket directory (`/run/user/xmsg` in a Pod `emptyDir`, or `.state/xmsg` on a
   host):

   ```sh
   install -d -m 700 .state .state/xmsg .state/xmsg/sessions
   xmsg serve \
     --listen 127.0.0.1:0 \
     --leaf \
     --leaf-principal svc:gateway \
     --sessions-dir .state/xmsg/sessions \
     --http-sock .state/xmsg/http.sock \
     --agent-sock .state/xmsg/agent.sock \
     --leaf-register-sock .state/xmsg/register.sock \
     --db-path .state/xmsg/xmsg.db \
     --peers-file /etc/xmsg/peers/peers.json \
     --fed-cert /etc/xmsg/tls/tls.crt \
     --fed-key /etc/xmsg/tls/tls.key
   ```

   Record the leaf's canonical node name (`<leaf-node>`: `<sa>.<ns>` for a
   `spiffe://` certificate, or the 16-character pin name logged at startup).

2. **Provision owner-only secrets and grant files** (never commit `.state/`):

   ```sh
   (umask 077; set -C; dd if=/dev/urandom bs=32 count=1 2>/dev/null > .state/events.key)
   umask 077
   # Write the introspection client secret to .state/introspection-secret (mode 0600)
   # Write the Tunnels Read+Use API key to .state/tunnel-runtime-key (mode 0600)
   chmod 600 .state/events.key .state/introspection-secret .state/tunnel-runtime-key
   ```

   Create `.state/binding.json` (matching `verifier` below):

   ```json
   {
     "service": "gateway",
     "issuer": "https://auth.example/realms/mcp",
     "resource": "https://gateway.example/mcp",
     "subject": "00000000-0000-4000-8000-000000000001",
     "hosted_client": "chatgpt-mcp-client"
   }
   ```

   Create `.state/serving.json` (for the direct Kanidm path, set `issuer` and
   `introspection_url` to Kanidm's endpoints and add `"audience": "chatgpt-mcp-client"`
   inside `verifier` per [provider-setup.md](provider-setup.md#direct-kanidm-1112);
   replace `<leaf-node>` and `<daemon-uid>` with the leaf's node name and numeric
   UID):

   ```json
   {
     "bind": "127.0.0.1:18787",
     "grant_store": "grants.db",
     "request_timeout_ms": 60000,
     "allowed_hosts": [
       "127.0.0.1",
       "localhost",
       "gateway.example"
     ],
     "allowed_origins": [],
     "verifier": {
       "service": "gateway",
       "issuer": "https://auth.example/realms/mcp",
       "resource": "https://gateway.example/mcp",
       "subject": "00000000-0000-4000-8000-000000000001",
       "hosted_client": "chatgpt-mcp-client",
       "introspection_url": "https://auth.example/realms/mcp/protocol/openid-connect/token/introspect",
       "introspection_client": "gateway-introspector",
       "client_secret_file": "introspection-secret",
       "provider_addresses": [],
       "required_scopes": [
         "identity:read",
         "events:subscribe"
       ],
       "timeout_ms": 5000
     },
     "messaging": {
       "xmsg": {
         "service": "gateway",
         "expected_node": "<leaf-node>",
         "daemon_uid": 10001,
         "register_socket": "xmsg/register.sock",
         "agent_socket": "xmsg/agent.sock"
       },
       "manifest": {
         "reply_ttl_secs": 604800,
         "idempotency_ttl_secs": 86400,
         "svc_queue_cap": 100,
         "dedup_lifetime_secs": 3600,
         "max_framed_bytes": 65536
       },
       "submission_timeout_ms": 5000,
       "max_reservations": 64,
       "max_retained_bytes": 4194304
     },
     "events": {
       "key_file": "events.key",
       "grant_id": "grant-1",
       "dispatch_timeout_ms": 16000
     }
   }
   ```

   Every `manifest.*` limit must match the `xmsg --leaf` daemon's effective
   values (`--reply-ttl`, `--idempotency-ttl`, `--svc-queue-cap`, `--max-body`),
   and `events.dispatch_timeout_ms` (`>= verifier.timeout_ms + 11000`) plus
   `request_timeout_ms` (`>= 2 * verifier.timeout_ms + 41000`, `<= 60000`) must
   satisfy the [Events startup budgets](events.md#configure-and-migrate).

3. **Initialize, migrate, enroll, enable, and start `xmsg-mcp-gateway`**
   (run migrations **before** `enroll` on a new store so its never-enabled
   history is explicit; in Kubernetes, run `init` / `migrate-*` as idempotent
   setup steps or an administrative job against the persistent volume):

   ```sh
   chmod 600 .state/binding.json .state/serving.json

   xmsg-mcp-gateway --state .state/grants.db init
   xmsg-mcp-gateway --state .state/grants.db migrate-custody
   xmsg-mcp-gateway --state .state/grants.db migrate-outbound
   xmsg-mcp-gateway --state .state/grants.db migrate-retirement
   xmsg-mcp-gateway --state .state/grants.db migrate-events --key-file .state/events.key
   xmsg-mcp-gateway --state .state/grants.db enroll grant-1 .state/binding.json
   xmsg-mcp-gateway --state .state/grants.db enable grant-1 1

   xmsg-mcp-gateway serve --config .state/serving.json
   ```

   Send/reply permissions start empty by default (receive + `xmsg_inbox` +
   `xmsg_read_message` + Events only); keep outbound send/reply disabled until
   initial hosted read and Events wakeup pass. When using the published container
   image (`ghcr.io/sini/xmsg-mcp-gateway:latest` or pinned `@sha256:...`), the
   image runs as `10001:10001` with entrypoint `xmsg-mcp-gateway` and default
   arguments `["serve", "--config", "/etc/xmsg-mcp-gateway/serving.json"]`.

## P2. Run `tunnel-client` (`v0.0.20`+) with the Harpoon OAuth shim

In `tunnel-client` `v0.0.20` (`docs/configuration.md`, *"OAuth-protected MCP notes"*
and *"OAuth forwarding origins"*), admitting the authorization server's HTTPS
origin in both `mcp.oauth_trusted_origins` and `harpoon.oauth_forward_origins`
keeps the OAuth server private on the operator's LAN or tailnet:

- **`mcp.oauth_trusted_origins`** (flag `--mcp.oauth-trusted-origin`, env
  `MCP_OAUTH_TRUSTED_ORIGINS`): authorizes `tunnel-client` to fetch OAuth
  Protected Resource Metadata and Authorization Server Metadata on the separate
  origin `https://auth.example`.
- **`harpoon.oauth_forward_origins`** (flag `--harpoon.oauth-forward-origin`, env
  `HARPOON_OAUTH_FORWARD_ORIGINS`): registers the discovered `token_endpoint`,
  `revocation_endpoint`, and `registration_endpoint` on `https://auth.example`
  as `harpoon://` targets (`inclusion_reason=oauth-forwarding-origin`) and
  rewrites those URLs to Tunnel OAuth-shim routes so ChatGPT's backend OAuth
  POSTs traverse the tunnel rather than requiring public ingress to the IdP.
- **Browser authorization stays direct:** `tunnel-client` does **not** rewrite
  `authorization_endpoint`; the owner's browser reaches
  `https://auth.example/...` directly over LAN/tailnet HTTPS.
- **`harpoon.allow_plaintext_http`** (flag `--harpoon.allow-plaintext-http`, env
  `HARPOON_ALLOW_PLAINTEXT_HTTP`): required when the local loopback MCP listener
  uses plaintext HTTP (`http://127.0.0.1:18787/mcp`) so `tunnel-client` permits
  registering its Protected Resource Metadata source target.
- **`mcp.startup_wait_timeout`** (flag `--mcp.startup-wait-timeout`, env
  `MCP_STARTUP_WAIT_TIMEOUT`): delays the first control-plane poll until the
  gateway's loopback listener is ready (important in a multi-container Pod).

Create `.state/tunnel-client.yaml` (mode `0600`; if `https://auth.example` uses
an internal PKI CA, also pass `--ca-bundle /path/to/ca.pem` or set `CA_BUNDLE`):

```yaml
config_version: 1
control_plane:
  base_url: https://api.openai.com
  tunnel_id: tunnel_0123456789abcdef0123456789abcdef
  api_key: file:.state/tunnel-runtime-key
log:
  level: info
  format: json
health:
  listen_addr: 127.0.0.1:18081
mcp:
  server_urls:
    - channel: main
      url: http://127.0.0.1:18787/mcp
  oauth_trusted_origins:
    - https://auth.example
  startup_wait_timeout: 60s
harpoon:
  allow_plaintext_http: true
  oauth_forward_origins:
    - https://auth.example
```

*(In a Kubernetes sidecar container where kubelet probes `/healthz` and `/readyz`
on the Pod IP, set `health.listen_addr: ":8080"` or `HEALTH_LISTEN_ADDR=:8080`
inside trusted cluster networking, or configure equivalent env vars
`CONTROL_PLANE_TUNNEL_ID`, `CONTROL_PLANE_API_KEY`, `MCP_SERVER_URL`,
`MCP_OAUTH_TRUSTED_ORIGINS=https://auth.example`,
`HARPOON_OAUTH_FORWARD_ORIGINS=https://auth.example`,
`HARPOON_ALLOW_PLAINTEXT_HTTP=true`, and `MCP_STARTUP_WAIT_TIMEOUT=60s`.)*

Validate the configuration and start `tunnel-client`:

```sh
chmod 600 .state/tunnel-client.yaml
tunnel-client doctor --config .state/tunnel-client.yaml --explain
tunnel-client run --config .state/tunnel-client.yaml
```

Confirm `/readyz` returns `200` (`curl -fsS http://127.0.0.1:18081/readyz`) and
that startup logs include `harpoon startup catalog digest` and
`inclusion_reason=oauth-forwarding-origin` before connecting from ChatGPT.

## P3. Connect in ChatGPT and verify Events delivery (cutover — not yet measured)

1. Open ChatGPT → **Plugins** → **+** → **Add custom MCP server**.
2. Under **Connection**, choose **Tunnel** and select the associated `tunnel_id`.
3. Under **Authentication**, choose **OAuth**:
   - Confirm the callback URI displayed by the form matches the pre-registered
     redirect URI (`https://chatgpt.com/connector_platform_oauth_redirect`; if
     the installation displays a per-connector callback URI, update the OAuth
     client's exact redirect URI before continuing).
   - Enter the pre-registered OAuth Client ID (`chatgpt-mcp-client`, plus Client
     Secret in the secure field if configured as a confidential client).
   - Complete the browser OAuth login (over LAN/tailnet to `https://auth.example`)
     and create the private plugin. Record the `plugin_asdk_app…` identifier.
4. **Verify identity and readiness:** In a dot conversation, call `xmsg_identity`
   and confirm `messaging_status` is `"ready"` with the expected `gateway@<leaf-node>`
   mailbox.
5. **Subscribe and observe a real Events wakeup:**
   - Ask the dot to subscribe to `xmsg.message.received.v1` and instruct it to
     read and report incoming messages when woken. Leave the conversation idle.
   - From an authorized `xmsg` peer session or host node, send a message to the
     gateway's service mailbox:

     ```sh
     xmsg send --to "gateway@<leaf-node>" --from "<authorized-sender>" "cutover ping 1"
     ```

   - Confirm `xmsg-mcp-gateway` commits custody, dispatches the signed
     `xmsg.message.received.v1` webhook (`2xx` callback acceptance), and wakes
     the idle dot conversation, which reads the message via `xmsg_inbox` /
     `xmsg_read_message` with the sender's attested `origin`.

## P4. Cutover checks to record

Record content-free pass/fail results and timestamps for each check below (never
paste tokens, secrets, callback URLs or private message bodies):

| Check | Gate | Passes when |
| --- | --- | --- |
| Harpoon OAuth shim `/token` path | Private-IdP proof | Authorization server (`https://auth.example`) access logs show `POST .../token` (and `/revoke` when tested) arriving from `tunnel-client` rather than requiring public IdP exposure. *(If a deployment's tunnel service does not forward `/token`, expose only the token/revocation routes or a public broker ingress as a deliberate contingency.)* |
| Hosted connect, `xmsg_identity`, discovery, and subscription | Acceptance gate 1 | The hosted dot connects over the tunnel with OAuth, calls `xmsg_identity` (`messaging_status: "ready"`), discovers `xmsg.message.received.v1`, completes signed callback challenge verification, and wakes end to end (a tool call alone does not pass). |
| Peer send to idle wakeup with attested origin | Acceptance gate 3 | An authorized `xmsg` peer sends to `gateway@<leaf-node>`, a signed `xmsg.message.received.v1` event wakes the idle dot conversation, and the read payload carries the sender's attested `origin` (`node` + `id` or `service`). |
| Restart across handoff boundaries | Acceptance gate 6 | Subscription and custody survive restarts without duplicate message creation or silent loss across the four handoffs: before custody commit, after custody commit / before `xmsg` ACK, after `xmsg` ACK / before webhook dispatch, and after callback `2xx` / before receipt commit. |
| Scoped egress and external-data framing | Acceptance gate 11 | Only messages addressed to `gateway@<leaf-node>` and explicitly scoped metadata leave the network (`xmsg_inbox`, `xmsg_read_message`, errors and logs expose no other mailboxes, callback URLs or secrets), and once an outbound target is explicitly enabled, `xmsg_send` / `xmsg_reply` preserve the gateway's external-data framing at the recipient. |

## P5. Production disable and teardown

- **Immediate local revocation (without deleting state):** Disable the local
  grant revision so subsequent requests and webhook dispatches halt immediately,
  even before remote OAuth access tokens expire:

  ```sh
  # Replace <current-revision> with the grant's current revision (2 after first enable)
  xmsg-mcp-gateway --state .state/grants.db disable grant-1 2
  ```

- **Full teardown:**
  1. Unsubscribe in the dot conversation and delete the custom MCP server plugin
     in ChatGPT.
  2. Revoke the downstream OAuth grant/client at the authorization server.
  3. Stop `tunnel-client`, `xmsg-mcp-gateway`, and `xmsg --leaf` (`SIGTERM`
     drains handlers and writes a clean disconnect observation).
  4. Revoke the Platform Tunnels runtime API key (and delete the tunnel in
     Platform settings if decommissioning), then securely remove `.state/` if
     retiring the installation.

---

# Part II: Step 0 synthetic feasibility probe

This feasibility probe connects a hosted ChatGPT dot to the synthetic reference server, through OpenAI's Secure MCP
Tunnel. It proves four things before any production work depends on them:

1. the dot connects and authenticates;
2. it lists and subscribes to an MCP event;
3. a signed event delivered to its callback wakes the idle conversation;
4. which authentication the installation actually offers.

The server behind it is synthetic: it has no xmsg node behind it and no write tools. The production Events
path is the Rust gateway in [Part I](#part-i-production-hosted-dot-setup).

## 0. Prerequisites

- **OpenAI Platform roles** at the organization level: Tunnels **Read + Manage** to create the tunnel, and
  Tunnels **Read + Use** to run `tunnel-client` and to select the tunnel. An org owner or RBAC admin grants
  them; a new grant can take up to 30 minutes to apply.
- **ChatGPT workspace:** the workspace admin allows custom MCP servers and event-triggered tasks.
- **One host** that runs the reference server and `tunnel-client` side by side. It needs outbound HTTPS to
  `api.openai.com:443` (paths `/v1/tunnel/*`), and outbound HTTPS to the public internet, because event
  callbacks go out directly from the server to ChatGPT. It needs no inbound port.
- **A checkout of this repository** with the [Python reference setup](../README.md#python-reference-setup)
  done (`uv sync --locked`).

## 1. Create the tunnel

1. Open Platform → Settings → Organization → **Tunnels** (`platform.openai.com/settings/organization/tunnels`)
   and create a tunnel. Record its `tunnel_id`. It is an identifier, not a secret.
2. Associate the tunnel with the ChatGPT workspace where the dot runs. A tunnel tied only to a personal org
   does not appear in an Enterprise or Edu workspace. If the association can't be verified automatically, the
   OpenAI account team can set a manual override.

## 2. Create the runtime key

Create a restricted Platform API key with only Tunnels **Read + Use**. It is the tunnel's transport
credential. Never reuse it as the MCP login credential or a webhook secret. Store it in an owner-only file,
so it never reaches shell history:

```sh
install -d -m 700 .state
umask 077; $EDITOR .state/tunnel-runtime-key   # paste the key, save
```

## 3. Start the reference server

Run these commands from the repository root. The throwaway
[example](../examples/step0-spike.md) reuses the Python reference only for this probe. Neither the example
nor `phase1` becomes a runtime dependency of the shipped Rust gateway. No xmsg node is needed.

Use a separate state directory for each authentication arm, and stop one server before starting the other.
Both configurations below use `http://127.0.0.1:8765/mcp`; use that URL in step 4. Keep secrets out of the
config and command line. Access logging is disabled; the observation procedure below uses content-free
status rather than raw requests.

### No Authentication arm: tunnel-only example ingress

Create `.state/step0-bearer.toml` with this nonsecret configuration:

```toml
auth_mode = "bearer"
state_dir = ".state/step0-bearer"
bind = "127.0.0.1"
port = 8765
```

If the trusted CA bundle is not at Python/OpenSSL's default location, set its path before starting the
server. The hosted probe on NixOS with uv's standalone Python failed callback verification because
`/etc/ssl/cert.pem` was absent; this resolved it:

```sh
export SSL_CERT_FILE=/etc/ssl/certs/ca-certificates.crt
```

Use the trusted CA bundle appropriate to the host; keep TLS certificate verification enabled. This also
applies to the OAuth arm below. A missing CA bundle is a local TLS configuration failure, not evidence that
the callback endpoint rejected the subscription.

Issue a temporary credential into an owner-only file, then start the tunnel ingress:

```sh
uv run --locked python examples/step0_spike.py --config .state/step0-bearer.toml \
  --allow-bearer issue-bearer --output .state/step0-bearer-token
uv run --locked python examples/step0_spike.py --config .state/step0-bearer.toml \
  --allow-bearer serve --no-auth-ingress .state/step0-bearer-token
```

Issuance refuses an existing output file. The token is never printed; the server stores its digest.
The observed ChatGPT form offers **OAuth** or **No Authentication**, with no bearer/API-key entry. Select
**No Authentication** for this arm. `--no-auth-ingress` accepts credential-less tunnel requests and supplies
the issued token internally, so the reference server still authenticates every request. An explicitly
supplied wrong bearer remains unauthorized. `tools/list` declares `noauth` for this ingress; an OAuth2
security scheme caused the form to reject the No Authentication connection.

This flag requires bearer mode and `bind = "127.0.0.1"`; it belongs only to this synthetic tunnel probe.
It changes no reference-server default, local-test constraint or shipped Rust authentication. For an HTTP
bearer control outside the hosted form, omit `--no-auth-ingress` and supply the token through the client's
secure authentication mechanism. The hosted form has no place to enter it.


After check 3 succeeds, leave the intended conversation idle. In a second terminal, trigger check 4:

```sh
uv run --locked python examples/step0_spike.py --config .state/step0-bearer.toml \
  --allow-bearer emit hosted-noauth-one
uv run --locked phase1 --state .state/step0-bearer status
```

### OAuth arm: the existing provider path

Copy `config.oauth.example.toml` to `.state/step0-oauth.toml`. Set `state_dir = ".state/step0-oauth"`,
`bind = "127.0.0.1"` and `port = 8765`. Fill in the actual issuer, resource, subject, introspection URL and
client ID from [provider setup](provider-setup.md). Set `client_secret_file` to the owner-only file holding
the dedicated introspection client secret; do not put its value in the TOML. The OAuth access token is
obtained through the connection flow, not the bearer token file above. The reference is a resource server,
not an authorization server.

```sh
uv run --locked python examples/step0_spike.py --config .state/step0-oauth.toml serve
```

OAuth is the default; it needs no bearer opt-in. After check 3, trigger check 4 from a second terminal:

```sh
uv run --locked python examples/step0_spike.py --config .state/step0-oauth.toml emit hosted-oauth-one
uv run --locked phase1 --state .state/step0-oauth status
```

Both hosted arms advertise `xmsg_identity` and `xmsg.message.received.v1`. The subscriber supplies the HTTPS
callback and its distinct signing secret. The server verifies the signed callback challenge before delivery.
Emitting the same occurrence ID deduplicates it; use a new ID for another trial. Callback validation remains HTTPS/public-only
with no redirects. Never substitute the fixture's loopback callback transport for a hosted run.

## 4. Run `tunnel-client`

Download `tunnel-client` from the link in the Platform tunnel settings or from the `openai/tunnel-client`
GitHub releases, and check the release checksum. Run it as an unprivileged user that can read only the
runtime key file. It doesn't need this repository, an SSH agent or any other credential.

```sh
export CONTROL_PLANE_API_KEY="$(cat .state/tunnel-runtime-key)"
tunnel-client init --profile dots-spike --tunnel-id <tunnel_id> \
  --mcp-server-url http://127.0.0.1:8765/mcp
tunnel-client doctor --profile dots-spike --explain
tunnel-client run --profile dots-spike
```

Keep it running for the whole test: discovery and every call fail while it is disconnected. Its admin UI
(`/ui`) and its `/healthz` and `/readyz` endpoints listen on loopback by default.

## 5. Add the server in ChatGPT

1. Open ChatGPT → **Plugins** → **+** → **Add custom MCP server**.
2. Under **Connection**, choose **Tunnel**, then select the tunnel or paste its `tunnel_id`. No URL is entered.
3. **Authentication.** The observed form offers **OAuth** and **No Authentication** only; there is no bearer
   or API-key field. Record the options shown by the installation being tested.
   - **No Authentication:** use the tunnel-only ingress command in section 3. The temporary bearer stays in
     its owner-only token file and is injected internally; do not paste it into another field.
   - **OAuth:** use the existing provider path. Without the Harpoon OAuth forwarding settings in
     [Section P2](#p2-run-tunnel-client-v0020-with-the-harpoon-oauth-shim), the authorization server is *not*
     carried by the tunnel: the browser must reach it, and it must meet the exact-audience rule in
     [provider setup](provider-setup.md#python-synthetic-reference). If no such issuer is available, record
     that OAuth could not be tested; the No Authentication arm can still be measured independently.
4. Accept the risk warning and select **Create as a plugin**. Record the plugin's connection ID
   (`plugin_asdk_app…`).

## 6. What to observe

For each check, record pass or fail, the time, and content-free status from the matching state directory
(section 3). `xmsg_identity` also returns subscription health. For the No Authentication ingress, inspect
both the example's shape-only diagnostics and reference status:

```sh
tail -n 20 .state/step0-bearer/step0-diagnostics.jsonl
uv run --locked phase1 --state .state/step0-bearer status
```

The owner-only diagnostics file records field shapes, JSON-RPC outcome and the callback step that failed.
For a valid callback request it can identify the scheme and host, without the full URL, secret or cursor.
Malformed subscription parameters are recorded by shape only. Read diagnostics plus status; never enable
raw request logs or share request bodies, callback URLs, credentials or webhook headers.

Two discovery/transport log lines were harmless in the observed run:

- ChatGPT first sent MCP 2.0 HTTP `server/discover`; the reference returned HTTP 400 / JSON-RPC `-32601`,
  then ChatGPT fell back to `initialize`. That initial response does not by itself fail connection.
- `tunnel-client` logged `unsupported channel "harpoon"` on its OAuth-derived HTTP-target channel. With no
  OAuth targets configured, it did not prevent this tunnel arm from working. Investigate an actual failed
  check below rather than treating that line alone as a failure.

| # | check | passes when |
|---|---|---|
| 1 | connect and authenticate | the plugin page lists `xmsg_identity`; a dot calls it and gets the synthetic identity |
| 2 | event discovery | the synthetic event appears beside the tools on the plugin page (rescan after any change) |
| 3 | subscribe | in a dot, ask it to subscribe to `xmsg.message.received.v1` and say how to respond; health becomes `active`, which requires successful signed-challenge verification and stored subscription |
| 4 | wake-up | trigger the synthetic event (section 3); status records its event ID as `accepted` after callback 2xx, and the intended idle dot responds |
| 5 | unsubscribe | ask the dot to stop; health becomes `inactive` and a fresh occurrence stays pending rather than being delivered |

A successful tool call alone doesn't pass checks 2 to 4. If checks 1 and 2 pass but 3 or 4 fail through the
tunnel, the tunnel hasn't been shown to carry the event flow. Record that, then try section 7.

Callback acceptance is distinct from wakeup, observation or task completion. The probe demonstrates only
the synthetic portions of connection/discovery and idle wakeup: real service discovery and attested peer
origins remain production checks. Restarting with the same state can test recovery of a queued synthetic
event and subscription. There is no real xmsg custody/ACK boundary here; the full production restart gate
still requires failure injection before commit, before ACK, before webhook and after callback acceptance.

## 7. Fallback: public HTTPS

Use this only if section 6 fails through the tunnel. Put the OAuth example behind a TLS reverse proxy at a
public hostname (`exposure = "public-https"`, `public_url = "https://<host>/mcp"`; see
`config.oauth.example.toml`), retaining the loopback listener. The public hostname must match the config's
resource or public URL for Host validation. Add the server in ChatGPT with its URL instead of a tunnel,
select OAuth, and repeat section 6. If a compatible public issuer is unavailable, record that the fallback
could not be tested. Remove the public exposure when the run ends.

Do not expose `--no-auth-ingress` through the public reverse proxy. It is the synthetic tunnel-only arm,
not a public authentication mechanism. The example's direct bearer HTTP control remains available to
clients with a supported secure bearer entry, but the observed ChatGPT form does not offer one.

## 8. Tear down

1. Unsubscribe in the dot, then delete the plugin.
2. Stop `tunnel-client` and the example, and delete `.state/` from the test checkout.
3. Revoke the runtime key, and delete the tunnel if it won't be reused.

## 9. Report

Report these results, with no secrets: which authentication options the form offered and which one worked;
the pass/fail table from section 6, with times; whether the tunnel or the fallback carried it; the
`tunnel-client` version; and content-free diagnostic steps or error codes. Do not attach raw requests or
credential-bearing error text.
