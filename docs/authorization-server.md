# Gateway authorization server

Planned, not yet released. The optional `authorization_server` makes the Rust gateway an OAuth authorization server for one pre-registered hosted client. Kanidm supplies upstream login; the gateway issues its own access and rotating refresh tokens. It adds no xmsg address or mailbox. Existing hosted ChatGPT OAuth and Events acceptance measured on 2026-11-10 used the legacy provider path; it does not establish acceptance of this new authorization flow.

The MCP resource URL and the authorization-server issuer are distinct. MCP may remain behind a private tunnel. The gateway's authorization-server routes must be reachable over public HTTPS by the browser and hosted OAuth client:

| Route | Method | Purpose |
| --- | --- | --- |
| `/.well-known/oauth-authorization-server` | GET | OAuth authorization-server metadata |
| `/oauth/authorize` | GET | Start upstream login, with downstream S256 PKCE |
| `/oauth/callback` | GET | Upstream login callback |
| `/oauth/token` | POST | Exchange a code or rotate a refresh token |
| `/oauth/revoke` | POST | Revoke the token's whole family; unknown token returns success |

Token and revocation requests require `client_secret_basic`. S256 PKCE is mandatory for code exchange. There is no dynamic client registration or CIMD. Register the exact redirect URI shown by the new connector; do not derive it from another connector. Provision the downstream client secret separately from upstream credentials and the liveness API token. Kanidm 1.11.2 ignores introspection caller Basic credentials; that measured provider behavior does **not** relax the gateway's own client authentication.

Startup rejects registered client redirect URIs whose decoded query keys contain `code`, `state`, `iss`, `error`, `error_description` or `error_uri`, including percent-encoded spellings. Noncolliding registered queries remain allowed and are preserved in success and error redirects. The AS never adds `iss` and does not advertise RFC 9207.

Every ingress proxy must drop the query string from access logs for `/oauth/*`. Callback code and state must not enter logs. PKCE mitigates a leaked authorization code; it does not make logging one acceptable.

## Owner configuration

Use `verifier_profiles` with exactly one local entry and a matching `authorization_server`. The local entry must set both `local` and `opaque_default` to true. Remote entries can remain during cutover; set the old entry's `advertised` to false to stop advertising its issuer while continuing to accept its tokens. `advertised` defaults to true and does not confer authority.

The following is a fragment of the owner file, not a complete runnable configuration. Replace example identifiers, provision private files, and supply all existing listener, store, messaging and Events fields separately:

```json
{
  "verifier_profiles": [{
    "local": true,
    "opaque_default": true,
    "advertised": true,
    "service": "gateway",
    "issuer": "https://auth.gateway.example",
    "resource": "https://gateway.example/mcp",
    "subject": "owner",
    "hosted_client": "hosted-dot",
    "required_scopes": ["identity:read", "events:subscribe"]
  }],
  "authorization_server": {
    "issuer": "https://auth.gateway.example",
    "client": {
      "id": "hosted-dot",
      "secret_file": "hosted-client-secret",
      "redirect_uris": ["https://chat.example/connector/oauth/example"]
    },
    "upstream": {
      "authorization_endpoint": "https://idm.example/ui/oauth2",
      "token_endpoint": "https://idm.example/oauth2/token",
      "client_id": "gateway-login",
      "redirect_uri": "https://auth.gateway.example/oauth/callback",
      "verify": {
        "service": "gateway",
        "issuer": "https://idm.example/oauth2/openid/gateway-login",
        "resource": "https://gateway.example/mcp",
        "audience": "gateway-login",
        "subject": "owner",
        "hosted_client": "gateway-login",
        "introspection_url": "https://idm.example/oauth2/token/introspect",
        "introspection_client": "gateway-lookup",
        "client_secret_file": "lookup-secret",
        "required_scopes": ["openid"],
        "timeout_ms": 5000
      }
    },
    "liveness": {
      "api_url": "https://idm.example",
      "person": "owner",
      "group": "gateway-login.access@idm.example",
      "canary_person": "gateway-liveness-test",
      "token_file": "liveness-reader-token",
      "grace_secs": 900,
      "timeout_ms": 5000
    }
  }
}
```

The example callback is illustrative; use the actual connector URI. The local AS issuer must be an HTTPS origin without a subpath, query, fragment or userinfo. An optional root slash remains part of its exact binding; endpoint URLs still use a single `/oauth/` separator. Upstream issuer strings also match exactly, including trailing slashes. `upstream.verify` is the existing strict verifier configuration for the upstream login client, with the configured owner subject. Its client/audience identify the login client, not the hosted downstream client. Secret/certificate paths resolve against the owner file's directory. Keep secret files owner-only, never inline or committed. Unknown fields refuse startup.

Include the authorization server's public Host in the existing `allowed_hosts` alongside the MCP Host, and configure legitimate browser `allowed_origins`. The OAuth routes use the same Host/Origin checks; exposing a separate issuer without these entries returns 403.

| Optional field | Default | Accepted range / meaning |
| --- | --- | --- |
| `access_ttl_secs` | 3600 | 60–86400 seconds |
| `refresh_idle_secs` | 2592000 | 3600–7776000 seconds; 30 days by default |
| `refresh_absolute_secs` | 7776000 | 86400–31536000 seconds; at least idle lifetime; 90 days by default |
| `max_families` | 8 | Live families per grant; least recently refreshed is evicted |
| `rotations_per_hour` | 12 | Successful rotations and retry mints per rolling hour |
| `max_refresh_rows` | 2048 | Retained rotated/superseded refresh rows per family |
| `pending_max` | 64 | Pending browser logins; oldest evicted at capacity |
| `authorize_rate_per_min` | 30 | Global authorization bucket, burst 10 |
| `liveness.grace_secs` | 900 | 0–3600 seconds; applies only to unavailable/indeterminate evidence |
| `liveness.timeout_ms` | 5000 | Positive, at most 30000 milliseconds |

The authorize bucket is global and unauthenticated. One caller can drain it, making the owner's reconnect return 429 until refill; this bounds memory/CPU, not lockout fairness. Per-IP limits belong at the ingress because the gateway does not trust forwarded-IP headers.

The five cap settings accept 1–65536. These are shared process resources, not separate capacity per dot.

## Lifetimes and liveness

A family lasts at most 90 days by default and expires after 30 days without successful refresh. Every successful retry updates the idle timestamp too. Access tokens default to one hour. Revocation, grant disable, readable liveness denial, reuse, code replay and family eviction end the family; re-enabling a grant does not revive it. There is no separate `oauth-revoke` CLI: use the authenticated revocation endpoint or the grant switch.

The runtime liveness reader uses a read-only Kanidm API token from a service account in builtin `idm_people_pii_read`. This permission covers PII across persons, not only the configured owner and canary. The gateway limits its requests to those configured entries; the credential's broader read capability is a provisioning cost. An administrator role or custom ACP is unnecessary. Owner-controlled provisioning must establish visibility before deployment.

Each liveness observation performs exactly five GETs to `/v1/person/<person>/_attr/<attribute>`: owner `account_valid_from`, `account_expire` and `memberof`, plus the permanent canary's `account_valid_from` and `account_expire`. The canary dates prove visibility; its membership never authorizes the owner. Do not write owner validity sentinels. Configure membership by its exact SPN, including domain, rather than UUID.

Decision precedence is **negative, unavailable, indeterminate, positive**. A readable future owner validity-from, expired owner validity, or present membership list without the required SPN denies even if another attribute is null or unavailable. A visible owner's null validity dates mean unrestricted validity only when the canary dates and owner's required membership are visible. Null membership, null canary dates or whole-entry `200 null` means indeterminate visibility, not proof of deletion. Malformed/unavailable reads are unavailable. Callback admits only positive evidence; unavailable/indeterminate callbacks return `temporarily_unavailable` without a code or family.

Refresh and due Events delivery read liveness without holding a service operation lease or network-spanning SQLite transaction. Reads use per-family tickets; older positive evidence cannot replace a newer outcome or revive a revoked family. A positive observation advances the bound from its **start**, not completion. A due Events item triggers a read when its delivery bound is within 600 seconds or passed, at most once per family per 300 seconds; a read mints no token.

A readable denial is enforced within one access lifetime (one hour by default). Unavailable or indeterminate evidence can extend access to the latest positive observation plus that lifetime and grace (75 minutes by default). Grace never applies to a readable denial. A null membership after removal, hidden/deleted entry, or denial observed only during an outage has the longer bound. Neither upstream consent removal alone nor Kanidm browser logout revokes an existing gateway family. Use local revocation, grant disable, account disable or readable group removal to end access.

All real-time bounds assume a trusted, NTP-disciplined gateway wall clock with bounded cumulative error. No numeric clock-error allowance is promised. Detected backward steps beyond five seconds revoke live families and block minting until catch-up; reconnect afterwards. Small repeated backward steps can evade detection. Rollback detection is a safety net, not an independent time source.

A detected rollback whose SQLite revoke write fails remains pending in the running process. New admission and minting fail closed until the revocation transaction commits, even if the wall clock catches up first. If the process dies before **any durable write recording that detection** and the wall clock catches up before restart, that unrecorded detection is lost. There is no second persistence channel; the trusted-clock assumption still applies.

## Admission, refresh and retained state

Ordinary local sends and broker calls, plus recovery of stored reply receipts/reservations, carry the transactionally captured admission identity, grant revision and in-memory outbound policy through their request budget. A later policy edit does not alter an admitted send; no durable policy snapshot is added. Custody reads, ACK, and reply-target ownership lookup with its pre-effect recheck retain the effect-point grant/revision fence. A disable after admission but before reply-target lookup refuses a new reply with no reservation or bus effect. Stored reply receipt/reservation recovery retains its admitted snapshot. Events subscribe/renew also freshly verifies at its effect point because it creates future wake authority. No eligibility-history table preserves earlier custody rights. Remote profiles retain their existing once-at-entry provider verification and effect-time expiry/grant checks.

Refresh rotates A to B. Ordinary rotation preserves prior access tokens until their own expiry or family revocation: rotating B does not invalidate its unused access token. A has one lost-response retry within 30 seconds of its original rotation, only while B is current and unused. Retry creates C, supersedes B and invalidates B's access token. Using B's access token or rotating B marks it used. A second retry, older predecessor, superseded token or late reuse revokes the family. A successful retry counts against the rolling rotation limit; it does not restart the retry window. Excess rotations return 429 with `Retry-After`; transient failures return 503 rather than inventing authority.

With the default log filter, post-commit `gateway_oauth_refresh` records identify `rotate`, `retry` and `reuse`. Class-only `gateway_oauth_authentication` records distinguish `invalid_client` and `invalid_token` refusals. They contain no token, family or secret value. If you override the filter, retain `gateway_oauth_refresh=info` for owner acceptance; local tests do not establish actual hosted refresh behavior.

The retry exception is a deliberate risk: someone holding A **and the downstream client secret** can take the retry slot before the legitimate client uses B. B's later refresh then revokes the whole family, including C. Reconnect is required after any family revocation. It does not guarantee another passkey prompt: an existing Kanidm browser session may satisfy upstream login.

Durable OAuth codes/access/refresh tokens are stored only as hashes; no raw pair cache survives or is required across restart. Rotation accounting is independent of refresh-row pruning. Pruned refresh tokens are unknown and refuse without revoking a family. Access rows remain through expiry plus 30 seconds; codes through expiry plus 60 seconds. Existing Events encryption still protects callback secrets and retained legacy bearer credentials.

## Events and explicit renewal

A local subscription stores `token_family`, with no stored bearer. The subscription TTL still defaults to one hour and is clamped between one minute and 24 hours, then by family absolute and idle expiry. It is not clamped to the access token's expiry. Family liveness can keep a pending delivery eligible across access-token expiry; it does not renew the subscription TTL. The client must renew it explicitly.

A revoked/expired family defers pending delivery without changing item state and does not use the legacy `credential_required` path. New authorization creates a new family but does **not** update the old subscription. Renew/re-subscribe with a live token to bind that family. There is no automatic follow-on by shared subject or grant: that could restore a revoked thief-owned callback. Legacy reconnect can make MCP work while Events remains parked on its old bearer until subscription renewal.

## Owner-run migration, cutover and rollback

These operations change durable authority and belong to an owner maintenance window. Back up the state database and existing configuration first. Preserve the legacy connector/profile until read-back and rollback checks complete. For a new store, follow the existing custody/outbound/retirement/Events migration sequence before the AS migration.

```sh
xmsg-mcp-gateway --state <store> migrate-profiles --if-needed
xmsg-mcp-gateway --state <store> migrate-attachments --if-needed
xmsg-mcp-gateway --state <store> migrate-authorization-server --if-needed
xmsg-mcp-gateway --state <store> migrations-pending
```

The attachment metadata migration is an independent marker extension. It can run before or after the AS migration, including on schema version 5, without changing that global version. `migrations-pending` lists attachments before the AS migration.

1. Start creating a **new** hosted connector. Obtain its exact redirect URI and provision the AS client secret and upstream login registration. Do not authorize it yet.
2. Migrate, read back an empty pending-migration list, enroll/enable the exact local binding, and deploy both profiles. Hide the old issuer with `advertised: false`; retain the old `events.grant_id` initially. The old connector continues to work.
3. Drain the old connector's inbox with reads and ACKs. Stop the gateway/pod before switching authority; a free operation lease alone does not prove the process stopped.
4. Run the offline guard:

   ```sh
   xmsg-mcp-gateway cutover-events --config <owner-file> --from <old-grant> --to <new-grant> --operator <operator> --reason <reason>
   ```

   Exit 4 means busy. Exit 3 means unobserved, unexpired content remains on either grant; drain it before proceeding. Only the owner may intentionally use `--abandon-unread`, which records `cutover-abandon` audit rows. An observed item with a pending callback is not independently unread.
5. Read back the latest `events_cutover.to_grant` and the release audit in the backed-up store using owner-controlled database inspection. The latest marker must match the new configured `events.grant_id`. Startup refuses a mismatch. The acceptance transaction defers a stale process still selecting the old grant without acknowledging upstream; queued messages remain in xmsg. This guard protects the switch but does not remove the maintenance-window requirement.
6. Start with the new Events grant, complete the new connector's OAuth, then explicitly subscribe with its token. Check identity, a wake, mailbox read/ACK and a send before retiring the old connector/grant. Wakes pause between quiescing and the new subscription. This procedure does not transfer old custody to the new grant.
7. Before retirement, rollback uses the same procedure in reverse: stop, guard `--from <new-grant> --to <old-grant>` with operator/reason, drain or explicitly abandon unread content, restore the old Events configuration, then use the old connector. Read back marker/configuration agreement again. Keep historical bindings wherever store validation requires them; disabling a grant does not delete its history.

Hosted acceptance for this flow remains pending: actual connector redirect/discovery, refresh retries/concurrency, subscription renewal, logout independence, revocation, restart, outage bounds and a soak beyond 25 hours must be observed by the owner. Local capability and the legacy 2026-11-10 hosted result do not substitute for those checks.
