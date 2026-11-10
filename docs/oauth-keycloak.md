# Keycloak OAuth broker setup (fallback path)

> **Fallback status:** Brokering OAuth through Keycloak is the **fallback** path.
> For the **direct** path — where Kanidm `1.11.2` (or any OAuth/OIDC provider
> whose access tokens set `aud` to the dedicated OAuth client name rather than
> the MCP resource URL) is used directly without running a broker — configure
> `verifier.audience` as documented in
> [OAuth provider setup — Direct Kanidm 1.11.2](provider-setup.md#direct-kanidm-1112).
> Use this Keycloak recipe only when a deployment requires an intermediate OAuth
> 2.1 broker that mints exact-resource audiences (`aud == verifier.resource`), or
> when exercising the strict-resource synthetic Python reference
> ([provider-setup.md](provider-setup.md#python-synthetic-reference)).

This guide configures a standard Keycloak `26.8.1` realm (with no experimental
`--features` flags) as an OAuth 2.1 authorization server or upstream OIDC broker
for `xmsg-mcp-gateway`. Every placeholder below (`https://auth.example`,
`https://idm.example`, `https://gateway.example/mcp`, and the example owner UUID
`00000000-0000-4000-8000-000000000001`) must be replaced with the deployment's
real HTTPS origins and owner subject. Keep client secrets, Events keys, access
tokens and session cookies in owner-only files (`0600` or `0400`), never in
committed files, command lines or logs.

## Architecture and reachability

- **Canonical MCP resource (`resource`):** `https://gateway.example/mcp` (the
  exact identifier advertised in `/.well-known/oauth-protected-resource`, not a
  tunnel ID or loopback bind address).
- **Canonical realm issuer (`issuer`):** `https://auth.example/realms/mcp` (**no
  trailing slash**; Keycloak omits a trailing slash in discovery metadata and
  introspection responses).
- **Browser and hosted-client reachability:** Browser authorization redirects go
  directly to Keycloak's `/realms/mcp/protocol/openid-connect/auth` endpoint (and
  any federated upstream login page); verify that discovery and `/token`
  endpoints are reachable along the chosen deployment route (public HTTPS or an
  explicitly configured tunnel OAuth forwarder).
- **Introspection reachability:** `/realms/mcp/protocol/openid-connect/token/introspect`
  only needs to be reachable from `xmsg-mcp-gateway` over verified HTTPS (public
  DNS, private PKI via `verifier.root_certificate_file`, or pinned IPs via
  `verifier.provider_addresses`).
- **Persistence:** Use PostgreSQL in production so realm signing keys, sessions
  and federated user `sub` UUIDs survive restarts.

## 1. Realm scopes and exact-resource audience mapper

Create a dedicated realm (for example `mcp`) and two OpenID Connect client scopes:

1. `identity:read` (`protocol`: `"openid-connect"`, attribute
   `"include.in.token.scope": "true"`).
2. `events:subscribe` (`protocol`: `"openid-connect"`, attribute
   `"include.in.token.scope": "true"`).

On `identity:read`, add an `oidc-audience-mapper` protocol mapper that stamps the
exact gateway `resource` URI into both the access token and the RFC 7662
introspection payload:

```json
{
  "name": "mcp-resource-audience",
  "protocol": "openid-connect",
  "protocolMapper": "oidc-audience-mapper",
  "consentRequired": false,
  "config": {
    "included.custom.audience": "https://gateway.example/mcp",
    "included.client.audience": "",
    "access.token.claim": "true",
    "id.token.claim": "false",
    "introspection.token.claim": "true"
  }
}
```

## 2. Dedicated introspection client

`xmsg-mcp-gateway` authenticates to the introspection endpoint with HTTP Basic
credentials (`verifier.introspection_client` and `verifier.client_secret_file`),
separate from the hosted OAuth client (`verifier.hosted_client`). Create a
confidential client with no interactive or token-minting flows enabled, and set
`"allow.token.introspection.without.audience.check": "true"` so Keycloak permits
it to introspect tokens whose singleton `aud` is `https://gateway.example/mcp`:

```json
{
  "clientId": "gateway-introspector",
  "protocol": "openid-connect",
  "enabled": true,
  "publicClient": false,
  "clientAuthenticatorType": "client-secret",
  "standardFlowEnabled": false,
  "implicitFlowEnabled": false,
  "directAccessGrantsEnabled": false,
  "serviceAccountsEnabled": false,
  "fullScopeAllowed": false,
  "attributes": {
    "allow.token.introspection.without.audience.check": "true"
  }
}
```

`clientId` must not contain `:` (RFC 7617 Basic authentication). Store its
generated secret in `.state/introspection-secret` with mode `0600`.

## 3. Pre-registered hosted OAuth client

Pre-register a dedicated OAuth client for the hosted MCP connector instead of
enabling anonymous Dynamic Client Registration (`403` by default in Keycloak
`26.8.1`). Pre-registration gives a stable `clientId` for `verifier.hosted_client`
and `binding.json`.

Keycloak `26.8.1` advertises `"authorization_response_iss_parameter_supported": true`
(RFC 9207) and returns `iss` on authorization redirects, for which ChatGPT uses
the redirect URI `https://chatgpt.com/connector_platform_oauth_redirect`. Confirm
the exact callback URI displayed by the connection UI when creating the connector.

```json
{
  "clientId": "chatgpt-mcp-client",
  "protocol": "openid-connect",
  "enabled": true,
  "publicClient": true,
  "standardFlowEnabled": true,
  "implicitFlowEnabled": false,
  "directAccessGrantsEnabled": false,
  "serviceAccountsEnabled": false,
  "fullScopeAllowed": false,
  "redirectUris": [
    "https://chatgpt.com/connector_platform_oauth_redirect"
  ],
  "defaultClientScopes": [
    "basic",
    "profile",
    "email"
  ],
  "optionalClientScopes": [
    "identity:read",
    "events:subscribe"
  ],
  "attributes": {
    "pkce.code.challenge.method": "S256"
  }
}
```

Public vs confidential client selection:

- Both `publicClient: true` (PKCE `S256` with `token_endpoint_auth_method = none`)
  and `publicClient: false` (`client_secret_post` or `client_secret_basic` plus
  PKCE `S256`) produce identical introspected claims and pass `xmsg-mcp-gateway`.
- Keycloak `26.8.1` omits `"none"` from `token_endpoint_auth_methods_supported`
  in discovery metadata even though `publicClient: true` accepts unauthenticated
  PKCE exchanges at `/token`. If the hosted UI's predefined-client form requires
  a client secret (or checks `token_endpoint_auth_methods_supported`), set
  `"publicClient": false` and supply the generated secret in that secure form.

Restrict login to the owner account in the realm (or in the upstream OIDC
provider's group-to-scope mapping).

## 4. Optional upstream OIDC federation (Kanidm or another OIDC provider)

When not using the direct `verifier.audience` path
([provider-setup.md](provider-setup.md#direct-kanidm-1112)), Keycloak can
federate to an upstream OIDC provider such as Kanidm `1.11.2`: Keycloak verifies
the upstream OIDC login (`ES256` JWKS + PKCE `S256`) and mints downstream tokens
carrying `"aud": "https://gateway.example/mcp"` and a stable Keycloak user `sub`
across token refreshes and subsequent logins.

1. **Upstream OIDC provider (for example Kanidm `1.11.2`):**
   - Create a confidential OAuth2 client (for example `keycloak-mcp-broker`).
   - Register Keycloak's fixed broker callback URI:
     `https://auth.example/realms/mcp/broker/upstream-idp/endpoint`.
   - Map only the owner group to `openid`, `profile`, `email`, and keep PKCE
     (`S256`) enabled.
2. **Keycloak Identity Provider (`alias`: `"upstream-idp"`, `providerId`: `"oidc"`):**

   ```json
   {
     "alias": "upstream-idp",
     "providerId": "oidc",
     "enabled": true,
     "trustEmail": true,
     "storeToken": false,
     "syncMode": "IMPORT",
     "firstBrokerLoginFlowAlias": "first broker login",
     "config": {
       "issuer": "https://idm.example/oauth2/openid/keycloak-mcp-broker",
       "authorizationUrl": "https://idm.example/ui/oauth2",
       "tokenUrl": "https://idm.example/oauth2/token",
       "userInfoUrl": "https://idm.example/oauth2/openid/keycloak-mcp-broker/userinfo",
       "jwksUrl": "https://idm.example/oauth2/openid/keycloak-mcp-broker/public_key.jwk",
       "useJwksUrl": "true",
       "validateSignature": "true",
       "clientId": "keycloak-mcp-broker",
       "clientSecret": "<provisioned-from-secret-file>",
       "clientAuthMethod": "client_secret_basic",
       "defaultScope": "openid profile email",
       "pkceEnabled": "true",
       "pkceMethod": "S256"
     }
   }
   ```

3. **Disable `idp-review-profile` in `first broker login`:** In a fresh Keycloak
   `26.8.1` realm, the `first broker login` authentication flow marks
   `idp-review-profile` (`Review Profile`) as `REQUIRED`. Set that execution's
   requirement to `DISABLED` so the owner's first federated login completes
   without an extra profile-confirmation form.

After the owner's first login (native or federated), read the Keycloak user's
`id` UUID from Keycloak Admin (`Users`) or from a test token introspection; that
UUID is the `subject` enrolled in `xmsg-mcp-gateway`.

## 5. Three configuration traps that fail closed

1. **Missing `allow.token.introspection.without.audience.check` on `gateway-introspector`:**
   Keycloak `26.8.1`'s `AccessTokenIntrospectionProvider.verifyAudience` checks
   whether the introspecting client's `clientId` appears in the token's `aud`
   claim and returns `{"active": false}` when it does not. Because this broker
   profile emits `aud` equal to the singleton `https://gateway.example/mcp` URI
   and `xmsg-mcp-gateway` forbids `:` in `introspection_client`,
   `gateway-introspector` cannot appear in `aud`. Setting
   `"allow.token.introspection.without.audience.check": "true"` on
   `gateway-introspector` resolves this without widening `aud` or weakening
   realm-wide defaults.
2. **Leaving `roles` attached (or `fullScopeAllowed: true`), or removing `basic`:**
   Keycloak's default `roles` client scope carries `oidc-audience-resolve-mapper`,
   which adds `"account"` to `aud` whenever the user holds default account roles.
   Introspection then reports `"aud": ["https://gateway.example/mcp", "account"]`,
   which `xmsg-mcp-gateway` rejects with `HTTP 401`. Conversely, `oidc-sub-mapper`
   lives on the `basic` client scope in Keycloak `26.8.1` (there is no separate
   `openid` client scope row), so `basic` **must** remain in `defaultClientScopes`
   or `sub` will be omitted.
3. **Issuer trailing-slash mismatch and experimental `--features=resource-indicators`:**
   Keycloak emits `"iss": "https://auth.example/realms/mcp"` with **no** trailing
   slash; configuring `"https://auth.example/realms/mcp/"` fails exact issuer
   comparison (`HTTP 401`). Do not enable Keycloak's experimental
   `--features=resource-indicators` mode as a substitute for §1 above: its
   `ResourceIndicatorsPostProcessor` rewrites `aud` when minting the JWT at
   `/token` but does not run during `AccessTokenIntrospectionProvider` mapper
   evaluation, re-injecting the resource-server `clientId` into introspected `aud`
   arrays unless mapper introspection flags are manually overridden.

## 6. Gateway configuration

### Rust `xmsg-mcp-gateway` (`docs/serving.md`, `docs/events.md`, `README.md`)

`xmsg-mcp-gateway` takes a JSON serving configuration (`serve --config`) and a
JSON enrollment binding (`enroll`), both rejecting unknown fields
(`#[serde(deny_unknown_fields)]`). Because Keycloak's `oidc-audience-mapper`
already emits `aud` equal to `verifier.resource`, omit `verifier.audience` (it
defaults to `verifier.resource`; `verifier.audience` is used on the
[direct Kanidm path](provider-setup.md#direct-kanidm-1112)).

Create `.state/binding.json` (replace `00000000-0000-4000-8000-000000000001` with
the owner's Keycloak user UUID):

```json
{
  "service": "gateway",
  "issuer": "https://auth.example/realms/mcp",
  "resource": "https://gateway.example/mcp",
  "subject": "00000000-0000-4000-8000-000000000001",
  "hosted_client": "chatgpt-mcp-client"
}
```

Create `.state/serving.json` (identity-only profile; `request_timeout_ms: 60000`
with `verifier.timeout_ms: 5000` already satisfies the Events budget ceiling
`request_timeout_ms >= 2 * verifier.timeout_ms + 41000` when adding `messaging`
and `events`):

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
  }
}
```

When enabling [messaging](serving.md#optional-messaging-profile) and
[Events](events.md), run `migrate-custody`, `migrate-outbound`, `migrate-retirement`, and
`migrate-events --key-file .state/events.key` before `enroll`, add the
`messaging` section ([serving.md](serving.md#optional-messaging-profile)), and
merge this `events` section into `.state/serving.json` (with
`verifier.timeout_ms: 5000`, `dispatch_timeout_ms: 16000` satisfies
`dispatch_timeout_ms >= verifier.timeout_ms + 11000` and
`request_timeout_ms: 60000` satisfies
`request_timeout_ms >= 2 * verifier.timeout_ms + 41000`):

```json
{
  "events": {
    "key_file": "events.key",
    "grant_id": "grant-1",
    "dispatch_timeout_ms": 16000
  }
}
```

If Keycloak uses a private CA during local testing, add
`"root_certificate_file": "ca.pem"` inside `verifier` (resolved relative to
`.state/`).

Initialize, enroll and enable the identity-only store before starting `serve`:

```sh
install -d -m 700 .state
umask 077
# Write the gateway-introspector secret into .state/introspection-secret (mode 0600)
chmod 600 .state/serving.json .state/binding.json .state/introspection-secret

xmsg-mcp-gateway --state .state/grants.db init
xmsg-mcp-gateway --state .state/grants.db enroll grant-1 .state/binding.json
xmsg-mcp-gateway --state .state/grants.db enable grant-1 1
xmsg-mcp-gateway serve --config .state/serving.json
```

### Synthetic Python reference server (`config.oauth.example.toml`, feasibility probe only)

If running the repository's synthetic feasibility server
([provider-setup.md](provider-setup.md#python-synthetic-reference)), its
`.state/oauth.toml` uses the TOML schema in `config.oauth.example.toml`:

```toml
auth_mode = "oauth"
state_dir = ".state/phase1"
exposure = "private"
issuer = "https://auth.example/realms/mcp"
resource = "https://gateway.example/mcp"
subject = "00000000-0000-4000-8000-000000000001"
introspection_url = "https://auth.example/realms/mcp/protocol/openid-connect/token/introspect"
client_id = "gateway-introspector"
client_secret_file = ".state/introspection-secret"
```

Note the schema differences from the Rust gateway: `oauth.toml` names the
introspection caller `client_id` (rather than `verifier.introspection_client`),
supports optional `provider_addresses`, and has no `audience`, `service`,
`hosted_client` or `root_certificate_file` fields because those belong only to
the Rust gateway's `VerifierConfig` and `Binding`.

## 7. Operator self-check (positive + multi-audience negative control)

Verify the deployment against the shipped Rust `xmsg-mcp-gateway` binary before
attaching a tunnel or hosted connector:

1. **Positive check (`HTTP 200` on singleton audience):**
   Obtain an Authorization Code + PKCE (`S256`) access token for
   `chatgpt-mcp-client` requesting `scope=openid profile email identity:read events:subscribe`,
   storing the token in an owner-only file `.state/good.token` (`0600`). Call
   `xmsg_identity` on the running Rust gateway:

   ```sh
   curl -sS -o /dev/null -w '%{http_code}\n' \
     -X POST http://127.0.0.1:18787/mcp \
     -H 'Content-Type: application/json' \
     -H 'Accept: application/json' \
     -H "Authorization: Bearer $(cat .state/good.token)" \
     -d '{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"xmsg_identity","arguments":{}}}'
   ```

   Expected output: `200`.

2. **Multi-audience negative control (`HTTP 401` when `roles` / `"account"` leaks into `aud`):**
   Temporarily add `"roles"` to `chatgpt-mcp-client`'s `defaultClientScopes` in
   Keycloak, mint a fresh PKCE access token into `.state/multi-aud.token` (so
   `iss`, `sub`, `client_id` and scopes still match `serving.json` and
   `binding.json`, isolating only `"aud": ["https://gateway.example/mcp", "account"]`),
   immediately remove `"roles"` from `chatgpt-mcp-client` again, and run the
   same `xmsg_identity` request:

   ```sh
   curl -sS -o /dev/null -w '%{http_code}\n' \
     -X POST http://127.0.0.1:18787/mcp \
     -H 'Content-Type: application/json' \
     -H 'Accept: application/json' \
     -H "Authorization: Bearer $(cat .state/multi-aud.token)" \
     -d '{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"xmsg_identity","arguments":{}}}'
   ```

   Expected output: `401` (with `WWW-Authenticate` challenge), confirming that
   multi-audience tokens are rejected at the gateway boundary. Revoke or delete
   both `.state/*.token` files when finished.

3. **Optional reference cross-check (development checkout only, not part of the Rust product):**
   In a repository checkout with `uv sync --locked`, `uv run python -m phase1.provider_probe --config .state/oauth.toml --token-file .state/good.token`
   can optionally be run to inspect content-free per-predicate booleans (`status: "pass"`
   for `.state/good.token` and `exact_resource_audience: false` for `.state/multi-aud.token`).
