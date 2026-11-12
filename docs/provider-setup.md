# OAuth provider setup

The Rust gateway and the Python synthetic reference have different audience
configuration. Keep credentials in owner-only files and local setup files out of
version control. The Rust owner configuration may be read-only and nonsecret, as
described in [serving configuration](serving.md#owner-configuration).
Never paste access tokens, client secrets or tunnel credentials into chat or logs.
This repository does not implement an authorization server.

## Rust gateway

The canonical `verifier.resource` is the exact URL advertised by the gateway's
protected-resource metadata. It remains the resource in the verified identity and
local grant, not the tunnel ID, listener address or OAuth client name.

Optional `verifier.audience` selects the expected access-token audience. Omit it
to require the resource URL. When supplied, it must be nonempty and contain no
whitespace. Introspection must return exactly that audience as a string or a
singleton array; additional audiences are refused even when the expected value
is present. The configured issuer, owner subject, active/unexpired claims and
required scopes are still checked, and `client_id` must equal `hosted_client`.
See the [Rust owner configuration](serving.md#owner-configuration).

### Direct Kanidm 1.11.2

The local Kanidm 1.11.2 measurement returned its OAuth client name as `aud`, even
when an MCP resource URL was requested. The Rust verifier can accept that profile
without a broker by setting `audience` to the dedicated client name:

```json
{
  "resource": "https://gateway.example/mcp",
  "audience": "gateway-dot",
  "hosted_client": "gateway-dot"
}
```

These are fields within `verifier`, not a complete serving configuration. Replace
`gateway-dot` with the actual dedicated registration name and verify that
introspection reports it as both the singleton audience and `client_id`.

When audience and resource differ, use one dedicated OAuth client for exactly
one gateway resource. Set that client's origin to the resource URL's origin
(scheme, host and port): for the example, `https://gateway.example`. Never reuse
that registration for another resource or application. This one-to-one binding
is required; accepting a shared application audience would not identify the MCP
resource. Keep the full resource URL in protected-resource metadata, verified
identity and grant enrollment. Do not replace those values with the client name.

The audience option is generic, not a Kanidm-specific authentication mode. A
provider that already issues resource audiences needs no override. A broker can
also remain in use as a fallback when an installation requires exact-resource
access tokens (see the [Keycloak OAuth broker fallback recipe](oauth-keycloak.md)).
Kanidm 1.11.2 does not authenticate introspection callers: a wrong Basic lookup secret produced the same active response in the measured installation. For that provider, the configured lookup header is compatibility, not an authentication control. Keep its configured file private, but do not claim that this secret protects introspection. Other providers such as Keycloak may require genuine lookup authentication. The verifier's introspection credentials are distinct from the
hosted OAuth client; keep their roles distinct and continue to check the returned
`client_id` against the approved `hosted_client`.

This audience profile does not establish the hosted client's complete OAuth
flow. Confirm registration, login, identity reads, refresh, revocation and restart
against the actual installation before rollout.

## Python synthetic reference

Use `uv sync --locked` and the tracked `config.oauth.example.toml`. No Nix or
particular identity provider is required for this reference implementation.
Use a fresh dedicated OAuth registration.

The Python probe and server remain strict-resource: introspection must report the
canonical `resource` itself as a string or singleton array, plus the configured
issuer and owner subject, active/unexpired claims and
`identity:read events:subscribe`. They do not implement Rust's `audience` option.
Direct Kanidm 1.11.2 therefore still fails this reference's exact-resource gate;
a compatible provider or reviewed broker (such as [Keycloak](oauth-keycloak.md))
is needed for that synthetic path. A local broker experiment passed this gate,
without establishing hosted compatibility.

The reference uses Basic introspection credentials configured by `client_id` and
`client_secret_file`. These identify the lookup caller, not the hosted OAuth
client. The reference does not enforce the Rust gateway's approved hosted-client
claim or durable local grant. Do not use it as a production authority boundary.
Introspection transport is separate from callback public-destination filtering:
LAN/tailnet provider endpoints are accepted by default, and optional
`provider_addresses` pin provider connections when configured.

## Hosted connection setup

Register callback URIs from the actual hosted connection UI. If a broker is used,
that callback belongs to the broker's downstream-client configuration; the
upstream provider instead registers the broker's fixed callback. The broker's
issuer and the private MCP resource may be different URLs. Match issuer strings
exactly, including canonical trailing slashes.

With Secure MCP Tunnel, the MCP server itself needs no public gateway URL. Use
Platform tunnel setup to obtain a tunnel associated with the intended ChatGPT
workspace, and keep its restricted runtime credential private. Point its client
at the private MCP endpoint. In Plugins select Connection: Tunnel, then OAuth.
The OAuth authorization server still needs browser reachability: the tunnel does
not automatically expose it. Consult the [current tunnel setup guide](https://developers.openai.com/api/docs/guides/secure-mcp-tunnels).
The step-by-step hosted dot run is in [hosted dots setup](hosted-dots-setup.md).

First prove discovery, login and the harmless identity read. Events challenge,
signed delivery, refresh, revocation and restart need their own hosted checks.
Testing writes requires a separately reviewed, explicitly authorized disposable
write target and read-back; the synthetic server has no write tool. Keep truthful
tool annotations. A successful local tool call does not pass the hosted gate.

The reference's unchanged `local-test` mode is loopback-only and intended for
isolated protocol/transport tests; its credentials have no expiry or scopes. Do
not point a tunnel at that mode. The separate throwaway synthetic example has an
explicit `--allow-bearer` / `--no-auth-ingress` arm for the hosted form's **No
Authentication** option. That loopback tunnel probe still authenticates internally
and has no xmsg behind it; see the [hosted probe commands](hosted-dots-setup.md#3-start-the-reference-server).
It is not the reference's `local-test` mode or a shipped authentication option.
The Rust gateway remains OAuth-only. The synthetic reference supports one callback
binding until an explicit owner reset; test client renewal within that constraint.

## Planned gateway-owned authorization

The [gateway AS](authorization-server.md) separates hosted credentials from upstream login. Provision a dedicated Kanidm login client with S256, `openid`, the exact gateway `/oauth/callback` URI and owner allowlisting. Its issuer, subject, client and audience must match `authorization_server.upstream.verify`. Hosted client authentication belongs to the gateway AS and remains mandatory even though Kanidm 1.11.2 ignores lookup Basic credentials.

Provision a read-only API-token service account in builtin `idm_people_pii_read`, plus a permanent visibility-canary person with planted `account_valid_from` and `account_expire` dates. This builtin reads PII across persons; it is broader than the gateway's configured owner/canary queries. Do not modify the owner's validity dates or add a custom ACP. Prove owner validity/membership and canary-date visibility with that reader, plus a hidden-reader control, before deployment. Membership must include the configured exact SPN, not merely a matching UUID. Liveness performs three owner attribute GETs and two canary date GETs; consent data and canary membership do not participate. See the [outcome rules and bounds](authorization-server.md#lifetimes-and-liveness).
