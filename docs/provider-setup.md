# Provider setup for the synthetic reference server

Use `uv sync --locked` and the tracked `config.oauth.example.toml`. No Nix,
particular identity provider, private design repository or infrastructure access
is required to use this reference implementation. Configuration and credentials
belong in ignored, owner-only files. Use a fresh dedicated OAuth registration.
Never paste access tokens, client secrets or tunnel credentials into chat or logs.

The canonical `resource` is the exact identifier returned by this gateway's
protected-resource metadata. It is not the tunnel ID or local listener address.
The provider's access-token introspection must report this exact audience, as a
string or singleton array, plus the configured issuer and owner subject, active
status, unexpired times and `identity:read events:subscribe`. Larger audience sets
are refused. The provider probe and server share this audience predicate.

Register callback URIs from the actual hosted connection UI. If a broker is used,
that callback belongs to the broker's downstream-client configuration; the
upstream provider instead registers the broker's fixed callback. The broker's
issuer and the private MCP resource may be different URLs. Match issuer strings
exactly, including canonical trailing slashes.

The current resource server uses Basic introspection credentials, configured by
`client_id` and `client_secret_file`. Those identify the lookup caller, not the
hosted OAuth client. The current serving profile does not yet enforce an approved
hosted-client claim or a durable local service grant. Those are phase-2 gates;
do not treat this synthetic feasibility server as a production authority boundary.
Introspection currently uses the same public-destination transport as callbacks:
LAN/tailnet-only provider endpoints are refused. An explicit provider allowlist
separate from the callback policy is planned, not implemented here.

A local Kanidm 1.11.2 experiment returned its OAuth client name as audience even
when an MCP resource was requested. Direct use did not pass the exact-resource
gate. A local broker experiment worked, but does not establish live hosted
compatibility or decide the production provider architecture. Use a compatible
provider or reviewed broker; do not relax audience validation or reuse an unrelated
application's credentials. This repository does not implement an authorization server.

With Secure MCP Tunnel, the MCP server itself needs no public gateway URL. Use
Platform tunnel setup to obtain a tunnel associated with the intended ChatGPT
workspace, and keep its restricted runtime credential private. Point its client
at the private MCP endpoint. In Plugins select Connection: Tunnel, then OAuth.
The OAuth authorization server still needs browser reachability: the tunnel does
not automatically expose it. Consult the [current tunnel setup guide](https://developers.openai.com/api/docs/guides/secure-mcp-tunnels).

First prove discovery, login and the harmless identity read. Events challenge,
signed delivery, refresh, revocation and restart need their own hosted checks.
Testing writes requires a separately reviewed, explicitly authorized disposable
write target and read-back; the synthetic server has no write tool. Keep truthful
tool annotations. A successful local tool call does not pass the hosted gate.

Local-test bearer credentials are only for isolated protocol/transport tests and
have no expiry or scopes. Do not point a tunnel at that mode. Only OAuth is the
intended hosted path. One callback binding is supported until an explicit owner
reset; test whether the actual client can operate within that constraint.
