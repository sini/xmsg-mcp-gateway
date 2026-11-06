# Rust identity listener

The Rust listener serves OAuth-protected MCP identity reads with durable local
grants. Its public resource metadata advertises the canonical resource and issuer
from the owner's configuration. `initialize`, `ping`, `tools/list`,
`notifications/initialized` and `xmsg_identity` are implemented. Standard `_meta`
progress tokens are accepted but unused. Messaging and Events return explicit
“not yet available” errors until their transport and custody units land.

The existing xmsg MCP entry point is a harness-associated stdio adapter behind its
daemon feature. Service-node I/O belongs to the shared `xmsg::client` boundary.
This unit implements HTTP and authorization and opens no xmsg socket. The identity
result describes the verified OAuth service profile and grant revision; it claims
no bus registration or node address.

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

The handler bounds the request body at 64 KiB and the entire request at the
configured deadline (1–60000 ms). After reading the body, each request obtains a
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
