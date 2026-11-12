# Verified-token foundation

The Rust library now separates owner enrollment (`grants::Binding`) from runtime
identity (`auth::VerifiedIdentity`). Only `Verifier::verify(token).await` constructs the
latter, after contacting the provider configured by the owner. Grant authorization
accepts this type; deserializing enrollment or request JSON cannot authorize.
There is no test constructor, injectable provider object, or enabling Cargo feature.

`VerifierConfig` rejects unknown fields. It requires a service, HTTPS issuer and
resource, expected subject, approved hosted client, HTTPS introspection endpoint,
separate introspection client, owner-private secret file, required scopes and a
bounded timeout. Optional `provider_addresses` pin the configured endpoint's
connections directly (disabling proxies) independently of the callback public-address
filter; when omitted or empty, standard DNS resolution and `HTTPS_PROXY`/`NO_PROXY`
environment settings apply. An optional PEM root certificate supports private PKI.
The asynchronous client disables redirects, verifies TLS, and bounds response bodies
at 64 KiB. Neither credentials nor provider response bodies appear in errors.

The provider must report an active token, exact issuer and configured audience
(string or singleton array), expected subject and hosted client, unexpired `exp`,
satisfied `nbf`, and all configured scopes. Optional `audience` defaults to the
canonical resource URL; an override must be nonempty and contain no whitespace.
Additional audiences are refused. `client_id` must still equal `hosted_client`,
and resource metadata, verified identity and grants retain the canonical resource
URL. A different audience requires a dedicated one-to-one OAuth client whose
origin is the resource origin, never a registration shared with another resource
or application; see [provider setup](provider-setup.md).
The introspection caller is never
substituted for the hosted client. Invalid claims return `InvalidToken`; transport,
non-200 and malformed provider responses return `Unavailable`. HTTP status mapping
belongs to the [identity listener](serving.md).

Tests use a generated, disposable TLS provider selected through this same config.
They record the submitted token and distinct lookup credentials. Existing grant
and CLI tests obtain identities through this endpoint, rather than constructing
them. Five stable Rust 1.95 trybuild snapshots reject deserialization, conversion
from Binding, Default, struct literals and Binding authorization. Each has an
independent source mutant that must make its rejecting test fail because the
forbidden program compiled; an unrelated diagnostic is not a kill.

## Pending acceptance

This foundation does not complete R1 or enable a hosted gateway. The [identity listener](serving.md) implements the R1 runtime
spoof cells (identity fields in arguments and `_meta`, `verified`, an
introspection-shaped body, and non-approved-client tokens) through the real serving handler. A sixth compile-fail handler-mint arm and runtime
fail-open, reuse, precedence and order mutants replace the unrepresentable
crate-visible-constructor mutant. The real module boundary stays private.
The listener adds current-token/current-grant revalidation for identity reads and 401/403/503 mapping;
out-of-allowlist/IP redirect variants (R3), live provider compatibility, and
the owner's provider/broker choice remain pending in their respective units.

The serving unit must load verifier settings only from the owner configuration file, never request arguments or metadata (A5).

## Unit validation

On stable Rust 1.95, the local run executes 25 tests with zero ignored or filtered,
passes Clippy, and kills 19 identity source mutants (five type arms, eight claim
checks, provider HTTPS/allowlist/IP-literal guards, redirect refusal, timeout and response size). The 13 existing grant
mutants also remain killed after the migration. CI repeats the test count guard on
Linux and macOS and both mutation suites on Linux. A completed Actions run and an
independent landing gate are required before this unit reaches main.

```sh
cargo test --locked -j 4
cargo clippy --locked --all-targets -j 4 -- -D warnings
python3 scripts/grant_mutants.py
python3 scripts/identity_mutants.py
```

Compile-driven trybuild mutation cases have a bounded 120-second execution budget for their nested cold Cargo build; ordinary runtime cases retain 30 seconds. Baseline timing is logged. A timeout or compilation failure still fails the driver and never counts as a kill. CI runs both operating systems with matrix fail-fast disabled.

## Planned local identity and admission

The [gateway AS](authorization-server.md) adds a private optional `token_family` with an accessor on `VerifiedIdentity`; local identities remain constructed only inside `auth.rs`. `LocalProfile::local_identity` accepts a verified upstream login only for the configured owner subject, returning the local binding for callback authorization without a family. `LocalProfile::verify_family` validates family lifetime/revocation and returns the local identity with its delivery bound; it does not depend on a live upstream login session.

Local access admission returns its identity and grant authorization from one validated transaction. The outbound policy is captured alongside that context in memory: later policy edits do not change an admitted send, and no durable policy snapshot is added. Normal local sends, broker calls and stored reply receipt/reservation recovery keep the captured context through bounded completion. Custody read/ACK and reply-target ownership lookup with its pre-effect recheck keep the effect-point grant/revision fence. Disable before target lookup refuses a new reply with no reservation or effect, and Events subscribe/renew freshly verifies before creating durable wake authority. Remote verification still introspects once at entry and checks captured expiry/current grant at effects. These distinctions do not expose an identity constructor to handlers or request metadata.

Kanidm 1.11.2 was measured to return the same active introspection result with a wrong lookup Basic secret. Its configured header is compatibility rather than proof of caller authentication. Exact introspected issuer, subject, audience, hosted client, scope and lifetime checks still apply. Keycloak's own lookup authentication and the gateway AS's mandatory downstream `client_secret_basic` remain real controls.
