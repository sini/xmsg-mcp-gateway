# Verified-token foundation

The Rust library now separates owner enrollment (`grants::Binding`) from runtime
identity (`auth::VerifiedIdentity`). Only `Verifier::verify(token).await` constructs the
latter, after contacting the provider configured by the owner. Grant authorization
accepts this type; deserializing enrollment or request JSON cannot authorize.
There is no test constructor, injectable provider object, or enabling Cargo feature.

`VerifierConfig` rejects unknown fields. It requires a service, HTTPS issuer and
resource, expected subject, approved hosted client, HTTPS introspection endpoint,
separate introspection client, owner-private secret file, explicit provider IP
addresses, required scopes and a bounded timeout. An optional PEM root certificate
supports private PKI. Provider addresses pin the configured endpoint's connections;
this is a separate policy from the future callback public-address filter. The
asynchronous client disables proxies and redirects, verifies TLS, and bounds response bodies
at 64 KiB. Neither credentials nor provider response bodies appear in errors.

The provider must report an active token, exact issuer and resource audience
(string or singleton array), expected subject and hosted client, unexpired `exp`,
satisfied `nbf`, and all configured scopes. The introspection caller is never
substituted for the hosted client. Invalid claims return `InvalidToken`; transport,
non-200 and malformed provider responses return `Unavailable`. HTTP status mapping
belongs to the serving handler, which is not implemented by this unit.

Tests use a generated, disposable TLS provider selected through this same config.
They record the submitted token and distinct lookup credentials. Existing grant
and CLI tests obtain identities through this endpoint, rather than constructing
them. Five stable Rust 1.95 trybuild snapshots reject deserialization, conversion
from Binding, Default, struct literals and Binding authorization. Each has an
independent source mutant that must make its rejecting test fail because the
forbidden program compiled; an unrelated diagnostic is not a kill.

## Pending acceptance

This foundation does not complete R1 or enable a hosted gateway. The R1 runtime
spoof cells (identity fields in arguments and `_meta`, `verified`, an
introspection-shaped body, and non-approved-client tokens) and the R1
`handler identity boundary: mint identity from request metadata` mutant ship with
the real serving handler. No substitute handler is introduced just for tests.
Current-token/current-grant revalidation before every dispatch, 401/403/503 mapping,
provider redirect target-connection oracles (R3), live provider compatibility, and
the owner's provider/broker choice remain pending in their respective units.

## Unit validation

On stable Rust 1.95, the local run executes 23 tests with zero ignored or filtered,
passes Clippy, and kills 16 identity source mutants (five type arms, eight claim
checks, provider HTTPS/allowlist guards and response size). The 13 existing grant
mutants also remain killed after the migration. CI repeats the test count guard on
Linux and macOS and both mutation suites on Linux. A completed Actions run and an
independent landing gate are required before this unit reaches main.

```sh
cargo test --locked -j 4
cargo clippy --locked --all-targets -j 4 -- -D warnings
python3 scripts/grant_mutants.py
python3 scripts/identity_mutants.py
```
