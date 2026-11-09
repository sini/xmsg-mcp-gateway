# Throwaway Step 0 spike

This example reuses the existing Python feasibility server. It has no xmsg
connection and emits only synthetic `xmsg.message.received.v1` events. The final
runtime is Rust; this example does not implement the production Events path.

Run from the repository root after `uv sync --locked`:

```sh
uv run --locked python examples/step0_spike.py --config config.oauth.example.toml serve
```

The default authentication mode is OAuth, using the existing owner-provisioned
introspection configuration. OAuth authorization-server reachability and client
registration belong to the hosted setup.

To probe a static bearer path, create a separate configuration with
`auth_mode = "bearer"` and its own `state_dir`. Explicit `--allow-bearer` is also
required for every invocation. Use `issue-bearer --output <private-file>` to
write a temporary credential, then `serve`; no credential is printed or passed
on the command line. Existing `phase1` `local-test` restrictions remain intact.
The bearer branch reuses the existing digest verifier; its internal credential
row keeps the existing `local-test` label.

```sh
uv run --locked python examples/step0_spike.py --config <bearer-config> --allow-bearer issue-bearer --output <private-file>
uv run --locked python examples/step0_spike.py --config <bearer-config> --allow-bearer serve
```

Both modes advertise `xmsg_identity` and one synthetic event. After subscription,
use the same configuration to run `emit <unique-occurrence-id>`; retries of the
same occurrence reuse the event ID. The serving worker sends the signed event
to the verified callback.

The observed hosted ChatGPT form offers **OAuth** or **No Authentication**, not bearer/API-key entry.
For the tunnel's No Authentication arm, keep bearer mode on `127.0.0.1` and start:

```sh
uv run --locked python examples/step0_spike.py --config <bearer-config> --allow-bearer serve --no-auth-ingress <private-file>
```

The example injects that issued bearer only when the request has no Authorization header; phase1 still
authenticates it. An explicitly wrong bearer is not replaced. Credential-less `tools/list` advertises
`noauth`, which the No Authentication connection requires. This is example-only tunnel ingress, never a
shipped product surface or a public reverse-proxy authentication mechanism.

The ingress writes owner-only `step0-diagnostics.jsonl` under its `state_dir`. Read its content-free
field shapes and failure steps alongside `phase1 status`; never turn on raw request logging. Callback
scheme/host may identify a valid request's destination, but no full URL, secret or cursor is recorded;
malformed subscriptions are recorded by shape only. If uv's Python/OpenSSL cannot find the host's trusted
CA bundle, set `SSL_CERT_FILE` to that bundle before serving; do not disable certificate verification.

See the public [hosted setup runbook](../docs/hosted-dots-setup.md) for commands, observations and the
harmless `server/discover` 400 / `harpoon` log findings. Keep the callback's HTTPS/public-address checks
intact. Local tests inject a fixture-only transport to a loopback callback; the example never does.
