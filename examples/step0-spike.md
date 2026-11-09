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

The inherited tool metadata declares OAuth2 even in bearer mode. This probe
proves bearer HTTP authentication locally, not compatibility with any hosted
API-key installation flow. Only the owner's actual hosted test can establish
whether that flow accepts the credential and discovers/subscribes successfully.
Keep the callback's HTTPS/public-address checks intact. Local tests inject a
fixture-only transport to a loopback callback; the example never does.
