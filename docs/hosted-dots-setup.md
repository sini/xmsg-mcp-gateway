# Connecting a hosted ChatGPT dot: feasibility runbook

This runbook connects a hosted ChatGPT dot to the synthetic reference server, through OpenAI's Secure MCP
Tunnel. It proves four things before any production work depends on them:

1. the dot connects and authenticates;
2. it lists and subscribes to an MCP event;
3. a signed event delivered to its callback wakes the idle conversation;
4. which authentication the installation actually offers.

The server behind it is synthetic: it has no xmsg node behind it and no write tools. The production Events
path is the Rust gateway, and it is built only after this run passes.

Read [provider setup](provider-setup.md) first. It states the audience, issuer and introspection rules this
runbook relies on. Upstream references: [Secure MCP Tunnel](https://developers.openai.com/api/docs/guides/secure-mcp-tunnels),
[MCP Events](https://developers.openai.com/plugins/build/mcp-events),
[plugin authentication](https://developers.openai.com/plugins/build/plugins).

Never paste the runtime key, an access token, a client secret, a webhook secret or a callback URL into chat,
an issue or a log you share. Record references to them instead (a file path or a secret name).

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

### Bearer arm: explicit opt-in

Create `.state/step0-bearer.toml` with this nonsecret configuration:

```toml
auth_mode = "bearer"
state_dir = ".state/step0-bearer"
bind = "127.0.0.1"
port = 8765
```

Issue a temporary credential into an owner-only file, then start the server:

```sh
uv run --locked python examples/step0_spike.py --config .state/step0-bearer.toml \
  --allow-bearer issue-bearer --output .state/step0-bearer-token
uv run --locked python examples/step0_spike.py --config .state/step0-bearer.toml \
  --allow-bearer serve
```

Issuance refuses an existing output file. The token is never printed; the server stores its digest.
Enter the file's contents only in the supported secure connection form in step 5. Configuring bearer mode
without `--allow-bearer` refuses startup. This changes no reference-server default or local-test constraint.
The inherited tool metadata declares OAuth2 even in bearer mode: this arm tests bearer HTTP auth, while
the hosted run must establish whether the installation actually accepts and uses it.

After check 3 succeeds, leave the intended conversation idle. In a second terminal, trigger check 4:

```sh
uv run --locked python examples/step0_spike.py --config .state/step0-bearer.toml \
  --allow-bearer emit hosted-bearer-one
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

Both arms advertise `xmsg_identity` and `xmsg.message.received.v1`. The subscriber supplies the HTTPS callback
and its distinct signing secret. The server verifies the signed callback challenge before delivery. Emitting the same
occurrence ID deduplicates it; use a new ID for another trial. Callback validation remains HTTPS/public-only
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
3. **Authentication.** Record every option the form offers; this list is one of the run's results.
   - **Bearer / API key, if offered:** start the example in bearer mode (section 3) and enter its token in
     the form. This path needs no authorization server.
   - **OAuth:** the authorization server is *not* carried by the tunnel. The browser must reach it publicly,
     and it must meet the exact-audience rule in [provider setup](provider-setup.md). If no such issuer is
     available yet, stop at this step and record "OAuth only, no issuer". That is a valid result.
4. Accept the risk warning and select **Create as a plugin**. Record the plugin's connection ID
   (`plugin_asdk_app…`).

## 6. What to observe

For each check, record pass or fail, the time, and content-free status from the matching state directory
(section 3). `xmsg_identity` also returns subscription health. Do not enable raw request logging to collect
callback URLs or credentials.

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

Use this only if section 6 fails through the tunnel. Put the example behind a TLS reverse proxy at a public
hostname (`exposure = "public-https"`, `public_url = "https://<host>/mcp"`; see
`config.oauth.example.toml`), retaining the loopback listener. The public hostname must match the config's
resource or public URL for Host validation. Use OAuth, or the example-only bearer arm with explicit
`--allow-bearer` if the installation offers supported secure entry. Add the server in ChatGPT with its URL
instead of a tunnel, and repeat section 6. Remove the public exposure when the run ends.

## 8. Tear down

1. Unsubscribe in the dot, then delete the plugin.
2. Stop `tunnel-client` and the example, and delete `.state/` from the test checkout.
3. Revoke the runtime key, and delete the tunnel if it won't be reused.

## 9. Report

Report these results, with no secrets: which authentication options the form offered and which one worked;
the pass/fail table from section 6, with times; whether the tunnel or the fallback carried it; the
`tunnel-client` version; and any error text that ChatGPT or the server showed.
