You are building **phase 1** of the hosted-dot ↔ xmsg bridge, for an independent review before anything connects to the
real fleet.

## The design (read in full first)

https://gist.github.com/sini/44d011556104b7341d521839cffba8b6 (the revised draft of 2026-11-05). It is the spec. Where
this prompt and the gist disagree, this prompt wins for phase 1; tell me about the disagreement in the report.

## Scope: phase 1 only

The gist's "Implementation order", first step: prove the hosted integration with a **minimal authenticated MCP
server** that advertises **one synthetic event**. It does NOT touch xmsg.

Build:

1. **A Streamable HTTP MCP server** at `/mcp`, implementing exactly these from the gist's "Proposed MCP surface":
   - `xmsg_identity()`, which returns a fixed synthetic identity (`dot@phase1-synthetic`), the granted scopes, the
     limits and the subscription health;
   - the MCP Events methods `events/list`, `events/subscribe` and `events/unsubscribe`, advertising one event,
     `xmsg.message.received.v1`, with the gist's data shape.

   No `xmsg_send`, `xmsg_list` or `xmsg_reply` in phase 1. All schemas reject unknown fields.
2. **Authentication** (the gist's "Identity", credential role 1):
   - The connection credential maps server-side to one principal, and the sender always comes from authentication,
     never from arguments.
   - Prefer the OAuth connection path if the hosted platform supports it for this install. Otherwise use a
     high-entropy revocable bearer token, stored as a verifier (a hash), never in plaintext, never in logs.
3. **Event delivery** (the gist's "Inbound events and wakeup"):
   - Follow the official MCP Events contract: the callback URL and signing secret come from the subscription, there is
     signed challenge verification, HTTPS only, and no redirects.
   - Validate callback destinations against SSRF: refuse private, loopback, link-local and tailnet ranges, re-checking
     at connect time.
   - Sign deliveries with a Standard Webhooks implementation, not hand-rolled HMAC.
   - A CLI or admin trigger (local only, never exposed) emits ONE synthetic occurrence to the active subscription.
4. **The custody basics, at small scale:**
   - durable subscription state;
   - a persisted outbox, so the event survives a restart before the webhook is accepted;
   - bounded retry and backoff, keeping the same event id across retries;
   - a visible dead-letter state.
5. **Network exposure:**
   - Support the private Secure MCP Tunnel path (OpenAI's `tunnel-client` run beside the server) AND the
     public-HTTPS fallback.
   - The server binds to localhost by default. Never bind it to 0.0.0.0 unless the fallback is explicitly configured.

Out of scope, and do not build any of it:
- an xmsg adapter, `register.sock` or `agent.sock`, peer grants, real message custody;
- sending anywhere but the subscription callback;
- multi-tenant support.

## Hard rules

- **A fresh, isolated workspace.** Create a new repository directory, for example `~/src/dot-xmsg-bridge`. Don't put
  it inside any existing repo.
  - The component's name and whether the repo is public are the OWNER's decisions. Use a placeholder name, ask in the
    report, and do not push to any remote.
- **No fleet access.**
  - Don't run xmsg, and don't connect to `/run/user/*/xmsg`, any `xmsg` socket, or any federation port.
  - Don't read `~/.claude`, `~/.codex/config.toml` secrets, `~/.ssh`, agenix or age keys, `/run/agenix`, or any
    credential that isn't one you generate for this test.
  - If your harness exposes xmsg tools, don't use them.
- **No real secrets in the repo, logs, tests or report.** Generated test credentials live in a gitignored file, or
  are created per test run.
- **No deploy.**
  - Don't create tunnels or public endpoints yourself.
  - Don't enrol anything in Tailscale.
  - Don't change system config.
  - Where the end-to-end hosted check needs the owner (OAuth app registration, tunnel authorization, a public URL),
    write the exact owner steps in the report and stop there.
- Any `nix` command runs under `systemd-run --user --scope -q -p MemoryMax=12G`.

## Tests (each one must fail against a deliberately broken build)

For each check below, write a test, then make ONE single-site edit to production code that breaks it, and show the test
turning RED. Record the edit and the red output. Never use environment-variable or flag "mutant" switches in
production code.

1. Unauthenticated, wrong-token and revoked-token requests are refused, for both tools and events methods. A valid
   token is accepted (the positive control).
2. An argument trying to set the sender (`from`, `origin`, `as_agent`, or a mailbox id) is rejected as an unknown
   field.
3. Callback SSRF: private, loopback, link-local, tailnet (100.64.0.0/10), and a DNS name resolving to a private
   address are all refused; a public test endpoint is allowed.
4. A redirecting callback is refused.
5. Signatures: the delivery's signature verifies with the subscription secret and fails with any other secret; a
   tampered body fails.
6. Custody: a crash after the outbox commit and before the webhook leads to delivery on restart with the SAME event
   id; a duplicate retry creates no second outbox entry.
7. The server binds to localhost by default.

## Deliverable

1. The repo, committed locally, with a README covering setup, configuration and the owner steps.
   - The README carries NO internal tracker ids, hostnames, IP addresses or room ids.
2. A report at `REPORT.md` in the repo root, containing:
   - what you built, mapped to the gist's sections;
   - each test with its mutant and its red output;
   - every place you measured versus inferred (cite the MCP Events and Secure MCP Tunnel docs you relied on, with
     URLs);
   - the owner steps still needed for the hosted end-to-end check (the gist's acceptance gate 1);
   - open questions, including the component name, public vs private, and the OAuth vs bearer choice;
   - anything in the gist you believe is wrong or underspecified.
3. Don't push. Tell me when it's done; an independent reviewer gates it before phase 2.
