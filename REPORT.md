# Phase 1 local build report

Date: 2026-11-05. Placeholder component name; local repository only, no remote.

Status: local implementation and mutation evidence ready for independent review.
The hosted feasibility gate is NOT passed. No OAuth client registration, tunnel,
public endpoint, infrastructure change, xmsg operation, socket or fleet connection
was made. No credentials from the existing environment were read. No Nix commands
were needed. The original design repository was not edited.

## What was built

| Design section | Implementation |
| --- | --- |
| Proposed MCP surface | Stateless initialized Streamable HTTP JSON at `/mcp`, `xmsg_identity`, and the three Events methods. Exactly one synthetic event. Strict tool/filter/transport request models reject unknown fields. |
| Identity, role 1 | OAuth resource server with HTTPS RFC 7662 introspection, exact issuer/resource audience/subject, active/expiry/not-before/scopes checks. Single fixed synthetic principal. A separate loopback-only fixture mode issues revocable 384-bit random tokens, stores SHA-256 verifiers, and writes credentials directly to private files. |
| Inbound events and wakeup | Deterministic subscription ID; signed fresh challenge; constant-time echo comparison; bounded verification cache; HTTPS-only, public-IP-pinned transport; no redirects; Standard Webhooks library signing; local CLI emits one occurrence. |
| Replay and lifecycle | Durable singleton callback binding, finite lifetime, owner-only binding reset, unsubscribe, five-minute dual-key rotation retained across restart. Refresh lifetime cannot exceed the OAuth access token lifetime. Pending outbox recovery survives restart; protocol cursor replay is explicitly unsupported. |
| Durable custody | SQLite FULL synchronous commits, unique occurrence key, immutable event ID/body, durably reserved attempts, bounded backoff, visible accepted/pending/dead states and manual dead-letter rearm. |
| Network and exposure | Loopback by default; non-loopback requires explicit public-HTTPS fallback plus OAuth; private Tunnel owner runbook and public reverse-proxy fallback. No tunnel was launched. |
| Security and failure handling | Private state files, Fernet encryption for callback secrets and retained OAuth tokens, categorized errors, no access logs or credential output, one subscription, 64-KiB inbound/response bounds and 1,000 retained occurrence quota. Public-DNS filtering also applies to introspection callouts. |

Files: `phase1/app.py` handles MCP, `schemas.py` request schemas, `auth.py` OAuth
introspection, `transport.py` DNS/TLS/signing, `store.py` durable state,
`events.py` subscription lifecycle, `worker.py` serialized dispatch, and `cli.py`
local administration. README covers configuration and exact owner checkpoints.

## Verification and mutation method

Commands from this repository:

```sh
uv sync --locked --link-mode copy
uv run pytest -q --tb=short
uv run ruff check phase1 tests scripts
uv run ruff format --check phase1 tests scripts
uv run python scripts/mutations.py
```

The final run is recorded in `evidence/final-tests.txt`, `final-lint.txt`,
`final-format.txt` and `final-mutations.txt`. There are 53 passing pytest cases.
The initial missing-component run failed collection; it is not counted as a
security oracle. Later targeted tests found and corrected callback-cache,
crash-attempt accounting, OAuth subscription-expiry, Host/Origin validation,
and slow TLS-response deadline defects before the final run.

Each required mutation changes ONE production site in a disposable source copy.
The script first runs that exact test against unchanged code (GREEN), applies one
literal replacement, and requires pytest exit 1 with that test named as FAILED
(RED). It records the exact unified patch and both outputs. It does not use any
production mutant flag or environment switch. Original source remains unchanged.
Generated signing keys and credentials are per-test ephemeral values, not live
secrets; failure output avoids displaying generated credential arguments.

| Check | Test | Single-site edit | Observed RED |
| --- | --- | --- | --- |
| 1. Auth missing/wrong/revoked and valid control | `test_auth` (five method cases) | Replace the unauthenticated-request guard with `if False` | Five failures: unauthenticated responses are 200 instead of 401. |
| 2. Sender override fields | `test_unknown_sender` (five fields, identity and subscription paths) | Base strict request model changes extra-fields policy from forbid to ignore | Five failures: error response disappears for forbidden sender fields. |
| 3. Callback SSRF | `test_ssrf` (15 address cases; literal and DNS names) | Remove the public-address predicate while retaining empty-DNS rejection | Fifteen failures: forbidden DNS resolution no longer raises DestinationError. |
| 4. Redirect | `test_redirect` | Verification accepts status 302 by changing its status guard to reject only status >=400 | Failure: redirecting verification is accepted. |
| 5. Signatures | `test_signatures` | Sign the literal string `tampered` instead of exact serialized bytes | WebhookVerificationError: no matching signature. |
| 6. Custody | `test_custody` | Insert a new outbox row as accepted instead of pending | Failure after abrupt process exit: committed event is not pending delivery. |
| 7. Default bind | `test_default_bind` | Default bind changes from loopback to wildcard | ValidationError: non-loopback requires explicit fallback; default construction fails. |

Exact patches and full RED output for all seven checks are appended below. Their
GREEN controls are in the corresponding `evidence/*-green.txt` files.

## Measured versus inferred

**Measured locally:** authorization denials and valid controls through the HTTP
application; unknown sender rejection; initialized tool/event catalogs; signed
challenge echo and failure; verification-cache expiry; idempotent subscription
identity, unsubscribe and callback conflict; encrypted state; rotation across
Store reopen; OAuth claim rejection and upstream revocation; no dispatch after
revocation/expiry; 410/413/redirect terminal states and retry exhaustion; quota
constants and request-size enforcement; and a real launched CLI server listening
only on loopback with no credential in its output.

The custody test starts a separate process, commits an occurrence and exits via
`os._exit(73)` before callback dispatch. A new Store sees the same pending event,
re-emitting the occurrence does not add an entry, a failed callback retries with
the same bytes/ID, and a later acceptance updates the same row. An additional test
interrupts execution after durable attempt reservation. This measures process
restart, not power loss, disk-controller behavior or an accepted-response crash.
SQLite's documented commit durability is relied upon for the latter storage layer.

The TLS fixture uses an ephemeral self-signed test certificate and a local TLS
server. Test-only DNS answers present a public address, and a test-only dial map
routes that checked address to the fixture. The production connection code checks
TLS hostname/SNI, rejects a wrong certificate name, does not follow a real redirect,
and interrupts a slow response. No external callback was contacted. Private,
loopback, link-local, carrier-grade NAT/tailnet, mapped IPv6, transition and mixed
DNS results are exercised with controlled DNS answers. Public-address allowance
is a controlled positive result, NOT an observed successful internet webhook.

OAuth tests use a generated-token introspection fixture. They measure resource
server behavior, NOT ChatGPT login, PKCE exchange, provider discovery, secure
credential entry, actual Kanidm revocation latency or hosted refresh scheduling.
The server implements no authorization/token endpoint or OAuth broker.

**Documented, not measured in the actual installation:**

- [Official MCP Events](https://developers.openai.com/plugins/build/mcp-events):
  initialized Streamable HTTP event discovery, subscription-supplied callback and
  secret, signed challenge and Standard Webhooks, limits, refresh and unsubscribe.
  The implementation follows this contract; local webhook acceptance does not
  establish hosted dot wakeup.
- [Secure MCP Tunnel](https://developers.openai.com/api/docs/guides/secure-mcp-tunnels):
  private MCP request transport and separate workspace/organization permissions;
  the authorization server is not automatically exposed. The owner saw Tunnel
  and OAuth in the custom-server form. No tunnel operation or hosted request was
  observed by this build.
- [Tunnel client onboarding](https://github.com/openai/tunnel-client/blob/master/docs/onboarding.md):
  environment-based HTTP binding, Authorization forwarding and metadata rewriting.
  The selected release, actual metadata resource URI, and Events interoperability
  must be checked during owner setup.
- [OpenAI OAuth requirements](https://developers.openai.com/plugins/build/auth):
  protected-resource metadata, PKCE, provider discovery/client setup, resource-bound
  audience and per-request token validation. The server provides the protected
  resource side; a compatible authorization provider remains owner infrastructure.
- [Kanidm OAuth documentation](https://kanidm.github.io/kanidm/stable/integrations/oauth2.html):
  discovery, S256, introspection and separate per-application client registrations.
  These foundations do not by themselves prove MCP resource-indicator support.

**Measured public-source compatibility concern:** at upstream Kanidm revision
`8b5382f2037bcaf2bf84cb67e7e6353d73de173a`, the
[introspection implementations](https://github.com/kanidm/kanidm/blob/8b5382f2037bcaf2bf84cb67e7e6353d73de173a/server/lib/src/idm/oauth2.rs#L2926)
return `aud: Some(client_id)`; the
[token definition](https://github.com/kanidm/kanidm/blob/8b5382f2037bcaf2bf84cb67e7e6353d73de173a/proto/src/oauth2.rs#L216)
also documents client-ID audience. Therefore direct use of a conventional Kanidm
client is not established for this resource-bound MCP flow. This is a source
finding, not a test of the deployed version. The relevant declarative OAuth client
provisioning exists in nix-config; it was inspected read-only without opening
secrets or contacting the deployment. No conclusion about deployed reachability
or provider version follows from those declarations.

## Owner actions remaining: hosted acceptance gate 1

1. Resolve the authorization-provider mismatch before live registration. Verify
   whether the intended Kanidm version/configuration can issue the exact MCP
   resource audience and accept ChatGPT's supported predefined-client flow with
   S256. If it cannot, decide between provider support work and a separately
   reviewed OAuth authorization layer using Kanidm login. Neither was built here.
   Never relax audience validation to accept tokens minted for unrelated clients.
2. Choose the placeholder's final component name and repository visibility. Select
   the test resource URI and dedicated owner subject/scopes. Provision only fresh
   test credentials into private files; keep the tunnel runtime credential separate.
3. Follow README's private-tunnel steps: authorized tunnel, correct association and
   permissions, reviewed/pinned client release, healthy HTTP binding and mandatory
   OAuth. Confirm that the resource URI visible through tunnel metadata is the
   exact value the provider issues and this server checks. Browser and hosted
   token endpoints need appropriate reachability; no connectivity change is
   authorized by this report.
4. Connect/install the plugin and rescan. Observe initialized `events` capability,
   exactly `xmsg_identity` and `xmsg.message.received.v1`, and a successful OAuth
   identity call. Record metadata and outcomes without tokens or callback URLs.
5. Have dot subscribe with an explicit instruction to report the synthetic preview
   once. Observe successful signed challenge, subscription persistence and expiry.
6. Emit one local occurrence. Independently observe callback receipt and dot's
   response in the correct idle conversation. Restart before a pending dispatch
   and check that the original ID survives. Check duplicate retry behavior at the
   hosted consumer; this server promises stable IDs, not exactly-once agent work.
7. Exercise hosted refresh (including key rotation), unsubscribe and revocation.
   If the combined tunnel path is unsupported, use the explicitly authorized
   public-HTTPS fallback described in README and repeat these same checks.
8. Send this local commit and REPORT to the independent reviewer. Phase 2 remains
   gated; do not attach an xmsg adapter or real fleet credentials.

## Design differences, open questions and limits

- The phase-1 dispatch outranks the gist: no `xmsg_list`, send/reply/read tools,
  xmsg adapter, peer ACLs, bus custody or fleet access. Gist acceptance gate 1's
  `xmsg_list` call is intentionally excluded; the applicable hosted gate is
  identity plus discovery/subscription/challenge/wakeup. Durable outbox/subscription
  behavior moved into phase 1 at the dispatch's explicit request.
- The gist says component naming/shape sign-off precedes implementation; the
  dispatch explicitly authorizes a placeholder isolated repo and asks naming and
  visibility to remain open in the report. This build follows that scoped override.
- Owner confirmed Tunnel and OAuth options in the actual form. Mandatory OAuth is
  selected for hosted use. Fixed bearer entry was not available there; the local
  hashed-token mode is only a fixture, not a claimed hosted fallback. Provider
  compatibility/registration remains open.
- The illustrated gist occurrence says `body_available: true`; this synthetic
  server has no body-read tool, so it truthfully sends false. Mailbox/origin are
  synthetic constants and no actual peer identity or message is implied.
- The gist discusses replay cursors but does not require that optional feature in
  the phase-1 dispatch. This server advertises no protocol replay (`cursor: null`).
  Restart retries and an explicitly reset binding still drain retained pending
  outbox work; accepted events are not automatically replayed to another binding.
- Signing secrets require recoverable encryption for webhook delivery; retained
  OAuth tokens need it for online introspection. The local state key is separate
  from the database but on the same account. This is not hardware-backed custody.
- Subscription health reports binding state and queue counts, not proof of the
  subscriber's current authorization. The worker rechecks authorization before
  dispatch; it pauses without sending when token activity cannot be established.
  OAuth expiry bounds the granted subscription lifetime to prompt refresh.
- Delivery retries regenerate signing metadata. If two attempts occur in the same
  Unix second the valid Standard Webhooks timestamp/signature can be identical;
  this does not change event identity or imply a new occurrence.
- Retention is a hard 1,000-row cap, without automatic deletion. The small-scale
  dispatch leaves retention/quota defaults unspecified; these conservative defaults
  refuse additional custody instead of dropping accepted work.
- Five attempts include durably reserved attempts interrupted by a crash. Upstream
  revocation stops new dispatch after introspection observes it; already initiated
  traffic cannot be recalled. No exactly-once callback or task guarantee is made.
- Threaded DNS slots and socket/watchdog deadlines bound normal failures. This is
  a single-host Linux fixture, not a hardened multi-tenant internet service. No
  load benchmark, power-loss test, real authorization-code exchange or hosted
  acceptance test was performed.
- README contains no actual internal tracker identifiers, hostnames, IP addresses,
  room IDs or live URLs. Test address literals are synthetic protocol fixtures.

## Exact mutation patches and RED outputs

### 01-auth

```diff
--- a/phase1/app.py
+++ b/phase1/app.py
@@ -187,7 +187,7 @@
         credential = (
             await run_in_threadpool(store.authenticate, token, oauth) if token else None
         )
-        if not credential:
+        if False:
             challenge = "Bearer"
             if settings.resource:
                 challenge += (
```

```text
FFFFF                                                                    [100%]
=================================== FAILURES ===================================
____________________________ test_auth[tools/list] _____________________________
tests/test_phase1.py:104: in test_auth
    assert missing.status_code == 401
E   assert 200 == 401
E    +  where 200 = <Response [200 OK]>.status_code
____________________________ test_auth[tools/call] _____________________________
tests/test_phase1.py:104: in test_auth
    assert missing.status_code == 401
E   assert 200 == 401
E    +  where 200 = <Response [200 OK]>.status_code
____________________________ test_auth[events/list] ____________________________
tests/test_phase1.py:104: in test_auth
    assert missing.status_code == 401
E   assert 200 == 401
E    +  where 200 = <Response [200 OK]>.status_code
_________________________ test_auth[events/subscribe] __________________________
tests/test_phase1.py:104: in test_auth
    assert missing.status_code == 401
E   assert 200 == 401
E    +  where 200 = <Response [200 OK]>.status_code
________________________ test_auth[events/unsubscribe] _________________________
tests/test_phase1.py:104: in test_auth
    assert missing.status_code == 401
E   assert 200 == 401
E    +  where 200 = <Response [200 OK]>.status_code
=========================== short test summary info ============================
FAILED tests/test_phase1.py::test_auth[tools/list] - assert 200 == 401
FAILED tests/test_phase1.py::test_auth[tools/call] - assert 200 == 401
FAILED tests/test_phase1.py::test_auth[events/list] - assert 200 == 401
FAILED tests/test_phase1.py::test_auth[events/subscribe] - assert 200 == 401
FAILED tests/test_phase1.py::test_auth[events/unsubscribe] - assert 200 == 401
5 failed in 0.21s
```

### 02-unknown-fields

```diff
--- a/phase1/schemas.py
+++ b/phase1/schemas.py
@@ -6,7 +6,7 @@
 
 
 class Strict(BaseModel):
-    model_config = ConfigDict(extra="forbid", strict=True)
+    model_config = ConfigDict(extra="ignore", strict=True)
 
 
 class Empty(Strict):
```

```text
FFFFF                                                                    [100%]
=================================== FAILURES ===================================
__________________________ test_unknown_sender[from] ___________________________
tests/test_phase1.py:124: in test_unknown_sender
    assert response.json()["error"]["code"] == -32602
           ^^^^^^^^^^^^^^^^^^^^^^^^
E   KeyError: 'error'
_________________________ test_unknown_sender[origin] __________________________
tests/test_phase1.py:124: in test_unknown_sender
    assert response.json()["error"]["code"] == -32602
           ^^^^^^^^^^^^^^^^^^^^^^^^
E   KeyError: 'error'
________________________ test_unknown_sender[as_agent] _________________________
tests/test_phase1.py:124: in test_unknown_sender
    assert response.json()["error"]["code"] == -32602
           ^^^^^^^^^^^^^^^^^^^^^^^^
E   KeyError: 'error'
_________________________ test_unknown_sender[mailbox] _________________________
tests/test_phase1.py:124: in test_unknown_sender
    assert response.json()["error"]["code"] == -32602
           ^^^^^^^^^^^^^^^^^^^^^^^^
E   KeyError: 'error'
_______________________ test_unknown_sender[mailbox_id] ________________________
tests/test_phase1.py:124: in test_unknown_sender
    assert response.json()["error"]["code"] == -32602
           ^^^^^^^^^^^^^^^^^^^^^^^^
E   KeyError: 'error'
=========================== short test summary info ============================
FAILED tests/test_phase1.py::test_unknown_sender[from] - KeyError: 'error'
FAILED tests/test_phase1.py::test_unknown_sender[origin] - KeyError: 'error'
FAILED tests/test_phase1.py::test_unknown_sender[as_agent] - KeyError: 'error'
FAILED tests/test_phase1.py::test_unknown_sender[mailbox] - KeyError: 'error'
FAILED tests/test_phase1.py::test_unknown_sender[mailbox_id] - KeyError: 'error'
5 failed in 0.21s
```

### 03-ssrf

```diff
--- a/phase1/transport.py
+++ b/phase1/transport.py
@@ -70,7 +70,7 @@
         port = parsed.port or 443
         answers = bounded_dns(parsed.hostname, port)
         addresses = list(dict.fromkeys(answer[4][0] for answer in answers))
-        if not addresses or not all(public_address(address) for address in addresses):
+        if not addresses:
             raise DestinationError("non_public_destination")
         return parsed, addresses
     except (ValueError, OSError) as exc:
```

```text
FFFFFFFFFFFFFFF                                                          [100%]
=================================== FAILURES ===================================
_____________________________ test_ssrf[127.0.0.1] _____________________________
tests/test_phase1.py:172: in test_ssrf
    with pytest.raises(transport.DestinationError):
         ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
E   Failed: DID NOT RAISE DestinationError
_____________________________ test_ssrf[10.0.0.1] ______________________________
tests/test_phase1.py:172: in test_ssrf
    with pytest.raises(transport.DestinationError):
         ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
E   Failed: DID NOT RAISE DestinationError
____________________________ test_ssrf[172.16.0.1] _____________________________
tests/test_phase1.py:172: in test_ssrf
    with pytest.raises(transport.DestinationError):
         ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
E   Failed: DID NOT RAISE DestinationError
____________________________ test_ssrf[192.168.0.1] ____________________________
tests/test_phase1.py:172: in test_ssrf
    with pytest.raises(transport.DestinationError):
         ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
E   Failed: DID NOT RAISE DestinationError
__________________________ test_ssrf[169.254.169.254] __________________________
tests/test_phase1.py:172: in test_ssrf
    with pytest.raises(transport.DestinationError):
         ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
E   Failed: DID NOT RAISE DestinationError
____________________________ test_ssrf[100.64.0.1] _____________________________
tests/test_phase1.py:172: in test_ssrf
    with pytest.raises(transport.DestinationError):
         ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
E   Failed: DID NOT RAISE DestinationError
__________________________ test_ssrf[100.127.255.254] __________________________
tests/test_phase1.py:172: in test_ssrf
    with pytest.raises(transport.DestinationError):
         ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
E   Failed: DID NOT RAISE DestinationError
________________________________ test_ssrf[::1] ________________________________
tests/test_phase1.py:172: in test_ssrf
    with pytest.raises(transport.DestinationError):
         ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
E   Failed: DID NOT RAISE DestinationError
______________________________ test_ssrf[fc00::1] ______________________________
tests/test_phase1.py:172: in test_ssrf
    with pytest.raises(transport.DestinationError):
         ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
E   Failed: DID NOT RAISE DestinationError
______________________________ test_ssrf[fe80::1] ______________________________
tests/test_phase1.py:172: in test_ssrf
    with pytest.raises(transport.DestinationError):
         ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
E   Failed: DID NOT RAISE DestinationError
_________________________ test_ssrf[::ffff:127.0.0.1] __________________________
tests/test_phase1.py:172: in test_ssrf
    with pytest.raises(transport.DestinationError):
         ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
E   Failed: DID NOT RAISE DestinationError
___________________________ test_ssrf[2002:7f00:1::] ___________________________
tests/test_phase1.py:172: in test_ssrf
    with pytest.raises(transport.DestinationError):
         ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
E   Failed: DID NOT RAISE DestinationError
__________________________ test_ssrf[64:ff9b::7f00:1] __________________________
tests/test_phase1.py:172: in test_ssrf
    with pytest.raises(transport.DestinationError):
         ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
E   Failed: DID NOT RAISE DestinationError
______________________________ test_ssrf[0.0.0.0] ______________________________
tests/test_phase1.py:172: in test_ssrf
    with pytest.raises(transport.DestinationError):
         ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
E   Failed: DID NOT RAISE DestinationError
_____________________________ test_ssrf[224.0.0.1] _____________________________
tests/test_phase1.py:172: in test_ssrf
    with pytest.raises(transport.DestinationError):
         ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
E   Failed: DID NOT RAISE DestinationError
=========================== short test summary info ============================
FAILED tests/test_phase1.py::test_ssrf[127.0.0.1] - Failed: DID NOT RAISE Des...
FAILED tests/test_phase1.py::test_ssrf[10.0.0.1] - Failed: DID NOT RAISE Dest...
FAILED tests/test_phase1.py::test_ssrf[172.16.0.1] - Failed: DID NOT RAISE De...
FAILED tests/test_phase1.py::test_ssrf[192.168.0.1] - Failed: DID NOT RAISE D...
FAILED tests/test_phase1.py::test_ssrf[169.254.169.254] - Failed: DID NOT RAI...
FAILED tests/test_phase1.py::test_ssrf[100.64.0.1] - Failed: DID NOT RAISE De...
FAILED tests/test_phase1.py::test_ssrf[100.127.255.254] - Failed: DID NOT RAI...
FAILED tests/test_phase1.py::test_ssrf[::1] - Failed: DID NOT RAISE Destinati...
FAILED tests/test_phase1.py::test_ssrf[fc00::1] - Failed: DID NOT RAISE Desti...
FAILED tests/test_phase1.py::test_ssrf[fe80::1] - Failed: DID NOT RAISE Desti...
FAILED tests/test_phase1.py::test_ssrf[::ffff:127.0.0.1] - Failed: DID NOT RA...
FAILED tests/test_phase1.py::test_ssrf[2002:7f00:1::] - Failed: DID NOT RAISE...
FAILED tests/test_phase1.py::test_ssrf[64:ff9b::7f00:1] - Failed: DID NOT RAI...
FAILED tests/test_phase1.py::test_ssrf[0.0.0.0] - Failed: DID NOT RAISE Desti...
FAILED tests/test_phase1.py::test_ssrf[224.0.0.1] - Failed: DID NOT RAISE Des...
15 failed in 0.16s
```

### 04-redirect

```diff
--- a/phase1/events.py
+++ b/phase1/events.py
@@ -58,7 +58,7 @@
                     identifier,
                     [request.delivery.secret],
                 )
-                if not 200 <= status < 300:
+                if status >= 400:
                     raise CallbackError("challenge_failed")
                 reply = json.loads(raw)
                 if (
```

```text
F                                                                        [100%]
=================================== FAILURES ===================================
________________________________ test_redirect _________________________________
tests/test_phase1.py:234: in test_redirect
    assert response.json()["error"]["code"] == -32015
           ^^^^^^^^^^^^^^^^^^^^^^^^
E   KeyError: 'error'
=========================== short test summary info ============================
FAILED tests/test_phase1.py::test_redirect - KeyError: 'error'
1 failed in 0.13s
```

### 05-signatures

```diff
--- a/phase1/transport.py
+++ b/phase1/transport.py
@@ -145,7 +145,7 @@
 def signed_post(http, url, body, event_id, subscription_id, keys):
     stamp = datetime.now(UTC)
     signature = " ".join(
-        Webhook(key).sign(event_id, stamp, body.decode()) for key in keys
+        Webhook(key).sign(event_id, stamp, "tampered") for key in keys
     )
     headers = {
         "Content-Type": "application/json",
```

```text
F                                                                        [100%]
=================================== FAILURES ===================================
_______________________________ test_signatures ________________________________
tests/test_phase1.py:243: in test_signatures
    Webhook(key).verify(challenge, challenge_headers)
/home/sini/src/dot-phase1-placeholder/.venv/lib/python3.12/site-packages/standardwebhooks/webhooks.py:86: in verify
    raise WebhookVerificationError("No matching signature found")
E   standardwebhooks.webhooks.WebhookVerificationError: No matching signature found
=========================== short test summary info ============================
FAILED tests/test_phase1.py::test_signatures - standardwebhooks.webhooks.Webh...
1 failed in 0.12s
```

### 06-custody

```diff
--- a/phase1/store.py
+++ b/phase1/store.py
@@ -164,7 +164,7 @@
                 "cursor": None,
             }
             db.execute(
-                "INSERT INTO outbox(occurrence,event_id,body) VALUES (?,?,?)",
+                "INSERT INTO outbox(occurrence,event_id,body,state) VALUES (?,?,?,'accepted')",
                 (occurrence, event_id, encode(event)),
             )
             return event_id
```

```text
F                                                                        [100%]
=================================== FAILURES ===================================
_________________________________ test_custody _________________________________
tests/test_phase1.py:274: in test_custody
    assert len(pending) == 1 and pending[0]["state"] == "pending"
E   assert (1 == 1 and 'accepted' == 'pending'
E    +  where 1 = len([{'sequence': 1, 'occurrence': 'crash-occurrence', 'event_id': 'xm_evt_9a88a7fc42e3024374ee4ecb57f6a7c4', 'body': b'{"...a7fc42e3024374ee4ecb57f6a7c4","name":"xmsg.message.received.v1","timestamp":"2026-11-05T20:33:23.979528+00:00"}', ...}])
E     
E     - pending
E     + accepted)
=========================== short test summary info ============================
FAILED tests/test_phase1.py::test_custody - assert (1 == 1 and 'accepted' == ...
1 failed in 0.15s
```

### 07-loopback

```diff
--- a/phase1/config.py
+++ b/phase1/config.py
@@ -9,7 +9,7 @@
     state_dir: Path = Path(".state")
     auth_mode: Literal["oauth", "local-test"] = "oauth"
     exposure: Literal["private", "public-https"] = "private"
-    bind: str = "127.0.0.1"
+    bind: str = "0.0.0.0"
     port: int = 8765
     public_url: str | None = None
     issuer: str | None = None
```

```text
F                                                                        [100%]
=================================== FAILURES ===================================
______________________________ test_default_bind _______________________________
tests/test_phase1.py:293: in test_default_bind
    assert Settings(state_dir=tmp_path).bind == "127.0.0.1"
           ^^^^^^^^^^^^^^^^^^^^^^^^^^^^
E   pydantic_core._pydantic_core.ValidationError: 1 validation error for Settings
E     Value error, non-loopback bind requires explicit public-https exposure [type=value_error, input_value={'state_dir': PosixPath('...88/test_default_bind0')}, input_type=dict]
E       For further information visit https://errors.pydantic.dev/2.14/v/value_error
=========================== short test summary info ============================
FAILED tests/test_phase1.py::test_default_bind - pydantic_core._pydantic_core...
1 failed in 0.09s
```
