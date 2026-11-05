# Phase 1 implementation plan

Spec: the owner's phase-1 dispatch and revised 2026-11-05 design gist
https://gist.github.com/sini/44d011556104b7341d521839cffba8b6.
The dispatch wins, including placeholder naming and no xmsg or infrastructure changes.

Goal: locally committed, independently reviewable authenticated Streamable HTTP MCP
server with one synthetic event. Hosted feasibility remains an owner-run gate.

Architecture: Python/Starlette stateless Streamable HTTP JSON responses, strict
Pydantic request models, SQLite durable subscription and outbox, Fernet encrypted
webhook secrets, Standard Webhooks signatures, public-IP-pinned HTTPS transport.
OAuth resource server with online introspection per request and before dispatch;
local fixture mode uses high-entropy revocable hashed tokens, never hosted bearer
setup. No OAuth authorization server, xmsg adapter, or remote endpoints are created.

User decisions: name the public project `xmsg-mcp-gateway`, store it under `Documents/repos/sini`, and keep design/review documents in `xmsg/`; use the existing Kanidm deployment if compatible; prefer Tunnel
and mandatory OAuth; continue autonomously until an actual owner input is needed.

## Tasks

- [x] Implement safe HTTPS and test DNS, address classes, TLS pinning, redirects,
  signing and challenge mismatch. IPv4 and IPv6 non-global destinations are denied.
- [x] Implement durable credentials, encrypted subscriptions and outbox with
  idempotent synthetic occurrence IDs, expiry, rotation, retry and dead letters.
- [x] Implement authenticated MCP initialization, identity tool and Events RPCs;
  reject unknown fields and identity overrides. Add owner-only local CLI commands.
- [x] Run seven required single-site production mutants in isolated copies, each
  with green control and failing assertion, and preserve exact patches/output.
- [x] Write README and REPORT with measured/inferred limits, official citations,
  Kanidm compatibility questions, owner setup and end-to-end steps; commit locally.

## Review focus

Credentials revoked after subscription; secret rotation after restart; mixed
public/private DNS answers and DNS rebinding; crash between commit and delivery;
concurrent subscription replacement and retries; callback 410/413 and saturation.

Validation: `uv run pytest -q`, `uv run ruff check phase1 tests`, and
`uv run python scripts/mutations.py`. Each mutant changes one site only and runs
against a copy; production is never toggled by an environment flag. Local fake
OAuth and callback fixtures measure server behavior, not hosted ChatGPT support.
