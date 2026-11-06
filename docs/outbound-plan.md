# Outbound custody unit

Build the dispatcher and durable reservations against the existing pinned
xmsg::client. No serving or Configuration change is authorized. The tool-layer
request_id / JSON-RPC-ID end-to-end oracle belongs to the later wiring unit.
RequestId is required and validated in this dispatcher, with no Default, Option
or conversion from a JSON-RPC Value.

The existing Store gains an explicit migration from custody schema 2 to outbound
schema 3. Legacy authority schema 1 and inbound schema 2 remain readable. Policy
is default-empty per grant; owner policy updates advance its revision. Fixtures
use the real Store and verifier, not an identity constructor.

Reserve the owner/profile, operation and request_id, canonical payload hash,
attested sender, acceptance grant/revision, stable key and framed bytes before
network submission. Pending means reserved, possibly already submitted after a
crash. Exceptions and elapsed protection become unknown; only a bus receipt
becomes confirmed. Preserve the original send/reply receipt vocabulary.

Retry with the stored key and bytes only before the conservative deadline fixed
at reservation. Reconfiguration cannot extend that deadline. Same request and
payload returns the original receipt; changed payload conflicts. A sender change
or stale grant cannot submit an old reservation. No automatic ledger eviction
may turn an old request into a fresh send; retention is capacity-bounded and
requires future explicit reconciliation/archival.

Fresh verification, current policy, owned reply correlation and exact live service
target checks precede each bounded submission under the durable SQL operation
guard. Disable waits for the guarded submission to finish. Request framing uses
the actual service address and stable gateway correlation, with no model-selected
origin. The complete framed text must fit the configured bound and the pinned
node's default 65536-byte text ceiling; oversize is rejected, never truncated.
Dedup lifetime is an explicit library input. Startup/Q1 remain unexposed.

Real private-node tests kill the gateway after reservation/before submission and
after node acceptance/before confirmation. Recovery must preserve the key,
original message ID and exactly one receiver delivery. Additional cases cover
reply receipts and ownership, expired uncertainty without retry, changed payload,
request-ID requirements, policy/grant/scope checks, oversize, guard ordering and
bounded state. Every oracle has a single-site source mutant, plus mandatory
profile count/marker and missing/early-return controls. No runtime mutant flags.
