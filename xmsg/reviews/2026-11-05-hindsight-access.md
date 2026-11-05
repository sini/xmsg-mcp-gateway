# Hindsight access design and PR 186 review

Reviewed 2026-11-05, with no live infrastructure/credential access or PR edits.
No PR comments were posted and no message was sent to another session.

Design: [revision e7e4a5d](https://gist.github.com/sini/8eae0acffe268e6a07721169418d5cd0/e7e4a5d3504e6ee9939b236faa30fa9e405a2ac4),
SHA256 `fdc83231ba87e4728c31fc164390f32cbe5c69827a8f03e55429800983cdeb79`.
PR: [186](https://github.com/sini/nix-config/pull/186), head
`fa68f4c7ad1807bec1a6be4dafa8cc15001810d5`, base
`7e48829a9058a68fb8b04d766d904e66289e0b16`.
The PR was still draft at the same head when rechecked after inspection.

What this change does: the design proposes a private, fixed-bank Hindsight MCP
adapter with hosted OAuth and a separate backend credential. The PR implements
only the default-disabled named-writer foundation. It does not claim to implement
OAuth, an MCP adapter, network isolation, a tunnel or hosted write access.

Expected load: one owner/hosted integration; existing local owner and reader
clients continue using the existing dataplane. This is not a multi-tenant review.

## Must resolve in the design before shared-auth implementation

1. **Choose Pod-level or process-level isolation; the current requirements conflict.**
   Design Architecture/Network isolation, lines 44 and 54, permits a sidecar Pod
   while requiring different destination sets for the adapter and tunnel client.
   Cilium policies select the shared Pod endpoint, not each container separately.
   Allowing the adapter to reach Hindsight therefore gives the sidecar that same
   network reachability. Separate secret mounts do not split this boundary.

   Fix: either choose separate Pods and their private authenticated MCP hop, or
   explicitly accept one shared Pod egress set as the trust boundary. If different
   process policies are required within a Pod, name the additional enforcement
   mechanism and test it. Probe destinations from both containers, including the
   effective union of clusterwide policies. This is a design contradiction, not
   a claim that the foundation PR deploys an unsafe sidecar.
   [Cilium endpoint definition](https://docs.cilium.io/en/stable/gettingstarted/terminology/#endpoint),
   [Pod-based selectors](https://docs.cilium.io/en/stable/security/policy/kubernetes/).

2. **The shared auth boundary needs a concrete grant and revocation contract.**
   Authentication/Revocation and coordination item 1 require a verified owner and
   active connection grant, but do not define how an access token identifies that
   grant, who persists it, or which component enforces disablement. Issuer, subject
   and audience identify an account/resource combination; they do not by themselves
   distinguish separate authorizations for the same account and resource.

   Failure scenario to rule out: an operator disables a connection by its current
   access-token digest, but a refresh issues a different token for the same subject
   and audience, and the generic verifier admits it again. Alternatively, disabling
   an account-wide record revokes both integrations despite their independence
   requirement. Existing xmsg phase-1 code has token-specific local revocation and
   online introspection; it is not already an implementation of this durable
   shared connection-grant contract.

   Fix: define the service resource and trusted identity result, stable grant key
   or explicitly single-binding-per-service policy, grant-store owner, disabled
   state/version, and fail-closed behavior on lookup failure. Specify that a refreshed
   token cannot revive an operator-disabled service grant. Bind queued work and
   event subscriptions to that grant and define the check immediately before a
   new backend submission; distinguish already accepted upstream work. Keep domain
   permissions in each adapter, not in the shared authentication package.

   Required tests: a refreshed token cannot undo a service disable; an xmsg token
   cannot authorize Hindsight and vice versa; disabling Hindsight leaves xmsg
   working; authorization/grant-store outages admit no new work. This is missing
   interface detail, not evidence of an implemented broker vulnerability.
   [OpenAI authentication contract](https://developers.openai.com/plugins/build/auth).

## Must fix in the PR runbook

3. **The new Nix instructions omit the mandatory host memory cap.**
   [Runbook lines 83 onward](https://github.com/sini/nix-config/blob/fa68f4c7ad1807bec1a6be4dafa8cc15001810d5/docs/runbooks/hindsight-artemis.md#L83)
   show bare `nix build`, `nix-flake-build` and `nix flake check`; setup also shows
   bare `nix develop`. Following these on the shared host bypasses the owner's
   evaluation memory limit. Wrap the evaluation/build/check commands, including
   wrappers that evaluate Nix, in `systemd-run --user --scope -q -p MemoryMax=12G`.
   Exit 137 is a finding and must not prompt an uncapped retry. Apply the appropriate
   heavy-run lock when running a heavy phase from the design workspace.

## PR code findings and validation

No new permission-check correctness defect found in this revision. In particular:

- Named writers are recognized before open-bank fallback, and bank listings apply
  that same confinement. Anonymous/open-bank access is explicitly preserved;
  dropping a bearer token remains why this is not a public isolation boundary.
- Writer tokens are separate from owner/reader/admin credentials. Missing, empty
  and malformed configured writer inputs fail startup. Disabling the typed option
  omits its grant and secret declaration.
- Startup-loaded token revocation requires a dataplane rollout; the runbook says so.
- The PR does not change the bank-wide MCP tool ceiling. A full bank token alone
  therefore does not create hosted write tools; the design correctly uses a
  separate fixed-bank REST adapter or an explicitly approved policy migration.

Reproduced locally against a downloaded snapshot of the exact seven PR files:

```text
python3 -I .../hindsight-write-gate-unit.py
Ran 11 tests in 0.008s
OK
```

Parsed all three changed Nix files under the 12-GiB cap: exit 0 for each. An isolated
capped `nix eval` probe, using minimal library stand-ins and dummy configuration
rather than the real secret modules, also returned:

```json
{"absentWhenDisabled":true,"declaredWhenEnabled":true,"defaultDisabled":true}
```

This verifies the touched secret-declaration expression and boolean default, not
the complete den module graph, secret generation, cluster rendering or deployment.
The Python policy tests use upstream interface stand-ins. They do not establish
that the pinned upstream HTTP/MCP routes call the validators.

Not run: full Nix check/build, treefmt, secret generation, nixidy rendering,
pinned-upstream HTTP/MCP oracle with disposable pgvector Postgres, deployed
network-policy probes, actual OAuth login/refresh, hosted tool calls or live bank
configuration. These remain explicit validation before activating this integration.
No existing keys, sockets, live bank contents or production databases were used.

## Coordination conclusions

The design's credential split and its Kanidm/service-account distinction are sound.
I independently confirmed the documented v1.11.2 authorization-code audience
construction uses the OAuth client name, and introspection returns client-ID
`aud`, so RFC 8693 service-account exchange is not proof of hosted authorization-code
compatibility. The design already treats this correctly as a gate.
[Code-token audience](https://github.com/kanidm/kanidm/blob/v1.11.2/server/lib/src/idm/oauth2.rs#L2005),
[introspection audience](https://github.com/kanidm/kanidm/blob/v1.11.2/server/lib/src/idm/oauth2.rs#L2857).

The owner's observed form offers Tunnel plus OAuth, No Authentication, and OAuth
or No Authentication. For this install the selected route is mandatory OAuth;
fixed-token setup remains unproved, not an alternative already available to us.

Recommendation: continue the foundation PR independently of OAuth-provider work,
fix item 3 and retain its draft/activation limits until the remaining checks are
complete. Resolve items 1 and 2 in the design before implementing reusable auth.
Use one reviewed auth contract with separate resource audiences and service grants;
share its implementation, not backend credentials or domain authority. Keep xmsg
Events/outbox semantics separate from Hindsight job semantics.

This is a source-backed review, not the unavailable orchestrator's approval and
not a completed multi-agent adversarial review loop. The artifact is another
session's design; no design or PR revisions were applied by this reviewer.
