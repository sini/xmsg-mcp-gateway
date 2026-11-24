# Kubernetes reference chart

`charts/xmsg-mcp-gateway/` is a **reference; adapt** Helm chart for one gateway pod:
the gateway, its `xmsg --leaf` sidecar, and an optional OpenAI `tunnel-client`. It
renders the pod's structure: hardening, the grant-store init chain, sockets and
paths. Your cluster supplies everything instance-specific through values. It
creates no credentials, certificates, issuers, DNS, network policy or proxy.

Every hostname and identity below (`example.com`, `owner.hub`,
`00000000-0000-4000-8000-000000000001`) is a placeholder. Complete example values
are in `charts/xmsg-mcp-gateway/ci/`: `loopback-values.yaml` (tunnel-only, fresh-store
bootstrap) and `podnetwork-values.yaml` (in-cluster proxy, tunnel, routes, alerts).

```sh
helm template gw charts/xmsg-mcp-gateway -f my-values.yaml
```

The [serving configuration](serving.md), [Events](events.md) and
[hosted setup](hosted-dots-setup.md) guides remain the reference for what the
configuration means. This page covers only how the chart lays it out.

## What the chart renders

| Resource | Notes |
|---|---|
| `Deployment` | `replicas: 1` and `strategy: Recreate`: one SQLite writer on a `ReadWriteOnce` volume, and the old pod stops before the new one migrates. Pod `fsGroup` with `fsGroupChangePolicy: OnRootMismatch`, so kubelet never re-adds group access to the `0700` state directories. `seccompProfile: RuntimeDefault`, no service-account token, no service links. |
| `ServiceAccount` | `automountServiceAccountToken: false`. |
| `ConfigMap` `-config` | `serving.json`, plus `binding-<id>.json` and `policy-<id>.json` per grant. World-readable, never writable. A checksum annotation restarts the pod when it changes, because the gateway and the leaf read configuration only at start. |
| `ConfigMap` `-peers` | The leaf's `peers.json`, `{"peers": <xmsg.peers>}`. |
| `PersistentVolumeClaim` | Unless `persistence.existingClaim` is set. It holds the grant store, custody and the leaf's database. |
| `Service` | Only with `gateway.podNetwork`. |
| `HTTPRoute` | Only with `httpRoute.enabled`. See [public OAuth paths](#public-oauth-paths). |
| `ConfigMap` `-custody-alerts` | Only with `custodyAlerts.enabled`. See [custody alerts](#custody-alerts). |

Every container runs as one uid (`uid`, default 10001, the image's user) with
`runAsNonRoot`, `readOnlyRootFilesystem`, no privilege escalation and every
capability dropped. The uid must be shared: the leaf admits `register.sock` and
`agent.sock` callers by peer uid, and the chart writes the same uid into
`serving.json` as `messaging.xmsg.daemon_uid`.

## Pod-owned paths

The chart owns the in-pod paths and writes them into `serving.json` over your
`serving` values, so every container agrees on them:

| Field | Value |
|---|---|
| `bind` | `127.0.0.1:<gateway.port>`, or `0.0.0.0:<port>` with `gateway.podNetwork` |
| `allow_non_loopback_bind` | `true` only with `gateway.podNetwork`; otherwise removed |
| `grant_store` | `/var/lib/xmsg-mcp-gateway/state/grants.db` |
| `messaging.xmsg.service` | `xmsg.principal`, which is also the leaf's `--leaf-principal` |
| `messaging.xmsg.daemon_uid` | `uid` |
| `messaging.xmsg.register_socket`, `agent_socket` | `/run/user/xmsg/register.sock`, `/run/user/xmsg/agent.sock`, on a shared memory `emptyDir` |
| `messaging.manifest.reply_ttl_secs`, `idempotency_ttl_secs`, `svc_queue_cap` | `xmsg.limits`, which are also passed to the leaf as `--reply-ttl`, `--idempotency-ttl` and `--svc-queue-cap` |
| `messaging.manifest.dedup_lifetime_secs`, `max_framed_bytes` | Your value, or half the idempotency TTL and `xmsg.limits.maxBody` |

You write the rest: the verifier or verifier profiles, `allowed_hosts`, `events`,
timeouts and limits. Reference key files as `/run/xmsg-mcp-gateway/keys/<key>`,
where `<key>` is the Secret item key.

Rendering refuses the gateway's budget rules early (the gateway also refuses them at
startup): `events.dispatch_timeout_ms` against the verifier timeout,
`request_timeout_ms` against the verifier timeout, the 30 s store wait, and the
submission and operation timeouts.

## Secrets

Kubernetes Secret files are root-owned and group-readable, and the gateway refuses
group-accessible credentials. The `prepare` init container (`helperImage`, which
needs a POSIX shell, because the gateway image has none) copies each `secrets.items`
entry from `secrets.existingSecret` into a memory `emptyDir` with the given mode:

```yaml
secrets:
  existingSecret: gateway
  items:
    - {key: lookup-secret, mode: "0400"}
    - {key: events-key, mode: "0600", base64Decode: true}  # 32 raw bytes
```

`prepare` also creates `state/` and `xmsg/` on the volume at `0700`. The leaf's
database lives in `xmsg/`, and xmsg requires that directory to be owner-only.

The leaf's federation identity comes from `xmsg.tls.existingSecret`, a
`kubernetes.io/tls` Secret (for example a cert-manager `Certificate` with the leaf's
SPIFFE URI SAN). The tunnel runtime key comes from `tunnel.apiKeySecret`.

## The grant-store init chain

The init containers run in this order. Each store step is the gateway image with its
own entrypoint, `--state <store> <command>`, with no shell:

1. `prepare`.
2. With `store.bootstrap.enabled`: `store-init` runs `init --if-needed` on the real
   store. A valid existing store is preserved; corrupt or incompatible state refuses.
3. `store.preMigrate`: your own init containers, verbatim. This is the slot for a
   pre-migration backup.
4. `store-migrate-*` on the real store, in the gateway's order, each with
   `--if-needed`: `migrate-custody`, `migrate-outbound`, `migrate-retirement`,
   `migrate-custody-summaries`, `migrate-events` (with `--key-file` when
   `store.eventsKey` is set), `migrate-profiles`, `migrate-attachments`, and
   `migrate-authorization-server` when `store.authorizationServer` is set. Run that
   last one only in a maintenance window (see the [authorization server](authorization-server.md) guide).
5. With `store.bootstrap.enabled`: `store-enroll-<id>` runs `enroll --if-needed`
   after migrations. An exact existing binding preserves revision and enablement;
   a different binding refuses without replacement. A newly enrolled grant is disabled.
6. `store-apply-<id>` per grant: `apply --id <id> --policy policy-<id>.json`. It
   passes no `--enabled` or `--disabled`, so enablement is unchanged. An unchanged
   policy writes nothing.

The chart never runs `enable`. Enabling a grant is a deliberate owner step.

Use a gateway image built from this release or later for `init --if-needed`,
`enroll --if-needed`, and `backup-if-pending` in the updated chain. There
is no staging store or shell install step. A restart resumes the idempotent chain;
initialization never resets an existing store.

`store.preMigrate` remains an explicit owner-configured slot. For example, add a
same-UID gateway container with these arguments and a `data` volume mount at
`/var/lib/xmsg-mcp-gateway` (use top-level `extraVolumes` if a `store.preMigrate`
hook needs additional pod volumes):

```yaml
args:
  - --state
  - /var/lib/xmsg-mcp-gateway/state/grants.db
  - backup-if-pending
  - --backup-dir
  - /var/lib/xmsg-mcp-gateway/backups
  - --keep
  - "3"
```

Use the same pinned gateway image and hardened security context as the other store
steps; do not override its command or pass credentials through environment variables.
The command publishes a private consistent snapshot before pruning only completed
backups of this store. It creates nothing and prunes nothing when no migration is
pending. The chart does not configure backups automatically. Rolling back an image
that changed the schema means restoring a compatible backup; see
[store maintenance](serving.md#snapshot-before-a-pending-migration).

To preserve an existing workload's object names and SPIFFE `sa/<name>` identity, set
`fullnameOverride` (which overrides the `<release>-xmsg-mcp-gateway` prefix on every
rendered resource) and optionally `serviceAccount.name` (which overrides the
ServiceAccount name and `pod.serviceAccountName` independently).

## Exposure and probes

With `gateway.podNetwork: false` (the default), the gateway listens on loopback
only. The tunnel-client reaches it there, and nothing else in the cluster can.
Kubelet cannot reach a loopback listener and the image has no shell, so the chart
renders no probes in this mode.

With `gateway.podNetwork: true`, the gateway binds `0.0.0.0` with
`allow_non_loopback_bind`, and the chart adds:

- a `Service`;
- a readiness probe, `GET /.well-known/oauth-protected-resource` with `Host: 127.0.0.1`
  (this path is unauthenticated, and `127.0.0.1` must be in `serving.allowed_hosts`);
- a liveness probe, a TCP check on the listener.

Restrict ingress to your proxy with a NetworkPolicy: the listener is plain HTTP.

## Public OAuth paths

The proxy routes only OAuth discovery and the authorization server's endpoints.
Every other path on the host, `/mcp` included, stays unrouted unless you opt in:

| Match | Path |
|---|---|
| `PathPrefix` | `/.well-known/oauth-protected-resource` |
| `Exact` | `/.well-known/oauth-authorization-server` |
| `PathPrefix` | `/oauth` |
| `PathPrefix` | `/oauth/authorize` (its own route, so a rate-limit policy can target it) |
| `PathPrefix` | `/mcp`, only with `httpRoute.mcp` (direct HTTPS MCP) |

With Gateway API:

```yaml
gateway: {podNetwork: true}
httpRoute:
  enabled: true
  hostnames: [gateway.example.com]
  parentRefs: [{name: public-gateway, namespace: gateways}]
```

The chart does not render an Ingress. For an Ingress controller, the equivalent is
(reference; adapt):

```yaml
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: gw-xmsg-mcp-gateway
spec:
  rules:
    - host: gateway.example.com
      http:
        paths:
          - {path: /.well-known/oauth-protected-resource, pathType: Prefix, backend: {service: {name: gw-xmsg-mcp-gateway, port: {name: http}}}}
          - {path: /.well-known/oauth-authorization-server, pathType: Exact, backend: {service: {name: gw-xmsg-mcp-gateway, port: {name: http}}}}
          - {path: /oauth, pathType: Prefix, backend: {service: {name: gw-xmsg-mcp-gateway, port: {name: http}}}}
  tls:
    - hosts: [gateway.example.com]
      secretName: gateway-example-com-tls
```

Add the public hostname to `serving.allowed_hosts`. Drop query strings from `/oauth/*`
access logs, and never log callback codes or state
([serving](serving.md#planned-authorization-server-configuration-and-commands)).

## Tunnel sidecar

With `tunnel.enabled`, the chart adds `tunnel-client` and points it at
`http://127.0.0.1:<port>/mcp`. Set `tunnel.id`, `tunnel.apiKeySecret` and a pinned
`tunnel.image`. Each `tunnel.oauthOrigins` entry (your authorization server's origin
and the gateway's public origin) becomes both `--mcp.oauth-trusted-origin` and
`--harpoon.oauth-forward-origin`, and `--harpoon.allow-plaintext-http` permits the
loopback target. `MCP_STARTUP_WAIT_TIMEOUT` is 60 s, because the gateway may bind
after the sidecar starts. See [hosted setup](hosted-dots-setup.md).

## Custody alerts

With `custodyAlerts.enabled`, the chart renders a ConfigMap of five LogQL rules over
the gateway container's log, for a Loki ruler that loads rule ConfigMaps (set
`custodyAlerts.labels` and `namespace` to what your ruler's sidecar selects):

| Alert | Fires on |
|---|---|
| `XmsgGatewayCustodyDeferred` (critical) | any `custody intake deferred` line in 5 m, by `reason`. New messages are not stored or acked. |
| `XmsgGatewayCustodyUnavailable` (critical) | any `custody unavailable` or `custody store unavailable` line in 5 m |
| `XmsgGatewayCustodyNearFull` (warning) | `active_rows / max_items >= 0.8` on the `custody capacity` line |
| `XmsgGatewayCustodyRetiredNearFull` (warning) | `retired_rows / max_retired_items >= 0.8` |
| `XmsgGatewayCustodyCapacityLogMissing` (warning) | no `custody capacity` line in 20 m, so the other rules are blind |

The default stream selector is `{namespace="<release namespace>", container="gateway"}`.
Override it with `custodyAlerts.selector` if your log shipper labels streams
differently. These are log rules, not Prometheus rules, so the chart renders no
`PrometheusRule`.

## Checks

`nix build .#checks.x86_64-linux.k8s` renders the chart with each `ci/*-values.yaml`
file and asserts the structural invariants: one uid across containers and
`daemon_uid`, hardening on every container, the init-chain order with `--if-needed`
and no enablement change, no non-loopback bind without `allow_non_loopback_bind`,
only the public OAuth route paths, the single-writer envelope, and a refused budget
violation. It then applies each mutant listed in `nix/check_k8s.py` to a copy of the
chart and requires its assertion to fail.
