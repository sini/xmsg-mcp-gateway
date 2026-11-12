# Authentication profiles

Planned, not yet released. Multiple verifier profiles let one canonical MCP resource accept separately configured OAuth integrations or retain an old issuer during a cutover. They do not create extra xmsg service addresses, mailboxes or dots.

The existing `verifier` object remains supported, including opaque access tokens. For explicit profiles use `verifier_profiles` instead; configure exactly one form. Each entry has the existing verifier fields plus optional `opaque_default` (false by default). The collection is bounded to 16 entries. Keep one service and canonical resource across all entries. Each exact `(issuer, hosted_client, audience)` selects one profile; omitted audience means the canonical resource. Subject, scopes, introspection endpoint, credential file, certificate and provider-address restrictions remain specific to that entry. Duplicate selection keys and duplicate grant bindings are refused.

## Selection and authority

For a compact JWS carrying `iss`, bounded local decoding supplies only a routing hint: its exact issuer, client (`client_id`, or `azp` when client_id is absent) and single audience must select one configured entry. Conflicting client_id/azp values refuse. The gateway then sends the token to that entry's introspection provider and repeats all exact identity, audience, scope and lifetime checks. It never tries another profile after rejection or provider failure. A token cannot choose an arbitrary provider URL.

At most one entry may set `opaque_default: true`. Tokens without a readable JWS issuer go only to this entry. An unknown issuer or other unknown JWS profile does not fall back to the default. Without a default, opaque/encrypted tokens refuse in explicit-profile mode. Never label an entry a default merely to broaden accepted identities: introspection still has to match that exact entry.

Kanidm 1.11.2's authorization-code access tokens are signed JWS with `iss`, `aud` and `client_id`; its client-credentials access tokens are encrypted JWE. This is a source-version statement, not a claim about every token or live deployment. A proxy issuer must supply a compatible selector or use the one explicit opaque default.

Discovery advertises the configured issuer set at the unchanged resource. Advertised scopes describe available configuration; authorization always uses the selected profile's scopes and its exact enabled grant. One profile cannot borrow another profile's permissions.

Outbound calls select and verify their profile once at public entry. An immutable
verified context carries that identity (including audience) and its entry grant
through list, send and broker dispatch. Before bus effects and stored receipt
recovery, the gateway checks captured expiry and live grant/revision authority;
it does not contact the provider again within that call. Provider-side revocation
after entry applies to the next call. Events retains its separate fresh-verification
contract. See [outbound authorization](outbound.md).

## Example

Replace an existing single `verifier` object with an array of complete entries. This abbreviated fragment illustrates the selector fields; retain every required existing verifier field, including subject, introspection credentials, timeout and required scopes, in each entry:

```json
{
  "verifier_profiles": [
    {
      "service": "gateway",
      "resource": "https://gateway.example/mcp",
      "issuer": "https://old-id.example/oauth2/openid/gateway",
      "hosted_client": "gateway",
      "audience": "gateway",
      "opaque_default": false
    },
    {
      "service": "gateway",
      "resource": "https://gateway.example/mcp",
      "issuer": "https://proxy.example/issuer",
      "hosted_client": "hosted-client",
      "audience": "https://gateway.example/mcp",
      "opaque_default": false
    }
  ]
}
```

This fragment is not a runnable owner file. Relative credential and certificate paths resolve against the owner file's directory for every entry, just as for the legacy object. Do not copy credentials between profiles unless the owner explicitly provisions that configuration.

## Owner-run migration and cutover

Grant coexistence requires the explicit `migrate-profiles --if-needed` store migration. Follow the same store-path and backup procedure as the existing [migration commands](serving.md). Read back `migrations-pending` after migration; `migrate-profiles` must no longer be listed. The migration preserves grant IDs, revisions, enabled state and existing custody/Events schema. It replaces service-only uniqueness with one enabled grant per exact `(service, issuer, resource, subject, hosted_client)` binding. It does not enroll or enable a new grant.

1. The owner provisions the new issuer/client and its introspection credentials separately. Retain the old entry and exact binding.
2. With the normal owner-controlled service maintenance procedure, migrate and inspect the store, enroll the new exact binding and explicitly enable its grant. Add both complete verifier entries. Run both integrations' identity/grant-authorized checks against the same resource before withdrawing either.
3. Events and mailbox custody remain bound to the one configured `events.grant_id`. Other profiles gain no custody or Events rights merely by being accepted for identity/outbound operations. A second profile does not receive old subscriptions or bearer credentials.
4. Moving Events to the new grant is an explicit owner action: update `events.grant_id` in the owner configuration and use the normal owner-run restart/cutover procedure. The new client must establish its own authenticated subscription; verify its wake and mailbox read before retiring the old connection. Existing grant-bound custody is not automatically transferred by changing this field.
5. After the owner verifies the transition, disable the old grant. Retain its verifier entry while its historical grant row remains in the store: startup validates disabled bindings too. Removing that profile and history requires a separately supported owner procedure; this change adds no deletion or retirement command. Rollback retains the old profile/grant and explicitly restores Events selection if it moved.

No deploy, token mint, credential movement or automatic Events transfer is performed by enabling this feature. Multiple profiles still share process capacity and one xmsg service.

## Planned local authorization profile

The [gateway authorization server](authorization-server.md) adds one `local: true` entry with `opaque_default: true`, the exact local service/issuer/resource/subject/hosted-client binding and `required_scopes`. It has no remote introspection fields. Exactly one such entry and a matching `authorization_server` must appear together. Remote entries retain their existing fields. `advertised` defaults to true on either kind; false hides an issuer from resource discovery without disabling that profile. This supports accepting an old provider while advertising only the new gateway issuer. It does not make multiple xmsg mailboxes.

Local access-token verification atomically admits a request and captures its grant revision; the outbound policy is captured alongside it in memory. Normal local sends, broker calls and stored reply receipt/reservation recovery use that snapshot within their existing budget. A policy edit after admission does not change the admitted send, and no durable policy snapshot is added. Custody reads (including attachment reads before and after the bus read)/ACK and reply-target ownership lookup with its pre-effect recheck retain their stricter effect-point revision fence. A disable before reply-target lookup refuses a new reply without a reservation or effect; Events subscribe/renew freshly verifies before writing future wake authority. Remote profiles retain the once-at-entry provider and effect-time expiry/grant behavior described above. No eligibility history restores custody rights after a disable.

For an AS issuer cutover, use the explicit offline `cutover-events` guard and read-back procedure in the [AS guide](authorization-server.md#owner-run-migration-cutover-and-rollback), rather than treating a configuration-only `events.grant_id` edit as a completed switch. A new authorization never moves an existing subscription automatically; the new connector must subscribe with its token. Retain disabled historical bindings required by store validation.
