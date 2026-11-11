"""Exact verifier-profile and grant cutover source mutants with fresh-artifact controls."""

import argparse
import tempfile
from pathlib import Path

import events_mutants as harness
from events_mutants import Case, Edit

ROOT = Path(__file__).resolve().parents[1]
CASES = [
    Case(
        "merged-provider",
        "multi_profile_identity",
        "exact_profile_routes_one_provider_and_keeps_credentials_and_scopes_separate",
        "tests/multi_profile_identity.rs",
        (
            Edit(
                "src/auth.rs",
                "profile.verify(token).await",
                "self.profiles[0].verify(token).await",
            ),
        ),
    ),
    Case(
        "merged-scopes",
        "multi_profile_identity",
        "exact_profile_routes_one_provider_and_keeps_credentials_and_scopes_separate",
        "tests/multi_profile_identity.rs",
        (
            Edit(
                "src/auth.rs",
                "&& profile.requires_scope(scope)",
                "&& self.profiles.iter().any(|candidate| candidate.requires_scope(scope))",
                "    pub fn requires_scope_for(",
                "    pub async fn verify(",
            ),
        ),
    ),
    Case(
        "routing-issuer",
        "multi_profile_identity",
        "unknown_or_malformed_issuer_claims_refuse_without_opaque_fallback",
        "tests/multi_profile_identity.rs",
        (Edit("src/auth.rs", "claims.iss == profile.config.issuer", "true"),),
    ),
    Case(
        "routing-client",
        "multi_profile_identity",
        "unknown_or_malformed_issuer_claims_refuse_without_opaque_fallback",
        "tests/multi_profile_identity.rs",
        (Edit("src/auth.rs", "client == profile.config.hosted_client", "true"),),
    ),
    Case(
        "routing-audience",
        "multi_profile_identity",
        "unknown_or_malformed_issuer_claims_refuse_without_opaque_fallback",
        "tests/multi_profile_identity.rs",
        (
            Edit(
                "src/auth.rs",
                "&& exact_audience(\n                                &claims.aud,\n                                profile\n                                    .config\n                                    .audience\n                                    .as_deref()\n                                    .unwrap_or(&profile.config.resource),\n                            )",
                "&& true",
            ),
        ),
    ),
    Case(
        "unsolicited-opaque",
        "multi_profile_identity",
        "opaque_requires_explicit_default_and_never_falls_through",
        "tests/multi_profile_identity.rs",
        (
            Edit(
                "src/auth.rs",
                "self.opaque_default.ok_or(Error::InvalidToken)?",
                "self.opaque_default.unwrap_or(0)",
            ),
        ),
    ),
    Case(
        "unknown-jws-fallback",
        "multi_profile_identity",
        "unknown_or_malformed_issuer_claims_refuse_without_opaque_fallback",
        "tests/multi_profile_identity.rs",
        (
            Edit(
                "src/auth.rs",
                "                    .ok_or(Error::InvalidToken)?\n            } else {",
                "                    .unwrap_or(&self.profiles[self.opaque_default.unwrap_or(0)])\n            } else {",
            ),
        ),
    ),
    Case(
        "authoritative-active",
        "multi_profile_identity",
        "selected_provider_must_revalidate_every_authoritative_claim",
        "tests/multi_profile_identity.rs",
        (Edit("src/auth.rs", 'claims["active"] != true', "false"),),
    ),
    Case(
        "authoritative-issuer",
        "multi_profile_identity",
        "selected_provider_must_revalidate_every_authoritative_claim",
        "tests/multi_profile_identity.rs",
        (
            Edit(
                "src/auth.rs",
                'claims["iss"].as_str() != Some(&self.config.issuer)',
                "false",
            ),
        ),
    ),
    Case(
        "authoritative-audience",
        "multi_profile_identity",
        "selected_provider_must_revalidate_every_authoritative_claim",
        "tests/multi_profile_identity.rs",
        (Edit("src/auth.rs", '!exact_audience(&claims["aud"], audience)', "false"),),
    ),
    Case(
        "authoritative-subject",
        "multi_profile_identity",
        "selected_provider_must_revalidate_every_authoritative_claim",
        "tests/multi_profile_identity.rs",
        (
            Edit(
                "src/auth.rs",
                'claims["sub"].as_str() != Some(&self.config.subject)',
                "false",
            ),
        ),
    ),
    Case(
        "authoritative-client",
        "multi_profile_identity",
        "selected_provider_must_revalidate_every_authoritative_claim",
        "tests/multi_profile_identity.rs",
        (
            Edit(
                "src/auth.rs",
                "client != Some(self.config.hosted_client.as_str())",
                "false",
            ),
        ),
    ),
    Case(
        "authoritative-expiry",
        "multi_profile_identity",
        "selected_provider_must_revalidate_every_authoritative_claim",
        "tests/multi_profile_identity.rs",
        (Edit("src/auth.rs", "exp <= now", "false"),),
    ),
    Case(
        "authoritative-not-before",
        "multi_profile_identity",
        "selected_provider_must_revalidate_every_authoritative_claim",
        "tests/multi_profile_identity.rs",
        (Edit("src/auth.rs", "nbf > now", "false"),),
    ),
    Case(
        "authoritative-scopes",
        "multi_profile_identity",
        "selected_provider_must_revalidate_every_authoritative_claim",
        "tests/multi_profile_identity.rs",
        (
            Edit(
                "src/auth.rs",
                "!self.config.required_scopes.iter().all(|required| {\n                scope\n                    .split_ascii_whitespace()\n                    .any(|actual| actual == required)\n            })",
                "false",
            ),
        ),
    ),
    Case(
        "two-opaque-defaults",
        "multi_profile_identity",
        "profile_configuration_rejects_ambiguity_and_preserves_legacy_opaque",
        "tests/multi_profile_identity.rs",
        (Edit("src/auth.rs", "defaults.len() > 1", "false"),),
    ),
    Case(
        "profile-cap",
        "multi_profile_identity",
        "profile_configuration_rejects_ambiguity_and_preserves_legacy_opaque",
        "tests/multi_profile_identity.rs",
        (Edit("src/auth.rs", "configs.len() > MAX_PROFILES", "false"),),
    ),
    Case(
        "canonical-resource",
        "multi_profile_identity",
        "profile_configuration_rejects_ambiguity_and_preserves_legacy_opaque",
        "tests/multi_profile_identity.rs",
        (Edit("src/auth.rs", "config.resource != first.resource", "false"),),
    ),
    Case(
        "canonical-service",
        "multi_profile_identity",
        "profile_configuration_rejects_ambiguity_and_preserves_legacy_opaque",
        "tests/multi_profile_identity.rs",
        (Edit("src/auth.rs", "config.service != first.service", "false"),),
    ),
    Case(
        "duplicate-grant",
        "multi_profile_identity",
        "profile_configuration_rejects_ambiguity_and_preserves_legacy_opaque",
        "tests/multi_profile_identity.rs",
        (Edit("src/auth.rs", "|| prior.subject == config.subject", "|| false"),),
    ),
    Case(
        "duplicate-route",
        "multi_profile_identity",
        "profile_configuration_rejects_ambiguity_and_preserves_legacy_opaque",
        "tests/multi_profile_identity.rs",
        (
            Edit(
                "src/auth.rs",
                "prior.audience.as_deref().unwrap_or(&prior.resource)\n                            == config.audience.as_deref().unwrap_or(&config.resource)",
                "false",
            ),
        ),
    ),
    Case(
        "grant-membership",
        "profile_grants",
        "configured_profile_membership_is_exact_including_disabled_clients",
        "tests/profile_grants.rs",
        (Edit("src/grants.rs", "if !bindings.contains(&row?) {", "if false {"),),
    ),
    Case(
        "grant-migration-required",
        "profile_grants",
        "migration_preserves_authority_and_exact_bindings_can_coexist",
        "tests/profile_grants.rs",
        (
            Edit(
                "src/grants.rs",
                "self.require_profiles_ready()?;",
                "",
                "    pub fn validate_profiles(",
                "    pub fn enroll(",
            ),
        ),
    ),
    Case(
        "grant-exact-index",
        "profile_grants",
        "migration_preserves_authority_and_exact_bindings_can_coexist",
        "tests/profile_grants.rs",
        (
            Edit(
                "src/grants.rs",
                "CREATE UNIQUE INDEX one_enabled_per_binding ON grants(service,issuer,resource,subject,hosted_client) WHERE enabled = 1;",
                "CREATE UNIQUE INDEX one_enabled_per_binding ON grants(service) WHERE enabled = 1;",
            ),
        ),
    ),
    Case(
        "events-selected-subscription",
        "lib",
        "event_dispatch::tests::cutover_selects_new_subscription_while_both_grants_remain_enabled",
        "src/event_dispatch.rs",
        (Edit("src/event_dispatch.rs", "AND s.grant_id=?4", "AND (?4 IS NOT NULL)"),),
    ),
    Case(
        "outbound-foreign-pending",
        "profile_outbound",
        "foreign_pending_and_confirmed_reservations_are_denied_before_reverification",
        "tests/profile_outbound.rs",
        (
            Edit(
                "src/outbound.rs",
                "    if store\n        .reservation(&owner, op, id)?\n        .is_some_and(|row| row.grant_id != initial_grant.grant_id || row.sender != service.sender())\n    {\n        return Err(Error::Denied);\n    }\n",
                "",
            ),
        ),
    ),
    Case(
        "discovery-issuer-set",
        "serving_profiles",
        "one_endpoint_selects_two_profiles_and_advertises_both_issuers",
        "tests/serving_profiles.rs",
        (
            Edit(
                "src/serving.rs",
                '"authorization_servers": app.issuers',
                '"authorization_servers": [app.issuers[0]]',
            ),
        ),
    ),
    Case(
        "exclusive-config",
        "serving_profiles",
        "collection_requires_migration_and_exactly_one_configuration_form",
        "tests/serving_profiles.rs",
        (Edit("src/serving.rs", "(Some(single), None) =>", "(Some(single), _) =>"),),
    ),
    Case(
        "custody-catalog",
        "serving_profiles",
        "one_endpoint_selects_two_profiles_and_advertises_both_issuers",
        "tests/serving_profiles.rs",
        (Edit("src/serving.rs", "if !custody_selected {", "if false {"),),
    ),
    Case(
        "custody-denial",
        "serving_profiles",
        "one_endpoint_selects_two_profiles_and_advertises_both_issuers",
        "tests/serving_profiles.rs",
        (
            Edit(
                "src/serving.rs",
                ".is_some_and(|events| events.selected_grant != grant.grant_id)",
                ".is_some_and(|_events| false)",
            ),
        ),
    ),
    Case(
        "identity-health-profile",
        "serving_profiles",
        "one_endpoint_selects_two_profiles_and_advertises_both_issuers",
        "tests/serving_profiles.rs",
        (
            Edit(
                "src/serving.rs",
                ".filter(|events| events.selected_grant == grant.grant_id)",
                ".filter(|_events| true)",
            ),
        ),
    ),
    Case(
        "profile-credentials",
        "multi_profile_identity",
        "exact_profile_routes_one_provider_and_keeps_credentials_and_scopes_separate",
        "tests/multi_profile_identity.rs",
        (
            Edit(
                "src/auth.rs",
                ".basic_auth(&self.config.introspection_client, Some(&self.secret))",
                ".basic_auth(&self.config.introspection_client, None::<&str>)",
            ),
        ),
    ),
    Case(
        "tool-scopes-profile",
        "serving_profiles",
        "one_endpoint_selects_two_profiles_and_advertises_both_issuers",
        "tests/serving_profiles.rs",
        (
            Edit(
                "src/serving.rs",
                ".filter(|scope| app.verifier.requires_scope_for(identity, scope))",
                ".filter(|_scope| true)",
            ),
        ),
    ),
]


def preflight():
    with tempfile.TemporaryDirectory(prefix="gateway-profile-preflight-") as temporary:
        for case in CASES:
            tree = Path(temporary) / case.label
            for file in {
                "src/lib.rs",
                case.test_file,
                *(edit.file for edit in case.edits),
            }:
                destination = tree / file
                destination.parent.mkdir(parents=True, exist_ok=True)
                destination.write_bytes((ROOT / file).read_bytes())
            for edit in case.edits:
                harness.edit_source(tree, edit)
            harness.instrument(tree, "preflight", case)
    print(f"profile-mutants-preflight:{len(CASES)}/{len(CASES)}", flush=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument(
        "--list",
        action="store_true",
        help="list registered source cells without building",
    )
    mode.add_argument(
        "--preflight",
        action="store_true",
        help="verify source edit bindings without building",
    )
    args = parser.parse_args()
    assert len(CASES) == 33, "profile mutant inventory drift"
    if args.list:
        for case in CASES:
            print(f"{case.label}: {case.target}::{case.test}")
        return
    if args.preflight:
        preflight()
        return
    preflight()
    harness.ROOT = ROOT
    harness.EVIDENCE = ROOT / ".artifacts/profile-mutants"
    harness.CASES = CASES
    harness.BASELINE_TARGETS = [
        "lib",
        "multi_profile_identity",
        "profile_grants",
        "profile_outbound",
        "serving_profiles",
    ]
    harness.NONCE_TEST = "profile_build_nonce_receipt"
    harness.main()
    print("profile-mutants-complete:33/33", flush=True)


if __name__ == "__main__":
    main()
