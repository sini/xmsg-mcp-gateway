"""Local OAuth authority source mutants; reuse fresh-artifact assertion controls."""

import argparse
import tempfile
from pathlib import Path

import events_mutants as harness
from events_mutants import Case, Edit

ROOT = Path(__file__).resolve().parents[1]
STORE = "src/authorization_server/store.rs"
CLOCK = "src/authorization_server/clock.rs"
LIVE = "src/authorization_server/liveness.rs"
HTTP = "src/authorization_server/protocol.rs"
TESTS = "src/authorization_server/tests.rs"


def case(label, test, *edits):
    return Case(
        label,
        "lib",
        "authorization_server::tests::" + test,
        "src/authorization_server/property_tests.rs"
        if test.startswith("properties::")
        else TESTS,
        tuple(edits),
    )


CASES = [
    case(
        "access-expiry",
        "admission_marks_successor_once_and_rechecks_revoked_expired_idle_absolute_and_grant",
        Edit(
            STORE,
            "expires <= now",
            "false",
            "fn admit_in_store(",
            "fn delivery_read_due(",
        ),
    ),
    case(
        "family-absolute",
        "admission_marks_successor_once_and_rechecks_revoked_expired_idle_absolute_and_grant",
        Edit(STORE, "now >= f.absolute", "false", "fn live_family(", "fn admit("),
    ),
    case(
        "family-idle",
        "admission_marks_successor_once_and_rechecks_revoked_expired_idle_absolute_and_grant",
        Edit(
            STORE,
            "now >= f.refreshed.saturating_add(self.config.refresh_idle_secs)",
            "false",
            "fn live_family(",
            "fn admit(",
        ),
    ),
    case(
        "grant-enabled",
        "admission_marks_successor_once_and_rechecks_revoked_expired_idle_absolute_and_grant",
        Edit(
            STORE,
            "AND enabled=1",
            "AND enabled IN (0,1)",
            "fn authority(",
            "fn local_authority(",
        ),
    ),
    case(
        "code-pkce",
        "failed_exchange_rolls_back_code_use_but_successful_replay_revokes_family",
        Edit(
            STORE, "challenge != expected", "false", "fn exchange(", "async fn refresh("
        ),
    ),
    case(
        "code-resource",
        "redirects_are_byte_exact_and_resource_mismatch_never_consumes_code",
        Edit(
            STORE,
            "resource.is_some_and(|r| r != self.binding.resource)",
            "false",
            "fn exchange(",
            "async fn refresh(",
        ),
    ),
    case(
        "code-expiry",
        "code_expiry_and_revision_fence_fail_without_consumption",
        Edit(STORE, "expires <= now", "false", "fn exchange(", "async fn refresh("),
        Edit(
            STORE,
            "AND expires_at>?2",
            "AND ?2 IS NOT NULL",
            "fn exchange(",
            "async fn refresh(",
        ),
    ),
    case(
        "retry-window",
        "superseded_refresh_is_reuse_and_old_rotated_refresh_expires_at_31_seconds",
        Edit(STORE, "now - t > 30", "now - t > 300"),
    ),
    case(
        "successor-use",
        "successor_access_use_prevents_lost_response_retry",
        Edit(
            STORE, "used.is_some()", "false", "async fn refresh(", "fn rotation_limit("
        ),
    ),
    case(
        "stale-liveness-positive",
        "stale_liveness_never_replaces_newer_evidence_or_revives_revoked_family",
        Edit(
            STORE,
            "AND liveness_applied<?3",
            "",
            "            Outcome::Positive =>",
            "            other =>",
        ),
    ),
    case(
        "negative-expiry",
        "liveness_negative_first_and_null_visibility_matrix",
        Edit(LIVE, "*t<=now", "false"),
    ),
    case(
        "negative-validity",
        "liveness_negative_first_and_null_visibility_matrix",
        Edit(LIVE, "*t>now", "false"),
    ),
    case(
        "negative-group",
        "liveness_negative_first_and_null_visibility_matrix",
        Edit(LIVE, "!groups.iter().any(|g|g==group)", "false"),
    ),
    case(
        "canary-visibility",
        "liveness_negative_first_and_null_visibility_matrix",
        Edit(LIVE, "canary.iter().any(|a| !matches!(a, Attribute::Date(_)))", "false"),
    ),
    case(
        "clock-tolerance",
        "tolerated_three_second_step_allows_refresh_and_code_exchange",
        Edit(CLOCK, "high.value.saturating_sub(5)", "high.value"),
    ),
    case(
        "clock-global-revoke",
        "rollback_revokes_persistently_and_mints_wait_for_catchup",
        Edit(
            CLOCK,
            "WHERE revoked_at IS NULL",
            "WHERE ?1 IS NULL",
            "if rollback {",
            "} else {",
        ),
    ),
    case(
        "clock-sqlite-memory-lock",
        "clock_fence_never_holds_memory_lock_across_sqlite_wait",
        Edit(
            CLOCK,
            "        let result = (|| {",
            "        let held_memory=self.high.lock().unwrap();\n        let result = (|| {",
        ),
        Edit(
            CLOCK,
            "        {\n            let mut high = self.high.lock()",
            "        drop(held_memory);\n        {\n            let mut high = self.high.lock()",
            "let result = (|| {",
            "        result?;",
        ),
    ),
    case(
        "clock-rollback-cache",
        "rollback_of_clock_persistence_does_not_advance_committed_cache",
        Edit(CLOCK, " && autonomous && (write || rollback)", " && (write || rollback)"),
    ),
    case(
        "metadata-rfc9207",
        "actual_listener_serves_as_metadata_host_guards_no_store_and_local_identity",
        Edit(
            HTTP,
            '"response_types_supported":["code"]',
            '"authorization_response_iss_parameter_supported":true,"response_types_supported":["code"]',
        ),
    ),
    case(
        "client-secret",
        "exact_client_authentication_applies_to_token_and_revoke",
        Edit(HTTP, "== 0", "== 0 || true", "fn authenticated(", "fn authorize("),
    ),
]


GRANTS = "src/grants.rs"
SERVING = "src/serving.rs"
EVENTS = "src/events.rs"
DISPATCH = "src/event_dispatch.rs"
AUTH = "src/auth.rs"

CASES += [
    case(
        "log-access-secret",
        "authorization_flow_secret_census_covers_trace_sql_values_and_sqlite_file_bytes",
        Edit(
            STORE,
            'let access = random("xgw_at_")?;',
            'let access = random("xgw_at_")?; tracing::debug!(credential=access.as_str(),"unsafe secret");',
        ),
    ),
    case(
        "raw-access-storage",
        "authorization_flow_secret_census_covers_trace_sql_values_and_sqlite_file_bytes",
        Edit(STORE, "hash(&access),f.id", "access,f.id"),
        Edit(
            STORE,
            "let digest = hash(token);",
            "let digest = token.to_owned();",
            "fn admit_in_store(",
            "fn delivery_read_due(",
        ),
    ),
    case(
        "persist-pending-verifier",
        "authorization_flow_secret_census_covers_trace_sql_values_and_sqlite_file_bytes",
        Edit(
            HTTP,
            "            runtime.pending.insert(",
            '            self.store()?.connection.execute_batch("CREATE TABLE unsafe_pending(value TEXT)")?; self.store()?.connection.execute("INSERT INTO unsafe_pending VALUES(?1)",[&verifier])?;\n            runtime.pending.insert(',
        ),
    ),
    case(
        "log-oauth-uri",
        "authorization_flow_secret_census_covers_trace_sql_values_and_sqlite_file_bytes",
        Edit(
            SERVING,
            "route=route.as_str(),method=method.as_str()",
            'route=format!("{route}?{query}").as_str(),method=method.as_str()',
        ),
    ),
    case(
        "retry-once",
        "exact_30_second_retry_once_only_and_pruned_predecessor_rules",
        Edit(
            STORE,
            "retried.is_some()",
            "false",
            "async fn refresh(",
            "fn rotation_limit(",
        ),
    ),
    case(
        "replay-code-family-revoke",
        "failed_exchange_rolls_back_code_use_but_successful_replay_revokes_family",
        Edit(
            STORE,
            "WHERE id=?1",
            "WHERE ?1 IS NULL",
            "fn exchange(",
            "async fn refresh(",
        ),
    ),
    case(
        "failure-advances-liveness",
        "nonpositive_liveness_status_timeout_and_malformed_arms_never_refresh_evidence",
        Edit(
            STORE,
            "SET last_liveness_outcome=?2,liveness_applied=?3",
            "SET last_liveness_outcome=?2,liveness_applied=?3,liveness_ok_at=?4",
        ),
        Edit(
            STORE,
            "params![id,other.text(),ticket]",
            "params![id,other.text(),ticket,now]",
        ),
    ),
    case(
        "negative-loses-to-newer-ticket",
        "competing_liveness_results_follow_ticket_order_and_negative_never_loses",
        Edit(
            STORE,
            "WHERE id=?1 AND revoked_at IS NULL",
            "WHERE id=?1 AND revoked_at IS NULL AND liveness_applied<?3",
            "            Outcome::Negative =>",
            "            Outcome::Positive =>",
        ),
    ),
    case(
        "family-scope",
        "family_binding_scope_and_steady_state_readonly_admission_are_enforced",
        Edit(STORE, "!scopes_cover(&f.scope, &self.scopes)", "false"),
    ),
    case(
        "family-client",
        "family_binding_scope_and_steady_state_readonly_admission_are_enforced",
        Edit(STORE, "f.client != self.binding.hosted_client", "false"),
    ),
    case(
        "family-subject",
        "family_binding_scope_and_steady_state_readonly_admission_are_enforced",
        Edit(STORE, "f.subject != self.binding.subject", "false"),
    ),
    case(
        "family-resource",
        "family_binding_scope_and_steady_state_readonly_admission_are_enforced",
        Edit(STORE, "f.resource != self.binding.resource", "false"),
    ),
    case(
        "cutover-acceptance",
        "cutover_acceptance_defers_old_scope_without_ack_then_accepts_same_delivery_on_new_scope",
        Edit(
            "src/custody.rs", "selected.is_some_and(|id| id != scope.grant_id)", "false"
        ),
    ),
    case(
        "cutover-startup",
        "cutover_acceptance_defers_old_scope_without_ack_then_accepts_same_delivery_on_new_scope",
        Edit(
            STORE,
            "Some(expected) != selected",
            "false",
            "fn validate_cutover_selection(",
            "fn selected_cutover_grant(",
        ),
    ),
    case(
        "captured-policy",
        "admitted_send_uses_its_policy_snapshot_after_policy_changes",
        Edit(
            AUTH,
            "identity.admission_policy = Some(admitted.policy);",
            "identity.admission_policy = None;",
        ),
    ),
    case(
        "subscription-fresh",
        "subscribe_and_renew_keep_fresh_revalidation_and_verify_then_write",
        Edit(
            EVENTS,
            "        self.fresh(identity, token, &authority).await?;",
            "",
            "pub async fn subscribe(",
            "pub async fn unsubscribe(",
        ),
    ),
    case(
        "subscription-absolute-clamp",
        "family_subscription_expiry_is_clamped_to_absolute_and_idle_bounds",
        Edit(
            STORE,
            ".min(f.absolute)",
            "",
            "fn subscription_expiry(",
            "fn verify_family(",
        ),
    ),
    case(
        "subscription-idle-clamp",
        "family_subscription_expiry_is_clamped_to_absolute_and_idle_bounds",
        Edit(
            STORE,
            ".min(f.refreshed.saturating_add(self.config.refresh_idle_secs))",
            "",
            "fn subscription_expiry(",
            "fn verify_family(",
        ),
    ),
    case(
        "dispatch-latest-outcome",
        "latest_outage_controls_delivery_grace_even_without_a_new_mint",
        Edit(
            STORE,
            "access_expires_at,last_liveness_outcome,revoked_at,revoked_reason FROM oauth_families",
            "access_expires_at,CASE WHEN last_mint_graced=1 THEN 'unavailable' ELSE 'positive' END,revoked_at,revoked_reason FROM oauth_families",
        ),
    ),
    case(
        "issuer-root",
        "issuer_is_root_without_query_and_trailing_root_slash_composes_working_endpoints",
        Edit(HTTP, 'issuer.path() != "/" || issuer.query().is_some()', "false"),
    ),
    case(
        "clock-partial-revoke",
        "first_clock_detection_revokes_every_live_family_before_any_later_token_check",
        Edit(
            CLOCK,
            "WHERE revoked_at IS NULL",
            "WHERE id=(SELECT id FROM oauth_families WHERE revoked_at IS NULL LIMIT 1)",
            "if rollback {",
            "} else {",
        ),
    ),
]

CASES += [
    case(
        "code-revision",
        "code_expiry_and_revision_fence_fail_without_consumption",
        Edit(STORE, "self.authority(&tx, &grant)?.revision != revision", "false"),
    ),
    case(
        "callback-revision",
        "pending_state_is_single_use_revision_bound_and_lost_on_restart",
        Edit(STORE, "self.authority(&tx, &authority.grant_id)? != *authority", "false"),
    ),
    case(
        "authorize-redirect",
        "all_redirect_difference_arms_refuse_and_token_redirect_is_bound_to_code",
        Edit(
            HTTP, "!self.config.client.redirect_uris.iter().any(|u| u == uri)", "false"
        ),
    ),
    case(
        "token-redirect",
        "all_redirect_difference_arms_refuse_and_token_redirect_is_bound_to_code",
        Edit(STORE, "bound_redirect != redirect", "false"),
    ),
    case(
        "pkce-method",
        "mandatory_s256_and_distinct_token_kinds_refuse_without_authority_or_pending_state",
        Edit(HTTP, 'field(&fields, "code_challenge_method")? != "S256"', "false"),
    ),
    case(
        "pending-cap",
        "pending_eviction_rate_bucket_and_code_pkce_boundaries",
        Edit(HTTP, "runtime.pending.len() >= self.config.pending_max", "false"),
    ),
    case(
        "authorize-rate",
        "pending_eviction_rate_bucket_and_code_pkce_boundaries",
        Edit(HTTP, "state.tokens < 1.0", "false"),
    ),
    case(
        "family-cap",
        "family_cap_evicts_least_recently_refreshed_not_oldest_created",
        Edit(
            STORE,
            "ORDER BY last_refresh_at DESC,rowid DESC LIMIT -1 OFFSET ?3",
            "ORDER BY created_at DESC,rowid DESC LIMIT -1 OFFSET ?3",
        ),
    ),
    case(
        "rotation-cap",
        "pruning_refresh_rows_never_resets_rolling_rotation_cap",
        Edit(STORE, "count >= self.config.rotations_per_hour as i64", "false"),
    ),
    case(
        "refresh-prune",
        "properties::retention_statistics_preserve_rate_caps_and_pruned_tokens_do_not_revoke_or_write",
        Edit(STORE, "self.config.max_refresh_rows as i64", "10000i64"),
    ),
    case(
        "grace-bound",
        "grace_is_bounded_freezes_positive_time_and_preserves_current_on_refusal",
        Edit(
            STORE,
            ".saturating_add(self.config.liveness.grace_secs)",
            ".saturating_add(self.config.liveness.grace_secs + 3600)",
            "fn expiry(",
            "fn pair(",
        ),
    ),
    case(
        "grace-60",
        "grace_is_bounded_freezes_positive_time_and_preserves_current_on_refusal",
        Edit(STORE, "if grace && expires <= now.saturating_add(60)", "if false"),
    ),
    case(
        "liveness-first-mint",
        "first_code_and_access_expiry_use_liveness_start_not_completion_time",
        Edit(
            HTTP,
            "                start,\n            )",
            "                self.clock.wall(),\n            )",
        ),
    ),
    case(
        "callback-skip-liveness",
        "complete_liveness_table_is_consistent_at_callback_and_refresh",
        Edit(
            HTTP, "match self.liveness.read(start).await {", "match Outcome::Positive {"
        ),
    ),
    case(
        "refresh-skip-liveness",
        "complete_liveness_table_is_consistent_at_callback_and_refresh",
        Edit(STORE, "self.check_liveness(&id, false).await?;", ""),
    ),
    case(
        "dispatch-600",
        "dispatcher_liveness_trigger_includes_exactly_600_seconds",
        Edit(
            STORE, "bound.saturating_sub(now) <= 600", "bound.saturating_sub(now) < 600"
        ),
    ),
    case(
        "dispatch-read-cap",
        "slow_family_liveness_allows_disable_to_complete_and_due_tick_rate_caps_reads",
        Edit(STORE, "liveness_read_at<=?2-300", "liveness_read_at<=?2"),
    ),
    case(
        "dispatch-lease-before-read",
        "slow_family_liveness_allows_disable_to_complete_and_due_tick_rate_caps_reads",
        Edit(
            DISPATCH,
            "    if let Some(family) = &sub.family {",
            "    let early_lease = store.try_operation_lease(&sub.service)?;\n    if let Some(family) = &sub.family {",
            "pub(crate) async fn tick(",
            "    let Some(_lease)",
        ),
        Edit(
            DISPATCH,
            "    let Some(_lease) = store.try_operation_lease(&sub.service)? else {",
            "    drop(early_lease);\n    let Some(_lease) = store.try_operation_lease(&sub.service)? else {",
        ),
    ),
    case(
        "custody-read-effect",
        "custody_read_and_ack_recheck_effect_authority_without_partial_state",
        Edit(
            "src/reads.rs",
            "authority: identity.custody_authority(&store)?,",
            "authority: identity.admitted_authority().map(Ok).unwrap_or_else(|| store.authorize(identity))?,",
        ),
    ),
    case(
        "custody-ack-effect",
        "custody_read_and_ack_recheck_effect_authority_without_partial_state",
        Edit(
            "src/recovery.rs",
            "Request::Ack(_) => identity.custody_authority(&store)?,",
            "Request::Ack(_) => identity.admitted_authority().map(Ok).unwrap_or_else(|| store.authorize(identity))?,",
        ),
    ),
    case(
        "clock-restart",
        "restart_before_first_rollback_detection_uses_persisted_clock_and_revokes_all_families",
        Edit(
            CLOCK,
            "                value,\n                persisted: value,",
            "                value: 0,\n                persisted: value,",
        ),
        Edit(
            CLOCK,
            "high.value = high.value.max(stored).max(wall);",
            "high.value = high.value.max(wall);",
        ),
    ),
    case(
        "clock-catchup",
        "rollback_state_survives_restart_and_a_later_within_tolerance_catchup_step",
        Edit(
            CLOCK,
            "SELECT value,rollback_until FROM clock_hw WHERE id=1",
            "SELECT value,0 FROM clock_hw WHERE id=1",
            "pub fn new(",
            "pub fn observe(",
        ),
        Edit(
            CLOCK,
            "high.blocked_until = high.blocked_until.max(blocked);",
            "high.blocked_until = high.blocked_until;",
        ),
    ),
    case(
        "auth-reject-observation",
        "authorization_flow_secret_census_covers_trace_sql_values_and_sqlite_file_bytes",
        Edit(
            HTTP,
            'tracing::info!(target: "gateway_oauth_authentication", class = "invalid_client", "OAuth authentication refused");',
            "",
        ),
    ),
]

CASES += [
    case(
        "reuse-family-update",
        "properties::thirty_two_current_presentations_keep_one_current_row_and_revoke_after_one_retry",
        Edit(
            STORE,
            "WHERE id=?1 AND revoked_at IS NULL",
            "WHERE ?1 IS NULL",
            "        if superseded.is_some()",
            "        if rotated.is_some()",
        ),
    ),
    case(
        "retry-supersede",
        "refresh_retry_supersedes_successor_and_reuse_revokes_whole_family",
        Edit(
            STORE,
            "SET superseded_at=?2 WHERE hash=?1 AND rotated_at IS NULL AND superseded_at IS NULL",
            "SET superseded_at=NULL WHERE hash=?1 AND ?2 IS NOT NULL AND rotated_at IS NULL AND superseded_at IS NULL",
        ),
        Edit(
            STORE,
            "UPDATE oauth_access_tokens SET revoked_at=?2 WHERE refresh_hash=?1",
            "UPDATE oauth_access_tokens SET revoked_at=NULL WHERE refresh_hash=?1 AND ?2 IS NOT NULL",
        ),
    ),
    case(
        "successor-used-mark",
        "successor_access_use_prevents_lost_response_retry",
        Edit(
            STORE,
            "SET successor_used_at=COALESCE(successor_used_at,?2) WHERE successor_hash=?1",
            "SET successor_used_at=NULL WHERE successor_hash=?1 AND ?2 IS NOT NULL",
            "fn admit_in_store(",
            "fn delivery_read_due(",
        ),
    ),
    case(
        "grant-disable-families",
        "grant_disable_revokes_family_without_breaking_legacy_store",
        Edit(
            GRANTS,
            "WHERE grant_id=?1",
            "WHERE ?1 IS NULL",
            "if !enabled && version >= crate::authorization_server::SCHEMA_VERSION",
            "        let events_change",
        ),
    ),
    case(
        "grant-disable-version",
        "grant_disable_revokes_family_without_breaking_legacy_store",
        Edit(
            GRANTS,
            "!enabled && version >= crate::authorization_server::SCHEMA_VERSION",
            "!enabled",
        ),
    ),
    case(
        "redirect-prefix",
        "all_redirect_difference_arms_refuse_and_token_redirect_is_bound_to_code",
        Edit(HTTP, ".any(|u| u == uri)", ".any(|u| uri.starts_with(u))"),
    ),
    case(
        "redirect-normalize",
        "all_redirect_difference_arms_refuse_and_token_redirect_is_bound_to_code",
        Edit(
            HTTP,
            ".any(|u| u == uri)",
            ".any(|u| Url::parse(u).ok() == Url::parse(uri).ok())",
        ),
    ),
    case(
        "redirect-percent-decode",
        "all_redirect_difference_arms_refuse_and_token_redirect_is_bound_to_code",
        Edit(
            HTTP,
            ".any(|u| u == uri)",
            '.any(|u| u.replace("%2F","/") == uri.replace("%2F","/"))',
        ),
    ),
    case(
        "code-single-use",
        "concurrent_code_exchanges_mint_exactly_once_then_replay_revokes",
        Edit(
            STORE,
            "if used.is_some() {",
            "if false {",
            "fn exchange(",
            "async fn refresh(",
        ),
        Edit(
            STORE,
            "WHERE code_hash=?1 AND used_at IS NULL AND expires_at>?2",
            "WHERE code_hash=?1 AND expires_at>?2",
        ),
    ),
    case(
        "callback-local-subject",
        "verified_foreign_login_cannot_be_mapped_to_local_owner",
        Edit(AUTH, "login.subject() != self.server.binding.subject", "false"),
    ),
    case(
        "success-redirect-iss",
        "authorize_exact_redirect_pkce_metadata_basic_and_upstream_callback",
        Edit(
            HTTP,
            'Ok(code) => redirect(&pending.redirect, &pending.state, "code", &code),',
            'Ok(code) => { let mut reply = redirect(&pending.redirect, &pending.state, "code", &code); reply.location.as_mut().unwrap().push_str("&iss=https%3A%2F%2Fgateway.example"); reply },',
        ),
    ),
    case(
        "no-family-follow-on",
        "dead_family_never_follows_live_same_owner_family_without_explicit_renewal",
        Edit(
            DISPATCH,
            "SELECT token_family FROM event_subscriptions WHERE id=?1",
            "SELECT (SELECT id FROM oauth_families WHERE grant_id=s.grant_id AND revoked_at IS NULL ORDER BY rowid DESC LIMIT 1) FROM event_subscriptions s WHERE s.id=?1",
        ),
    ),
    case(
        "dispatch-skip-read",
        "expired_access_still_wakes_through_bounded_family_liveness",
        Edit(
            DISPATCH,
            "if server.check_liveness(family, true).await.is_err() {",
            "if false {",
        ),
    ),
    case(
        "liveness-unavailable-positive",
        "complete_liveness_table_is_consistent_at_callback_and_refresh",
        Edit(
            LIVE,
            "return Outcome::Unavailable;",
            "return Outcome::Positive;",
            "pub(crate) fn decision(",
            "impl Liveness",
        ),
    ),
    case(
        "liveness-null-negative",
        "grace_and_denial_bounds_stop_tokens_and_delivery_without_inventing_deletion",
        Edit(
            LIVE,
            "return Outcome::Indeterminate;",
            "return Outcome::Negative;",
            "pub(crate) fn decision(",
            "impl Liveness",
        ),
    ),
    case(
        "owner-null-not-unrestricted",
        "complete_liveness_table_is_consistent_at_callback_and_refresh",
        Edit(
            LIVE,
            "if !entry_visible",
            "if owner[..2].iter().any(|a| matches!(a, Attribute::Null)) || !entry_visible",
        ),
    ),
    case(
        "access-type-prefix",
        "refused_local_admission_opens_once_without_second_grant_query_or_dispatch",
        Edit(
            AUTH, '!crate::authorization_server::token_shape(token, "xgw_at_")', "false"
        ),
    ),
    case(
        "clock-zero-tolerance",
        "repeated_small_clock_steps_document_accumulation_without_invented_bound",
        Edit(CLOCK, "wall < high.value.saturating_sub(5)", "wall < high.value"),
    ),
    case(
        "clock-small-step",
        "tolerated_three_second_step_allows_refresh_and_code_exchange",
        Edit(CLOCK, "wall < high.value.saturating_sub(5)", "wall < high.value"),
    ),
]

CASES += [
    case(
        "custody-read-revision",
        "current_enabled_grant_cannot_read_or_ack_fenced_prior_revision",
        Edit(
            "src/reads.rs",
            "ea.dispatch_revision=:revision",
            ":revision IS NOT NULL",
            "pub(crate) fn dispatch(",
            "pub(crate) fn correlated(",
        ),
    ),
    case(
        "custody-ack-revision",
        "current_enabled_grant_cannot_read_or_ack_fenced_prior_revision",
        Edit(
            "src/recovery.rs",
            "a.dispatch_revision=?5",
            "?5 IS NOT NULL",
            "Request::Ack(args) =>",
            "            let Some(event)",
        ),
    ),
    case(
        "reply-target-revision",
        "enabled_new_grant_cannot_reply_to_fenced_prior_custody",
        Edit(
            "src/outbound.rs",
            "ea.dispatch_revision=?9",
            "?9 IS NOT NULL",
            "fn reply_target(",
            "fn expire_reservation(",
        ),
    ),
    case(
        "advertised-filter",
        "hidden_legacy_jws_and_local_opaque_coexist_without_cross_grant_authority",
        Edit(
            AUTH,
            "self.advertised[index] && !issuers.contains(&profile.config.issuer)",
            "!issuers.contains(&profile.config.issuer)",
        ),
    ),
    case(
        "opaque-to-introspection",
        "hidden_legacy_jws_and_local_opaque_coexist_without_cross_grant_authority",
        Edit(
            AUTH,
            "if let Some(local) = &self.local {",
            "if let Some(local) = None::<&Arc<LocalProfile>> {",
            "pub async fn verify(",
            "struct ProfileVerifier",
        ),
        Edit(
            AUTH,
            "self.opaque_default.ok_or(Error::InvalidToken)?",
            "self.opaque_default.unwrap_or(0)",
        ),
    ),
    case(
        "cutover-observations",
        "cutover_busy_unread_observed_and_abandon_guard",
        Edit(
            STORE,
            "AND seen.event_id IS NULL",
            "",
            "let unread = |id: &str|",
            "        let old = unread(from)?;",
        ),
    ),
    case(
        "family-revoked",
        "refused_local_admission_opens_once_without_second_grant_query_or_dispatch",
        Edit(
            STORE,
            "if f.revoked.is_some()\n            || now >= f.absolute",
            "if false\n            || now >= f.absolute",
            "fn live_family(",
            "fn admit(",
        ),
    ),
    case(
        "admission-split-check-mark",
        "atomic_admission_holds_snapshot_until_mark_and_admits_no_post_change_snapshot",
        Edit(
            STORE,
            '            tracing::debug!(target:"gateway_oauth_admission",class="validated_snapshot",sampled_now=now,marking=write);',
            '            tx.commit()?;\n            tracing::debug!(target:"gateway_oauth_admission",class="validated_snapshot",sampled_now=now,marking=write);',
        ),
        Edit(
            STORE,
            "            if used.is_none() {",
            "            let tx=rusqlite::Transaction::new_unchecked(&store.connection, TransactionBehavior::Immediate)?;\n            if used.is_none() {",
            'tracing::debug!(target:"gateway_oauth_admission"',
            "    pub(crate) fn delivery_read_due(",
        ),
    ),
]

CASES += [
    case(
        "retry-idle-update",
        "refresh_retry_supersedes_successor_and_reuse_revokes_whole_family",
        Edit(
            STORE,
            "let pair = self.pair(&tx, &f, now)?;",
            "let pair = self.pair(&tx, &f, if rotated.is_some() { f.refreshed } else { now })?;",
            "async fn refresh(",
            "fn rotation_limit(",
        ),
    ),
    case(
        "retry-counted",
        "eleven_rotations_plus_retry_fill_the_twelve_per_hour_budget",
        Edit(
            STORE,
            '        tx.execute(\n            "INSERT INTO oauth_rotation_log VALUES(?1,?2)",\n            params![id, now],\n        )?;',
            '        if rotated.is_none() { tx.execute("INSERT INTO oauth_rotation_log VALUES(?1,?2)", params![id,now])?; }',
        ),
    ),
    case(
        "mark-rechecks-now",
        "first_use_upgrade_rechecks_now_before_marking_access",
        Edit(
            STORE,
            "        self.clock.observe(&store.connection, false)?;\n        let digest",
            "        let (_, snapshot_now)=self.clock.observe(&store.connection, false)?;\n        let digest",
        ),
        Edit(
            STORE,
            "Ok(time) => time,",
            "Ok((wall, _)) => (wall,snapshot_now),",
            "fn admit_in_store(",
            "fn delivery_read_due(",
        ),
    ),
]

CASES += [
    case(
        "mark-idempotent",
        "refresh_of_successor_does_not_implicitly_revoke_its_unused_access",
        Edit(
            STORE,
            "SET successor_used_at=COALESCE(successor_used_at,?2) WHERE successor_hash=?1",
            "SET successor_used_at=?2 WHERE successor_hash=?1 AND successor_used_at IS NULL",
            "fn admit_in_store(",
            "fn delivery_read_due(",
        ),
    ),
    case(
        "mark-rowcount",
        "suppressed_predecessor_mark_refuses_and_rolls_back_first_use",
        Edit(STORE, "if pred && changed != 1 {", "if false {"),
    ),
]

CASES += [
    case(
        "positive-on-revoked",
        "stale_liveness_never_replaces_newer_evidence_or_revives_revoked_family",
        Edit(
            STORE,
            "AND revoked_at IS NULL AND liveness_applied<?3",
            "AND liveness_applied<?3",
            "            Outcome::Positive =>",
            "            other =>",
        ),
    ),
    case(
        "negative-revoke-update",
        "dispatcher_positive_mints_no_access_and_negative_revokes_without_send_or_credential_park",
        Edit(
            STORE,
            "WHERE id=?1 AND revoked_at IS NULL",
            "WHERE ?1 IS NULL AND revoked_at IS NULL",
            "            Outcome::Negative =>",
            "            Outcome::Positive =>",
        ),
    ),
    case(
        "clock-no-revoke",
        "first_clock_detection_revokes_every_live_family_before_any_later_token_check",
        Edit(
            CLOCK,
            "WHERE revoked_at IS NULL",
            "WHERE revoked_at IS NULL AND ?1 IS NULL",
            "if rollback {",
            "} else {",
        ),
    ),
    case(
        "error-redirect-iss",
        "every_oauth_error_redirect_omits_issuer_parameter",
        Edit(
            HTTP,
            ".append_pair(kind, value)",
            '.append_pair("iss", "https://gateway.example").append_pair(kind, value)',
        ),
    ),
    case(
        "log-refresh-secret",
        "authorization_flow_secret_census_covers_trace_sql_values_and_sqlite_file_bytes",
        Edit(
            STORE,
            'let refresh = random("xgw_rt_")?;',
            'let refresh = random("xgw_rt_")?; tracing::debug!(credential=refresh.as_str(),"unsafe refresh secret");',
        ),
    ),
]

CASES += [
    case(
        "clock-pending-revoke",
        "failed_clock_revoke_write_stays_pending_through_catchup_and_repeated_sql_errors",
        Edit(
            CLOCK,
            "let rollback = high.revoke_ticket > high.revoked_ticket;",
            "let rollback = detected;",
        ),
        Edit(
            CLOCK,
            "if result.is_ok() && high.revoke_ticket != high.revoked_ticket {",
            "if false {",
        ),
    ),
    case(
        "clock-catchup-marker",
        "failed_clock_revoke_write_stays_pending_through_catchup_and_repeated_sql_errors",
        Edit(
            CLOCK,
            '                    if clear {\n                        tx.execute("UPDATE clock_hw SET rollback_until=0 WHERE id=1 AND rollback_until<=?1",[wall])?;\n                    }',
            "",
            "        let result = (|| {",
            "            } else {",
        ),
    ),
]

CASES += [
    case(
        "clock-stale-ticket",
        "handled_stale_clock_observer_never_revokes_a_post_catchup_new_family",
        Edit(CLOCK, "if needs_revoke {", "if true {"),
    ),
    case(
        "clock-ticket-before-lock",
        "handled_stale_clock_observer_never_revokes_a_post_catchup_new_family",
        Edit(
            CLOCK,
            "            if rollback {",
            "            if rollback {\n"
            + "                let needs_revoke = self\n                    .high\n                    .lock()\n                    .map_err(|_| Error::Unavailable)?\n                    .revoked_ticket\n                    < revoke_ticket;\n",
            "        let result = (|| {",
            "            } else {",
        ),
        Edit(
            CLOCK,
            "                let needs_revoke = self\n                    .high\n                    .lock()\n                    .map_err(|_| Error::Unavailable)?\n                    .revoked_ticket\n                    < revoke_ticket;\n",
            "",
            "                let tx = rusqlite::Transaction::new_unchecked(",
            "                let mut changed = 0;",
        ),
    ),
]

CASES += [
    case(
        "redirect-query-collision",
        "registered_redirects_reject_decoded_oauth_query_collisions_and_preserve_other_queries",
        Edit(HTTP, "reserved.contains(&key.as_ref())", "false"),
    )
]

CASES += [
    case(
        "visibility-before-negative",
        "complete_liveness_table_is_consistent_at_callback_and_refresh",
        Edit(
            LIVE,
            "    if matches!(&owner[0]",
            "    if !entry_visible\n        || matches!(owner[2], Attribute::Null)\n        || canary.iter().any(|a| !matches!(a, Attribute::Date(_)))\n    {\n        return Outcome::Indeterminate;\n    }\n    if matches!(&owner[0]",
        ),
        Edit(
            LIVE,
            "    if !entry_visible\n        || matches!(owner[2], Attribute::Null)\n        || canary.iter().any(|a| !matches!(a, Attribute::Date(_)))\n    {\n        return Outcome::Indeterminate;\n    }\n",
            "",
            "return Outcome::Unavailable;",
            "    Outcome::Positive",
        ),
    ),
    case(
        "member-null-ignored",
        "complete_liveness_table_is_consistent_at_callback_and_refresh",
        Edit(LIVE, "|| matches!(owner[2], Attribute::Null)", "|| false"),
    ),
    case(
        "unavailable-as-negative",
        "complete_liveness_table_is_consistent_at_callback_and_refresh",
        Edit(
            LIVE,
            "return Outcome::Unavailable;",
            "return Outcome::Negative;",
            "pub(crate) fn decision(",
            "impl Liveness",
        ),
    ),
    case(
        "callback-grace",
        "complete_liveness_table_is_consistent_at_callback_and_refresh",
        Edit(
            HTTP,
            "_ => return Err(Error::Unavailable),",
            "_ => {}",
            "match self.liveness.read(start).await {",
            "            if pending.resource",
        ),
    ),
    case(
        "refresh-outage-refused",
        "complete_liveness_table_is_consistent_at_callback_and_refresh",
        Edit(
            STORE,
            'let grace = f.outcome != "positive";',
            'let grace = f.outcome != "positive"; if grace { return Err(Error::Unavailable); }',
        ),
    ),
    case(
        "forbidden-consent-read",
        "consent_and_canary_membership_never_enter_liveness_requests_or_authority",
        Edit(
            LIVE,
            "    pub async fn read(&self, now: i64) -> Outcome {",
            '    pub async fn read(&self, now: i64) -> Outcome {\n        let _ = self.get(&self.config.person,Some("oauth2_consent_scope_map")).await;',
        ),
    ),
    case(
        "consent-participation",
        "consent_and_canary_membership_never_enter_liveness_requests_or_authority",
        Edit(
            LIVE,
            "    pub async fn read(&self, now: i64) -> Outcome {",
            '    pub async fn read(&self, now: i64) -> Outcome {\n        if !matches!(self.get(&self.config.person,Some("oauth2_consent_scope_map")).await,Ok(Value::Array(entries)) if !entries.is_empty()) { return Outcome::Negative; }',
        ),
    ),
    case(
        "forbidden-canary-membership-read",
        "consent_and_canary_membership_never_enter_liveness_requests_or_authority",
        Edit(
            LIVE,
            "    pub async fn read(&self, now: i64) -> Outcome {",
            '    pub async fn read(&self, now: i64) -> Outcome {\n        let _ = self.attribute(&self.config.canary_person,"memberof").await;',
        ),
    ),
    case(
        "canary-membership-authority",
        "consent_and_canary_membership_never_enter_liveness_requests_or_authority",
        Edit(
            LIVE,
            'self.attribute(&self.config.person, "memberof")',
            'self.attribute(&self.config.canary_person, "memberof")',
        ),
    ),
    case(
        "liveness-completion-time",
        "common_liveness_application_uses_network_observation_start_not_completion",
        Edit(
            STORE,
            "self.apply_liveness(id, n, start, outcome)?;",
            "self.apply_liveness(id, n, self.clock.wall(), outcome)?;",
        ),
    ),
]

CASES += [
    case(
        "pending-eviction-refused",
        "pending_eviction_rate_bucket_and_code_pkce_boundaries",
        Edit(
            HTTP,
            "            if runtime.pending.len() >= self.config.pending_max {\n                if let Some(old) = runtime\n                    .pending\n                    .iter()\n                    .min_by_key(|(_, p)| p.sequence)\n                    .map(|(k, _)| k.clone())\n                {\n                    runtime.pending.remove(&old);\n                }\n            }\n",
            "            if runtime.pending.len() >= self.config.pending_max { return Err(Error::RateLimited); }\n",
        ),
    ),
    case(
        "negative-as-graced-outage",
        "grace_and_denial_bounds_stop_tokens_and_delivery_without_inventing_deletion",
        Edit(
            LIVE,
            "return Outcome::Negative;",
            "return Outcome::Unavailable;",
            "pub(crate) fn decision(",
            "impl Liveness",
        ),
    ),
]

CASES += [
    case(
        "union-attachment-pre-revision",
        "local_as_attachment_union_preserves_success_and_pre_effect_custody_fence",
        Edit(
            "src/reads.rs",
            "identity.custody_authority(store)?",
            "store.authorize(identity)?",
            "pub(crate) fn owned_attachment(",
            "#[cfg",
        ),
    ),
    case(
        "union-attachment-post-revision",
        "local_as_attachment_union_rechecks_custody_after_bus_read",
        Edit(
            "src/reads.rs",
            "identity.custody_authority(store)?",
            "store.authorize(identity)?",
            "pub(crate) fn owned_attachment(",
            "#[cfg",
        ),
    ),
]


def preflight(cases):
    with tempfile.TemporaryDirectory(prefix="gateway-as-preflight-") as temporary:
        for item in cases:
            tree = Path(temporary) / item.label
            for filename in {
                "src/lib.rs",
                item.test_file,
                *(edit.file for edit in item.edits),
            }:
                target = tree / filename
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_bytes((ROOT / filename).read_bytes())
            for edit in item.edits:
                harness.edit_source(tree, edit)
            harness.instrument(tree, "preflight", item)
    print(
        f"authorization-server-mutants-preflight:{len(cases)}/{len(cases)}", flush=True
    )


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--list", action="store_true")
    parser.add_argument("--preflight", action="store_true")
    parser.add_argument(
        "--case", action="append", choices=[item.label for item in CASES]
    )
    args = parser.parse_args()
    selected = [item for item in CASES if not args.case or item.label in args.case]
    if args.list:
        for item in selected:
            print(f"{item.label}: {item.test}")
        return
    preflight(selected)
    if args.preflight:
        return
    harness.ROOT = ROOT
    harness.EVIDENCE = ROOT / ".artifacts/authorization-server-mutants"
    harness.CASES = selected
    harness.BASELINE_TARGETS = ["lib"]
    harness.NONCE_TEST = "authorization_server_build_nonce_receipt"
    harness.main()
    mode = "partial" if args.case else "complete"
    print(
        f"authorization-server-mutants-{mode}:{len(selected)}/{len(selected)}",
        flush=True,
    )


if __name__ == "__main__":
    main()
