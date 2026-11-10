"""Broker authority and fixture oracles using the fresh-artifact mutation harness."""

from pathlib import Path

import events_mutants as harness
from events_mutants import Case, Edit

ROOT = Path(__file__).resolve().parents[1]
OWNED = "broker::tests::broker_full_custody_requires_origin_correlation_owner_revision_retention_and_size"
MCP = "tests/broker_bridge.rs"
source = (ROOT / "src/serving.rs").read_text()
start = source.index("let mut result = recovery::dispatch(", source.index("let status_store_file ="))
lookup = source.index("let broker_result = if let (Some(config), Some(id)) =", start)
end = source.index("match broker_result {", lookup)
current = source[start:end]
stale = source[lookup:end] + source[start:lookup]

CASES = [
    Case("origin", "lib", OWNED, "src/broker.rs", (Edit("src/reads.rs", "if origin.id.is_none() && origin.service.as_deref() == Some(service) && origin.node == node", "if true"),)),
    Case("correlation", "lib", OWNED, "src/broker.rs", (Edit("src/reads.rs", "AND c.in_reply_to=:correlation", "AND (:correlation IS NOT NULL)"),)),
    Case("result-byte-bound", "lib", OWNED, "src/broker.rs", (Edit("src/reads.rs", "length(CAST(c.text AS BLOB))<=:max_bytes", ":max_bytes>0"),)),
    Case("selected-grant", "broker_bridge", "gist_advertising_and_dispatch_require_selected_grant_and_exact_current_target", MCP, (Edit("src/broker.rs", "grant.grant_id == selected", "true"),)),
    Case("framed-byte-bound", "broker_bridge", "broker_complete_encoded_request_bound_and_authentication_refuse_before_publication", MCP, (Edit("src/outbound.rs", "if !limits.text_fits(&framed_text) {", "if false {"), Edit("src/outbound.rs", "if !limits.text_fits(&reservation.framed_text) {", "if false {"))),
    Case("detached-broker-dispatch", "broker_bridge", "cancelling_broker_handler_keeps_the_accepted_submission_owned_by_the_worker", MCP, (Edit("src/serving.rs", "tasks.spawn(broker_work);", "broker_work.await;"),)),
    Case("final-result-authority", "broker_bridge", "broker_status_rechecks_send_ceiling_at_the_final_result_read", MCP, (Edit("src/serving.rs", current, stale),)),
    Case("post-send-deadline-label", "broker_bridge", "post_send_deadline_is_unknown_and_status_never_resubmits", MCP, (Edit("src/outbound.rs", "            Ok(Outcome::Unknown)\n        }\n    }?;", "            Err(Error::Deadline)\n        }\n    }?;"),)),
    Case("confirmed-recovery-phase", "broker_bridge", "confirmed_broker_recovery_failures_never_claim_no_submission", MCP, (Edit("src/serving.rs", "confirmed_submission = true;", "confirmed_submission = false;"),)),
    Case("authorized-deadline-response", "broker_bridge", "authorized_ack_deadline_has_body_without_claiming_rollback", MCP, (Edit("src/serving.rs", "tool_unavailable(&context.id, false)", "unavailable()"),)),
    Case("fixture-retry-new-id", "broker_bridge", "first_call_recovery_retries_identical_requests_after_pending", MCP, (Edit(MCP, "let retry = request.clone();", 'let mut retry = request.clone(); retry["params"]["arguments"]["request_id"] = serde_json::json!(format!("{}-new", original_id.as_str().unwrap()));'),)),
    Case("fixture-list-budget", "list", "xmsg_list_returns_only_permitted_send_targets_with_live_status_and_never_unpermitted", "tests/list.rs", (Edit("tests/common/serving_fixture.rs", "pub const HAPPY_DISPATCH_TIMEOUT_MS: u64 = 5000;", "pub const HAPPY_DISPATCH_TIMEOUT_MS: u64 = 1000;"),)),

]


def main():
    assert len(CASES) == 12, "broker mutant inventory drift"
    harness.ROOT = ROOT
    harness.EVIDENCE = ROOT / ".artifacts/broker-mutants"
    harness.CASES = CASES
    harness.BASELINE_TARGETS = ["lib", "broker_bridge", "list"]
    harness.NONCE_TEST = "broker_build_nonce_receipt"
    harness.main()
    print("broker-mutants-complete:12/12", flush=True)


if __name__ == "__main__":
    main()
