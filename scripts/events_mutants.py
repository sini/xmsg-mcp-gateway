"""G5 production-source mutants; compilation, timeout and stale artifacts never kill."""

import hashlib
import json
import os
import re
import shutil
import signal
import subprocess
import tempfile
import time
import uuid
from dataclasses import dataclass
from pathlib import Path

from artifact_evidence import record
from transport_compat import invocation_evidence

ROOT = Path(__file__).resolve().parents[1]
EVIDENCE = ROOT / ".artifacts/g5-events-mutants"
BUDGET = 120
BUILD_BUDGET = 300
NONCE_TEST = "g5_events_build_nonce_receipt"
BASELINE_TARGETS = [
    "lib",
    "events_store",
    "events_rpc",
    "events_replay",
    "events_https",
    "events_contract",
    "webhook",
]


@dataclass(frozen=True)
class Edit:
    file: str
    needle: str
    replacement: str
    start: str = ""
    end: str = ""


@dataclass(frozen=True)
class Case:
    label: str
    target: str
    test: str
    test_file: str
    edits: tuple[Edit, ...]


DISPATCH = "src/event_dispatch.rs"
RECOVERY = "src/recovery.rs"
OWNED_TEST = "event_dispatch::tests::mailbox_revision_expiry_and_due_head_are_enforced_before_provider_calls"
ACK_TEST = "recovery::tests::responsibility_ack_is_owned_idempotent_contiguous_and_independent_of_subscription"
CASES = [
    Case(
        "candidate-mailbox",
        "lib",
        OWNED_TEST,
        DISPATCH,
        (
            Edit(
                DISPATCH,
                "AND c.mailbox=?2",
                "AND ?2 IS NOT NULL",
                "fn candidate(",
                "fn open_text(",
            ),
        ),
    ),
    Case(
        "candidate-revision",
        "lib",
        OWNED_TEST,
        DISPATCH,
        (
            Edit(
                DISPATCH,
                "AND a.dispatch_revision=?5",
                "AND ?5 IS NOT NULL",
                "fn candidate(",
                "fn open_text(",
            ),
        ),
    ),
    Case(
        "post-lease-candidate",
        "lib",
        "event_dispatch::concurrent_tests::stale_selection_is_rechecked_after_lease_before_introspection",
        DISPATCH,
        (
            Edit(
                DISPATCH,
                "    let Some(item) = candidate(&store, &sub, bus, mailbox, at)? else {\n        return Ok(Tick::Idle);\n    };",
                "    let item = _selected;",
            ),
        ),
    ),
    Case(
        "selected-grant-after-lease",
        "lib",
        "event_dispatch::authority_race_tests::selected_grant_is_rechecked_when_owner_switches_before_lease",
        DISPATCH,
        (
            Edit(
                DISPATCH,
                "    if sub.grant != events.selected_grant {\n        return Ok(Tick::Idle);\n    }",
                "    // Mutant: accept a replacement selected grant.",
                "// Selection precedes introspection",
                "    let Some(item) = candidate(",
            ),
        ),
    ),
    Case(
        "eligibility-after-provider",
        "lib",
        "event_dispatch::authority_race_tests::cached_body_is_not_delivered_if_content_expires_during_introspection",
        DISPATCH,
        (
            Edit(
                DISPATCH,
                "    let Some(current_item) = candidate(&store, &sub, bus, mailbox, at)? else {\n        return Ok(Tick::Idle);\n    };",
                "    let current_item = Candidate { id: item.id.clone(), sequence: item.sequence, attempts: item.attempts, body: item.body.clone() };",
            ),
        ),
    ),
    Case(
        "outcome-generation",
        "lib",
        "event_dispatch::tests::expiry_revocation_and_generation_fence_stop_dispatch_or_outcome",
        DISPATCH,
        (
            Edit(
                DISPATCH,
                "AND s.generation=?6 AND g.enabled=1",
                "AND ?6 IS NOT NULL AND g.enabled=1",
            ),
        ),
    ),
    Case(
        "retry-after-ignored",
        "lib",
        "event_dispatch::tests::retry_after_and_terminal_delivery_statuses_are_distinct",
        DISPATCH,
        (
            Edit(
                DISPATCH,
                "let next = retry_deadline(completed, delay, retry_after)?;",
                "let _ = retry_after;\n            let next = retry_deadline(completed, delay, None)?;",
            ),
        ),
    ),
    Case(
        "ack-mailbox",
        "lib",
        ACK_TEST,
        "src/recovery_tests.rs",
        (
            Edit(
                RECOVERY,
                "AND c.mailbox=?2",
                "AND ?2 IS NOT NULL",
                "let event: Option<String>",
                "            let Some(event)",
            ),
        ),
    ),
    Case(
        "ack-checkpoint-skips-gap",
        "lib",
        ACK_TEST,
        "src/recovery_tests.rs",
        (
            Edit(
                RECOVERY,
                "AND (?6 IS NULL OR o.seq<?6)",
                "AND (?6 IS NULL OR ?6 IS NOT NULL)",
            ),
        ),
    ),
    Case(
        "status-owner",
        "lib",
        "recovery::tests::uncertain_status_never_submits_or_reserves_and_scopes_both_operations",
        "src/recovery_tests.rs",
        (
            Edit(
                RECOVERY,
                "WHERE owner=?1 AND request_id=?2 AND sender=?3 AND grant_id=?4 ORDER BY operation",
                "WHERE ?1 IS NOT NULL AND request_id=?2 AND sender=?3 AND grant_id=?4 ORDER BY operation",
            ),
        ),
    ),
    Case(
        "first-enable-releases-ambiguous",
        "events_store",
        "first_enable_releases_only_proven_never_enabled_and_preserves_acceptance_revision",
        "tests/events_store.rs",
        (
            Edit(
                "src/event_store.rs",
                "AND a.acceptance_class='never_enabled' AND a.acceptance_enabled=0 AND a.acceptance_ever_enabled=0",
                "",
            ),
            Edit(
                "src/event_store.rs",
                "AND acceptance_class='never_enabled' AND acceptance_enabled=0 AND acceptance_ever_enabled=0",
                "",
            ),
        ),
    ),
    Case(
        "recovery-rpc-response-id",
        "lib",
        "serving::events_tests::production_rpc_and_session_poll_commit_ack_and_signed_owned_wake",
        "src/serving_events_tests.rs",
        (
            Edit(
                "src/serving.rs",
                "Ok(Ok(data)) => rpc_result(&id, tool_result(data)),",
                "Ok(Ok(data)) => rpc_result(&Value::Null, tool_result(data)),",
                'if matches!(call.name.as_str(), "xmsg_ack" | "xmsg_message_status") {',
                'if matches!(call.name.as_str(), "xmsg_inbox" | "xmsg_read_message")',
            ),
        ),
    ),
]


CASES.extend(
    [
        Case(
            "recovery-selected-grant",
            "lib",
            "recovery::tests::transaction_rechecks_selected_grant_for_ack_and_status",
            "src/recovery_tests.rs",
            (
                Edit(
                    RECOVERY, "if authority.grant_id != selected_grant {", "if false {"
                ),
            ),
        ),
        Case(
            "owner-rebind-selected-grant",
            "events_rpc",
            "configured_grant_cannot_rebind_or_replay_another_grants_subscription",
            "tests/events_rpc.rs",
            (
                Edit(
                    "src/events.rs",
                    "WHERE id=?1 AND grant_id=?2",
                    "WHERE id=?1 AND ?2 IS NOT NULL",
                    "    pub fn rebind(",
                    "    pub fn replay(",
                ),
            ),
        ),
        Case(
            "owner-replay-selected-grant",
            "events_rpc",
            "configured_grant_cannot_rebind_or_replay_another_grants_subscription",
            "tests/events_rpc.rs",
            (
                Edit(
                    "src/events.rs",
                    "WHERE id=?1 AND grant_id=?2",
                    "WHERE id=?1 AND ?2 IS NOT NULL",
                    "    pub fn replay(",
                ),
            ),
        ),
        Case(
            "failed-rotation-drops-previous-key",
            "events_rpc",
            "failed_rotation_refresh_cannot_discard_a_still_valid_previous_key",
            "tests/events_rpc.rs",
            (
                Edit(
                    "src/events.rs",
                    "if previous_secret != request.delivery.secret\n                && old.old_secret.is_some()",
                    "if false\n                && old.old_secret.is_some()",
                ),
            ),
        ),
        Case(
            "wrong-webhook-signing-key",
            "webhook",
            "standard_vector_dual_signatures_and_tampering",
            "tests/webhook.rs",
            (
                Edit(
                    "src/webhook.rs",
                    "standardwebhooks::Webhook::new(key)",
                    'standardwebhooks::Webhook::new("whsec_CQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQk=")',
                ),
            ),
        ),
        Case(
            "private-callback-address",
            "lib",
            "webhook::tests::all_dns_answers_must_be_public",
            "src/webhook.rs",
            (
                Edit(
                    "src/webhook.rs",
                    ".any(|address| !public_address(address.ip()))",
                    ".any(|_| false)",
                ),
            ),
        ),
        Case(
            "retry-changes-webhook-id",
            "lib",
            "event_dispatch::tests::signed_retry_preserves_identity_body_and_never_observes_work",
            DISPATCH,
            (
                Edit(
                    DISPATCH,
                    "        &item.id,",
                    '        if item.attempts > 0 { "fresh-retry-id" } else { &item.id },',
                    "    let result = crate::webhook::signed_post(",
                    "    let completed =",
                ),
            ),
        ),
        Case(
            "dispatcher-expiry-retains-preview",
            "lib",
            "event_dispatch::tests::expiry_redacts_cached_previews_without_inventing_receipt_or_observation",
            DISPATCH,
            (
                Edit(
                    DISPATCH,
                    "UPDATE custody_outbox SET body=NULL WHERE",
                    "UPDATE custody_outbox SET body=body WHERE",
                    "fn expire_history(",
                    "fn payload(",
                ),
            ),
        ),
        Case(
            "custody-expiry-retains-preview",
            "lib",
            "event_dispatch::tests::expiry_redacts_cached_previews_without_inventing_receipt_or_observation",
            DISPATCH,
            (
                Edit(
                    "src/custody.rs",
                    "UPDATE custody_outbox SET state='expired',body=NULL WHERE",
                    "UPDATE custody_outbox SET state='expired' WHERE",
                ),
            ),
        ),
        Case(
            "reply-dispatch-revision",
            "lib",
            "outbound::events_reply_tests::first_release_reply_requires_owned_current_dispatch_authority",
            "src/outbound.rs",
            (
                Edit(
                    "src/outbound.rs",
                    "AND ea.dispatch_revision=?9",
                    "AND ?9 IS NOT NULL",
                ),
            ),
        ),
    ]
)


CASES.extend([
    Case("policy-change-fences-events", "lib", "event_dispatch::policy_tests::policy_edit_preserves_subscription_pending_wakes_and_inflight_callback_outcome", "src/event_dispatch.rs", (
        Edit("src/outbound.rs", "crate::event_store::policy_changed(tx, id, revision, revision + 1)?;", "crate::event_store::revision_changed(tx, id)?;"),
    )),
    Case("policy-promotes-unapproved-history", "events_store", "policy_revision_carries_only_current_authority_without_mutating_wakes_or_subscriptions", "tests/events_store.rs", (
        Edit("src/event_store.rs", "WHERE dispatch_revision=?2 AND event_id IN", "WHERE ?2 IS NOT NULL AND event_id IN"),
    )),
])

CASES.append(Case(
    "events-callback-url-log", "lib",
    "event_observability_tests::committed_fence_dead_letter_and_consumer_state_are_private_and_read_only",
    "src/event_observability_tests.rs", (
        Edit("src/events.rs", "let url = webhook::callback_url(&request.delivery.url)?.to_string();", "let url = webhook::callback_url(&request.delivery.url)?.to_string();\n        tracing::info!(target: \"gateway_events\", url = %url, \"callback URL\");", start="pub async fn subscribe(", end="pub async fn unsubscribe("),
    ),
))

def sha(file):
    return hashlib.sha256(file.read_bytes()).hexdigest()


def run(args, *, cwd, env, label, budget=BUDGET):
    started = time.monotonic()
    child = subprocess.Popen(
        args,
        cwd=cwd,
        env=env,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        start_new_session=True,
    )
    try:
        stdout, stderr = child.communicate(timeout=budget)
    except subprocess.TimeoutExpired:
        try:
            os.killpg(child.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        try:
            stdout, stderr = child.communicate(timeout=5)
        except subprocess.TimeoutExpired:
            child.stdout.close()
            child.stderr.close()
            child.wait(timeout=5)
            stdout, stderr = "", "output drain exceeded deadline"
        (EVIDENCE / f"{label}-timeout.log").write_text(stdout + stderr)
        raise RuntimeError(
            f"{label}: timed out (HARNESS ERROR, never a kill)"
        ) from None
    return {
        "status": child.returncode,
        "stdout": stdout,
        "stderr": stderr,
        "duration_seconds": time.monotonic() - started,
    }


def copy_source(tree):
    tree.mkdir()
    for name in ["Cargo.toml", "Cargo.lock", "rust-toolchain.toml"]:
        shutil.copyfile(ROOT / name, tree / name)
    for name in ["src", "tests", "ci"]:
        shutil.copytree(ROOT / name, tree / name)


def edit_source(tree, edit):
    file = tree / edit.file
    text = file.read_text()
    start = text.index(edit.start) if edit.start else 0
    end = text.index(edit.end, start + len(edit.start)) if edit.end else len(text)
    region = text[start:end]
    assert region.count(edit.needle) == 1, ("production mutation needle drift", edit)
    region = region.replace(edit.needle, edit.replacement, 1)
    file.write_text(text[:start] + region + text[end:])


def instrument(tree, nonce, case=None):
    library = tree / "src/lib.rs"
    library.write_text(
        library.read_text()
        + f"""\n#[cfg(test)]\n#[test]\nfn {NONCE_TEST}() {{ eprintln!("g5-events-build nonce={nonce}"); }}\n"""
    )
    if case is None:
        return None
    test = tree / case.test_file
    text = test.read_text()
    leaf = case.test.rsplit("::", 1)[-1]
    pattern = rf"(\b(?:async\s+)?fn\s+{re.escape(leaf)}\(\)\s*\{{)"
    marker = f"g5-events-case nonce={nonce} test={case.test}"
    text, count = re.subn(
        pattern, lambda match: match[0] + f'\n        eprintln!("{marker}");', text
    )
    assert count == 1, ("named test instrumentation drift", case.test)
    test.write_text(text)
    return marker


def build(tree, targets, env, label, *, refuse_cached=False):
    args = [
        "cargo",
        "test",
        "--locked",
        "--offline",
        "-j",
        "2",
        "--no-run",
        "--message-format=json",
    ]
    for target in dict.fromkeys(["lib", *targets]):
        args += ["--lib"] if target == "lib" else ["--test", target]
    result = run(args, cwd=tree, env=env, label=f"{label}-build", budget=BUILD_BUDGET)
    print(
        json.dumps(
            {
                "build": label,
                "status": result["status"],
                "duration_seconds": result["duration_seconds"],
                "budget_seconds": BUILD_BUDGET,
            }
        ),
        flush=True,
    )
    (EVIDENCE / f"{label}-build.log").write_text(result["stdout"] + result["stderr"])
    if result["status"]:
        raise RuntimeError(
            f"{label}: compilation failed (HARNESS ERROR, never a kill): {result['stderr'][-4000:]}"
        )
    executables = {}
    fresh = True
    for line in result["stdout"].splitlines():
        message = json.loads(line)
        if message.get("reason") != "compiler-artifact":
            continue
        target = message.get("target", {}).get("name")
        if target not in ["xmsg_mcp_gateway", *targets]:
            continue
        if not message.get("profile", {}).get("test") or not message.get("executable"):
            continue
        key = "lib" if target == "xmsg_mcp_gateway" else target
        fresh &= not message["fresh"]
        executables[key] = Path(message["executable"])
    assert set(executables) == set(["lib", *targets]), (label, executables)
    if not fresh:
        if refuse_cached:
            print(f"g5-events-cached-artifact:refused:{label}", flush=True)
            return None
        raise RuntimeError(f"{label}: stale compiled test artifact (HARNESS ERROR)")
    if refuse_cached:
        raise RuntimeError(f"{label}: cached artifact control unexpectedly rebuilt")
    for target, executable in executables.items():
        record(tree, executable, f"{label}/{target}")
    return executables


def execute(tree, executable, env, label, *, name=None, marker=None, red=False):
    args = [str(executable), "--nocapture"]
    if name is not None:
        args += ["--exact", name]
    invocation_evidence(args)
    result = run(args, cwd=tree, env=env, label=label)
    output = result["stdout"] + result["stderr"]
    (EVIDENCE / f"{label}.log").write_text(output)
    summaries = re.findall(
        r"test result: (?:ok|FAILED)\. (\d+) passed; (\d+) failed; (\d+) ignored; (\d+) measured; (\d+) filtered out",
        output,
    )
    assert len(summaries) == 1, (label, "missing or ambiguous Rust completion counts")
    passed, failed, ignored, measured, filtered = map(int, summaries[0])
    assert measured == 0, (label, "benchmark substitution")
    if marker:
        assert output.count(marker) == 1, (
            label,
            "missing or duplicate nonce",
            output[-4000:],
        )
    if red:
        expected = f"test {name} ... FAILED"
        assert result["status"] == 101 and expected in output, (
            label,
            "not the named-test RED",
            output[-6000:],
        )
        assert "test result: FAILED. 0 passed; 1 failed;" in output
        print(f"g5-events RED {label}: {expected}", flush=True)
    else:
        assert result["status"] == 0, (label, output[-6000:])
        assert "test result: ok." in output
        assert result["duration_seconds"] < BUDGET / 2, (
            label,
            "baseline/restored GREEN too slow",
        )
        if name is not None:
            assert "test result: ok. 1 passed; 0 failed; 0 ignored;" in output
        else:
            assert passed > 0 and failed == 0 and filtered == 0, (
                label,
                "baseline did not execute the complete target",
            )
        print(f"g5-events GREEN {label}", flush=True)
    summary = {
        key: value for key, value in result.items() if key not in ["stdout", "stderr"]
    }
    summary.update({"label": label, "test": name, "red": red, "budget_seconds": BUDGET})
    summary["counts"] = {
        "passed": passed,
        "failed": failed,
        "ignored": ignored,
        "measured": measured,
        "filtered": filtered,
    }
    print(json.dumps(summary), flush=True)
    return summary


def main():
    EVIDENCE.mkdir(parents=True, exist_ok=True)
    originals = {
        edit.file: sha(ROOT / edit.file) for case in CASES for edit in case.edits
    }
    results = []
    environment = {**os.environ, "CARGO_TARGET_DIR": str(EVIDENCE / "build")}
    with tempfile.TemporaryDirectory(prefix="gateway-g5-mutants-") as temporary:
        root = Path(temporary)
        control = root / "baseline"
        copy_source(control)
        nonce = uuid.uuid4().hex
        instrument(control, nonce)
        binaries = build(control, BASELINE_TARGETS, environment, "baseline")
        build(
            control, BASELINE_TARGETS, environment, "cached-control", refuse_cached=True
        )
        for target in BASELINE_TARGETS:
            results.append(
                execute(
                    control,
                    binaries[target],
                    environment,
                    f"baseline-{target}",
                    marker=f"g5-events-build nonce={nonce}"
                    if target == "lib"
                    else None,
                )
            )
        for index, case in enumerate(CASES):
            for red in [True, False]:
                label = f"{index + 1:02}-{case.label}-{'red' if red else 'restored'}"
                tree = root / label
                copy_source(tree)
                if red:
                    for edit in case.edits:
                        edit_source(tree, edit)
                production = {edit.file: sha(tree / edit.file) for edit in case.edits}
                nonce = uuid.uuid4().hex
                marker = instrument(tree, nonce, case)
                binaries = build(tree, [case.target], environment, label)
                execute(
                    tree,
                    binaries["lib"],
                    environment,
                    f"{label}-nonce",
                    name=NONCE_TEST,
                    marker=f"g5-events-build nonce={nonce}",
                )
                result = execute(
                    tree,
                    binaries[case.target],
                    environment,
                    label,
                    name=case.test,
                    marker=marker,
                    red=red,
                )
                result.update({"nonce": nonce, "production_source_sha256": production})
                results.append(result)
            for file, digest in originals.items():
                assert sha(ROOT / file) == digest, f"primary source changed: {file}"
    (EVIDENCE / "results.json").write_text(json.dumps(results, indent=2) + "\n")
    print(f"g5-events-mutants-complete:{len(CASES)}/{len(CASES)}", flush=True)


if __name__ == "__main__":
    main()
