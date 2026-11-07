"""Require the complete real-node messaging profile and observable skip refusals."""

import os
import tempfile
from pathlib import Path

from transport_compat import (
    ROOT,
    build_test,
    copy_fixture_tree,
    failure_tail,
    live,
    pins,
    refuse_cached_control,
)

MARKERS = [
    "mcp-request-id-policy",
    "handler-cancellation",
    "reply-ttl",
    "idempotency-ttl",
    "queue-capacity",
    "dedup-lifetime",
    "service-name",
    "registration-failure",
    "migration-budget",
    "strict-optional-profile",
    "fresh-empty-policy",
    "owned-reply",
    "scope-ceiling",
    "complete-framed-bound",
    "deadline-pending",
    "reported-body-bound",
    "daemon-recovery",
    "reconnect-limits-ledger",
    "in-flight-recovery",
    "durable-reconnect-publication",
    "expired-unknown",
    "same-tick-health",
    "healthy-send-pressure",
    "observation-ceiling",
    "graceful-observation",
    "pressure-receiver-control",
    "coalesced-store-trace",
    "ordered-store-trace",
]
DEADLINE = "handler_deadline_reports_pending_without_cancelling_accepted_work"
EMPTY_POLICY = "fresh_policy_is_empty_and_cannot_be_changed_by_mcp"


def require_complete(result, *, markers=None, filtered=0):
    markers = MARKERS if markers is None else markers
    if result.returncode:
        raise RuntimeError(("wiring profile failed", failure_tail(result)))
    expected = (
        f"test result: ok. {len(markers)} passed; 0 failed; 0 ignored; 0 measured; "
        f"{filtered} filtered out"
    )
    if expected not in result.stdout:
        raise RuntimeError("wiring profile count/skip mismatch")
    for marker in markers:
        if result.stdout.count(f"gateway-wiring-complete:{marker}") != 1:
            raise RuntimeError(f"wiring completion missing: {marker}")


def expected_refusal(result, expected, **kwargs):
    try:
        require_complete(result, **kwargs)
    except RuntimeError as error:
        if str(error) != expected:
            raise RuntimeError(
                ("wrong control refusal", str(error), failure_tail(result))
            ) from error
    else:
        raise RuntimeError("wiring completion control escaped the guard")


def main():
    if not MARKERS or len(set(MARKERS)) != len(MARKERS):
        raise RuntimeError("wiring profile marker inventory drift")
    pin = pins()
    binary = Path(os.environ["XMSG_GATEWAY_BIN"])
    executable = build_test(target="messaging")
    result = live(executable, binary, pin["revision"])
    evidence = ROOT / ".artifacts/wiring"
    evidence.mkdir(parents=True, exist_ok=True)
    (evidence / "profile.log").write_text(result.stdout + result.stderr)
    require_complete(result)
    print(f"wiring profile:{len(MARKERS)}/{len(MARKERS)}, zero ignored, all completion markers", flush=True)
    missing = live(executable, None, pin["revision"], case=EMPTY_POLICY)
    if (
        missing.returncode != 101
        or "required pinned xmsg binary missing" not in missing.stderr
    ):
        raise RuntimeError(
            ("wiring missing-binary control escaped", failure_tail(missing))
        )
    skipped = live(executable, binary, pin["revision"], skip=DEADLINE)
    if skipped.returncode:
        raise RuntimeError(
            ("missing-case control failed before count guard", failure_tail(skipped))
        )
    expected_refusal(skipped, "wiring profile count/skip mismatch")
    with tempfile.TemporaryDirectory(prefix="gateway-wiring-skip-") as directory:
        root = Path(directory)
        copy_fixture_tree(root)
        file = root / "tests/messaging.rs"
        source = file.read_text()
        site = f"async fn {EMPTY_POLICY}() {{"
        if source.count(site) != 1:
            raise RuntimeError("wiring early-return site drift")
        file.write_text(source.replace(site, site + "\n    return;", 1))
        target = root / "target/skip"
        control = build_test(root, target="messaging", target_dir=target)
        refuse_cached_control(root, target="messaging", target_dir=target)
        skipped = live(control, binary, pin["revision"], case=EMPTY_POLICY)
        if skipped.returncode:
            raise RuntimeError(
                (
                    "early-return control failed before marker guard",
                    failure_tail(skipped),
                )
            )
        expected_refusal(
            skipped,
            "wiring completion missing: fresh-empty-policy",
            markers=["fresh-empty-policy"],
            filtered=len(MARKERS) - 1,
        )
    print(
        "wiring missing-binary, missing-case and early-return controls: expected refusals",
        flush=True,
    )
    print(f"wiring-checks-complete:{len(MARKERS)}", flush=True)


if __name__ == "__main__":
    main()
