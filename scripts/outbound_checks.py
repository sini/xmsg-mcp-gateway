"""Require the complete real-node outbound profile and deliberate skip refusals."""

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

MARKERS = (
    "child-control",
    "receipt-payload-policy-size",
    "crash-before",
    "crash-after",
    "expired-unknown",
    "disable-order",
    "inbound-concurrency",
    "owned-reply",
    "held-revision",
    "reservation-busy",
    "outcome-busy",
    "confirmed-reply-replay",
    "expired-stale-revision",
    "isolated-connection",
    "deadline-before-submit",
    "pending-recovery-deadline",
    "send-in-flight-deadline",
)


def require_complete(result):
    assert result.returncode == 0, (result.stdout, result.stderr)
    assert (
        "17 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out" in result.stdout
    ), "outbound profile count/skip mismatch"
    for marker in MARKERS:
        assert result.stdout.count(f"gateway-outbound-complete:{marker}") == 1, (
            f"outbound completion missing: {marker}"
        )


def main():
    pin = pins()
    binary = Path(os.environ["XMSG_GATEWAY_BIN"])
    executable = build_test(target="custody_outbound")
    result = live(executable, binary, pin["revision"])
    evidence = ROOT / ".artifacts/outbound"
    evidence.mkdir(parents=True, exist_ok=True)
    (evidence / "profile.log").write_text(result.stdout + result.stderr)
    require_complete(result)
    missing = live(
        executable,
        None,
        pin["revision"],
        case="crash_after_reservation_recovers_with_the_stored_key",
    )
    assert (
        missing.returncode == 101
        and "required pinned xmsg binary missing" in missing.stderr
    ), ("outbound missing-binary control escaped", failure_tail(missing))
    with tempfile.TemporaryDirectory(prefix="gateway-outbound-skip-") as directory:
        root = Path(directory)
        copy_fixture_tree(root)
        file = root / "tests/custody_outbound.rs"
        source = file.read_text()
        site = "async fn expired_uncertainty_never_blindly_retries() {"
        assert source.count(site) == 1
        file.write_text(source.replace(site, site + "\n    return;", 1))
        skipped = live(
            build_test(
                root,
                target="custody_outbound",
                target_dir=root / "target/skip",
            ),
            binary,
            pin["revision"],
        )
        assert skipped.returncode == 0, (
            "skip control failed before the guard",
            failure_tail(skipped),
        )
        refuse_cached_control(
            root, target="custody_outbound", target_dir=root / "target/skip"
        )
        try:
            require_complete(skipped)
        except AssertionError as error:
            assert "outbound completion missing: expired-unknown" in str(error)
        else:
            raise AssertionError(
                "outbound early-return control escaped completion guard"
            )
    print(
        "outbound missing-binary and early-return controls: expected refusals",
        flush=True,
    )
    print("outbound-checks-complete:17", flush=True)


if __name__ == "__main__":
    main()
