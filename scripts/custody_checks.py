"""Require every private-node custody oracle and its completion/skip controls."""

import os
import shutil
import tempfile
from pathlib import Path

from transport_compat import ROOT, build_test, failure_tail, live, pins

MARKERS = [
    "commit-before-ack",
    "oversized-refusal",
    "conflict-quarantine",
    "failed-transaction",
    "permanent-refusal-pressure",
    "retention",
    "mailbox-binding",
    "crash-helper-control",
    "crash-before",
    "crash-after",
    "conflict-pressure",
    "transient-capacity",
    "metadata-status",
    "metadata-bound",
    "real-upstream-expiry",
    "total-capacity-permanent",
    "byte-capacity",
    "idle-maintenance",
]


def require_complete(result):
    assert result.returncode == 0, (result.stdout, result.stderr)
    assert (
        "18 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out" in result.stdout
    ), "custody profile count/skip mismatch"
    for marker in MARKERS:
        assert result.stdout.count(f"gateway-custody-complete:{marker}") == 1, (
            f"custody completion missing: {marker}"
        )


def main():
    pin = pins()
    binary = Path(os.environ["XMSG_GATEWAY_BIN"])
    executable = build_test(target="custody_inbound")
    result = live(executable, binary, pin["revision"])
    evidence = ROOT / ".artifacts/custody"
    evidence.mkdir(parents=True, exist_ok=True)
    (evidence / "profile.log").write_text(result.stdout + result.stderr)
    require_complete(result)
    print("custody profile:18/18, zero ignored, all completion markers", flush=True)
    missing = live(
        executable,
        None,
        pin["revision"],
        case="process_crash_before_commit_leaves_redelivery",
    )
    assert (
        missing.returncode == 101
        and "required pinned xmsg binary missing" in missing.stderr
    ), ("custody missing-binary control was not refused", failure_tail(missing))
    with tempfile.TemporaryDirectory(
        prefix="gateway-custody-skip-control-"
    ) as directory:
        root = Path(directory)
        for name in ("Cargo.toml", "Cargo.lock"):
            shutil.copyfile(ROOT / name, root / name)
        for name in ("src", "tests", "ci"):
            shutil.copytree(ROOT / name, root / name, copy_function=shutil.copyfile)
        file = root / "tests/custody_inbound.rs"
        source = file.read_text()
        site = (
            "async fn a_delivery_larger_than_total_capacity_is_a_permanent_refusal() {"
        )
        assert source.count(site) == 1, "custody skip-control site drifted"
        file.write_text(source.replace(site, site + "\n    return;", 1))
        control = live(
            build_test(
                root,
                target="custody_inbound",
                target_dir=ROOT / "target/custody-controls",
            ),
            binary,
            pin["revision"],
        )
        assert control.returncode == 0, (
            "skip control did not reach completion guard",
            failure_tail(control),
        )
        try:
            require_complete(control)
        except AssertionError as error:
            assert "custody completion missing: total-capacity-permanent" in str(error)
        else:
            raise AssertionError(
                "custody early-return control escaped completion guard"
            )
    print(
        "custody missing-binary and early-return controls: expected refusals",
        flush=True,
    )
    print("custody-checks-complete:18", flush=True)


if __name__ == "__main__":
    main()
