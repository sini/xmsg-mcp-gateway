"""Prove ceiled reservation windows and bounded acceptance-before-expiry sequencing."""

import argparse
import json
import os
import subprocess
import tempfile
import time
import uuid
from pathlib import Path

from artifact_evidence import record
from transport_compat import (
    ROOT,
    build_test,
    copy_fixture_tree,
    invocation_evidence,
    live,
    pins,
)

UNIT = "outbound::reservation_time_tests::"
CELL = "expired_mcp_uncertainty_requires_reconciliation_without_resubmission"
SOURCE = ROOT / "src/outbound.rs"
UNITS = [
    "fractional_reservation_times_preserve_the_complete_lifetime",
    "full_ttl_windows_end_by_the_pinned_nodes_first_purge_tick",
    "unrepresentable_reservation_windows_are_configuration_refusals",
    "retry_deadlines_preserve_stored_windows_and_reduce_with_limits",
]
CASES = [
    (
        "floor-window",
        "src/deadline.rs",
        "i64::from(elapsed.subsec_nanos() != 0)",
        "0",
        UNITS[0],
        "reservation window was floored instead of ceiled",
    ),
    (
        "floor-reader-cap",
        "src/outbound.rs",
        ".saturating_add(1)",
        ".saturating_add(0)",
        UNITS[3],
        "ceiled retry window was shortened",
    ),
    (
        "extend-stored-window",
        "src/outbound.rs",
        "self.retry_until.min(",
        "i64::MAX.min(",
        UNITS[3],
        "stored retry deadline was extended",
    ),
]


def marked(source, test, marker):
    site = f"fn {test}() {{"
    assert source.count(site) == 1, ("named cell drift", test)
    return source.replace(site, site + f'\n    eprintln!("{marker}");', 1)


def build_units(root):
    result = subprocess.run(
        ["cargo", "test", "--locked", "--offline", "--lib", "--no-run",
         "--message-format=json", "-j", "4"],
        cwd=root,
        env={**os.environ, "CARGO_TARGET_DIR": str(root / "target")},
        capture_output=True,
        text=True,
        timeout=300,
    )
    if result.returncode:
        raise RuntimeError(("unit build failed; not a kill", result.stderr[-4000:]))
    records = [json.loads(line) for line in result.stdout.splitlines()
               if line.startswith("{")]
    found = [item for item in records if item.get("reason") == "compiler-artifact"
             and item.get("target", {}).get("name") == "xmsg_mcp_gateway"
             and item.get("profile", {}).get("test") and item.get("executable")]
    assert len(found) == 1 and not found[0].get("fresh", True), "unit artifact reused"
    return Path(found[0]["executable"])


def units():
    source = SOURCE.read_text()
    nonce = uuid.uuid4().hex
    arms = [("control", "src/outbound.rs", source, UNITS, None)]
    for label, filename, needle, replacement, test, diagnostic in CASES:
        target = (ROOT / filename).read_text()
        assert target.count(needle) == 1, ("source site drift", label)
        arms.append((label, filename, target.replace(needle, replacement, 1), [test], diagnostic))
    for label, filename, variant, tests, diagnostic in arms:
        with tempfile.TemporaryDirectory(prefix=f"gateway-lifetime-{label}-") as directory:
            root = Path(directory)
            copy_fixture_tree(root)
            (root / filename).write_text(variant)
            unit_source = (root / "src/outbound.rs").read_text()
            markers = []
            for test in tests:
                marker = f"reservation-lifetime-arm:{nonce}:{label}:{test}"
                markers.append(marker)
                unit_source = marked(unit_source, test, marker)
            (root / "src/outbound.rs").write_text(unit_source)
            executable = build_units(root)
            record(root, executable, label)
            args = [str(executable), UNIT if diagnostic is None else UNIT + tests[0],
                    "--nocapture"]
            if diagnostic is not None:
                args.append("--exact")
            invocation_evidence(args)
            result = subprocess.run(args, cwd=root, capture_output=True, text=True, timeout=15)
            output = result.stdout + result.stderr
            assert all(output.count(marker) == 1 for marker in markers), "arm was not executed"
            if diagnostic is None:
                assert result.returncode == 0 and "4 passed; 0 failed; 0 ignored" in output, output
            else:
                assert result.returncode == 101 and diagnostic in output, output
                assert "0 passed; 1 failed; 0 ignored" in output, output
            print(f"{label}: intended result; nonce={nonce}", flush=True)
    print("reservation-lifetime-unit-mutants-complete:3", flush=True)


def acceptance():
    source = (ROOT / "tests/messaging.rs").read_text()
    site = 'fixture.config["messaging"]["manifest"]["dedup_lifetime_secs"] = json!(3600);'
    assert source.count(site) == 1, "acceptance-window site drift"
    nonce = uuid.uuid4().hex
    for label, variant, expected in (
        ("control", source, None),
        ("old-one-second-setup", source.replace(site, site.replace("3600", "1"), 1),
         "expired uncertainty: initial request completed before upstream acceptance"),
    ):
        with tempfile.TemporaryDirectory(prefix=f"gateway-acceptance-{label}-") as directory:
            root = Path(directory)
            copy_fixture_tree(root)
            marker = f"reservation-acceptance-arm:{nonce}:{label}"
            (root / "tests/messaging.rs").write_text(marked(variant, CELL, marker))
            executable = Path(build_test(root, target="messaging"))
            record(root, executable, label)
            started = time.monotonic()
            result = live(executable, Path(os.environ["XMSG_GATEWAY_BIN"]),
                          pins()["revision"], case=CELL)
            elapsed = time.monotonic() - started
            output = result.stdout + result.stderr
            assert output.count(marker) == 1, "acceptance arm was not executed"
            assert elapsed < 15, ("acceptance arm did not fail promptly", elapsed)
            if expected is None:
                assert result.returncode == 0 and "1 passed; 0 failed; 0 ignored" in output, output
                assert output.count("gateway-wiring-complete:expired-unknown") == 1, output
            else:
                assert result.returncode == 101 and expected in output, output
                assert "0 passed; 1 failed; 0 ignored" in output, output
            print(f"{label}: intended result; seconds={elapsed:.3f}; nonce={nonce}", flush=True)
    print("reservation-acceptance-mutants-complete:1", flush=True)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--live", action="store_true", help="run the pinned-daemon acceptance arms")
    if parser.parse_args().live:
        acceptance()
    else:
        units()
