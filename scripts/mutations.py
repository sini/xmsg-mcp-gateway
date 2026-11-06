"""Run single-site production mutants in disposable independent directories."""

import difflib
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
EVIDENCE = ROOT / ".artifacts" / "mutations"
MUTANTS = [
    (
        "01-auth",
        "phase1/store.py",
        'if row and row["mode"] == "local-test" and not row["revoked"]',
        "if True",
        "test_auth",
    ),
    (
        "02-unknown-fields",
        "phase1/schemas.py",
        'extra="forbid"',
        'extra="ignore"',
        "test_unknown_sender",
    ),
    (
        "03-ssrf",
        "phase1/transport.py",
        "if not addresses or not all(public_address(address) for address in addresses):",
        "if not addresses:",
        "test_ssrf",
    ),
    (
        "04-redirect",
        "phase1/events.py",
        "if not 200 <= status < 300:",
        "if status >= 400:",
        "test_redirect",
    ),
    (
        "05-signatures",
        "phase1/transport.py",
        "Webhook(key).sign(event_id, stamp, body.decode())",
        'Webhook(key).sign(event_id, stamp, "tampered")',
        "test_signatures",
    ),
    (
        "06-custody",
        "phase1/store.py",
        "encode(event),\n                    state,",
        'encode(event),\n                    "accepted",',
        "test_custody",
    ),
    (
        "07-loopback",
        "phase1/config.py",
        'bind: str = "127.0.0.1"',
        'bind: str = "0.0.0.0"',
        "test_default_bind",
    ),
    (
        "08-hosted-client",
        "phase1/auth.py",
        'and claims.get("client_id")\n                == self.settings.approved_hosted_oauth_client_id',
        "and True",
        "tests/test_grants.py::test_token_client_is_independent_of_lookup_caller",
    ),
    (
        "09-disabled-enrollment",
        "phase1/grants.py",
        "INSERT INTO service_grants VALUES (?,?,?,?,?,?,?,1,0)",
        "INSERT INTO service_grants VALUES (?,?,?,?,?,?,?,1,1)",
        "tests/test_grants.py::test_enrollment_is_disabled_and_tokens_cannot_enroll",
    ),
    (
        "10-disable-guard",
        "phase1/grants.py",
        "def set_enabled(store, identifier, enabled):\n    with store.guard(), store.db() as db:",
        "def set_enabled(store, identifier, enabled):\n    with store.db() as db:",
        "tests/test_grants.py::test_disable_waits_for_real_network_submission_and_blocks_later_work",
    ),
    (
        "11-item-revision",
        "phase1/worker.py",
        'event["dispatch_grant_id"],\n                    event["dispatch_grant_revision"],',
        'subscription["grant_id"],\n                    subscription["grant_revision"],',
        "tests/test_grants.py::test_worker_checks_the_items_snapshot_not_only_the_subscription",
    ),
]


def test_path(test):
    return test if "::" in test else "tests/test_phase1.py::" + test


def run(directory, test):
    return subprocess.run(
        [
            sys.executable,
            "-m",
            "pytest",
            "-q",
            "--tb=short",
            test_path(test),
        ],
        cwd=directory,
        env={**os.environ, "PYTHONPATH": str(directory)},
        capture_output=True,
        text=True,
        timeout=45,
        check=False,
    )


def main():
    EVIDENCE.mkdir(parents=True, exist_ok=True)
    for name, filename, old, new, test in MUTANTS:
        with tempfile.TemporaryDirectory(prefix="dot-phase1-mutant-") as temp:
            root = Path(temp)
            shutil.copytree(
                ROOT / "phase1",
                root / "phase1",
                ignore=shutil.ignore_patterns("__pycache__"),
            )
            shutil.copytree(
                ROOT / "tests",
                root / "tests",
                ignore=shutil.ignore_patterns("__pycache__"),
            )
            shutil.copy2(ROOT / "pyproject.toml", root / "pyproject.toml")
            green = run(root, test)
            if green.returncode:
                raise RuntimeError(name + ": green control failed")
            source = root / filename
            before = source.read_text()
            if before.count(old) != 1:
                raise RuntimeError(name + ": mutation site must be unique")
            after = before.replace(old, new)
            source.write_text(after)
            # Invalidate bytecode even on filesystems with coarse timestamps.
            for cache in root.rglob("__pycache__"):
                shutil.rmtree(cache)
            red = run(root, test)
            if red.returncode != 1 or "FAILED " + test_path(test) not in red.stdout:
                raise RuntimeError(
                    name + ": mutant was not killed by its intended test"
                )
            patch = "".join(
                difflib.unified_diff(
                    before.splitlines(True),
                    after.splitlines(True),
                    fromfile="a/" + filename,
                    tofile="b/" + filename,
                )
            )
            (EVIDENCE / (name + ".patch")).write_text(patch)
            (EVIDENCE / (name + "-green.txt")).write_text(green.stdout + green.stderr)
            (EVIDENCE / (name + "-red.txt")).write_text(red.stdout + red.stderr)
            print(name + ": GREEN control, RED mutant (exit 1)", flush=True)
    print(
        f"{len(MUTANTS)}/{len(MUTANTS)} single-site production mutants killed; originals untouched."
    )


if __name__ == "__main__":
    main()
