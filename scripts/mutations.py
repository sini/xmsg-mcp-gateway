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
    ("01-auth", "phase1/app.py", "if not credential:", "if False:", "test_auth"),
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
        "INSERT INTO outbox(occurrence,event_id,body) VALUES (?,?,?)",
        "INSERT INTO outbox(occurrence,event_id,body,state) VALUES (?,?,?,'accepted')",
        "test_custody",
    ),
    (
        "07-loopback",
        "phase1/config.py",
        'bind: str = "127.0.0.1"',
        'bind: str = "0.0.0.0"',
        "test_default_bind",
    ),
]


def run(directory, test):
    return subprocess.run(
        [
            sys.executable,
            "-m",
            "pytest",
            "-q",
            "--tb=short",
            "tests/test_phase1.py::" + test,
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
            if (
                red.returncode != 1
                or "FAILED tests/test_phase1.py::" + test not in red.stdout
            ):
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
    print("7/7 single-site production mutants killed; originals untouched.")


if __name__ == "__main__":
    main()
