"""Prove timeout clues identify sleeping tests without exposing captured payloads."""

import hashlib
import os
import subprocess
import sys
import tempfile
import uuid
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / "scripts/transport_compat.py"
CATCH = """    try:
        return subprocess.run(
            args, cwd=ROOT, env=env, text=True, capture_output=True, timeout=timeout
        )
    except subprocess.TimeoutExpired as error:
        print("live-timeout: suite exceeded its deadline; no retry", flush=True)
        timeout_progress(error.stdout, "stdout")
        timeout_progress(error.stderr, "stderr")
        raise RuntimeError("live test suite timed out") from None"""
UNCATCHED = """    return subprocess.run(
        args, cwd=ROOT, env=env, text=True, capture_output=True, timeout=timeout
    )"""
CELL = "timeout_diagnostic_sleeping_cell"
SECRET = "TIMEOUT_PAYLOAD_SECRET_" + uuid.uuid4().hex


def require_diagnostic(result):
    if result.returncode == 0:
        raise RuntimeError("timed-out suite was accepted")
    if SECRET in result.stdout + result.stderr:
        raise RuntimeError("timeout diagnostic exposed a payload secret")
    if f"test={CELL} state=running" not in result.stdout:
        raise RuntimeError("timeout diagnostic lost the sleeping test name")
    if "live test suite timed out" not in result.stderr:
        raise RuntimeError("timeout diagnostic did not fail with its safe reason")


def main():
    source = SOURCE.read_text()
    assert source.count(CATCH) == 1, "timeout handler source site drifted"
    nonce = uuid.uuid4().hex
    with tempfile.TemporaryDirectory(
        prefix="gateway-timeout-diagnostics-"
    ) as directory:
        root = Path(directory)
        fixture = root / "fixture"
        fixture.write_text(
            f"#!{sys.executable}\nimport sys, time\n"
            "for i in range(25): print(f'test completed_{i} ... ok', flush=True)\n"
            f"print('test {CELL} ...', flush=True)\n"
            f"print('test stderr_sleeping_cell has been running for over 60 seconds', file=sys.stderr, flush=True)\n"
            f"print({SECRET!r}, flush=True)\n"
            f"print({SECRET!r}, file=sys.stderr, flush=True)\n"
            "time.sleep(30)\n"
        )
        fixture.chmod(0o700)
        for arm, text in (
            ("positive", source),
            ("uncaught-mutant", source.replace(CATCH, UNCATCHED)),
        ):
            variant = root / f"{arm}.py"
            variant.write_text(text)
            marker = f"timeout-diagnostics-executed:{nonce}:{arm}"
            code = (
                "import importlib.util, sys\n"
                "spec = importlib.util.spec_from_file_location('timeout_arm', sys.argv[1])\n"
                "module = importlib.util.module_from_spec(spec)\n"
                "spec.loader.exec_module(module)\n"
                "assert module.live.__kwdefaults__['timeout'] == 120\n"
                f"print({marker!r}, flush=True)\n"
                "module.live(sys.argv[2], None, 'diagnostic-fixture', timeout=0.2)\n"
            )
            result = subprocess.run(
                [sys.executable, "-c", code, str(variant), str(fixture)],
                env={**os.environ, "PYTHONPATH": str(ROOT / "scripts")},
                capture_output=True,
                text=True,
                timeout=5,
            )
            assert marker in result.stdout, "source arm was not executed"
            print(
                f"{marker} source_sha256={hashlib.sha256(variant.read_bytes()).hexdigest()} fixture_sha256={hashlib.sha256(fixture.read_bytes()).hexdigest()}"
            )
            if arm == "positive":
                require_diagnostic(result)
                assert result.stdout.count("live-timeout stdout test=") == 16
                assert "test=stderr_sleeping_cell state=running" in result.stdout
                print(result.stdout, end="")
            else:
                try:
                    require_diagnostic(result)
                except RuntimeError as error:
                    assert (
                        str(error) == "timeout diagnostic lost the sleeping test name"
                    ), error
                    print(
                        "uncaught timeout mutant: diagnostic guard RED (sleeping name absent)"
                    )
                else:
                    raise RuntimeError(
                        "uncaught timeout mutant escaped the diagnostic guard"
                    )
    print("timeout-diagnostics-complete:positive-and-source-mutant")


if __name__ == "__main__":
    main()
