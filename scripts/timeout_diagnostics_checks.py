"""Prove owned timeout diagnosis and per-invocation provenance without payload leaks."""

import hashlib
import json
import os
import subprocess
import sys
import tempfile
import time
import uuid
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / "scripts/transport_compat.py"
CELL = "timeout_diagnostic_sleeping_cell"
SECRET = "TIMEOUT_PAYLOAD_SECRET_" + uuid.uuid4().hex


def require_diagnostic(result, fixture, identity, *, summary):
    output = result.stdout + result.stderr
    if result.returncode == 0 or "live test suite timed out" not in result.stderr:
        raise RuntimeError("timeout did not fail safely")
    if SECRET in output:
        raise RuntimeError("timeout exposed a payload secret")
    records = [
        json.loads(line.removeprefix("live-invocation "))
        for line in result.stdout.splitlines()
        if line.startswith("live-invocation ")
    ]
    child = json.loads(identity.read_text())
    expected_cpu = child["available_cpu_count"]
    expected = {
        "command": [
            str(fixture),
            "--include-ignored",
            "--nocapture",
            "safe_filter",
            "--exact",
            "--skip",
            "safe_skip",
            "--skip",
            "federation_",
            "--skip",
            "socket_activation_",
        ],
        "available_cpu_count": expected_cpu,
        "test_binary_sha256": hashlib.sha256(fixture.read_bytes()).hexdigest(),
    }
    if child["command"] != expected["command"] or records != [expected]:
        raise RuntimeError("invocation evidence differs from actual command/CPU/binary")
    if f"summary-seen={str(summary).lower()}" not in result.stdout:
        raise RuntimeError("summary presence diagnostic missing or wrong")
    if not summary and f"test={CELL} state=running" not in result.stdout:
        raise RuntimeError("sleeping test name missing")
    if result.stdout.count("live-timeout stdout test=") > 16:
        raise RuntimeError("progress diagnostic is unbounded")
    role = "owned-child" if summary else "owned-root"
    if (
        f"{role} pid={child['pid']} name={json.dumps(child['name'])}"
        not in result.stdout
    ):
        raise RuntimeError("owned child identity diagnostic missing or wrong")
    for line in result.stdout.splitlines():
        if "owned-child" in line and ("--" in line or "time.sleep" in line):
            raise RuntimeError("child identity exposed command arguments")


def main():
    source = SOURCE.read_text()
    mutations = [
        (
            "no-diagnostics",
            "            report_timeout(error, owned, process.pid)",
            "            pass",
            "summary presence diagnostic missing or wrong",
            False,
        ),
        (
            "wrong-summary",
            "str(summary_seen).lower()",
            '"false"',
            "summary presence diagnostic missing or wrong",
            True,
        ),
        (
            "no-child-identity",
            "for pid, name in owned[:32]:",
            "for pid, name in []:",
            "owned child identity diagnostic missing or wrong",
            True,
        ),
        (
            "no-progress",
            '    timeout_progress(error.stdout, "stdout")',
            "    pass",
            "sleeping test name missing",
            False,
        ),
        (
            "no-evidence",
            "    invocation_evidence(args)",
            "    pass",
            "invocation evidence differs from actual command/CPU/binary",
            False,
        ),
        (
            "wrong-command",
            '"command": [str(argument) for argument in args]',
            '"command": []',
            "invocation evidence differs from actual command/CPU/binary",
            False,
        ),
        (
            "wrong-cpu",
            '"available_cpu_count": available',
            '"available_cpu_count": 0',
            "invocation evidence differs from actual command/CPU/binary",
            False,
        ),
        (
            "wrong-binary-hash",
            '"test_binary_sha256": digest',
            '"test_binary_sha256": "0" * 64',
            "invocation evidence differs from actual command/CPU/binary",
            False,
        ),
    ]
    mutations.append(
        (
            "inspection-unavailable-control",
            "                owned = owned_processes(process)",
            '                raise RuntimeError("fixture inspection unavailable")',
            "owned child identity diagnostic missing or wrong",
            True,
        )
    )
    nonce = uuid.uuid4().hex
    with tempfile.TemporaryDirectory(
        prefix="gateway-timeout-diagnostics-"
    ) as directory:
        root = Path(directory)
        fixtures = {}
        for summary in (False, True):
            fixture = root / ("fixture-b" if summary else "fixture-a")
            identity = root / ("identity-b" if summary else "identity-a")
            text = f"#!{sys.executable}\nimport json, os, subprocess, sys, time\n"
            if summary:
                text += "child = subprocess.Popen([sys.executable, '-c', 'import time; time.sleep(30)'])\n"
                text += "pid = child.pid\n"
            else:
                text += "pid = os.getpid()\n"
            text += "name = subprocess.check_output(['ps', '-p', str(pid), '-o', 'comm='], text=True).strip().rsplit('/', 1)[-1]\n"
            text += "cpu = len(os.sched_getaffinity(0)) if hasattr(os, 'sched_getaffinity') else (getattr(os, 'process_cpu_count', os.cpu_count)() or 1)\n"
            text += f"open({str(identity)!r}, 'w').write(json.dumps({{'pid':pid,'name':name,'command':sys.argv,'available_cpu_count':cpu}}))\n"
            text += (
                "for i in range(25): print(f'test completed_{i} ... ok', flush=True)\n"
            )
            text += f"print('test {CELL} ...', flush=True)\n"
            text += f"print({SECRET!r}, flush=True)\nprint({SECRET!r}, file=sys.stderr, flush=True)\n"
            if summary:
                text += "print('test result: ok. 26 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out', flush=True)\n"
            else:
                text += "time.sleep(30)\n"
            fixture.write_text(text)
            fixture.chmod(0o700)
            fixtures[summary] = fixture, identity
        arms = [
            ("positive-before-summary", source, False, None),
            ("positive-after-summary", source, True, None),
        ]
        for name, old, new, reason, summary in mutations:
            assert source.count(old) == 1, (name, "source mutation site drift")
            arms.append((name, source.replace(old, new, 1), summary, reason))
        for arm, text, summary, expected_red in arms:
            fixture, identity = fixtures[summary]
            variant = root / f"{arm}.py"
            variant.write_text(text)
            marker = f"timeout-diagnostics-executed:{nonce}:{arm}"
            code = (
                "import importlib.util, os, sys\n"
                "if hasattr(os, 'sched_setaffinity'): os.sched_setaffinity(0, {min(os.sched_getaffinity(0))})\n"
                "spec = importlib.util.spec_from_file_location('timeout_arm', sys.argv[1])\n"
                "module = importlib.util.module_from_spec(spec)\n"
                "spec.loader.exec_module(module)\n"
                "assert module.live.__kwdefaults__['timeout'] == 120\n"
                f"print({marker!r}, flush=True)\n"
                "module.live(sys.argv[2], None, 'diagnostic-fixture', case='safe_filter', skip='safe_skip', baseline=True, timeout=0.3)\n"
            )
            result = subprocess.run(
                [sys.executable, "-c", code, str(variant), str(fixture)],
                env={**os.environ, "PYTHONPATH": str(ROOT / "scripts")},
                capture_output=True,
                text=True,
                timeout=6,
            )
            assert marker in result.stdout, "source arm was not executed"
            if arm == "inspection-unavailable-control":
                assert "owned-inspection=unavailable" in result.stdout
            pid = json.loads(identity.read_text())["pid"]
            deadline = time.monotonic() + 2
            while True:
                state = subprocess.run(
                    ["ps", "-p", str(pid), "-o", "stat="],
                    text=True,
                    capture_output=True,
                    timeout=1,
                )
                if state.returncode == 1 or state.stdout.strip().startswith("Z"):
                    break
                assert time.monotonic() < deadline, (
                    "owned sleeping process survived cleanup"
                )
                time.sleep(0.01)
            print(
                f"{marker} source_sha256={hashlib.sha256(variant.read_bytes()).hexdigest()} fixture_sha256={hashlib.sha256(fixture.read_bytes()).hexdigest()}",
                flush=True,
            )
            try:
                require_diagnostic(result, fixture, identity, summary=summary)
            except RuntimeError as error:
                assert expected_red and str(error) == expected_red, (
                    arm,
                    str(error),
                    result.stdout,
                    result.stderr,
                )
                print(f"{arm}: diagnostic guard RED ({error})", flush=True)
            else:
                assert expected_red is None, (arm, "source mutant survived")
                print(result.stdout, end="", flush=True)
    print("timeout-diagnostics-complete:positive-and-source-mutant")


if __name__ == "__main__":
    main()
