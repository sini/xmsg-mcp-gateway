"""Run the real leaf/hub broker fixture with a pinned packaged genie-root.

XMSG_GATEWAY_BIN must name the revision-verified daemon produced by
scripts/transport_compat.py --build-only. This script builds genie-root from
its public test-only pin unless GENIE_ROOT explicitly supplies a local build.
"""

import json
import os
import signal
import subprocess
import tomllib
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def main():
    pin = tomllib.loads((ROOT / "ci/genie-pin.toml").read_text())
    binary = os.environ.get("GENIE_ROOT")
    if binary is None:
        built = subprocess.run(
            [
                "systemd-run",
                "--user",
                "--scope",
                "-q",
                "-p",
                "MemoryMax=12G",
                "nix",
                "build",
                "--no-link",
                "--print-out-paths",
                f"github:sini/genie-agent/{pin['revision']}#genie-root",
            ],
            cwd=ROOT,
            text=True,
            capture_output=True,
            check=True,
        )
        binary = str(Path(built.stdout.strip().splitlines()[-1]) / "bin/genie-root")
    assert Path(binary).is_file(), "packaged genie-root is required"
    assert Path(os.environ["XMSG_GATEWAY_BIN"]).is_file(), (
        "verified xmsg daemon is required"
    )
    evidence = ROOT / ".artifacts/broker-bridge-e2e"
    evidence.mkdir(parents=True, exist_ok=True)
    env = {**os.environ, "GENIE_ROOT": binary}
    process = subprocess.Popen(
        [
            "cargo",
            "test",
            "--locked",
            "--test",
            "broker_bridge_e2e",
            "--",
            "--ignored",
            "--exact",
            "real_mcp_leaf_genie_bridge_scrubs_and_consumes_guard_rewrite",
            "--nocapture",
        ],
        cwd=ROOT,
        env=env,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        start_new_session=True,
    )
    try:
        output, _ = process.communicate(timeout=300)
    except subprocess.TimeoutExpired:
        os.killpg(process.pid, signal.SIGKILL)
        output, _ = process.communicate()
        (evidence / "test.log").write_text(output)
        raise RuntimeError("broker fixture exceeded 300 seconds") from None
    (evidence / "test.log").write_text(output)
    (evidence / "result.json").write_text(
        json.dumps(
            {
                "genie_revision": pin["revision"],
                "genie_executable": binary,
                "local_genie_override": "GENIE_ROOT" in os.environ,
                "exit_code": process.returncode,
            },
            indent=2,
        )
        + "\n"
    )
    print(output, end="")
    assert process.returncode == 0, "broker fixture failed"
    assert "broker-bridge-e2e-complete:mcp-leaf-hub-genie-guard-rewrite-dedup" in output


if __name__ == "__main__":
    main()
