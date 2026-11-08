"""Prove the real CLI refuses excess connections; compiler errors are not kills."""

import json
import os
import shutil
import subprocess
import tempfile
from pathlib import Path

from artifact_evidence import NONCE, record

ROOT = Path(__file__).resolve().parents[1]
TEST = "connection_cap_bounds_idle_and_keepalive_and_releases_slots"


def arm(root, name):
    marker = f"connection-cap-arm:{NONCE}:{name}"
    entry = root / "tests/connection_cap.rs"
    entry.write_text(
        entry.read_text().replace(
            f"async fn {TEST}() {{",
            f'async fn {TEST}() {{\n    eprintln!("{marker}");',
            1,
        )
    )
    env = {
        **os.environ,
        "CARGO_TARGET_DIR": str(ROOT / "target/connection-cap-mutants" / NONCE / name),
    }
    built = subprocess.run(
        [
            "cargo",
            "test",
            "--locked",
            "--offline",
            "-j",
            "2",
            "--test",
            "connection_cap",
            "--no-run",
            "--message-format=json",
        ],
        cwd=root,
        env=env,
        capture_output=True,
        text=True,
        timeout=360,
    )
    if built.returncode:
        raise RuntimeError(
            f"compilation failed; not a kill: {built.stdout[-8000:]} {built.stderr[-4000:]}"
        )
    artifacts = [
        json.loads(line) for line in built.stdout.splitlines() if line.startswith("{")
    ]
    selected = {}
    for item in artifacts:
        if item.get("reason") != "compiler-artifact":
            continue
        target = item.get("target", {})
        if target.get("name") == "connection_cap" and item.get("executable"):
            selected["test"] = (item, Path(item["executable"]))
        elif (
            target.get("name") == "xmsg-mcp-gateway"
            and item.get("executable")
            and not item["profile"]["test"]
        ):
            selected["app"] = (item, Path(item["executable"]))
        elif target.get("name") == "xmsg_mcp_gateway" and not item["profile"]["test"]:
            libs = [Path(file) for file in item["filenames"] if file.endswith(".rlib")]
            if len(libs) == 1:
                selected["library"] = (item, libs[0])
    assert set(selected) == {"test", "app", "library"}, selected
    for kind, (receipt, file) in selected.items():
        assert receipt.get("fresh") is False, (name, kind, "cached artifact")
        record(root, file, f"connection-cap/{name}/{kind}")
    result = subprocess.run(
        [str(selected["test"][1]), TEST, "--exact", "--nocapture"],
        cwd=root,
        env=env,
        capture_output=True,
        text=True,
        timeout=15,
    )
    output = result.stdout + result.stderr
    assert marker in output, "intended test nonce did not execute"
    evidence = ROOT / ".artifacts/connection-cap-mutants" / NONCE
    evidence.mkdir(parents=True, exist_ok=True)
    (evidence / f"{name}.log").write_text(output)
    print(f"executed {marker}\n{output}", flush=True)
    return result.returncode, output


def main():
    with tempfile.TemporaryDirectory(prefix="gateway-cap-mutants-") as directory:
        for name in ("control", "bypass", "missing-reason"):
            root = Path(directory) / name
            root.mkdir()
            for file in ("Cargo.toml", "Cargo.lock"):
                shutil.copyfile(ROOT / file, root / file)
            for folder in ("src", "tests"):
                shutil.copytree(ROOT / folder, root / folder)
            if name == "bypass":
                file = root / "src/serving.rs"
                original = file.read_text()
                old = "Semaphore::new(self.max_connections)"
                assert original.count(old) == 1, "cap mutation site changed"
                file.write_text(
                    original.replace(old, "Semaphore::new(Semaphore::MAX_PERMITS)", 1)
                )
            elif name == "missing-reason":
                file = root / "src/serving.rs"
                original = file.read_text()
                old = 'tracing::warn!(target: "gateway_transport", reason = ?ConnectionCapacityRefusal, "connection refused");'
                assert original.count(old) == 1, "cap reason mutation site changed"
                file.write_text(original.replace(old, "", 1))
            code, output = arm(root, name)
            if name == "control":
                assert code == 0 and "1 passed; 0 failed" in output, output
            else:
                assert (
                    code == 101
                    and f"test {TEST} ... FAILED" in output
                    and (
                        "connection cap failed to promptly refuse N+1"
                        if name == "bypass"
                        else "missing production cap reason"
                    )
                    in output
                ), output
    print("2/2 connection cap mutants killed", flush=True)


if __name__ == "__main__":
    main()
