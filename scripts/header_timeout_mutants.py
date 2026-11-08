"""Fresh-build listener deadline control and source mutant (run under heavy-lock)."""

import hashlib
import json
import os
import shutil
import subprocess
import tempfile
import uuid
from pathlib import Path

from artifact_evidence import record

ROOT = Path(__file__).resolve().parents[1]
TEST = "header_deadline_is_absolute_and_excludes_body"


def digest(file):
    return hashlib.sha256(file.read_bytes()).hexdigest()


def main():
    with tempfile.TemporaryDirectory(prefix="gateway-header-mutants-") as temporary:
        for mutant in [False, True]:
            label = "mutant" if mutant else "control"
            nonce = f"{label}-{uuid.uuid4()}"
            tree = Path(temporary) / label
            shutil.copytree(
                ROOT,
                tree,
                ignore=shutil.ignore_patterns(
                    ".git",
                    "target",
                    ".worktrees",
                    "__pycache__",
                    ".venv",
                    ".ruff_cache",
                    ".pytest_cache",
                ),
            )
            source = tree / "src/serving.rs"
            text = source.read_text()
            needle = "builder.header_read_timeout(deadline);"
            assert text.count(needle) == 1
            if mutant:
                text = text.replace(needle, "builder.header_read_timeout(None);", 1)
            source.write_text(text + f"\n// Build receipt: {nonce}\n")
            target = tree / "target"
            environment = dict(
                os.environ, CARGO_TARGET_DIR=str(target), GW_H1_NONCE=nonce
            )
            build = subprocess.run(
                [
                    "cargo",
                    "test",
                    "--locked",
                    "--test",
                    "header_timeout",
                    "--no-run",
                    "--message-format=json",
                ],
                cwd=tree,
                env=environment,
                capture_output=True,
                text=True,
            )
            if build.returncode:
                raise AssertionError(
                    f"{label} did not compile (not a killed mutant): {build.stderr}"
                )
            receipts = []
            executable = None
            kinds = set()
            for line in build.stdout.splitlines():
                artifact = json.loads(line)
                if artifact.get("reason") != "compiler-artifact" or artifact["target"][
                    "name"
                ] not in ["xmsg_mcp_gateway", "xmsg-mcp-gateway", "header_timeout"]:
                    continue
                assert not artifact["fresh"], artifact
                kinds.add(artifact["target"]["name"])
                for name in artifact["filenames"]:
                    file = Path(name)
                    receipts.append(
                        {"file": str(file.relative_to(tree)), "sha256": digest(file)}
                    )
                if artifact["target"]["name"] == "header_timeout":
                    executable = artifact["executable"]
            assert kinds == {
                "xmsg_mcp_gateway",
                "xmsg-mcp-gateway",
                "header_timeout",
            }, kinds
            record(tree, Path(executable), label)
            result = subprocess.run(
                [executable, "--exact", TEST, "--nocapture"],
                cwd=tree,
                env=environment,
                capture_output=True,
                text=True,
                timeout=20,
            )
            output = result.stdout + result.stderr
            assert f"header-timeout nonce={nonce}" in output, output
            if mutant:
                assert (
                    result.returncode != 0
                    and "slow headers were not disconnected within header deadline plus scheduling tolerance"
                    in output
                ), output
            else:
                assert result.returncode == 0, output
            print(
                json.dumps(
                    {
                        "arm": label,
                        "nonce": nonce,
                        "source_sha256": digest(source),
                        "artifacts": receipts,
                        "status": result.returncode,
                    }
                ),
                flush=True,
            )
            print(output, flush=True)


if __name__ == "__main__":
    main()
