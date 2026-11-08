"""Prove header lifetimes, safe refusal diagnostics and accept-error recovery."""

import hashlib
import json
import os
import shutil
import subprocess
import tempfile
import uuid
from pathlib import Path

from artifact_evidence import record
from transport_compat import invocation_evidence

ROOT = Path(__file__).resolve().parents[1]
TEST = "header_deadline_is_absolute_and_excludes_body"
IDLE = "idle_keepalive_is_bounded_by_the_next_header_deadline"
ACCEPT = "accept_errors_recover_after_descriptor_exhaustion"
SHUTDOWN = "shutdown_is_not_delayed_by_accept_backoff"
SOURCE = (ROOT / "src/serving.rs").read_text()
accept_start = SOURCE.index(
    "                        Err(error) => {",
    SOURCE.index("accepted = listener.accept()"),
)
accept_end = SOURCE.index("\n                    };", accept_start)
CASES = [
    (
        "control",
        None,
        None,
        [(TEST, None), (IDLE, None), (ACCEPT, None), (SHUTDOWN, None)],
    ),
    (
        "deadline-disabled",
        "builder.header_read_timeout(deadline);",
        "builder.header_read_timeout(None);",
        [
            (
                TEST,
                "slow headers were not disconnected within header deadline plus scheduling tolerance",
            ),
            (IDLE, "idle keep-alive exceeded next-header deadline"),
        ],
    ),
    (
        "header-reason-removed",
        'tracing::warn!(target: "gateway_transport", reason = ?reason, "transport refused");',
        "let _ = reason;",
        [
            (TEST, "header timeout reason was not emitted"),
        ],
    ),
    (
        "accept-fatal",
        SOURCE[accept_start:accept_end],
        "                        Err(error) => break Err(error),",
        [
            (ACCEPT, "server terminated on recoverable accept error"),
        ],
    ),
    (
        "uninterruptible-backoff",
        """                            tokio::select! {
                                _ = &mut shutdown => break Ok(()),
                                _ = tokio::time::sleep(Duration::from_secs(1)) => {},
                            }""",
        "                            tokio::time::sleep(Duration::from_secs(1)).await;",
        [(SHUTDOWN, "shutdown delayed by accept-error backoff")],
    ),
]


def digest(file):
    return hashlib.sha256(file.read_bytes()).hexdigest()


def main():
    with tempfile.TemporaryDirectory(prefix="gateway-header-mutants-") as temporary:
        for label, needle, replacement, cells in CASES:
            nonce = f"{label}-{uuid.uuid4()}"
            tree = Path(temporary) / label
            shutil.copytree(
                ROOT,
                tree,
                ignore=shutil.ignore_patterns(
                    ".git",
                    ".artifacts",
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
            if needle is not None:
                assert text.count(needle) == 1
                text = text.replace(needle, replacement, 1)
            source.write_text(text + f"\n// Build receipt: {nonce}\n")
            test = tree / "tests/header_timeout.rs"
            original = test.read_text()
            for name, _ in cells:
                entry = f"async fn {name}() {{"
                assert original.count(entry) == 1
                original = original.replace(
                    entry,
                    entry + f'\n    eprintln!("header-timeout nonce={nonce}");',
                    1,
                )
            test.write_text(original)
            target = tree / "target"
            environment = dict(os.environ, CARGO_TARGET_DIR=str(target))
            environment.pop("GW_H1_NONCE", None)
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
            results = []
            for name, diagnostic in cells:
                args = [executable, "--exact", name, "--nocapture"]
                invocation_evidence(args)
                result = subprocess.run(
                    args,
                    cwd=tree,
                    env=environment,
                    capture_output=True,
                    text=True,
                    timeout=20,
                )
                output = result.stdout + result.stderr
                assert output.count(f"header-timeout nonce={nonce}") == 1, output
                if diagnostic is not None:
                    assert result.returncode != 0 and diagnostic in output, output
                else:
                    assert result.returncode == 0, output
                results.append({"test": name, "status": result.returncode})
                print(output, flush=True)
            print(
                json.dumps(
                    {
                        "arm": label,
                        "nonce": nonce,
                        "source_sha256": digest(source),
                        "artifacts": receipts,
                        "results": results,
                    }
                ),
                flush=True,
            )


if __name__ == "__main__":
    main()
