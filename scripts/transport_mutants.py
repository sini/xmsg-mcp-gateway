"""Kill isolated node-admission source mutants through the real shared client."""

import argparse
import tempfile
from pathlib import Path

from transport_compat import ROOT, build, build_test, command, live, pins, stamp

CASES = [
    (
        "allow",
        'if !peer_cfg.allow.iter().any(|op| op == "send") {',
        "if false {",
        "federation_requires_peer_send_permission",
    ),
    (
        "principals",
        "if !peer_cfg.principals.is_empty() {",
        "if false {",
        "federation_requires_the_approved_service_principal",
    ),
    (
        "targets",
        "if !target_matches_allowlist(&t, allowed_targets) {",
        "if false {",
        "federation_requires_the_approved_target",
    ),
    (
        "from",
        "if let Some(ref from_list) = peer_cfg.from {",
        "if let Some(ref from_list) = None::<Vec<String>> {",
        "federation_requires_the_observed_source_address",
    ),
]


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--source-repository", type=Path)
    args = parser.parse_args()
    pin = pins()
    executable = build_test()
    evidence = ROOT / ".artifacts/transport"
    original = evidence / pin["revision"] / "xmsg"
    with tempfile.TemporaryDirectory(prefix="gateway-admission-mutants-") as directory:
        source = Path(directory) / "xmsg"
        clone = ["git", "clone", "--no-checkout"]
        if args.source_repository:
            clone.append("--shared")
        command(
            [*clone, str(args.source_repository or pin["repository"]), str(source)],
            ROOT,
        )
        command(["git", "checkout", "--detach", pin["revision"]], source)
        stamp(source, pin["revision"])
        entry = source / "src/fed.rs"
        unmodified = entry.read_text()
        for name, before, after, case in CASES:
            baseline = live(executable, original, pin["revision"], case=case)
            assert (
                baseline.returncode == 0
                and f"gateway-real-node-complete:federation-{name}" in baseline.stdout
            ), (name, "baseline failed", baseline.stderr)
            # Restrict send-policy mutations to its actual handler, excluding other operations.
            start = (
                unmodified.index("async fn fed_send_message_handler")
                if name != "from"
                else 0
            )
            prefix, body = unmodified[:start], unmodified[start:]
            assert before in body, (name, "mutation site drifted")
            entry.write_text(prefix + body.replace(before, after, 1))
            try:
                binary = build(
                    source,
                    ROOT / "target/xmsg-fixtures",
                    pin["revision"],
                    evidence / f"mutant-{name}/xmsg",
                )
                result = live(executable, binary, pin["revision"], case=case)
                (evidence / f"mutant-{name}.log").write_text(
                    result.stdout + result.stderr
                )
                assert (
                    result.returncode == 101
                    and f"federation {name} refusal was bypassed" in result.stderr
                ), (
                    name,
                    "intended test did not kill mutant",
                    result.stdout,
                    result.stderr,
                )
                print(
                    f"transport mutant {name}: GREEN baseline / RED intended",
                    flush=True,
                )
            finally:
                entry.write_text(unmodified)
        assert len(CASES) == 4
    print("transport-admission-mutants-complete:4/4", flush=True)


if __name__ == "__main__":
    main()
