"""Prove early body refusal and startup budget with independently rebuilt source arms."""

import tempfile
from pathlib import Path

import grant_mutants
from artifact_evidence import NONCE, record
from transport_compat import ROOT, copy_fixture_tree

SOURCE = (ROOT / "src/serving.rs").read_text()
EARLY_START = SOURCE.index("    if method == Method::POST\n")
EARLY_END = SOURCE.index("    let raw = if method == Method::POST", EARLY_START)
EARLY = SOURCE[EARLY_START:EARLY_END]
LATE = SOURCE.index(
    "    let identity = match app.verifier.verify(&token).await", EARLY_END
)
MOVED = SOURCE[:EARLY_START] + SOURCE[EARLY_END:LATE] + EARLY + SOURCE[LATE:]
BOUND = "if config.max_request_body_bytes < minimum {"
assert SOURCE.count(BOUND) == 1
CASES = [
    (
        "late-length-check",
        MOVED,
        "oversized_advertised_body_is_refused_before_body_bytes",
        "oversized declared body waited for body bytes",
        True,
    ),
    (
        "missing-startup-budget",
        SOURCE.replace(BOUND, "if false && config.max_request_body_bytes < minimum {"),
        "insufficient_escaped_body_budget_is_a_typed_startup_refusal",
        "insufficient escaped request budget was accepted or refused for the wrong reason",
        False,
    ),
]


def main():
    evidence = ROOT / ".artifacts/body-mutants" / NONCE
    evidence.mkdir(parents=True)
    for name, mutant, test, reason, application in CASES:
        for arm, source in (("positive", SOURCE), ("mutant", mutant)):
            with tempfile.TemporaryDirectory(
                prefix=f"gateway-body-{name}-{arm}-"
            ) as directory:
                root = Path(directory)
                copy_fixture_tree(root)
                (root / "src/serving.rs").write_text(source)
                # run() uses ROOT for its target dir: each source arm gets its own build tree.
                grant_mutants.ROOT = root
                result = grant_mutants.run(
                    root,
                    "content_length",
                    test,
                    "src/serving.rs",
                    application=application,
                )
                libraries = list(
                    (root / "target/grant-mutants-build/debug").rglob(
                        "libxmsg_mcp_gateway*.rlib"
                    )
                )
                assert len(libraries) == 1, "intended rebuilt library missing"
                record(
                    root, libraries[0], f"library/{name}/{arm}", directories=("src",)
                )
                (evidence / f"{name}-{arm}.log").write_text(
                    result.stdout + result.stderr
                )
                if arm == "positive":
                    assert (
                        result.returncode == 0
                        and "1 passed; 0 failed; 0 ignored" in result.stdout
                    ), result
                else:
                    assert (
                        result.returncode == 101
                        and f"test {test} ... FAILED" in result.stdout
                        and reason in result.stdout
                    ), result
            print(f"{name}/{arm}: intended result", flush=True)
    print("2/2 body mutants killed", flush=True)


if __name__ == "__main__":
    main()
