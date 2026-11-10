"""Require zero-byte cancellation recovery and strict partial-request failure."""

import subprocess
import tempfile
from pathlib import Path

from artifact_evidence import record
from transport_compat import ROOT, build_test, copy_fixture_tree, invocation_evidence

TEST = "partial_tls_eof_is_a_fixture_error"
REFUSAL = "serving provider fixture worker did not exit within 3 seconds"
SITE = """        assert_ne!(
            reader.read_line(&mut line).unwrap(),
            0,
            "partial provider request ended during headers"
        );"""


def main():
    source = (ROOT / "tests/common/provider.rs").read_text()
    assert source.count(SITE) == 1, "header EOF source site changed"
    mutant = source.replace(SITE, "        reader.read_line(&mut line).unwrap();")
    for arm, text in (("positive", source), ("ignore-header-eof", mutant)):
        with tempfile.TemporaryDirectory(
            prefix=f"gateway-provider-eof-{arm}-"
        ) as directory:
            root = Path(directory)
            copy_fixture_tree(root)
            (root / "tests/common/provider.rs").write_text(text)
            executable = Path(build_test(root, target="provider_eof"))
            record(root, executable, arm)
            args = [str(executable), "--nocapture"]
            invocation_evidence(args)
            result = subprocess.run(
                args,
                cwd=root,
                capture_output=True,
                text=True,
                timeout=15,
            )
            output = result.stdout + result.stderr
            if arm == "positive":
                assert result.returncode == 0 and "5 passed" in output, output
            else:
                assert result.returncode != 0, "ignored-header-EOF mutant survived"
                assert REFUSAL in output and f"{TEST} - should panic ... FAILED" in output, output
                assert "4 passed; 1 failed" in output, output
                print(
                    f"named mutant refusal: {REFUSAL}; 4 passed; 1 failed", flush=True
                )
            print(f"provider-eof-{arm}: verified", flush=True)


if __name__ == "__main__":
    main()
