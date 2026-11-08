"""Require clean TLS EOF recovery and reject a single-site ignored-EOF mutant."""

import subprocess
import tempfile
from pathlib import Path

from artifact_evidence import record
from transport_compat import ROOT, build_test, copy_fixture_tree, invocation_evidence

TEST = "clean_tls_eof_during_headers_releases_provider_fixture"
REFUSAL = "serving provider fixture worker did not exit within 3 seconds"
SITE = """        if reader.read_line(&mut line).unwrap() == 0 {
            return None;
        }"""


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
                assert result.returncode == 0 and "2 passed" in output, output
            else:
                assert result.returncode != 0, "ignored-header-EOF mutant survived"
                assert REFUSAL in output and f"{TEST} ... FAILED" in output, output
                assert "1 passed; 1 failed" in output, output
                print(
                    f"named mutant refusal: {REFUSAL}; 1 passed; 1 failed", flush=True
                )
            print(f"provider-eof-{arm}: verified", flush=True)


if __name__ == "__main__":
    main()
