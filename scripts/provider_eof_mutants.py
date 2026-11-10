"""Require strict incomplete requests and bounded post-complete cancellation."""

import hashlib
import json
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
STOP_SITE = """        if let Some(socket) = self.active.lock().unwrap().take() {
            let _ = socket.shutdown(Shutdown::Both);
        }"""


def main():
    source = (ROOT / "tests/common/provider.rs").read_text()
    serving = (ROOT / "tests/common/serving_fixture.rs").read_text()
    assert source.count(SITE) == 1, "header EOF source site changed"
    assert serving.count(STOP_SITE) == 1, "active socket cancellation site changed"
    write_site = source[source.index("pub fn write_complete_response(") :].strip()
    write_mutant = """pub fn write_complete_response(stream: &mut impl Write, response: &[u8]) -> bool {
    stream.write_all(response).and_then(|_| stream.flush()).unwrap();
    true
}"""
    evidence = ROOT / ".artifacts/cy740/provider-mutants"
    evidence.mkdir(parents=True, exist_ok=True)
    arms = [
        ("positive", source, serving, None, None),
        (
            "ignore-header-eof",
            source.replace(SITE, "        reader.read_line(&mut line).unwrap();"),
            serving,
            TEST,
            REFUSAL,
        ),
        (
            "post-complete-write-unwrap",
            source.replace(write_site, write_mutant),
            serving,
            "complete_request_cancelled_response_write_is_quiet",
            "post-complete cancellation panicked in response write",
        ),
        (
            "active-stop-without-shutdown",
            source,
            serving.replace(STOP_SITE, "        self.active.lock().unwrap().take();"),
            "active_partial_body_stop_is_strict_without_teardown_timeout",
            "active I/O exceeded teardown instead of strict partial failure",
        ),
        ("restored", source, serving, None, None),
    ]
    results = []
    for arm, text, fixture, test, diagnostic in arms:
        with tempfile.TemporaryDirectory(prefix=f"gateway-provider-eof-{arm}-") as directory:
            root = Path(directory)
            copy_fixture_tree(root)
            (root / "tests/common/provider.rs").write_text(text)
            (root / "tests/common/serving_fixture.rs").write_text(fixture)
            executable = Path(build_test(root, target="provider_eof", target_dir=evidence / "build"))
            record(root, executable, arm)
            args = [str(executable), "--nocapture"]
            if test:
                args += ["--exact", test]
            invocation_evidence(args)
            result = subprocess.run(args, cwd=root, capture_output=True, text=True, timeout=15)
            output = result.stdout + result.stderr
            (evidence / f"{arm}.log").write_text(output)
            item = {
                "arm": arm,
                "exit": result.returncode,
                "test": test,
                "provider_sha256": hashlib.sha256(text.encode()).hexdigest(),
                "fixture_sha256": hashlib.sha256(fixture.encode()).hexdigest(),
                "binary_sha256": hashlib.sha256(executable.read_bytes()).hexdigest(),
            }
            results.append(item)
            if test:
                named = f"{test} - should panic ... FAILED" if test == TEST else f"{test} ... FAILED"
                assert result.returncode == 101 and named in output, output
                assert diagnostic in output and "0 passed; 1 failed" in output, output
                print(f"provider-eof RED {arm}: {named}; {diagnostic}", flush=True)
            else:
                assert result.returncode == 0 and "7 passed; 0 failed" in output, output
                print(f"provider-eof GREEN {arm}: 7 passed; 0 failed", flush=True)
            print(f"provider-eof-{arm}: verified", flush=True)
    (evidence / "results.json").write_text(json.dumps(results, indent=2) + "\n")
    print("provider-eof-mutants-complete:3/3", flush=True)


if __name__ == "__main__":
    main()
