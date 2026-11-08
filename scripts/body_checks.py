"""Run the complete-frame JSON expansion utility against the pinned real daemon."""

import os
from pathlib import Path

from grant_mutants import run
from transport_compat import ROOT, pins


def main():
    pin = pins()
    assert Path(os.environ["XMSG_GATEWAY_BIN"]).is_file()
    os.environ["XMSG_GATEWAY_REVISION"] = pin["revision"]
    test = "maximum_escaped_complete_frame_survives_the_real_listener"
    # Force the intended library, CLI and named test to rebuild for artifact receipts.
    for file in (ROOT / "src").glob("*.rs"):
        file.touch()
    result = run(
        ROOT,
        "content_length",
        test,
        "src/serving.rs",
        application=True,
        test_args=("--ignored",),
        test_timeout=60,
    )
    evidence = ROOT / ".artifacts/body"
    evidence.mkdir(parents=True, exist_ok=True)
    (evidence / "maximum-escaped-frame.log").write_text(result.stdout + result.stderr)
    assert (
        result.returncode == 0 and "1 passed; 0 failed; 0 ignored" in result.stdout
    ), result
    assert result.stdout.count("content-length-complete:maximum-escaped-frame:") == 1, (
        result
    )
    print("body profile:1/1 complete escaped frame, zero ignored", flush=True)


if __name__ == "__main__":
    main()
