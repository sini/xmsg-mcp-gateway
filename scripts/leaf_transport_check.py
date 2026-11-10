"""Measure agent.sock leaf service traffic against pinned daemons with/without proc metadata."""

import argparse
import hashlib
import json
import os
import signal
import subprocess
import tempfile
import tomllib
from pathlib import Path

from transport_compat import (
    build,
    build_test,
    command,
    copy_fixture_tree,
    pins,
    refuse_cached_control,
    stamp,
    verify_source,
)

ROOT = Path(__file__).resolve().parents[1]
LEAF = "leaf_agent_socket_send_reply_preserve_service_identity"
CONTROL = "nonleaf_registration_measures_process_metadata_availability"


def run_cell(executable, binary, revision, name, evidence, unavailable=None, hub=None):
    env = {
        **os.environ,
        "XMSG_GATEWAY_BIN": str(binary),
        "XMSG_GATEWAY_REVISION": revision,
        "XMSG_GATEWAY_REQUIRED": "1",
    }
    if hub is not None:
        env["XMSG_GATEWAY_HUB_BIN"] = str(hub)
    env.pop("XMSG_GATEWAY_UNAVAILABLE_PROC_ROOT", None)
    if unavailable is not None:
        assert not unavailable.exists(), "missing-proc fixture path unexpectedly exists"
        env["XMSG_GATEWAY_UNAVAILABLE_PROC_ROOT"] = str(unavailable)
    child = subprocess.Popen(
        [str(executable), "--include-ignored", "--nocapture", name, "--exact"],
        cwd=ROOT,
        env=env,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        start_new_session=True,
    )
    try:
        stdout, stderr = child.communicate(timeout=60)
    except subprocess.TimeoutExpired:
        try:
            os.killpg(child.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        stdout, stderr = child.communicate(timeout=5)
        evidence.write_text(stdout + stderr)
        raise RuntimeError(f"leaf transport cell timed out: {name}") from None
    output = stdout + stderr
    evidence.write_text(output)
    assert child.returncode == 0, (name, child.returncode, output[-5000:])
    assert "test result: ok. 1 passed; 0 failed; 0 ignored;" in stdout
    marker = (
        "gateway-leaf-transport-complete:send-reply-service-identity"
        if name == LEAF
        else "gateway-leaf-proc-control:nonleaf-"
        + ("refused" if unavailable is not None else "accepted")
    )
    assert stdout.count(marker) == 1, ("missing leaf completion", marker)
    print(marker, flush=True)


def build_no_proc_client(work, source, pin, evidence):
    fixture = work / "gateway-no-proc-client"
    fixture.mkdir()
    copy_fixture_tree(fixture)
    manifest_file = fixture / "Cargo.toml"
    manifest = manifest_file.read_text()
    dependency = tomllib.loads(manifest)["dependencies"]["xmsg"]
    assert dependency["default-features"] is False
    assert dependency["features"] == ["client"]
    assert dependency["rev"] == pin["revision"]
    assert dependency["git"] == pin["repository"]
    manifest_file.write_text(
        manifest
        + f"\n[patch.{json.dumps(pin['repository'])}]\n"
        + f"xmsg = {{ path = {json.dumps(str(source))} }}\n"
    )
    command(["cargo", "update", "--offline", "--package", "xmsg"], fixture)
    command(["cargo", "fetch", "--locked"], fixture)
    metadata = json.loads(
        command(
            ["cargo", "metadata", "--offline", "--locked", "--format-version=1"],
            fixture,
        )
    )
    library = [package for package in metadata["packages"] if package["name"] == "xmsg"]
    assert len(library) == 1, "no-proc client must use exactly one xmsg dependency"
    library = library[0]
    assert library["source"] is None, (
        "no-proc client unexpectedly used the git dependency"
    )
    assert Path(library["manifest_path"]).resolve() == (source / "Cargo.toml").resolve()
    resolved = next(
        node for node in metadata["resolve"]["nodes"] if node["id"] == library["id"]
    )
    assert resolved["features"] == ["client"], "no-proc client dependency feature drift"
    digest = hashlib.sha256()
    for file in sorted((source / "src").rglob("*.rs")):
        digest.update(str(file.relative_to(source)).encode())
        digest.update(file.read_bytes())
    dependency_evidence = {
        "manifest_path": library["manifest_path"],
        "source": library["source"],
        "features": resolved["features"],
        "xmsg_source_sha256": digest.hexdigest(),
        "revision": pin["revision"],
    }
    (evidence / "no-proc-client-dependency.json").write_text(
        json.dumps(dependency_evidence, indent=2) + "\n"
    )
    print(
        f"no-proc-client dependency source={digest.hexdigest()} features=client source-dir={source}",
        flush=True,
    )
    target = work / "client-target"
    executable = build_test(fixture, target="leaf_transport", target_dir=target)
    refuse_cached_control(fixture, target="leaf_transport", target_dir=target)
    return executable


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--source-repository", type=Path)
    args = parser.parse_args()
    pin = pins()
    revision = pin["revision"]
    evidence = ROOT / ".artifacts/leaf-transport"
    evidence.mkdir(parents=True, exist_ok=True)
    existing = os.environ.get("XMSG_GATEWAY_BIN")
    normal = Path(existing) if existing else None
    executable = build_test(target="leaf_transport")
    with tempfile.TemporaryDirectory(prefix="gateway-leaf-fixture-") as temporary:
        work = Path(temporary)
        source = work / "source"
        command(
            [
                "git",
                "clone",
                "--no-hardlinks",
                "--no-checkout",
                str(args.source_repository or pin["repository"]),
                str(source),
            ],
            ROOT,
        )
        command(["git", "checkout", "--detach", revision], source)
        verify_source(source, revision)
        stamp(source, revision)
        if normal is None:
            normal = build(source, work / "target", revision, evidence / "normal-xmsg")
        version = command([str(normal), "--version"], ROOT).strip()
        assert version == f"xmsg 0.1.0+{revision}", "normal fixture revision mismatch"
        run_cell(executable, normal, revision, CONTROL, evidence / "normal-control.log")
        run_cell(
            executable, normal, revision, LEAF, evidence / "normal-leaf.log", hub=normal
        )

        process = source / "src/process.rs"
        original = process.read_text()
        needle = 'pub const LIVE_PROC_ROOT: &str = "/proc";'
        assert original.count(needle) == 1, "proc-root fixture source needle drifted"
        unavailable = work / "unavailable-process-metadata"
        assert not unavailable.exists()
        process.write_text(
            original.replace(
                needle,
                f"pub const LIVE_PROC_ROOT: &str = {json.dumps(str(unavailable))};",
            )
        )
        # Cover literal proc users too, including the optional pidfd fdinfo adapter.
        rewritten = 0
        for file in (source / "src").rglob("*.rs"):
            text = file.read_text()
            rewritten += text.count('"/proc')
            file.write_text(text.replace('"/proc', '"' + str(unavailable)))
        assert rewritten > 0, "literal process metadata fixture control disappeared"
        print(
            f"no-proc fixture: LIVE_PROC_ROOT plus {rewritten} literal paths redirected to absent root",
            flush=True,
        )
        no_proc = build(source, work / "target", revision, evidence / "no-proc-xmsg")
        (evidence / "no-proc-source.patch").write_text(command(["git", "diff"], source))
        run_cell(
            executable,
            no_proc,
            revision,
            CONTROL,
            evidence / "no-proc-control.log",
            unavailable,
        )
        no_proc_client = build_no_proc_client(work, source, pin, evidence)
        run_cell(
            no_proc_client,
            no_proc,
            revision,
            LEAF,
            evidence / "no-proc-client-and-daemon-leaf.log",
            unavailable,
            hub=normal,
        )
    print("leaf-transport-complete:normal-and-no-proc", flush=True)
    print("leaf-transport-complete:no-proc-client-and-daemon", flush=True)


if __name__ == "__main__":
    main()
