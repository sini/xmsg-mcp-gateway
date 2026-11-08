"""Build revision-verified private daemon fixtures and require real compatibility."""

import argparse
import hashlib
import json
import os
import re
import shutil
import signal
import subprocess
import tempfile
import tomllib
from pathlib import Path

from artifact_evidence import record

ROOT = Path(__file__).resolve().parents[1]
MARKERS = [
    "roundtrip",
    "wrong-node",
    "federation-allow",
    "federation-principals",
    "federation-targets",
    "federation-from",
    "restart-redelivery",
    "socket-activation",
]


def failure_tail(result):
    return (result.returncode, result.stdout[-4000:], result.stderr[-4000:])


def command(args, cwd, *, env=None, timeout=300):
    result = subprocess.run(
        args, cwd=cwd, env=env, text=True, capture_output=True, timeout=timeout
    )
    assert result.returncode == 0, (
        args[0:3],
        result.returncode,
        result.stdout[-5000:],
        result.stderr[-5000:],
    )
    return result.stdout


def pins():
    pin = tomllib.loads((ROOT / "ci/xmsg-pin.toml").read_text())
    manifest = tomllib.loads((ROOT / "Cargo.toml").read_text())["dependencies"]["xmsg"]
    assert (
        manifest["git"] == pin["repository"] and manifest["rev"] == pin["revision"]
    ), "library/source pin mismatch"
    assert manifest["default-features"] is False and manifest["features"] == [
        "client"
    ], "client-only dependency required"
    package = next(
        p
        for p in tomllib.loads((ROOT / "Cargo.lock").read_text())["package"]
        if p["name"] == "xmsg"
    )
    assert (
        package["source"]
        == f"git+{pin['repository']}?rev={pin['revision']}#{pin['revision']}"
    ), "library lock pin mismatch"
    for field in ("revision", "baseline_revision"):
        assert re.fullmatch("[0-9a-f]{40}", pin[field]), (
            "full fixture revision required"
        )
    return pin


def verify_source(source, expected):
    actual = command(["git", "rev-parse", "HEAD"], source).strip()
    assert actual == expected, "actual source revision differs from expected revision"


def stamp(source, revision):
    verify_source(source, revision)
    assert not command(
        ["git", "status", "--porcelain", "--untracked-files=all"], source
    ).strip(), "fixture source must start clean"
    entry = source / "src/main.rs"
    text = entry.read_text()
    assert text.count("    version,") == 1, "fixture CLI stamp site drifted"
    entry.write_text(
        text.replace("    version,", f'    version = "0.1.0+{revision}",', 1)
    )


def build(source, target, revision, output):
    env = {**os.environ, "CARGO_TARGET_DIR": str(target)}
    log = command(
        [
            "cargo",
            "build",
            "--locked",
            "--bin",
            "xmsg",
            "-j",
            "4",
            "--message-format=json",
        ],
        source,
        env=env,
        timeout=900,
    )
    artifacts = [json.loads(line) for line in log.splitlines() if line.startswith("{")]
    binary = [
        item["executable"]
        for item in artifacts
        if item.get("reason") == "compiler-artifact"
        and item.get("target", {}).get("name") == "xmsg"
        and item.get("executable")
    ]
    assert len(binary) == 1, "fixture daemon executable missing"
    if not all(
        not item["fresh"]
        for item in artifacts
        if item.get("reason") == "compiler-artifact"
        and item.get("target", {}).get("name") == "xmsg"
        and item.get("executable")
    ):
        raise RuntimeError("fixture daemon reused a cached executable")
    record(source, Path(binary[0]), "xmsg-daemon")
    output.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(binary[0], output)
    assert (
        command([str(output), "--version"], ROOT).strip() == f"xmsg 0.1.0+{revision}"
    ), "built daemon revision stamp missing"
    return output


def copy_fixture_tree(destination):
    for name in ("Cargo.toml", "Cargo.lock", "rust-toolchain.toml"):
        shutil.copyfile(ROOT / name, destination / name)
    for name in ("src", "tests", "ci"):
        shutil.copytree(ROOT / name, destination / name, copy_function=shutil.copyfile)


def build_test(root=ROOT, *, target="real_xmsg", target_dir=None):
    log = command(
        [
            "cargo",
            "test",
            "--locked",
            "--test",
            target,
            "--no-run",
            "-j",
            "4",
            "--message-format=json",
        ],
        root,
        env={
            **os.environ,
            "CARGO_TARGET_DIR": str(target_dir or root / "target"),
        },
    )
    records = [json.loads(line) for line in log.splitlines() if line.startswith("{")]
    found = [
        item["executable"]
        for item in records
        if item.get("reason") == "compiler-artifact"
        and item.get("target", {}).get("name") == target
        and item.get("profile", {}).get("test")
        and item.get("executable")
    ]
    assert len(found) == 1, "mandatory real-node test binary absent"
    if root != ROOT:
        rebuilt = [
            item
            for item in records
            if item.get("reason") == "compiler-artifact"
            and (
                item.get("target", {}).get("name") == "xmsg_mcp_gateway"
                or item.get("executable") == found[0]
            )
        ]
        if len(rebuilt) != 2 or not all(
            not item.get("fresh", True) for item in rebuilt
        ):
            raise RuntimeError("copied control reused a cached artifact")
        record(root, Path(found[0]), target)
    return found[0]


def refuse_cached_control(root, *, target, target_dir):
    try:
        build_test(root, target=target, target_dir=target_dir)
    except RuntimeError as error:
        if str(error) != "copied control reused a cached artifact":
            raise
    else:
        raise RuntimeError("cached copied-control artifact was accepted")
    print(f"copied-control-cached-artifact:refused:{target}", flush=True)


def timeout_progress(partial, stream):
    if not partial:
        return
    tail = partial[-65_536:]
    if isinstance(tail, bytes):
        tail = tail.decode("utf-8", errors="replace")
    progress = []
    for line in tail.splitlines():
        match = re.fullmatch(
            r"test ([A-Za-z_][A-Za-z_0-9:]*) (?:\.\.\.(?: (ok|FAILED|ignored))?|has been running for over [0-9]+ seconds)",
            line,
        )
        if match and len(match[1]) <= 200:
            progress.append((match[1], match[2] or "running"))
    for name, state in progress[-16:]:
        print(f"live-timeout {stream} test={name} state={state}", flush=True)


def invocation_evidence(args):
    """Return and emit provenance for the exact argv passed to the test process."""
    if hasattr(os, "sched_getaffinity"):
        available = len(os.sched_getaffinity(0))
    else:
        available = getattr(os, "process_cpu_count", os.cpu_count)() or 1
    with Path(args[0]).open("rb") as executable:
        digest = hashlib.file_digest(executable, "sha256").hexdigest()
    evidence = {
        "command": [str(argument) for argument in args],
        "available_cpu_count": available,
        "test_binary_sha256": digest,
    }
    print("live-invocation " + json.dumps(evidence, sort_keys=True), flush=True)
    return evidence


def owned_processes(process):
    # The new session/group contains only this invocation and its descendants.
    result = subprocess.run(
        ["ps", "-o", "pid=,comm=", "-g", str(process.pid)],
        text=True,
        capture_output=True,
        timeout=2,
    )
    if result.returncode not in (0, 1):
        raise RuntimeError("owned process identity query failed")
    owned = []
    for line in result.stdout.splitlines():
        pid, name = line.strip().split(None, 1)
        owned.append((int(pid), Path(name).name))
    return owned


def report_timeout(error, owned, root_pid):
    summary_seen = any(
        re.search(rb"(?m)^test result: (?:ok|FAILED)\. [0-9]+ passed;", partial)
        for partial in (error.stdout or b"", error.stderr or b"")
    )
    print(f"live-timeout summary-seen={str(summary_seen).lower()}", flush=True)
    for pid, name in owned[:32]:
        role = "owned-root" if pid == root_pid else "owned-child"
        print(f"live-timeout {role} pid={pid} name={json.dumps(name)}", flush=True)
    timeout_progress(error.stdout, "stdout")
    timeout_progress(error.stderr, "stderr")


def live(
    executable, binary, revision, *, case=None, skip=None, baseline=False, timeout=120
):
    env = {
        **os.environ,
        "XMSG_GATEWAY_REQUIRED": "1",
        "XMSG_GATEWAY_REVISION": revision,
    }
    if binary is None:
        env.pop("XMSG_GATEWAY_BIN", None)
    else:
        env["XMSG_GATEWAY_BIN"] = str(binary)
    args = [str(executable), "--include-ignored", "--nocapture"]
    if case:
        args.extend([case, "--exact"])
    if skip:
        args.extend(["--skip", skip])
    if baseline:
        args.extend(["--skip", "federation_", "--skip", "socket_activation_"])
    invocation_evidence(args)
    process = subprocess.Popen(
        args,
        cwd=ROOT,
        env=env,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        start_new_session=True,
    )
    try:
        stdout, stderr = process.communicate(timeout=timeout)
        return subprocess.CompletedProcess(args, process.returncode, stdout, stderr)
    except subprocess.TimeoutExpired as error:
        try:
            try:
                owned = owned_processes(process)
            except (OSError, RuntimeError, ValueError, subprocess.TimeoutExpired):
                owned = []
                print("live-timeout owned-inspection=unavailable", flush=True)
            report_timeout(error, owned, process.pid)
        finally:
            # start_new_session made this launch-captured process group ours.
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            try:
                process.communicate(timeout=2)
            except subprocess.TimeoutExpired:
                process.stdout.close()
                process.stderr.close()
                process.wait(timeout=2)
        raise RuntimeError("live test suite timed out") from None


def require_complete(result, *, baseline=False):
    assert result.returncode == 0, (result.stdout, result.stderr)
    assert (
        "test result: ok. 4 passed; 0 failed; 0 ignored; 0 measured; 5 filtered out"
        if baseline
        else "test result: ok. 9 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out"
    ) in result.stdout, "mandatory live case count/skip mismatch"
    for marker in MARKERS:
        if baseline and (
            marker.startswith("federation-") or marker == "socket-activation"
        ):
            continue
        assert result.stdout.count(f"gateway-real-node-complete:{marker}") == 1, (
            f"mandatory live completion missing: {marker}"
        )


def consumer_controls(binary, revision):
    with tempfile.TemporaryDirectory(prefix="gateway-transport-controls-") as directory:
        fixture = Path(directory)
        copy_fixture_tree(fixture)
        entry = fixture / "tests/real_xmsg.rs"
        original = entry.read_text()
        before = (
            "async fn pinned_node_roundtrip_uses_the_registered_service_identity() {"
        )
        assert original.count(before) == 1
        entry.write_text(original.replace(before, before + "\n    return;", 1))
        skip_target = fixture / "target/skip"
        executable = build_test(fixture, target_dir=skip_target)
        refuse_cached_control(fixture, target="real_xmsg", target_dir=skip_target)
        skipped = live(executable, binary, revision)
        assert skipped.returncode == 0, (
            "early-return control failed before completion guard",
            failure_tail(skipped),
        )
        try:
            require_complete(skipped)
        except AssertionError as error:
            assert "completion missing: roundtrip" in str(error)
        else:
            raise AssertionError("early-return control escaped completion guard")
        entry.write_text(original)
        config = fixture / "src/xmsg_config.rs"
        original_config = config.read_text()
        before = "expected_node: Some(self.expected_node.clone()),"
        assert original_config.count(before) == 1
        config.write_text(original_config.replace(before, "expected_node: None,", 1))
        result = live(
            build_test(fixture, target_dir=fixture / "target/expected-node"),
            binary,
            revision,
            case="pinned_node_refuses_a_different_configured_identity",
        )
        assert (
            result.returncode == 101 and "assertion failed: matches!" in result.stderr
        ), ("expected-node mutant was not killed by its named assertion", result.stderr)
    print(
        "early-return control refused; expected-node source mutant killed", flush=True
    )


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--source-repository", type=Path)
    parser.add_argument("--build-only", action="store_true")
    args = parser.parse_args()
    pin = pins()
    evidence = ROOT / ".artifacts/transport"
    evidence.mkdir(parents=True, exist_ok=True)
    tree = command(["cargo", "tree", "--locked", "-p", "xmsg", "-e", "normal"], ROOT)
    for package in (
        "rusqlite",
        "rustls",
        "axum",
        "reqwest",
        "matrix-sdk",
        "tokio-rustls",
        "rcgen",
    ):
        assert not re.search(rf"\b{re.escape(package)} v", tree), (
            f"daemon dependency in client-only graph: {package}"
        )
    (evidence / "client-normal-tree.txt").write_text(tree)
    binaries = {}
    with tempfile.TemporaryDirectory(prefix="gateway-xmsg-fixtures-") as directory:
        for key in ("revision", "baseline_revision"):
            revision = pin[key]
            source = Path(directory) / revision
            origin = (
                str(args.source_repository)
                if args.source_repository
                else pin["repository"]
            )
            clone = ["git", "clone", "--no-checkout"]
            if args.source_repository:
                clone.append("--shared")
            command([*clone, origin, str(source)], ROOT)
            command(["git", "checkout", "--detach", revision], source)
            verify_source(source, revision)
            try:
                verify_source(
                    source,
                    pin["baseline_revision"] if key == "revision" else pin["revision"],
                )
            except AssertionError:
                pass
            else:
                raise AssertionError("wrong actual source revision was accepted")
            print(
                f"{key}: source revision verified, wrong-revision control refused",
                flush=True,
            )
            stamp(source, revision)
            binaries[revision] = build(
                source,
                ROOT / "target/xmsg-fixtures",
                revision,
                evidence / revision / "xmsg",
            )
            (evidence / revision / "source.json").write_text(
                json.dumps(
                    {
                        "repository": pin["repository"],
                        "revision": revision,
                        "cli_stamp_only": True,
                    }
                )
                + "\n"
            )
            print(f"{key}: built revision-stamped daemon {revision}", flush=True)
    if args.build_only:
        return
    executable = build_test()
    for revision, binary in binaries.items():
        baseline = revision == pin["baseline_revision"]
        result = live(executable, binary, revision, baseline=baseline)
        (evidence / f"{revision}.log").write_text(result.stdout + result.stderr)
        require_complete(result, baseline=baseline)
        print(
            f"{revision}: mandatory real-node compatibility {'4/4 Unix-only' if baseline else '9/9'} completed",
            flush=True,
        )
    case = "pinned_node_roundtrip_uses_the_registered_service_identity"
    missing = live(executable, None, pin["revision"], case=case)
    assert (
        missing.returncode == 101
        and "required pinned xmsg binary missing" in missing.stderr
    ), "missing fixture was not refused"
    wrong = live(
        executable, binaries[pin["baseline_revision"]], pin["revision"], case=case
    )
    assert wrong.returncode == 101 and "wrong xmsg fixture revision" in wrong.stderr, (
        "wrong binary revision was not refused"
    )
    print(
        "missing fixture and wrong binary revision: required refusals verified",
        flush=True,
    )
    consumer_controls(binaries[pin["revision"]], pin["revision"])
    print("transport-compat-complete:pinned-9-baseline-unix-4", flush=True)


if __name__ == "__main__":
    main()
