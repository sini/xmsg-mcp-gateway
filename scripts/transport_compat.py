"""Build revision-verified private daemon fixtures and require real compatibility."""

import argparse
import json
import os
import re
import shutil
import subprocess
import tempfile
import tomllib
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
MARKERS = [
    "roundtrip",
    "wrong-node",
    "federation-allow",
    "federation-principals",
    "federation-targets",
    "federation-from",
    "restart-redelivery",
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
    assert all(
        not item["fresh"]
        for item in artifacts
        if item.get("reason") == "compiler-artifact"
        and item.get("target", {}).get("name") == "xmsg"
        and item.get("executable")
    ), "fixture daemon reused a cached executable"
    output.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(binary[0], output)
    assert (
        command([str(output), "--version"], ROOT).strip() == f"xmsg 0.1.0+{revision}"
    ), "built daemon revision stamp missing"
    return output


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
            "CARGO_TARGET_DIR": str(
                target_dir
                or ROOT / ("target" if root == ROOT else "target/transport-controls")
            ),
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
    return found[0]


def live(executable, binary, revision, *, case=None):
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
    return subprocess.run(
        args, cwd=ROOT, env=env, text=True, capture_output=True, timeout=120
    )


def require_complete(result):
    assert result.returncode == 0, (result.stdout, result.stderr)
    assert (
        "8 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out" in result.stdout
    ), "mandatory live case count/skip mismatch"
    for marker in MARKERS:
        assert result.stdout.count(f"gateway-real-node-complete:{marker}") == 1, (
            f"mandatory live completion missing: {marker}"
        )


def consumer_controls(binary, revision):
    with tempfile.TemporaryDirectory(prefix="gateway-transport-controls-") as directory:
        fixture = Path(directory)
        for name in ("Cargo.toml", "Cargo.lock", "rust-toolchain.toml"):
            shutil.copy2(ROOT / name, fixture / name)
        for name in ("src", "tests", "ci"):
            shutil.copytree(ROOT / name, fixture / name)
        entry = fixture / "tests/real_xmsg.rs"
        original = entry.read_text()
        before = (
            "async fn pinned_node_roundtrip_uses_the_registered_service_identity() {"
        )
        assert original.count(before) == 1
        entry.write_text(original.replace(before, before + "\n    return;", 1))
        skipped = live(build_test(fixture), binary, revision)
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
            build_test(fixture),
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
        result = live(executable, binary, revision)
        (evidence / f"{revision}.log").write_text(result.stdout + result.stderr)
        require_complete(result)
        print(
            f"{revision}: mandatory real-node compatibility 8/8 completed", flush=True
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
    print("transport-compat-complete:2-revisions-8-cases", flush=True)


if __name__ == "__main__":
    main()
