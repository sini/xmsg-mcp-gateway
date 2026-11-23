#!/usr/bin/env python3
"""Measure this migration unit's isolated source faults with atomic arm receipts."""

import argparse
import hashlib
import json
import os
import re
import shutil
import signal
import stat
import subprocess
import time
import uuid
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
BUILD_NONCE = "GATEWAY_MIGRATION_BUILD_NONCE"
PROOF_NONCE = "GATEWAY_MIGRATION_PROOF_NONCE"
CLI_PATH = "GATEWAY_MIGRATION_PROOF_CLI"
CLI_HASH = "GATEWAY_MIGRATION_PROOF_CLI_SHA256"
PRODUCTION = {"src/grants.rs", "src/grants_backup.rs", "src/main.rs"}
CLI_RUN = b"""fn run(file: &Path, args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_xmsg-mcp-gateway"))
        .arg("--state")
        .arg(file)
        .args(args)
        .output()
        .unwrap()
}"""
CLI_RUN_GUARDED = b"""fn run(file: &Path, args: &[&str]) -> Output {
    use sha2::Digest;
    let binary = env!("CARGO_BIN_EXE_xmsg-mcp-gateway");
    let before = sha2::Sha256::digest(std::fs::read(binary).unwrap());
    let encoded: String = before.iter().map(|byte| format!("{byte:02x}")).collect();
    assert_eq!(encoded, std::env::var("GATEWAY_MIGRATION_PROOF_CLI_SHA256").unwrap(), "CLI artifact changed before invocation");
    let output = Command::new(binary).arg("--state").arg(file).args(args).output().unwrap();
    let after = sha2::Sha256::digest(std::fs::read(binary).unwrap());
    assert_eq!(before, after, "CLI artifact changed after invocation");
    eprintln!("unit5-cli-receipt:{}", serde_json::json!({
        "path": binary, "sha256": encoded, "exit": output.status.code(),
        "operation": args.first().copied().unwrap_or(""),
        "nonce": env!("GATEWAY_MIGRATION_BUILD_NONCE")
    }));
    output
}"""


def sha(data):
    return hashlib.sha256(data).hexdigest()


def atomic_json(destination, value):
    temporary = destination.with_name(destination.name + ".new")
    with temporary.open("w") as output:
        json.dump(value, output, indent=2)
        output.write("\n")
        output.flush()
        os.fsync(output.fileno())
    temporary.replace(destination)
    descriptor = os.open(destination.parent, os.O_RDONLY)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def originals():
    names = subprocess.check_output(["git", "ls-files", "-z"], cwd=ROOT).split(b"\0")
    result = {}
    for encoded in names:
        if not encoded:
            continue
        relative = os.fsdecode(encoded)
        entry = ROOT / relative
        if entry.is_symlink() or not entry.is_file():
            raise ValueError(
                "protected input must be a regular tracked file: " + relative
            )
        result[relative] = (entry.read_bytes(), stat.S_IMODE(entry.stat().st_mode))
    return result


def verify(base, expected):
    for relative, (data, mode) in expected.items():
        entry = base / relative
        if entry.is_symlink() or not entry.is_file():
            raise RuntimeError("source guard failed: " + relative)
        if entry.read_bytes() != data or stat.S_IMODE(entry.stat().st_mode) != mode:
            raise RuntimeError("source guard failed: " + relative)
    for folder in ["src", "tests", ".cargo"]:
        found = {
            str(entry.relative_to(base))
            for entry in (base / folder).rglob("*")
            if entry.is_file() or entry.is_symlink()
        }
        required = {entry for entry in expected if Path(entry).parts[0] == folder}
        if found != required:
            raise RuntimeError("recursive input inventory changed: " + folder)
    for optional in ["build.rs", "rust-toolchain", "rust-toolchain.toml"]:
        if (base / optional).exists() and optional not in expected:
            raise RuntimeError("undeclared root build input: " + optional)
    if base != ROOT:
        found = {
            str(entry.relative_to(base))
            for entry in base.rglob("*")
            if entry.is_file() or entry.is_symlink()
        }
        if found != set(expected):
            raise RuntimeError("isolated source inventory changed")


def rows(output):
    result = []
    for line in output.splitlines():
        try:
            result.append(json.loads(line))
        except (json.JSONDecodeError, UnicodeDecodeError):
            continue
    return result


def executable(records, target, kind, name, testing, require_fresh=True):
    selected = [
        item
        for item in records
        if item.get("reason") == "compiler-artifact"
        and item.get("executable")
        and item.get("target", {}).get("kind") == [kind]
        and item.get("target", {}).get("name") == name
        and item.get("profile", {}).get("test") is testing
    ]
    if len(selected) != 1:
        raise RuntimeError("expected exactly one selected executable")
    item = selected[0]
    binary = Path(item["executable"])
    if binary.is_symlink() or not binary.resolve().is_relative_to(target.resolve()):
        raise RuntimeError("artifact isolation guard failed")
    if require_fresh and item.get("fresh") is not False:
        raise RuntimeError("cached artifact refused")
    metadata = binary.stat()
    parent = binary.parent.stat()
    return {
        "path": str(binary),
        "sha256": sha(binary.read_bytes()),
        "fresh": item["fresh"],
        "mode": stat.S_IMODE(metadata.st_mode),
        "parent_dev": parent.st_dev,
        "parent_ino": parent.st_ino,
        "target_root": str(target.resolve()),
    }


def verify_artifacts(artifacts):
    for item in artifacts.values():
        binary = Path(item["path"])
        parent = binary.parent.stat()
        if (
            binary.is_symlink()
            or not binary.resolve().is_relative_to(item["target_root"])
            or sha(binary.read_bytes()) != item["sha256"]
            or stat.S_IMODE(binary.stat().st_mode) != item["mode"]
            or (parent.st_dev, parent.st_ino)
            != (item["parent_dev"], item["parent_ino"])
        ):
            raise RuntimeError("artifact identity guard failed")


def validate(cases):
    names = [case["id"] for case in cases]
    if len(names) != len(set(names)) or any(
        not re.fullmatch(r"[a-z][a-z0-9-]*", name) for name in names
    ):
        raise ValueError("case IDs must be unique safe path components")
    for case in cases:
        if case["file"] not in PRODUCTION:
            raise ValueError("mutation must target this unit's production source")
        source = (ROOT / case["file"]).read_text()
        if source.count(case["needle"]) != 1 or case["needle"] == case["replacement"]:
            raise ValueError(
                "production anchor missing, ambiguous or no-op: " + case["id"]
            )
        offset = source.index(case["needle"])
        boundary = source.find("#[cfg(test)]")
        if boundary != -1 and offset >= boundary:
            raise ValueError("test-only mutation refused")
        if case["target"] not in {"lib", "migrations"}:
            raise ValueError("unknown witness target")
        relative = Path(case["test_file"])
        if (
            relative.is_absolute()
            or ".." in relative.parts
            or relative.parts[0] not in {"src", "tests"}
        ):
            raise ValueError("unsafe witness path")
        if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", case["test"]):
            raise ValueError("unsafe witness function")
        if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_:]*", case["qualified_test"]):
            raise ValueError("unsafe qualified witness")
        if not case["qualified_test"].endswith(case["test"]) or not case["assertion"]:
            raise ValueError("witness metadata mismatch")
        anchor = "fn " + case["test"] + "() {"
        if (ROOT / relative).read_text().count(anchor) != 1:
            raise ValueError("witness anchor missing or ambiguous")
        if (
            case["target"] == "migrations"
            and (ROOT / relative).read_bytes().count(CLI_RUN) != 1
        ):
            raise ValueError("CLI invocation helper must be unique")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--evidence", type=Path)
    parser.add_argument("--work-root", type=Path)
    parser.add_argument("--seed-target", type=Path)
    parser.add_argument("--case", action="append", default=[])
    parser.add_argument("--preflight", action="store_true")
    args = parser.parse_args()
    cases = json.loads(args.manifest.read_text())
    validate(cases)
    identifiers = {case["id"] for case in cases}
    if len(args.case) != len(set(args.case)) or not set(args.case) <= identifiers:
        raise ValueError("unknown or duplicate case selection")
    if args.case:
        cases = [case for case in cases if case["id"] in args.case]
    head = subprocess.check_output(
        ["git", "rev-parse", "HEAD"], cwd=ROOT, text=True
    ).strip()
    if args.preflight:
        print(
            json.dumps(
                {
                    "status": "anchors-only-not-compilation",
                    "head": head,
                    "cases": [case["id"] for case in cases],
                }
            )
        )
        return
    if args.evidence is None or args.work_root is None:
        raise ValueError("evidence and work-root are required for flight")
    if subprocess.check_output(["git", "status", "--porcelain"], cwd=ROOT).strip():
        raise ValueError("source flight requires a clean immutable checkout")
    rustc = subprocess.check_output(
        [os.environ.get("RUSTC", "rustc"), "--version"], text=True
    ).strip()
    cargo = subprocess.check_output(["cargo", "--version"], text=True).strip()
    if not rustc.startswith("rustc 1.95.0 ") or not cargo.startswith("cargo 1.95.0 "):
        raise ValueError("flight requires the repository's Rust/Cargo 1.95.0 pin")
    evidence = args.evidence.resolve()
    work = args.work_root.resolve()
    if evidence.is_relative_to(ROOT) or work.is_relative_to(ROOT) or work == evidence:
        raise ValueError(
            "flight output/build trees must be outside the reported checkout"
        )
    evidence.mkdir(parents=True, exist_ok=False)
    work.mkdir(parents=True, exist_ok=False)
    original = originals()
    verify(ROOT, original)
    ledger = {
        "head": head,
        "status": "running",
        "toolchain": {"rustc": rustc, "cargo": cargo},
        "protected": {
            key: {"sha256": sha(data), "mode": mode}
            for key, (data, mode) in original.items()
        },
        "controls": {},
        "arms": [],
        "commands": [],
    }

    def persist():
        atomic_json(evidence / "results.json", ledger)

    def command(argv, cwd, stem, environment, timeout):
        started = time.monotonic()
        receipt = {
            "label": stem,
            "argv": argv,
            "cwd": str(cwd),
            "timeout_seconds": timeout,
            "status": "running",
        }
        ledger["commands"].append(receipt)
        persist()
        try:
            process = subprocess.Popen(
                argv,
                cwd=cwd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                env=environment,
                start_new_session=os.name == "posix",
            )
        except BaseException as error:
            receipt.update(
                {
                    "status": "spawn_failed",
                    "error": type(error).__name__ + ": " + str(error),
                }
            )
            persist()
            raise
        interrupted = None
        try:
            receipt["pid"] = process.pid
            persist()
            stdout, stderr = process.communicate(timeout=timeout)
        except BaseException as error:
            interrupted = error
            try:
                if os.name == "posix":
                    os.killpg(process.pid, signal.SIGKILL)
                else:
                    process.kill()
            except ProcessLookupError:
                pass
            try:
                stdout, stderr = process.communicate(timeout=5)
            except subprocess.TimeoutExpired as stalled:
                stdout, stderr = stalled.output or b"", stalled.stderr or b""
                for pipe in [process.stdout, process.stderr]:
                    if pipe is not None:
                        pipe.close()
                process.wait(timeout=5)
        for suffix, data in [(".stdout", stdout), (".stderr", stderr)]:
            with (evidence / (stem + suffix)).open("wb") as output:
                output.write(data)
                output.flush()
                os.fsync(output.fileno())
        receipt.update(
            {
                "exit": process.returncode,
                "stdout_sha256": sha(stdout),
                "stderr_sha256": sha(stderr),
                "elapsed_seconds": time.monotonic() - started,
                "status": "completed" if interrupted is None else "interrupted",
            }
        )
        persist()
        if interrupted is not None:
            raise interrupted
        return subprocess.CompletedProcess(argv, process.returncode, stdout, stderr)

    def build_inner(source, target, case, nonce, stem, require_fresh=True):
        environment = {
            **os.environ,
            "CARGO_TARGET_DIR": str(target),
            BUILD_NONCE: nonce,
        }
        selection = ["--lib"] if case["target"] == "lib" else ["--test", case["target"]]
        argv = [
            "cargo",
            "test",
            "--manifest-path",
            str(source / "Cargo.toml"),
            "--locked",
            "-j4",
            "--no-run",
            "--message-format=json",
            *selection,
        ]
        witness = command(argv, source, stem + "-witness-build", environment, 600)
        if witness.returncode:
            raise RuntimeError("compilation failure is not a semantic kill")
        compiler = rows(witness.stdout)
        kind, name = (
            ("lib", "xmsg_mcp_gateway")
            if case["target"] == "lib"
            else ("test", case["target"])
        )
        artifacts = {
            "test": executable(compiler, target, kind, name, True, require_fresh)
        }
        cli_records = [
            item
            for item in compiler
            if item.get("target", {}).get("kind") == ["bin"]
            and item.get("profile", {}).get("test") is False
            and item.get("executable")
        ]
        if not cli_records:
            argv = [
                "cargo",
                "build",
                "--manifest-path",
                str(source / "Cargo.toml"),
                "--locked",
                "-j4",
                "--bin",
                "xmsg-mcp-gateway",
                "--message-format=json",
            ]
            cli = command(argv, source, stem + "-cli-build", environment, 600)
            if cli.returncode:
                raise RuntimeError("CLI compilation failure is not a semantic kill")
            compiler = rows(cli.stdout)
        artifacts["cli"] = executable(
            compiler, target, "bin", "xmsg-mcp-gateway", False, require_fresh
        )
        for item in artifacts.values():
            if nonce.encode() not in Path(item["path"]).read_bytes():
                raise RuntimeError("compiled nonce absent from executable")
        return artifacts

    def build(source, target, case, nonce, stem, expected, require_fresh=True):
        try:
            return build_inner(source, target, case, nonce, stem, require_fresh)
        finally:
            verify(source, expected)
            verify(ROOT, original)

    def refused(label, operation, expected_message):
        try:
            operation()
        except RuntimeError as error:
            if str(error) != expected_message:
                raise
            ledger["controls"][label] = True
        else:
            raise RuntimeError("negative control survived: " + label)
        persist()

    def arm(case, phase):
        record = {"case": case["id"], "phase": phase, "status": "preparing"}
        ledger["arms"].append(record)
        persist()
        verify(ROOT, original)
        nonce = uuid.uuid4().hex
        stem = case["id"] + "-" + phase
        variant = work / stem
        source, target = variant / "source", variant / "target"
        source.mkdir(parents=True)
        if args.seed_target:
            shutil.copytree(args.seed_target.resolve(), target, symlinks=True)
        expected = dict(original)
        mutation = case["file"]
        data, mode = expected[mutation]
        if phase == "red":
            data = data.replace(
                case["needle"].encode(), case["replacement"].encode(), 1
            )
        expected[mutation] = (data, mode)
        witness = case["test_file"]
        data, mode = expected[witness]
        anchor = ("fn " + case["test"] + "() {").encode()
        injection = (
            anchor
            + b'\nassert_eq!(env!("'
            + BUILD_NONCE.encode()
            + b'"), std::env::var("'
            + PROOF_NONCE.encode()
            + b'").unwrap(), "compiled nonce mismatch");\n'
            + b'eprintln!("control-proof-nonce:{}", env!("'
            + BUILD_NONCE.encode()
            + b'"));\n'
        )
        if case["target"] != "lib":
            injection += (
                b'assert_eq!(env!("CARGO_BIN_EXE_xmsg-mcp-gateway"), std::env::var("'
                + CLI_PATH.encode()
                + b'").unwrap(), "compiled CLI path mismatch");\n'
            )
        expected[witness] = (data.replace(anchor, injection, 1), mode)
        if case["target"] != "lib":
            content, permissions = expected[witness]
            expected[witness] = (
                content.replace(CLI_RUN, CLI_RUN_GUARDED, 1),
                permissions,
            )
        main_data, main_mode = expected["src/main.rs"]
        if main_data.count(b"async fn main() {") != 1:
            raise ValueError("main nonce anchor must be unique")
        main_data = main_data.replace(
            b"async fn main() {",
            b'async fn main() {\nstd::hint::black_box(env!("'
            + BUILD_NONCE.encode()
            + b'"));\n',
            1,
        )
        expected["src/main.rs"] = (main_data, main_mode)
        for relative, (content, permissions) in expected.items():
            destination = source / relative
            destination.parent.mkdir(parents=True, exist_ok=True)
            destination.write_bytes(content)
            destination.chmod(permissions)
        record.update(
            {
                "case": case["id"],
                "phase": phase,
                "nonce": nonce,
                "status": "building",
                "variant_hashes": {
                    key: sha(content) for key, (content, _) in expected.items()
                },
            }
        )
        persist()
        verify(source, expected)
        if not ledger["controls"]:
            changed = source / witness
            saved = changed.read_bytes()
            changed.write_bytes(saved + b"\n")
            refused(
                "source_tamper_refused",
                lambda: verify(source, expected),
                "source guard failed: " + witness,
            )
            changed.write_bytes(saved)
            kind, name = (
                ("lib", "xmsg_mcp_gateway")
                if case["target"] == "lib"
                else ("test", case["target"])
            )
            fake = [
                {
                    "reason": "compiler-artifact",
                    "target": {"kind": [kind], "name": name},
                    "profile": {"test": True},
                    "executable": "/bin/false",
                    "fresh": False,
                }
            ]
            refused(
                "outside_artifact_refused",
                lambda: executable(fake, target, kind, name, True),
                "artifact isolation guard failed",
            )
        artifacts = build(source, target, case, nonce, stem, expected)
        record.update({"status": "compiled", "artifacts": artifacts})
        persist()
        verify(source, expected)
        verify_artifacts(artifacts)
        cache_key = "cached_artifact_refused_" + case["target"]
        if cache_key not in ledger["controls"]:
            cached = build(
                source, target, case, nonce, stem + "-cache-control", expected, False
            )
            for key in artifacts:
                if (
                    cached[key]["fresh"] is not True
                    or cached[key]["path"] != artifacts[key]["path"]
                    or cached[key]["sha256"] != artifacts[key]["sha256"]
                ):
                    raise RuntimeError(
                        "cache positive control rebuilt or changed executable"
                    )
            ledger["controls"]["cache_positive_same_artifacts_" + case["target"]] = True
            refused(
                cache_key,
                lambda: build(
                    source, target, case, nonce, stem + "-cache-refusal", expected
                ),
                "cached artifact refused",
            )
        if "artifact_tamper_refused" not in ledger["controls"]:
            binary = Path(artifacts["cli"]["path"])
            saved = binary.read_bytes()
            binary.write_bytes(saved + b"\0")
            refused(
                "artifact_tamper_refused",
                lambda: verify_artifacts(artifacts),
                "artifact identity guard failed",
            )
            binary.write_bytes(saved)
            verify_artifacts(artifacts)
        environment = {
            **os.environ,
            PROOF_NONCE: nonce,
            CLI_PATH: artifacts["cli"]["path"],
            CLI_HASH: artifacts["cli"]["sha256"],
        }
        argv = [
            artifacts["test"]["path"],
            "--exact",
            case["qualified_test"],
            "--nocapture",
        ]
        if "wrong_nonce_refused" not in ledger["controls"]:
            verify_artifacts(artifacts)
            wrong = command(
                argv,
                source,
                "compiled-nonce-negative",
                {**environment, PROOF_NONCE: "deliberately-wrong-nonce"},
                120,
            )
            if (
                wrong.returncode != 101
                or b"compiled nonce mismatch" not in wrong.stdout + wrong.stderr
            ):
                raise RuntimeError("compiled nonce negative control survived")
            verify_artifacts(artifacts)
            verify(source, expected)
            verify(ROOT, original)
            ledger["controls"]["wrong_nonce_refused"] = True
            persist()
        if (
            case["target"] != "lib"
            and "wrong_cli_path_refused" not in ledger["controls"]
        ):
            verify_artifacts(artifacts)
            wrong_cli = command(
                argv,
                source,
                "compiled-cli-path-negative",
                {**environment, CLI_PATH: "/bin/false"},
                120,
            )
            if (
                wrong_cli.returncode != 101
                or b"compiled CLI path mismatch"
                not in wrong_cli.stdout + wrong_cli.stderr
            ):
                raise RuntimeError("compiled CLI path control survived")
            verify_artifacts(artifacts)
            verify(source, expected)
            verify(ROOT, original)
            ledger["controls"]["wrong_cli_path_refused"] = True
            persist()
        verify(source, expected)
        verify(ROOT, original)
        verify_artifacts(artifacts)
        result = command(argv, source, stem + "-test", environment, 120)
        output = result.stdout + result.stderr
        verify_artifacts(artifacts)
        verify(source, expected)
        verify(ROOT, original)
        cli_executions = [
            json.loads(line.split(b"unit5-cli-receipt:", 1)[1])
            for line in output.splitlines()
            if b"unit5-cli-receipt:" in line
        ]
        if case["target"] != "lib":
            if not cli_executions or any(
                item["nonce"] != nonce
                or item["path"] != artifacts["cli"]["path"]
                or item["sha256"] != artifacts["cli"]["sha256"]
                for item in cli_executions
            ):
                raise RuntimeError("CLI execution receipt missing or mismatched")
        record["cli_executions"] = cli_executions
        marker = ("control-proof-nonce:" + nonce).encode()
        record.update(
            {
                "status": "executed",
                "exit": result.returncode,
                "test": case["qualified_test"],
                "log_sha256": sha(output),
                "compiled_nonce_observed": marker in output,
                "assertion_present": case["assertion"].encode() in output,
                "source_guard_before_after": True,
                "artifact_guard_before_after": True,
            }
        )
        persist()
        if marker not in output:
            raise RuntimeError("compiled nonce was not observed in witness")
        if any(
            value in output.lower()
            for value in [b"timed out", b"elapsed(", b"test-hang", b"running for over"]
        ):
            raise RuntimeError("timeout or hang is not a semantic kill")
        if phase == "red":
            failed = f"test {case['qualified_test']} ... FAILED".encode()
            if (
                result.returncode != 101
                or not record["assertion_present"]
                or failed not in output
                or b"1 failed" not in output
            ):
                raise RuntimeError("fault survived or failed for the wrong reason")
            record["outcome"] = "semantic_kill"
        elif result.returncode or b"1 passed" not in output:
            raise RuntimeError("restored witness is not green")
        retained = work / "executables" / stem
        retained.mkdir(parents=True)
        for key, item in artifacts.items():
            destination = retained / key
            shutil.copy2(item["path"], destination)
            if sha(destination.read_bytes()) != item["sha256"]:
                raise RuntimeError("retained executable copy changed")
            item["retained_path"] = str(destination)
        shutil.rmtree(variant)
        record["isolated_build_tree_removed_after_receipts"] = True
        persist()
        print(stem + ": exit=" + str(result.returncode) + " nonce=" + nonce, flush=True)

    persist()
    signal.signal(signal.SIGTERM, lambda *_: (_ for _ in ()).throw(KeyboardInterrupt()))
    try:
        for case in cases:
            for phase in ["red", "green"]:
                try:
                    arm(case, phase)
                except BaseException as error:
                    if ledger["arms"]:
                        ledger["arms"][-1]["failure"] = (
                            type(error).__name__ + ": " + str(error)
                        )
                        ledger["arms"][-1]["status"] = (
                            "compile_failed"
                            if "compilation failure" in str(error)
                            else "failed"
                        )
                    persist()
                    raise
        ledger["status"] = "passed"
        ledger["completed_at"] = time.time()
    except BaseException as error:
        ledger["status"] = "failed"
        ledger["error"] = type(error).__name__ + ": " + str(error)
        persist()
        raise
    finally:
        try:
            verify(ROOT, original)
        except BaseException as error:
            ledger["status"] = "failed"
            ledger["error"] = type(error).__name__ + ": " + str(error)
            raise
        finally:
            persist()


if __name__ == "__main__":
    main()
