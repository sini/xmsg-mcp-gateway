"""Drive grant-store and CLI source mutations; compilation/timeout is never a kill."""

import json
import os
import shutil
import subprocess
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
CASES = [
    (
        "disabled-enrollment",
        "src/grants.rs",
        "VALUES (?1, ?2, ?3, ?4, ?5, ?6, 1, 0)",
        "VALUES (?1, ?2, ?3, ?4, ?5, ?6, 1, 1)",
        "grant_core",
        "enrollment_is_disabled_and_restart_keeps_revision",
    ),
    (
        "foreign-client",
        "src/grants.rs",
        "AND hosted_client = ?5",
        "AND (?5 IS NOT NULL)",
        "grant_core",
        "all_binding_fields_are_required",
    ),
    (
        "changed-row",
        "src/grants.rs",
        "if changed != 1 {",
        "if false {",
        "grant_core",
        "unknown_stale_and_noop_mutations_fail_without_changes",
    ),
    (
        "disabled-authorization",
        "src/grants.rs",
        "AND enabled = 1",
        "AND enabled IN (0, 1)",
        "grant_core",
        "enrollment_is_disabled_and_restart_keeps_revision",
    ),
    (
        "foreign-store",
        "src/grants.rs",
        "if application != APPLICATION_ID || version != SCHEMA_VERSION {",
        "if false {",
        "grant_core",
        "foreign_store_metadata_is_refused_without_reinitialization",
    ),
    (
        "single-enabled",
        "src/grants.rs",
        "CREATE UNIQUE INDEX one_enabled_per_service",
        "CREATE INDEX one_enabled_per_service",
        "grant_core",
        "one_enabled_binding_per_service",
    ),
    (
        "audience-string",
        "src/grants.rs",
        "Value::String(audience) => audience == resource,",
        "Value::String(audience) => !audience.is_empty(),",
        "grant_core",
        "exact_resource_audience",
    ),
    (
        "audience-array",
        "src/grants.rs",
        "audiences.len() == 1 && audiences[0].as_str() == Some(resource)",
        "!audiences.is_empty() && audiences[0].as_str() == Some(resource)",
        "grant_core",
        "exact_resource_audience",
    ),
    (
        "cli-exit",
        "src/main.rs",
        "std::process::exit(1);",
        "std::process::exit(0);",
        "grant_cli",
        "unknown_stale_and_unchanged_ids_exit_nonzero_and_change_nothing",
    ),
]


def run(root, target, test, changed_source):
    env = {**os.environ, "CARGO_TARGET_DIR": str(ROOT / "target/grant-mutants-build")}
    built = subprocess.run(
        [
            "cargo",
            "test",
            "--locked",
            "--offline",
            "-j",
            "4",
            "--test",
            target,
            "--no-run",
            "--message-format=json",
        ],
        cwd=root,
        env=env,
        capture_output=True,
        text=True,
        timeout=120,
    )
    assert built.returncode == 0, (
        "compilation failed; not a kill",
        built.stderr[-4000:],
    )
    artifacts = [
        json.loads(line) for line in built.stdout.splitlines() if line.startswith("{")
    ]
    executables = [
        item
        for item in artifacts
        if item.get("reason") == "compiler-artifact"
        and item.get("target", {}).get("name") == target
        and item.get("profile", {}).get("test")
        and item.get("executable")
    ]
    assert len(executables) == 1, "missing intended test artifact"
    changed_target = (
        "xmsg-mcp-gateway" if changed_source == "src/main.rs" else "xmsg_mcp_gateway"
    )
    rebuilt = [
        item
        for item in artifacts
        if item.get("reason") == "compiler-artifact"
        and item.get("target", {}).get("name") == changed_target
        and not item.get("profile", {}).get("test")
    ]
    assert len(rebuilt) == 1 and not rebuilt[0].get("fresh", True), (
        "changed library or application binary was cached"
    )
    return subprocess.run(
        [executables[0]["executable"], test, "--exact"],
        cwd=root,
        env=env,
        capture_output=True,
        text=True,
        timeout=30,
    )


def main():
    evidence = ROOT / ".artifacts/grant-mutants"
    evidence.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="gateway-grant-mutants-") as directory:
        root = Path(directory)
        for name in ["Cargo.toml", "Cargo.lock"]:
            shutil.copyfile(ROOT / name, root / name)
        for name in ["src", "tests"]:
            shutil.copytree(ROOT / name, root / name, copy_function=shutil.copyfile)
        for name, filename, old, new, target, test in CASES:
            source = root / filename
            original = source.read_text()
            assert original.count(old) == 1, (name, original.count(old))
            source.touch()
            green = run(root, target, test, filename)
            assert (
                green.returncode == 0
                and "1 passed; 0 failed; 0 ignored" in green.stdout
            ), (name, "invalid baseline", green.stdout, green.stderr)
            try:
                source.write_text(original.replace(old, new, 1))
                source.touch()
                red = run(root, target, test, filename)
                assert (
                    red.returncode == 101 and f"test {test} ... FAILED" in red.stdout
                ), (name, "survived or wrong red", red.stdout, red.stderr)
                (evidence / f"{name}.log").write_text(red.stdout + red.stderr)
                print(f"{name}: GREEN baseline, RED intended test", flush=True)
            finally:
                source.write_text(original)
                source.touch()
    print(f"{len(CASES)}/{len(CASES)} grant mutants killed", flush=True)


if __name__ == "__main__":
    main()
