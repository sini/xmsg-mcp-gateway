"""Drive grant-store and CLI source mutations; compilation/timeout is never a kill."""

import hashlib
import json
import os
import re
import shutil
import subprocess
import tempfile
import uuid
from pathlib import Path

from artifact_evidence import NONCE, record
from transport_compat import invocation_evidence

ROOT = Path(__file__).resolve().parents[1]
CASES = [
    (
        "pending-shared-predicate",
        "src/grants.rs",
        "if !self.migration_applied(migration)? {",
        "if self.migration_applied(migration)? {",
        "migrations",
        "migrations_pending_matches_shared_predicates_without_writes",
    ),
    (
        "apply-policy-validation",
        "src/outbound.rs",
        "    policy.validate()?;",
        "    let _ = policy;",
        "apply",
        "invalid_apply_policy_and_missing_grant_never_write_business_state",
    ),
    (
        "cli-input-redaction",
        "src/main.rs",
        '#[error("invalid enrollment binding document")]',
        '#[error("invalid enrollment binding document: {0}")]',
        "grant_cli",
        "invalid_enrollment_document_does_not_echo_input",
    ),
    (
        "empty-binding",
        "src/grants.rs",
        ".any(|s| s.trim().is_empty())",
        ".any(|_s| false)",
        "grant_core",
        "empty_and_whitespace_binding_fields_never_write_rows",
    ),
    (
        "stale-revision",
        "src/grants.rs",
        "AND revision = ?3",
        "AND ?3 IS NOT NULL",
        "grant_core",
        "unknown_stale_and_noop_mutations_fail_without_changes",
    ),
    (
        "conflict-kind",
        "src/grants.rs",
        "Error::Conflict",
        "Error::Database(error)",
        "grant_core",
        "one_enabled_binding_per_service",
    ),
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
        "if !matches!(\n            application,\n            LEGACY_APPLICATION_ID | RETIREMENT_APPLICATION_ID | SUMMARY_APPLICATION_ID\n        ) || !(SCHEMA_VERSION..=MAX_SUPPORTED_SCHEMA_VERSION).contains(&version)\n        {",
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
        """if let Err(error) = run(Cli::parse()).await {
        eprintln!("gateway command failed: {error}");
        std::process::exit(1);
    }""",
        """if let Err(error) = run(Cli::parse()).await {
        eprintln!("gateway command failed: {error}");
        std::process::exit(0);
    }""",
        "grant_cli",
        "unknown_stale_and_unchanged_ids_exit_nonzero_and_change_nothing",
    ),
]


def run(root, target, test, changed_source, *, test_timeout=30, test_args=(), application=False):
    entry = root / "tests" / f"{target}.rs"
    original = entry.read_text()
    variant = hashlib.sha256((root / changed_source).read_bytes()).hexdigest()
    marker = f"gateway-mutant-arm:{NONCE}:{target}/{test}:{variant}:{uuid.uuid4().hex}"
    pattern = rf"(\bfn {re.escape(test)}\(\)\s*\{{)"
    instrumented, count = re.subn(
        pattern, lambda match: match[0] + f'\n    eprintln!("{marker}");', original
    )
    if count != 1:
        raise RuntimeError(f"named-test marker site missing: {target}/{test}")
    entry.write_text(instrumented)
    try:
        result = run_marked(
            root,
            target,
            test,
            changed_source,
            test_timeout=test_timeout,
            test_args=test_args,
            application=application,
        )
        if marker not in result.stdout + result.stderr:
            raise RuntimeError("compiled arm marker was not executed")
        print(f"executed {marker}", flush=True)
        return result
    finally:
        entry.write_text(original)


def run_marked(root, target, test, changed_source, *, test_timeout, test_args, application=False):
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
    if built.returncode:
        diagnostics = []
        for line in built.stdout.splitlines():
            try:
                message = json.loads(line)
            except json.JSONDecodeError:
                continue
            if message.get("reason") == "compiler-message":
                diagnostics.append(message.get("message", {}).get("rendered", ""))
        raise RuntimeError(
            (
                "compilation failed; not a kill",
                "".join(diagnostics)[-8000:],
                built.stderr[-4000:],
            )
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
    if executables[0].get("fresh", True):
        raise RuntimeError("selected test executable was cached")
    record(root, Path(executables[0]["executable"]), f"{target}/{test}")
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
    if not changed_source.startswith("tests/") and (
        len(rebuilt) != 1 or rebuilt[0].get("fresh", True)
    ):
        raise RuntimeError("changed library or application binary was cached")
    if changed_source == "src/main.rs":
        record(
            root,
            Path(rebuilt[0]["executable"]),
            f"application/{test}",
            directories=("src",),
        )
    app = None
    if application:
        apps = [item for item in artifacts if item.get("reason") == "compiler-artifact"
                and item.get("target", {}).get("name") == "xmsg-mcp-gateway"
                and not item.get("profile", {}).get("test") and item.get("executable")]
        if len(apps) != 1 or apps[0].get("fresh", True):
            raise RuntimeError("intended subprocess application was cached or missing")
        app = Path(apps[0]["executable"])
        record(root, app, f"application/{test}", directories=("src",))
    args = [executables[0]["executable"], test, "--exact", "--show-output", *test_args]
    invocation_evidence(args)
    result = subprocess.run(
        args,
        cwd=root,
        env=env,
        capture_output=True,
        text=True,
        timeout=test_timeout,
    )
    if app is not None and f"gateway-mutant-app:{app}" not in result.stdout + result.stderr:
        raise RuntimeError("named subprocess test did not execute the built application")
    return result


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
