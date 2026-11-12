"""Kill attachment source regressions; build failures and timeouts never count."""

import argparse
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
from grant_mutants import ROOT, run
from transport_compat import invocation_evidence

OUTBOUND = (ROOT / "src/outbound.rs").read_text()
ATTACHMENTS = (ROOT / "src/attachments.rs").read_text()
_checked_start = ATTACHMENTS.index("async fn checked_owned(")
_checked_end = ATTACHMENTS.index("pub(crate) async fn read(", _checked_start)
CHECKED_OWNED = ATTACHMENTS[_checked_start:_checked_end]
_checked_spawn = "    tokio::task::spawn_blocking(move || {"
_checked_join = "    })\n    .await\n    .map_err(|_| crate::outbound::Error::Worker)?"
assert CHECKED_OWNED.count(_checked_spawn) == CHECKED_OWNED.count(_checked_join) == 1
CHECKED_INLINE = CHECKED_OWNED.replace(_checked_spawn, "    (move || {", 1).replace(
    _checked_join, "    })()", 1
)
POST_OWNED = """    let current = checked_owned(
        file,
        context.clone(),
        bus.to_owned(),
        mailbox.to_owned(),
        args.clone(),
    )
    .await?;
    if current.as_ref() != Some(&reference) {
        return Err(Error::Denied);
    }
"""

STAGE = """    for file in prepared {
        stage_attachment(service, store, context, file).await?;
    }
"""
RESERVED = '    tracing::debug!(target:"gateway_outbound_reserved", "pending");'
assert OUTBOUND.count(STAGE) == OUTBOUND.count(RESERVED) == 1
SEND = "attachment_retries_conflict_in_both_fingerprint_paths_and_store_only_refs"
FRESH = "grant_revocation_before_staging_or_after_staging_prevents_delivery"
CHUNKS = "chunk_and_finalize_each_require_fresh_authority"
CAPACITY = "retained_capacity_counts_existing_and_new_reference_json"
COMPAT = (
    "old_node_still_sends_plain_text_but_file_cap_and_returned_reference_fail_closed"
)
OWNED = (
    "owned_read_is_bounded_untrusted_and_checks_every_custody_dimension_before_bus_io"
)
READ_FRESH = (
    "store_changes_and_token_expiry_after_entry_refuse_attachment_before_agent_effect"
)
RANGES = "malformed_or_oversized_bus_ranges_never_escape_the_owned_read_bound"
STARTUP = (
    "attachment_startup_covers_daemon_pending_wait_with_default_and_explicit_budgets"
)
CASES = [
    (
        "M11-busy",
        "src/outbound.rs",
        "payload_fingerprint(op, target, correlation, text, &references)?",
        "payload_fingerprint(op, target, correlation, text, &[])?",
        "outbound_attachments",
        SEND,
        "called `Result::unwrap()` on an `Err` value: Conflict",
    ),
    (
        "M11-submit",
        "src/outbound.rs",
        'payload_fingerprint(op, &target, correlation.unwrap_or(""), text, &references)?',
        'payload_fingerprint(op, &target, correlation.unwrap_or(""), text, &[])?',
        "outbound_attachments",
        SEND,
        "M11: changed file reused a confirmed reservation",
    ),
    (
        "inline-freshness",
        "src/outbound.rs",
        "require_current(context, store)?;\n        service.client.attach(inline)",
        "service.client.attach(inline)",
        "outbound_attachments",
        FRESH,
        "assertion `left == right` failed",
    ),
    (
        "chunk-freshness",
        "src/outbound.rs",
        "require_current(context, store)?;\n            service.client.attach(request)",
        "service.client.attach(request)",
        "outbound_attachments",
        CHUNKS,
        "a later chunk or finalization ran after revocation",
    ),
    (
        "finish-freshness",
        "src/outbound.rs",
        "require_current(context, store)?;\n        service.client.attach(finish)",
        "service.client.attach(finish)",
        "outbound_attachments",
        CHUNKS,
        "a later chunk or finalization ran after revocation",
    ),
    (
        "send-freshness",
        "src/outbound.rs",
        RESERVED + "\n    require_current(context, store)?;",
        RESERVED,
        "outbound_attachments",
        FRESH,
        '&request("revoked", "bytes")',
    ),
    (
        "capacity-sum",
        "src/outbound.rs",
        "+length(CAST(attachments AS BLOB))",
        "",
        "outbound_attachments",
        CAPACITY,
        "reference bytes escaped retained capacity accounting",
    ),
    (
        "capacity-new",
        "src/outbound.rs",
        "refs_json.len()",
        "0",
        "outbound_attachments",
        CAPACITY,
        "reference bytes escaped retained capacity accounting",
    ),
    (
        "returned-ref",
        "src/outbound.rs",
        "if reference != file.reference {",
        "if false {",
        "outbound_attachments",
        COMPAT,
        '&request("corrupt", "abc")',
    ),
    (
        "stage-order",
        "src/outbound.rs",
        OUTBOUND,
        OUTBOUND.replace(STAGE, "", 1).replace(RESERVED, STAGE + RESERVED, 1),
        "outbound_attachments",
        SEND,
        "new reservation existed before attachment staging succeeded",
    ),
    (
        "read-owner",
        "src/reads.rs",
        "c.owner=:owner",
        "(:owner=:owner)",
        "attachments_rpc",
        OWNED,
        "foreign owner escaped custody",
    ),
    (
        "read-revision",
        "src/reads.rs",
        "AND c.grant_id=:grant AND c.grant_revision=:revision",
        "AND c.grant_id=:grant AND (:revision=:revision)",
        "attachments_rpc",
        OWNED,
        "stale custody leaked bytes",
    ),
    (
        "read-expiry",
        "src/outbound.rs",
        "if context.identity().expires_at() <= now() as u64 {",
        "if false && context.identity().expires_at() <= now() as u64 {",
        "attachments_rpc",
        READ_FRESH,
        "expiry not refused at read effect",
    ),
    (
        "read-maximum",
        "src/attachments.rs",
        "pub(crate) const READ_MAX: usize = 32768;",
        "pub(crate) const READ_MAX: usize = 65536;",
        "attachments_rpc",
        OWNED,
        "invalid index/range leaked bytes",
    ),
    (
        "read-response-bound",
        "src/attachments.rs",
        "|| length > limit",
        "|| false",
        "attachments_rpc",
        RANGES,
        "malformed bus utf8 byte bound escaped read validation",
    ),
    (
        "read-reference",
        "src/attachments.rs",
        "|| range.attachment != reference",
        "|| false",
        "attachments_rpc",
        RANGES,
        "malformed bus reference escaped read validation",
    ),
    (
        "M12-custody-fingerprint",
        "src/custody.rs",
        "fingerprint(&[origin, text, envelope, correlation, refs])",
        "fingerprint(&[origin, text, envelope, correlation])",
        "lib",
        "custody::attachment_custody_tests::refs_require_migration_and_commit_with_content_then_redact",
        "M12: attachment-only changed frame was not quarantined",
    ),
    (
        "startup-timeout",
        "src/serving.rs",
        "if attachments_enabled && messaging.xmsg.operation_timeout_ms <= 11_000 {",
        "if false && attachments_enabled && messaging.xmsg.operation_timeout_ms <= 11_000 {",
        "attachments_rpc",
        STARTUP,
        "attachment startup accepted an operation budget no longer than 11 seconds",
    ),
    (
        "startup-default",
        "src/xmsg_config.rs",
        "fn default_timeout_ms() -> u64 {\n    15_000\n}",
        "fn default_timeout_ms() -> u64 {\n    10_000\n}",
        "attachments_rpc",
        STARTUP,
        "default operation budget cannot outlast daemon pending wait",
    ),
    (
        "decoded-file-cap",
        "src/attachments.rs",
        "if input.data.len() > cap {",
        "if false {",
        "outbound_attachments",
        COMPAT,
        "Err(Error::Oversized)",
    ),
    (
        "file-count",
        "src/attachments.rs",
        "pub(crate) const MAX_FILES: usize = 8;",
        "pub(crate) const MAX_FILES: usize = 9;",
        "attachments_rpc",
        "malformed_inline_files_and_ninth_reference_are_rejected_before_staging_or_effect",
        "malformed file accepted",
    ),
]


CASES += [
    (
        "read-db-worker",
        "src/attachments.rs",
        CHECKED_OWNED,
        CHECKED_INLINE,
        "attachments_rpc",
        "attachment_db_checks_leave_single_worker_available_during_contention",
        "attachment SQL blocked read progress before the unrelated route could release its lock",
    ),
    (
        "read-post-authority",
        "src/attachments.rs",
        POST_OWNED,
        "",
        "attachments_rpc",
        "grant_revoked_during_attachment_read_suppresses_received_bytes",
        "grant revoked in flight still released attachment",
    ),
    (
        "upload-geometry",
        "src/outbound.rs",
        'format!("gateway-{}-{chunk_size}", file.reference.sha256)',
        'format!("gateway-{}", file.reference.sha256)',
        "outbound_attachments",
        "interrupted_upload_retries_after_client_frame_budget_changes",
        "retry after frame budget change collided with old upload geometry",
    ),
]


def run_unit(root, test, filename):
    """Use the same fresh artifact and executed-marker controls for one library cell."""
    entry = root / filename
    source = entry.read_text()
    variant = hashlib.sha256(source.encode()).hexdigest()
    marker = f"gateway-mutant-arm:{NONCE}:lib/{test}:{variant}:{uuid.uuid4().hex}"
    pattern = rf"(\bfn {re.escape(test.rsplit('::', 1)[-1])}\(\)\s*\{{)"
    instrumented, count = re.subn(
        pattern, lambda m: m[0] + f'\n    eprintln!("{marker}");', source
    )
    assert count == 1, "named unit marker site drift"
    entry.write_text(instrumented)
    env = {**os.environ, "CARGO_TARGET_DIR": str(ROOT / "target/grant-mutants-build")}
    try:
        built = subprocess.run(
            [
                "cargo",
                "test",
                "--locked",
                "--offline",
                "-j",
                "4",
                "--lib",
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
            raise RuntimeError(
                (
                    "unit compilation failed; not a kill",
                    built.stdout[-8000:],
                    built.stderr[-4000:],
                )
            )
        artifacts = [
            json.loads(line)
            for line in built.stdout.splitlines()
            if line.startswith("{")
        ]
        executable = [
            a
            for a in artifacts
            if a.get("reason") == "compiler-artifact"
            and a.get("target", {}).get("name") == "xmsg_mcp_gateway"
            and a.get("profile", {}).get("test")
            and a.get("executable")
        ]
        assert len(executable) == 1 and not executable[0].get("fresh", True), (
            "intended unit executable missing or cached"
        )
        binary = executable[0]["executable"]
        record(root, Path(binary), f"lib/{test}")
        args = [binary, test, "--exact", "--show-output"]
        invocation_evidence(args)
        result = subprocess.run(
            args, cwd=root, env=env, capture_output=True, text=True, timeout=30
        )
        assert marker in result.stdout + result.stderr, (
            "compiled unit arm marker was not executed"
        )
        print(f"executed {marker}", flush=True)
        return result
    finally:
        entry.write_text(source)


def execute(root, target, test, filename):
    if target == "lib":
        return run_unit(root, test, filename)
    return run(root, target, test, filename)


def green(result, name, phase):
    assert (
        result.returncode == 0 and "1 passed; 0 failed; 0 ignored" in result.stdout
    ), (
        name,
        phase,
        result.stdout,
        result.stderr,
    )


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--case", choices=[case[0] for case in CASES])
    parser.add_argument("--list", action="store_true")
    args = parser.parse_args()
    assert len(CASES) == 24 and len({case[0] for case in CASES}) == 24, (
        "attachment inventory drift"
    )
    for name, filename, old, new, *_ in CASES:
        assert old != new and (ROOT / filename).read_text().count(old) == 1, (
            name,
            "source site drift",
        )
    if args.list:
        print("\n".join(case[0] for case in CASES))
        return
    evidence = ROOT / ".artifacts/attachments-mutants"
    evidence.mkdir(parents=True, exist_ok=True)
    controls = {
        "script_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
        "cases": [],
    }
    print(f"attachments-mutants-script:{controls['script_sha256']}", flush=True)
    with tempfile.TemporaryDirectory(
        prefix="gateway-attachments-mutants-"
    ) as directory:
        root = Path(directory)
        for filename in ("Cargo.toml", "Cargo.lock"):
            shutil.copyfile(ROOT / filename, root / filename)
        for directory in ("src", "tests", "ci"):
            shutil.copytree(
                ROOT / directory, root / directory, copy_function=shutil.copyfile
            )
        for name, filename, old, new, target, test, expected in CASES:
            if args.case and name != args.case:
                continue
            file = root / filename
            original = file.read_text()
            file.touch()
            baseline = execute(root, target, test, filename)
            (evidence / f"{name}-baseline.log").write_text(
                baseline.stdout + baseline.stderr
            )
            green(baseline, name, "invalid baseline")
            try:
                mutated = original.replace(old, new, 1)
                file.write_text(mutated)
                red = execute(root, target, test, filename)
                (evidence / f"{name}-red.log").write_text(red.stdout + red.stderr)
                assert (
                    red.returncode == 101
                    and f"test {test} ... FAILED" in red.stdout
                    and expected in red.stdout + red.stderr
                ), (
                    name,
                    "intended assertion did not kill mutant",
                    red.stdout,
                    red.stderr,
                )
            finally:
                file.write_text(original)
                file.touch()
            restored = execute(root, target, test, filename)
            (evidence / f"{name}-restored.log").write_text(
                restored.stdout + restored.stderr
            )
            green(restored, name, "restore was not green")
            controls["cases"].append(
                {
                    "label": name,
                    "source": filename,
                    "target": target,
                    "test": test,
                    "baseline": baseline.returncode,
                    "red": red.returncode,
                    "restored": restored.returncode,
                    "before_sha256": hashlib.sha256(original.encode()).hexdigest(),
                    "mutant_sha256": hashlib.sha256(mutated.encode()).hexdigest(),
                    "witness": expected,
                }
            )
            (evidence / "controls.json").write_text(
                json.dumps(controls, indent=2) + "\n"
            )
            print(f"{name}: GREEN baseline / RED intended / GREEN restored", flush=True)
    completed = len(controls["cases"])
    assert completed == (1 if args.case else 24), (
        "attachment mutant completion mismatch"
    )
    print(f"attachments-mutants-complete:{completed}", flush=True)


if __name__ == "__main__":
    main()
