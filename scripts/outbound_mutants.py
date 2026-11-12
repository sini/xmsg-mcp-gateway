"""Kill single-site outbound regressions on named cells, never on build/timeouts."""

import argparse
import shutil
import tempfile
from pathlib import Path

from grant_mutants import ROOT, run

OUTBOUND = (ROOT / "src/outbound.rs").read_text()
AUTH = (ROOT / "src/auth.rs").read_text()
SEND_TEST = "same_request_reuses_receipt_and_changed_payload_conflicts"
REPLY_TEST = "replies_require_owned_current_correlations_and_preserve_bus_receipts"
ARGS_TEST = "request_id_is_required_and_strict"
BEFORE = "crash_after_reservation_recovers_with_the_stored_key"
AFTER = "accepted_before_confirm_crash_returns_original_message_id"
LEASE_TEST = "operation_lease_is_private_and_refuses_symlinks"

start = OUTBOUND.index(
    "#[derive(Debug, Deserialize)]\n#[serde(deny_unknown_fields)]\npub struct SendArguments"
)
end = OUTBOUND.index("\n}", start) + 2
arguments = OUTBOUND[start:end]
scope_start = AUTH.index("    pub fn requires_scope_for(")
scope_end = AUTH.index("\n    }", scope_start) + len("\n    }")
scope_method = AUTH[scope_start:scope_end]
permission_start = OUTBOUND.index(
    "        match request {", OUTBOUND.index("    fn permission(")
)
permission_end = OUTBOUND.index("\n    }", permission_start)
permission = OUTBOUND[permission_start:permission_end]
capacity_start = OUTBOUND.index("            if count >= limits.max_reservations")
capacity_end = OUTBOUND.index("\n            {", capacity_start)
capacity = OUTBOUND[capacity_start:capacity_end]

FRESH_ULID = """let key = {
        use std::io::Read;
        let millis = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_millis() as u64;
        let mut bytes = [0u8; 16];
        bytes[..6].copy_from_slice(&millis.to_be_bytes()[2..]);
        std::fs::File::open("/dev/urandom").unwrap().read_exact(&mut bytes[6..]).unwrap();
        let mut value = u128::from_be_bytes(bytes);
        let mut encoded = [b'0'; 26];
        for byte in encoded.iter_mut().rev() {
            *byte = b"0123456789ABCDEFGHJKMNPQRSTVWXYZ"[(value & 31) as usize];
            value >>= 5;
        }
        String::from_utf8(encoded.to_vec()).unwrap()
    };"""

CASES = [
    (
        "request-id-validation",
        "src/outbound.rs",
        'b"._:-".contains(&byte)',
        "byte.is_ascii()",
        "outbound_arguments",
        ARGS_TEST,
        "accepted",
    ),
    (
        "json-rpc-conversion",
        "src/outbound.rs",
        "pub struct RequestId(String);",
        "pub struct RequestId(String);\nimpl From<serde_json::Value> for RequestId { fn from(value: serde_json::Value) -> Self { Self(value.to_string()) } }",
        "outbound_arguments",
        "json_rpc_id_cannot_become_a_request_id",
        "Expected test case to fail to compile, but it succeeded.",
    ),
    (
        "missing-request-id",
        "src/outbound.rs",
        arguments,
        'fn default_request_argument() -> RequestId { RequestId("default".into()) }\n'
        + arguments.replace(
            "    pub request_id:",
            '    #[serde(default = "default_request_argument")]\n    pub request_id:',
        ),
        "outbound_arguments",
        ARGS_TEST,
        "outbound send arguments accepted",
    ),
    (
        "default-empty-policy",
        "src/outbound.rs",
        permission,
        """        match request {
            Request::Send(args) => Ok(self.send.clone().unwrap_or_else(|| Permission { targets:[args.to.clone()].into(), required_scope:"send:write".into() })),
            Request::Reply(_) => self.reply.clone().ok_or(Error::Denied),
        }""",
        "custody_outbound",
        SEND_TEST,
        "empty policy allowed a send",
    ),
    (
        "write-scope",
        "src/auth.rs",
        scope_method,
        "    pub fn requires_scope_for(&self, _identity: &VerifiedIdentity, _scope: &str) -> bool { true }\n\n",
        "custody_outbound",
        SEND_TEST,
        "identity-only verifier admitted write scope",
    ),
    (
        "payload-conflict",
        "src/outbound.rs",
        "reservation.payload_hash != payload_hash",
        "false",
        "custody_outbound",
        SEND_TEST,
        "Err(Error::Conflict)",
    ),
    (
        "original-receipt",
        "src/outbound.rs",
        "if let Some(receipt) = &reservation.receipt {",
        "if let Some(receipt) = &None::<String> {",
        "custody_outbound",
        SEND_TEST,
        "same request lost its original receipt",
    ),
    (
        "framed-text-bound",
        "src/outbound.rs",
        "framed.len() <= self.max_framed_bytes",
        "true",
        "custody_outbound",
        SEND_TEST,
        "oversized framed text was submitted",
    ),
    (
        "fresh-ulid-key",
        "src/outbound.rs",
        "let key = reservation.key.clone();",
        FRESH_ULID,
        "custody_outbound",
        AFTER,
        "recovery lost the original message ID",
    ),
    (
        "submit-before-reserve-commit",
        "src/outbound.rs",
        "            let (timestamp, retry_until) =\n                reservation_times(timestamp_now, limits.dedup_lifetime_secs)?;\n            let (_, recovery_until) =\n                reservation_times(timestamp_now, limits.result_recovery_secs)?;\n            let tx = store",
        "            let (timestamp, retry_until) =\n                reservation_times(timestamp_now, limits.dedup_lifetime_secs)?;\n            let (_, recovery_until) =\n                reservation_times(timestamp_now, limits.result_recovery_secs)?;\n            service.client.send(&target, &framed_text, Some(&key)).await?;\n            let tx = store",
        "custody_outbound",
        BEFORE,
        "reserved work submitted before crash cut",
    ),
    (
        "stored-framed-body",
        "src/outbound.rs",
        "key,target,correlation,framed_text,timestamp",
        'key,target,correlation,"mutated stored bytes",timestamp',
        "custody_outbound",
        BEFORE,
        "recovery changed the stored framed body",
    ),
    (
        "dedup-expiry",
        "src/outbound.rs",
        "now() >= self.retry_deadline(limits) || now() < self.created_at",
        "false",
        "custody_outbound",
        "expired_uncertainty_never_blindly_retries",
        "expired uncertainty was blindly retried",
    ),
    (
        "held-revision",
        "src/outbound.rs",
        "|| reservation.grant_revision != authority.revision",
        "",
        "custody_outbound",
        "pending_work_stays_held_across_disable_and_reenable",
        "old pending work escaped disable and re-enable",
    ),
    (
        "fresh-store-authority",
        "src/outbound.rs",
        'tracing::debug!(target:"gateway_outbound_reserved", "pending");\n    require_current(context, store)?;',
        'tracing::debug!(target:"gateway_outbound_reserved", "pending");',
        "custody_outbound",
        SEND_TEST,
        "revoked grant was not rechecked before submission",
    ),
    (
        "owned-correlation",
        "src/outbound.rs",
        " AND c.owner=?4 AND g.service=?5 AND g.issuer=?6 AND g.resource=?7 AND c.grant_id=?8 AND {authority_predicate}",
        "",
        "custody_outbound",
        REPLY_TEST,
        "foreign owner's correlation authorized a reply",
    ),
    (
        "per-service-lease",
        "src/outbound_lease.rs",
        "Sha256::digest(service.as_bytes())",
        'Sha256::digest(b"global")',
        "outbound_lease",
        "operation_lease_is_per_service_and_nonblocking",
        'first.try_operation_lease("other")',
    ),
    (
        "nonblocking-lease",
        "src/outbound_lease.rs",
        "match file.try_lock() {",
        "match file.lock().map_err(TryLockError::Error) {",
        "outbound_lease",
        "operation_lease_is_per_service_and_nonblocking",
        "lease acquisition blocked instead of returning pending",
    ),
    (
        "lease-no-follow",
        "src/outbound_lease.rs",
        ".custom_flags(libc::O_NOFOLLOW)",
        ".custom_flags(0)",
        "outbound_lease",
        LEASE_TEST,
        'store.try_operation_lease("gateway").is_err()',
    ),
    (
        "lease-private-mode",
        "src/outbound_lease.rs",
        "|| metadata.mode() & 0o777 != 0o600",
        "",
        "outbound_lease",
        LEASE_TEST,
        "lease file with public permissions was accepted",
    ),
    (
        "disable-lease",
        "src/grants.rs",
        "let _lease = self.wait_operation_lease(&service, Duration::from_secs(30))?;",
        "let _lease = ();",
        "custody_outbound",
        "disable_waits_for_the_service_lease_and_prevents_later_submission",
        "disable bypassed the held operation lease",
    ),
    (
        "disable-timeout-fail-open",
        "src/grants.rs",
        "let _lease = self.wait_operation_lease(&service, Duration::from_secs(30))?;",
        "let _lease = self.wait_operation_lease(&service, Duration::from_secs(30)).ok();",
        "outbound_lease",
        "disable_timeout_refuses_without_a_partial_write",
        "disable committed without acquiring the lease after timeout",
    ),
    (
        "sqlite-across-network",
        "src/outbound.rs",
        '    tracing::debug!(target:"gateway_outbound_reserved", "pending");',
        '    let _network_guard = rusqlite::Connection::open(&store.file)?;\n    _network_guard.execute_batch("BEGIN IMMEDIATE")?;\n    tracing::debug!(target:"gateway_outbound_reserved", "pending");',
        "custody_outbound",
        "inbound_commit_and_ack_complete_while_outbound_acceptance_is_stalled",
        "SQLite write guard blocked inbound custody during network submission",
    ),
    (
        "reservation-capacity",
        "src/outbound.rs",
        capacity,
        "            if false",
        "custody_outbound",
        SEND_TEST,
        "outbound reservations exceeded their count budget",
    ),
    (
        "explicit-migration",
        "src/outbound.rs",
        "    store.require_outbound_ready()?;",
        "",
        "custody_outbound",
        SEND_TEST,
        "outbound dispatch accepted an unmigrated store",
    ),
    (
        "policy-auto-enable",
        "src/outbound.rs",
        "UPDATE grants SET revision=revision+1 WHERE id=?1 AND revision=?2",
        "UPDATE grants SET revision=revision+1, enabled=1 WHERE id=?1 AND revision=?2",
        "outbound_store",
        "migration_is_explicit_and_policy_is_owner_revision_checked",
        "writing policy enabled a grant",
    ),
    (
        "policy-stale-revision",
        "src/outbound.rs",
        "UPDATE grants SET revision=revision+1 WHERE id=?1 AND revision=?2",
        "UPDATE grants SET revision=revision+1 WHERE id=?1 AND ?2 IS NOT NULL",
        "outbound_store",
        "migration_is_explicit_and_policy_is_owner_revision_checked",
        "GrantError::NoChange",
    ),
]


CASES += [
    (
        "reservation-busy-classification",
        "src/outbound.rs",
        "Self::Busy",
        "Self::Conflict",
        "custody_outbound",
        "busy_reservation_refuses_transiently_without_a_row_or_submission",
        "pre-submit BUSY was not a transient refusal",
    ),
    (
        "accepted-outcome-busy",
        "src/outbound.rs",
        "Err(_error) if accepted => Ok(Outcome::Pending),",
        "Err(error) if accepted => Err(error),",
        "custody_outbound",
        "busy_outcome_commit_keeps_pending_and_recovers_original_message_id",
        "accepted send reported failure on a busy outcome commit",
    ),
]


expiry_check = """        if reservation.expired(limits) {
            store.expire_reservation(reservation, limits)?;
            return Ok(Outcome::Unknown);
        }
"""
revision_check = """        if reservation.sender != sender
            || reservation.grant_id != authority.grant_id
            || reservation.grant_revision != authority.revision
        {
            return Err(Error::Denied);
        }
"""
CASES += [
    (
        "confirmed-reply-query-order",
        "src/outbound.rs",
        "if let Some(reservation) = existing {",
        "if let Some(reservation) = None::<&Reservation> {",
        "custody_outbound",
        "confirmed_reply_replay_survives_policy_write_and_correlation_expiry",
        "confirmed reply was denied after a policy write",
    ),
    (
        "expired-before-revision",
        "src/outbound.rs",
        expiry_check + revision_check,
        revision_check + expiry_check,
        "custody_outbound",
        "expired_pending_work_becomes_unknown_even_after_grant_revision_changes",
        "expired stale reservation was denied instead of becoming unknown",
    ),
    (
        "bounded-busy-wait",
        "src/grants.rs",
        "Self::open_with_wait(file, Duration::from_millis(250))",
        "Self::open_with_wait(file, Duration::from_secs(30))",
        "custody_outbound",
        "busy_reservation_refuses_transiently_without_a_row_or_submission",
        "pre-submit BUSY exceeded its bounded wait",
    ),
    (
        "short-busy-wait",
        "src/grants.rs",
        "Self::open_with_wait(file, Duration::from_millis(250))",
        "Self::open_with_wait(file, Duration::ZERO)",
        "custody_outbound",
        "dispatch_does_not_change_the_callers_custody_busy_wait",
        "short heartbeat write refused a send",
    ),
    (
        "caller-busy-wait",
        "src/outbound.rs",
        "let mut dedicated = Store::open_for_dispatch(&store.file)?;",
        "store.connection.busy_timeout(std::time::Duration::ZERO)?;\n    let mut dedicated = Store::open_for_dispatch(&store.file)?;",
        "custody_outbound",
        "dispatch_does_not_change_the_callers_custody_busy_wait",
        "dispatch disabled the caller Store's custody busy wait",
    ),
    (
        "policy-lease",
        "src/outbound.rs",
        'let _lease = self.wait_operation_lease(&service, std::time::Duration::from_secs(30))?;\n        let tx = self\n            .connection\n            .transaction_with_behavior(TransactionBehavior::Immediate)?;\n        let next = Self::set_outbound_policy_in',
        'let _lease = ();\n        let tx = self\n            .connection\n            .transaction_with_behavior(TransactionBehavior::Immediate)?;\n        let next = Self::set_outbound_policy_in',
        "outbound_lease",
        "owner_policy_write_waits_for_the_same_service_lease",
        "policy write bypassed the service lease",
    ),
    (
        "lease-single-link",
        "src/outbound_lease.rs",
        "|| metadata.nlink() != 1",
        "",
        "outbound_lease",
        LEASE_TEST,
        "lease with multiple hard links was accepted",
    ),
    (
        "deadline-before-submit",
        "src/outbound.rs",
        "if !may_have_submitted.load(Ordering::Relaxed) {",
        "if false {",
        "custody_outbound",
        "timeout_before_reservation_is_a_transient_refusal_not_unknown",
        "pre-reservation timeout was reported as unknown",
    ),
]


flag_line = "    may_have_submitted.store(true, Ordering::Relaxed);\n"
send_start = OUTBOUND.index(flag_line)
send_end = OUTBOUND.index(
    '    tracing::debug!(target:"gateway_outbound_submitted"', send_start
)
send_block = OUTBOUND[send_start:send_end]
CASES += [
    (
        "pending-row-is-uncertain",
        "src/outbound.rs",
        ".is_some_and(|row| row.receipt.is_none()),",
        ".is_some_and(|row| row.receipt.is_none() && false),",
        "custody_outbound",
        "pending_recovery_timeout_during_discovery_remains_unknown",
        "pending recovery deadline was reported as transient",
    ),
    (
        "submission-flag-before-send",
        "src/outbound.rs",
        send_block,
        send_block.replace(flag_line, "", 1) + flag_line,
        "custody_outbound",
        "deadline_after_send_begins_keeps_the_outcome_unknown",
        "in-flight send deadline was reported as transient",
    ),
]


def schema_floor_control(root):
    file = root / "src/grants.rs"
    original = file.read_text()
    site = "pub const MAX_SUPPORTED_SCHEMA_VERSION: i64 = EVENTS_SCHEMA_VERSION;"
    assert original.count(site) == 1, "schema ceiling control needs updating"
    try:
        file.write_text(
            original.replace(
                site,
                "pub const MAX_SUPPORTED_SCHEMA_VERSION: i64 = EVENTS_SCHEMA_VERSION + 1;",
                1,
            )
        )
        forward = run(
            root,
            "outbound_store",
            "migration_is_explicit_and_policy_is_owner_revision_checked",
            "src/grants.rs",
        )
        assert (
            forward.returncode == 0
            and "1 passed; 0 failed; 0 ignored" in forward.stdout
        ), (
            "outbound required schema followed the supported ceiling",
            forward.stdout,
            forward.stderr,
        )
    finally:
        file.write_text(original)
    print("outbound-schema-floor-control:passed", flush=True)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--case", choices=[case[0] for case in CASES])
    parser.add_argument("--list", action="store_true")
    args = parser.parse_args()
    assert len(CASES) == 38, "outbound mutant inventory drift"
    for name, filename, old, *_ in CASES:
        assert (ROOT / filename).read_text().count(old) == 1, (
            name,
            "source site drift",
        )
    if args.list:
        print("\n".join(case[0] for case in CASES))
        return
    evidence = ROOT / ".artifacts/outbound-mutants"
    evidence.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="gateway-outbound-mutants-") as directory:
        root = Path(directory)
        for name in ("Cargo.toml", "Cargo.lock"):
            shutil.copyfile(ROOT / name, root / name)
        for name in ("src", "tests", "ci"):
            shutil.copytree(ROOT / name, root / name, copy_function=shutil.copyfile)
        completed = 0
        for name, filename, old, new, target, test, expected in CASES:
            if args.case and args.case != name:
                continue
            file = root / filename
            source = file.read_text()
            file.touch()
            green = run(
                root,
                target,
                test,
                filename,
                test_args=("--include-ignored",),
                test_timeout=60,
            )
            assert (
                green.returncode == 0
                and "1 passed; 0 failed; 0 ignored" in green.stdout
            ), (name, "invalid baseline", green.stdout, green.stderr)
            try:
                file.write_text(source.replace(old, new, 1))
                red = run(
                    root,
                    target,
                    test,
                    filename,
                    test_args=("--include-ignored",),
                    test_timeout=60,
                )
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
                (evidence / f"{name}.log").write_text(red.stdout + red.stderr)
                completed += 1
                print(f"{name}: GREEN baseline / RED intended", flush=True)
            finally:
                file.write_text(source)
        assert completed == (1 if args.case else 38), (
            "outbound mutant completion mismatch"
        )
        if not args.case:
            schema_floor_control(root)
    print(f"outbound-mutants-complete:{completed}", flush=True)


if __name__ == "__main__":
    main()
