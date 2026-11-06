"""Drive custody source mutations through isolated real-node acceptance cells."""

import argparse
import shutil
import tempfile
from pathlib import Path

from grant_mutants import ROOT, run

SOURCE = (ROOT / "src/custody.rs").read_text()
metadata_write = next(
    line
    for line in SOURCE.splitlines()
    if 'tx.execute("INSERT OR IGNORE INTO custody_metadata' in line
)
CASES = [
    (
        "permanent-refusal-ack",
        "    fn can_ack(&self) -> bool {",
        "    fn can_ack(&self) -> bool {\n        if matches!(self, Self::Refused) { return false; }",
        "permanent_refusals_do_not_starve_valid_traffic",
        "oversized refusals exhausted node queue",
    ),
    (
        "mailbox-binding",
        "        let mailbox = service\n            .address()\n            .ok_or(xmsg::client::ClientError::Disconnected)?;",
        "        let mailbox = scope.bus_instance.as_str();",
        "mailbox_is_derived_from_the_registered_handle_not_configuration",
        "mailbox came from configuration instead of the registered handle",
    ),
    (
        "stored-body",
        "mailbox, owner, origin, delivery.text(),",
        'mailbox, owner, origin, "mutated stored body",',
        "commit_before_ack_preserves_the_original_event_across_restart",
        "stored body differs from the accepted delivery",
    ),
    (
        "early-ack",
        "    let accepted = store.accept_delivery(scope, service, &delivery, limits, now)?;",
        "    service.ack(delivery.message_id()).await?;\n    let accepted = store.accept_delivery(scope, service, &delivery, limits, now)?;",
        "failed_transaction_never_acknowledges_or_retains_partial_custody",
        "failed custody transaction ACKed upstream",
    ),
    (
        "quarantine-write",
        metadata_write,
        "",
        "conflict_is_quarantined_before_the_upstream_ack",
        "durable quarantine missing",
    ),
    (
        "content-expiry",
        "UPDATE custody_items SET text=NULL, envelope=NULL WHERE",
        "UPDATE custody_items SET text=text, envelope=envelope WHERE",
        "retention_redacts_content_without_rebinding_the_tombstone",
        "expired body retained",
    ),
    (
        "refusal-size",
        "let bounded_size = i64::try_from(size).map_err(|_| Error::Configuration)?;",
        "let bounded_size = 0;",
        "oversized_refusal_is_durable_content_free_before_ack",
        "actual bounded byte size missing",
    ),
]

CASES += [
    (
        "transient-ack",
        "Self::Deferred => false,",
        "Self::Deferred => true,",
        "transient_capacity_and_failed_refusal_persistence_keep_redelivery",
        "transient capacity refusal ACKed upstream",
    ),
    (
        "conflict-ack",
        "    fn can_ack(&self) -> bool {",
        "    fn can_ack(&self) -> bool {\n        if matches!(self, Self::Quarantined) { return false; }",
        "repeated_conflicts_do_not_starve_valid_traffic",
        "conflicts exhausted node queue",
    ),
    (
        "metadata-count",
        "if !known && records >= limits.max_metadata {",
        "if false {",
        "refusal_metadata_is_bounded_and_failed_audit_never_acks",
        "refusal metadata count bound missing",
    ),
    (
        "metadata-expiry",
        "DELETE FROM custody_metadata WHERE expires_at <= ?1",
        "DELETE FROM custody_metadata WHERE 0 AND expires_at <= ?1",
        "metadata_retention_and_status_survive_restart_without_fake_loss_ids",
        "refusal retention did not expire",
    ),
    (
        "gap-write",
        next(
            line
            for line in SOURCE.splitlines()
            if 'tx.execute("UPDATE custody_links SET disconnected_at=' in line
        ),
        "",
        "metadata_retention_and_status_survive_restart_without_fake_loss_ids",
        "disconnect uncertainty was not durable",
    ),
    (
        "message-age-warning",
        "age >= effective_reply_ttl_secs",
        "age >= i64::MAX",
        "metadata_retention_and_status_survive_restart_without_fake_loss_ids",
        "known message age did not drive possible loss",
    ),
    (
        "pending-expiry",
        "DELETE FROM custody_pending WHERE expires_at<=?1",
        "DELETE FROM custody_pending WHERE 0 AND expires_at<=?1",
        "metadata_retention_and_status_survive_restart_without_fake_loss_ids",
        "known pending IDs were not retention-bounded",
    ),
    (
        "process-crash-early-ack",
        "    let accepted = store.accept_delivery(scope, service, &delivery, limits, now)?;",
        "    service.ack(delivery.message_id()).await?;\n    let accepted = store.accept_delivery(scope, service, &delivery, limits, now)?;",
        "process_crash_before_commit_leaves_redelivery",
        "process crash lost unacknowledged upstream delivery",
    ),
    (
        "crash-event-identity",
        "return Ok(Acceptance::Duplicate { event_id });",
        'return Ok(Acceptance::Duplicate { event_id: format!("{event_id}-mutated") });',
        "process_crash_after_commit_preserves_one_event",
        "crash redelivery minted a different event",
    ),
    (
        "tombstone-expiry",
        "DELETE FROM custody_items WHERE text IS NULL AND expires_at<=?1",
        "DELETE FROM custody_items WHERE 0 AND text IS NULL AND expires_at<=?1",
        "retention_redacts_content_without_rebinding_the_tombstone",
        "expired tombstone was not reclaimed",
    ),
    (
        "ack-status",
        "DELETE FROM custody_pending WHERE bus=?1 AND upstream_id=?2",
        "DELETE FROM custody_pending WHERE 0 AND bus=?1 AND upstream_id=?2",
        "repeated_conflicts_do_not_starve_valid_traffic",
        "confirmed ACKs retained pending IDs",
    ),
    (
        "unfit-refusal",
        " || size as u128 > limits.max_bytes as u128",
        "",
        "a_delivery_larger_than_total_capacity_is_a_permanent_refusal",
        "unfit delivery was treated as transient",
    ),
    (
        "aggregate-byte-capacity",
        "size as u128 + bytes as u128 > limits.max_bytes as u128",
        "false",
        "aggregate_byte_capacity_is_transient_and_preserves_redelivery",
        "aggregate byte capacity was not enforced",
    ),
]
CASES += [
    (
        "idle-maintenance",
        "            store.record_custody_link(scope, true, limits, now)?;",
        "",
        "idle_poll_enforces_retention_and_observes_connection_changes",
        "idle receive ignored retention",
    ),
    (
        "receive-disconnect",
        "            store.record_custody_link(scope, false, limits, now)?;",
        "",
        "idle_poll_enforces_retention_and_observes_connection_changes",
        "disconnect was not recorded",
    ),
    (
        "reconnect-status",
        "UPDATE custody_links SET connected=1, reconnected_at=?2 WHERE",
        "UPDATE custody_links SET connected=0, reconnected_at=?2 WHERE",
        "idle_poll_enforces_retention_and_observes_connection_changes",
        "reconnected handle was not recorded",
    ),
]


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--case", choices=[case[0] for case in CASES])
    args = parser.parse_args()
    assert len(CASES) == 23, "custody mutant inventory drift"
    evidence = ROOT / ".artifacts/custody-mutants"
    evidence.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="gateway-custody-mutants-") as directory:
        root = Path(directory)
        for name in ("Cargo.toml", "Cargo.lock"):
            shutil.copyfile(ROOT / name, root / name)
        for name in ("src", "tests", "ci"):
            shutil.copytree(ROOT / name, root / name, copy_function=shutil.copyfile)
        file = root / "src/custody.rs"
        completed = 0
        for name, old, new, test, expected in CASES:
            if args.case and args.case != name:
                continue
            assert SOURCE.count(old) == 1, name
            file.touch()
            green = run(
                root,
                "custody_inbound",
                test,
                "src/custody.rs",
                test_args=("--include-ignored",),
                test_timeout=60,
            )
            assert (
                green.returncode == 0
                and "1 passed; 0 failed; 0 ignored" in green.stdout
            ), (name, "invalid baseline", green.stdout, green.stderr)
            try:
                file.write_text(SOURCE.replace(old, new, 1))
                red = run(
                    root,
                    "custody_inbound",
                    test,
                    "src/custody.rs",
                    test_args=("--include-ignored",),
                    test_timeout=60,
                )
                assert (
                    red.returncode == 101
                    and f"test {test} ... FAILED" in red.stdout
                    and expected in red.stdout + red.stderr
                ), (name, "intended cell did not kill mutant", red.stdout, red.stderr)
                (evidence / f"{name}.log").write_text(red.stdout + red.stderr)
                completed += 1
                print(f"{name}: GREEN baseline / RED intended", flush=True)
            finally:
                file.write_text(SOURCE)
        assert completed == (1 if args.case else 23)
    print(f"custody-mutants-complete:{completed}", flush=True)


if __name__ == "__main__":
    main()
