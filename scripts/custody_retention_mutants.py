"""Require fractional gap windows and immutable repeated-gap expiry."""

import subprocess
import tempfile
import uuid
from pathlib import Path

from artifact_evidence import record
from reservation_lifetime_mutants import build_units, marked
from transport_compat import ROOT, copy_fixture_tree, invocation_evidence

CASES = [
    (
        "floor-gap",
        "src/custody.rs",
        "crate::deadline::window(observation_at, limits.metadata_retention_secs)",
        "crate::deadline::window(UNIX_EPOCH + Duration::from_secs(observed as u64), limits.metadata_retention_secs)",
        "custody::retention_tests::fractional_gap_retention_preserves_the_complete_lifetime",
        "remaining >= Duration::from_secs(lifetime as u64)",
    ),
    (
        "extend-gap",
        "src/custody.rs",
        "stored_expiry.map_or(proposed_expiry, |stored| stored.min(proposed_expiry))",
        "stored_expiry.map_or(proposed_expiry, |_stored| proposed_expiry)",
        "custody::retention_tests::repeated_gap_observations_never_extend_the_stored_expiry",
        "repeat extended the same gap's retention",
    ),
    (
        "floor-session-observation",
        "src/session.rs",
        ".record_bus_link(bus, connected, limits, at)",
        ".record_bus_link(bus, connected, limits, std::time::UNIX_EPOCH + Duration::from_secs(at.duration_since(std::time::UNIX_EPOCH).unwrap().as_secs()))",
        "session::tests::production_bus_observations_preserve_fractional_retention",
        "remaining >= Duration::from_secs(lifetime)",
    ),
]

CASES += [
    (
        "late-gap",
        "src/custody.rs",
        "DELETE FROM custody_gaps WHERE expires_at<=?1",
        "DELETE FROM custody_gaps WHERE expires_at<?1",
        "custody::expiry_boundary_tests::gaps_expire_at_the_observed_boundary",
        "gap remained visible at expiry",
    ),
    (
        "late-pending",
        "src/custody.rs",
        "DELETE FROM custody_pending WHERE expires_at<=?1",
        "DELETE FROM custody_pending WHERE expires_at<?1",
        "custody::expiry_boundary_tests::pending_ids_expire_at_the_observed_boundary",
        "pending ID remained visible at expiry",
    ),
    (
        "late-pending-summary",
        "src/custody.rs",
        'tx.execute("UPDATE custody_links SET expired_first_seen = (SELECT MIN(first_seen) FROM (SELECT expired_first_seen AS first_seen UNION ALL SELECT first_seen FROM custody_pending WHERE bus = custody_links.bus AND expires_at<=?1)) WHERE EXISTS(SELECT 1 FROM custody_pending WHERE bus=custody_links.bus AND expires_at<=?1)", [now])?;',
        'tx.execute("UPDATE custody_links SET expired_first_seen = (SELECT MIN(first_seen) FROM (SELECT expired_first_seen AS first_seen UNION ALL SELECT first_seen FROM custody_pending WHERE bus = custody_links.bus AND expires_at<?1)) WHERE EXISTS(SELECT 1 FROM custody_pending WHERE bus=custody_links.bus AND expires_at<?1)", [now])?;',
        "custody::expiry_boundary_tests::pending_ids_expire_at_the_observed_boundary",
        "expired pending uncertainty summary missing at expiry",
    ),
    (
        "late-metadata",
        "src/custody.rs",
        "DELETE FROM custody_metadata WHERE expires_at <= ?1",
        "DELETE FROM custody_metadata WHERE expires_at < ?1",
        "custody::expiry_boundary_tests::refusal_metadata_expires_at_the_observed_boundary",
        "metadata remained visible at expiry",
    ),
    (
        "late-content",
        "src/custody.rs",
        "UPDATE custody_items SET text=NULL, envelope=NULL WHERE text IS NOT NULL AND expires_at<=?1",
        "UPDATE custody_items SET text=NULL, envelope=NULL WHERE text IS NOT NULL AND expires_at<?1",
        "custody::expiry_boundary_tests::held_content_expires_at_the_observed_boundary",
        "content remained visible at expiry",
    ),
    (
        "late-outbox",
        "src/custody.rs",
        "UPDATE custody_outbox SET state='expired' WHERE event_id IN (SELECT event_id FROM custody_items WHERE text IS NOT NULL AND expires_at<=?1)",
        "UPDATE custody_outbox SET state='expired' WHERE event_id IN (SELECT event_id FROM custody_items WHERE text IS NOT NULL AND expires_at<?1)",
        "custody::expiry_boundary_tests::outbox_expires_at_the_observed_boundary",
        "outbox remained held at expiry",
    ),
    (
        "late-tombstone",
        "src/custody.rs",
        "DELETE FROM custody_items WHERE text IS NULL AND expires_at<=?1",
        "DELETE FROM custody_items WHERE text IS NULL AND expires_at<?1",
        "custody::expiry_boundary_tests::tombstones_expire_at_the_observed_cutoff",
        "tombstone remained visible at cutoff",
    ),
    (
        "late-tombstone-outbox",
        "src/custody.rs",
        "DELETE FROM custody_outbox WHERE event_id IN (SELECT event_id FROM custody_items WHERE text IS NULL AND expires_at<=?1)",
        "DELETE FROM custody_outbox WHERE event_id IN (SELECT event_id FROM custody_items WHERE text IS NULL AND expires_at<?1)",
        "custody::expiry_boundary_tests::tombstones_expire_at_the_observed_cutoff",
        "tombstone outbox remained visible at cutoff",
    ),
]


def main():
    nonce = uuid.uuid4().hex
    for label, filename, needle, replacement, test, diagnostic in CASES:
        original = (ROOT / filename).read_text()
        assert original.count(needle) == 1, ("retention site drift", label)
        for arm, source in [
            ("control", original),
            ("mutant", original.replace(needle, replacement, 1)),
        ]:
            with tempfile.TemporaryDirectory(
                prefix=f"gateway-retention-{label}-{arm}-"
            ) as directory:
                root = Path(directory)
                copy_fixture_tree(root)
                marker = f"custody-retention-arm:{nonce}:{label}:{arm}"
                (root / filename).write_text(
                    marked(source, test.rsplit("::", 1)[1], marker)
                )
                executable = build_units(root)
                record(root, executable, f"{label}/{arm}")
                args = [str(executable), test, "--exact", "--nocapture"]
                invocation_evidence(args)
                result = subprocess.run(
                    args, cwd=root, capture_output=True, text=True, timeout=15
                )
                output = result.stdout + result.stderr
                assert output.count(marker) == 1, "named retention arm did not execute"
                if arm == "control":
                    assert (
                        result.returncode == 0
                        and "1 passed; 0 failed; 0 ignored" in output
                    ), output
                else:
                    assert result.returncode == 101 and diagnostic in output, output
                    assert "0 passed; 1 failed; 0 ignored" in output, output
            print(f"{label}/{arm}: intended result; nonce={nonce}", flush=True)
    print("custody-retention-mutants-complete:11", flush=True)


if __name__ == "__main__":
    main()
