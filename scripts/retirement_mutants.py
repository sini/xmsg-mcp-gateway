"""Prove a retired gist write cannot become a fresh effect after witness loss."""

from pathlib import Path

import events_mutants as harness
from events_mutants import Case, Edit

ROOT = Path(__file__).resolve().parents[1]
TEST = "retired_gist_write_request_id_never_reexecutes"

CASES = [
    Case(
        "erase-last-refusal-witness",
        "broker_bridge",
        TEST,
        "tests/broker_bridge.rs",
        (
            Edit(
                "src/retirement.rs",
                "tx.commit()?;",
                '''tx.execute("DELETE FROM outbound_retired", [])?;
        tx.execute("DELETE FROM outbound_request_fences WHERE NOT EXISTS (SELECT 1 FROM outbound_reservations r WHERE r.owner=outbound_request_fences.owner AND r.request_id=outbound_request_fences.request_id)", [])?;
        tx.commit()?;''',
                "pub(crate) fn retire_outbound_locked(",
                "#[cfg(test)]",
            ),
        ),
    ),
]


def main():
    harness.ROOT = ROOT
    harness.EVIDENCE = ROOT / ".artifacts/retirement-mutants"
    harness.CASES = CASES
    harness.BASELINE_TARGETS = ["broker_bridge"]
    harness.NONCE_TEST = "retirement_build_nonce_receipt"
    harness.main()
    print("retirement-mutants-complete:1/1", flush=True)


if __name__ == "__main__":
    main()
