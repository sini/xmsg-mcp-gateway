"""Require content-free INFO dispatch outcomes using a request-data source mutant."""
from pathlib import Path

import events_mutants as harness
from events_mutants import Case, Edit

ROOT = Path(__file__).resolve().parents[1]
CASES = [
    Case(
        "log-request-arguments",
        "broker_bridge",
        "dispatch_outcomes_are_single_static_info_records_without_request_canaries",
        "tests/broker_bridge.rs",
        (Edit(
            "src/serving.rs",
            "            let operation = diagnostic::operation(&call.name);",
            '            tracing::info!(target: "gateway_dispatch", arguments = ?call.arguments, "dispatch arguments");\n            let operation = diagnostic::operation(&call.name);',
        ),),
    ),
]


def main():
    harness.ROOT = ROOT
    harness.EVIDENCE = ROOT / ".artifacts/dispatch-logging-mutants"
    harness.CASES = CASES
    harness.BASELINE_TARGETS = ["broker_bridge"]
    harness.NONCE_TEST = "dispatch_logging_build_nonce_receipt"
    harness.main()
    print("dispatch-logging-mutants-complete:1/1", flush=True)


if __name__ == "__main__":
    main()
