"""Ordinary stdlib controls for mutation classification and completion."""

import copy
import importlib.util
import json
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "mutation_gates", ROOT / "scripts/mutation_gates.py"
)
gates = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = gates
SPEC.loader.exec_module(gates)


class MutationGatesTests(unittest.TestCase):
    def setUp(self):
        self.suites = gates.load_registry()

    def test_complete_inventory_and_execution_modes(self):
        self.assertEqual(len(self.suites), 19)
        self.assertEqual(sum(s["count"] for s in self.suites), 244)
        modes = {(s["script"], tuple(s["args"])) for s in self.suites}
        self.assertIn(("scripts/reservation_lifetime_mutants.py", ("--live",)), modes)

    def test_shared_unknown_and_full_changes_select_every_suite(self):
        expected = [s["id"] for s in self.suites]
        for changed in [
            ["scripts/artifact_evidence.py"],
            ["Cargo.lock"],
            ["rust-toolchain.toml"],
            [".github/workflows/ci.yml"],
            ["src/new_unclassified.rs"],
            ["tests/new_unclassified.rs"],
        ]:
            self.assertEqual(gates.select(self.suites, changed), expected)
        self.assertEqual(gates.select(self.suites, [], full=True), expected)

    def test_main_dispatch_and_persistent_full_label_select_every_suite(self):
        for event_name in ["push", "workflow_dispatch"]:
            self.assertTrue(gates.event_requires_full(event_name, {}))
        labeled = {"pull_request": {"labels": [{"name": "full-gates"}]}}
        self.assertTrue(gates.event_requires_full("pull_request", labeled))
        labeled["action"] = "synchronize"
        self.assertTrue(gates.event_requires_full("pull_request", labeled))
        self.assertFalse(
            gates.event_requires_full("pull_request", {"pull_request": {"labels": []}})
        )

    def test_documentation_and_ordinary_counts_can_select_nothing(self):
        self.assertEqual(
            gates.select(self.suites, ["docs/serving.md", "ci/ordinary-counts.json"]),
            [],
        )

    def test_nested_markdown_is_not_silently_classified_as_root_documentation(self):
        self.assertEqual(gates.select(self.suites, ["README.md"]), [])
        expected = [suite["id"] for suite in self.suites]
        self.assertEqual(
            gates.select(self.suites, ["tests/fixtures/input.md"]), expected
        )
        for helper in ["src/outbound_lease.rs", "src/xmsg_config.rs"]:
            self.assertEqual(gates.select(self.suites, [helper]), expected)

    def test_source_named_test_and_helper_changes_select_dependencies(self):
        self.assertIn("dispatch_logging", gates.select(self.suites, ["src/serving.rs"]))
        self.assertIn("broker", gates.select(self.suites, ["tests/broker_bridge.rs"]))
        self.assertEqual(
            len(gates.select(self.suites, ["tests/common/provider.rs"])), 19
        )
        self.assertEqual(gates.select(self.suites, ["phase1/worker.py"]), ["python"])

    def test_missing_registration_is_an_error(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "ci").mkdir()
            (root / "scripts").mkdir()
            (root / gates.REGISTRY).write_text((ROOT / gates.REGISTRY).read_text())
            with self.assertRaisesRegex(ValueError, "unregistered"):
                gates.load_registry(root)

    def fixture(self, root):
        suite = self.suites[0]
        (root / "ci").mkdir()
        (root / gates.REGISTRY).write_text((ROOT / gates.REGISTRY).read_text())
        log = root / "suite.log"
        log.write_text(
            "\n".join(
                [
                    f"g5-events {arm} {i + 1:02}-{label}-{suffix}{colon}"
                    for i, label in enumerate(suite["labels"])
                    for arm, suffix, colon in [
                        ("RED", "red", ": intended"),
                        ("GREEN", "restored", ""),
                    ]
                ]
                + [suite["completion"]]
            )
            + "\n"
        )
        receipt = {
            "suite": suite["id"],
            "exit": 0,
            "count": suite["count"],
            "revision": "revision",
            "registry_sha256": gates.digest(root / gates.REGISTRY),
            "log": "suite.log",
            "log_sha256": gates.digest(log),
        }
        plan = {
            "revision": "revision",
            "full": False,
            "selected": [suite["id"]],
            "changed": ["src/event_dispatch.rs"],
        }
        return plan, receipt

    def test_actual_receipt_positive_and_missing_duplicate_stale_controls(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            plan, receipt = self.fixture(root)
            self.assertEqual(gates.verify(plan, [receipt], self.suites, root), 22)
            for receipts in [[], [receipt, receipt]]:
                with self.assertRaises(ValueError):
                    gates.verify(plan, receipts, self.suites, root)
            for field, value in [
                ("exit", 1),
                ("count", 1),
                ("revision", "stale"),
                ("registry_sha256", "stale"),
                ("log_sha256", "stale"),
            ]:
                bad = dict(receipt, **{field: value})
                with self.assertRaises(ValueError):
                    gates.verify(plan, [bad], self.suites, root)

    def test_early_return_missing_case_unknown_and_false_full_controls(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            plan, receipt = self.fixture(root)
            (root / "suite.log").write_text("baseline passed; early return\n")
            receipt["log_sha256"] = gates.digest(root / "suite.log")
            with self.assertRaisesRegex(ValueError, "execution|completion"):
                gates.verify(plan, [receipt], self.suites, root)
            for selected in [["unknown"], ["events", "events"]]:
                bad = dict(plan, selected=selected)
                with self.assertRaises(ValueError):
                    gates.verify(bad, [receipt], self.suites, root)
            with self.assertRaisesRegex(ValueError, "omitted"):
                gates.verify(dict(plan, full=True), [receipt], self.suites, root)

    def test_omitted_named_mutant_fails_even_with_final_marker_and_fresh_log_hash(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            plan, receipt = self.fixture(root)
            log = root / "suite.log"
            log.write_text("\n".join(log.read_text().splitlines()[1:]) + "\n")
            receipt["log_sha256"] = gates.digest(log)
            with self.assertRaisesRegex(ValueError, "named mutant"):
                gates.verify(plan, [receipt], self.suites, root)

    def test_changed_script_inventory_requires_review(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "ci").mkdir()
            (root / "scripts").mkdir()
            (root / gates.REGISTRY).write_text((ROOT / gates.REGISTRY).read_text())
            for suite in self.suites:
                (root / suite["script"]).write_bytes(
                    (ROOT / suite["script"]).read_bytes()
                )
            with (root / self.suites[0]["script"]).open("a") as changed:
                changed.write("\n# changed inventory control\n")
            with self.assertRaisesRegex(ValueError, "inventory changed"):
                gates.load_registry(root)

    def test_empty_selection_is_valid_and_no_receipt_is_fabricated(self):
        self.assertEqual(
            gates.verify(
                {"selected": [], "full": False, "changed": []}, [], self.suites
            ),
            0,
        )

    def test_completion_must_be_unique(self):
        suite = self.suites[0]
        with self.assertRaises(ValueError):
            gates.validate_output(suite, (suite["completion"] + "\n") * 2)

    def test_header_receipt_requires_every_existing_arm(self):
        suite = next(s for s in self.suites if s["id"] == "header_timeout")
        arms = [
            {
                "arm": label,
                "nonce": "nonce",
                "source_sha256": "sha",
                "artifacts": ["artifact"],
                "results": [
                    {
                        "test": test,
                        "status": 0 if label == "control" else 101,
                        "verdict": "green" if label == "control" else "red",
                    }
                    for test in suite["arm_tests"][label]
                ],
            }
            for label in ["control", *suite["labels"]]
        ]
        text = "\n".join(json.dumps(a) for a in arms)
        gates.validate_output(suite, text)
        with self.assertRaises(ValueError):
            gates.validate_output(suite, "\n".join(json.dumps(a) for a in arms[:-1]))
        broken = copy.deepcopy(arms)
        broken[0]["results"] = []
        with self.assertRaises(ValueError):
            gates.validate_output(suite, "\n".join(json.dumps(a) for a in broken))


if __name__ == "__main__":
    unittest.main()
