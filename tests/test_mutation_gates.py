"""Ordinary stdlib controls for mutation classification and completion."""

import copy
import importlib.util
import io
import json
import os
import subprocess
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

    def test_live_tee_preserves_stdout_stderr_bytes_and_failure_exit(self):
        with tempfile.TemporaryDirectory() as directory:
            log = Path(directory) / "execution.log"
            console = io.BytesIO()
            command = [
                sys.executable,
                "-c",
                "import os; os.write(1,b'arm started\\n'); os.write(2,b'arm failed\\n'); raise SystemExit(7)",
            ]
            self.assertEqual(gates.tee_command(command, log, console), 7)
            self.assertEqual(log.read_bytes(), b"arm started\narm failed\n")
            self.assertEqual(console.getvalue(), log.read_bytes())

    def test_tee_delivers_progress_before_child_can_finish(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            released = root / "released"

            class Console(io.BytesIO):
                def write(self, chunk):
                    released.touch()
                    return super().write(chunk)

            console = Console()
            program = (
                "import os,time,pathlib; os.write(1,b'first\\n'); end=time.monotonic()+2; flag=pathlib.Path("
                + repr(str(released))
                + "); "
                + "\nwhile not flag.exists() and time.monotonic()<end: time.sleep(.01)\nraise SystemExit(0 if flag.exists() else 9)"
            )
            self.assertEqual(
                gates.tee_command(
                    [sys.executable, "-c", program], root / "log", console
                ),
                0,
            )
            self.assertEqual(console.getvalue(), b"first\n")

    def test_tee_interrupt_reaps_its_owned_child(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            owned = []

            class InterruptConsole:
                def write(self, chunk):
                    owned.append(int(chunk))
                    raise InterruptedError("forced console interruption")

            program = "import os,time; print(os.getpid(),flush=True); time.sleep(60)"
            with self.assertRaises(InterruptedError):
                gates.tee_command(
                    [sys.executable, "-c", program], root / "log", InterruptConsole()
                )
            self.assertEqual(len(owned), 1)
            with self.assertRaises(ProcessLookupError):
                os.kill(owned[0], 0)

    def test_real_cli_relative_output_writes_verifiable_receipt(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "scripts").mkdir()
            (root / "ci").mkdir()
            (root / "scripts/mutation_gates.py").write_bytes(
                (ROOT / "scripts/mutation_gates.py").read_bytes()
            )
            suite = self.suites[0]
            output = (
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
            registry = json.loads((ROOT / gates.REGISTRY).read_text())
            for entry in registry["suites"]:
                script = root / entry["script"]
                script.write_text("print(" + repr(output) + ", end='')\n")
                entry["script_sha256"] = gates.digest(script)
            (root / gates.REGISTRY).write_text(json.dumps(registry))
            subprocess.run(["git", "init", "-q"], cwd=root, check=True)
            subprocess.run(
                [
                    "git",
                    "-c",
                    "user.name=fixture",
                    "-c",
                    "user.email=fixture@example.invalid",
                    "commit",
                    "--allow-empty",
                    "-qm",
                    "fixture",
                ],
                cwd=root,
                check=True,
            )
            command = [
                sys.executable,
                str(root / "scripts/mutation_gates.py"),
                "run",
                "events",
                "--output",
                ".artifacts/receipts",
            ]
            result = subprocess.run(command, cwd=root, capture_output=True, text=True)
            self.assertEqual(result.returncode, 0, result.stderr)
            receipt = json.loads((root / ".artifacts/receipts/events.json").read_text())
            self.assertEqual(receipt["log"], ".artifacts/receipts/events.log")
            plan = {
                "revision": receipt["revision"],
                "full": False,
                "selected": ["events"],
                "changed": ["src/event_observability_tests.rs"],
            }
            self.assertEqual(
                gates.verify(plan, [receipt], registry["suites"], root), 35
            )
            result = subprocess.run(
                command[:-1] + ["../outside"], cwd=root, capture_output=True, text=True
            )
            self.assertNotEqual(result.returncode, 0)
            self.assertFalse((root.parent / "outside").exists())

    def test_every_rust_shard_fetches_before_unchanged_offline_scripts(self):
        workflow = (ROOT / ".github/workflows/ci.yml").read_text()
        shard = workflow.split("  mutation-suite:", 1)[1].split(
            "  mutation-completion:", 1
        )[0]
        prerequisite = "      - name: Fetch locked dependencies before offline mutation builds\n        if: ${{ !matrix.python }}\n        run: cargo fetch --locked"
        self.assertIn(prerequisite, shard)
        self.assertLess(
            shard.index(prerequisite),
            shard.index(
                "      - name: Prepare existing revision-verified daemon fixtures"
            ),
        )
        self.assertLess(
            shard.index(prerequisite),
            shard.index("      - name: Complete selected suite with its controls"),
        )

    def test_complete_inventory_and_execution_modes(self):
        self.assertEqual(len(self.suites), 21)
        self.assertEqual(sum(s["count"] for s in self.suites), 410)
        modes = {(s["script"], tuple(s["args"])) for s in self.suites}
        self.assertIn(("scripts/reservation_lifetime_mutants.py", ("--live",)), modes)

    def test_authorization_server_inventory_and_all_shared_auth_sources_are_covered(
        self,
    ):
        suite = next(s for s in self.suites if s["id"] == "authorization_server")
        self.assertEqual(suite["count"], 118)
        self.assertEqual(len(suite["required_output"]), 236)
        self.assertEqual(
            suite["completion"], "authorization-server-mutants-complete:118/118"
        )
        for filename in [
            "src/auth/identity.rs",
            "src/authorization_server/store.rs",
            "src/authorization_server/property_tests.rs",
        ]:
            self.assertEqual(
                gates.select(self.suites, [filename]), [s["id"] for s in self.suites]
            )
        for label in [
            "reuse-family-update",
            "mark-rowcount",
            "log-oauth-uri",
            "admission-split-check-mark",
            "clock-partial-revoke",
        ]:
            self.assertIn(label, suite["labels"])

    def test_profiles_have_full_source_and_named_output_coverage(self):
        suite = next(s for s in self.suites if s["id"] == "profiles")
        self.assertEqual(suite["count"], 33)
        self.assertEqual(len(suite["required_output"]), 66)
        for source in [
            "src/auth.rs",
            "src/grants.rs",
            "src/event_dispatch.rs",
            "src/serving.rs",
            "src/outbound.rs",
        ]:
            self.assertIn(source, suite["dependencies"])
            self.assertIn("profiles", gates.select(self.suites, [source]))
        self.assertIn("merged-provider", suite["labels"])
        self.assertIn("events-selected-subscription", suite["labels"])
        self.assertEqual(suite["completion"], "profile-mutants-complete:33/33")

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
            len(gates.select(self.suites, ["tests/common/provider.rs"])), 21
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
            "changed": ["src/event_observability_tests.rs"],
        }
        return plan, receipt

    def test_actual_receipt_positive_and_missing_duplicate_stale_controls(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            plan, receipt = self.fixture(root)
            self.assertEqual(gates.verify(plan, [receipt], self.suites, root), 35)
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
