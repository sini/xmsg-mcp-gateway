"""A broken socket fixture cannot count as a callback transport mutant kill."""
import importlib.util
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
SPEC = importlib.util.spec_from_file_location(
    "webhook_transport_gate", ROOT / "scripts/events_mutants.py"
)
gate = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = gate
SPEC.loader.exec_module(gate)


class WebhookTransportGateTests(unittest.TestCase):
    def test_fixture_failures_are_not_transport_kills(self):
        for name, witness in gate.CALLBACK_TRANSPORT_WITNESSES.items():
            output = (
                f"test {name} ... FAILED\n"
                "test result: FAILED. 0 passed; 1 failed; 0 ignored; 0 measured; 2 filtered out\n"
            )
            result = {"status": 101, "stdout": output, "stderr": "resolver shim positive control failed", "duration_seconds": 0.1}
            with tempfile.TemporaryDirectory() as directory, mock.patch.object(
                gate, "EVIDENCE", Path(directory)
            ), mock.patch.object(gate, "run", return_value=result), mock.patch.object(
                gate, "invocation_evidence"
            ):
                with self.assertRaisesRegex(AssertionError, "outside its intended oracle"):
                    gate.execute(ROOT, Path("fixture-binary"), {}, "fixture-error", name=name, red=True)
                result["stderr"] = witness
                accepted = gate.execute(ROOT, Path("fixture-binary"), {}, "intended-error", name=name, red=True)
                self.assertEqual(accepted["counts"]["failed"], 1)
