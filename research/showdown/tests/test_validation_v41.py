import copy
import importlib.util
import json
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
RESULT_ROOT = ROOT / "results" / "v41" / "20260822T092628Z-1787390788047173000"


def load_runner():
    spec = importlib.util.spec_from_file_location("validation_suite_v41", ROOT / "validation_suite_v41.py")
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


V41 = load_runner()


class ValidationV41Tests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.results = [
            json.loads((RESULT_ROOT / f"process-{index:02d}.json").read_text(encoding="utf-8"))
            for index in range(5)
        ]

    def test_retained_processes_satisfy_the_frozen_schema(self):
        for result in self.results:
            V41.validate_result(result)

    def test_changed_embedded_ratio_fails_closed(self):
        changed = copy.deepcopy(self.results[0])
        changed["latency_cases"][0]["embedded_native_distance"] *= 2
        with self.assertRaises(ValueError):
            V41.validate_result(changed)

    def test_changed_embedded_security_proof_fails_closed(self):
        changed = copy.deepcopy(self.results[0])
        changed["security"]["embedded_replay_refused"] = False
        with self.assertRaises(ValueError):
            V41.validate_result(changed)

    def test_retained_campaign_passes_every_gate(self):
        summary = V41.aggregate(
            self.results,
            [0] * 5,
            "test-campaign",
            {"client": "test", "postgres": "test", "postgrest": "test"},
            {"gateway": 1, "postgres": 1, "postgrest": 1},
        )
        self.assertTrue(summary["hard_gate"]["passed"])
        self.assertEqual(
            [item["id"] for item in summary["hard_gate"]["checks"] if not item["passed"]],
            [],
        )
        self.assertEqual(summary["status"], "accepted")


if __name__ == "__main__":
    unittest.main()
