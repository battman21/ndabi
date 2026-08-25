import copy
import importlib.util
import json
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
RESULT_ROOT = ROOT / "results" / "v40" / "20260822T073638Z-1787384198469986000"


def load_runner():
    spec = importlib.util.spec_from_file_location("validation_suite_v40", ROOT / "validation_suite_v40.py")
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


V40 = load_runner()


class ValidationV40Tests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.results = [
            json.loads((RESULT_ROOT / f"process-{index:02d}.json").read_text(encoding="utf-8"))
            for index in range(5)
        ]

    def test_retained_processes_satisfy_the_frozen_schema(self):
        for result in self.results:
            V40.validate_result(result)

    def test_changed_receipt_identity_fails_closed(self):
        changed = copy.deepcopy(self.results[0])
        changed["latency_cases"][0]["receipt_sha256"] = "0" * 64
        summary = V40.aggregate(
            [changed, *self.results[1:]],
            [0] * 5,
            "test-campaign",
            {"client": "test", "postgres": "test", "postgrest": "test"},
            {"gateway": 1, "postgres": 1, "postgrest": 1},
        )
        identity = next(
            item
            for item in summary["hard_gate"]["checks"]
            if item["id"] == "batch-32-one-identity"
        )
        self.assertFalse(identity["passed"])

    def test_changed_percentile_fails_closed(self):
        changed = copy.deepcopy(self.results[0])
        changed["latency_cases"][0]["measurements"][0]["p95_batch_ns"] += 1
        with self.assertRaises(ValueError):
            V40.validate_result(changed)

    def test_retained_campaign_records_only_native_ceiling_failures(self):
        summary = V40.aggregate(
            self.results,
            [0] * 5,
            "test-campaign",
            {"client": "test", "postgres": "test", "postgrest": "test"},
            {"gateway": 1, "postgres": 1, "postgrest": 1},
        )
        failed = [item["id"] for item in summary["hard_gate"]["checks"] if not item["passed"]]
        self.assertEqual(
            failed,
            [
                "batch-32-native-distance",
                "batch-128-native-distance",
                "concurrency-1-native-throughput",
                "concurrency-1-native-p95",
                "concurrency-8-native-throughput",
                "concurrency-8-native-p95",
                "concurrency-32-native-throughput",
                "concurrency-32-native-p95",
                "concurrency-128-native-throughput",
                "concurrency-128-native-p95",
            ],
        )
        self.assertEqual(summary["status"], "failed")


if __name__ == "__main__":
    unittest.main()
