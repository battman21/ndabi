import copy
import importlib.util
import json
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def load_module(name: str):
    spec = importlib.util.spec_from_file_location(name, ROOT / f"{name}.py")
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


V34 = load_module("validation_suite_v34")
V35 = load_module("validation_suite_v35")
V34_ROOT = ROOT / "results" / "v34" / "20260822T054732Z-1787377652364643000"
V35_ROOT = ROOT / "results" / "v35" / "20260822T060415Z-1787378655381197000"


class ValidationV35Tests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.v34_results = [
            json.loads((V34_ROOT / f"process-{index:02d}.json").read_text(encoding="utf-8"))
            for index in range(5)
        ]
        cls.v35_results = [
            json.loads((V35_ROOT / f"process-{index:02d}.json").read_text(encoding="utf-8"))
            for index in range(5)
        ]

    def test_retained_processes_satisfy_both_schemas(self):
        for result in self.v34_results:
            V34.validate_result(result)
        for result in self.v35_results:
            V35.validate_result(result)

    def test_changed_percentile_fails_closed(self):
        changed = copy.deepcopy(self.v35_results[0])
        changed["concurrency_cases"][0]["measurements"][0]["p95_request_ns"] += 1
        with self.assertRaises(ValueError):
            V35.validate_result(changed)

    def test_changed_derived_ratio_fails_closed(self):
        changed = copy.deepcopy(self.v35_results[0])
        changed["concurrency_cases"][0]["resumable_throughput_ratio"] *= 2
        with self.assertRaises(ValueError):
            V35.validate_result(changed)

    def test_retained_v35_failure_has_only_two_repeatability_failures(self):
        summary = V35.aggregate(
            self.v35_results,
            [0] * 5,
            "test-campaign",
            "test-postgres-image",
        )
        failed = [item["id"] for item in summary["hard_gate"]["checks"] if not item["passed"]]
        self.assertEqual(
            failed,
            [
                "concurrency-1-resumable-throughput-repeatability",
                "concurrency-8-resumable-p95-repeatability",
            ],
        )
        self.assertEqual(summary["status"], "failed")

    def test_nonzero_process_exit_fails_closed(self):
        summary = V35.aggregate(
            self.v35_results,
            [0, 0, 1, 0, 0],
            "test-campaign",
            "test-postgres-image",
        )
        check = next(
            item for item in summary["hard_gate"]["checks"] if item["id"] == "five-zero-exit-codes"
        )
        self.assertFalse(check["passed"])
        self.assertEqual(summary["status"], "failed")


if __name__ == "__main__":
    unittest.main()
