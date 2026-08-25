import copy
import importlib.util
import json
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "validation_suite_v33", ROOT / "validation_suite_v33.py"
)
assert SPEC is not None and SPEC.loader is not None
VALIDATION = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(VALIDATION)
RESULT = (
    ROOT
    / "results"
    / "v33"
    / "20260822T034314Z-1787370194473542000"
    / "process-00.json"
)


class ValidationV33Tests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.result = json.loads(RESULT.read_text(encoding="utf-8"))

    def test_retained_result_satisfies_the_schema(self):
        VALIDATION.validate_result(self.result)

    def test_changed_percentile_fails_closed(self):
        changed = copy.deepcopy(self.result)
        changed["cases"][0]["measurements"][0]["p95_batch_ns"] += 1
        with self.assertRaises(ValueError):
            VALIDATION.validate_result(changed)

    def test_process_failure_cannot_become_aggregate_success(self):
        summary = VALIDATION.aggregate(
            [self.result] * 5,
            [0, 0, 1, 0, 0],
            "test-campaign",
            "test-postgres-image",
        )
        self.assertFalse(summary["hard_gate"]["passed"])


if __name__ == "__main__":
    unittest.main()
