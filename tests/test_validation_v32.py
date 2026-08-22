import copy
import importlib.util
import json
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "validation_suite_v32", ROOT / "validation_suite_v32.py"
)
assert SPEC is not None and SPEC.loader is not None
VALIDATION = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(VALIDATION)
RESULT = (
    ROOT
    / "results"
    / "v32"
    / "20260822T031028Z-1787368228461102000"
    / "process-00.json"
)


class ValidationV32Tests(unittest.TestCase):
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

    def test_duplicate_arm_fails_closed(self):
        changed = copy.deepcopy(self.result)
        changed["cases"][0]["measurements"][1]["id"] = "sequential-prepared"
        with self.assertRaises(ValueError):
            VALIDATION.validate_result(changed)


if __name__ == "__main__":
    unittest.main()
