import importlib.util
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("validation_suite_v24", ROOT / "validation_suite_v24.py")
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


class ValidationSuiteV24Tests(unittest.TestCase):
    def test_coefficient_is_zero_for_equal_values(self):
        self.assertEqual(MODULE.coefficient([1.0, 1.0, 1.0]), 0.0)

    def test_correctness_requires_both_named_gates(self):
        result = {
            "hard_gate": {
                "checks": [
                    {"id": "literal-semantic-equality", "passed": True},
                    {"id": "frame-refusals", "passed": False},
                ]
            }
        }
        self.assertFalse(MODULE.correctness_passed(result))


if __name__ == "__main__":
    unittest.main()
