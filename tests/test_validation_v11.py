import importlib.util
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "validation_suite_v11", ROOT / "validation_suite_v11.py"
)
assert SPEC is not None and SPEC.loader is not None
CAMPAIGN = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(CAMPAIGN)


class ValidationV10Tests(unittest.TestCase):
    def test_registered_cases_are_unique(self):
        identifiers = [case[0] for case in CAMPAIGN.CASES]
        self.assertEqual(len(identifiers), 12)
        self.assertEqual(len(set(identifiers)), len(identifiers))

    def test_registered_cases_cover_scale_boundaries(self):
        records = {case[2] for case in CAMPAIGN.CASES}
        result_bytes = {case[3] for case in CAMPAIGN.CASES}
        workloads = {case[1] for case in CAMPAIGN.CASES}
        self.assertEqual(records, {512, 10_000, 100_000, 1_000_000})
        self.assertEqual(result_bytes, {64, 4_096, 65_536, 1_048_576})
        self.assertEqual(workloads, {"point", "filter", "aggregate", "temporal"})


if __name__ == "__main__":
    unittest.main()
