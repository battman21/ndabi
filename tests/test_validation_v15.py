import importlib.util
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "validation_suite_v15", ROOT / "validation_suite_v15.py"
)
assert SPEC is not None and SPEC.loader is not None
CAMPAIGN = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(CAMPAIGN)


class ValidationV15Tests(unittest.TestCase):
    def test_campaign_has_fixed_process_count(self):
        self.assertEqual(len(CAMPAIGN.CASES), 3)
        self.assertEqual(CAMPAIGN.REPLICAS, 3)
        self.assertEqual(len(CAMPAIGN.CASES) * CAMPAIGN.REPLICAS, 9)

    def test_container_command_enforces_containment(self):
        command = CAMPAIGN.container_command(CAMPAIGN.IMAGE, CAMPAIGN.CASES[0])
        self.assertIn("none", command)
        self.assertIn("--read-only", command)
        self.assertIn("ALL", command)
        self.assertIn("no-new-privileges", command)
        self.assertIn(CAMPAIGN.CPUSET, command)

    def test_resource_usage_parser_accepts_gnu_time(self):
        result = CAMPAIGN.parse_rusage(
            b"NDABI_RUSAGE user=1.25 system=0.50 max_rss_kb=4096 elapsed=0:01.80\n"
        )
        self.assertEqual(result["max_rss_kb"], 4096)
        self.assertEqual(result["elapsed_seconds"], 1.8)

    def test_phase_lookup_and_variation_are_exact(self):
        result = {"phases": [{"id": "kernel", "median_ns_per_operation": 12.0}]}
        self.assertEqual(CAMPAIGN.phase(result, "kernel")["median_ns_per_operation"], 12.0)
        self.assertEqual(CAMPAIGN.coefficient_variation([2.0, 2.0, 2.0]), 0.0)


if __name__ == "__main__":
    unittest.main()
