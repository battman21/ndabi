import unittest

import validation_suite_v75 as repair


class SupavisorBuildExclusiveCampaignTests(unittest.TestCase):
    def test_repair_keeps_every_workload_and_performance_gate(self):
        self.assertEqual(repair.campaign.CONCURRENCY_LEVELS, (1, 8, 32))
        self.assertEqual(repair.campaign.OPERATIONS, 16)
        self.assertEqual(repair.campaign.SAMPLES, 31)
        self.assertEqual(repair.MINIMUM_HOST_IDLE_PERCENT, 0.0)
        self.assertEqual(
            repair.campaign.FORBIDDEN_BUILD_PROCESSES,
            {"cargo", "cargo-tauri", "clang", "rustc", "swiftc"},
        )

    def test_source_custody_covers_the_v75_contract(self):
        paths = set(repair.SOURCE_PATHS)
        self.assertIn("validation_suite_v75.py", paths)
        self.assertIn(
            "../../specs/ndabi_supavisor_concurrency_campaign_v7_5.md", paths
        )


if __name__ == "__main__":
    unittest.main()
