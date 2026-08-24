import unittest

import validation_suite_v74 as repair


class SupavisorConcurrencyRepairTests(unittest.TestCase):
    def test_repair_keeps_the_workload_and_changes_only_the_environment_gate(self):
        self.assertEqual(repair.campaign.CONCURRENCY_LEVELS, (1, 8, 32))
        self.assertEqual(repair.campaign.OPERATIONS, 16)
        self.assertEqual(repair.campaign.SAMPLES, 31)
        self.assertEqual(repair.campaign.MINIMUM_HOST_IDLE_PERCENT, 50.0)
        self.assertEqual(
            repair.campaign.CAMPAIGN_NAME,
            "NDABI Supavisor concurrency campaign v7.4",
        )

    def test_source_custody_covers_the_repair_contract(self):
        paths = set(repair.campaign.SOURCE_PATHS)
        self.assertIn("validation_suite_v74.py", paths)
        self.assertIn(
            "../../specs/ndabi_supavisor_concurrency_campaign_v7_4.md", paths
        )


if __name__ == "__main__":
    unittest.main()
