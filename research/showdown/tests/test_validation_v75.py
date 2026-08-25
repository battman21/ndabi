import json
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

    def test_failed_evidence_revalidates(self):
        aggregate = json.loads((repair.RESULT_ROOT / "latest.json").read_text())
        campaign = repair.RESULT_ROOT / aggregate["campaign_id"]
        stored = json.loads((campaign / "aggregate.json").read_text())
        self.assertEqual(aggregate, stored)
        self.assertEqual(
            aggregate["source_commit"],
            "72fc936c928dcbcb8fdda0e81401ba79148a70b8",
        )
        self.assertTrue(aggregate["source_custody_passed"])
        self.assertTrue(aggregate["security_passed"])
        self.assertEqual(len(aggregate["security"]), 17)
        self.assertTrue(all(aggregate["security"].values()))
        self.assertFalse(aggregate["repeatability_passed"])
        self.assertFalse(aggregate["accepted"])
        self.assertTrue(all(not item["passed"] for item in aggregate["repeatability"]))
        for process in range(1, aggregate["process_count"] + 1):
            report = json.loads((campaign / f"process-{process}.json").read_text())
            repair.campaign.validate_process_report(report)
            self.assertTrue(report["passed"])


if __name__ == "__main__":
    unittest.main()
