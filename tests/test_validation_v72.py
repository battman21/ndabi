import copy
import json
import unittest

import validation_suite_v72


class SupavisorSessionCampaignTests(unittest.TestCase):
    def test_campaign_shape_and_images_are_frozen(self):
        self.assertEqual(validation_suite_v72.PROCESS_COUNT, 5)
        self.assertEqual(validation_suite_v72.EXPECTED_QUERIES_PER_ARM, 2_030)
        self.assertIn("@sha256:", validation_suite_v72.SUPAVISOR_IMAGE)
        self.assertEqual(validation_suite_v72.TENANT_ID, "ndabi-v72")

    def test_source_custody_covers_the_pooler_and_inherited_binary(self):
        paths = set(validation_suite_v72.SOURCE_PATHS)
        expected = {
            "src/bin/ndabi_v71.rs",
            "validation_suite_v71.py",
            "validation_suite_v72.py",
            "support/v72/pooler.exs",
            "../../specs/ndabi_supavisor_session_campaign_v7_2.md",
        }
        self.assertTrue(expected.issubset(paths))

    def test_equal_reports_pass_the_pair_comparison(self):
        aggregate = json.loads(
            (validation_suite_v72.v71.RESULT_ROOT / "latest.json").read_text()
        )
        path = (
            validation_suite_v72.v71.RESULT_ROOT
            / aggregate["campaign_id"]
            / "process-1.json"
        )
        direct = json.loads(path.read_text())
        pooled = copy.deepcopy(direct)
        result = validation_suite_v72.compare_pair(direct, pooled)
        self.assertTrue(result["passed"])
        self.assertTrue(all(case["canonical_result_equal"] for case in result["cases"]))
        self.assertTrue(
            all(case["pooled_to_direct_p50_ratio"] == 1.0 for case in result["cases"])
        )

    def test_pair_comparison_rejects_result_drift(self):
        aggregate = json.loads(
            (validation_suite_v72.v71.RESULT_ROOT / "latest.json").read_text()
        )
        path = (
            validation_suite_v72.v71.RESULT_ROOT
            / aggregate["campaign_id"]
            / "process-1.json"
        )
        direct = json.loads(path.read_text())
        pooled = copy.deepcopy(direct)
        pooled["cases"][0]["result_sha256"] = "00" * 32
        result = validation_suite_v72.compare_pair(direct, pooled)
        self.assertFalse(result["passed"])

    def test_pair_comparison_records_invalid_evidence(self):
        result = validation_suite_v72.compare_pair({"passed": True}, {"passed": True})
        self.assertFalse(result["passed"])
        self.assertIsNotNone(result["validation_error"])

    def test_accepted_evidence_revalidates(self):
        root = validation_suite_v72.RESULT_ROOT
        aggregate = json.loads((root / "latest.json").read_text())
        campaign = root / aggregate["campaign_id"]
        stored = json.loads((campaign / "aggregate.json").read_text())
        self.assertEqual(aggregate, stored)
        self.assertTrue(aggregate["accepted"])
        self.assertEqual(
            aggregate["source_commit"],
            "9c4112818b76a25ddc72bbfb79d64046bfae6866",
        )
        self.assertTrue(aggregate["source_custody_passed"])
        self.assertTrue(aggregate["session_proof_passed"])
        self.assertEqual(len(aggregate["security"]), 17)
        self.assertTrue(all(aggregate["security"].values()))
        self.assertTrue(aggregate["repeatability_passed"])
        for process in range(1, validation_suite_v72.PROCESS_COUNT + 1):
            direct = json.loads((campaign / f"direct-process-{process}.json").read_text())
            pooled = json.loads((campaign / f"pooled-process-{process}.json").read_text())
            pair = json.loads((campaign / f"pair-process-{process}.json").read_text())
            validation_suite_v72.v71.validate_report(direct)
            validation_suite_v72.v71.validate_report(pooled)
            self.assertEqual(
                direct["observed_data_queries"],
                validation_suite_v72.EXPECTED_QUERIES_PER_ARM,
            )
            self.assertEqual(
                pooled["observed_data_queries"],
                validation_suite_v72.EXPECTED_QUERIES_PER_ARM,
            )
            self.assertTrue(direct["campaign_gate_passed"])
            self.assertTrue(pooled["campaign_gate_passed"])
            self.assertTrue(pair["passed"])


if __name__ == "__main__":
    unittest.main()
