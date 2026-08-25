import json
import unittest

import validation_suite_v71


class SupabaseIndexedBatchCampaignTests(unittest.TestCase):
    def test_campaign_shape_and_images_are_frozen(self):
        self.assertEqual(validation_suite_v71.PROCESS_COUNT, 5)
        self.assertEqual(validation_suite_v71.BATCH_SIZES, (2, 8, 16))
        self.assertEqual(validation_suite_v71.EXPECTED_QUERIES, 2_030)
        self.assertIn("@sha256:", validation_suite_v71.POSTGRES_IMAGE)
        self.assertIn("@sha256:", validation_suite_v71.POSTGREST_IMAGE)

    def test_source_custody_covers_every_executed_local_module(self):
        paths = set(validation_suite_v71.SOURCE_PATHS)
        expected = {
            "src/lib.rs",
            "src/alloc.rs",
            "src/bin/ndabi_v71.rs",
            "validation_suite_v58.py",
            "validation_suite_v71.py",
            "crates/ndabi-protocol/src/batch.rs",
            "crates/ndabi-protocol/src/connection.rs",
            "crates/ndabi-protocol/src/replay.rs",
            "crates/ndabi-protocol/src/transport.rs",
            "crates/ndabi-supabase-indexed-batch-session-v1/src/lib.rs",
            "../../specs/ndabi_supabase_indexed_batch_campaign_v7_1.md",
        }
        self.assertTrue(expected.issubset(paths))

    def test_accepted_evidence_revalidates(self):
        result_root = validation_suite_v71.RESULT_ROOT
        aggregate = json.loads((result_root / "latest.json").read_text())
        stored = json.loads(
            (result_root / aggregate["campaign_id"] / "aggregate.json").read_text()
        )
        self.assertEqual(aggregate, stored)
        self.assertTrue(aggregate["accepted"])
        self.assertTrue(aggregate["source_custody_passed"])
        self.assertEqual(len(aggregate["security"]), 17)
        self.assertTrue(all(aggregate["security"].values()))
        reports = sorted((result_root / aggregate["campaign_id"]).glob("process-*.json"))
        self.assertEqual(len(reports), validation_suite_v71.PROCESS_COUNT)
        for path in reports:
            report = json.loads(path.read_text())
            validation_suite_v71.validate_report(report)
            self.assertTrue(report["validated"])
            self.assertTrue(report["passed"])
            self.assertEqual(
                report["observed_data_queries"],
                validation_suite_v71.EXPECTED_QUERIES,
            )


if __name__ == "__main__":
    unittest.main()
