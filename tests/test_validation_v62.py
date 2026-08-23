import unittest
from unittest import mock

import validation_suite_v62


class PostgresBatchEvidenceRepairTests(unittest.TestCase):
    def test_repair_retains_the_v61_engine_and_process_count(self):
        self.assertEqual(validation_suite_v62.PROCESS_COUNT, 5)
        self.assertEqual(
            validation_suite_v62.POSTGRES_IMAGE,
            validation_suite_v62.base.POSTGRES_IMAGE,
        )

    def test_source_custody_includes_both_campaigns_and_runners(self):
        paths = set(validation_suite_v62.SOURCE_PATHS)
        self.assertIn("validation_suite_v61.py", paths)
        self.assertIn("validation_suite_v62.py", paths)
        self.assertIn(
            "../../specs/ndabi_canonical_postgresql_batch_campaign_v6_1.md",
            paths,
        )
        self.assertIn(
            "../../specs/ndabi_canonical_postgresql_batch_campaign_v6_2.md",
            paths,
        )

    def test_invalid_child_output_is_represented_by_a_digest(self):
        self.assertEqual(
            validation_suite_v62.digest_text("invalid"),
            "f1234d75178d892a133a410355a5a990cf75d2f33eba25d575943d4df632f3a4",
        )

    def test_cleanup_retries_until_the_container_is_absent(self):
        present = mock.Mock(returncode=0)
        absent = mock.Mock(returncode=1)
        command = mock.Mock(side_effect=[mock.Mock(), present, mock.Mock(), absent])
        with mock.patch.object(validation_suite_v62.base, "command", command):
            validation_suite_v62.remove_container("campaign-container")
        self.assertEqual(command.call_count, 4)


if __name__ == "__main__":
    unittest.main()
