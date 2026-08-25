import unittest

import validation_suite_v63


class PostgresBatchMethodologyRepairTests(unittest.TestCase):
    def test_campaign_uses_a_dedicated_build_target(self):
        self.assertEqual(
            validation_suite_v63.BINARY,
            validation_suite_v63.BUILD_TARGET / "release" / "ndabi_v61",
        )

    def test_source_custody_includes_all_three_campaigns(self):
        paths = set(validation_suite_v63.SOURCE_PATHS)
        self.assertIn("validation_suite_v61.py", paths)
        self.assertIn("validation_suite_v62.py", paths)
        self.assertIn("validation_suite_v63.py", paths)
        self.assertIn(
            "../../specs/ndabi_canonical_postgresql_batch_campaign_v6_3.md",
            paths,
        )

    def test_repeatability_uses_the_median_native_distance(self):
        source = validation_suite_v63.Path(validation_suite_v63.__file__).read_text()
        self.assertIn('item["batch_native_p50_distance"]', source)
        self.assertIn("variation < 0.10", source)


if __name__ == "__main__":
    unittest.main()
