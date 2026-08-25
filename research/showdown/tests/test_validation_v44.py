import unittest

import validation_suite_v44


class ValidationSuiteV44Tests(unittest.TestCase):
    def test_campaign_constants_match_the_frozen_spec(self):
        self.assertEqual(validation_suite_v44.PROCESS_COUNT, 5)
        self.assertEqual(validation_suite_v44.ITERATIONS, 20_000)
        self.assertEqual(validation_suite_v44.WARMUP, 2_000)

    def test_source_digest_covers_the_shared_profiles(self):
        self.assertIn("crates/ndabi-session/src/lib.rs", validation_suite_v44.SOURCE_PATHS)
        self.assertIn("crates/ndabi-postgres/src/lib.rs", validation_suite_v44.SOURCE_PATHS)
        self.assertIn("src/white_tree.rs", validation_suite_v44.SOURCE_PATHS)


if __name__ == "__main__":
    unittest.main()
