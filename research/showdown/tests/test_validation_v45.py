import unittest

import validation_suite_v45


class ValidationSuiteV45Tests(unittest.TestCase):
    def test_campaign_constants_match_the_frozen_spec(self):
        self.assertEqual(validation_suite_v45.PROCESS_COUNT, 5)
        self.assertEqual(validation_suite_v45.ITERATIONS, 20_000)
        self.assertEqual(validation_suite_v45.WARMUP, 2_000)

    def test_campaign_binds_the_repaired_binary(self):
        self.assertEqual(validation_suite_v45.BINARY.name, "ndabi_v45")
        self.assertIn("src/bin/ndabi_v45.rs", validation_suite_v45.SOURCE_PATHS)


if __name__ == "__main__":
    unittest.main()
