import unittest

import validation_suite_v60


class CanonicalMongoCampaignTests(unittest.TestCase):
    def test_campaign_uses_five_processes_and_a_pinned_image(self):
        self.assertEqual(validation_suite_v60.PROCESS_COUNT, 5)
        self.assertIn("@sha256:", validation_suite_v60.MONGODB_IMAGE)

    def test_source_custody_covers_the_protocol_adapter_and_runner(self):
        paths = set(validation_suite_v60.SOURCE_PATHS)
        self.assertIn("crates/ndabi-protocol/src/lib.rs", paths)
        self.assertIn("crates/ndabi-mongodb-v1/src/lib.rs", paths)
        self.assertIn("validation_suite_v60.py", paths)

    def test_prepare_requires_an_explicit_destructive_sentinel(self):
        self.assertIn("I_UNDERSTAND", validation_suite_v60.PREPARE_SENTINEL)


if __name__ == "__main__":
    unittest.main()
