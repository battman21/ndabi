import unittest

import validation_suite_v47


class ValidationSuiteV47Tests(unittest.TestCase):
    def test_campaign_has_five_processes(self):
        self.assertEqual(validation_suite_v47.PROCESS_COUNT, 5)

    def test_mongodb_image_is_digest_pinned(self):
        self.assertIn("@sha256:", validation_suite_v47.MONGODB_IMAGE)


if __name__ == "__main__":
    unittest.main()
