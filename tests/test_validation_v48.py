import unittest

import validation_suite_v48


class ValidationSuiteV48Tests(unittest.TestCase):
    def test_compatibility_image_is_digest_pinned(self):
        self.assertEqual(validation_suite_v48.campaign.MONGODB_IMAGE.split("@")[0], "mongo")
        self.assertIn("@sha256:", validation_suite_v48.campaign.MONGODB_IMAGE)

    def test_result_root_is_separate(self):
        self.assertEqual(validation_suite_v48.campaign.RESULT_ROOT.name, "v48")


if __name__ == "__main__":
    unittest.main()
