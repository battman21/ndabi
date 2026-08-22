import unittest

import validation_suite_v50


class ValidationSuiteV50Tests(unittest.TestCase):
    def test_campaign_has_five_processes(self):
        self.assertEqual(validation_suite_v50.PROCESS_COUNT, 5)

    def test_images_are_digest_pinned(self):
        self.assertIn("@sha256:", validation_suite_v50.POSTGRES_IMAGE)
        self.assertIn("@sha256:", validation_suite_v50.POSTGREST_IMAGE)


if __name__ == "__main__":
    unittest.main()
