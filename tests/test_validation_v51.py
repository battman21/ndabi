import unittest

import validation_suite_v51


class ValidationSuiteV51Tests(unittest.TestCase):
    def test_campaign_has_five_processes(self):
        self.assertEqual(validation_suite_v51.PROCESS_COUNT, 5)

    def test_postgresql_image_is_digest_pinned(self):
        self.assertIn("@sha256:", validation_suite_v51.POSTGRES_IMAGE)


if __name__ == "__main__":
    unittest.main()
