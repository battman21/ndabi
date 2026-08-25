import unittest

import validation_suite_v43


class ValidationV43Tests(unittest.TestCase):
    def test_repair_campaign_uses_the_rebuilt_image(self):
        self.assertEqual(validation_suite_v43.CLIENT_IMAGE, "ndabi-showdown:v4.3-local")
        self.assertEqual(len(validation_suite_v43.CASES), 5)
        self.assertEqual(len(validation_suite_v43.SECURITY_CHECKS), 8)

    def test_percentile_uses_the_upper_observation(self):
        self.assertEqual(validation_suite_v43.percentile([1, 2, 3, 4, 5], 0.95), 5)


if __name__ == "__main__":
    unittest.main()
