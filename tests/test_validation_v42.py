import unittest

import validation_suite_v42


class ValidationV42Tests(unittest.TestCase):
    def test_percentile_uses_the_upper_observation(self):
        self.assertEqual(validation_suite_v42.percentile([1, 2, 3, 4, 5], 0.95), 5)

    def test_registered_matrix_is_complete(self):
        self.assertEqual(len(validation_suite_v42.CASES), 5)
        self.assertEqual(len(validation_suite_v42.ARMS), 3)
        self.assertEqual(len(validation_suite_v42.SECURITY_CHECKS), 8)

    def test_check_preserves_a_failed_gate(self):
        result = validation_suite_v42.check("example", False, 1.2, "at most 1.0")
        self.assertFalse(result["passed"])
        self.assertEqual(result["observed"], 1.2)


if __name__ == "__main__":
    unittest.main()
