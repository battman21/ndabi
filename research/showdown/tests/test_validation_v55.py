import unittest

import validation_suite_v55


class ValidationSuiteV55Tests(unittest.TestCase):
    def test_campaign_shape_is_frozen(self):
        self.assertEqual(validation_suite_v55.PROCESS_COUNT, 5)
        self.assertEqual(validation_suite_v55.BATCH_SIZES, (1, 8, 32, 128))
        self.assertEqual(validation_suite_v55.RESULT_ROOT.name, "v55")

    def test_process_integrity_requires_literal_and_command_proofs(self):
        arms = [{"deterministic_encoding": True}]
        report = {
            "refusals": "8/8",
            "single_batch_audit": {
                "find_commands": 1,
                "get_more_commands": 0,
                "passed": True,
            },
            "cases": [{"exact_results": True, "arms": arms}],
        }
        self.assertTrue(validation_suite_v55.process_integrity(report))
        report["single_batch_audit"]["get_more_commands"] = 1
        self.assertFalse(validation_suite_v55.process_integrity(report))


if __name__ == "__main__":
    unittest.main()
