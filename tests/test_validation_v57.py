import unittest

import validation_suite_v57


class ValidationSuiteV57Tests(unittest.TestCase):
    def valid_report(self):
        return {
            "campaign": validation_suite_v57.CAMPAIGN_LABEL,
            "dataset_rows": 1_000_000,
            "frame_bytes": 76,
            "refusals": "8/8",
            "passed": True,
            "single_batch_audit": {
                "find_commands": 1,
                "get_more_commands": 0,
                "passed": True,
            },
            "cases": [
                {
                    "batch_size": size,
                    "exact_results": True,
                    "passed": True,
                    "arms": [
                        {"id": identifier, "deterministic_encoding": True}
                        for identifier in validation_suite_v57.ARM_IDS
                    ],
                }
                for size in validation_suite_v57.BATCH_SIZES
            ],
        }

    def test_integrity_accepts_the_complete_shape(self):
        self.assertTrue(validation_suite_v57.process_integrity(self.valid_report()))

    def test_integrity_refuses_a_failed_process_flag(self):
        report = self.valid_report()
        report["passed"] = False
        self.assertFalse(validation_suite_v57.process_integrity(report))

    def test_integrity_refuses_a_failed_case_flag(self):
        report = self.valid_report()
        report["cases"][0]["passed"] = False
        self.assertFalse(validation_suite_v57.process_integrity(report))


if __name__ == "__main__":
    unittest.main()
