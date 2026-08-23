import unittest

import validation_suite_v56


class ValidationSuiteV56Tests(unittest.TestCase):
    def valid_report(self):
        return {
            "campaign": validation_suite_v56.CAMPAIGN_LABEL,
            "dataset_rows": 1_000_000,
            "frame_bytes": 76,
            "refusals": "8/8",
            "single_batch_audit": {
                "find_commands": 1,
                "get_more_commands": 0,
                "passed": True,
            },
            "cases": [
                {
                    "batch_size": size,
                    "exact_results": True,
                    "arms": [
                        {"id": identifier, "deterministic_encoding": True}
                        for identifier in validation_suite_v56.ARM_IDS
                    ],
                }
                for size in validation_suite_v56.BATCH_SIZES
            ],
        }

    def test_integrity_accepts_the_complete_shape(self):
        self.assertTrue(validation_suite_v56.process_integrity(self.valid_report()))

    def test_integrity_refuses_a_missing_command_proof(self):
        report = self.valid_report()
        report.pop("single_batch_audit")
        self.assertFalse(validation_suite_v56.process_integrity(report))

    def test_integrity_refuses_a_duplicate_batch(self):
        report = self.valid_report()
        report["cases"][0]["batch_size"] = 8
        self.assertFalse(validation_suite_v56.process_integrity(report))


if __name__ == "__main__":
    unittest.main()
