import unittest

import validation_suite_v53


class ValidationSuiteV53Tests(unittest.TestCase):
    def test_image_is_digest_pinned(self):
        self.assertEqual(validation_suite_v53.MONGODB_IMAGE.split("@")[0], "mongo")
        self.assertIn("@sha256:", validation_suite_v53.MONGODB_IMAGE)

    def test_campaign_shape_is_frozen(self):
        self.assertEqual(validation_suite_v53.PROCESS_COUNT, 5)
        self.assertEqual(validation_suite_v53.BATCH_SIZES, (1, 8, 32, 128))
        self.assertEqual(validation_suite_v53.RESULT_ROOT.name, "v53")

    def test_aggregate_recomputes_registered_gates(self):
        arms = [
            {"id": "native-sequential", "p95_ns": 1_000},
            {"id": "json-sequential", "p95_ns": 1_000},
            {"id": "json-set", "p95_ns": 210},
            {"id": "native-set", "p95_ns": 200},
            {"id": "ndabi-typed", "p95_ns": 205},
            {"id": "ndabi-raw", "p95_ns": 190},
        ]
        report = {
            "cases": [
                {
                    "batch_size": 128,
                    "arms": arms,
                    "exact_results": True,
                    "request_compression": 0.75,
                    "ndabi_raw_allocated_byte_reduction": 0.31,
                }
            ]
        }
        aggregate = validation_suite_v53.aggregate_case([report] * 5, 128)
        self.assertTrue(aggregate["passed"])


if __name__ == "__main__":
    unittest.main()
