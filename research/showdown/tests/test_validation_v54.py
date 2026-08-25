import unittest

import validation_suite_v54


class ValidationSuiteV54Tests(unittest.TestCase):
    def test_image_is_digest_pinned(self):
        self.assertEqual(validation_suite_v54.MONGODB_IMAGE.split("@")[0], "mongo")
        self.assertIn("@sha256:", validation_suite_v54.MONGODB_IMAGE)

    def test_campaign_shape_is_frozen(self):
        self.assertEqual(validation_suite_v54.PROCESS_COUNT, 5)
        self.assertEqual(validation_suite_v54.BATCH_SIZES, (1, 8, 32, 128))
        self.assertEqual(validation_suite_v54.RESULT_ROOT.name, "v54")

    def test_aggregate_recomputes_registered_gates(self):
        arms = [
            {"id": "native-sequential", "p95_ns": 20_000},
            {"id": "json-sequential", "p95_ns": 21_000},
            {"id": "json-set", "p95_ns": 1_100},
            {
                "id": "native-set",
                "p95_ns": 1_000,
                "allocated_bytes_per_operation": 10_000.0,
            },
            {
                "id": "ndabi-typed",
                "p95_ns": 1_050,
                "allocated_bytes_per_operation": 10_100.0,
            },
            {
                "id": "ndabi-raw",
                "p95_ns": 1_200,
                "allocated_bytes_per_operation": 11_000.0,
            },
        ]
        report = {
            "cases": [
                {
                    "batch_size": 128,
                    "arms": arms,
                    "exact_results": True,
                    "request_compression": 0.75,
                }
            ]
        }
        aggregate = validation_suite_v54.aggregate_case([report] * 5, 128)
        self.assertTrue(aggregate["passed"])


if __name__ == "__main__":
    unittest.main()
