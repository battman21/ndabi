import tempfile
import unittest
from pathlib import Path

import validation_suite_v07


class ValidationV07Tests(unittest.TestCase):
    def test_summary_statistics_report_population_variation(self) -> None:
        result = validation_suite_v07.summary_stats([10.0, 20.0, 30.0])
        self.assertEqual(result["minimum"], 10.0)
        self.assertEqual(result["maximum"], 30.0)
        self.assertEqual(result["mean"], 20.0)
        self.assertGreater(result["coefficient_of_variation"], 0.0)

    def test_empty_statistics_refuse(self) -> None:
        with self.assertRaisesRegex(ValueError, "empty"):
            validation_suite_v07.summary_stats([])

    def test_exclusive_evidence_store_refuses_overwrite(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / "run.json"
            validation_suite_v07.store_exclusive(target, b"first")
            with self.assertRaises(FileExistsError):
                validation_suite_v07.store_exclusive(target, b"second")
            self.assertEqual(target.read_bytes(), b"first")

    def test_sha256_bytes_is_deterministic(self) -> None:
        first = validation_suite_v07.sha256_bytes(b"ndabi")
        second = validation_suite_v07.sha256_bytes(b"ndabi")
        self.assertEqual(first, second)
        self.assertEqual(len(first), 64)


if __name__ == "__main__":
    unittest.main()
