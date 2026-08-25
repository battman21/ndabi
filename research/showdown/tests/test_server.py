import importlib.util
import json
import tempfile
import unittest
from pathlib import Path
from unittest import mock


MODULE_PATH = Path(__file__).resolve().parents[1] / "server.py"
SPEC = importlib.util.spec_from_file_location("ndabi_showdown_server", MODULE_PATH)
SERVER = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
SPEC.loader.exec_module(SERVER)


class ConfigurationTests(unittest.TestCase):
    def test_accepts_the_default_configuration(self):
        self.assertEqual(
            SERVER.validate_config(SERVER.DEFAULT_CONFIG), SERVER.DEFAULT_CONFIG
        )

    def test_refuses_unknown_fields(self):
        with self.assertRaisesRegex(ValueError, "unknown or missing"):
            SERVER.validate_config(
                {"rows": 4096, "iterations": 2000, "warmup": 100, "shell": "id"}
            )

    def test_refuses_boolean_numbers(self):
        with self.assertRaisesRegex(ValueError, "rows must be an integer"):
            SERVER.validate_config(
                {"rows": True, "iterations": 2000, "warmup": 100}
            )

    def test_refuses_out_of_range_work(self):
        with self.assertRaisesRegex(ValueError, "iterations"):
            SERVER.validate_config(
                {"rows": 4096, "iterations": 50001, "warmup": 100}
            )

    def test_refuses_unbalanced_iteration_count(self):
        with self.assertRaisesRegex(ValueError, "divisible by forty"):
            SERVER.validate_config(
                {"rows": 4096, "iterations": 22, "warmup": 100}
            )

    def test_missing_token_evidence_is_explicit(self):
        with tempfile.TemporaryDirectory() as directory:
            missing = Path(directory) / "absent.json"
            with mock.patch.object(SERVER, "TOKEN_RESULT", missing):
                self.assertEqual(SERVER.load_token_evidence()["status"], "unavailable")

    def test_token_evidence_requires_the_known_schema(self):
        with tempfile.TemporaryDirectory() as directory:
            result = Path(directory) / "token.json"
            result.write_text(json.dumps({"schema": "wrong"}), encoding="utf-8")
            with mock.patch.object(SERVER, "TOKEN_RESULT", result):
                with self.assertRaisesRegex(RuntimeError, "unknown result schema"):
                    SERVER.load_token_evidence()

    def test_validation_suite_requires_the_known_schema(self):
        with tempfile.TemporaryDirectory() as directory:
            result = Path(directory) / "validation.json"
            result.write_text(json.dumps({"schema": "wrong"}), encoding="utf-8")
            with mock.patch.object(SERVER, "VALIDATION_RESULT", result):
                with self.assertRaisesRegex(RuntimeError, "unknown result schema"):
                    SERVER.load_validation_suite()

    def test_missing_v06_validation_is_explicit(self):
        with tempfile.TemporaryDirectory() as directory:
            missing = Path(directory) / "absent.json"
            with mock.patch.object(SERVER, "V06_VALIDATION_RESULT", missing):
                self.assertEqual(
                    SERVER.load_v06_validation_suite()["status"], "unavailable"
                )

    def test_v06_validation_requires_the_known_schema(self):
        with tempfile.TemporaryDirectory() as directory:
            result = Path(directory) / "validation.json"
            result.write_text(json.dumps({"schema": "wrong"}), encoding="utf-8")
            with mock.patch.object(SERVER, "V06_VALIDATION_RESULT", result):
                with self.assertRaisesRegex(RuntimeError, "unknown result schema"):
                    SERVER.load_v06_validation_suite()

    def test_missing_v08_campaign_is_explicit(self):
        with tempfile.TemporaryDirectory() as directory:
            missing = Path(directory) / "absent.json"
            with mock.patch.object(SERVER, "V08_VALIDATION_RESULT", missing):
                self.assertEqual(
                    SERVER.load_v08_validation_suite()["status"], "unavailable"
                )

    def test_v08_campaign_requires_the_known_schema(self):
        with tempfile.TemporaryDirectory() as directory:
            result = Path(directory) / "campaign.json"
            result.write_text(json.dumps({"schema": "wrong"}), encoding="utf-8")
            with mock.patch.object(SERVER, "V08_VALIDATION_RESULT", result):
                with self.assertRaisesRegex(RuntimeError, "unknown result schema"):
                    SERVER.load_v08_validation_suite()

    def test_missing_v09_campaign_is_explicit(self):
        with tempfile.TemporaryDirectory() as directory:
            missing = Path(directory) / "absent.json"
            with mock.patch.object(SERVER, "V09_VALIDATION_RESULT", missing):
                self.assertEqual(
                    SERVER.load_v09_validation_suite()["status"], "unavailable"
                )

    def test_v09_campaign_requires_the_known_schema(self):
        with tempfile.TemporaryDirectory() as directory:
            result = Path(directory) / "campaign.json"
            result.write_text(json.dumps({"schema": "wrong"}), encoding="utf-8")
            with mock.patch.object(SERVER, "V09_VALIDATION_RESULT", result):
                with self.assertRaisesRegex(RuntimeError, "unknown result schema"):
                    SERVER.load_v09_validation_suite()


if __name__ == "__main__":
    unittest.main()
