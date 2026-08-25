import unittest

import validation_suite_v46


class ValidationSuiteV46Tests(unittest.TestCase):
    def test_campaign_has_five_processes(self):
        self.assertEqual(validation_suite_v46.PROCESS_COUNT, 5)

    def test_source_digest_binds_tls_and_session_sources(self):
        self.assertIn("src/bin/ndabi_v46.rs", validation_suite_v46.SOURCE_PATHS)
        self.assertIn("crates/ndabi-session/src/lib.rs", validation_suite_v46.SOURCE_PATHS)


if __name__ == "__main__":
    unittest.main()
