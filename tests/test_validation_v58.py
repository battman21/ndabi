import unittest

import validation_suite_v58


class CanonicalSupabaseCampaignTests(unittest.TestCase):
    def test_campaign_uses_five_processes_and_pinned_images(self):
        self.assertEqual(validation_suite_v58.PROCESS_COUNT, 5)
        self.assertIn("@sha256:", validation_suite_v58.POSTGRES_IMAGE)
        self.assertIn("@sha256:", validation_suite_v58.POSTGREST_IMAGE)

    def test_source_custody_covers_the_canonical_protocol_and_adapter(self):
        paths = set(validation_suite_v58.SOURCE_PATHS)
        self.assertIn("crates/ndabi-protocol/src/lib.rs", paths)
        self.assertIn("crates/ndabi-postgres-v1/src/lib.rs", paths)
        self.assertIn("validation_suite_v58.py", paths)

    def test_unsigned_tokens_declare_no_signature_algorithm(self):
        encoded = validation_suite_v58.unsigned_token()
        header = encoded.split(".", 1)[0]
        padding = "=" * (-len(header) % 4)
        decoded = validation_suite_v58.base64.urlsafe_b64decode(header + padding)
        self.assertEqual(validation_suite_v58.json.loads(decoded)["alg"], "none")


if __name__ == "__main__":
    unittest.main()
