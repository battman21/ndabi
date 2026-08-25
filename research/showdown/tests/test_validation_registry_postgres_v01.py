import copy
import hashlib
import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

import validation_suite_registry_postgres_v01 as campaign


class RegisteredPostgresValidationTests(unittest.TestCase):
    def report(self) -> dict:
        identifiers = (1, 2)
        result = campaign.expected_result(identifiers)
        report = {
            "campaign": campaign.CAMPAIGN,
            "mode": "service",
            "registered_profile": campaign.REGISTERED_PROFILE,
            "registry_digest": "ab" * 32,
            "request_bytes": 160,
            "result_rows": len(identifiers),
            "result_bytes": len(result),
            "result_sha256": hashlib.sha256(result).hexdigest(),
        }
        report.update({field: True for field in campaign.TRUE_FIELDS})
        return report

    def test_validator_accepts_the_complete_registered_report(self):
        campaign.validate_report(self.report(), "service", (1, 2))

    def test_validator_refuses_any_disabled_security_gate(self):
        for field in campaign.TRUE_FIELDS:
            with self.subTest(field=field):
                report = copy.deepcopy(self.report())
                report[field] = False
                with self.assertRaises(ValueError):
                    campaign.validate_report(report, "service", (1, 2))

    def test_validator_refuses_legacy_profile_identity(self):
        report = self.report()
        report["registered_profile"] = "0x50471001"
        with self.assertRaises(ValueError):
            campaign.validate_report(report, "service", (1, 2))


if __name__ == "__main__":
    unittest.main()
