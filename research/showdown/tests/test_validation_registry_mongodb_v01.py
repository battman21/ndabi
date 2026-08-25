import copy
import hashlib
import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

import validation_suite_registry_mongodb_v01 as campaign


class RegisteredMongoDbValidationTests(unittest.TestCase):
    def report(self) -> dict:
        result = campaign.expected_result()
        report = {
            "campaign": campaign.CAMPAIGN,
            "registered_profile": campaign.REGISTERED_PROFILE,
            "registry_digest": "cd" * 32,
            "request_bytes": 160,
            "response_bytes": len(result),
            "response_rows": 128,
            "result_sha256": hashlib.sha256(result).hexdigest(),
            "find_commands": 1,
            "get_more_commands": 0,
        }
        report.update({field: True for field in campaign.TRUE_FIELDS})
        return report

    def test_validator_accepts_the_complete_registered_report(self):
        campaign.validate_report(self.report())

    def test_validator_refuses_any_disabled_security_gate(self):
        for field in campaign.TRUE_FIELDS:
            with self.subTest(field=field):
                report = copy.deepcopy(self.report())
                report[field] = False
                with self.assertRaises(ValueError):
                    campaign.validate_report(report)

    def test_validator_refuses_an_extra_database_command(self):
        report = self.report()
        report["find_commands"] = 2
        with self.assertRaises(ValueError):
            campaign.validate_report(report)


if __name__ == "__main__":
    unittest.main()
