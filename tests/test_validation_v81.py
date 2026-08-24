import unittest

import validation_suite_v80 as production
import validation_suite_v81 as duration_repair


class SupabaseProductionDurationRepairTests(unittest.TestCase):
    def tearDown(self):
        production.configure = duration_repair.BASE_CONFIGURE
        production.restore_legacy_campaign()

    def test_control_samples_have_a_duration_margin(self):
        self.assertEqual(duration_repair.SAMPLES_BY_ARM["postgrest_rpc"], 2_047)
        self.assertEqual(duration_repair.SAMPLES_BY_ARM["postgrest"], 255)
        self.assertEqual(duration_repair.SAMPLES_BY_ARM["native"], 8_191)
        self.assertEqual(duration_repair.SAMPLES_BY_ARM["ndabi"], 8_191)

    def test_configuration_uses_the_v81_identity_and_source(self):
        duration_repair.configure(build_binary=False)
        self.assertEqual(production.campaign.CAMPAIGN_NAME, duration_repair.CAMPAIGN_NAME)
        self.assertEqual(production.campaign.SAMPLES_BY_ARM, duration_repair.SAMPLES_BY_ARM)
        self.assertIn("validation_suite_v81.py", production.campaign.SOURCE_PATHS)
        self.assertEqual(production.ENTRYPOINT.name, "validation_suite_v81.py")
        self.assertEqual(
            production.campaign.SMOKE_RESULT_PATH.name,
            "performance-smoke-latest.json",
        )

    def test_functional_configuration_cannot_claim_performance(self):
        duration_repair.configure(build_binary=False, functional=True)
        self.assertEqual(production.campaign.MEASUREMENT_MODE, "functional-only")
        self.assertFalse(production.campaign.PERFORMANCE_GATES_ENFORCED)
        self.assertEqual(
            production.campaign.SAMPLES_BY_ARM,
            production.FUNCTIONAL_SAMPLES_BY_ARM,
        )


if __name__ == "__main__":
    unittest.main()
