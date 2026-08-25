import unittest

import validation_suite_v49


class ValidationSuiteV49Tests(unittest.TestCase):
    def test_result_root_is_separate(self):
        self.assertEqual(validation_suite_v49.campaign.RESULT_ROOT.name, "v49")

    def test_campaign_keeps_five_processes(self):
        self.assertEqual(validation_suite_v49.campaign.PROCESS_COUNT, 5)


if __name__ == "__main__":
    unittest.main()
