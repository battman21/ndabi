import unittest

import validation_suite_v52


class ValidationSuiteV52Tests(unittest.TestCase):
    def test_result_root_is_separate(self):
        self.assertEqual(validation_suite_v52.campaign.RESULT_ROOT.name, "v52")

    def test_campaign_keeps_five_processes(self):
        self.assertEqual(validation_suite_v52.campaign.PROCESS_COUNT, 5)


if __name__ == "__main__":
    unittest.main()
