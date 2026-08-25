import importlib.util
import pathlib
import sys
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
SPEC = importlib.util.spec_from_file_location("token_canary_v02", ROOT / "token_canary_v02.py")
CANARY = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(CANARY)


class TokenCanaryV02Tests(unittest.TestCase):
    def test_fixture_has_exact_registered_selection(self):
        selected = CANARY.selected_records()
        self.assertEqual(tuple(item["identifier"] for item in selected), CANARY.MATCH_IDS)
        self.assertTrue(all(item["owner"] == 7 and item["score"] >= 250 for item in selected))
        excluded = [item for item in CANARY.records() if item["identifier"] not in CANARY.MATCH_IDS]
        self.assertTrue(all(item["owner"] != 7 or item["score"] < 250 for item in excluded))

    def test_human_prompt_is_byte_identical_across_surfaces(self):
        for prompt in CANARY.prompts().values():
            self.assertEqual(prompt.count(CANARY.HUMAN_PROMPT), 1)

    def test_answer_accepts_presentation_spacing_only(self):
        self.assertEqual(
            CANARY.answer_identifiers("17, 49, 81, 113, 145, 177, 209, 241"),
            list(CANARY.MATCH_IDS),
        )
        self.assertNotEqual(
            CANARY.answer_identifiers("17,49,81,113,145,177,209"),
            list(CANARY.MATCH_IDS),
        )

    def test_semantic_surface_reduces_submitted_bytes(self):
        prompts = CANARY.prompts()
        reduction = 1 - len(prompts["selected_semantic"].encode()) / len(
            prompts["full_verbose"].encode()
        )
        self.assertGreaterEqual(reduction, 0.70)

    def test_summary_uses_medians(self):
        runs = [
            {
                "answer_exact": True,
                "submitted_prompt_bytes": 100,
                "elapsed_ms": 30.0,
                "usage": {
                    "input_tokens": 90,
                    "uncached_input_tokens": 20,
                    "cached_input_tokens": 70,
                    "output_tokens": 3,
                },
            },
            {
                "answer_exact": True,
                "submitted_prompt_bytes": 100,
                "elapsed_ms": 10.0,
                "usage": {
                    "input_tokens": 110,
                    "uncached_input_tokens": 30,
                    "cached_input_tokens": 80,
                    "output_tokens": 5,
                },
            },
        ]
        summary = CANARY.summarise_surface("selected_semantic", runs)
        self.assertEqual(summary["median_input_tokens"], 100)
        self.assertEqual(summary["median_elapsed_ms"], 20.0)
        self.assertEqual(summary["cold_uncached_input_tokens"], 20)
        self.assertEqual(summary["warm_uncached_input_tokens"], 30)
        self.assertEqual(summary["warm_cached_input_tokens"], 80)


if __name__ == "__main__":
    unittest.main()
