import importlib.util
import pathlib
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("token_canary", ROOT / "token_canary.py")
TOKEN_CANARY = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(TOKEN_CANARY)


class TokenCanaryTests(unittest.TestCase):
    def test_claude_usage_includes_cache_components(self):
        documents = [
            {
                "result": "17|7|250|24",
                "usage": {
                    "input_tokens": 10,
                    "cache_creation_input_tokens": 20,
                    "cache_read_input_tokens": 30,
                    "output_tokens": 5,
                },
            }
        ]
        self.assertEqual(
            TOKEN_CANARY.usage_from_documents(documents),
            {
                "input_tokens": 60,
                "uncached_input_tokens": 30,
                "cached_input_tokens": 30,
                "output_tokens": 5,
            },
        )

    def test_codex_usage_subtracts_cached_input(self):
        documents = [
            {
                "type": "turn.completed",
                "usage": {
                    "input_tokens": 100,
                    "cached_input_tokens": 60,
                    "output_tokens": 7,
                },
            }
        ]
        self.assertEqual(
            TOKEN_CANARY.usage_from_documents(documents)["uncached_input_tokens"],
            40,
        )

    def test_agent_message_requires_the_exact_answer(self):
        documents = [
            {
                "type": "item.completed",
                "item": {"type": "agent_message", "text": "17|7|250|24"},
            }
        ]
        self.assertEqual(
            TOKEN_CANARY.answer_from_documents("codex", documents),
            TOKEN_CANARY.EXPECTED,
        )

    def test_grok_json_can_follow_log_output(self):
        documents = TOKEN_CANARY.parse_json_documents(
            'warning before output\n{\n  "text": "17|7|250|24",\n  "stopReason": "EndTurn"\n}\n'
        )
        self.assertEqual(
            TOKEN_CANARY.answer_from_documents("grok", documents),
            TOKEN_CANARY.EXPECTED,
        )


if __name__ == "__main__":
    unittest.main()
