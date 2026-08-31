from __future__ import annotations

import importlib.util
import sys
import unittest
from pathlib import Path


CAMPAIGN_DIR = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(CAMPAIGN_DIR))
SPEC = importlib.util.spec_from_file_location(
    "dynamic_supabase_rls_v01", CAMPAIGN_DIR / "dynamic_supabase_rls_v01.py"
)
campaign = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
SPEC.loader.exec_module(campaign)


def report(subject: str) -> dict[str, object]:
    ids = [2, 4, 6, 8] if subject == "user-a" else [1, 3, 5, 7]
    return {
        "subject": subject,
        "rows": [[identifier, subject] for identifier in ids],
        "result_digest": subject,
        "receipt_verified": True,
        "replay_refused": True,
        "mutation_refused": True,
        "principal_refused": True,
        "jwt_refusals": True,
    }


class DynamicSupabaseRlsCampaignTests(unittest.TestCase):
    def test_only_postgresql_startup_transitions_are_retryable(self) -> None:
        for detail in (
            "No such file or directory",
            "FATAL: the database system is starting up",
            "FATAL: the database system is shutting down",
        ):
            self.assertTrue(campaign.transient_seed_failure(detail))
        self.assertFalse(campaign.transient_seed_failure("permission denied"))

    def test_source_closure_contains_transitive_local_crates(self) -> None:
        closure = {
            path.relative_to(campaign.ROOT).as_posix()
            for path in campaign.source_closure()
        }
        self.assertIn(".cargo/config.toml", closure)
        self.assertIn("crates/ndabi-session/src/lib.rs", closure)
        self.assertIn("crates/ndabi-postgres-v1/src/lib.rs", closure)
        self.assertIn("crates/ndabi-protocol/src/registry_store.rs", closure)

    def test_fixture_container_name_is_one_dns_label(self) -> None:
        suffix = campaign.fixture_suffix(99_999, 9_999_999_999_999_999_999)
        self.assertLessEqual(len(f"ndabi-semantic-toxiproxy-{suffix}"), 63)

    def test_cleanup_requires_every_resource_to_be_absent(self) -> None:
        cleanup = {
            "containers_removed": True,
            "network_removed": True,
            "runner_pulled_proxy_image_removed": True,
            "temporary_binaries_removed": True,
        }
        self.assertTrue(campaign.cleanup_complete(cleanup))
        cleanup["temporary_binaries_removed"] = False
        self.assertFalse(campaign.cleanup_complete(cleanup))

    def test_distinct_exact_user_results_pass(self) -> None:
        result = campaign.evaluate_pair([report("user-a"), report("user-b")])
        self.assertTrue(result["accepted"])

    def test_cross_user_result_leak_fails(self) -> None:
        user_a = report("user-a")
        user_b = report("user-b")
        user_b["rows"] = user_a["rows"]
        result = campaign.evaluate_pair([user_a, user_b])
        self.assertFalse(result["accepted"])
        self.assertFalse(result["gates"]["exact_user_b"])

    def test_each_refusal_is_required(self) -> None:
        for gate in (
            "receipt_verified",
            "replay_refused",
            "mutation_refused",
            "principal_refused",
            "jwt_refusals",
        ):
            with self.subTest(gate=gate):
                user_a = report("user-a")
                user_b = report("user-b")
                user_a[gate] = False
                result = campaign.evaluate_pair([user_a, user_b])
                self.assertFalse(result["accepted"])
                self.assertFalse(result["gates"]["complete_refusals"])


if __name__ == "__main__":
    unittest.main()
