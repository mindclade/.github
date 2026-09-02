import hashlib
import importlib.util
import json
import unittest
from pathlib import Path

MODULE_PATH = Path(__file__).parents[1] / "tools" / "collect_estate_health.py"
SPEC = importlib.util.spec_from_file_location("collect_estate_health", MODULE_PATH)
collector = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
SPEC.loader.exec_module(collector)


class EstateHealthContractTest(unittest.TestCase):
    def test_canonical_json_is_sorted_and_compact(self):
        self.assertEqual(collector.canonical({"b": 2, "a": 1}), b'{"a":1,"b":2}')

    def test_snapshot_digest_binds_empty_digest_material(self):
        old = collector.repository_health
        collector.repository_health = lambda repository, profile, token, evidence, observed: {
            "repository": repository, "profile": profile, "head_sha": "a" * 40,
            "last_green_sha": "a" * 40, "required_check_status": "success",
            "queue_seconds": 0, "execution_seconds": 0, "failure_class": "none",
            "cache_hit_basis_points": 0, "evidence_digest": evidence, "observed_at": observed,
        }
        try:
            snapshot = collector.seal_snapshot("b" * 40, "sha256:" + "c" * 64, "token")
        finally:
            collector.repository_health = old
        digest = snapshot["digest"]
        snapshot["digest"] = ""
        expected = "sha256:" + hashlib.sha256(collector.canonical(snapshot)).hexdigest()
        self.assertEqual(digest, expected)
        self.assertEqual(len(json.loads(collector.canonical(snapshot))["repositories"]), 7)


if __name__ == "__main__":
    unittest.main()
