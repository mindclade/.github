# pyright: basic, reportArgumentType=false, reportIndexIssue=false
from __future__ import annotations

import importlib.util
import json
import unittest
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
MODULE_PATH = ROOT / ".github/actions/required-workflow-profile/required_workflow_profile.py"
SPEC = importlib.util.spec_from_file_location("required_workflow_profile", MODULE_PATH)
assert SPEC is not None and SPEC.loader is not None
profile = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(profile)
PROFILES = profile.load_profiles(
    ROOT / ".github/actions/required-workflow-profile/profiles.generated.json"
)
HEAD = "a" * 40


class StubClient:
    def __init__(
        self,
        *,
        author: str = "contributor",
        labels: list[str] | None = None,
        reviews: list[dict[str, Any]] | None = None,
        comments: list[dict[str, Any]] | None = None,
        head: str = HEAD,
    ) -> None:
        self.pull = {
            "head": {"sha": head},
            "labels": [{"name": label} for label in (labels or [])],
            "user": {"login": author},
        }
        self.reviews = reviews or []
        self.comments = comments or []

    def object(self, _path: str) -> dict[str, Any]:
        return self.pull

    def pages(self, path: str, maximum_pages: int = 10) -> list[dict[str, Any]]:
        del maximum_pages
        return self.reviews if "/reviews?" in path else self.comments


def review(review_id: int, login: str, state: str) -> dict[str, Any]:
    return {
        "commit_id": HEAD,
        "id": review_id,
        "state": state,
        "user": {"login": login},
    }


def bypass_comment(comment_id: int, login: str, head: str = HEAD) -> dict[str, Any]:
    return {
        "id": comment_id,
        "html_url": f"https://github.com/mindclade/bootstrap/pull/7#issuecomment-{comment_id}",
        "user": {"login": login},
        "body": (
            "<!-- founder-pr-bypass:v1 -->\n"
            f"head-sha: {head}\n"
            "reason: Restore estate governance while independent staffing is completed"
        ),
    }


class RequiredWorkflowProfileTest(unittest.TestCase):
    def test_plan_is_fixed_by_repository_and_event(self) -> None:
        nix = profile.plan(PROFILES, "mindclade/bootstrap", "pull_request", HEAD)
        self.assertEqual("nix-standard", nix["profile"])
        self.assertEqual(
            ["review_policy", "nix_validation"],
            json.loads(nix["affected_shards_json"]),
        )
        merge_group = profile.plan(PROFILES, "mindclade/mindclade", "merge_group", HEAD)
        self.assertEqual("buildkite-isolated", merge_group["profile"])
        self.assertIn("review_policy", json.loads(merge_group["not_required_shards_json"]))
        with self.assertRaisesRegex(ValueError, "no fixed required-workflow profile"):
            profile.plan(PROFILES, "mindclade/unregistered", "pull_request", HEAD)

    def test_two_latest_distinct_non_author_approvals_satisfy_normal_quorum(self) -> None:
        client = StubClient(
            reviews=[
                review(1, "reviewer-a", "APPROVED"),
                review(2, "reviewer-b", "APPROVED"),
                review(3, "contributor", "APPROVED"),
            ]
        )
        evidence = profile.evaluate_review(PROFILES, "mindclade/bootstrap", 7, HEAD, client)
        self.assertEqual("approved", evidence["decision"])
        self.assertEqual(["reviewer-a", "reviewer-b"], evidence["normal_review"]["approved_logins"])

        client.reviews.append(review(4, "reviewer-b", "CHANGES_REQUESTED"))
        denied = profile.evaluate_review(PROFILES, "mindclade/bootstrap", 7, HEAD, client)
        self.assertEqual("denied", denied["decision"])

        stale = review(5, "reviewer-b", "APPROVED")
        stale["commit_id"] = "b" * 40
        client.reviews[-1] = stale
        denied = profile.evaluate_review(PROFILES, "mindclade/bootstrap", 7, HEAD, client)
        self.assertEqual("denied", denied["decision"])

    def test_founder_can_bypass_own_pull_request_with_exact_head_evidence(self) -> None:
        client = StubClient(
            author="robpearc",
            labels=["founder-bypass"],
            comments=[bypass_comment(11, "robpearc")],
        )
        evidence = profile.evaluate_review(PROFILES, "mindclade/bootstrap", 7, HEAD, client)
        self.assertEqual("bypassed", evidence["decision"])
        self.assertEqual("FOUNDER_PR_BYPASS_VALID", evidence["reason_code"])
        self.assertEqual("founder-primary", evidence["founder_bypass"]["principal_id"])
        without_label = StubClient(author="robpearc", comments=client.comments)
        self.assertEqual(
            "denied",
            profile.evaluate_review(PROFILES, "mindclade/bootstrap", 7, HEAD, without_label)[
                "decision"
            ],
        )

    def test_new_commit_or_malformed_marker_invalidates_bypass(self) -> None:
        stale = StubClient(
            labels=["founder-bypass"],
            comments=[bypass_comment(11, "mindclade-founder", "b" * 40)],
        )
        self.assertEqual(
            "denied",
            profile.evaluate_review(PROFILES, "mindclade/bootstrap", 7, HEAD, stale)["decision"],
        )
        malformed = bypass_comment(12, "mindclade-founder")
        malformed["body"] += "\nunbounded: field"
        stale.comments = [malformed]
        self.assertEqual(
            "denied",
            profile.evaluate_review(PROFILES, "mindclade/bootstrap", 7, HEAD, stale)["decision"],
        )

    def test_live_head_mismatch_fails_closed(self) -> None:
        with self.assertRaisesRegex(RuntimeError, "live pull-request head"):
            profile.evaluate_review(
                PROFILES,
                "mindclade/bootstrap",
                7,
                HEAD,
                StubClient(head="b" * 40),
            )

    def test_evidence_digest_binds_the_complete_decision(self) -> None:
        evidence = profile.evaluate_review(
            PROFILES,
            "mindclade/bootstrap",
            7,
            HEAD,
            StubClient(reviews=[review(1, "a", "APPROVED"), review(2, "b", "APPROVED")]),
        )
        without_digest = {key: value for key, value in evidence.items() if key != "evidence_digest"}
        self.assertEqual(profile.digest(without_digest), evidence["evidence_digest"])


if __name__ == "__main__":
    unittest.main()
