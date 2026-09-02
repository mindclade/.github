#!/usr/bin/env python3
"""Resolve fixed required-workflow profiles and review evidence."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import sys
import urllib.error
import urllib.parse
import urllib.request
from collections.abc import Callable
from pathlib import Path
from typing import Any

SHA = re.compile(r"^[0-9a-f]{40}$")
REPOSITORY = re.compile(r"^mindclade/[A-Za-z0-9._-]+$")
COMMENT = re.compile(
    r"^<!-- founder-pr-bypass:v1 -->\n"
    r"head-sha: ([0-9a-f]{40})\n"
    r"reason: (\S(?:.{0,498}\S)?)$"
)
ALLOWED_EVENTS = frozenset({"pull_request", "pull_request_review", "merge_group"})


def canonical_json(value: Any) -> str:
    return json.dumps(value, ensure_ascii=True, separators=(",", ":"), sort_keys=True)


def digest(value: Any) -> str:
    return "sha256:" + hashlib.sha256(canonical_json(value).encode("utf-8")).hexdigest()


def load_profiles(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict) or value.get("kind") != "RequiredWorkflowProfiles":
        raise ValueError("generated profile catalog has an invalid root")
    generated = value.get("generated")
    if not isinstance(generated, dict) or not re.fullmatch(
        r"sha256:[0-9a-f]{64}", str(generated.get("profile_digest", ""))
    ):
        raise ValueError("generated profile catalog is missing its digest binding")
    return value


def write_outputs(path: Path, values: dict[str, str]) -> None:
    with path.open("a", encoding="utf-8") as output:
        for name, value in values.items():
            if "\n" in value or "\r" in value:
                raise ValueError(f"output {name} must be a single line")
            output.write(f"{name}={value}\n")


def plan(
    profiles: dict[str, Any], repository: str, event_name: str, source_revision: str
) -> dict[str, str]:
    if not REPOSITORY.fullmatch(repository):
        raise ValueError("repository must be an exact mindclade owner/name identity")
    if event_name not in ALLOWED_EVENTS:
        raise ValueError(f"unsupported required-workflow event: {event_name}")
    if not SHA.fullmatch(source_revision):
        raise ValueError("source revision must be a lowercase 40-character commit SHA")
    spec = profiles.get("spec")
    repositories = spec.get("repositories") if isinstance(spec, dict) else None
    definition = repositories.get(repository) if isinstance(repositories, dict) else None
    if not isinstance(definition, dict):
        raise ValueError(f"repository has no fixed required-workflow profile: {repository}")
    profile = definition.get("profile")
    event_class = "merge_group" if event_name == "merge_group" else "pull_request"
    review = ["review_policy"] if event_class == "pull_request" else []
    if profile == "nix-standard":
        affected = [*review, "nix_validation"]
        not_required = ["classify", "fork_checks", "dispatch", "buildkite_required"]
    elif profile == "buildkite-isolated":
        affected = [*review, "classify", "dispatch", "buildkite_required"]
        not_required = ["nix_validation"]
    else:
        raise ValueError(f"repository has an unsupported fixed profile: {repository}")
    if event_class == "merge_group":
        not_required = ["review_policy", *not_required]
    return {
        "profile": profile,
        "event_class": event_class,
        "affected_shards_json": canonical_json(affected),
        "not_required_shards_json": canonical_json(not_required),
        "policy_digest": profiles["generated"]["profile_digest"],
    }


class GitHubClient:
    def __init__(
        self,
        api_url: str,
        token: str,
        opener: Callable[..., Any] = urllib.request.urlopen,
    ) -> None:
        parsed = urllib.parse.urlparse(api_url)
        if parsed.scheme != "https" or not parsed.netloc or parsed.query or parsed.fragment:
            raise ValueError("GitHub API URL must be an absolute HTTPS origin")
        self._origin = f"{parsed.scheme}://{parsed.netloc}"
        self._base = api_url.rstrip("/")
        if not token:
            raise ValueError("review evaluation requires a read-only GitHub token")
        self._token = token
        self._opener = opener

    def _request(self, url: str) -> tuple[Any, str | None]:
        parsed = urllib.parse.urlparse(url)
        if f"{parsed.scheme}://{parsed.netloc}" != self._origin:
            raise RuntimeError("GitHub pagination attempted to leave the configured API origin")
        request = urllib.request.Request(
            url,
            headers={
                "Accept": "application/vnd.github+json",
                "Authorization": f"Bearer {self._token}",
                "X-GitHub-Api-Version": "2022-11-28",
                "User-Agent": "mindclade-required-workflow/v1",
            },
        )
        try:
            with self._opener(request, timeout=15) as response:
                payload = json.load(response)
                link = response.headers.get("Link")
        except urllib.error.HTTPError as error:
            raise RuntimeError(f"GitHub API returned HTTP {error.code}") from error
        except urllib.error.URLError as error:
            raise RuntimeError("GitHub API request failed") from error
        return payload, link

    @staticmethod
    def _next_link(value: str | None) -> str | None:
        if not value:
            return None
        for entry in value.split(","):
            match = re.fullmatch(r'\s*<([^>]+)>;\s*rel="([^"]+)"\s*', entry)
            if match and match.group(2) == "next":
                return match.group(1)
        return None

    def object(self, path: str) -> dict[str, Any]:
        payload, link = self._request(self._base + path)
        if link:
            raise RuntimeError("object response unexpectedly requested pagination")
        if not isinstance(payload, dict):
            raise RuntimeError("GitHub API object response has an invalid shape")
        return payload

    def pages(self, path: str, maximum_pages: int = 10) -> list[dict[str, Any]]:
        url: str | None = self._base + path
        values: list[dict[str, Any]] = []
        for _ in range(maximum_pages):
            if url is None:
                return values
            payload, link = self._request(url)
            if not isinstance(payload, list) or any(not isinstance(item, dict) for item in payload):
                raise RuntimeError("GitHub API list response has an invalid shape")
            values.extend(payload)
            url = self._next_link(link)
        if url is not None:
            raise RuntimeError("GitHub API pagination exceeded its fixed bound")
        return values


def _login(value: Any) -> str | None:
    login = value.get("login") if isinstance(value, dict) else None
    return login if isinstance(login, str) and login else None


def _normal_approvals(reviews: list[dict[str, Any]], author: str, expected_head: str) -> list[str]:
    latest: dict[str, tuple[int, str, str, str | None]] = {}
    for review in reviews:
        login = _login(review.get("user"))
        state = review.get("state")
        review_id = review.get("id")
        commit_id = review.get("commit_id")
        if login is None or not isinstance(state, str) or not isinstance(review_id, int):
            continue
        folded = login.casefold()
        previous = latest.get(folded)
        if previous is None or review_id > previous[0]:
            latest[folded] = (
                review_id,
                login,
                state.upper(),
                commit_id if isinstance(commit_id, str) else None,
            )
    return sorted(
        value[1]
        for folded, value in latest.items()
        if (folded != author.casefold() and value[2] == "APPROVED" and value[3] == expected_head)
    )


def _bypass_comment(
    comments: list[dict[str, Any]], allowed_accounts: list[str], expected_head: str
) -> dict[str, Any] | None:
    allowed = {account.casefold() for account in allowed_accounts}
    candidates: list[dict[str, Any]] = []
    for comment in comments:
        login = _login(comment.get("user"))
        body = comment.get("body")
        if login is None or login.casefold() not in allowed or not isinstance(body, str):
            continue
        match = COMMENT.fullmatch(body.replace("\r\n", "\n").strip())
        if match is None or match.group(1) != expected_head:
            continue
        comment_id = comment.get("id")
        url = comment.get("html_url")
        if not isinstance(comment_id, int) or not isinstance(url, str):
            continue
        candidates.append(
            {
                "author": login,
                "comment_id": comment_id,
                "comment_url": url,
                "head_sha": match.group(1),
                "reason": match.group(2),
            }
        )
    return max(candidates, key=lambda item: item["comment_id"], default=None)


def evaluate_review(
    profiles: dict[str, Any],
    repository: str,
    pull_request_number: int,
    expected_head: str,
    client: GitHubClient,
) -> dict[str, Any]:
    plan(profiles, repository, "pull_request", expected_head)
    pull = client.object(f"/repos/{repository}/pulls/{pull_request_number}")
    live_head = pull.get("head", {}).get("sha") if isinstance(pull.get("head"), dict) else None
    if live_head != expected_head:
        raise RuntimeError("live pull-request head does not match the evaluated source revision")
    author = _login(pull.get("user"))
    if author is None:
        raise RuntimeError("pull-request author is missing")
    labels = sorted(
        label["name"]
        for label in pull.get("labels", [])
        if isinstance(label, dict) and isinstance(label.get("name"), str)
    )
    reviews = client.pages(f"/repos/{repository}/pulls/{pull_request_number}/reviews?per_page=100")
    comments = client.pages(
        f"/repos/{repository}/issues/{pull_request_number}/comments?per_page=100"
    )
    bypass_policy = profiles["spec"]["founder_pr_bypass"]
    approvals = _normal_approvals(reviews, author, expected_head)
    minimum = bypass_policy["minimum_normal_approvals"]
    quorum = len(approvals) >= minimum
    bypass = _bypass_comment(comments, bypass_policy["accounts"], expected_head)
    bypass_satisfied = bypass_policy["label"] in labels and bypass is not None
    if quorum:
        decision, reason_code = "approved", "NORMAL_REVIEW_QUORUM"
    elif bypass_satisfied:
        decision, reason_code = "bypassed", "FOUNDER_PR_BYPASS_VALID"
    else:
        decision, reason_code = "denied", "REVIEW_POLICY_UNSATISFIED"
    evidence_without_digest = {
        "api_version": "ci.mindclade.dev/v1",
        "kind": "RequiredWorkflowReviewEvidence",
        "repository": repository,
        "pull_request_number": pull_request_number,
        "source_revision": expected_head,
        "policy_digest": profiles["generated"]["profile_digest"],
        "decision": decision,
        "reason_code": reason_code,
        "normal_review": {
            "approved_logins": approvals,
            "minimum_approvals": minimum,
            "pull_request_author": author,
            "satisfied": quorum,
        },
        "founder_bypass": {
            "evidence": bypass,
            "identity_authority": bypass_policy["identity_authority"],
            "label": bypass_policy["label"],
            "label_present": bypass_policy["label"] in labels,
            "marker": bypass_policy["marker"],
            "principal_id": bypass_policy["principal_id"],
            "satisfied": bypass_satisfied,
        },
    }
    return {
        **evidence_without_digest,
        "evidence_digest": digest(evidence_without_digest),
    }


def parser() -> argparse.ArgumentParser:
    cli = argparse.ArgumentParser(description=__doc__)
    cli.add_argument("mode", choices=("plan", "review"))
    cli.add_argument("--profiles", type=Path, required=True)
    cli.add_argument("--repository", required=True)
    cli.add_argument("--event-name", required=True)
    cli.add_argument("--source-revision", required=True)
    cli.add_argument("--pull-request-number", default="")
    cli.add_argument("--api-url", default="https://api.github.com")
    cli.add_argument("--github-output", type=Path, required=True)
    cli.add_argument("--evidence-path", type=Path, required=True)
    return cli


def main(argv: list[str] | None = None) -> int:
    args = parser().parse_args(argv)
    try:
        profiles = load_profiles(args.profiles)
        planned = plan(profiles, args.repository, args.event_name, args.source_revision)
        if args.mode == "plan":
            write_outputs(args.github_output, planned)
            return 0
        if args.event_name not in {"pull_request", "pull_request_review"}:
            raise ValueError("review mode is restricted to pull-request events")
        if not re.fullmatch(r"[1-9][0-9]*", args.pull_request_number):
            raise ValueError("review mode requires a canonical pull-request number")
        client = GitHubClient(args.api_url, os.environ.get("GITHUB_TOKEN", ""))
        evidence = evaluate_review(
            profiles,
            args.repository,
            int(args.pull_request_number),
            args.source_revision,
            client,
        )
        args.evidence_path.write_text(
            pretty := json.dumps(evidence, indent=2, sort_keys=True) + "\n"
        )
        if not pretty:
            raise AssertionError("unreachable empty evidence")
        write_outputs(
            args.github_output,
            {
                **planned,
                "decision": evidence["decision"],
                "reason_code": evidence["reason_code"],
                "evidence_path": str(args.evidence_path),
            },
        )
        return 0
    except (OSError, ValueError, RuntimeError, json.JSONDecodeError) as error:
        print(str(error), file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
