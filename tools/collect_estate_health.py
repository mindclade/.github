#!/usr/bin/env python3
"""Collect and publish one canonical, create-only estate health snapshot."""

from __future__ import annotations

import argparse
import base64
import datetime as dt
import hashlib
import json
import os
import re
import subprocess
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid
from pathlib import Path
from typing import Any

API = "https://api.github.com"
REPOSITORIES = {
    "mindclade/.github": "nix-standard",
    "mindclade/bootstrap": "nix-standard",
    "mindclade/estate-ci": "buildkite-isolated",
    "mindclade/github-config": "nix-standard",
    "mindclade/gitops": "nix-standard",
    "mindclade/infrastructure-live": "nix-standard",
    "mindclade/mindclade": "buildkite-isolated",
}
DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
SHA = re.compile(r"^[0-9a-f]{40}$")
BUCKET = re.compile(r"^[a-z0-9][a-z0-9._-]{4,61}[a-z0-9]$")


def canonical(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()


def b64url(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).decode().rstrip("=")


def request_json(request: urllib.request.Request, maximum: int = 2 * 1024 * 1024) -> tuple[Any, Any]:
    with urllib.request.urlopen(request, timeout=20) as response:
        raw = response.read(maximum + 1)
        if len(raw) > maximum:
            raise RuntimeError("remote response exceeds its fixed bound")
        return json.loads(raw), response.headers


def mint_installation_token(app_id: int, installation_id: int, private_key: Path) -> str:
    now = int(time.time())
    header = b64url(canonical({"alg": "RS256", "typ": "JWT"}))
    payload = b64url(canonical({"iat": now - 60, "exp": now + 540, "iss": str(app_id)}))
    signing_input = f"{header}.{payload}".encode()
    signature = subprocess.run(
        ["openssl", "dgst", "-sha256", "-sign", str(private_key)],
        input=signing_input,
        check=True,
        capture_output=True,
    ).stdout
    jwt = f"{header}.{payload}.{b64url(signature)}"
    request = urllib.request.Request(
        f"{API}/app/installations/{installation_id}/access_tokens",
        data=b"{}",
        method="POST",
        headers={
            "Accept": "application/vnd.github+json",
            "Authorization": f"Bearer {jwt}",
            "Content-Type": "application/json",
            "X-GitHub-Api-Version": "2026-03-10",
        },
    )
    result, _ = request_json(request)
    token = result.get("token", "")
    if not isinstance(token, str) or len(token) < 20:
        raise RuntimeError("GitHub App installation token response is invalid")
    return token


def github_get(path: str, token: str) -> tuple[Any, Any]:
    if not path.startswith("/repos/mindclade/"):
        raise RuntimeError("GitHub request escaped the estate repository boundary")
    request = urllib.request.Request(
        API + path,
        headers={
            "Accept": "application/vnd.github+json",
            "Authorization": f"Bearer {token}",
            "X-GitHub-Api-Version": "2026-03-10",
        },
    )
    return request_json(request)


def parse_time(value: str | None) -> dt.datetime | None:
    if not value:
        return None
    return dt.datetime.fromisoformat(value.replace("Z", "+00:00"))


def durations(check: dict[str, Any]) -> tuple[int, int]:
    created = parse_time(check.get("created_at"))
    started = parse_time(check.get("started_at"))
    completed = parse_time(check.get("completed_at"))
    queue = max(0, int((started - created).total_seconds())) if created and started else 0
    execution = max(0, int((completed - started).total_seconds())) if started and completed else 0
    return queue, execution


def repository_health(repository: str, profile: str, token: str, evidence_digest: str, observed_at: str) -> dict[str, Any]:
    branch, _ = github_get(f"/repos/{repository}/branches/main", token)
    head_sha = branch.get("commit", {}).get("sha", "")
    if not SHA.fullmatch(head_sha):
        raise RuntimeError(f"{repository} returned an invalid main SHA")
    checks, _ = github_get(f"/repos/{repository}/commits/{head_sha}/check-runs?per_page=100", token)
    runs = checks.get("check_runs", [])
    if not isinstance(runs, list) or len(runs) > 100:
        raise RuntimeError(f"{repository} check-run inventory exceeds its fixed bound")
    required = [item for item in runs if item.get("name") in {"required", "Pull request / required"}]
    required.sort(key=lambda item: item.get("started_at") or item.get("created_at") or "", reverse=True)
    selected = required[0] if required else {}
    if not branch.get("protected", False):
        status, failure = "blocked", "main-not-protected"
    elif not selected:
        status, failure = "unknown", "required-check-missing"
    elif selected.get("status") != "completed":
        status, failure = "blocked", "required-check-pending"
    elif selected.get("conclusion") == "success":
        status, failure = "success", "none"
    else:
        status, failure = "failure", "required-check-failure"
    queue, execution = durations(selected)
    return {
        "repository": repository,
        "profile": profile,
        "head_sha": head_sha,
        "last_green_sha": head_sha if status == "success" else "0" * 40,
        "required_check_status": status,
        "queue_seconds": queue,
        "execution_seconds": execution,
        "failure_class": failure,
        "cache_hit_basis_points": 0,
        "evidence_digest": evidence_digest,
        "observed_at": observed_at,
    }


def seal_snapshot(protected_main_sha: str, evidence_digest: str, token: str) -> dict[str, Any]:
    if not SHA.fullmatch(protected_main_sha) or not DIGEST.fullmatch(evidence_digest):
        raise RuntimeError("snapshot bindings are invalid")
    observed_at = dt.datetime.now(dt.timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")
    repositories = [
        repository_health(repository, profile, token, evidence_digest, observed_at)
        for repository, profile in sorted(REPOSITORIES.items())
    ]
    summary = {name: sum(item["required_check_status"] == status for item in repositories) for name, status in (
        ("healthy", "success"), ("degraded", "failure"), ("blocked", "blocked"), ("unknown", "unknown")
    )}
    snapshot = {
        "schema_version": "estate.health/v1",
        "snapshot_id": str(uuid.uuid4()),
        "observed_at": observed_at,
        "protected_main_sha": protected_main_sha,
        "summary": summary,
        "repositories": repositories,
        "digest": "",
    }
    snapshot["digest"] = "sha256:" + hashlib.sha256(canonical(snapshot)).hexdigest()
    return snapshot


def upload_snapshot(bucket: str, snapshot: dict[str, Any], access_token: str) -> str:
    if not BUCKET.fullmatch(bucket) or len(access_token) < 20:
        raise RuntimeError("GCS publication inputs are invalid")
    object_name = f"health/snapshots/{snapshot['observed_at'].replace(':', '').replace('-', '')}-{snapshot['snapshot_id']}.json"
    query = urllib.parse.urlencode({"uploadType": "media", "ifGenerationMatch": "0", "name": object_name})
    request = urllib.request.Request(
        f"https://storage.googleapis.com/upload/storage/v1/b/{urllib.parse.quote(bucket, safe='')}/o?{query}",
        data=canonical(snapshot),
        method="POST",
        headers={"Authorization": f"Bearer {access_token}", "Content-Type": "application/json"},
    )
    try:
        with urllib.request.urlopen(request, timeout=20) as response:
            if response.status not in {200, 201}:
                raise RuntimeError(f"GCS create returned HTTP {response.status}")
    except urllib.error.HTTPError as error:
        if error.code in {409, 412}:
            raise RuntimeError("create-only health snapshot already exists") from error
        raise
    return object_name


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--app-id", type=int, required=True)
    parser.add_argument("--installation-id", type=int, required=True)
    parser.add_argument("--private-key-file", type=Path, required=True)
    parser.add_argument("--protected-main-sha", required=True)
    parser.add_argument("--evidence-digest", required=True)
    parser.add_argument("--health-bucket", required=True)
    args = parser.parse_args()
    token = mint_installation_token(args.app_id, args.installation_id, args.private_key_file)
    snapshot = seal_snapshot(args.protected_main_sha, args.evidence_digest, token)
    object_name = upload_snapshot(args.health_bucket, snapshot, os.environ.get("GCS_ACCESS_TOKEN", ""))
    print(json.dumps({"object": object_name, "digest": snapshot["digest"]}, separators=(",", ":")))


if __name__ == "__main__":
    main()
