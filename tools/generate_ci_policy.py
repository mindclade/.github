#!/usr/bin/env python3
# pyright: basic, reportArgumentType=false, reportIndexIssue=false, reportOptionalMemberAccess=false
"""Generate the immutable estate Nix, Bazel, and required-workflow policy closure."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from pathlib import Path
from typing import Any

POLICY_SOURCE = Path("config/nix-bazel-policy.json")
PROFILE_SOURCE = Path("config/required-workflow-profiles.json")
EXTERNAL_LOCKS = (Path("flake.lock"), Path("MODULE.bazel.lock"))
NIX_POLICY = Path("generated/nix-bazel-policy.nix")
BAZELRC = Path("generated/bazelrc.common")
MANIFEST_DEFAULTS = Path("generated/toolchain-manifest.defaults.json")
PROFILE_CATALOG = Path(".github/actions/required-workflow-profile/profiles.generated.json")
POLICY_LOCK = Path("generated/nix-bazel-policy.lock.json")
GENERATED_ARTIFACTS = (NIX_POLICY, BAZELRC, MANIFEST_DEFAULTS, PROFILE_CATALOG)
SHA = re.compile(r"^[0-9a-f]{40}$")


def canonical_json(value: Any) -> str:
    return json.dumps(value, ensure_ascii=True, separators=(",", ":"), sort_keys=True)


def pretty_json(value: Any) -> str:
    return json.dumps(value, ensure_ascii=True, indent=2, sort_keys=True) + "\n"


def sha256_bytes(value: bytes) -> str:
    return "sha256:" + hashlib.sha256(value).hexdigest()


def sha256_json(value: Any) -> str:
    return sha256_bytes(canonical_json(value).encode("utf-8"))


def read_json(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError(f"{path}: document root must be an object")
    return value


def _validate_policy(policy: dict[str, Any]) -> None:
    if policy.get("api_version") != "ci.mindclade.dev/v1":
        raise ValueError("Nix/Bazel policy api_version must be ci.mindclade.dev/v1")
    if policy.get("kind") != "NixBazelPolicy":
        raise ValueError("Nix/Bazel policy kind must be NixBazelPolicy")
    spec = policy.get("spec")
    if not isinstance(spec, dict):
        raise ValueError("Nix/Bazel policy spec must be an object")
    systems = spec.get("systems")
    expected_systems = ["aarch64-darwin", "aarch64-linux", "x86_64-linux"]
    if systems != expected_systems:
        raise ValueError(f"systems must be exactly {expected_systems}")
    runners = spec.get("native_runners")
    if not isinstance(runners, list) or [entry.get("system") for entry in runners] != systems:
        raise ValueError("native_runners must cover each system once in canonical order")
    for entry in runners:
        if not isinstance(entry, dict) or not re.fullmatch(
            r"[0-9a-f]{64}", str(entry.get("installer_sha256", ""))
        ):
            raise ValueError("each native runner must declare an exact installer SHA-256")
    bazel = spec.get("bazel")
    if not isinstance(bazel, dict) or not isinstance(bazel.get("common_rc"), list):
        raise ValueError("bazel.common_rc must be an array")
    if any(not isinstance(line, str) or not line for line in bazel["common_rc"]):
        raise ValueError("bazel.common_rc lines must be nonempty strings")
    for tool_name in ("biome", "opa"):
        tool = spec.get("tools", {}).get(tool_name)
        targets = tool.get("targets") if isinstance(tool, dict) else None
        if not isinstance(targets, dict) or sorted(targets) != sorted(systems):
            raise ValueError(f"{tool_name} targets must cover every standard system")


def _validate_profiles(profiles: dict[str, Any]) -> None:
    if profiles.get("api_version") != "ci.mindclade.dev/v1":
        raise ValueError("profile api_version must be ci.mindclade.dev/v1")
    if profiles.get("kind") != "RequiredWorkflowProfiles":
        raise ValueError("profile kind must be RequiredWorkflowProfiles")
    spec = profiles.get("spec")
    repositories = spec.get("repositories") if isinstance(spec, dict) else None
    if not isinstance(repositories, dict) or not repositories:
        raise ValueError("profile catalog must declare repositories")
    allowed_profiles = {"nix-standard", "buildkite-isolated"}
    for repository, definition in repositories.items():
        if not re.fullmatch(r"mindclade/[A-Za-z0-9._-]+", repository):
            raise ValueError(f"invalid fixed repository identity: {repository}")
        if not isinstance(definition, dict) or definition.get("profile") not in allowed_profiles:
            raise ValueError(f"{repository}: invalid fixed profile")
        if set(definition) - {"profile", "documentation_roots"}:
            raise ValueError(f"{repository}: unsupported profile fields")
    bypass = spec.get("founder_pr_bypass")
    if not isinstance(bypass, dict):
        raise ValueError("founder_pr_bypass must be an object")
    accounts = bypass.get("accounts")
    if accounts != sorted(set(accounts or []), key=str.casefold) or len(accounts) != 2:
        raise ValueError("founder bypass accounts must be two sorted distinct accounts")
    authority = bypass.get("identity_authority")
    if not isinstance(authority, dict) or not SHA.fullmatch(str(authority.get("revision", ""))):
        raise ValueError("founder bypass identity authority must use an exact revision")
    if not re.fullmatch(r"[0-9a-f]{64}", str(authority.get("source_sha256", ""))):
        raise ValueError("founder bypass identity authority must bind the source digest")


def _existing_authority_revision(root: Path) -> str | None:
    path = root / POLICY_LOCK
    if not path.is_file():
        return None
    lock = read_json(path)
    authority = lock.get("authority")
    revision = authority.get("revision") if isinstance(authority, dict) else None
    if revision is not None and not SHA.fullmatch(str(revision)):
        raise ValueError(f"{POLICY_LOCK}: authority revision must be null or a full SHA")
    return revision


def render(root: Path, authority_revision: str | None) -> dict[Path, bytes]:
    if authority_revision is not None and not SHA.fullmatch(authority_revision):
        raise ValueError("authority revision must be a lowercase 40-character commit SHA")
    policy = read_json(root / POLICY_SOURCE)
    profiles = read_json(root / PROFILE_SOURCE)
    _validate_policy(policy)
    _validate_profiles(profiles)

    policy_digest = sha256_json(policy)
    profile_digest = sha256_json(profiles)
    policy_projection = {
        **policy,
        "generated": {
            "authority_repository": "mindclade/.github",
            "authority_revision": authority_revision,
            "policy_digest": policy_digest,
        },
    }
    nix = "# Generated by tools/generate_ci_policy.py. Do not edit.\n"
    nix += "builtins.fromJSON ''\n"
    nix += canonical_json(policy_projection) + "\n"
    nix += "''\n"

    spec = policy["spec"]
    bazelrc = (
        "# Generated by tools/generate_ci_policy.py. Do not edit.\n"
        + "\n".join(spec["bazel"]["common_rc"])
        + "\n"
    )
    lock_hashes = {
        path.as_posix(): sha256_bytes((root / path).read_bytes()) for path in EXTERNAL_LOCKS
    }
    manifest = {
        "api_version": "ci.mindclade.dev/v1",
        "kind": "ToolchainManifestDefaults",
        "generator": {
            "command": "python3 tools/generate_ci_policy.py generate",
            "source": POLICY_SOURCE.as_posix(),
        },
        "authority": {
            "policy_digest": policy_digest,
            "repository": "mindclade/.github",
            "revision": authority_revision,
        },
        "bazel": {
            "startup_jdk_major": spec["bazel"]["startup_jdk_major"],
            "version": spec["bazel"]["version"],
        },
        "locks": lock_hashes,
        "nixpkgs": spec["nixpkgs"],
        "supported_systems": spec["systems"],
    }
    profile_projection = {
        **profiles,
        "generated": {
            "authority_repository": "mindclade/.github",
            "authority_revision": authority_revision,
            "profile_digest": profile_digest,
        },
    }
    artifacts: dict[Path, bytes] = {
        NIX_POLICY: nix.encode("utf-8"),
        BAZELRC: bazelrc.encode("utf-8"),
        MANIFEST_DEFAULTS: pretty_json(manifest).encode("utf-8"),
        PROFILE_CATALOG: pretty_json(profile_projection).encode("utf-8"),
    }
    source_hashes = {
        path.as_posix(): sha256_bytes((root / path).read_bytes())
        for path in (POLICY_SOURCE, PROFILE_SOURCE, *EXTERNAL_LOCKS)
    }
    artifact_hashes = {
        path.as_posix(): sha256_bytes(contents)
        for path, contents in sorted(artifacts.items(), key=lambda item: item[0].as_posix())
    }
    lock_without_digest = {
        "api_version": "ci.mindclade.dev/v1",
        "kind": "GeneratedPolicyLock",
        "authority": {
            "repository": "mindclade/.github",
            "revision": authority_revision,
        },
        "artifacts": artifact_hashes,
        "sources": source_hashes,
    }
    lock = {**lock_without_digest, "contract_digest": sha256_json(lock_without_digest)}
    artifacts[POLICY_LOCK] = pretty_json(lock).encode("utf-8")
    return artifacts


def write(root: Path, authority_revision: str | None) -> None:
    for relative, contents in render(root, authority_revision).items():
        path = root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(contents)


def check(root: Path) -> list[str]:
    expected = render(root, _existing_authority_revision(root))
    errors: list[str] = []
    for relative, contents in expected.items():
        path = root / relative
        if not path.is_file():
            errors.append(f"missing generated artifact: {relative}")
        elif path.read_bytes() != contents:
            errors.append(f"generated artifact drift: {relative}")
    return errors


def parser() -> argparse.ArgumentParser:
    cli = argparse.ArgumentParser(description=__doc__)
    subparsers = cli.add_subparsers(dest="command", required=True)
    generate = subparsers.add_parser("generate")
    generate.add_argument("--root", type=Path, default=Path.cwd())
    generate.add_argument("--authority-revision")
    verify = subparsers.add_parser("check")
    verify.add_argument("--root", type=Path, default=Path.cwd())
    return cli


def main(argv: list[str] | None = None) -> int:
    args = parser().parse_args(argv)
    root = args.root.resolve()
    try:
        if args.command == "generate":
            write(root, args.authority_revision)
            return 0
        errors = check(root)
    except (OSError, ValueError, json.JSONDecodeError) as error:
        print(str(error), file=sys.stderr)
        return 2
    for error in errors:
        print(error, file=sys.stderr)
    return 1 if errors else 0


if __name__ == "__main__":
    raise SystemExit(main())
