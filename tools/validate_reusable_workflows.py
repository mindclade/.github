#!/usr/bin/env python3
# pyright: basic, reportArgumentType=false, reportAttributeAccessIssue=false, reportCallIssue=false, reportOperatorIssue=false, reportOptionalMemberAccess=false, reportOptionalSubscript=false
"""Deterministic, stdlib-only validation for this organisation's GitHub assets."""

from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import os
import re
import subprocess
import sys
import urllib.parse
from collections.abc import Iterable
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
SHA = re.compile(r"^[0-9a-f]{40}$")
IMPLEMENTATION_ACTION = re.compile(
    r"^\$/\.github/actions/[A-Za-z0-9][A-Za-z0-9._-]*(?:/[A-Za-z0-9][A-Za-z0-9._-]*)*$"
)
SELF_TEST_LOCAL_ACTION = re.compile(
    r"^\./\.github/actions/[A-Za-z0-9][A-Za-z0-9._-]*(?:/[A-Za-z0-9][A-Za-z0-9._-]*)*$"
)
SELF_TEST_WORKFLOW_PATH = ".github/workflows/pull-request.yml"
REQUIRED_CHECK_WORKFLOW_PATH = ".github/workflows/reusable-required-check.yml"
BUILDKITE_DISPATCH_WORKFLOW_PATH = ".github/workflows/reusable-buildkite-dispatch.yml"
BUILDKITE_BRIDGE_TEMPLATE_PATH = "workflow-templates/buildkite-bridge.yml"
REQUIRED_CHECK_CALL = re.compile(
    r"^mindclade/\.github/\.github/workflows/reusable-required-check\.yml@[0-9a-f]{40}$"
)
ARCHIVE_HANDOFF_ASSERTIONS = (
    '[[ "${ARTIFACT_ID}" =~ ^[1-9][0-9]*$ ]]',
    '[[ "${ARTIFACT_DIGEST}" =~ ^sha256:[0-9a-f]{64}$ ]]',
    '[[ "${EVIDENCE_DIGEST}" =~ ^sha256:[0-9a-f]{64}$ ]]',
    '[[ "${GCP_WORKLOAD_IDENTITY_PROVIDER}" =~ ^projects/[1-9][0-9]*/locations/global/workloadIdentityPools/github-ci-evidence/providers/writer$ ]]',
    '[[ "${GCP_SERVICE_ACCOUNT}" =~ ^ci-evidence-writer@[a-z][a-z0-9-]{4,28}[a-z0-9]\\.iam\\.gserviceaccount\\.com$ ]]',
    '[[ "${GCS_EVIDENCE_BUCKET}" =~ ^[a-z][a-z0-9-]{4,28}[a-z0-9]-production-ci-evidence$ ]]',
)
INTERNAL_IMMUTABLE_REFERENCE = re.compile(
    r"^mindclade/\.github/\.github/(?:actions|workflows)/[A-Za-z0-9][A-Za-z0-9._-]*(?:/[A-Za-z0-9][A-Za-z0-9._-]*)*$",
    re.IGNORECASE,
)
MAX_CANONICAL_YAML_BYTES = 1024 * 1024
MAX_CANONICAL_YAML_DEPTH = 64
DOCUMENTATION_REQUIRED_HEADINGS = {
    "README.md": frozenset({"Ownership", "Activation boundary"}),
    "CONTRIBUTING.md": frozenset({"Activation"}),
    "GOVERNANCE.md": frozenset({"Ownership", "Change control", "Connected activation"}),
    "SECURITY.md": frozenset({"Reporting", "Review and disclosure", "Activation boundary"}),
    "SUPPORT.md": frozenset({"Source support", "Security support", "Connected requests"}),
    "profile/README.md": frozenset({"Activation boundary"}),
}
APPROVED_SCORECARD_WORKFLOW_SHA256 = (
    "4b3bc05348f5cc7ec69c74348c6ff28441d543ed64296a70c06d4850d82102e7"
)
COMMON_WORKFLOW_OUTPUTS = (
    "correlation_id",
    "source_revision",
    "caller_repository",
    "trust_classification",
    "execution_tier",
    "plan_id",
    "build_id",
    "conclusion",
    "reason_code",
    "evidence_digest",
    "evidence_ref",
)
DERIVED_TRUST_INPUTS = frozenset(
    {
        "trusted_context",
        "trust_classification",
        "execution_tier",
        "source_trust",
        "fork",
        "ref_protected",
    }
)
ALLOWED_INPUT_TYPES = frozenset({"string", "boolean", "number"})
BUILDKITE_WORKFLOW_PATHS = frozenset(
    {
        ".github/workflows/reusable-buildkite-dispatch.yml",
        ".github/workflows/reusable-required-check.yml",
    }
)
BUILDKITE_SECRETS = frozenset(
    {
        "buildkite_cancel_token",
        "buildkite_dispatch_token",
        "buildkite_evidence_token",
        "buildkite_pipeline",
    }
)
ALLOWED_PERMISSIONS = {
    "actions": "read",
    "checks": "write",
    "contents": "read",
    "id-token": "write",
    "issues": "read",
    "pull-requests": "read",
    "security-events": "write",
}
PROTECTED_TIER_GUARDS = frozenset(
    {
        "needs.prepare.outputs.execution_tier == 'trusted' || needs.prepare.outputs.execution_tier == 'release'",
        "needs.prepare.outputs.execution_tier == 'release' || needs.prepare.outputs.execution_tier == 'trusted'",
        "needs.prepare.result == 'success' && (needs.prepare.outputs.execution_tier == 'trusted' || needs.prepare.outputs.execution_tier == 'release')",
        "needs.prepare.result == 'success' && (needs.prepare.outputs.execution_tier == 'release' || needs.prepare.outputs.execution_tier == 'trusted')",
        "inputs.archive_evidence && needs.required.result == 'success' && (needs.required.outputs.execution_tier == 'trusted' || needs.required.outputs.execution_tier == 'release')",
    }
)
APPROVED_EXTERNAL_REFERENCES = {
    "actions/checkout": "3d3c42e5aac5ba805825da76410c181273ba90b1",
    "github/codeql-action/init": "cdf488f595d80d6e07e03d4674febd5ab45fa938",
    "github/codeql-action/analyze": "cdf488f595d80d6e07e03d4674febd5ab45fa938",
    "github/codeql-action/upload-sarif": "cdf488f595d80d6e07e03d4674febd5ab45fa938",
    "actions/dependency-review-action": "a1d282b36b6f3519aa1f3fc636f609c47dddb294",
    "actions/download-artifact": "3e5f45b2cfb9172054b4087a40e8e0b5a5461e7c",
    "actions/upload-artifact": "043fb46d1a93c77aae656e7c1c64a875d1fc6a0a",
    "google-github-actions/auth": "7c6bc770dae815cd3e89ee6cdf493a5fab2cc093",  # gitleaks:allow -- immutable public action commit
    "google-github-actions/setup-gcloud": "aa5489c8933f4cc7a4f7d45035b3b1440c9c10db",
    "DeterminateSystems/nix-installer-action": "ef8a148080ab6020fd15196c2084a2eea5ff2d25",
    "ghcr.io/ossf/scorecard-action": "sha256:ae5104dd3cc28466ebeb11144354be4cac4b7ff829654f9fab89021d71c46670",
    "docker://ghcr.io/ossf/scorecard-action": "sha256:ae5104dd3cc28466ebeb11144354be4cac4b7ff829654f9fab89021d71c46670",
}

EXPECTED_INVENTORY = frozenset(
    {
        ".github/actions/validate-trusted-context/action.yml",
        ".github/actions/validate-trusted-context/README.md",
        ".github/actions/verify-pinned-actions/action.yml",
        ".github/actions/verify-pinned-actions/README.md",
        ".github/actions/publish-ci-evidence/action.yml",
        ".github/actions/publish-ci-evidence/README.md",
        ".github/actions/required-workflow-profile/action.yml",
        ".github/actions/required-workflow-profile/README.md",
        ".github/actions/required-workflow-profile/profiles.generated.json",
        ".github/actions/required-workflow-profile/required_workflow_profile.py",
        ".github/workflows/reusable-buildkite-dispatch.yml",
        ".github/workflows/reusable-required-check.yml",
        ".github/workflows/reusable-nix-validation.yml",
        ".github/workflows/reusable-metadata-validation.yml",
        ".github/workflows/reusable-documentation-check.yml",
        ".github/workflows/reusable-dependency-review.yml",
        ".github/workflows/reusable-codeql.yml",
        ".github/workflows/reusable-scorecard.yml",
        ".github/workflows/pull-request.yml",
        ".github/ISSUE_TEMPLATE/bug.yml",
        ".github/ISSUE_TEMPLATE/security-control-gap.yml",
        ".github/ISSUE_TEMPLATE/architecture-change.yml",
        ".github/ISSUE_TEMPLATE/scientific-correctness.yml",
        ".github/ISSUE_TEMPLATE/config.yml",
        ".github/actionlint.yaml",
        ".github/CODEOWNERS",
        ".github/dependabot.yml",
        ".github/pull_request_template.md",
        "profile/README.md",
        "workflow-templates/buildkite-bridge.yml",
        "workflow-templates/buildkite-bridge.properties.json",
        "workflow-templates/repository-metadata.yml",
        "workflow-templates/repository-metadata.properties.json",
        "schemas/trusted_context.schema.json",
        "schemas/ci_evidence.schema.json",
        "config/nix-bazel-policy.json",
        "config/required-workflow-profiles.json",
        "generated/bazelrc.common",
        "generated/nix-bazel-policy.lock.json",
        "generated/nix-bazel-policy.nix",
        "generated/toolchain-manifest.defaults.json",
        "policy/action_pinning.rego",
        "policy/workflow_permissions.rego",
        "policy/reusable_workflow_interface.rego",
        "policy/tests/action_pinning_test.rego",
        "policy/tests/workflow_permissions_test.rego",
        "policy/tests/reusable_workflow_interface_test.rego",
        "tests/fixtures/trusted_pull_request.json",
        "tests/fixtures/untrusted_pull_request.json",
        "tests/fixtures/protected_release.json",
        "tests/test_reusable_workflow_contract.py",
        "tests/test_declared_permissions.py",
        "tests/test_generated_ci_policy.py",
        "tests/test_action_digest_pinning.py",
        "tests/test_required_workflow_profile.py",
        "tools/validate_reusable_workflows.py",
        "tools/emit_ci_evidence.py",
        "tools/generate_ci_policy.py",
        "BUILD.bazel",
        ".bazelignore",
        ".bazelrc",
        ".bazelversion",
        "MODULE.bazel",
        "MODULE.bazel.lock",
        "component.yaml",
        "flake.lock",
        "flake.nix",
        "justfile",
        ".editorconfig",
        ".gitignore",
        ".markdownlint-cli2.yaml",
        ".pre-commit-config.yaml",
        ".vscode/extensions.json",
        ".vscode/settings.json",
        ".yamllint.yaml",
        "biome.json",
        "CODE_OF_CONDUCT.md",
        "CONTRIBUTING.md",
        "GOVERNANCE.md",
        "LICENSE",
        "README.md",
        "SECURITY.md",
        "SUPPORT.md",
        "pyproject.toml",
    }
)
IGNORED_INVENTORY_PARTS = frozenset(
    {
        ".git",
        ".mypy_cache",
        ".pytest_cache",
        ".ruff_cache",
        "__pycache__",
    }
)


def canonical_json(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def digest(value: Any) -> str:
    payload = value if isinstance(value, str) else canonical_json(value)
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def result(ok: bool, errors: Iterable[str] = (), **details: Any) -> dict[str, Any]:
    return {"ok": ok, "errors": sorted(set(errors)), **details}


class CanonicalYAMLError(ValueError):
    """Raised when input is outside the deliberately bounded YAML dialect."""

    def __init__(self, line: int, message: str):
        super().__init__(f"line {line}: {message}")
        self.line = line
        self.message = message


class _CanonicalYAMLParser:
    """Parse the small, deterministic YAML subset used by governed assets.

    This is intentionally not a general YAML implementation. Features whose
    semantics can obscure policy-relevant keys are rejected rather than
    guessed: quoted/explicit keys, flow mappings, aliases, anchors, tags,
    merge keys, duplicate keys, directives, and multiple documents.
    """

    _KEY = re.compile(r"[A-Za-z_][A-Za-z0-9_./-]*")
    _BLOCK_SCALAR = re.compile(r"[|>][+-]?")

    def __init__(self, text: str):
        if len(text.encode("utf-8")) > MAX_CANONICAL_YAML_BYTES:
            raise CanonicalYAMLError(1, "document exceeds the 1 MiB limit")
        if "\t" in text:
            line = text[: text.index("\t")].count("\n") + 1
            raise CanonicalYAMLError(line, "tabs are unsupported")
        self.lines = text.splitlines()

    def parse(self) -> Any:
        first = self._next_significant(0)
        if first is None:
            return {}
        line, _content = self._significant(first)
        if line != 0:
            raise CanonicalYAMLError(first + 1, "root content must not be indented")
        value, following = self._parse_block(first, 0, 0)
        trailing = self._next_significant(following)
        if trailing is not None:
            raise CanonicalYAMLError(trailing + 1, "unexpected trailing content")
        return value

    def _next_significant(self, index: int) -> int | None:
        while index < len(self.lines):
            stripped = self.lines[index].strip()
            if stripped and not stripped.startswith("#"):
                if stripped in {"---", "..."} or stripped.startswith("%"):
                    raise CanonicalYAMLError(
                        index + 1, "directives and multiple documents are unsupported"
                    )
                return index
            index += 1
        return None

    def _significant(self, index: int) -> tuple[int, str]:
        raw = self.lines[index]
        indentation = len(raw) - len(raw.lstrip(" "))
        if indentation % 2:
            raise CanonicalYAMLError(index + 1, "indentation must use multiples of two spaces")
        return indentation, self._strip_comment(raw[indentation:]).rstrip()

    @staticmethod
    def _strip_comment(value: str) -> str:
        quote = ""
        escaped = False
        index = 0
        while index < len(value):
            character = value[index]
            if quote == '"':
                if escaped:
                    escaped = False
                elif character == "\\":
                    escaped = True
                elif character == quote:
                    quote = ""
            elif quote == "'":
                if character == "'" and index + 1 < len(value) and value[index + 1] == "'":
                    index += 1
                elif character == quote:
                    quote = ""
            elif character in {"'", '"'}:
                quote = character
            elif character == "#" and (index == 0 or value[index - 1].isspace()):
                return value[:index]
            index += 1
        if quote:
            # Scalar parsing provides the line number for the final error.
            return value
        return value

    def _parse_block(self, index: int, indent: int, depth: int) -> tuple[Any, int]:
        if depth > MAX_CANONICAL_YAML_DEPTH:
            raise CanonicalYAMLError(index + 1, "nesting exceeds 64 levels")
        actual_indent, content = self._significant(index)
        if actual_indent != indent:
            raise CanonicalYAMLError(
                index + 1, f"expected indentation {indent}, found {actual_indent}"
            )
        if content == "-" or content.startswith("- "):
            return self._parse_sequence(index, indent, depth)
        return self._parse_mapping(index, indent, depth)

    def _parse_mapping(self, index: int, indent: int, depth: int) -> tuple[dict[str, Any], int]:
        mapping: dict[str, Any] = {}
        while True:
            current = self._next_significant(index)
            if current is None:
                return mapping, len(self.lines)
            actual_indent, content = self._significant(current)
            if actual_indent < indent:
                return mapping, current
            if actual_indent > indent:
                raise CanonicalYAMLError(
                    current + 1, f"unexpected indentation {actual_indent}; expected {indent}"
                )
            if content == "-" or content.startswith("- "):
                return mapping, current
            key, inline = self._mapping_pair(content, current + 1)
            if key in mapping:
                raise CanonicalYAMLError(current + 1, f"duplicate mapping key {key}")
            if self._BLOCK_SCALAR.fullmatch(inline):
                value, index = self._parse_block_scalar(current, indent, inline[0])
            elif inline:
                value = self._parse_scalar(inline, current + 1)
                index = current + 1
                child = self._next_significant(index)
                if child is not None and self._significant(child)[0] > indent:
                    raise CanonicalYAMLError(child + 1, f"scalar {key} cannot have nested content")
            else:
                child = self._next_significant(current + 1)
                if child is None or self._significant(child)[0] <= indent:
                    value = None
                    index = current + 1
                else:
                    child_indent = self._significant(child)[0]
                    if child_indent != indent + 2:
                        raise CanonicalYAMLError(
                            child + 1, f"nested content must be indented {indent + 2} spaces"
                        )
                    value, index = self._parse_block(child, child_indent, depth + 1)
            mapping[key] = value

    def _parse_sequence(self, index: int, indent: int, depth: int) -> tuple[list[Any], int]:
        sequence: list[Any] = []
        while True:
            current = self._next_significant(index)
            if current is None:
                return sequence, len(self.lines)
            actual_indent, content = self._significant(current)
            if actual_indent < indent:
                return sequence, current
            if actual_indent > indent:
                raise CanonicalYAMLError(
                    current + 1, f"unexpected indentation {actual_indent}; expected {indent}"
                )
            if content != "-" and not content.startswith("- "):
                return sequence, current
            inline = content[1:].strip()
            if not inline:
                child = self._next_significant(current + 1)
                if child is None or self._significant(child)[0] <= indent:
                    sequence.append(None)
                    index = current + 1
                    continue
                child_indent = self._significant(child)[0]
                if child_indent != indent + 2:
                    raise CanonicalYAMLError(
                        child + 1, f"sequence content must be indented {indent + 2} spaces"
                    )
                value, index = self._parse_block(child, child_indent, depth + 1)
                sequence.append(value)
                continue
            pair = self._maybe_mapping_pair(inline, current + 1)
            if pair is None:
                sequence.append(self._parse_scalar(inline, current + 1))
                index = current + 1
                child = self._next_significant(index)
                if child is not None and self._significant(child)[0] > indent:
                    raise CanonicalYAMLError(
                        child + 1, "scalar sequence item cannot have nested content"
                    )
                continue
            key, first_inline = pair
            item: dict[str, Any] = {}
            if self._BLOCK_SCALAR.fullmatch(first_inline):
                value, index = self._parse_block_scalar(current, indent + 2, first_inline[0])
            elif first_inline:
                value = self._parse_scalar(first_inline, current + 1)
                index = current + 1
            else:
                child = self._next_significant(current + 1)
                if child is None or self._significant(child)[0] <= indent + 1:
                    value = None
                    index = current + 1
                else:
                    child_indent = self._significant(child)[0]
                    if child_indent != indent + 4:
                        raise CanonicalYAMLError(
                            child + 1, f"nested content must be indented {indent + 4} spaces"
                        )
                    value, index = self._parse_block(child, child_indent, depth + 2)
            item[key] = value
            continuation = self._next_significant(index)
            if continuation is not None and self._significant(continuation)[0] > indent:
                continuation_indent = self._significant(continuation)[0]
                if continuation_indent != indent + 2:
                    raise CanonicalYAMLError(
                        continuation + 1, f"sequence mapping must be indented {indent + 2} spaces"
                    )
                remainder, index = self._parse_mapping(continuation, indent + 2, depth + 1)
                duplicates = set(item).intersection(remainder)
                if duplicates:
                    raise CanonicalYAMLError(
                        continuation + 1, f"duplicate mapping key {sorted(duplicates)[0]}"
                    )
                item.update(remainder)
            sequence.append(item)

    def _parse_block_scalar(self, key_line: int, indent: int, style: str) -> tuple[str, int]:
        index = key_line + 1
        content_indent = indent + 2
        collected: list[str] = []
        while index < len(self.lines):
            raw = self.lines[index]
            if not raw.strip():
                collected.append("")
                index += 1
                continue
            actual_indent = len(raw) - len(raw.lstrip(" "))
            if actual_indent <= indent:
                break
            if actual_indent < content_indent:
                raise CanonicalYAMLError(
                    index + 1,
                    f"block scalar content must be indented at least {content_indent} spaces",
                )
            collected.append(raw[content_indent:])
            index += 1
        if style == ">":
            return " ".join(part.strip() for part in collected), index
        return "\n".join(collected), index

    def _mapping_pair(self, content: str, line: int) -> tuple[str, str]:
        pair = self._maybe_mapping_pair(content, line)
        if pair is None:
            raise CanonicalYAMLError(line, "expected a plain mapping key")
        return pair

    def _maybe_mapping_pair(self, content: str, line: int) -> tuple[str, str] | None:
        if content.startswith("?"):
            raise CanonicalYAMLError(line, "explicit mapping keys are unsupported")
        colon = self._mapping_colon(content)
        if colon < 0:
            return None
        if content.startswith(("'", '"')):
            raise CanonicalYAMLError(line, "quoted mapping keys are unsupported")
        key = content[:colon].strip()
        if key == "<<":
            raise CanonicalYAMLError(line, "merge keys are unsupported")
        if not self._KEY.fullmatch(key):
            raise CanonicalYAMLError(line, f"unsupported mapping key {key or '<empty>'}")
        return key, content[colon + 1 :].strip()

    @staticmethod
    def _mapping_colon(content: str) -> int:
        quote = ""
        escaped = False
        index = 0
        while index < len(content):
            character = content[index]
            if quote == '"':
                if escaped:
                    escaped = False
                elif character == "\\":
                    escaped = True
                elif character == quote:
                    quote = ""
            elif quote == "'":
                if character == "'" and index + 1 < len(content) and content[index + 1] == "'":
                    index += 1
                elif character == quote:
                    quote = ""
            elif character in {"'", '"'}:
                quote = character
            elif character == ":" and (index + 1 == len(content) or content[index + 1].isspace()):
                return index
            index += 1
        return -1

    @staticmethod
    def _has_unquoted_colon(content: str) -> bool:
        quote = ""
        escaped = False
        index = 0
        while index < len(content):
            character = content[index]
            if quote == '"':
                if escaped:
                    escaped = False
                elif character == "\\":
                    escaped = True
                elif character == quote:
                    quote = ""
            elif quote == "'":
                if character == "'" and index + 1 < len(content) and content[index + 1] == "'":
                    index += 1
                elif character == quote:
                    quote = ""
            elif character in {"'", '"'}:
                quote = character
            elif character == ":":
                return True
            index += 1
        return False

    def _parse_scalar(self, token: str, line: int) -> Any:
        if token == "{}":
            return {}
        if token.startswith("{"):
            raise CanonicalYAMLError(line, "non-empty flow mappings are unsupported")
        if token.startswith("["):
            return self._parse_flow_sequence(token, line)
        if token.startswith("&"):
            raise CanonicalYAMLError(line, "anchors are unsupported")
        if token.startswith("*"):
            raise CanonicalYAMLError(line, "aliases are unsupported")
        if token.startswith("!"):
            raise CanonicalYAMLError(line, "tags are unsupported")
        if re.search(r"(?:^|\s)[&*][A-Za-z0-9_-]+(?:\s|$)", token):
            raise CanonicalYAMLError(line, "anchors and aliases are unsupported")
        if token.startswith("'"):
            if len(token) < 2 or not token.endswith("'"):
                raise CanonicalYAMLError(line, "unterminated single-quoted scalar")
            return token[1:-1].replace("''", "'")
        if token.startswith('"'):
            try:
                decoded = json.loads(token)
            except json.JSONDecodeError as exc:
                raise CanonicalYAMLError(line, f"invalid double-quoted scalar: {exc.msg}") from exc
            if not isinstance(decoded, str):
                raise CanonicalYAMLError(line, "double-quoted scalar must decode to a string")
            return decoded
        lowered = token.lower()
        if lowered in {
            "null",
            "true",
            "false",
            "yes",
            "no",
            "on",
            "off",
            ".inf",
            "+.inf",
            "-.inf",
            ".nan",
        } and token not in {"null", "true", "false"}:
            raise CanonicalYAMLError(
                line,
                f"ambiguous plain scalar {token} must be quoted or use canonical lowercase spelling",
            )
        if token in {"null", "~"}:
            return None
        if token == "true":
            return True
        if token == "false":
            return False
        if re.fullmatch(r"-?(?:0|[1-9][0-9]*)", token):
            return int(token)
        if re.fullmatch(
            r"[+-]?(?:[0-9][0-9_]*(?:\.[0-9_]*)?(?:[eE][+-]?[0-9]+)?|0[xX][0-9a-fA-F_]+|0[oO][0-7_]+|0[bB][01_]+|\.[0-9_]+)",
            token,
        ):
            raise CanonicalYAMLError(line, f"unsupported numeric scalar {token}")
        if re.fullmatch(r"[+-]?[0-9][0-9_]*(?::[0-5]?[0-9])+(?:\.[0-9_]*)?", token):
            raise CanonicalYAMLError(line, f"unsupported sexagesimal numeric scalar {token}")
        if re.fullmatch(r"[0-9]{4}-[0-9]{2}-[0-9]{2}(?:[Tt ].*)?", token):
            raise CanonicalYAMLError(line, "timestamp-like plain scalars must be quoted")
        return token

    def _parse_flow_sequence(self, token: str, line: int) -> list[Any]:
        if not token.endswith("]"):
            raise CanonicalYAMLError(line, "unterminated flow sequence")
        inner = token[1:-1].strip()
        if not inner:
            return []
        items: list[str] = []
        start = 0
        quote = ""
        escaped = False
        index = 0
        while index < len(inner):
            character = inner[index]
            if quote == '"':
                if escaped:
                    escaped = False
                elif character == "\\":
                    escaped = True
                elif character == quote:
                    quote = ""
            elif quote == "'":
                if character == "'" and index + 1 < len(inner) and inner[index + 1] == "'":
                    index += 1
                elif character == quote:
                    quote = ""
            elif character in {"'", '"'}:
                quote = character
            elif character in "[{":
                raise CanonicalYAMLError(line, "nested flow collections are unsupported")
            elif character == ",":
                items.append(inner[start:index].strip())
                start = index + 1
            index += 1
        if quote:
            raise CanonicalYAMLError(line, "unterminated quoted flow-sequence item")
        items.append(inner[start:].strip())
        if any(not item for item in items):
            raise CanonicalYAMLError(line, "empty flow-sequence items are unsupported")
        if any(self._has_unquoted_colon(item) for item in items):
            raise CanonicalYAMLError(
                line, "unquoted colon-bearing flow-sequence items are unsupported"
            )
        return [self._parse_scalar(item, line) for item in items]


def parse_canonical_yaml(text: str) -> Any:
    """Parse governed YAML with deterministic, fail-closed semantics."""
    return _CanonicalYAMLParser(text).parse()


def _parsed_yaml(path: Path, root: Path) -> tuple[Any | None, str | None]:
    relative = path.relative_to(root)
    try:
        return parse_canonical_yaml(path.read_text(encoding="utf-8")), None
    except (OSError, UnicodeError, CanonicalYAMLError) as exc:
        return None, f"{relative}: unsupported canonical YAML: {exc}"


def write_output(path: str | None, values: dict[str, Any]) -> None:
    if not path:
        return
    lines = [f"{key}={value}" for key, value in values.items()]
    Path(path).parent.mkdir(parents=True, exist_ok=True)
    with Path(path).open("a", encoding="utf-8") as output:
        output.write("\n".join(lines) + "\n")


def files(root: Path, patterns: Iterable[str]) -> list[Path]:
    return sorted({path for pattern in patterns for path in root.glob(pattern) if path.is_file()})


def inventory_files(root: Path) -> dict[str, Path]:
    root = root.resolve()
    observed: dict[str, Path] = {}
    bazel_output_roots = {
        "bazel-bin",
        "bazel-out",
        "bazel-testlogs",
        f"bazel-{root.name}",
    }
    for path in root.rglob("*"):
        relative = path.relative_to(root)
        if any(part in IGNORED_INVENTORY_PARTS for part in relative.parts):
            continue
        if len(relative.parts) == 1 and path.is_symlink() and relative.name in bazel_output_roots:
            continue
        if path.suffix == ".pyc":
            continue
        if path.is_file() or path.is_symlink():
            observed[relative.as_posix()] = path
    return observed


def source_closure_digest(root: Path, selected_paths: Iterable[str] | None = None) -> str:
    closure: dict[str, str] = {}
    if selected_paths is not None:
        resolved_root = root.resolve()
        for relative in sorted(set(selected_paths)):
            candidate, path_error = _repository_path(resolved_root, relative)
            if path_error or candidate is None:
                closure[relative] = "INVALID"
            elif candidate.is_symlink():
                closure[relative] = "SYMLINK"
            elif candidate.is_file():
                closure[relative] = hashlib.sha256(candidate.read_bytes()).hexdigest()
            else:
                closure[relative] = "MISSING"
        return digest(closure)
    observed = inventory_files(root)
    for relative in sorted(EXPECTED_INVENTORY):
        path = root / relative
        if path.is_symlink():
            closure[relative] = "SYMLINK"
        elif path.is_file():
            closure[relative] = hashlib.sha256(path.read_bytes()).hexdigest()
        else:
            closure[relative] = "MISSING"
    for relative in sorted(set(observed).difference(EXPECTED_INVENTORY)):
        path = observed[relative]
        closure[f"UNEXPECTED:{relative}"] = (
            "SYMLINK" if path.is_symlink() else hashlib.sha256(path.read_bytes()).hexdigest()
        )
    return digest(closure)


def validate_inventory(root: Path) -> dict[str, Any]:
    observed = inventory_files(root)
    missing = sorted(
        path
        for path in EXPECTED_INVENTORY
        if not (root / path).is_file() or (root / path).is_symlink()
    )
    unexpected = sorted(set(observed).difference(EXPECTED_INVENTORY))
    errors = [*missing, *(f"unexpected: {path}" for path in unexpected)]
    return result(
        not errors,
        errors,
        check="inventory",
        expected=len(EXPECTED_INVENTORY),
        observed=len(set(observed).intersection(EXPECTED_INVENTORY)),
    )


def _executable_yaml_paths(root: Path) -> list[Path]:
    return files(
        root,
        (
            ".github/workflows/*.yml",
            ".github/workflows/*.yaml",
            ".github/actions/*/action.yml",
            ".github/actions/*/action.yaml",
            "workflow-templates/*.yml",
            "workflow-templates/*.yaml",
        ),
    )


def _walk_yaml(
    value: Any, path: tuple[str, ...] = ()
) -> Iterable[tuple[tuple[str, ...], str, Any]]:
    if isinstance(value, dict):
        for key, child in value.items():
            current = (*path, key)
            yield current, key, child
            yield from _walk_yaml(child, current)
    elif isinstance(value, list):
        for index, child in enumerate(value):
            yield from _walk_yaml(child, (*path, str(index)))


def _run_uses_caller_inputs(value: str) -> bool:
    """Detect caller inputs anywhere inside a GitHub expression in shell source."""
    search_from = 0
    while True:
        start = value.find("${{", search_from)
        if start < 0:
            return False
        cursor = start + 3
        quoted = False
        while cursor < len(value) - 1:
            character = value[cursor]
            if quoted:
                if character == "'" and cursor + 1 < len(value) and value[cursor + 1] == "'":
                    cursor += 2
                    continue
                if character == "'":
                    quoted = False
            elif character == "'":
                quoted = True
            elif character == "}" and value[cursor + 1] == "}":
                if re.search(r"\binputs\b", value[start + 3 : cursor], re.IGNORECASE):
                    return True
                search_from = cursor + 2
                break
            cursor += 1
        else:
            # Malformed expressions are rejected by actionlint; still fail
            # closed if the unterminated tail references caller inputs.
            return re.search(r"\binputs\b", value[start + 3 :], re.IGNORECASE) is not None


def _pin_reference_error(relative: Path, reference: Any) -> str | None:
    if not isinstance(reference, str) or not reference:
        return f"{relative}: uses reference must be a non-empty string"
    if reference.startswith("./"):
        if relative.as_posix() == SELF_TEST_WORKFLOW_PATH and SELF_TEST_LOCAL_ACTION.fullmatch(
            reference
        ):
            return None
        return f"{relative}: caller-checkout local action reference is forbidden: {reference}"
    if reference.startswith("$/"):
        if IMPLEMENTATION_ACTION.fullmatch(reference) and ".." not in reference.split("/"):
            return None
        return f"{relative}: invalid implementation action reference {reference}"
    if "@" not in reference:
        return f"{relative}: unpinned uses reference {reference}"
    source, revision = reference.rsplit("@", 1)
    if not SHA.fullmatch(revision) and not re.fullmatch(r"sha256:[0-9a-f]{64}", revision):
        return f"{relative}: action is not SHA pinned: {reference}"
    if APPROVED_EXTERNAL_REFERENCES.get(source) == revision:
        return None
    if SHA.fullmatch(revision) and INTERNAL_IMMUTABLE_REFERENCE.fullmatch(source):
        return None
    return f"{relative}: action or workflow is not allowlisted: {reference}"


def _container_reference_error(relative: Path, reference: Any) -> str | None:
    if not isinstance(reference, str) or not reference:
        return f"{relative}: container image reference must be a non-empty string"
    if "@" not in reference:
        return f"{relative}: container image is not digest pinned: {reference}"
    source, revision = reference.rsplit("@", 1)
    if APPROVED_EXTERNAL_REFERENCES.get(source) != revision:
        return f"{relative}: container image is not allowlisted: {reference}"
    return None


def validate_pins(root: Path) -> dict[str, Any]:
    errors: list[str] = []
    for path in _executable_yaml_paths(root):
        relative = path.relative_to(root)
        document, parse_error = _parsed_yaml(path, root)
        if parse_error:
            errors.append(parse_error)
            continue
        for yaml_path, key, value in _walk_yaml(document):
            if key == "uses":
                error = _pin_reference_error(relative, value)
                if error:
                    errors.append(error)
            is_container_reference = (
                key == "SCORECARD_IMAGE"
                or key == "container"
                or (key == "image" and ("container" in yaml_path or "services" in yaml_path))
            )
            if is_container_reference:
                reference = (
                    value.get("image") if key == "container" and isinstance(value, dict) else value
                )
                error = _container_reference_error(relative, reference)
                if error:
                    errors.append(error)
            if (
                key == "run"
                and isinstance(value, str)
                and re.search(r"\bdocker\b", value, re.IGNORECASE)
            ):
                approved_scorecard_run = (
                    relative.as_posix() == ".github/workflows/reusable-scorecard.yml"
                    and hashlib.sha256(path.read_bytes()).hexdigest()
                    == APPROVED_SCORECARD_WORKFLOW_SHA256
                )
                if not approved_scorecard_run:
                    errors.append(
                        f"{relative}: direct docker execution must match the approved Scorecard script"
                    )
    return result(not errors, errors, check="pins")


def _git_object_exists(root: Path, object_name: str) -> bool:
    completed = subprocess.run(
        ["git", "cat-file", "-e", object_name],
        cwd=root,
        check=False,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    return completed.returncode == 0


def validate_template_pins(root: Path, approved_main_revision: str) -> dict[str, Any]:
    """Prove internal template pins exist on approved main and contain their targets."""
    errors: list[str] = []
    if not SHA.fullmatch(approved_main_revision):
        return result(
            False,
            ["approved main revision must be a lowercase 40-character Git SHA"],
            check="template_pins",
        )
    if not _git_object_exists(root, f"{approved_main_revision}^{{commit}}"):
        return result(
            False,
            [f"approved main revision does not exist: {approved_main_revision}"],
            check="template_pins",
        )
    internal_references: set[tuple[str, str, str]] = set()
    for path in files(root, ("workflow-templates/*.yml", "workflow-templates/*.yaml")):
        relative = path.relative_to(root)
        document, parse_error = _parsed_yaml(path, root)
        if parse_error:
            errors.append(parse_error)
            continue
        for _, key, value in _walk_yaml(document):
            if key != "uses" or not isinstance(value, str) or "@" not in value:
                continue
            source, revision = value.rsplit("@", 1)
            if not INTERNAL_IMMUTABLE_REFERENCE.fullmatch(source):
                continue
            repository_path = source.removeprefix("mindclade/.github/")
            internal_references.add((relative.as_posix(), repository_path, revision))
    for template, repository_path, revision in sorted(internal_references):
        if not SHA.fullmatch(revision):
            errors.append(f"{template}: internal template reference is not SHA pinned")
            continue
        if not _git_object_exists(root, f"{revision}^{{commit}}"):
            errors.append(f"{template}: pinned commit does not exist: {revision}")
            continue
        ancestor = subprocess.run(
            ["git", "merge-base", "--is-ancestor", revision, approved_main_revision],
            cwd=root,
            check=False,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        if ancestor.returncode != 0:
            errors.append(f"{template}: pinned commit is not on approved main: {revision}")
            continue
        if not _git_object_exists(root, f"{revision}:{repository_path}"):
            errors.append(f"{template}: pinned commit does not contain {repository_path}")
    return result(
        not errors, errors, check="template_pins", approved_main_revision=approved_main_revision
    )


def _permission_violations(
    relative: Path, scope: str, untrusted: bool, protected: bool, value: Any
) -> list[str]:
    prefix = f"{relative}:{scope}"
    if isinstance(value, str) and value in {"read-all", "write-all"}:
        return [f"{prefix}: permissions: {value} is forbidden"]
    if not isinstance(value, dict):
        return [f"{prefix}: permissions must be an explicit object"]
    errors: list[str] = []
    for permission, level in value.items():
        expected = ALLOWED_PERMISSIONS.get(permission)
        if expected is None:
            errors.append(f"{prefix}: unapproved permission scope {permission}")
            continue
        if level != expected:
            errors.append(f"{prefix}: permission {permission} must be {expected}, not {level}")
        if untrusted and level == "write":
            errors.append(f"{prefix}: untrusted job cannot request write permission {permission}")
        if level == "write" and (scope == "workflow" or not protected):
            errors.append(
                f"{prefix}: write permission {permission} requires an explicit trusted/release execution-tier guard"
            )
    return errors


def _has_protected_tier_guard(condition: str) -> bool:
    return condition in PROTECTED_TIER_GUARDS


def _has_trusted_context_producer(document: Any, jobs: Any) -> bool:
    if not isinstance(document, dict) or "env" in document or not isinstance(jobs, dict):
        return False
    prepare = jobs.get("prepare") or jobs.get("required")
    if not isinstance(prepare, dict):
        return False
    if prepare.get("continue-on-error", False) is not False:
        return False
    if prepare.get("runs-on") != "ubuntu-24.04" or "env" in prepare or "container" in prepare:
        return False
    outputs = prepare.get("outputs")
    if (
        not isinstance(outputs, dict)
        or outputs.get("execution_tier") != "${{ steps.context.outputs.execution_tier }}"
    ):
        return False
    steps = prepare.get("steps")
    if not isinstance(steps, list) or len(steps) < 2:
        return False
    context_steps = [
        step for step in steps if isinstance(step, dict) and step.get("id") == "context"
    ]
    if len(context_steps) != 1:
        return False
    context = context_steps[0]
    if context is not steps[0]:
        return False
    if context.get("uses") != "$/.github/actions/validate-trusted-context":
        return False
    if context.get("continue-on-error", False) is not False or "if" in context or "env" in context:
        return False
    context_inputs = context.get("with")
    if not isinstance(context_inputs, dict):
        return False
    if context_inputs.get("expected-source-revision") != "${{ inputs.source_revision }}":
        return False

    pin_steps = [
        step
        for step in steps
        if isinstance(step, dict) and step.get("uses") == "$/.github/actions/verify-pinned-actions"
    ]
    if len(pin_steps) != 1:
        return False
    pins = pin_steps[0]
    if pins is not steps[1]:
        return False
    return not (
        pins.get("continue-on-error", False) is not False
        or "if" in pins
        or "with" in pins
        or "env" in pins
    )


def validate_permissions(root: Path) -> dict[str, Any]:
    errors: list[str] = []
    paths = files(
        root,
        (
            ".github/workflows/*.yml",
            ".github/workflows/*.yaml",
            "workflow-templates/*.yml",
            "workflow-templates/*.yaml",
        ),
    )
    for path in paths:
        relative = path.relative_to(root)
        document, parse_error = _parsed_yaml(path, root)
        if parse_error:
            errors.append(parse_error)
            continue
        if not isinstance(document, dict):
            errors.append(f"{relative}: workflow root must be a mapping")
            continue
        if "permissions" not in document:
            errors.append(f"{relative}: missing explicit permissions declaration")
        else:
            errors.extend(
                _permission_violations(relative, "workflow", False, False, document["permissions"])
            )
        jobs = document.get("jobs")
        trusted_context_producer = _has_trusted_context_producer(document, jobs)
        valid_paths = {("permissions",)}
        if isinstance(jobs, dict):
            for job_name, job in jobs.items():
                if not isinstance(job, dict) or "permissions" not in job:
                    continue
                condition = job.get("if") if isinstance(job.get("if"), str) else ""
                untrusted = job_name == "untrusted" or bool(
                    "execution_tier" in condition
                    and re.search(r"==\s*['\"]untrusted['\"]", condition)
                )
                protected = (
                    "execution_tier" in condition
                    and _has_protected_tier_guard(condition)
                    and trusted_context_producer
                )
                approved_delegation = (
                    relative.as_posix() == BUILDKITE_BRIDGE_TEMPLATE_PATH
                    and job_name == "buildkite_required"
                    and isinstance(job.get("uses"), str)
                    and REQUIRED_CHECK_CALL.fullmatch(job["uses"]) is not None
                    and job["permissions"]
                    == {"actions": "read", "contents": "read", "id-token": "write"}
                )
                valid_paths.add(("jobs", job_name, "permissions"))
                errors.extend(
                    _permission_violations(
                        relative,
                        job_name,
                        untrusted,
                        protected or approved_delegation,
                        job["permissions"],
                    )
                )
        for yaml_path, key, _ in _walk_yaml(document):
            if key == "permissions" and yaml_path not in valid_paths:
                errors.append(
                    f"{relative}:{'.'.join(yaml_path)}: permissions must be declared at workflow level or directly on a job"
                )
    return result(not errors, errors, check="permissions")


def _workflow_call_interface_errors(
    path: Path, document: dict[str, Any], relative: Path
) -> list[str]:
    triggers = document.get("on")
    call = triggers.get("workflow_call") if isinstance(triggers, dict) else None
    if not isinstance(call, dict):
        return [f"{relative}: reusable workflow must declare workflow_call"]

    errors: list[str] = []
    inputs = call.get("inputs")
    if not isinstance(inputs, dict):
        errors.append(f"{relative}: workflow_call must declare source_revision input")
        inputs = {}
    else:
        source_revision = inputs.get("source_revision")
        if not isinstance(source_revision, dict):
            errors.append(f"{relative}: workflow_call must declare source_revision input")
        else:
            if source_revision.get("required") is not True:
                errors.append(f"{relative}: source_revision input must be required: true")
            if source_revision.get("type") != "string":
                errors.append(f"{relative}: source_revision input must have type: string")
    input_names_by_casefold: dict[str, str] = {}
    derived_names = {name.casefold() for name in DERIVED_TRUST_INPUTS}
    for name in sorted(inputs):
        definition = inputs[name]
        folded = name.casefold()
        if folded in derived_names:
            errors.append(f"{relative}: workflow_call input {name} is derived and forbidden")
        previous = input_names_by_casefold.get(folded)
        if previous is not None:
            errors.append(
                f"{relative}: workflow_call inputs {previous} and {name} differ only by case"
            )
        else:
            input_names_by_casefold[folded] = name
        if not isinstance(definition, dict):
            errors.append(f"{relative}: workflow_call input {name} definition must be a mapping")
        elif definition.get("type") not in ALLOWED_INPUT_TYPES:
            errors.append(
                f"{relative}: workflow_call input {name} must declare string, boolean, or number type"
            )

    outputs = call.get("outputs")
    if not isinstance(outputs, dict):
        errors.append(f"{relative}: workflow_call must declare common outputs")
    else:
        for name in COMMON_WORKFLOW_OUTPUTS:
            output = outputs.get(name)
            if not isinstance(output, dict):
                errors.append(f"{relative}: workflow_call output {name} is required")
                continue
            if not isinstance(output.get("value"), str) or not output["value"].strip():
                errors.append(f"{relative}: workflow_call output {name} must declare value")

    if any(key == "secrets" and value == "inherit" for _, key, value in _walk_yaml(document)):
        errors.append(f"{relative}: secrets: inherit is forbidden")
    secrets = call.get("secrets")
    if secrets is not None:
        if not isinstance(secrets, dict):
            errors.append(f"{relative}: workflow_call secrets must be an explicit object")
            secrets = {}
        if relative.as_posix() not in BUILDKITE_WORKFLOW_PATHS:
            for name in sorted(secrets):
                errors.append(
                    f"{relative}: non-Buildkite reusable workflow may not declare secret {name}"
                )
        else:
            for name in sorted(secrets):
                if name.casefold() not in BUILDKITE_SECRETS:
                    errors.append(
                        f"{relative}: Buildkite reusable workflow declares unapproved secret {name}"
                    )
                if not isinstance(secrets[name], dict):
                    errors.append(
                        f"{relative}: workflow_call secret {name} definition must be a mapping"
                    )
    return errors


def _required_check_archive_errors(document: dict[str, Any], relative: Path) -> list[str]:
    if relative.as_posix() != REQUIRED_CHECK_WORKFLOW_PATH:
        return []
    prefix = f"{relative}: archive activation"
    jobs = document.get("jobs")
    triggers = document.get("on")
    workflow_call = triggers.get("workflow_call") if isinstance(triggers, dict) else None
    inputs = workflow_call.get("inputs") if isinstance(workflow_call, dict) else None
    archive_declared = isinstance(jobs, dict) and "archive" in jobs
    archive_input_declared = isinstance(inputs, dict) and "archive_evidence" in inputs
    if not archive_declared and not archive_input_declared:
        return []
    archive = jobs.get("archive") if isinstance(jobs, dict) else None
    steps = archive.get("steps") if isinstance(archive, dict) else None
    if not isinstance(steps, list):
        return [f"{prefix} job must declare ordered steps"]

    validation_steps = [
        (index, step)
        for index, step in enumerate(steps)
        if isinstance(step, dict) and step.get("name") == "Validate archive activation inputs"
    ]
    auth_steps = [
        (index, step)
        for index, step in enumerate(steps)
        if isinstance(step, dict)
        and isinstance(step.get("uses"), str)
        and step["uses"].startswith("google-github-actions/auth@")
    ]
    errors: list[str] = []
    expected_job_guard = "inputs.archive_evidence && needs.required.result == 'success' && (needs.required.outputs.execution_tier == 'trusted' || needs.required.outputs.execution_tier == 'release')"
    if archive.get("needs") != "required":
        errors.append(f"{prefix} job must depend only on required")
    if archive.get("if") != expected_job_guard:
        errors.append(f"{prefix} job must use the exact activation and trusted-tier guard")
    if len(validation_steps) != 1:
        errors.append(f"{prefix} must have exactly one handoff validation step")
    if len(auth_steps) != 1:
        errors.append(f"{prefix} must have exactly one Google OIDC exchange step")
    if len(validation_steps) != 1 or len(auth_steps) != 1:
        return errors

    validation_index, validation = validation_steps[0]
    auth_index, auth = auth_steps[0]
    if validation_index >= auth_index:
        errors.append(f"{prefix} must validate every handoff value before OIDC exchange")
    if validation.get("if") != "inputs.archive_evidence":
        errors.append(f"{prefix} validation must use the exact archive activation guard")
    if validation.get("continue-on-error", False) is not False:
        errors.append(f"{prefix} validation must fail closed before OIDC exchange")
    expected_env = {
        "ARTIFACT_DIGEST": "${{ needs.required.outputs.artifact_digest }}",
        "ARTIFACT_ID": "${{ needs.required.outputs.artifact_id }}",
        "EVIDENCE_DIGEST": "${{ needs.required.outputs.evidence_digest }}",
        "GCP_SERVICE_ACCOUNT": "${{ inputs.gcp_service_account }}",
        "GCP_WORKLOAD_IDENTITY_PROVIDER": "${{ inputs.gcp_workload_identity_provider }}",
        "GCS_EVIDENCE_BUCKET": "${{ inputs.gcs_evidence_bucket }}",
    }
    if validation.get("env") != expected_env:
        errors.append(f"{prefix} validation environment must bind the exact caller handoff inputs")
    run = validation.get("run")
    run_lines = {line.strip() for line in run.splitlines()} if isinstance(run, str) else set()
    for assertion in ARCHIVE_HANDOFF_ASSERTIONS:
        if assertion not in run_lines:
            errors.append(f"{prefix} is missing exact-shape assertion: {assertion}")

    if auth.get("if") != "inputs.archive_evidence":
        errors.append(f"{prefix} OIDC exchange must use the exact archive activation guard")
    auth_inputs = auth.get("with")
    expected_auth_inputs = {
        "workload_identity_provider": "${{ inputs.gcp_workload_identity_provider }}",
        "service_account": "${{ inputs.gcp_service_account }}",
        "create_credentials_file": True,
        "export_environment_variables": True,
        "cleanup_credentials": True,
    }
    if auth_inputs != expected_auth_inputs:
        errors.append(
            f"{prefix} OIDC exchange must consume only the validated writer identity inputs"
        )
    return errors


def _bounded_concurrency_errors(document: dict[str, Any], relative: Path) -> list[str]:
    if not relative.as_posix().startswith(".github/workflows/"):
        return []
    # Incomplete unit-test documents without jobs are validated by their
    # focused interface checks. Every executable repository workflow has jobs
    # and must carry a stable repository-scoped cancellation boundary. Reusable
    # workflows inherit the caller's github context, so their groups bind both
    # the caller workflow and its stable pull-request/ref boundary. They
    # deliberately omit the source revision: a revision-scoped group would
    # create one independent lane per push and would not bound superseded work.
    if not isinstance(document.get("jobs"), dict):
        return []
    concurrency = document.get("concurrency")
    if not isinstance(concurrency, dict):
        return [f"{relative}: executable workflow must declare bounded concurrency"]
    errors: list[str] = []
    group = concurrency.get("group")
    if not isinstance(group, str) or "${{ github.repository }}" not in group:
        errors.append(f"{relative}: concurrency group must include github.repository")
    if relative.name.startswith("reusable-"):
        if not isinstance(group, str) or "${{ github.workflow }}" not in group:
            errors.append(
                f"{relative}: reusable concurrency group must include the caller github.workflow"
            )
        if (
            not isinstance(group, str)
            or "${{ github.event.pull_request.number || github.ref }}" not in group
        ):
            errors.append(
                f"{relative}: reusable concurrency group must include its stable pull-request/ref boundary"
            )
        if isinstance(group, str) and "${{ inputs.source_revision }}" in group:
            errors.append(
                f"{relative}: reusable concurrency group must not create a lane per source revision"
            )
    elif (
        not isinstance(group, str)
        or "${{ github.event.pull_request.number || github.ref }}" not in group
    ):
        errors.append(
            f"{relative}: repository workflow concurrency group must include its stable pull-request/ref boundary"
        )
    if concurrency.get("cancel-in-progress") != "${{ github.event_name == 'pull_request' }}":
        errors.append(f"{relative}: concurrency must cancel only pull_request runs")
    return errors


def _buildkite_bridge_errors(document: dict[str, Any], relative: Path) -> list[str]:
    if relative.as_posix() != BUILDKITE_BRIDGE_TEMPLATE_PATH:
        return []
    prefix = f"{relative}: Buildkite bridge"
    errors: list[str] = []
    triggers = document.get("on")
    if not isinstance(triggers, dict):
        return [f"{prefix} triggers must be an explicit mapping"]
    required_triggers = {"pull_request", "merge_group", "push", "release"}
    if set(triggers) != required_triggers:
        errors.append(
            f"{prefix} must declare exactly pull_request, merge_group, push, and release triggers"
        )
    if "pull_request_target" in triggers:
        errors.append(f"{prefix} must never use pull_request_target")
    if triggers.get("pull_request") is not None or triggers.get("merge_group") is not None:
        errors.append(
            f"{prefix} pull_request and merge_group triggers must not carry mutable filters"
        )
    if triggers.get("push") != {"branches": ["main"]} or triggers.get("release") != {
        "types": ["published"]
    }:
        errors.append(
            f"{prefix} protected triggers must be exactly main pushes and published releases"
        )
    if document.get("permissions") != {"contents": "read"}:
        errors.append(f"{prefix} must declare only contents: read at workflow scope")
    concurrency = document.get("concurrency")
    if not isinstance(concurrency, dict):
        errors.append(f"{prefix} must bound repository/ref concurrency")
    else:
        group = concurrency.get("group")
        required_dimensions = (
            "${{ github.repository }}",
            "${{ github.workflow }}",
            "${{ github.event.pull_request.number || github.ref }}",
        )
        if not isinstance(group, str) or any(
            dimension not in group for dimension in required_dimensions
        ):
            errors.append(
                f"{prefix} concurrency must bind repository, workflow, and stable pull-request/ref identity"
            )
        if concurrency.get("cancel-in-progress") != "${{ github.event_name == 'pull_request' }}":
            errors.append(f"{prefix} must cancel only pull_request runs")

    jobs = document.get("jobs")
    if not isinstance(jobs, dict):
        return [*errors, f"{prefix} jobs must be an explicit mapping"]
    required_jobs = {"classify", "fork_checks", "dispatch", "buildkite_required", "required"}
    if set(jobs) != required_jobs:
        errors.append(f"{prefix} must declare exactly {', '.join(sorted(required_jobs))}")
        return errors
    classify = jobs["classify"]
    fork_checks = jobs["fork_checks"]
    dispatch = jobs["dispatch"]
    buildkite_required = jobs["buildkite_required"]
    gate = jobs["required"]
    if not all(
        isinstance(job, dict) for job in (classify, fork_checks, dispatch, buildkite_required, gate)
    ):
        return [*errors, f"{prefix} every job must be a mapping"]

    source_expression = "${{ github.event.pull_request.head.sha || github.event.merge_group.head_sha || github.sha }}"
    classify_inputs = classify.get("with")
    if classify_inputs != {"source_revision": source_expression}:
        errors.append(
            f"{prefix} classifier must receive the exact observed PR/merge/source revision"
        )
    if (
        not isinstance(classify.get("uses"), str)
        or "reusable-metadata-validation.yml@" not in classify["uses"]
    ):
        errors.append(f"{prefix} classifier must use the pinned metadata workflow")
    if "secrets" in classify:
        errors.append(f"{prefix} classifier must be secretless")

    fork_condition = fork_checks.get("if")
    expected_fork_condition = (
        "needs.classify.result == 'success' && github.event_name == 'pull_request' && "
        "needs.classify.outputs.trust_classification == 'untrusted'"
    )
    if (
        not isinstance(fork_condition, str)
        or " ".join(fork_condition.split()) != expected_fork_condition
    ):
        errors.append(
            f"{prefix} fork checks must be guarded by successful untrusted-PR classification"
        )
    if fork_checks.get("needs") != "classify" or "secrets" in fork_checks:
        errors.append(
            f"{prefix} fork checks must depend only on classification and receive no secrets"
        )
    if (
        not isinstance(fork_checks.get("uses"), str)
        or "reusable-documentation-check.yml@" not in fork_checks["uses"]
    ):
        errors.append(f"{prefix} fork checks must use the pinned secretless documentation workflow")
    if fork_checks.get("with") != {"source_revision": "${{ github.event.pull_request.head.sha }}"}:
        errors.append(
            f"{prefix} fork checks must receive only the observed pull-request head revision"
        )

    dispatch_condition = dispatch.get("if")
    expected_dispatch_condition = (
        "needs.classify.result == 'success' && ( github.event_name != 'pull_request' || "
        "needs.classify.outputs.trust_classification == 'trusted' )"
    )
    if (
        not isinstance(dispatch_condition, str)
        or " ".join(dispatch_condition.split()) != expected_dispatch_condition
    ):
        errors.append(f"{prefix} dispatch must skip every pull request not classified trusted")
    if (
        dispatch.get("needs") != "classify"
        or not isinstance(dispatch.get("uses"), str)
        or "reusable-buildkite-dispatch.yml@" not in dispatch["uses"]
    ):
        errors.append(
            f"{prefix} dispatch must depend on classification and use the pinned Buildkite dispatcher"
        )
    dispatch_inputs = dispatch.get("with")
    expected_pipeline_class = "${{ (github.event_name == 'pull_request' || github.event_name == 'merge_group') && 'presubmit' || github.event_name == 'release' && 'release' || 'protected' }}"
    if dispatch_inputs != {
        "source_revision": source_expression,
        "pipeline_class": expected_pipeline_class,
    }:
        errors.append(
            f"{prefix} dispatch must pass the exact source revision and let the pinned dispatcher resolve the protected definition"
        )
    dispatch_secrets = dispatch.get("secrets")
    if dispatch_secrets != {
        "buildkite_dispatch_token": "${{ secrets.MINDCLADE_BUILDKITE_DISPATCH_TOKEN }}",
        "buildkite_pipeline": "${{ secrets.MINDCLADE_BUILDKITE_PIPELINE }}",
    }:
        errors.append(
            f"{prefix} dispatch must receive only its two explicitly mapped Buildkite secrets"
        )

    if (
        buildkite_required.get("needs") != ["classify", "dispatch"]
        or buildkite_required.get("if") != "needs.dispatch.result == 'success'"
    ):
        errors.append(
            f"{prefix} Buildkite verifier must run only after successful classified dispatch"
        )
    if buildkite_required.get("permissions") != {
        "actions": "read",
        "contents": "read",
        "id-token": "write",
    }:
        errors.append(
            f"{prefix} Buildkite verifier must authorize only evidence download and archive OIDC"
        )
    if (
        not isinstance(buildkite_required.get("uses"), str)
        or "reusable-required-check.yml@" not in buildkite_required["uses"]
    ):
        errors.append(f"{prefix} Buildkite verifier must use the pinned required-check workflow")
    required_inputs = buildkite_required.get("with")
    expected_required_inputs = {
        "source_revision": source_expression,
        "pipeline_definition_revision": "${{ needs.dispatch.outputs.pipeline_definition_revision }}",
        "build_id": "${{ needs.dispatch.outputs.build_id }}",
        "build_number": "${{ needs.dispatch.outputs.build_number }}",
        "correlation_id": "${{ needs.dispatch.outputs.correlation_id }}",
        "context_digest": "${{ needs.dispatch.outputs.context_digest }}",
    }
    if required_inputs != expected_required_inputs:
        errors.append(f"{prefix} Buildkite verifier must bind only the exact dispatch outputs")
    required_secrets = buildkite_required.get("secrets")
    if required_secrets != {
        "buildkite_cancel_token": "${{ secrets.MINDCLADE_BUILDKITE_CANCEL_TOKEN }}",
        "buildkite_evidence_token": "${{ secrets.MINDCLADE_BUILDKITE_EVIDENCE_TOKEN }}",
        "buildkite_pipeline": "${{ secrets.MINDCLADE_BUILDKITE_PIPELINE }}",
    }:
        errors.append(
            f"{prefix} verifier must receive only its explicitly mapped Buildkite secrets"
        )

    if (
        gate.get("name") != "Mindclade / Required"
        or gate.get("if") != "always()"
        or gate.get("permissions") != {}
    ):
        errors.append(
            f"{prefix} final gate must be the always-running permissionless Mindclade / Required context"
        )
    gate_env = gate.get("env")
    expected_gate_env = {
        "BUILDKITE_REQUIRED_RESULT": "${{ needs.buildkite_required.result }}",
        "CLASSIFY_RESULT": "${{ needs.classify.result }}",
        "DISPATCH_RESULT": "${{ needs.dispatch.result }}",
        "EVENT_NAME": "${{ github.event_name }}",
        "FORK_CHECKS_RESULT": "${{ needs.fork_checks.result }}",
        "TRUST_CLASSIFICATION": "${{ needs.classify.outputs.trust_classification }}",
    }
    if gate_env != expected_gate_env:
        errors.append(
            f"{prefix} final gate must consume only the exact job-result and trust outputs"
        )
    expected_gate_needs = ["classify", "fork_checks", "dispatch", "buildkite_required"]
    if (
        gate.get("needs") != expected_gate_needs
        or gate.get("runs-on") != "ubuntu-24.04"
        or gate.get("timeout-minutes") != 5
    ):
        errors.append(f"{prefix} final gate must use the exact bounded dependency closure")
    expected_gate_script = """set -euo pipefail
[[ "${CLASSIFY_RESULT}" == success ]]
case "${EVENT_NAME}:${TRUST_CLASSIFICATION}" in
  pull_request:untrusted)
    [[ "${FORK_CHECKS_RESULT}" == success ]]
    [[ "${DISPATCH_RESULT}" == skipped ]]
    [[ "${BUILDKITE_REQUIRED_RESULT}" == skipped ]]
    ;;
  pull_request:trusted)
    [[ "${FORK_CHECKS_RESULT}" == skipped ]]
    [[ "${DISPATCH_RESULT}" == success ]]
    [[ "${BUILDKITE_REQUIRED_RESULT}" == success ]]
    ;;
  merge_group:protected|push:protected|release:protected)
    [[ "${FORK_CHECKS_RESULT}" == skipped ]]
    [[ "${DISPATCH_RESULT}" == success ]]
    [[ "${BUILDKITE_REQUIRED_RESULT}" == success ]]
    ;;
  *)
    exit 1
    ;;
esac"""
    gate_steps = gate.get("steps")
    if (
        not isinstance(gate_steps, list)
        or len(gate_steps) != 1
        or not isinstance(gate_steps[0], dict)
        or set(gate_steps[0]) != {"name", "run"}
        or gate_steps[0].get("run", "").strip() != expected_gate_script
    ):
        errors.append(
            f"{prefix} final gate script must enforce the exact fork/trusted/protected result matrix"
        )
    return errors


def _buildkite_dispatch_errors(document: dict[str, Any], relative: Path) -> list[str]:
    if relative.as_posix() != BUILDKITE_DISPATCH_WORKFLOW_PATH:
        return []
    prefix = f"{relative}: Buildkite dispatcher"
    errors: list[str] = []
    triggers = document.get("on")
    call = triggers.get("workflow_call") if isinstance(triggers, dict) else None
    inputs = call.get("inputs") if isinstance(call, dict) else None
    if not isinstance(inputs, dict):
        return [f"{prefix} workflow_call inputs must be an explicit mapping"]
    if "pipeline_definition_revision" in inputs:
        errors.append(
            f"{prefix} must derive pipeline_definition_revision instead of accepting caller provenance"
        )

    jobs = document.get("jobs")
    dispatch = jobs.get("dispatch") if isinstance(jobs, dict) else None
    steps = dispatch.get("steps") if isinstance(dispatch, dict) else None
    if not isinstance(steps, list):
        return [*errors, f"{prefix} dispatch steps must be an explicit list"]
    by_id = {
        step.get("id"): step
        for step in steps
        if isinstance(step, dict) and isinstance(step.get("id"), str)
    }
    required_ids = {
        "context",
        "pins",
        "definition",
        "preflight",
        "create",
        "cancel",
        "result",
        "evidence",
    }
    if not required_ids.issubset(by_id):
        errors.append(f"{prefix} must declare the complete immutable definition-launch closure")
        return errors

    outputs = dispatch.get("outputs")
    if (
        not isinstance(outputs, dict)
        or outputs.get("pipeline_definition_revision")
        != "${{ steps.definition.outputs.pipeline_definition_revision }}"
    ):
        errors.append(
            f"{prefix} output must expose only the internally resolved definition revision"
        )

    definition = by_id["definition"]
    expected_definition_env = {
        "BASE_REVISION": "${{ steps.context.outputs.base_revision }}",
        "EXECUTION_TIER": "${{ steps.context.outputs.execution_tier }}",
        "PIPELINE_CLASS": "${{ inputs.pipeline_class }}",
        "SOURCE_REVISION": "${{ inputs.source_revision }}",
    }
    definition_script = definition.get("run")
    required_definition_fragments = (
        "untrusted:presubmit|trusted:presubmit)",
        'pipeline_definition_revision="${BASE_REVISION}"',
        "trusted:protected|release:release)",
        'pipeline_definition_revision="${SOURCE_REVISION}"',
        '[[ "${pipeline_definition_revision}" =~ ^[0-9a-f]{40}$ ]]',
        "printf 'pipeline_definition_revision=%s\\n'",
    )
    if (
        definition.get("env") != expected_definition_env
        or not isinstance(definition_script, str)
        or any(fragment not in definition_script for fragment in required_definition_fragments)
    ):
        errors.append(
            f"{prefix} must resolve the immutable definition from GitHub-observed base/source context"
        )

    create = by_id["create"]
    create_env = create.get("env")
    create_script = create.get("run")
    if (
        not isinstance(create_env, dict)
        or create_env.get("PIPELINE_DEFINITION_REVISION")
        != "${{ steps.definition.outputs.pipeline_definition_revision }}"
    ):
        errors.append(f"{prefix} launch must consume the internally resolved definition revision")
    if (
        not isinstance(create_script, str)
        or '--commit "${PIPELINE_DEFINITION_REVISION}"' not in create_script
        or '--commit "${SOURCE_REVISION}"' in create_script
    ):
        errors.append(
            f"{prefix} must launch Buildkite at the immutable definition revision before candidate checkout"
        )
    if (
        not isinstance(create_script, str)
        or '"PIPELINE_DEFINITION_REVISION", "SOURCE_REVISION"' not in create_script
    ):
        errors.append(
            f"{prefix} must pass separate definition and candidate revisions to Buildkite"
        )

    cancel = by_id["cancel"]
    cancel_script = cancel.get("run")
    if (
        not isinstance(cancel_script, str)
        or '--expected-pipeline-definition-revision "${PIPELINE_DEFINITION_REVISION}"'
        not in cancel_script
    ):
        errors.append(
            f"{prefix} cancellation must rebind the build to its immutable definition revision"
        )

    evidence_step = by_id["evidence"]
    evidence_inputs = evidence_step.get("with")
    if (
        not isinstance(evidence_inputs, dict)
        or evidence_inputs.get("pipeline-definition-revision")
        != "${{ steps.definition.outputs.pipeline_definition_revision }}"
    ):
        errors.append(f"{prefix} evidence must bind the internally resolved definition revision")
    return errors


def validate_workflows(root: Path) -> dict[str, Any]:
    errors: list[str] = []
    workflow_paths = files(
        root,
        (
            ".github/workflows/*.yml",
            ".github/workflows/*.yaml",
            "workflow-templates/*.yml",
            "workflow-templates/*.yaml",
        ),
    )
    for path in workflow_paths:
        relative = path.relative_to(root)
        document, parse_error = _parsed_yaml(path, root)
        if parse_error:
            errors.append(parse_error)
            continue
        if not isinstance(document, dict):
            errors.append(f"{relative}: workflow root must be a mapping")
            continue
        if "on" not in document:
            errors.append(f"{relative}: missing workflow trigger")
        if path.name.startswith("reusable-"):
            errors.extend(_workflow_call_interface_errors(path, document, relative))
        errors.extend(_required_check_archive_errors(document, relative))
        errors.extend(_bounded_concurrency_errors(document, relative))
        errors.extend(_buildkite_dispatch_errors(document, relative))
        errors.extend(_buildkite_bridge_errors(document, relative))
        for _, key, value in _walk_yaml(document):
            if key == "run" and isinstance(value, str) and _run_uses_caller_inputs(value):
                errors.append(
                    f"{relative}: run scripts must receive caller inputs through the environment"
                )
    action_dir = root / ".github/actions"
    action_paths = (
        sorted({*action_dir.glob("*/action.yml"), *action_dir.glob("*/action.yaml")})
        if action_dir.is_dir()
        else []
    )
    for path in action_paths:
        relative = path.relative_to(root)
        document, parse_error = _parsed_yaml(path, root)
        if parse_error:
            errors.append(parse_error)
            continue
        if not isinstance(document, dict):
            errors.append(f"{relative}: action root must be a mapping")
            continue
        for key in ("name", "description", "runs"):
            if key not in document:
                errors.append(f"{relative}: composite action missing {key}")
        runs = document.get("runs")
        if not isinstance(runs, dict) or runs.get("using") != "composite":
            errors.append(f"{relative}: action must use the composite runtime")
        if not isinstance(runs, dict) or not isinstance(runs.get("steps"), list):
            errors.append(f"{relative}: composite action missing steps")
        for _, key, value in _walk_yaml(document):
            if key == "run" and isinstance(value, str) and _run_uses_caller_inputs(value):
                errors.append(
                    f"{relative}: run scripts must receive caller inputs through the environment"
                )
    return result(not errors, errors, check="workflows")


def _relative_paths(value: str | None) -> list[str]:
    if not value:
        return []
    return [entry.strip() for entry in value.splitlines() if entry.strip()]


def _repository_path(root: Path, value: Any) -> tuple[Path | None, str | None]:
    if not isinstance(value, str) or not value or value != value.strip():
        return None, "must be a non-empty repository-relative path"
    requested = Path(value)
    if requested.is_absolute() or not requested.parts or ".." in requested.parts:
        return None, "must be a non-empty repository-relative path without traversal"
    resolved_root = root.resolve()
    candidate = (resolved_root / requested).resolve()
    if candidate == resolved_root or not candidate.is_relative_to(resolved_root):
        return None, "must resolve inside the repository root"
    return candidate, None


def _markdown_target(raw_target: str) -> str:
    value = raw_target.strip()
    if value.startswith("<"):
        closing = value.find(">", 1)
        return value[1:closing] if closing > 1 else ""
    return value.split(maxsplit=1)[0] if value else ""


def _reference_label(value: str) -> str:
    return " ".join(value.split()).casefold()


def _markdown_links(text: str) -> tuple[list[str], list[str]]:
    """Return inline/reference targets plus malformed-reference errors."""
    definitions: dict[str, str] = {}
    for match in re.finditer(r"(?m)^[ \t]{0,3}\[([^\]\n]+)\]:[ \t]*(\S.*)$", text):
        target = _markdown_target(match.group(2))
        if target:
            definitions[_reference_label(match.group(1))] = target

    targets = [
        _markdown_target(match.group(1))
        for match in re.finditer(r"!?\[[^\]\n]*\]\(([^)\n]+)\)", text)
    ]
    errors: list[str] = []
    occupied: list[tuple[int, int]] = []
    for match in re.finditer(r"!?\[([^\]\n]+)\]\[([^\]\n]*)\]", text):
        occupied.append(match.span())
        label = _reference_label(match.group(2) or match.group(1))
        target = definitions.get(label)
        if target is None:
            errors.append(f"undefined Markdown reference: {match.group(2) or match.group(1)}")
        else:
            targets.append(target)

    # Shortcut references are only links when a matching definition exists.
    # Exclude explicit-reference spans already handled above.
    for match in re.finditer(r"!?\[([^\]\n]+)\](?![\[(])", text):
        if any(start <= match.start() < end for start, end in occupied):
            continue
        target = definitions.get(_reference_label(match.group(1)))
        if target is not None:
            targets.append(target)
    return targets, errors


def _markdown_link_path(root: Path, document: Path, target: str) -> tuple[Path | None, str | None]:
    try:
        decoded = urllib.parse.unquote(target)
        parsed = urllib.parse.urlsplit(decoded)
    except ValueError:
        return None, "is not a valid URL"
    if parsed.scheme or parsed.netloc or target.startswith("//"):
        return None, "is not a repository-local path"
    if not parsed.path:
        return document, None
    requested = Path(parsed.path)
    if requested.is_absolute():
        return None, "must not be absolute"
    resolved_root = root.resolve()
    candidate = (document.parent / requested).resolve()
    if not candidate.is_relative_to(resolved_root):
        return None, "must not traverse outside the repository root"
    return candidate, None


def _review_metadata_errors(relative: str, text: str) -> list[str]:
    errors: list[str] = []
    review_dates = re.findall(r"(?mi)^Last reviewed:\s*(\S+)\s*$", text)
    cadences = re.findall(r"(?mi)^Review cadence:\s*(\S(?:.*\S)?)\s*$", text)
    if len(review_dates) != 1:
        errors.append(f"{relative}: must declare exactly one Last reviewed: YYYY-MM-DD value")
        return errors
    if len(cadences) != 1:
        errors.append(f"{relative}: must declare exactly one Review cadence: N days value")
        return errors
    try:
        reviewed = dt.date.fromisoformat(review_dates[0])
    except ValueError:
        errors.append(f"{relative}: Last reviewed must be an ISO YYYY-MM-DD date")
        return errors
    cadence_match = re.fullmatch(r"([1-9][0-9]{0,2}) days", cadences[0])
    if cadence_match is None or int(cadence_match.group(1)) > 366:
        errors.append(f"{relative}: Review cadence must be between 1 and 366 days")
        return errors
    today = dt.date.today()
    cadence = dt.timedelta(days=int(cadence_match.group(1)))
    if reviewed > today:
        errors.append(f"{relative}: Last reviewed date cannot be in the future")
    elif reviewed + cadence < today:
        errors.append(f"{relative}: review metadata is stale")
    return errors


def _nonempty_text_file(path: Path) -> bool:
    try:
        return path.is_file() and bool(path.read_text(encoding="utf-8").strip())
    except (OSError, UnicodeError):
        return False


def _markdown_errors(path: Path, root: Path) -> list[str]:
    relative = path.relative_to(root).as_posix()
    try:
        text = path.read_text(encoding="utf-8")
    except (OSError, UnicodeError) as exc:
        return [f"{relative}: cannot read Markdown: {exc}"]
    errors: list[str] = []
    lines = text.splitlines()
    first = next((line for line in lines if line.strip()), "")
    if not re.fullmatch(r"# [^#].+", first):
        errors.append(f"{relative}: first content line must be one H1 title")
    headings = {
        match.group(1).strip() for line in lines if (match := re.fullmatch(r"## ([^#].+)", line))
    }
    for heading in sorted(DOCUMENTATION_REQUIRED_HEADINGS.get(relative, frozenset())):
        if heading not in headings:
            errors.append(f"{relative}: missing required section {heading}")
    if relative in DOCUMENTATION_REQUIRED_HEADINGS:
        if not re.search(r"(?mi)^Owner:\s+@mindclade/[a-z0-9-]+\s*$", text):
            errors.append(f"{relative}: missing explicit Mindclade owner metadata")
        errors.extend(_review_metadata_errors(relative, text))
    if re.search(r"(?i)(?:\bTODO\b|\bTBD\b|\bPLACEHOLDER\b|lorem ipsum)", text):
        errors.append(f"{relative}: contains placeholder documentation")
    link_targets, reference_errors = _markdown_links(text)
    errors.extend(f"{relative}: {error}" for error in reference_errors)
    for target in link_targets:
        if not target or target.startswith(("#", "https://", "http://", "mailto:")):
            continue
        candidate, target_error = _markdown_link_path(root, path, target)
        if target_error or candidate is None or not candidate.exists():
            errors.append(f"{relative}: local link target does not exist: {target}")
    return errors


def _complete_metadata_value(value: Any) -> bool:
    if value is None:
        return False
    if isinstance(value, str):
        return bool(value.strip())
    if isinstance(value, dict):
        return bool(value) and all(_complete_metadata_value(child) for child in value.values())
    if isinstance(value, list):
        return bool(value) and all(_complete_metadata_value(child) for child in value)
    return isinstance(value, (bool, int))


def validate_metadata(
    root: Path, component_path: str = "component.yaml", required_files: Iterable[str] = ()
) -> dict[str, Any]:
    resolved_root = root.resolve()
    component, path_error = _repository_path(resolved_root, component_path)
    if path_error:
        return result(False, [f"{component_path}: {path_error}"], check="metadata")
    assert component is not None
    if not component.is_file():
        return result(False, [f"{component_path}: missing"], check="metadata")
    document, parse_error = _parsed_yaml(component, resolved_root)
    errors: list[str] = []
    if parse_error:
        errors.append(parse_error)
        document = {}
    if not isinstance(document, dict):
        errors.append(f"{component_path}: document root must be a mapping")
        document = {}
    api_version = document.get("apiVersion")
    if api_version not in {"mindclade.io/v1alpha1", "components.mindclade.dev/v1alpha1"}:
        errors.append(f"{component_path}: apiVersion must be a supported Component contract")
    if document.get("kind") != "Component":
        errors.append(f"{component_path}: kind must be Component")
    metadata = document.get("metadata")
    if not isinstance(metadata, dict):
        errors.append(f"{component_path}: metadata must be a mapping")
        metadata = {}
    if not isinstance(metadata.get("name"), str) or not metadata["name"].strip():
        errors.append(f"{component_path}: metadata.name must be a non-empty string")
    spec = document.get("spec")
    if not isinstance(spec, dict):
        errors.append(f"{component_path}: spec must be a mapping")
        spec = {}
    for key in ("owner", "maturity"):
        value = spec.get(key)
        if not isinstance(value, str) or not value.strip():
            errors.append(f"{component_path}: spec.{key} must be a non-empty string")
    if api_version == "mindclade.io/v1alpha1":
        for key in ("repository_class", "trust_tier", "recovery_tier"):
            value = spec.get(key)
            if not isinstance(value, str) or not value.strip():
                errors.append(f"{component_path}: spec.{key} must be a non-empty string")
    dependencies = spec.get("dependencies")
    if not isinstance(dependencies, list):
        errors.append(f"{component_path}: spec.dependencies must be a list")
    else:
        for index, dependency in enumerate(dependencies):
            valid = isinstance(dependency, str) and bool(dependency.strip())
            valid = valid or (
                isinstance(dependency, dict)
                and isinstance(dependency.get("component"), str)
                and bool(dependency["component"].strip())
                and _complete_metadata_value(dependency)
            )
            if not valid:
                errors.append(
                    f"{component_path}: spec.dependencies[{index}] must be a non-empty string or mapping with a non-empty component key"
                )
    release = spec.get("release")
    if not isinstance(release, dict):
        errors.append(f"{component_path}: spec.release must be a mapping")
    elif api_version == "mindclade.io/v1alpha1":
        for key in ("strategy", "artifact"):
            value = release.get(key)
            if not isinstance(value, str) or not value.strip():
                errors.append(f"{component_path}: spec.release.{key} must be a non-empty string")
        if not isinstance(release.get("immutable"), bool):
            errors.append(f"{component_path}: spec.release.immutable must be a boolean")
        if release and not _complete_metadata_value(release):
            errors.append(f"{component_path}: spec.release values must be complete")
    else:
        mode = release.get("mode")
        if not isinstance(mode, str) or not mode.strip():
            errors.append(f"{component_path}: spec.release.mode must be a non-empty string")
        for key in ("artifact", "version"):
            value = release.get(key)
            if value is not None and (not isinstance(value, str) or not value.strip()):
                errors.append(
                    f"{component_path}: spec.release.{key} must be null or a non-empty string"
                )
        if not isinstance(release.get("public"), bool):
            errors.append(f"{component_path}: spec.release.public must be a boolean")
        controls = release.get("controls")
        if not isinstance(controls, list) or any(
            not isinstance(control, str) or not control.strip() for control in controls
        ):
            errors.append(
                f"{component_path}: spec.release.controls must be a list of non-empty strings"
            )
        if mode != "none" and (
            not isinstance(release.get("artifact"), str)
            or not isinstance(release.get("version"), str)
        ):
            errors.append(f"{component_path}: an active release must declare artifact and version")
        for key in ("type", "visibility", "dataClassification", "description"):
            value = spec.get(key)
            if not isinstance(value, str) or not value.strip():
                errors.append(f"{component_path}: spec.{key} must be a non-empty string")
    for required_path in required_files:
        candidate, required_error = _repository_path(resolved_root, required_path)
        if required_error:
            errors.append(f"{required_path}: {required_error}")
        elif candidate is None or not _nonempty_text_file(candidate):
            errors.append(f"{required_path}: missing or empty")
    return result(not errors, errors, check="metadata")


def validate_documentation(root: Path, documentation_roots: Iterable[str] = ()) -> dict[str, Any]:
    paths = list(documentation_roots) or [
        "README.md",
        "CONTRIBUTING.md",
        "GOVERNANCE.md",
        "SECURITY.md",
        "SUPPORT.md",
        "profile/README.md",
    ]
    resolved_root = root.resolve()
    errors: list[str] = []
    for path in paths:
        candidate, path_error = _repository_path(resolved_root, path)
        if path_error:
            errors.append(f"{path}: {path_error}")
            continue
        assert candidate is not None
        if candidate.is_file():
            if not _nonempty_text_file(candidate):
                errors.append(f"{path}: missing or empty")
            elif candidate.suffix.lower() == ".md":
                errors.extend(_markdown_errors(candidate, resolved_root))
        elif candidate.is_dir():
            markdown_files = sorted(
                markdown.resolve()
                for markdown in candidate.rglob("*.md")
                if markdown.resolve().is_relative_to(resolved_root)
            )
            if not markdown_files:
                errors.append(f"{path}: contains no non-empty Markdown files")
            for markdown in markdown_files:
                if not _nonempty_text_file(markdown):
                    errors.append(f"{markdown.relative_to(resolved_root)}: missing or empty")
                else:
                    errors.extend(_markdown_errors(markdown, resolved_root))
        else:
            errors.append(f"{path}: missing or empty")
    return result(not errors, errors, check="documentation")


def validate_schemas_and_fixtures(root: Path) -> dict[str, Any]:
    errors: list[str] = []
    for path in files(root, ("schemas/*.json", "tests/fixtures/*.json")):
        try:
            decoded = json.loads(path.read_text(encoding="utf-8"))
        except json.JSONDecodeError as exc:
            errors.append(f"{path.relative_to(root)}: invalid JSON: {exc.msg}")
            continue
        if path.parent.name == "schemas" and not isinstance(decoded, dict):
            errors.append(f"{path.relative_to(root)}: schema root must be an object")
        if path.parent.name == "fixtures" and not isinstance(decoded, dict):
            errors.append(f"{path.relative_to(root)}: fixture root must be an object")
    return result(not errors, errors, check="schemas_and_fixtures")


CHECKS = {
    "inventory": validate_inventory,
    "pins": validate_pins,
    "permissions": validate_permissions,
    "workflows": validate_workflows,
    "metadata": validate_metadata,
    "documentation": validate_documentation,
    "schemas": validate_schemas_and_fixtures,
}


def validate(root: Path, names: Iterable[str] | None = None) -> dict[str, Any]:
    selected = list(names or CHECKS)
    checks = {name: CHECKS[name](root) for name in selected}
    errors = [error for check in checks.values() for error in check["errors"]]
    return result(not errors, errors, checks=checks, root=str(root.resolve()))


def selected_checks(value: str | None) -> list[str] | None:
    if value is None:
        return None
    selected = [name.strip() for name in value.split(",")]
    if not selected or any(not name for name in selected):
        raise ValueError("--checks must be a non-empty comma-separated list")
    unknown = sorted(set(selected) - set(CHECKS))
    if unknown:
        raise ValueError("unknown checks: " + ", ".join(unknown))
    return selected


def _nested(payload: dict[str, Any], *keys: str) -> Any:
    value: Any = payload
    for key in keys:
        if not isinstance(value, dict):
            return None
        value = value.get(key)
    return value


def _workflow_identity() -> tuple[str, str]:
    reference = os.environ.get("GITHUB_WORKFLOW_REF", "")
    match = re.search(
        r"(\.github/workflows/[A-Za-z0-9._-]+\.ya?ml)(?:@([0-9a-f]{40}))?", reference, re.IGNORECASE
    )
    workflow_ref = match.group(1) if match else ""
    workflow_revision = match.group(2) if match and match.group(2) else ""
    workflow_sha = os.environ.get("GITHUB_WORKFLOW_SHA", "")
    if SHA.fullmatch(workflow_sha):
        workflow_revision = workflow_sha
    elif not workflow_revision and SHA.fullmatch(os.environ.get("GITHUB_SHA", "")):
        workflow_revision = os.environ["GITHUB_SHA"]
    return workflow_ref, workflow_revision


def validate_context_schema(
    context: dict[str, Any], schema_path: Path = ROOT / "schemas/trusted_context.schema.json"
) -> list[str]:
    """Validate the fixed trusted-context contract without a runtime dependency."""
    try:
        schema = json.loads(schema_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        return [f"trusted context schema unavailable: {exc}"]
    errors: list[str] = []
    required = schema.get("required", [])
    properties = schema.get("properties", {})
    errors.extend(f"missing {key}" for key in required if key not in context)
    if schema.get("additionalProperties") is False:
        errors.extend(f"unexpected {key}" for key in context if key not in properties)
    if context.get("schema_version") != "1.0.0":
        errors.append("schema_version must be 1.0.0")
    if not isinstance(context.get("repository"), str) or not re.fullmatch(
        r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", context["repository"]
    ):
        errors.append("repository is invalid")
    if not isinstance(context.get("actor"), str) or not re.fullmatch(
        r"[A-Za-z0-9][A-Za-z0-9-]{0,38}(?:\[bot\])?", context["actor"]
    ):
        errors.append("actor is invalid")
    if context.get("event_name") not in {
        "pull_request",
        "push",
        "release",
        "schedule",
        "workflow_dispatch",
        "merge_group",
    }:
        errors.append("event_name is invalid")
    if not isinstance(context.get("ref"), str) or not re.fullmatch(
        r"refs/(heads|tags)/[A-Za-z0-9._/-]+", context["ref"]
    ):
        errors.append("ref is invalid")
    for key in ("source_revision", "workflow_revision"):
        if not isinstance(context.get(key), str) or not SHA.fullmatch(context[key]):
            errors.append(f"{key} is not a lowercase SHA")
    if context.get("base_revision") is not None and (
        not isinstance(context["base_revision"], str) or not SHA.fullmatch(context["base_revision"])
    ):
        errors.append("base_revision is invalid")
    if not isinstance(context.get("workflow_ref"), str) or not re.fullmatch(
        r"\.github/workflows/[A-Za-z0-9._-]+\.ya?ml", context["workflow_ref"]
    ):
        errors.append("workflow_ref is invalid")
    if not isinstance(context.get("fork"), bool) or not isinstance(
        context.get("ref_protected"), bool
    ):
        errors.append("fork/ref_protected must be booleans")
    if context.get("source_trust") not in {"untrusted", "trusted", "protected"}:
        errors.append("source_trust is invalid")
    if context.get("execution_tier") not in {"untrusted", "trusted", "release"}:
        errors.append("execution_tier is invalid")
    if (
        context.get("event_name") in {"pull_request", "merge_group"}
        and context.get("execution_tier") != "untrusted"
    ):
        errors.append("pull_request and merge_group must use untrusted execution tier")
    if context.get("event_name") == "release" and (
        context.get("execution_tier") != "release"
        or context.get("source_trust") != "protected"
        or context.get("fork")
        or not context.get("ref_protected")
        or not str(context.get("ref", "")).startswith("refs/tags/")
    ):
        errors.append("release context does not meet protected release constraints")
    return errors


def trusted_context(
    event_path: Path,
    expected_revision: str,
    allowed_tiers: set[str],
    implementation_root: Path = ROOT,
) -> dict[str, Any]:
    payload = json.loads(event_path.read_text(encoding="utf-8"))
    if not isinstance(payload, dict):
        raise ValueError("event payload root must be an object")
    event_name = os.environ.get("GITHUB_EVENT_NAME", "")
    release_target = _nested(payload, "release", "target_commitish")
    release_revision = (
        release_target
        if isinstance(release_target, str) and SHA.fullmatch(release_target)
        else None
    )
    source_revision = (
        _nested(payload, "pull_request", "head", "sha")
        or _nested(payload, "merge_group", "head_sha")
        or release_revision
        or payload.get("after")
        or os.environ.get("GITHUB_SHA", "")
    )
    base_revision = (
        _nested(payload, "pull_request", "base", "sha")
        or _nested(payload, "merge_group", "base_sha")
        or payload.get("before")
        or None
    )
    fork_provenance_ambiguous = False
    if event_name == "pull_request":
        head_repository = _nested(payload, "pull_request", "head", "repo")
        observed_fork = head_repository.get("fork") if isinstance(head_repository, dict) else None
        if type(observed_fork) is not bool:
            # Fail safe before assigning any trust label. The context remains
            # schema-valid and explicitly untrusted so denied-step outputs
            # cannot be mistaken for trusted provenance by a caller.
            fork_provenance_ambiguous = True
            fork = True
        else:
            fork = observed_fork
    else:
        fork = False
    head_ref = _nested(payload, "pull_request", "head", "ref")
    context_ref = os.environ.get("GITHUB_REF", "")
    if (
        event_name == "pull_request"
        and isinstance(head_ref, str)
        and re.fullmatch(r"[A-Za-z0-9._/-]+", head_ref)
    ):
        context_ref = "refs/heads/" + head_ref
    ref_protected = os.environ.get("GITHUB_REF_PROTECTED", "").lower() == "true"
    release = payload.get("release") if isinstance(payload.get("release"), dict) else {}
    if event_name in {"pull_request", "merge_group"}:
        execution_tier = "untrusted"
    elif event_name == "release":
        execution_tier = "release"
    elif ref_protected:
        execution_tier = "trusted"
    else:
        execution_tier = "untrusted"
    if event_name == "release":
        source_trust = "protected"
    elif event_name == "pull_request":
        # A protected base ref says nothing about pull-request head
        # provenance, so it must never elevate the source classification.
        source_trust = "untrusted" if fork else "trusted"
    elif ref_protected:
        source_trust = "protected"
    else:
        source_trust = "trusted"
    workflow_ref, workflow_revision = _workflow_identity()
    context = {
        "schema_version": "1.0.0",
        "correlation_id": digest(
            {
                "run_id": os.environ.get("GITHUB_RUN_ID", ""),
                "attempt": os.environ.get("GITHUB_RUN_ATTEMPT", ""),
                "source_revision": source_revision,
            }
        )[:32],
        "repository": os.environ.get("GITHUB_REPOSITORY", ""),
        "actor": os.environ.get("GITHUB_ACTOR", ""),
        "event_name": event_name,
        "ref": context_ref,
        "source_revision": source_revision,
        "base_revision": base_revision,
        "workflow_ref": workflow_ref,
        "workflow_revision": workflow_revision,
        "fork": fork,
        "ref_protected": ref_protected,
        "source_trust": source_trust,
        "execution_tier": execution_tier,
    }
    reason_code = "accepted"
    verdict = "allow"
    if event_name == "pull_request_target":
        verdict, reason_code = "deny", "pull_request_target_forbidden"
    elif fork_provenance_ambiguous:
        verdict, reason_code = "deny", "ambiguous_fork_context"
    elif not SHA.fullmatch(expected_revision):
        verdict, reason_code = "deny", "invalid_expected_source_revision"
    elif source_revision != expected_revision:
        verdict, reason_code = "deny", "source_revision_mismatch"
    elif execution_tier not in allowed_tiers:
        verdict, reason_code = "deny", "execution_tier_not_allowed"
    elif event_name == "release" and (
        not ref_protected
        or bool(release.get("prerelease"))
        or bool(release.get("draft"))
        or payload.get("action") != "published"
    ):
        verdict, reason_code = "deny", "release_not_published_protected"
    else:
        schema_errors = validate_context_schema(context)
        if schema_errors:
            verdict, reason_code = "deny", "invalid_context_schema"
    return {
        "verdict": verdict,
        "reason_code": reason_code,
        "context": context,
        "context_json": canonical_json(context),
        # Digest is an external action output, so it carries its algorithm
        # marker; the context schema deliberately does not contain it.
        "context_digest": "sha256:" + digest(context),
        "implementation_root": str(implementation_root.resolve()),
    }


def command_context(args: argparse.Namespace) -> int:
    try:
        allowed = {tier.strip() for tier in args.allowed_execution_tiers.split(",") if tier.strip()}
        outcome = trusted_context(
            Path(args.event_path),
            args.expected_source_revision,
            allowed,
            Path(args.implementation_root),
        )
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        outcome = {
            "verdict": "deny",
            "reason_code": "invalid_event_payload",
            "context": {},
            "context_json": "{}",
            "context_digest": "sha256:" + digest({}),
            "implementation_root": str(Path(args.implementation_root).resolve()),
            "error": str(exc),
        }
    context = outcome["context"]
    write_output(
        args.github_output,
        {
            "verdict": outcome["verdict"],
            "reason_code": outcome["reason_code"],
            "context_json": outcome["context_json"],
            "context_digest": outcome["context_digest"],
            "correlation_id": context.get("correlation_id", ""),
            "source_revision": context.get("source_revision", ""),
            "base_revision": context.get("base_revision", ""),
            "source_trust": context.get("source_trust", ""),
            "execution_tier": context.get("execution_tier", ""),
            "implementation_root": outcome["implementation_root"],
        },
    )
    print(canonical_json(outcome))
    return 0 if outcome["verdict"] == "allow" else 1


def command_validate(args: argparse.Namespace, names: Iterable[str] | None = None) -> int:
    root = Path(args.root)
    if args.command == "metadata":
        required_files = _relative_paths(args.required_files)
        outcome = validate_metadata(root, args.component_path, required_files)
        closure_paths = [args.component_path, *required_files]
    elif args.command == "documentation":
        documentation_roots = _relative_paths(args.documentation_roots)
        outcome = validate_documentation(root, documentation_roots)
        closure_paths = []
        for relative in documentation_roots or list(DOCUMENTATION_REQUIRED_HEADINGS):
            candidate, path_error = _repository_path(root.resolve(), relative)
            if path_error or candidate is None or not candidate.is_dir():
                closure_paths.append(relative)
            else:
                closure_paths.extend(
                    markdown.relative_to(root.resolve()).as_posix()
                    for markdown in sorted(candidate.rglob("*.md"))
                    if markdown.resolve().is_relative_to(root.resolve())
                )
    else:
        outcome = validate(root, names)
        closure_paths = None
    closure_digest = source_closure_digest(root, closure_paths)
    outcome.update(
        {
            "verdict": "allow" if outcome["ok"] else "deny",
            "reason_code": "accepted" if outcome["ok"] else "validation_failed",
            "closure_digest": closure_digest,
            "violations_json": canonical_json(outcome["errors"]),
            "implementation_root": str(Path(args.implementation_root).resolve()),
        }
    )
    write_output(
        args.github_output,
        {
            "verdict": outcome["verdict"],
            "reason_code": outcome["reason_code"],
            "closure_digest": outcome["closure_digest"],
            "violations_json": outcome["violations_json"],
            "implementation_root": outcome["implementation_root"],
        },
    )
    print(canonical_json(outcome))
    return 0 if outcome["ok"] else 1


def parser() -> argparse.ArgumentParser:
    command = argparse.ArgumentParser(description=__doc__)
    subcommands = command.add_subparsers(dest="command", required=True)
    context = subcommands.add_parser("context")
    context.add_argument("--event-path", required=True)
    context.add_argument("--expected-source-revision", required=True)
    context.add_argument("--allowed-execution-tiers", required=True)
    context.add_argument("--github-output")
    context.add_argument("--implementation-root", default=str(ROOT))
    validate_command = subcommands.add_parser("validate")
    validate_command.add_argument("--root", required=True)
    validate_command.add_argument("--checks")
    validate_command.add_argument("--github-output")
    validate_command.add_argument("--implementation-root", default=str(ROOT))
    template_pins = subcommands.add_parser("template-pins")
    template_pins.add_argument("--root", required=True)
    template_pins.add_argument("--approved-main-revision", required=True)
    for name in CHECKS:
        check = subcommands.add_parser(name)
        check.add_argument("--root", required=True)
        check.add_argument("--github-output")
        check.add_argument("--implementation-root", default=str(ROOT))
        if name == "metadata":
            check.add_argument("--component-path", default="component.yaml")
            check.add_argument("--required-files")
        if name == "documentation":
            check.add_argument("--documentation-roots")
    return command


def main(argv: list[str] | None = None) -> int:
    args = parser().parse_args(argv)
    if args.command == "context":
        return command_context(args)
    if args.command == "template-pins":
        outcome = validate_template_pins(Path(args.root), args.approved_main_revision)
        print(canonical_json(outcome))
        return 0 if outcome["ok"] else 1
    if args.command == "validate":
        try:
            return command_validate(args, selected_checks(args.checks))
        except ValueError as exc:
            print(canonical_json({"ok": False, "error": str(exc)}), file=sys.stderr)
            return 2
    return command_validate(args, [args.command])


if __name__ == "__main__":
    raise SystemExit(main())
