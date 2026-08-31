#!/usr/bin/env python3
# pyright: basic, reportArgumentType=false, reportAttributeAccessIssue=false, reportCallIssue=false, reportOperatorIssue=false, reportOptionalMemberAccess=false, reportOptionalSubscript=false
"""Create, validate, and transport canonical CI evidence without third-party Python."""

from __future__ import annotations

import argparse
import datetime as dt
import email.utils
import hashlib
import json
import os
import random
import re
import stat
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from collections.abc import Callable
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
BUILDKITE_API = "https://api.buildkite.com/v2"
BUILDKITE_UUID = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$")
BUILDKITE_BUILD_NUMBER = re.compile(r"^[1-9][0-9]*$")
GIT_SHA = re.compile(r"^[0-9a-f]{40}$")
SHA256_DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
ARTIFACT_REPORT_PATH = re.compile(r"^reports/[A-Za-z0-9._-]+$")
MAX_API_RESPONSE_BYTES = 1024 * 1024
MAX_REDIRECT_RESPONSE_BYTES = 64 * 1024
MAX_EVIDENCE_BYTES = 1024 * 1024
MAX_REPORT_FILES = 32
MAX_REPORT_BYTES = 16 * 1024 * 1024
MAX_REPORT_AGGREGATE_BYTES = 64 * 1024 * 1024
RETRYABLE_HTTP_STATUS = frozenset({408, 429, 500, 502, 503, 504})
RETRY_BASE_DELAYS = (0.5, 1.0, 2.0)
MAX_RETRY_DELAY_SECONDS = 30.0
REQUEST_TIMEOUT_SECONDS = 15.0
DEADLINE_EXCEEDED = "Buildkite evidence verification deadline exceeded"


class _NoRedirectHandler(urllib.request.HTTPRedirectHandler):
    def redirect_request(
        self, request: Any, file_pointer: Any, code: int, message: str, headers: Any, new_url: str
    ) -> None:
        return None


def _open_without_redirects(request: urllib.request.Request, timeout: int) -> Any:
    return urllib.request.build_opener(_NoRedirectHandler()).open(request, timeout=timeout)


def _read_bounded(response: Any, limit: int, description: str) -> bytes:
    payload = response.read(limit + 1)
    if len(payload) > limit:
        raise RuntimeError(f"{description} exceeded the maximum allowed size")
    return payload


def _canonical_build_id(value: Any) -> str:
    if not isinstance(value, str) or not BUILDKITE_UUID.fullmatch(value):
        raise ValueError("Buildkite build id must be a canonical lowercase UUID")
    return value


def _canonical_build_number(value: Any) -> str:
    if isinstance(value, bool):
        raise ValueError("Buildkite build number must be a positive integer")
    text = str(value)
    if not BUILDKITE_BUILD_NUMBER.fullmatch(text):
        raise ValueError("Buildkite build number must be a positive integer")
    return text


def _canonical_source_revision(value: Any) -> str:
    if not isinstance(value, str) or not GIT_SHA.fullmatch(value):
        raise ValueError("source revision must be a canonical lowercase 40-character Git SHA")
    return value


def _validate_build_response(
    response: dict[str, Any],
    build_id: str,
    build_number: str,
    expected_commit: str | None = None,
) -> None:
    if response.get("id") != build_id:
        raise RuntimeError("Buildkite response build id mismatch")
    response_number = response.get("number")
    if (
        isinstance(response_number, bool)
        or not isinstance(response_number, int)
        or str(response_number) != build_number
    ):
        raise RuntimeError("Buildkite response build number mismatch")
    if expected_commit is not None and response.get("commit") != expected_commit:
        raise RuntimeError("Buildkite response commit mismatch")


def canonical_json(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def sha256(value: Any) -> str:
    if isinstance(value, bytes):
        payload = value
    else:
        text = value if isinstance(value, str) else canonical_json(value)
        payload = text.encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


def utc_now() -> str:
    return dt.datetime.now(dt.UTC).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def load_json(path: str | Path) -> Any:
    return json.loads(Path(path).read_text(encoding="utf-8"))


def write_json(path: str | Path, value: Any) -> None:
    destination = Path(path)
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_text(canonical_json(value) + "\n", encoding="utf-8")


def write_output(path: str | None, values: dict[str, Any]) -> None:
    if not path:
        return
    with Path(path).open("a", encoding="utf-8") as output:
        for key, value in values.items():
            output.write(f"{key}={value}\n")


def _type_matches(value: Any, expected: str) -> bool:
    return {
        "object": isinstance(value, dict),
        "array": isinstance(value, list),
        "string": isinstance(value, str),
        "integer": isinstance(value, int) and not isinstance(value, bool),
        "number": isinstance(value, (int, float)) and not isinstance(value, bool),
        "boolean": isinstance(value, bool),
        "null": value is None,
    }.get(expected, True)


def _resolve_ref(schema: dict[str, Any], reference: str) -> dict[str, Any]:
    if not reference.startswith("#/"):
        raise ValueError(f"unsupported schema reference {reference}")
    resolved: Any = schema
    for part in reference[2:].split("/"):
        resolved = resolved[part.replace("~1", "/").replace("~0", "~")]
    if not isinstance(resolved, dict):
        raise ValueError(f"schema reference {reference} is not an object")
    return resolved


def validate_schema(
    value: Any,
    schema: dict[str, Any],
    location: str = "$",
    root_schema: dict[str, Any] | None = None,
) -> list[str]:
    """A deliberately small, strict JSON-Schema evaluator for our two schemas."""
    root_schema = root_schema or schema
    if "$ref" in schema:
        return validate_schema(
            value, _resolve_ref(root_schema, schema["$ref"]), location, root_schema
        )
    errors: list[str] = []
    if "const" in schema and value != schema["const"]:
        errors.append(f"{location}: expected constant {schema['const']!r}")
    if "enum" in schema and value not in schema["enum"]:
        errors.append(f"{location}: value is not in enum")
    expected = schema.get("type")
    if isinstance(expected, str) and not _type_matches(value, expected):
        return [f"{location}: expected {expected}"]
    if isinstance(expected, list) and not any(_type_matches(value, item) for item in expected):
        return [f"{location}: expected one of {', '.join(expected)}"]
    if isinstance(value, str):
        if "minLength" in schema and len(value) < schema["minLength"]:
            errors.append(f"{location}: shorter than minLength")
        if "maxLength" in schema and len(value) > schema["maxLength"]:
            errors.append(f"{location}: longer than maxLength")
        if "pattern" in schema and not re.search(schema["pattern"], value):
            errors.append(f"{location}: does not match pattern")
        if schema.get("format") == "date-time":
            date_time = re.fullmatch(
                r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})",
                value,
            )
            try:
                parsed = (
                    dt.datetime.fromisoformat(value.replace("Z", "+00:00")) if date_time else None
                )
            except ValueError:
                parsed = None
            if parsed is None or parsed.utcoffset() is None:
                errors.append(f"{location}: invalid RFC3339 date-time")
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        if "minimum" in schema and value < schema["minimum"]:
            errors.append(f"{location}: smaller than minimum")
        if "maximum" in schema and value > schema["maximum"]:
            errors.append(f"{location}: larger than maximum")
    if isinstance(value, list):
        if "minItems" in schema and len(value) < schema["minItems"]:
            errors.append(f"{location}: fewer than minItems")
        if isinstance(schema.get("items"), dict):
            for index, item in enumerate(value):
                errors.extend(
                    validate_schema(item, schema["items"], f"{location}[{index}]", root_schema)
                )
    if isinstance(value, dict):
        properties = schema.get("properties", {})
        for key in schema.get("required", []):
            if key not in value:
                errors.append(f"{location}: missing required property {key}")
        if schema.get("additionalProperties") is False:
            errors.extend(
                f"{location}: unexpected property {key}" for key in value if key not in properties
            )
        for key, child_schema in properties.items():
            if key in value and isinstance(child_schema, dict):
                errors.extend(
                    validate_schema(value[key], child_schema, f"{location}.{key}", root_schema)
                )
        dependent_required = schema.get("dependentRequired", {})
        if isinstance(dependent_required, dict):
            for key, dependencies in dependent_required.items():
                if key in value and isinstance(dependencies, list):
                    errors.extend(
                        f"{location}: property {key} requires property {dependency}"
                        for dependency in dependencies
                        if dependency not in value
                    )
    if "allOf" in schema:
        for child in schema["allOf"]:
            errors.extend(validate_schema(value, child, location, root_schema))
    if "anyOf" in schema and not any(
        not validate_schema(value, child, location, root_schema) for child in schema["anyOf"]
    ):
        errors.append(f"{location}: does not satisfy anyOf")
    if (
        "oneOf" in schema
        and sum(
            not validate_schema(value, child, location, root_schema) for child in schema["oneOf"]
        )
        != 1
    ):
        errors.append(f"{location}: does not satisfy exactly one oneOf branch")
    if "if" in schema and not validate_schema(value, schema["if"], location, root_schema):
        if isinstance(schema.get("then"), dict):
            errors.extend(validate_schema(value, schema["then"], location, root_schema))
    elif "else" in schema and isinstance(schema["else"], dict):
        errors.extend(validate_schema(value, schema["else"], location, root_schema))
    return errors


def validate_document(document: Any, schema_path: str | Path) -> list[str]:
    schema = load_json(schema_path)
    if not isinstance(schema, dict):
        return ["schema root must be an object"]
    return validate_schema(document, schema)


def context_from_args(args: argparse.Namespace) -> dict[str, Any]:
    if args.context and args.context_json:
        raise ValueError("choose either --context or --context-json")
    context = load_json(args.context) if args.context else json.loads(args.context_json)
    if not isinstance(context, dict):
        raise ValueError("context must be a JSON object")
    return context


def checks_from_args(args: argparse.Namespace) -> list[Any]:
    if args.checks and args.checks_path:
        raise ValueError("choose either --checks or --checks-path")
    checks = load_json(args.checks_path) if args.checks_path else json.loads(args.checks or "[]")
    if not isinstance(checks, list):
        raise ValueError("checks must be a JSON array")
    for report_path in _report_paths(args.report_paths):
        report = Path(report_path)
        payload = _read_report_snapshot(report)
        check = {
            "name": args.artifact_name or report.name,
            "conclusion": _conclusion(args.conclusion),
            "report_digest": "sha256:" + sha256(payload),
        }
        if report.parent.name == "reports" and ARTIFACT_REPORT_PATH.fullmatch(
            f"reports/{report.name}"
        ):
            check["report_path"] = f"reports/{report.name}"
            check["report_size"] = len(payload)
        checks.append(check)
    if not checks:
        checks.append(
            {
                "name": args.artifact_name,
                "conclusion": _conclusion(args.conclusion),
                "report_digest": "sha256:" + sha256(""),
            }
        )
    return checks


def _report_paths(value: str | None) -> list[str]:
    if not value:
        return []
    return [item.strip() for item in value.replace(",", "\n").splitlines() if item.strip()]


def _report_roots() -> list[tuple[Path, Path]]:
    roots: list[tuple[Path, Path]] = []
    for value in (os.environ.get("GITHUB_WORKSPACE"), os.environ.get("RUNNER_TEMP")):
        if not value:
            continue
        # Keep this path lexical so ancestor-symlink checks cannot be bypassed.
        lexical = Path(os.path.abspath(value))  # noqa: PTH100
        roots.append((lexical, lexical.resolve(strict=True)))
    return roots


def _report_root(candidate: Path) -> Path | None:
    return next(
        (
            resolved
            for lexical, resolved in _report_roots()
            if candidate == lexical or lexical in candidate.parents
        ),
        None,
    )


def _is_safe_report_path(value: str) -> bool:
    """Accept only lexical paths below GitHub's designated work or temp roots."""
    try:
        # Keep this path lexical so ancestor-symlink checks cannot be bypassed.
        candidate = Path(os.path.abspath(value))  # noqa: PTH100
    except OSError:
        return False
    return _report_root(candidate) is not None


def _read_report_snapshot(path: Path) -> bytes:
    """Read one stable regular-file snapshot without following any symlink."""
    # Keep this path lexical so ancestor-symlink checks cannot be bypassed.
    candidate = Path(os.path.abspath(path))  # noqa: PTH100
    selected = next(
        (
            (lexical, resolved)
            for lexical, resolved in _report_roots()
            if candidate != lexical and lexical in candidate.parents
        ),
        None,
    )
    if selected is None:
        raise ValueError(f"report path escapes GITHUB_WORKSPACE/RUNNER_TEMP: {path}")
    lexical_root, resolved_root = selected
    parts = candidate.relative_to(lexical_root).parts
    nofollow = getattr(os, "O_NOFOLLOW", 0)
    directory_flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | nofollow
    try:
        directory_descriptor = os.open(resolved_root, directory_flags)
    except OSError as exc:
        raise ValueError(f"report root cannot be opened safely: {resolved_root}") from exc
    try:
        for part in parts[:-1]:
            try:
                child_descriptor = os.open(part, directory_flags, dir_fd=directory_descriptor)
            except OSError as exc:
                raise ValueError(f"report path must not contain symlinks: {path}") from exc
            os.close(directory_descriptor)
            directory_descriptor = child_descriptor
        try:
            descriptor = os.open(parts[-1], os.O_RDONLY | nofollow, dir_fd=directory_descriptor)
        except OSError as exc:
            raise ValueError(
                f"report path must not contain symlinks and must be safely readable: {path}"
            ) from exc
        try:
            before = os.fstat(descriptor)
            if not stat.S_ISREG(before.st_mode):
                raise ValueError(f"report path must be a regular file: {path}")
            if before.st_size > MAX_REPORT_BYTES:
                raise ValueError(
                    f"report exceeds the {MAX_REPORT_BYTES}-byte per-file limit: {path}"
                )
            chunks: list[bytes] = []
            remaining = MAX_REPORT_BYTES + 1
            while remaining:
                chunk = os.read(descriptor, min(1024 * 1024, remaining))
                if not chunk:
                    break
                chunks.append(chunk)
                remaining -= len(chunk)
            payload = b"".join(chunks)
            after = os.fstat(descriptor)
        finally:
            os.close(descriptor)
    finally:
        os.close(directory_descriptor)
    if len(payload) > MAX_REPORT_BYTES:
        raise ValueError(f"report exceeds the {MAX_REPORT_BYTES}-byte per-file limit: {path}")
    identity_before = (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns)
    identity_after = (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns)
    if identity_before != identity_after or len(payload) != after.st_size:
        raise ValueError(f"report changed while it was being staged: {path}")
    return payload


def stage_reports(value: str | None, staging_directory: str | Path) -> list[Path]:
    """Copy bounded report snapshots into the only directory later uploaded."""
    source_paths = _report_paths(value)
    if len(source_paths) > MAX_REPORT_FILES:
        raise ValueError(f"report count exceeds the {MAX_REPORT_FILES}-file limit")
    staging = Path(staging_directory)
    if staging.is_symlink():
        raise ValueError("staging directory must not be a symlink")
    staging.mkdir(mode=0o700, parents=True, exist_ok=True)
    staging.chmod(0o700)
    reports_directory = staging / "reports"
    if source_paths:
        reports_directory.mkdir(mode=0o700, exist_ok=False)
    resolved_sources: set[Path] = set()
    staged: list[Path] = []
    aggregate = 0
    for index, source_value in enumerate(source_paths, start=1):
        source = Path(source_value)
        try:
            resolved = source.resolve(strict=True)
        except OSError as exc:
            raise ValueError(f"report path does not exist: {source_value}") from exc
        if resolved in resolved_sources:
            raise ValueError(f"duplicate report path: {source_value}")
        resolved_sources.add(resolved)
        payload = _read_report_snapshot(source)
        aggregate += len(payload)
        if aggregate > MAX_REPORT_AGGREGATE_BYTES:
            raise ValueError(
                f"reports exceed the {MAX_REPORT_AGGREGATE_BYTES}-byte aggregate limit"
            )
        safe_name = re.sub(r"[^A-Za-z0-9._-]", "_", source.name) or "report"
        destination = reports_directory / f"{index:02d}-{safe_name}"
        descriptor = os.open(destination, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        try:
            view = memoryview(payload)
            while view:
                view = view[os.write(descriptor, view) :]
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
        destination.chmod(0o400)
        staged.append(destination)
    return staged


def verify_artifact_directory(
    artifact_directory: str | Path,
    *,
    expected_evidence_digest: str | None = None,
    expected_source_revision: str | None = None,
    schema_path: str | Path = ROOT / "schemas/ci_evidence.schema.json",
) -> dict[str, Any]:
    """Verify the complete extracted artifact and every declared report byte."""
    # Keep this path lexical so ancestor-symlink checks cannot be bypassed.
    artifact = Path(os.path.abspath(artifact_directory))  # noqa: PTH100
    if not _is_safe_report_path(str(artifact)):
        raise ValueError("artifact directory escapes GITHUB_WORKSPACE/RUNNER_TEMP")
    try:
        artifact_status = artifact.lstat()
    except OSError as exc:
        raise ValueError("artifact directory does not exist") from exc
    if artifact.is_symlink() or not stat.S_ISDIR(artifact_status.st_mode):
        raise ValueError("artifact directory must be a non-symlink directory")

    with os.scandir(artifact) as entries:
        root_entries = {entry.name for entry in entries}
    evidence_path = artifact / "ci-evidence.json"
    evidence_payload = _read_report_snapshot(evidence_path)
    if len(evidence_payload) > MAX_EVIDENCE_BYTES:
        raise ValueError(f"ci-evidence.json exceeds the {MAX_EVIDENCE_BYTES}-byte limit")
    try:
        document = json.loads(evidence_payload.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError("ci-evidence.json is not valid UTF-8 JSON") from exc
    errors = validate_document(document, schema_path)
    if errors:
        raise ValueError("ci-evidence.json does not satisfy schema: " + "; ".join(errors))
    if not isinstance(document, dict):  # Kept explicit for type narrowing and defensive callers.
        raise ValueError("ci-evidence.json root must be an object")

    evidence_digest = "sha256:" + sha256(canonical_json(document))
    if expected_evidence_digest is not None:
        if not SHA256_DIGEST.fullmatch(expected_evidence_digest):
            raise ValueError("expected evidence digest must be a canonical SHA-256 digest")
        if evidence_digest != expected_evidence_digest:
            raise ValueError("downloaded evidence digest mismatch")
    if expected_source_revision is not None:
        expected_source_revision = _canonical_source_revision(expected_source_revision)
        if document.get("source_revision") != expected_source_revision:
            raise ValueError("downloaded evidence source revision mismatch")

    report_specs: dict[str, tuple[int, str]] = {}
    checks = document.get("checks")
    if not isinstance(checks, list):
        raise ValueError("ci-evidence.json checks must be an array")
    for check in checks:
        if not isinstance(check, dict):
            raise ValueError("ci-evidence.json check must be an object")
        report_path = check.get("report_path")
        report_size = check.get("report_size")
        if report_path is None and report_size is None:
            continue
        if not isinstance(report_path, str) or not ARTIFACT_REPORT_PATH.fullmatch(report_path):
            raise ValueError("evidence report_path must be a canonical reports/<file> path")
        if (
            isinstance(report_size, bool)
            or not isinstance(report_size, int)
            or not 0 <= report_size <= MAX_REPORT_BYTES
        ):
            raise ValueError("evidence report_size is outside the per-file limit")
        report_digest = check.get("report_digest")
        if not isinstance(report_digest, str) or not SHA256_DIGEST.fullmatch(report_digest):
            raise ValueError("evidence report_digest must be a canonical SHA-256 digest")
        if report_path in report_specs:
            raise ValueError(f"evidence declares duplicate report path: {report_path}")
        report_specs[report_path] = (report_size, report_digest)
    if len(report_specs) > MAX_REPORT_FILES:
        raise ValueError(f"report count exceeds the {MAX_REPORT_FILES}-file limit")

    expected_root_entries = {"ci-evidence.json"}
    if report_specs:
        expected_root_entries.add("reports")
    if root_entries != expected_root_entries:
        missing = sorted(expected_root_entries - root_entries)
        extra = sorted(root_entries - expected_root_entries)
        raise ValueError(f"artifact file set mismatch; missing={missing}, extra={extra}")

    actual_report_paths: set[str] = set()
    reports_directory = artifact / "reports"
    if report_specs:
        reports_status = reports_directory.lstat()
        if reports_directory.is_symlink() or not stat.S_ISDIR(reports_status.st_mode):
            raise ValueError("artifact reports entry must be a non-symlink directory")
        with os.scandir(reports_directory) as entries:
            for entry in entries:
                report_path = f"reports/{entry.name}"
                try:
                    entry_status = entry.stat(follow_symlinks=False)
                except OSError as exc:
                    raise ValueError(
                        f"artifact report cannot be inspected safely: {report_path}"
                    ) from exc
                if entry.is_symlink() or not stat.S_ISREG(entry_status.st_mode):
                    raise ValueError(
                        f"artifact report must be a non-symlink regular file: {report_path}"
                    )
                actual_report_paths.add(report_path)
    if actual_report_paths != set(report_specs):
        missing = sorted(set(report_specs) - actual_report_paths)
        extra = sorted(actual_report_paths - set(report_specs))
        raise ValueError(f"artifact report set mismatch; missing={missing}, extra={extra}")

    aggregate = 0
    for report_path, (expected_size, expected_digest) in sorted(report_specs.items()):
        payload = _read_report_snapshot(artifact / report_path)
        aggregate += len(payload)
        if aggregate > MAX_REPORT_AGGREGATE_BYTES:
            raise ValueError(
                f"reports exceed the {MAX_REPORT_AGGREGATE_BYTES}-byte aggregate limit"
            )
        if len(payload) != expected_size:
            raise ValueError(f"artifact report size mismatch: {report_path}")
        if "sha256:" + sha256(payload) != expected_digest:
            raise ValueError(f"artifact report digest mismatch: {report_path}")

    return {
        "document": document,
        "evidence_digest": evidence_digest,
        "report_count": len(report_specs),
        "report_bytes": aggregate,
    }


def _conclusion(value: str) -> str:
    normalized = value.upper()
    return {
        "SUCCESS": "PASS",
        "FAILURE": "FAIL",
        "CANCELLED": "CANNOT_EVALUATE",
        "TIMED_OUT": "CANNOT_EVALUATE",
        "ACTION_REQUIRED": "CANNOT_EVALUATE",
    }.get(normalized, normalized)


def _reason_code(value: str) -> str:
    normalized = value.upper().replace("-", "_")
    if not normalized or not normalized[0].isalpha():
        normalized = "EVIDENCE_" + normalized
    return normalized


def build_evidence(args: argparse.Namespace) -> dict[str, Any]:
    context = context_from_args(args)
    checks = checks_from_args(args)
    required_context = (
        "correlation_id",
        "source_revision",
        "base_revision",
        "repository",
        "workflow_ref",
        "workflow_revision",
    )
    missing = [key for key in required_context if key not in context]
    if missing:
        raise ValueError("context missing: " + ", ".join(missing))
    return {
        "schema_version": args.schema_version,
        "correlation_id": context["correlation_id"],
        "source_revision": context["source_revision"],
        "base_revision": context["base_revision"],
        "context_digest": args.context_digest or "sha256:" + sha256(context),
        "caller_repository": args.caller_repository or context["repository"],
        "workflow_ref": context["workflow_ref"],
        "workflow_revision": context["workflow_revision"],
        "pipeline_definition_revision": args.pipeline_definition_revision
        or context["workflow_revision"],
        "producer": args.producer,
        "plan_id": args.plan_id or f"{args.producer}-plan-{context['correlation_id'][:8]}",
        "build_id": args.build_id or context["correlation_id"],
        "conclusion": _conclusion(args.conclusion),
        "reason_code": _reason_code(args.reason_code),
        "checks": checks,
        "started_at": args.started_at or utc_now(),
        "completed_at": args.completed_at or utc_now(),
    }


class BuildkiteClient:
    """Small injectable transport boundary; tests provide an opener, never a network."""

    def __init__(
        self,
        token: str,
        organization: str,
        opener: Callable[..., Any] = _open_without_redirects,
        sleeper: Callable[[float], None] = time.sleep,
        clock: Callable[[], float] = time.monotonic,
        wall_clock: Callable[[], float] = time.time,
        jitter: Callable[[], float] = random.random,
        artifact_opener: Callable[..., Any] = _open_without_redirects,
    ):
        if not token:
            raise ValueError("BUILDKITE_API_TOKEN is required")
        if not organization:
            raise ValueError("BUILDKITE_ORGANIZATION is required")
        self._token = token
        self._organization = organization
        self._opener = opener
        self._artifact_opener = artifact_opener
        self._sleeper = sleeper
        self._clock = clock
        self._wall_clock = wall_clock
        self._jitter = jitter

    @classmethod
    def from_environment(cls) -> BuildkiteClient:
        return cls(
            os.environ.get("BUILDKITE_API_TOKEN", ""), os.environ.get("BUILDKITE_ORGANIZATION", "")
        )

    def _request_payload_with_link(
        self,
        method: str,
        path: str,
        body: dict[str, Any] | None = None,
        deadline: float | None = None,
    ) -> tuple[Any, str | None]:
        request = urllib.request.Request(
            BUILDKITE_API + path,
            data=canonical_json(body).encode("utf-8") if body is not None else None,
            headers={
                "Authorization": f"Bearer {self._token}",
                "Accept": "application/json",
                "Content-Type": "application/json",
            },
            method=method,
        )
        if method == "GET":
            response = self._open_get_with_retries(
                self._opener,
                request,
                deadline,
                http_label="Buildkite API",
                transport_message="Buildkite API request failed",
            )
        else:
            # Mutating requests are deliberately attempted once. A caller must
            # reconcile the remote build before deciding whether to try again.
            try:
                response = self._opener(request, timeout=self._request_timeout(deadline))
            except urllib.error.HTTPError as exc:
                raise RuntimeError(f"Buildkite API returned HTTP {exc.code}") from exc
            except urllib.error.URLError as exc:
                raise RuntimeError("Buildkite API request failed") from exc
        with response:
            payload = _read_bounded(
                response, MAX_API_RESPONSE_BYTES, "Buildkite API response"
            ).decode("utf-8")
            link = (
                response.headers.get("Link")
                if getattr(response, "headers", None) is not None
                else None
            )
        return (json.loads(payload) if payload else {}), link

    def _request_timeout(self, deadline: float | None) -> float:
        if deadline is None:
            return REQUEST_TIMEOUT_SECONDS
        remaining = deadline - self._clock()
        if remaining <= 0:
            raise RuntimeError(DEADLINE_EXCEEDED)
        return min(REQUEST_TIMEOUT_SECONDS, remaining)

    def _sleep_before_retry(self, delay: float, deadline: float | None) -> None:
        if deadline is None:
            self._sleeper(delay)
            return
        remaining = deadline - self._clock()
        if remaining <= 0:
            raise RuntimeError(DEADLINE_EXCEEDED)
        if delay >= remaining:
            # Sleeping the remaining budget is safe, but another request is
            # not. Raise deterministically even when an injected test sleeper
            # does not advance the injected clock.
            self._sleeper(remaining)
            raise RuntimeError(DEADLINE_EXCEEDED)
        self._sleeper(delay)
        if self._clock() >= deadline:
            raise RuntimeError(DEADLINE_EXCEEDED)

    def _open_get_with_retries(
        self,
        opener: Callable[..., Any],
        request: urllib.request.Request,
        deadline: float | None,
        *,
        http_label: str,
        transport_message: str,
        accepted_http_errors: frozenset[int] = frozenset(),
    ) -> Any:
        for attempt in range(4):
            try:
                return opener(request, timeout=self._request_timeout(deadline))
            except urllib.error.HTTPError as exc:
                if exc.code in accepted_http_errors:
                    return exc
                if exc.code not in RETRYABLE_HTTP_STATUS or attempt == 3:
                    raise RuntimeError(f"{http_label} returned HTTP {exc.code}") from exc
                self._sleep_before_retry(
                    self._retry_delay(attempt, getattr(exc, "headers", None)),
                    deadline,
                )
            except urllib.error.URLError as exc:
                if attempt == 3:
                    raise RuntimeError(transport_message) from exc
                self._sleep_before_retry(self._retry_delay(attempt, None), deadline)
        raise RuntimeError(transport_message)  # pragma: no cover

    def _retry_delay(self, attempt: int, headers: Any) -> float:
        base = RETRY_BASE_DELAYS[min(attempt, len(RETRY_BASE_DELAYS) - 1)]
        random_value = self._jitter()
        if not 0.0 <= random_value <= 1.0:
            raise RuntimeError("retry jitter source returned a value outside [0, 1]")
        delay = (base / 2.0) + (random_value * base / 2.0)
        retry_after = headers.get("Retry-After") if headers is not None else None
        if isinstance(retry_after, str):
            retry_after = retry_after.strip()
            if retry_after.isdigit():
                delay = max(delay, float(retry_after))
            elif retry_after:
                try:
                    parsed = email.utils.parsedate_to_datetime(retry_after)
                    if parsed.tzinfo is None:
                        parsed = parsed.replace(tzinfo=dt.UTC)
                    delay = max(delay, parsed.timestamp() - self._wall_clock())
                except (TypeError, ValueError, OverflowError):
                    pass
        return min(MAX_RETRY_DELAY_SECONDS, max(0.0, delay))

    def _request_payload(
        self,
        method: str,
        path: str,
        body: dict[str, Any] | None = None,
        deadline: float | None = None,
    ) -> Any:
        payload, _ = self._request_payload_with_link(method, path, body, deadline)
        return payload

    def _request(
        self,
        method: str,
        path: str,
        body: dict[str, Any] | None = None,
        deadline: float | None = None,
    ) -> dict[str, Any]:
        decoded = self._request_payload(method, path, body, deadline)
        if not isinstance(decoded, dict):
            raise RuntimeError("Buildkite API returned a non-object response")
        return decoded

    def _build_path(self, pipeline: str, build: str = "") -> str:
        organisation = urllib.parse.quote(self._organization, safe="")
        pipeline_part = urllib.parse.quote(pipeline, safe="")
        suffix = f"/builds/{urllib.parse.quote(build, safe='')}" if build else "/builds"
        return f"/organizations/{organisation}/pipelines/{pipeline_part}{suffix}"

    @staticmethod
    def _next_artifact_page(link: str | None, artifact_path: str) -> str | None:
        if not link:
            return None
        next_urls: list[str] = []
        for entry in link.split(","):
            match = re.fullmatch(r'\s*<([^>]+)>\s*;\s*rel="?([^";]+)"?(?:\s*;.*)?\s*', entry)
            if not match:
                raise RuntimeError("Buildkite artifacts pagination Link header is malformed")
            if "next" in match.group(2).split():
                next_urls.append(match.group(1))
        if not next_urls:
            return None
        if len(next_urls) != 1:
            raise RuntimeError("Buildkite artifacts pagination declared multiple next pages")
        parsed = urllib.parse.urlsplit(next_urls[0])
        if (
            parsed.scheme != "https"
            or parsed.netloc != "api.buildkite.com"
            or parsed.path != "/v2" + artifact_path
            or parsed.fragment
        ):
            raise RuntimeError(
                "Buildkite artifacts pagination URL is outside the expected API path"
            )
        query = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)
        if set(query) - {"page", "per_page"}:
            raise RuntimeError("Buildkite artifacts pagination URL has unexpected query parameters")
        pages = query.get("page", [])
        if len(pages) != 1 or not BUILDKITE_BUILD_NUMBER.fullmatch(pages[0]):
            raise RuntimeError("Buildkite artifacts pagination URL has an invalid page number")
        per_page = query.get("per_page")
        if per_page is not None and (
            len(per_page) != 1 or not BUILDKITE_BUILD_NUMBER.fullmatch(per_page[0])
        ):
            raise RuntimeError("Buildkite artifacts pagination URL has an invalid per_page value")
        return artifact_path + "?" + parsed.query

    def dispatch(
        self, pipeline: str, commit: str, branch: str, message: str, environment: dict[str, str]
    ) -> dict[str, Any]:
        commit = _canonical_source_revision(commit)
        response = self._request(
            "POST",
            self._build_path(pipeline),
            {"commit": commit, "branch": branch, "message": message, "env": environment},
        )
        try:
            _canonical_build_id(response.get("id"))
        except ValueError as exc:
            raise RuntimeError(
                "Buildkite dispatch response has an invalid build id or build number"
            ) from exc
        response_number = response.get("number")
        if (
            isinstance(response_number, bool)
            or not isinstance(response_number, int)
            or response_number < 1
        ):
            raise RuntimeError(
                "Buildkite dispatch response has an invalid build id or build number"
            )
        if response.get("commit") != commit:
            raise RuntimeError(
                "Buildkite dispatch response commit does not match the requested pipeline definition"
            )
        return response

    def verify(
        self,
        pipeline: str,
        build_id: str,
        build_number: str,
        expected_commit: str,
        deadline: float | None = None,
    ) -> dict[str, Any]:
        build_id = _canonical_build_id(build_id)
        build_number = _canonical_build_number(build_number)
        expected_commit = _canonical_source_revision(expected_commit)
        response = self._request(
            "GET",
            self._build_path(pipeline, build_number) + "?exclude_jobs=true&exclude_pipeline=true",
            deadline=deadline,
        )
        _validate_build_response(response, build_id, build_number, expected_commit)
        if not isinstance(response.get("blocked"), bool):
            raise RuntimeError("Buildkite build response has an invalid blocked flag")
        return response

    def cancel(
        self,
        pipeline: str,
        build_id: str,
        build_number: str,
        expected_commit: str | None = None,
    ) -> dict[str, Any]:
        build_id = _canonical_build_id(build_id)
        build_number = _canonical_build_number(build_number)
        if expected_commit is not None:
            self.verify(pipeline, build_id, build_number, expected_commit)
        response = self._request("PUT", self._build_path(pipeline, build_number) + "/cancel")
        _validate_build_response(response, build_id, build_number)
        return response

    def _download_artifact(self, download_url: str, deadline: float | None = None) -> bytes:
        request = urllib.request.Request(
            download_url,
            headers={"Authorization": f"Bearer {self._token}", "Accept": "application/json"},
            method="GET",
        )
        response = self._open_get_with_retries(
            self._opener,
            request,
            deadline,
            http_label="Buildkite API",
            transport_message="Buildkite artifact redirect request failed",
            accepted_http_errors=frozenset({302}),
        )
        with response:
            status = getattr(response, "status", None)
            if status is None and hasattr(response, "getcode"):
                status = response.getcode()
            if status != 302:
                raise RuntimeError("Buildkite artifact endpoint did not return HTTP 302")
            redirect_payload = _read_bounded(
                response, MAX_REDIRECT_RESPONSE_BYTES, "Buildkite artifact redirect response"
            )
            location = (
                response.headers.get("Location")
                if getattr(response, "headers", None) is not None
                else None
            )
        signed_url = location
        if not isinstance(signed_url, str) or not signed_url:
            raise RuntimeError("Buildkite artifact redirect omitted its Location header")
        if redirect_payload:
            try:
                decoded_redirect = json.loads(redirect_payload.decode("utf-8"))
            except (UnicodeDecodeError, json.JSONDecodeError) as exc:
                raise RuntimeError(
                    "Buildkite artifact redirect response was not valid JSON"
                ) from exc
            if not isinstance(decoded_redirect, dict) or decoded_redirect.get("url") != signed_url:
                raise RuntimeError("Buildkite artifact redirect URL mismatch")
        parsed = urllib.parse.urlsplit(signed_url)
        if (
            parsed.scheme != "https"
            or not parsed.hostname
            or parsed.username is not None
            or parsed.password is not None
            or parsed.fragment
        ):
            raise RuntimeError("Buildkite artifact redirect URL is not a safe HTTPS URL")
        # The signed storage request intentionally has no Authorization header.
        storage_request = urllib.request.Request(signed_url, method="GET")
        storage_response = self._open_get_with_retries(
            self._artifact_opener,
            storage_request,
            deadline,
            http_label="Buildkite artifact storage",
            transport_message="Buildkite artifact storage request failed",
        )
        with storage_response:
            return _read_bounded(storage_response, MAX_EVIDENCE_BYTES, "ci-evidence.json artifact")

    def verify_evidence(
        self,
        pipeline: str,
        build_id: str,
        build_number: str,
        expected_commit: str,
        timeout_seconds: int,
    ) -> tuple[dict[str, Any], bytes | None]:
        build_id = _canonical_build_id(build_id)
        build_number = _canonical_build_number(build_number)
        expected_commit = _canonical_source_revision(expected_commit)
        if not 1 <= timeout_seconds <= 3600:
            raise ValueError("--timeout-seconds must be between 1 and 3600")
        deadline = self._clock() + timeout_seconds
        terminal = {"passed", "failed", "canceled", "canceling", "blocked", "skipped", "not_run"}
        build_response = self.verify(pipeline, build_id, build_number, expected_commit, deadline)
        while (
            not build_response["blocked"]
            and str(build_response.get("state", "")).lower() not in terminal
        ):
            if self._clock() >= deadline:
                raise RuntimeError(DEADLINE_EXCEEDED)
            remaining = deadline - self._clock()
            if remaining <= 0:
                raise RuntimeError(DEADLINE_EXCEEDED)
            self._sleeper(min(2.0, remaining))
            if self._clock() >= deadline:
                raise RuntimeError(DEADLINE_EXCEEDED)
            build_response = self.verify(
                pipeline, build_id, build_number, expected_commit, deadline
            )
        if build_response["blocked"] or str(build_response.get("state", "")).lower() != "passed":
            return build_response, None
        build_path = self._build_path(pipeline, build_number)
        artifact_path = build_path + "/artifacts"
        artifacts: list[Any] = []
        page_path: str | None = artifact_path
        seen_pages: set[str] = set()
        while page_path is not None:
            if page_path in seen_pages or len(seen_pages) >= 100:
                raise RuntimeError("Buildkite artifacts pagination did not terminate safely")
            seen_pages.add(page_path)
            page, link = self._request_payload_with_link("GET", page_path, deadline=deadline)
            if not isinstance(page, list):
                raise RuntimeError("Buildkite artifacts response was not a list")
            artifacts.extend(page)
            page_path = self._next_artifact_page(link, artifact_path)
        matches = [
            artifact
            for artifact in artifacts
            if isinstance(artifact, dict) and artifact.get("filename") == "ci-evidence.json"
        ]
        if len(matches) != 1:
            raise RuntimeError("Buildkite build must contain exactly one ci-evidence.json artifact")
        artifact = matches[0]
        if artifact.get("state") != "finished":
            raise RuntimeError("ci-evidence.json artifact is not finished")
        try:
            artifact_id = _canonical_build_id(artifact.get("id"))
            job_id = _canonical_build_id(artifact.get("job_id"))
        except ValueError as exc:
            raise RuntimeError("ci-evidence.json artifact has an invalid id or job_id") from exc
        expected_download_url = (
            BUILDKITE_API
            + build_path
            + "/jobs/"
            + urllib.parse.quote(job_id, safe="")
            + "/artifacts/"
            + urllib.parse.quote(artifact_id, safe="")
            + "/download"
        )
        download_url = artifact.get("download_url")
        if download_url != expected_download_url:
            raise RuntimeError("ci-evidence.json artifact download_url mismatch")
        return build_response, self._download_artifact(download_url, deadline)


def buildkite_evidence_binding_errors(
    evidence_document: dict[str, Any], response: dict[str, Any], args: argparse.Namespace
) -> list[str]:
    expected = {
        "source_revision": args.expected_source_revision,
        "pipeline_definition_revision": args.expected_pipeline_definition_revision,
        "build_id": args.build_id,
        "correlation_id": args.expected_correlation_id,
        "context_digest": args.expected_context_digest,
    }
    caller_repository = os.environ.get("GITHUB_REPOSITORY")
    if caller_repository:
        expected["caller_repository"] = caller_repository
    errors: list[str] = []
    if response.get("id") != args.build_id:
        errors.append("Buildkite response build id mismatch")
    if str(response.get("number", "")) != str(args.build_number):
        errors.append("Buildkite response build number mismatch")
    if response.get("commit") != args.expected_pipeline_definition_revision:
        errors.append("Buildkite response commit mismatch")
    if evidence_document.get("producer") != "buildkite":
        errors.append("ci-evidence.json producer is not buildkite")
    if evidence_document.get("conclusion") != "PASS":
        errors.append("ci-evidence.json conclusion is not PASS")
    checks = evidence_document.get("checks")
    if not isinstance(checks, list) or any(
        not isinstance(check, dict) or check.get("conclusion") != "PASS" for check in checks
    ):
        errors.append("ci-evidence.json contains a non-PASS check")
    errors.extend(
        f"evidence binding mismatch for {key}"
        for key, expected_value in expected.items()
        if evidence_document.get(key) != expected_value
    )
    return errors


def command_emit(args: argparse.Namespace) -> int:
    artifact_path = ""
    if args.staging_dir:
        staging = Path(args.staging_dir)
        staged_reports = stage_reports(args.report_paths, staging)
        args.report_paths = "\n".join(str(path) for path in staged_reports)
        args.output = str(staging / "ci-evidence.json")
        artifact_path = str(staging)
    evidence = build_evidence(args)
    errors = validate_document(evidence, args.schema)
    if errors:
        raise ValueError("evidence does not satisfy schema: " + "; ".join(errors))
    write_json(args.output, evidence)
    if args.staging_dir:
        Path(args.output).chmod(0o400)
    evidence_json = canonical_json(evidence)
    evidence_digest = "sha256:" + sha256(evidence_json)
    write_output(
        args.github_output,
        {
            "artifact_name": args.artifact_name,
            "artifact_path": artifact_path or str(args.output),
            "evidence_json": evidence_json,
            "evidence_path": str(args.output),
            "evidence_digest": evidence_digest,
            "correlation_id": evidence["correlation_id"],
            "conclusion": evidence["conclusion"],
            "reason_code": evidence["reason_code"],
        },
    )
    print(
        canonical_json(
            {
                "ok": True,
                "artifact_name": args.artifact_name,
                "artifact_path": artifact_path or str(args.output),
                "evidence_digest": evidence_digest,
                "evidence_path": str(args.output),
            }
        )
    )
    return 0


def command_validate(args: argparse.Namespace) -> int:
    errors = validate_document(load_json(args.input), args.schema)
    print(canonical_json({"ok": not errors, "errors": errors}))
    return 0 if not errors else 1


def command_verify_artifact(args: argparse.Namespace) -> int:
    verified = verify_artifact_directory(
        args.artifact_directory,
        expected_evidence_digest=args.expected_evidence_digest,
        expected_source_revision=args.expected_source_revision,
        schema_path=args.schema,
    )
    values = {
        "evidence_digest": verified["evidence_digest"],
        "report_count": verified["report_count"],
        "report_bytes": verified["report_bytes"],
    }
    write_output(args.github_output, values)
    print(canonical_json({"ok": True, **values}))
    return 0


def command_buildkite(args: argparse.Namespace) -> int:
    if args.command in {"buildkite-verify", "buildkite-cancel"}:
        args.build_id = _canonical_build_id(args.build_id)
        args.build_number = _canonical_build_number(args.build_number)
    client = BuildkiteClient.from_environment()
    if args.command == "buildkite-dispatch":
        environment = json.loads(args.env_json)
        if not isinstance(environment, dict) or not all(
            isinstance(key, str) and isinstance(value, str) for key, value in environment.items()
        ):
            raise ValueError("--env-json must be an object of string values")
        response = client.dispatch(
            args.pipeline, args.commit, args.branch, args.message, environment
        )
    elif args.command == "buildkite-verify":
        response, payload = client.verify_evidence(
            args.pipeline,
            args.build_id,
            args.build_number,
            args.expected_pipeline_definition_revision,
            args.timeout_seconds,
        )
        response_digest = "sha256:" + sha256(response)
        state = str(response.get("state", "")).lower()
        if state != "passed" or response.get("blocked") is True:
            build_state = (
                "blocked" if response.get("blocked") is True else response.get("state", "")
            )
            write_output(
                args.github_output,
                {
                    "build_id": response.get("id", ""),
                    "build_number": response.get("number", ""),
                    "build_state": build_state,
                    "build_url": response.get("web_url", ""),
                    "response_digest": response_digest,
                    "evidence_path": "",
                    "evidence_json": "",
                    "evidence_digest": "",
                    "reason_code": "BUILDKITE_BUILD_NOT_PASSED",
                },
            )
            print(
                canonical_json(
                    {"ok": False, "reason_code": "BUILDKITE_BUILD_NOT_PASSED", "response": response}
                ),
                file=sys.stderr,
            )
            return 1
        assert payload is not None
        try:
            evidence_document = json.loads(payload.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise ValueError("ci-evidence.json artifact is not valid JSON") from exc
        errors = validate_document(evidence_document, args.schema)
        errors.extend(buildkite_evidence_binding_errors(evidence_document, response, args))
        if errors:
            write_output(
                args.github_output,
                {
                    "build_id": response.get("id", ""),
                    "build_number": response.get("number", ""),
                    "build_state": response.get("state", ""),
                    "build_url": response.get("web_url", ""),
                    "response_digest": response_digest,
                    "evidence_path": "",
                    "evidence_json": "",
                    "evidence_digest": "",
                    "reason_code": "BUILDKITE_EVIDENCE_BINDING_FAILED",
                },
            )
            print(
                canonical_json(
                    {
                        "ok": False,
                        "reason_code": "BUILDKITE_EVIDENCE_BINDING_FAILED",
                        "errors": errors,
                    }
                ),
                file=sys.stderr,
            )
            return 1
        write_json(args.evidence_output, evidence_document)
        evidence_json = canonical_json(evidence_document)
        evidence_digest = "sha256:" + sha256(evidence_json)
        write_output(
            args.github_output,
            {
                "build_id": response.get("id", ""),
                "build_number": response.get("number", ""),
                "build_state": response.get("state", ""),
                "build_url": response.get("web_url", ""),
                "response_digest": response_digest,
                "evidence_path": str(args.evidence_output),
                "evidence_digest": evidence_digest,
                "evidence_json": evidence_json,
                "reason_code": "EVIDENCE_VERIFIED",
            },
        )
        print(
            canonical_json(
                {
                    "ok": True,
                    "response": response,
                    "evidence_path": str(args.evidence_output),
                    "evidence_digest": evidence_digest,
                }
            )
        )
        return 0
    else:
        response = client.cancel(
            args.pipeline,
            args.build_id,
            args.build_number,
            args.expected_pipeline_definition_revision,
        )
    response_digest = "sha256:" + sha256(response)
    write_output(
        args.github_output,
        {
            "build_id": response.get("id", ""),
            "build_number": response.get("number", ""),
            "build_state": response.get("state", ""),
            "build_url": response.get("web_url", ""),
            "response_digest": response_digest,
        },
    )
    print(canonical_json({"ok": True, "response": response, "response_digest": response_digest}))
    return 0


def parser() -> argparse.ArgumentParser:
    command = argparse.ArgumentParser(description=__doc__)
    subcommands = command.add_subparsers(dest="command", required=True)
    emit = subcommands.add_parser("emit")
    emit_context = emit.add_mutually_exclusive_group(required=True)
    emit_context.add_argument("--context")
    emit_context.add_argument("--context-json")
    emit_checks = emit.add_mutually_exclusive_group()
    emit_checks.add_argument("--checks")
    emit_checks.add_argument("--checks-path")
    emit.add_argument("--schema", default=str(ROOT / "schemas/ci_evidence.schema.json"))
    emit.add_argument("--output", required=True)
    emit.add_argument("--staging-dir")
    emit.add_argument("--github-output")
    emit.add_argument("--schema-version", default="1.0.0")
    emit.add_argument("--context-digest")
    emit.add_argument("--caller-repository")
    emit.add_argument("--pipeline-definition-revision", default="")
    emit.add_argument("--report-paths")
    emit.add_argument("--artifact-name", default="ci-evidence")
    emit.add_argument("--producer", required=True)
    emit.add_argument("--plan-id", default="")
    emit.add_argument("--build-id", default="")
    emit.add_argument("--conclusion", required=True)
    emit.add_argument("--reason-code", required=True)
    emit.add_argument("--started-at")
    emit.add_argument("--completed-at")
    validate = subcommands.add_parser("validate")
    validate.add_argument("--input", required=True)
    validate.add_argument("--schema", default=str(ROOT / "schemas/ci_evidence.schema.json"))
    verify_artifact = subcommands.add_parser("verify-artifact")
    verify_artifact.add_argument("--artifact-directory", required=True)
    verify_artifact.add_argument("--expected-evidence-digest")
    verify_artifact.add_argument("--expected-source-revision")
    verify_artifact.add_argument("--schema", default=str(ROOT / "schemas/ci_evidence.schema.json"))
    verify_artifact.add_argument("--github-output")
    for name in ("buildkite-dispatch", "buildkite-verify", "buildkite-cancel"):
        buildkite = subcommands.add_parser(name)
        buildkite.add_argument("--pipeline", required=True)
        buildkite.add_argument("--github-output")
        if name == "buildkite-dispatch":
            buildkite.add_argument("--commit", required=True)
            buildkite.add_argument("--branch", required=True)
            buildkite.add_argument("--message", required=True)
            buildkite.add_argument("--env-json", default="{}")
        else:
            buildkite.add_argument("--build-id", required=True)
            buildkite.add_argument("--build-number", required=True)
            if name == "buildkite-cancel":
                buildkite.add_argument("--expected-pipeline-definition-revision", required=True)
        if name == "buildkite-verify":
            buildkite.add_argument("--timeout-seconds", type=int, default=60)
            buildkite.add_argument(
                "--schema", default=str(ROOT / "schemas/ci_evidence.schema.json")
            )
            buildkite.add_argument("--evidence-output", default="ci-evidence.json")
            buildkite.add_argument("--expected-source-revision", required=True)
            buildkite.add_argument("--expected-pipeline-definition-revision", required=True)
            buildkite.add_argument("--expected-correlation-id", required=True)
            buildkite.add_argument("--expected-context-digest", required=True)
    return command


def main(argv: list[str] | None = None) -> int:
    args = parser().parse_args(argv)
    try:
        if args.command == "emit":
            return command_emit(args)
        if args.command == "validate":
            return command_validate(args)
        if args.command == "verify-artifact":
            return command_verify_artifact(args)
        return command_buildkite(args)
    except (OSError, ValueError, json.JSONDecodeError, RuntimeError) as exc:
        reason_codes = {
            "buildkite-dispatch": "BUILDKITE_DISPATCH_FAILED",
            "buildkite-verify": "BUILDKITE_VERIFY_FAILED",
            "buildkite-cancel": "BUILDKITE_CANCEL_FAILED",
        }
        reason_code = reason_codes.get(args.command)
        if reason_code:
            write_output(
                getattr(args, "github_output", None),
                {
                    "build_id": getattr(args, "build_id", ""),
                    "build_number": getattr(args, "build_number", ""),
                    "build_state": "",
                    "build_url": "",
                    "response_digest": "",
                    "evidence_path": "",
                    "evidence_json": "",
                    "evidence_digest": "",
                    "reason_code": reason_code,
                },
            )
        print(canonical_json({"ok": False, "error": str(exc)}), file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
