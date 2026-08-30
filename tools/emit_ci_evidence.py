#!/usr/bin/env python3
"""Create, validate, and transport canonical CI evidence without third-party Python."""

from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import os
import re
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Any, Callable


ROOT = Path(__file__).resolve().parents[1]
BUILDKITE_API = "https://api.buildkite.com/v2"
BUILDKITE_UUID = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$")
BUILDKITE_BUILD_NUMBER = re.compile(r"^[1-9][0-9]*$")
MAX_API_RESPONSE_BYTES = 1024 * 1024
MAX_REDIRECT_RESPONSE_BYTES = 64 * 1024
MAX_EVIDENCE_BYTES = 1024 * 1024


class _NoRedirectHandler(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, request: Any, file_pointer: Any, code: int, message: str, headers: Any, new_url: str) -> None:
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


def _validate_build_response(response: dict[str, Any], build_id: str, build_number: str) -> None:
    if response.get("id") != build_id:
        raise RuntimeError("Buildkite response build id mismatch")
    response_number = response.get("number")
    if isinstance(response_number, bool) or not isinstance(response_number, int) or str(response_number) != build_number:
        raise RuntimeError("Buildkite response build number mismatch")


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
    return dt.datetime.now(dt.timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


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


def validate_schema(value: Any, schema: dict[str, Any], location: str = "$", root_schema: dict[str, Any] | None = None) -> list[str]:
    """A deliberately small, strict JSON-Schema evaluator for our two schemas."""
    root_schema = root_schema or schema
    if "$ref" in schema:
        return validate_schema(value, _resolve_ref(root_schema, schema["$ref"]), location, root_schema)
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
        if "pattern" in schema:
            if not re.search(schema["pattern"], value):
                errors.append(f"{location}: does not match pattern")
        if schema.get("format") == "date-time":
            date_time = re.fullmatch(
                r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})",
                value,
            )
            try:
                parsed = dt.datetime.fromisoformat(value.replace("Z", "+00:00")) if date_time else None
            except ValueError:
                parsed = None
            if parsed is None or parsed.utcoffset() is None:
                errors.append(f"{location}: invalid RFC3339 date-time")
    if isinstance(value, list):
        if "minItems" in schema and len(value) < schema["minItems"]:
            errors.append(f"{location}: fewer than minItems")
        if isinstance(schema.get("items"), dict):
            for index, item in enumerate(value):
                errors.extend(validate_schema(item, schema["items"], f"{location}[{index}]", root_schema))
    if isinstance(value, dict):
        properties = schema.get("properties", {})
        for key in schema.get("required", []):
            if key not in value:
                errors.append(f"{location}: missing required property {key}")
        if schema.get("additionalProperties") is False:
            errors.extend(f"{location}: unexpected property {key}" for key in value if key not in properties)
        for key, child_schema in properties.items():
            if key in value and isinstance(child_schema, dict):
                errors.extend(validate_schema(value[key], child_schema, f"{location}.{key}", root_schema))
    if "allOf" in schema:
        for child in schema["allOf"]:
            errors.extend(validate_schema(value, child, location, root_schema))
    if "anyOf" in schema and not any(not validate_schema(value, child, location, root_schema) for child in schema["anyOf"]):
        errors.append(f"{location}: does not satisfy anyOf")
    if "oneOf" in schema and sum(not validate_schema(value, child, location, root_schema) for child in schema["oneOf"]) != 1:
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
        if not report.is_file():
            raise ValueError(f"report path does not exist: {report_path}")
        if not _is_safe_report_path(report_path):
            raise ValueError(f"report path escapes GITHUB_WORKSPACE/RUNNER_TEMP: {report_path}")
        checks.append({
            "name": args.artifact_name or report.name,
            "conclusion": _conclusion(args.conclusion),
            "report_digest": "sha256:" + sha256(report.read_bytes()),
        })
    if not checks:
        checks.append({
            "name": args.artifact_name,
            "conclusion": _conclusion(args.conclusion),
            "report_digest": "sha256:" + sha256(""),
        })
    return checks


def _report_paths(value: str | None) -> list[str]:
    if not value:
        return []
    return [item.strip() for item in value.replace(",", "\n").splitlines() if item.strip()]


def _is_safe_report_path(value: str) -> bool:
    """Accept only real files below GitHub's designated work or temp roots."""
    try:
        candidate = Path(value).resolve(strict=True)
    except OSError:
        return False
    roots = [Path(root).resolve() for root in (os.environ.get("GITHUB_WORKSPACE"), os.environ.get("RUNNER_TEMP")) if root]
    return any(candidate == root or root in candidate.parents for root in roots)


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
    required_context = ("correlation_id", "source_revision", "base_revision", "repository", "workflow_ref", "workflow_revision")
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
        "pipeline_definition_revision": args.pipeline_definition_revision or context["workflow_revision"],
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

    @classmethod
    def from_environment(cls) -> "BuildkiteClient":
        return cls(os.environ.get("BUILDKITE_API_TOKEN", ""), os.environ.get("BUILDKITE_ORGANIZATION", ""))

    def _request_payload_with_link(
        self,
        method: str,
        path: str,
        body: dict[str, Any] | None = None,
    ) -> tuple[Any, str | None]:
        request = urllib.request.Request(
            BUILDKITE_API + path,
            data=canonical_json(body).encode("utf-8") if body is not None else None,
            headers={"Authorization": f"Bearer {self._token}", "Accept": "application/json", "Content-Type": "application/json"},
            method=method,
        )
        try:
            response = self._opener(request, timeout=15)
            with response:
                payload = _read_bounded(response, MAX_API_RESPONSE_BYTES, "Buildkite API response").decode("utf-8")
                link = response.headers.get("Link") if getattr(response, "headers", None) is not None else None
        except urllib.error.HTTPError as exc:
            raise RuntimeError(f"Buildkite API returned HTTP {exc.code}") from exc
        except urllib.error.URLError as exc:
            raise RuntimeError("Buildkite API request failed") from exc
        return (json.loads(payload) if payload else {}), link

    def _request_payload(self, method: str, path: str, body: dict[str, Any] | None = None) -> Any:
        payload, _ = self._request_payload_with_link(method, path, body)
        return payload

    def _request(self, method: str, path: str, body: dict[str, Any] | None = None) -> dict[str, Any]:
        decoded = self._request_payload(method, path, body)
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
            raise RuntimeError("Buildkite artifacts pagination URL is outside the expected API path")
        query = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)
        if set(query) - {"page", "per_page"}:
            raise RuntimeError("Buildkite artifacts pagination URL has unexpected query parameters")
        pages = query.get("page", [])
        if len(pages) != 1 or not BUILDKITE_BUILD_NUMBER.fullmatch(pages[0]):
            raise RuntimeError("Buildkite artifacts pagination URL has an invalid page number")
        per_page = query.get("per_page")
        if per_page is not None and (len(per_page) != 1 or not BUILDKITE_BUILD_NUMBER.fullmatch(per_page[0])):
            raise RuntimeError("Buildkite artifacts pagination URL has an invalid per_page value")
        return artifact_path + "?" + parsed.query

    def dispatch(self, pipeline: str, commit: str, branch: str, message: str, environment: dict[str, str]) -> dict[str, Any]:
        response = self._request("POST", self._build_path(pipeline), {"commit": commit, "branch": branch, "message": message, "env": environment})
        try:
            _canonical_build_id(response.get("id"))
        except ValueError as exc:
            raise RuntimeError("Buildkite dispatch response has an invalid build id or build number") from exc
        response_number = response.get("number")
        if isinstance(response_number, bool) or not isinstance(response_number, int) or response_number < 1:
            raise RuntimeError("Buildkite dispatch response has an invalid build id or build number")
        return response

    def verify(self, pipeline: str, build_id: str, build_number: str) -> dict[str, Any]:
        build_id = _canonical_build_id(build_id)
        build_number = _canonical_build_number(build_number)
        response = self._request(
            "GET",
            self._build_path(pipeline, build_number) + "?exclude_jobs=true&exclude_pipeline=true",
        )
        _validate_build_response(response, build_id, build_number)
        if not isinstance(response.get("blocked"), bool):
            raise RuntimeError("Buildkite build response has an invalid blocked flag")
        return response

    def cancel(self, pipeline: str, build_id: str, build_number: str) -> dict[str, Any]:
        build_id = _canonical_build_id(build_id)
        build_number = _canonical_build_number(build_number)
        response = self._request("PUT", self._build_path(pipeline, build_number) + "/cancel")
        _validate_build_response(response, build_id, build_number)
        return response

    def _download_artifact(self, download_url: str) -> bytes:
        request = urllib.request.Request(
            download_url,
            headers={"Authorization": f"Bearer {self._token}", "Accept": "application/json"},
            method="GET",
        )
        try:
            try:
                response = self._opener(request, timeout=15)
            except urllib.error.HTTPError as exc:
                if exc.code != 302:
                    raise RuntimeError(f"Buildkite API returned HTTP {exc.code}") from exc
                response = exc
            with response:
                status = getattr(response, "status", None)
                if status is None and hasattr(response, "getcode"):
                    status = response.getcode()
                if status != 302:
                    raise RuntimeError("Buildkite artifact endpoint did not return HTTP 302")
                redirect_payload = _read_bounded(response, MAX_REDIRECT_RESPONSE_BYTES, "Buildkite artifact redirect response")
                location = response.headers.get("Location") if getattr(response, "headers", None) is not None else None
        except urllib.error.URLError as exc:
            raise RuntimeError("Buildkite artifact redirect request failed") from exc
        try:
            decoded_redirect = json.loads(redirect_payload.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise RuntimeError("Buildkite artifact redirect response was not valid JSON") from exc
        signed_url = decoded_redirect.get("url") if isinstance(decoded_redirect, dict) else None
        if not isinstance(signed_url, str) or not signed_url or signed_url != location:
            raise RuntimeError("Buildkite artifact redirect URL mismatch")
        parsed = urllib.parse.urlsplit(signed_url)
        if parsed.scheme != "https" or not parsed.hostname or parsed.username is not None or parsed.password is not None or parsed.fragment:
            raise RuntimeError("Buildkite artifact redirect URL is not a safe HTTPS URL")
        storage_request = urllib.request.Request(signed_url, method="GET")
        try:
            storage_response = self._artifact_opener(storage_request, timeout=15)
            with storage_response:
                return _read_bounded(storage_response, MAX_EVIDENCE_BYTES, "ci-evidence.json artifact")
        except urllib.error.HTTPError as exc:
            raise RuntimeError(f"Buildkite artifact storage returned HTTP {exc.code}") from exc
        except urllib.error.URLError as exc:
            raise RuntimeError("Buildkite artifact storage request failed") from exc

    def verify_evidence(self, pipeline: str, build_id: str, build_number: str, timeout_seconds: int) -> tuple[dict[str, Any], bytes | None]:
        build_id = _canonical_build_id(build_id)
        build_number = _canonical_build_number(build_number)
        if not 1 <= timeout_seconds <= 3600:
            raise ValueError("--timeout-seconds must be between 1 and 3600")
        deadline = self._clock() + timeout_seconds
        terminal = {"passed", "failed", "canceled", "canceling", "blocked", "skipped", "not_run"}
        build_response = self.verify(pipeline, build_id, build_number)
        while not build_response["blocked"] and str(build_response.get("state", "")).lower() not in terminal:
            if self._clock() >= deadline:
                raise RuntimeError("Buildkite build did not reach a terminal state before timeout")
            self._sleeper(min(2.0, max(0.0, deadline - self._clock())))
            build_response = self.verify(pipeline, build_id, build_number)
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
            page, link = self._request_payload_with_link("GET", page_path)
            if not isinstance(page, list):
                raise RuntimeError("Buildkite artifacts response was not a list")
            artifacts.extend(page)
            page_path = self._next_artifact_page(link, artifact_path)
        matches = [artifact for artifact in artifacts if isinstance(artifact, dict) and artifact.get("filename") == "ci-evidence.json"]
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
        return build_response, self._download_artifact(download_url)


def buildkite_evidence_binding_errors(evidence_document: dict[str, Any], response: dict[str, Any], args: argparse.Namespace) -> list[str]:
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
    if evidence_document.get("producer") != "buildkite":
        errors.append("ci-evidence.json producer is not buildkite")
    if evidence_document.get("conclusion") != "PASS":
        errors.append("ci-evidence.json conclusion is not PASS")
    checks = evidence_document.get("checks")
    if not isinstance(checks, list) or any(not isinstance(check, dict) or check.get("conclusion") != "PASS" for check in checks):
        errors.append("ci-evidence.json contains a non-PASS check")
    errors.extend(f"evidence binding mismatch for {key}" for key, expected_value in expected.items() if evidence_document.get(key) != expected_value)
    return errors


def command_emit(args: argparse.Namespace) -> int:
    evidence = build_evidence(args)
    errors = validate_document(evidence, args.schema)
    if errors:
        raise ValueError("evidence does not satisfy schema: " + "; ".join(errors))
    write_json(args.output, evidence)
    evidence_json = canonical_json(evidence)
    evidence_digest = "sha256:" + sha256(evidence_json)
    write_output(args.github_output, {"artifact_name": args.artifact_name, "evidence_json": evidence_json, "evidence_path": str(args.output), "evidence_digest": evidence_digest, "correlation_id": evidence["correlation_id"], "conclusion": evidence["conclusion"], "reason_code": evidence["reason_code"]})
    print(canonical_json({"ok": True, "artifact_name": args.artifact_name, "evidence_digest": evidence_digest, "evidence_path": str(args.output)}))
    return 0


def command_validate(args: argparse.Namespace) -> int:
    errors = validate_document(load_json(args.input), args.schema)
    print(canonical_json({"ok": not errors, "errors": errors}))
    return 0 if not errors else 1


def command_buildkite(args: argparse.Namespace) -> int:
    if args.command in {"buildkite-verify", "buildkite-cancel"}:
        args.build_id = _canonical_build_id(args.build_id)
        args.build_number = _canonical_build_number(args.build_number)
    client = BuildkiteClient.from_environment()
    if args.command == "buildkite-dispatch":
        environment = json.loads(args.env_json)
        if not isinstance(environment, dict) or not all(isinstance(key, str) and isinstance(value, str) for key, value in environment.items()):
            raise ValueError("--env-json must be an object of string values")
        response = client.dispatch(args.pipeline, args.commit, args.branch, args.message, environment)
        if response.get("commit") not in (None, args.commit):
            raise RuntimeError("Buildkite dispatch response commit does not match the requested source")
    elif args.command == "buildkite-verify":
        response, payload = client.verify_evidence(args.pipeline, args.build_id, args.build_number, args.timeout_seconds)
        response_digest = "sha256:" + sha256(response)
        state = str(response.get("state", "")).lower()
        if state != "passed" or response.get("blocked") is True:
            build_state = "blocked" if response.get("blocked") is True else response.get("state", "")
            write_output(args.github_output, {"build_id": response.get("id", ""), "build_number": response.get("number", ""), "build_state": build_state, "build_url": response.get("web_url", ""), "response_digest": response_digest, "evidence_path": "", "evidence_json": "", "evidence_digest": "", "reason_code": "BUILDKITE_BUILD_NOT_PASSED"})
            print(canonical_json({"ok": False, "reason_code": "BUILDKITE_BUILD_NOT_PASSED", "response": response}), file=sys.stderr)
            return 1
        assert payload is not None
        try:
            evidence_document = json.loads(payload.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise ValueError("ci-evidence.json artifact is not valid JSON") from exc
        errors = validate_document(evidence_document, args.schema)
        errors.extend(buildkite_evidence_binding_errors(evidence_document, response, args))
        if errors:
            write_output(args.github_output, {"build_id": response.get("id", ""), "build_number": response.get("number", ""), "build_state": response.get("state", ""), "build_url": response.get("web_url", ""), "response_digest": response_digest, "evidence_path": "", "evidence_json": "", "evidence_digest": "", "reason_code": "BUILDKITE_EVIDENCE_BINDING_FAILED"})
            print(canonical_json({"ok": False, "reason_code": "BUILDKITE_EVIDENCE_BINDING_FAILED", "errors": errors}), file=sys.stderr)
            return 1
        write_json(args.evidence_output, evidence_document)
        evidence_json = canonical_json(evidence_document)
        evidence_digest = "sha256:" + sha256(evidence_json)
        write_output(args.github_output, {"build_id": response.get("id", ""), "build_number": response.get("number", ""), "build_state": response.get("state", ""), "build_url": response.get("web_url", ""), "response_digest": response_digest, "evidence_path": str(args.evidence_output), "evidence_digest": evidence_digest, "evidence_json": evidence_json, "reason_code": "EVIDENCE_VERIFIED"})
        print(canonical_json({"ok": True, "response": response, "evidence_path": str(args.evidence_output), "evidence_digest": evidence_digest}))
        return 0
    else:
        response = client.cancel(args.pipeline, args.build_id, args.build_number)
    response_digest = "sha256:" + sha256(response)
    write_output(args.github_output, {"build_id": response.get("id", ""), "build_number": response.get("number", ""), "build_state": response.get("state", ""), "build_url": response.get("web_url", ""), "response_digest": response_digest})
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
        if name == "buildkite-verify":
            buildkite.add_argument("--timeout-seconds", type=int, default=60)
            buildkite.add_argument("--schema", default=str(ROOT / "schemas/ci_evidence.schema.json"))
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
        return command_buildkite(args)
    except (OSError, ValueError, json.JSONDecodeError, RuntimeError) as exc:
        reason_codes = {
            "buildkite-dispatch": "BUILDKITE_DISPATCH_FAILED",
            "buildkite-verify": "BUILDKITE_VERIFY_FAILED",
            "buildkite-cancel": "BUILDKITE_CANCEL_FAILED",
        }
        reason_code = reason_codes.get(args.command)
        if reason_code:
            write_output(getattr(args, "github_output", None), {
                "build_id": getattr(args, "build_id", ""),
                "build_number": getattr(args, "build_number", ""),
                "build_state": "",
                "build_url": "",
                "response_digest": "",
                "evidence_path": "",
                "evidence_json": "",
                "evidence_digest": "",
                "reason_code": reason_code,
            })
        print(canonical_json({"ok": False, "error": str(exc)}), file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
