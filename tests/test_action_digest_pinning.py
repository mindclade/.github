from __future__ import annotations

import argparse
import io
import json
import os
import re
import tempfile
import unittest
import urllib.error
from pathlib import Path

import emit_ci_evidence as evidence
import validate_reusable_workflows as validator


SHA = "a" * 40
BUILD_ID = "11111111-1111-4111-8111-111111111111"
OTHER_BUILD_ID = "22222222-2222-4222-8222-222222222222"
ARTIFACT_ID = "33333333-3333-4333-8333-333333333333"
JOB_ID = "44444444-4444-4444-8444-444444444444"
BUILD_NUMBER = "7"
COMPACT_BUILD_URL = (
    "https://api.buildkite.com/v2/organizations/mindclade/pipelines/validate/builds/7"
    "?exclude_jobs=true&exclude_pipeline=true"
)


class _Response:
    def __init__(self, payload: object, status: int = 200, headers: dict[str, str] | None = None):
        self.payload = payload if isinstance(payload, bytes) else json.dumps(payload).encode("utf-8")
        self.status = status
        self.headers = headers or {}

    def __enter__(self) -> "_Response":
        return self

    def __exit__(self, *_: object) -> None:
        return None

    def read(self, size: int = -1) -> bytes:
        return self.payload if size < 0 else self.payload[:size]

    def getcode(self) -> int:
        return self.status


class ActionDigestPinningTest(unittest.TestCase):
    def test_external_actions_require_full_commit_shas(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            workflow = root / ".github/workflows/self-test.yml"
            workflow.parent.mkdir(parents=True)
            workflow.write_text("steps:\n  - uses: actions/checkout@v4\n  - uses: $/.github/actions/verify-pinned-actions\n", encoding="utf-8")
            outcome = validator.validate_pins(root)
            self.assertFalse(outcome["ok"])
            self.assertIn("not SHA pinned", outcome["errors"][0])
            workflow.write_text("steps:\n  - uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1\n  - uses: $/.github/actions/verify-pinned-actions\n", encoding="utf-8")
            self.assertTrue(validator.validate_pins(root)["ok"])

    def test_full_sha_is_still_denied_when_action_is_not_allowlisted(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            workflow = root / ".github/workflows/self-test.yml"
            workflow.parent.mkdir(parents=True)
            workflow.write_text("steps:\n  - uses: example/unapproved@" + SHA + "\n", encoding="utf-8")
            outcome = validator.validate_pins(root)
            self.assertFalse(outcome["ok"])
            self.assertIn("not allowlisted", outcome["errors"][0])

    def test_python_and_rego_action_allowlists_are_identical(self) -> None:
        policy = (Path(__file__).resolve().parents[1] / "policy/action_pinning.rego").read_text(encoding="utf-8")
        policy_entries = dict(re.findall(r'^  "([^"]+)": "([^"]+)"(?:,)?$', policy, re.MULTILINE))
        self.assertEqual(validator.APPROVED_EXTERNAL_REFERENCES, policy_entries)

    def test_internal_reusable_workflow_requires_a_full_sha(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            workflow = root / "workflow-templates/example.yml"
            workflow.parent.mkdir(parents=True)
            workflow.write_text("jobs:\n  call:\n    uses: mindclade/.github/.github/workflows/reusable-metadata-validation.yml@" + SHA + "\n", encoding="utf-8")
            self.assertTrue(validator.validate_pins(root)["ok"])
            workflow.write_text("jobs:\n  call:\n    uses: mindclade/.github/.github/workflows/reusable-metadata-validation.yml@main\n", encoding="utf-8")
            self.assertFalse(validator.validate_pins(root)["ok"])

    def test_container_reference_requires_the_exact_approved_digest(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            workflow = root / ".github/workflows/scorecard.yml"
            workflow.parent.mkdir(parents=True)
            approved = "ghcr.io/ossf/scorecard-action@sha256:ae5104dd3cc28466ebeb11144354be4cac4b7ff829654f9fab89021d71c46670"
            workflow.write_text("env:\n  SCORECARD_IMAGE: " + approved + "\n", encoding="utf-8")
            self.assertTrue(validator.validate_pins(root)["ok"])
            workflow.write_text("env:\n  SCORECARD_IMAGE: ghcr.io/example/scorecard@sha256:" + "a" * 64 + "\n", encoding="utf-8")
            self.assertFalse(validator.validate_pins(root)["ok"])
            workflow.write_text("jobs:\n  scan:\n    container: ghcr.io/example/scorecard@sha256:" + "a" * 64 + "\n", encoding="utf-8")
            self.assertFalse(validator.validate_pins(root)["ok"])

    def test_direct_docker_execution_requires_the_exact_scorecard_script(self) -> None:
        repository_root = Path(__file__).resolve().parents[1]
        self.assertTrue(validator.validate_pins(repository_root)["ok"])
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            workflow = root / ".github/workflows/reusable-scorecard.yml"
            workflow.parent.mkdir(parents=True)
            scripts = (
                "docker run attacker/image:latest\ncat <<'EOF'\n\"${SCORECARD_IMAGE}\"\nEOF\n",
                "docker  run attacker/image:latest\n",
                "docker container run attacker/image:latest\n",
            )
            for script in scripts:
                with self.subTest(script=script):
                    indented = "\n".join("          " + line for line in script.splitlines())
                    workflow.write_text(
                        "env:\n  SCORECARD_IMAGE: "
                        "ghcr.io/ossf/scorecard-action@sha256:ae5104dd3cc28466ebeb11144354be4cac4b7ff829654f9fab89021d71c46670\n"
                        "jobs:\n  scorecard:\n    steps:\n      - run: |\n"
                        + indented
                        + "\n",
                        encoding="utf-8",
                    )
                    outcome = validator.validate_pins(root)
                    self.assertFalse(outcome["ok"])
                    self.assertTrue(any("approved Scorecard script" in error for error in outcome["errors"]))

            workflow.write_text(
                (repository_root / ".github/workflows/reusable-scorecard.yml")
                .read_text(encoding="utf-8")
                .replace(
                    "      - id: checkout\n"
                    "        name: Check out exact protected revision\n"
                    "        continue-on-error: true\n"
                    "        uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7.0.1\n",
                    "      - id: checkout\n"
                    "        name: Poison Scorecard image\n"
                    "        run: echo SCORECARD_IMAGE=attacker.example/rootkit:latest >> \"$GITHUB_ENV\"\n",
                ),
                encoding="utf-8",
            )
            outcome = validator.validate_pins(root)
            self.assertFalse(outcome["ok"])
            self.assertTrue(any("approved Scorecard script" in error for error in outcome["errors"]))

    def test_yaml_workflow_extension_is_scanned(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            workflow = root / ".github/workflows/evil.yaml"
            workflow.parent.mkdir(parents=True)
            workflow.write_text("steps:\n  - uses: example/unapproved@" + SHA + "\n", encoding="utf-8")
            self.assertFalse(validator.validate_pins(root)["ok"])

    def test_implementation_action_reference_is_strict(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            workflow = root / ".github/workflows/self-test.yml"
            workflow.parent.mkdir(parents=True)
            workflow.write_text("steps:\n  - uses: $/.github/actions/verify-pinned-actions\n", encoding="utf-8")
            self.assertTrue(validator.validate_pins(root)["ok"])
            workflow.write_text("steps:\n  - uses: ./.github/actions/verify-pinned-actions\n", encoding="utf-8")
            self.assertFalse(validator.validate_pins(root)["ok"])
            workflow.write_text("steps:\n  - uses: $/.github/actions/../verify-pinned-actions\n", encoding="utf-8")
            invalid = validator.validate_pins(root)
            self.assertFalse(invalid["ok"])
            self.assertIn("invalid implementation action reference", invalid["errors"][0])
            workflow.write_text("steps:\n  - uses: $/.github/actions//verify-pinned-actions\n", encoding="utf-8")
            self.assertFalse(validator.validate_pins(root)["ok"])
            workflow.write_text("steps:\n  - uses: $/other-root/actions/verify-pinned-actions\n", encoding="utf-8")
            self.assertFalse(validator.validate_pins(root)["ok"])

    def test_buildkite_client_uses_fixed_api_and_injectable_transport(self) -> None:
        observed: dict[str, object] = {}

        def opener(request: object, timeout: int) -> _Response:
            observed["url"] = request.full_url  # type: ignore[attr-defined]
            observed["method"] = request.get_method()  # type: ignore[attr-defined]
            observed["timeout"] = timeout
            return _Response({"id": BUILD_ID, "number": 7, "state": "scheduled", "web_url": "https://buildkite.example/build-id"})

        client = evidence.BuildkiteClient("token-not-logged", "mindclade", opener)
        response = client.dispatch("validate", SHA, "main", "validate", {"SOURCE_REVISION": SHA})
        self.assertEqual(BUILD_ID, response["id"])
        self.assertEqual("POST", observed["method"])
        self.assertEqual("https://api.buildkite.com/v2/organizations/mindclade/pipelines/validate/builds", observed["url"])
        self.assertEqual(15, observed["timeout"])
        self.assertIs(evidence.BuildkiteClient("token-not-logged", "mindclade")._artifact_opener, evidence._open_without_redirects)

    def test_buildkite_dispatch_rejects_noncanonical_response_identifiers(self) -> None:
        for build_id, build_number in (("build-id", 7), (BUILD_ID, "7"), (BUILD_ID, 0)):
            def opener(_request: object, timeout: int) -> _Response:
                self.assertEqual(15, timeout)
                return _Response({"id": build_id, "number": build_number, "state": "scheduled"})

            with self.subTest(build_id=build_id, build_number=build_number):
                client = evidence.BuildkiteClient("token-not-logged", "mindclade", opener)
                with self.assertRaisesRegex(RuntimeError, "invalid build id or build number"):
                    client.dispatch("validate", SHA, "main", "validate", {})

    def test_required_check_never_interpolates_caller_inputs_in_a_shell_script(self) -> None:
        workflow = (Path(__file__).resolve().parents[1] / ".github/workflows/reusable-required-check.yml").read_text(encoding="utf-8")
        verify_step = workflow.split("      - id: verify\n", 1)[1].split("      - id: result\n", 1)[0]
        verify_script = verify_step.split("        run: |\n", 1)[1]
        self.assertNotIn("${{ inputs.", verify_script)
        self.assertIn('--build-id "${BUILD_ID}"', verify_step)
        self.assertIn('--build-number "${BUILD_NUMBER}"', verify_step)
        self.assertIn("^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$", workflow)

    def test_buildkite_identifiers_are_validated_before_transport(self) -> None:
        calls = 0

        def opener(_request: object, timeout: int) -> _Response:
            nonlocal calls
            self.assertEqual(15, timeout)
            calls += 1
            return _Response({})

        client = evidence.BuildkiteClient("token-not-logged", "mindclade", opener)
        for build_id, build_number in (("$(exfiltrate-token)", BUILD_NUMBER), (BUILD_ID, "07"), ("AAAAAAAA-AAAA-4AAA-8AAA-AAAAAAAAAAAA", BUILD_NUMBER)):
            with self.subTest(build_id=build_id, build_number=build_number):
                with self.assertRaises(ValueError):
                    client.verify_evidence("validate", build_id, build_number, 10)
        self.assertEqual(0, calls)

    def test_buildkite_verify_uses_numbered_routes_and_strips_redirect_authorization(self) -> None:
        api_calls: list[tuple[str, str, str | None]] = []
        storage_calls: list[tuple[str, str | None]] = []
        build_calls = 0
        download_url = (
            "https://api.buildkite.com/v2/organizations/mindclade/pipelines/validate/builds/7/jobs/"
            + JOB_ID
            + "/artifacts/"
            + ARTIFACT_ID
            + "/download"
        )
        signed_url = "https://artifacts.example.test/evidence.json?signature=secret"
        evidence_document = {
            "schema_version": "1.0.0",
            "correlation_id": "correlation-id",
            "source_revision": SHA,
            "base_revision": "b" * 40,
            "context_digest": "sha256:" + "c" * 64,
            "caller_repository": "mindclade/.github",
            "workflow_ref": ".github/workflows/reusable-required-check.yml",
            "workflow_revision": "d" * 40,
            "pipeline_definition_revision": "e" * 40,
            "producer": "buildkite",
            "plan_id": "plan-id",
            "build_id": BUILD_ID,
            "conclusion": "PASS",
            "reason_code": "EVIDENCE_VERIFIED",
            "checks": [{"name": "required", "conclusion": "PASS", "report_digest": "sha256:" + "f" * 64}],
            "started_at": "2026-01-01T00:00:00Z",
            "completed_at": "2026-01-01T00:00:01Z",
        }

        def opener(request: object, timeout: int) -> _Response:
            nonlocal build_calls
            url = request.full_url  # type: ignore[attr-defined]
            api_calls.append((url, request.get_method(), request.get_header("Authorization")))  # type: ignore[attr-defined]
            self.assertEqual(15, timeout)
            if url == COMPACT_BUILD_URL:
                build_calls += 1
                return _Response({"id": BUILD_ID, "number": 7, "state": "running" if build_calls == 1 else "passed", "blocked": False, "web_url": "https://buildkite.example/build-id"})
            if url.endswith("/artifacts"):
                return _Response([{
                    "id": ARTIFACT_ID,
                    "job_id": JOB_ID,
                    "filename": "ci-evidence.json",
                    "state": "finished",
                    "download_url": download_url,
                }])
            if url == download_url:
                return _Response({"url": signed_url}, status=302, headers={"Location": signed_url})
            self.fail(f"unexpected network request {url}")

        def artifact_opener(request: object, timeout: int) -> _Response:
            storage_calls.append((request.full_url, request.get_header("Authorization")))  # type: ignore[attr-defined]
            self.assertEqual(15, timeout)
            return _Response(evidence_document)

        client = evidence.BuildkiteClient(
            "token-not-logged",
            "mindclade",
            opener,
            sleeper=lambda _: None,
            artifact_opener=artifact_opener,
        )
        response, payload = client.verify_evidence("validate", BUILD_ID, BUILD_NUMBER, 10)
        self.assertEqual("passed", response["state"])
        self.assertEqual(evidence_document, json.loads(payload.decode("utf-8")))
        self.assertEqual(4, len(api_calls))
        self.assertEqual([COMPACT_BUILD_URL, COMPACT_BUILD_URL], [url for url, _, _ in api_calls[:2]])
        self.assertTrue(all(url.startswith("https://api.buildkite.com/v2/") for url, _, _ in api_calls))
        self.assertTrue(all(authorization == "Bearer token-not-logged" for _, _, authorization in api_calls))
        self.assertEqual([(signed_url, None)], storage_calls)
        self.assertFalse(any(BUILD_ID in url for url, _, _ in api_calls))

    def test_buildkite_response_binding_mismatches_stop_before_artifact_access(self) -> None:
        for returned_id, returned_number in ((OTHER_BUILD_ID, 7), (BUILD_ID, 8)):
            calls = 0

            def opener(_request: object, timeout: int) -> _Response:
                nonlocal calls
                self.assertEqual(15, timeout)
                calls += 1
                return _Response({"id": returned_id, "number": returned_number, "state": "passed", "blocked": False})

            with self.subTest(returned_id=returned_id, returned_number=returned_number):
                client = evidence.BuildkiteClient("token-not-logged", "mindclade", opener)
                with self.assertRaisesRegex(RuntimeError, "build (id|number) mismatch"):
                    client.verify_evidence("validate", BUILD_ID, BUILD_NUMBER, 10)
                self.assertEqual(1, calls)

    def test_buildkite_blocked_flag_is_required_and_prevents_evidence_acceptance(self) -> None:
        calls: list[str] = []

        def blocked_opener(request: object, timeout: int) -> _Response:
            self.assertEqual(15, timeout)
            calls.append(request.full_url)  # type: ignore[attr-defined]
            return _Response({"id": BUILD_ID, "number": 7, "state": "passed", "blocked": True})

        blocked = evidence.BuildkiteClient("token-not-logged", "mindclade", blocked_opener)
        response, payload = blocked.verify_evidence("validate", BUILD_ID, BUILD_NUMBER, 10)
        self.assertIs(response["blocked"], True)
        self.assertIsNone(payload)
        self.assertEqual([COMPACT_BUILD_URL], calls)

        for invalid in (None, "false", 0):
            def invalid_opener(_request: object, timeout: int) -> _Response:
                self.assertEqual(15, timeout)
                response = {"id": BUILD_ID, "number": 7, "state": "passed"}
                if invalid is not None:
                    response["blocked"] = invalid
                return _Response(response)

            with self.subTest(invalid=invalid):
                client = evidence.BuildkiteClient("token-not-logged", "mindclade", invalid_opener)
                with self.assertRaisesRegex(RuntimeError, "invalid blocked flag"):
                    client.verify_evidence("validate", BUILD_ID, BUILD_NUMBER, 10)

    def test_buildkite_cancel_uses_numbered_route_and_validates_response_bindings(self) -> None:
        calls: list[tuple[str, str]] = []

        def opener(request: object, timeout: int) -> _Response:
            self.assertEqual(15, timeout)
            calls.append((request.full_url, request.get_method()))  # type: ignore[attr-defined]
            return _Response({"id": BUILD_ID, "number": 7, "state": "canceling"})

        client = evidence.BuildkiteClient("token-not-logged", "mindclade", opener)
        response = client.cancel("validate", BUILD_ID, BUILD_NUMBER)
        self.assertEqual("canceling", response["state"])
        self.assertEqual([("https://api.buildkite.com/v2/organizations/mindclade/pipelines/validate/builds/7/cancel", "PUT")], calls)

        def mismatched_opener(_request: object, timeout: int) -> _Response:
            self.assertEqual(15, timeout)
            return _Response({"id": OTHER_BUILD_ID, "number": 7, "state": "canceling"})

        mismatched = evidence.BuildkiteClient("token-not-logged", "mindclade", mismatched_opener)
        with self.assertRaisesRegex(RuntimeError, "build id mismatch"):
            mismatched.cancel("validate", BUILD_ID, BUILD_NUMBER)

    def test_buildkite_rejects_unfinished_or_misdirected_evidence_artifacts(self) -> None:
        correct_url = (
            "https://api.buildkite.com/v2/organizations/mindclade/pipelines/validate/builds/7/jobs/"
            + JOB_ID
            + "/artifacts/"
            + ARTIFACT_ID
            + "/download"
        )
        cases = (
            ({"id": ARTIFACT_ID, "job_id": JOB_ID, "filename": "ci-evidence.json", "state": "uploading", "download_url": correct_url}, "not finished"),
            ({"id": "not-a-uuid", "job_id": JOB_ID, "filename": "ci-evidence.json", "state": "finished", "download_url": correct_url}, "invalid id or job_id"),
            ({"id": ARTIFACT_ID, "job_id": JOB_ID, "filename": "ci-evidence.json", "state": "finished", "download_url": "https://attacker.example/evidence"}, "download_url mismatch"),
        )
        for artifact, error in cases:
            calls = 0

            def opener(request: object, timeout: int) -> _Response:
                nonlocal calls
                self.assertEqual(15, timeout)
                calls += 1
                if request.full_url == COMPACT_BUILD_URL:  # type: ignore[attr-defined]
                    return _Response({"id": BUILD_ID, "number": 7, "state": "passed", "blocked": False})
                if request.full_url.endswith("/artifacts"):  # type: ignore[attr-defined]
                    return _Response([artifact])
                self.fail("artifact validation should fail before download")

            with self.subTest(error=error):
                client = evidence.BuildkiteClient("token-not-logged", "mindclade", opener)
                with self.assertRaisesRegex(RuntimeError, error):
                    client.verify_evidence("validate", BUILD_ID, BUILD_NUMBER, 10)
                self.assertEqual(2, calls)

    def test_buildkite_scans_all_artifact_pages_without_leaking_authorization(self) -> None:
        artifact_path = "/v2/organizations/mindclade/pipelines/validate/builds/7/artifacts"
        next_url = "https://api.buildkite.com" + artifact_path + "?page=2"
        api_calls: list[str] = []

        def artifact(identifier: str) -> dict[str, object]:
            return {
                "id": identifier,
                "job_id": JOB_ID,
                "filename": "ci-evidence.json",
                "state": "finished",
                "download_url": (
                    "https://api.buildkite.com/v2/organizations/mindclade/pipelines/validate/builds/7/jobs/"
                    + JOB_ID
                    + "/artifacts/"
                    + identifier
                    + "/download"
                ),
            }

        def opener(request: object, timeout: int) -> _Response:
            self.assertEqual(15, timeout)
            url = request.full_url  # type: ignore[attr-defined]
            api_calls.append(url)
            if url == COMPACT_BUILD_URL:
                return _Response({"id": BUILD_ID, "number": 7, "state": "passed", "blocked": False})
            if url.endswith("/artifacts"):
                return _Response([artifact(ARTIFACT_ID)], headers={"Link": f'<{next_url}>; rel="next"'})
            if url == next_url:
                return _Response([artifact("55555555-5555-4555-8555-555555555555")])
            self.fail(f"unexpected request {url}")

        client = evidence.BuildkiteClient("token-not-logged", "mindclade", opener)
        with self.assertRaisesRegex(RuntimeError, "exactly one"):
            client.verify_evidence("validate", BUILD_ID, BUILD_NUMBER, 10)
        self.assertEqual(3, len(api_calls))

        malicious_link = '<https://attacker.example/artifacts?page=2>; rel="next"'

        def malicious_opener(request: object, timeout: int) -> _Response:
            self.assertEqual(15, timeout)
            if request.full_url == COMPACT_BUILD_URL:  # type: ignore[attr-defined]
                return _Response({"id": BUILD_ID, "number": 7, "state": "passed", "blocked": False})
            return _Response([], headers={"Link": malicious_link})

        malicious = evidence.BuildkiteClient("token-not-logged", "mindclade", malicious_opener)
        with self.assertRaisesRegex(RuntimeError, "outside the expected API path"):
            malicious.verify_evidence("validate", BUILD_ID, BUILD_NUMBER, 10)

    def test_buildkite_rejects_invalid_artifact_redirects_without_storage_access(self) -> None:
        cases = (
            (200, {"url": "https://storage.example/evidence"}, {"Location": "https://storage.example/evidence"}, "did not return HTTP 302"),
            (302, {"url": "https://storage.example/one"}, {"Location": "https://storage.example/two"}, "redirect URL mismatch"),
            (302, {"url": "http://storage.example/evidence"}, {"Location": "http://storage.example/evidence"}, "not a safe HTTPS URL"),
        )
        for status, payload, headers, error in cases:
            storage_calls = 0

            def opener(_request: object, timeout: int) -> _Response:
                self.assertEqual(15, timeout)
                return _Response(payload, status=status, headers=headers)

            def artifact_opener(_request: object, timeout: int) -> _Response:
                nonlocal storage_calls
                self.assertEqual(15, timeout)
                storage_calls += 1
                return _Response(b"should-not-be-read")

            with self.subTest(error=error):
                client = evidence.BuildkiteClient("token-not-logged", "mindclade", opener, artifact_opener=artifact_opener)
                with self.assertRaisesRegex(RuntimeError, error):
                    client._download_artifact("https://api.buildkite.com/v2/safe-download")
                self.assertEqual(0, storage_calls)

    def test_buildkite_rejects_redirects_from_signed_artifact_storage(self) -> None:
        signed_url = "https://artifacts.example.test/evidence.json?signature=secret"
        storage_calls: list[str] = []

        def opener(_request: object, timeout: int) -> _Response:
            self.assertEqual(15, timeout)
            return _Response({"url": signed_url}, status=302, headers={"Location": signed_url})

        def artifact_opener(request: object, timeout: int) -> _Response:
            self.assertEqual(15, timeout)
            storage_calls.append(request.full_url)  # type: ignore[attr-defined]
            raise urllib.error.HTTPError(
                request.full_url,  # type: ignore[attr-defined]
                302,
                "Found",
                {"Location": "http://unsafe.example.test/evidence.json"},
                io.BytesIO(b""),
            )

        client = evidence.BuildkiteClient(
            "token-not-logged",
            "mindclade",
            opener,
            artifact_opener=artifact_opener,
        )
        with self.assertRaisesRegex(RuntimeError, "artifact storage returned HTTP 302"):
            client._download_artifact("https://api.buildkite.com/v2/safe-download")
        self.assertEqual([signed_url], storage_calls)

    def test_buildkite_handles_no_redirect_opener_http_error_without_forwarding_auth(self) -> None:
        signed_url = "https://artifacts.example.test/evidence.json?signature=secret"

        def opener(request: object, timeout: int) -> _Response:
            self.assertEqual(15, timeout)
            self.assertEqual("Bearer token-not-logged", request.get_header("Authorization"))  # type: ignore[attr-defined]
            raise urllib.error.HTTPError(
                request.full_url,  # type: ignore[attr-defined]
                302,
                "Found",
                {"Location": signed_url},
                io.BytesIO(json.dumps({"url": signed_url}).encode("utf-8")),
            )

        def artifact_opener(request: object, timeout: int) -> _Response:
            self.assertEqual(15, timeout)
            self.assertIsNone(request.get_header("Authorization"))  # type: ignore[attr-defined]
            return _Response(b'{"verified":true}')

        client = evidence.BuildkiteClient(
            "token-not-logged",
            "mindclade",
            opener,
            artifact_opener=artifact_opener,
        )
        self.assertEqual(b'{"verified":true}', client._download_artifact("https://api.buildkite.com/v2/safe-download"))

    def test_buildkite_evidence_requires_buildkite_producer_and_all_pass_checks(self) -> None:
        document = {
            "source_revision": SHA,
            "pipeline_definition_revision": "e" * 40,
            "build_id": BUILD_ID,
            "correlation_id": "correlation-id",
            "context_digest": "sha256:" + "c" * 64,
            "caller_repository": "mindclade/.github",
            "producer": "buildkite",
            "conclusion": "PASS",
            "checks": [{"name": "required", "conclusion": "PASS"}],
        }
        args = argparse.Namespace(
            expected_source_revision=SHA,
            expected_pipeline_definition_revision="e" * 40,
            build_id=BUILD_ID,
            expected_correlation_id="correlation-id",
            expected_context_digest="sha256:" + "c" * 64,
            build_number="7",
        )
        old_repository = os.environ.get("GITHUB_REPOSITORY")
        try:
            os.environ["GITHUB_REPOSITORY"] = "mindclade/.github"
            self.assertEqual([], evidence.buildkite_evidence_binding_errors(document, {"id": BUILD_ID, "number": 7}, args))
            document["producer"] = "github_actions"
            document["checks"][0]["conclusion"] = "FAIL"
            errors = evidence.buildkite_evidence_binding_errors(document, {"id": BUILD_ID, "number": 7}, args)
        finally:
            if old_repository is None:
                os.environ.pop("GITHUB_REPOSITORY", None)
            else:
                os.environ["GITHUB_REPOSITORY"] = old_repository
        self.assertIn("ci-evidence.json producer is not buildkite", errors)
        self.assertIn("ci-evidence.json contains a non-PASS check", errors)

    def test_mismatched_evidence_is_rejected_by_schema(self) -> None:
        schema = {
            "type": "object",
            "required": ["source_revision", "context_digest"],
            "properties": {
                "source_revision": {"type": "string", "pattern": "^[0-9a-f]{40}$"},
                "context_digest": {"type": "string", "pattern": "^[0-9a-f]{64}$"},
            },
        }
        errors = evidence.validate_schema({"source_revision": "stale", "context_digest": "mismatch"}, schema)
        self.assertEqual(2, len(errors))


if __name__ == "__main__":
    unittest.main()
