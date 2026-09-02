# pyright: basic, reportArgumentType=false, reportAttributeAccessIssue=false, reportCallIssue=false, reportOperatorIssue=false, reportOptionalMemberAccess=false, reportOptionalSubscript=false
from __future__ import annotations

import argparse
import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import emit_ci_evidence as evidence
import validate_reusable_workflows as validator

ROOT = Path(__file__).resolve().parents[1]
CONTEXT_USES = f"        uses: {validator.TRUSTED_CONTEXT_ACTION}\n"
PINS_USES = f"        uses: {validator.PIN_VERIFICATION_ACTION}\n"


class InlineTrustedContextGateTest(unittest.TestCase):
    """A job may hold a write permission without a separate prepare job only if
    it gates itself under a strictly narrower contract. These cases pin that
    contract: every one of them would leave a write token reachable by code that
    had not been trust-validated first."""

    @staticmethod
    def _valid_job() -> dict:
        return {
            "runs-on": "ubuntu-24.04",
            "steps": [
                {
                    "id": "context",
                    "uses": validator.TRUSTED_CONTEXT_ACTION,
                    "with": {
                        "expected-source-revision": "${{ inputs.source_revision }}",
                        "allowed-execution-tiers": "trusted,release",
                    },
                },
                {"id": "pins", "uses": validator.PIN_VERIFICATION_ACTION},
                {
                    "env": {
                        "CONTEXT_OUTCOME": "${{ steps.context.outcome }}",
                        "PINS_OUTCOME": "${{ steps.pins.outcome }}",
                    },
                    "run": (
                        "set -euo pipefail\n"
                        '[[ "${CONTEXT_OUTCOME}" == success ]]\n'
                        '[[ "${PINS_OUTCOME}" == success ]]\n'
                    ),
                },
                {"uses": "actions/checkout@" + "0" * 40},
            ],
        }

    def test_the_approved_shape_is_accepted(self) -> None:
        self.assertTrue(validator._has_inline_trusted_context_gate(self._valid_job()))

    def test_every_weakening_is_rejected(self) -> None:
        def admit_untrusted(job):
            job["steps"][0]["with"]["allowed-execution-tiers"] = "untrusted,trusted,release"

        def drop_tier_restriction(job):
            job["steps"][0]["with"].pop("allowed-execution-tiers")

        def step_before_gate(job):
            job["steps"].insert(0, {"run": "echo arbitrary"})

        cases = {
            "untrusted execution admitted": admit_untrusted,
            "no execution-tier restriction": drop_tier_restriction,
            "arbitrary step ahead of the gate": step_before_gate,
            "context step soft-failed": lambda j: j["steps"][0].__setitem__("continue-on-error", True),
            "pin step soft-failed": lambda j: j["steps"][1].__setitem__("continue-on-error", True),
            "context step made conditional": lambda j: j["steps"][0].__setitem__("if", "false"),
            "enforcement made conditional": lambda j: j["steps"][2].__setitem__("if", "always()"),
            "job-level env introduced": lambda j: j.__setitem__("env", {"X": "1"}),
            "job container introduced": lambda j: j.__setitem__("container", {"image": "x"}),
            "enforcement assertions removed": lambda j: j["steps"][2].__setitem__("run", "true"),
            "pins outcome unwired": lambda j: j["steps"][2]["env"].pop("PINS_OUTCOME"),
            "pin verification swapped": lambda j: j["steps"].__setitem__(
                1, {"id": "pins", "uses": "evil/action@" + "0" * 40}
            ),
            "runner changed": lambda j: j.__setitem__("runs-on", "self-hosted"),
        }
        for label, mutate in cases.items():
            with self.subTest(weakening=label):
                job = self._valid_job()
                mutate(job)
                self.assertFalse(
                    validator._has_inline_trusted_context_gate(job),
                    f"{label} must not be accepted as a trusted-context gate",
                )


class DeclaredPermissionsTest(unittest.TestCase):
    def test_real_repository_permission_blocks_follow_the_allowlist(self) -> None:
        outcome = validator.validate_permissions(ROOT)
        self.assertTrue(outcome["ok"], outcome["errors"])

    def test_permissions_are_explicit_and_disallow_broad_or_wrong_levels(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            workflows = root / ".github/workflows"
            workflows.mkdir(parents=True)
            workflow = workflows / "pull-request.yml"
            workflow.write_text("on: [pull_request]\npermissions: write-all\n", encoding="utf-8")
            outcome = validator.validate_permissions(root)
            self.assertFalse(outcome["ok"])
            self.assertIn("permissions: write-all is forbidden", outcome["errors"][0])
            workflow.write_text("on: [pull_request]\npermissions: read-all\n", encoding="utf-8")
            self.assertIn(
                "permissions: read-all is forbidden",
                validator.validate_permissions(root)["errors"][0],
            )
            workflow.write_text(
                "on: [pull_request]\npermissions:\n  contents: write\n  issues: write\n  id-token: write\n",
                encoding="utf-8",
            )
            violations = validator.validate_permissions(root)["errors"]
            self.assertTrue(any("contents must be read" in violation for violation in violations))
            self.assertTrue(any("issues must be read" in violation for violation in violations))
            self.assertTrue(
                any("write permission id-token requires" in violation for violation in violations)
            )
            workflow.write_text(
                "on: [pull_request]\npermissions:\n  contents: read\n", encoding="utf-8"
            )
            self.assertTrue(validator.validate_permissions(root)["ok"])

    def test_untrusted_job_cannot_request_write_permission(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            workflows = root / ".github/workflows"
            workflows.mkdir(parents=True)
            (workflows / "tiered.yml").write_text(
                "on: [pull_request]\npermissions: {}\njobs:\n  untrusted:\n    permissions:\n      checks: write\n",
                encoding="utf-8",
            )
            violations = validator.validate_permissions(root)["errors"]
            self.assertTrue(
                any(
                    "untrusted job cannot request write permission checks" in violation
                    for violation in violations
                )
            )

    def test_oidc_requires_the_strict_protected_execution_guard(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            workflows = root / ".github/workflows"
            workflows.mkdir(parents=True)
            workflow = workflows / "tiered.yml"
            trusted_prepare = (
                "  prepare:\n"
                "    runs-on: ubuntu-24.04\n"
                "    outputs:\n"
                "      execution_tier: ${{ steps.context.outputs.execution_tier }}\n"
                "    steps:\n"
                "      - id: context\n" + CONTEXT_USES + "        with:\n"
                "          expected-source-revision: ${{ inputs.source_revision }}\n"
                f"      - uses: {validator.PIN_VERIFICATION_ACTION}\n"
            )
            protected_archive = (
                "  archive:\n"
                "    needs: prepare\n"
                "    if: needs.prepare.outputs.execution_tier == 'trusted' || needs.prepare.outputs.execution_tier == 'release'\n"
                "    permissions:\n"
                "      id-token: write\n"
            )
            workflow.write_text(
                "on: [workflow_call]\npermissions: {}\njobs:\n"
                + trusted_prepare
                + protected_archive,
                encoding="utf-8",
            )
            self.assertTrue(validator.validate_permissions(root)["ok"])
            workflow.write_text(
                "on: [workflow_call]\npermissions: {}\njobs:\n"
                + trusted_prepare
                + protected_archive.replace(" == 'release'", " == 'release' || true"),
                encoding="utf-8",
            )
            violations = validator.validate_permissions(root)["errors"]
            self.assertTrue(
                any("write permission id-token requires" in violation for violation in violations)
            )

    def test_write_permission_requires_explicit_protected_tier_guard(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            workflows = root / ".github/workflows"
            workflows.mkdir(parents=True)
            workflow = workflows / "tiered.yml"
            workflow.write_text(
                "on: [workflow_call]\npermissions: {}\njobs:\n  scan:\n    permissions:\n      security-events: write\n",
                encoding="utf-8",
            )
            violations = validator.validate_permissions(root)["errors"]
            self.assertTrue(
                any(
                    "requires an explicit trusted/release execution-tier guard" in violation
                    for violation in violations
                )
            )
            trusted_prepare = (
                "  prepare:\n"
                "    runs-on: ubuntu-24.04\n"
                "    outputs:\n"
                "      execution_tier: ${{ steps.context.outputs.execution_tier }}\n"
                "    steps:\n"
                "      - id: context\n" + CONTEXT_USES + "        with:\n"
                "          expected-source-revision: ${{ inputs.source_revision }}\n"
                "      - name: Verify immutable implementation closure\n" + PINS_USES
            )
            protected_scan = (
                "  scan:\n"
                "    needs: prepare\n"
                "    if: needs.prepare.outputs.execution_tier == 'trusted' || needs.prepare.outputs.execution_tier == 'release'\n"
                "    permissions:\n"
                "      security-events: write\n"
            )
            workflow.write_text(
                "on: [workflow_call]\npermissions: {}\njobs:\n" + trusted_prepare + protected_scan,
                encoding="utf-8",
            )
            self.assertTrue(validator.validate_permissions(root)["ok"])
            workflow.write_text(
                "on: [workflow_call]\npermissions: {}\njobs:\n"
                + trusted_prepare
                + protected_scan.replace(" == 'release'", " == 'release' || true"),
                encoding="utf-8",
            )
            violations = validator.validate_permissions(root)["errors"]
            self.assertTrue(
                any(
                    "requires an explicit trusted/release execution-tier guard" in violation
                    for violation in violations
                )
            )

            fake_prepare = (
                "  prepare:\n"
                "    outputs:\n"
                "      execution_tier: ${{ steps.fake.outputs.execution_tier }}\n"
                "    steps:\n"
                "      - id: fake\n"
                "        run: echo execution_tier=trusted >> $GITHUB_OUTPUT\n"
            )
            workflow.write_text(
                "on: [workflow_call]\npermissions: {}\njobs:\n" + fake_prepare + protected_scan,
                encoding="utf-8",
            )
            violations = validator.validate_permissions(root)["errors"]
            self.assertTrue(
                any(
                    "requires an explicit trusted/release execution-tier guard" in violation
                    for violation in violations
                )
            )

            bypassable_context = trusted_prepare.replace(
                CONTEXT_USES,
                "        continue-on-error: true\n" + CONTEXT_USES,
            )
            workflow.write_text(
                "on: [workflow_call]\npermissions: {}\njobs:\n"
                + bypassable_context
                + protected_scan,
                encoding="utf-8",
            )
            violations = validator.validate_permissions(root)["errors"]
            self.assertTrue(
                any(
                    "requires an explicit trusted/release execution-tier guard" in violation
                    for violation in violations
                )
            )

            bypassable_job = trusted_prepare.replace(
                "  prepare:\n",
                "  prepare:\n    continue-on-error: true\n",
            )
            workflow.write_text(
                "on: [workflow_call]\npermissions: {}\njobs:\n" + bypassable_job + protected_scan,
                encoding="utf-8",
            )
            violations = validator.validate_permissions(root)["errors"]
            self.assertTrue(
                any(
                    "requires an explicit trusted/release execution-tier guard" in violation
                    for violation in violations
                )
            )

            wrong_revision = trusted_prepare.replace(
                "          expected-source-revision: ${{ inputs.source_revision }}\n",
                "          expected-source-revision: ${{ github.sha }}\n",
            )
            workflow.write_text(
                "on: [workflow_call]\npermissions: {}\njobs:\n" + wrong_revision + protected_scan,
                encoding="utf-8",
            )
            violations = validator.validate_permissions(root)["errors"]
            self.assertTrue(
                any(
                    "requires an explicit trusted/release execution-tier guard" in violation
                    for violation in violations
                )
            )

            for bypassable_pins in (
                trusted_prepare.replace(
                    "      - name: Verify immutable implementation closure\n" + PINS_USES,
                    "",
                ),
                trusted_prepare.replace(
                    PINS_USES,
                    "        continue-on-error: true\n" + PINS_USES,
                ),
                trusted_prepare.replace(
                    PINS_USES,
                    "        if: false\n" + PINS_USES,
                ),
                trusted_prepare.replace(
                    PINS_USES,
                    PINS_USES + "        with:\n          root: caller\n",
                ),
            ):
                with self.subTest(bypassable_pins=bypassable_pins):
                    workflow.write_text(
                        "on: [workflow_call]\npermissions: {}\njobs:\n"
                        + bypassable_pins
                        + protected_scan,
                        encoding="utf-8",
                    )
                    violations = validator.validate_permissions(root)["errors"]
                    self.assertTrue(
                        any(
                            "requires an explicit trusted/release execution-tier guard" in violation
                            for violation in violations
                        )
                    )

            for poisoned_prepare in (
                trusted_prepare.replace(
                    "  prepare:\n",
                    "  prepare:\n    env:\n      BASH_ENV: /tmp/fabricate-context\n",
                ),
                trusted_prepare.replace(
                    CONTEXT_USES,
                    CONTEXT_USES + "        env:\n          BASH_ENV: /tmp/fabricate-context\n",
                ),
                trusted_prepare.replace(
                    PINS_USES,
                    PINS_USES + "        env:\n          BASH_ENV: /tmp/bypass-pins\n",
                ),
                trusted_prepare.replace(
                    "    steps:\n",
                    "    steps:\n"
                    "      - name: Poison subsequent steps\n"
                    "        run: echo /tmp/fake-bin >> $GITHUB_PATH\n",
                ),
                trusted_prepare.replace(
                    "      - id: context\n" + CONTEXT_USES + "        with:\n"
                    "          expected-source-revision: ${{ inputs.source_revision }}\n"
                    "      - name: Verify immutable implementation closure\n" + PINS_USES,
                    "      - name: Verify immutable implementation closure\n"
                    + PINS_USES
                    + "      - id: context\n"
                    + CONTEXT_USES
                    + "        with:\n"
                    "          expected-source-revision: ${{ inputs.source_revision }}\n",
                ),
                trusted_prepare.replace(
                    "    runs-on: ubuntu-24.04\n",
                    "    runs-on: self-hosted\n",
                ),
                trusted_prepare.replace(
                    "    outputs:\n",
                    "    container: ghcr.io/ossf/scorecard-action@sha256:ae5104dd3cc28466ebeb11144354be4cac4b7ff829654f9fab89021d71c46670\n"
                    "    outputs:\n",
                ),
            ):
                with self.subTest(poisoned_prepare=poisoned_prepare):
                    workflow.write_text(
                        "on: [workflow_call]\npermissions: {}\njobs:\n"
                        + poisoned_prepare
                        + protected_scan,
                        encoding="utf-8",
                    )
                    violations = validator.validate_permissions(root)["errors"]
                    self.assertTrue(
                        any(
                            "requires an explicit trusted/release execution-tier guard" in violation
                            for violation in violations
                        )
                    )

            workflow.write_text(
                "on: [workflow_call]\nenv:\n  BASH_ENV: /tmp/fabricate-context\npermissions: {}\njobs:\n"
                + trusted_prepare
                + protected_scan,
                encoding="utf-8",
            )
            violations = validator.validate_permissions(root)["errors"]
            self.assertTrue(
                any(
                    "requires an explicit trusted/release execution-tier guard" in violation
                    for violation in violations
                )
            )

    def test_nested_permissions_key_cannot_replace_workflow_permissions(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            workflows = root / ".github/workflows"
            workflows.mkdir(parents=True)
            workflow = workflows / "nested.yaml"
            workflow.write_text(
                "on: [push]\njobs:\n  test:\n    runs-on: ubuntu-24.04\n    env:\n      permissions:\n        contents: read\n",
                encoding="utf-8",
            )
            errors = validator.validate_permissions(root)["errors"]
            self.assertTrue(
                any("missing explicit permissions declaration" in error for error in errors)
            )
            self.assertTrue(
                any(
                    "permissions must be declared at workflow level or directly on a job" in error
                    for error in errors
                )
            )

    def test_permissions_policy_rejects_ambiguous_yaml_spellings(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            workflow = root / ".github/workflows/policy.yml"
            workflow.parent.mkdir(parents=True)
            rejected = (
                'on: [push]\n"permissions": write-all\n',
                "on: [push]\npermissions: &policy\n  contents: read\njobs:\n  test:\n    permissions: *policy\n",
                "on: [push]\npermissions: {}\njobs: {test: {permissions: {checks: write}}}\n",
                "on: [push]\npermissions:\n  contents: read\n  contents: write\n",
            )
            for source in rejected:
                with self.subTest(source=source):
                    workflow.write_text(source, encoding="utf-8")
                    outcome = validator.validate_permissions(root)
                    self.assertFalse(outcome["ok"])
                    self.assertTrue(
                        any("unsupported canonical YAML" in error for error in outcome["errors"])
                    )

            workflow.write_text('on: [push]\npermissions:\n  contents: "read"\n', encoding="utf-8")
            self.assertTrue(validator.validate_permissions(root)["ok"])

    def test_schemas_and_fixtures_are_json_objects(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            schemas = root / "schemas"
            fixtures = root / "tests/fixtures"
            schemas.mkdir(parents=True)
            fixtures.mkdir(parents=True)
            (schemas / "trusted_context.schema.json").write_text("{}", encoding="utf-8")
            (fixtures / "trusted.json").write_text("{}", encoding="utf-8")
            self.assertTrue(validator.validate_schemas_and_fixtures(root)["ok"])
            (fixtures / "trusted.json").write_text("[]", encoding="utf-8")
            self.assertFalse(validator.validate_schemas_and_fixtures(root)["ok"])

    def test_trusted_context_fixtures_satisfy_the_approved_schema(self) -> None:
        schema = ROOT / "schemas/trusted_context.schema.json"
        for fixture in sorted((ROOT / "tests/fixtures").glob("*.json")):
            with self.subTest(fixture=fixture.name):
                self.assertEqual(
                    [],
                    evidence.validate_document(
                        json.loads(fixture.read_text(encoding="utf-8")), schema
                    ),
                )

    def test_evidence_requires_exact_schema_fields_and_canonical_digest(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            schema = directory / "evidence.schema.json"
            schema.write_text(
                (ROOT / "schemas/ci_evidence.schema.json").read_text(encoding="utf-8"),
                encoding="utf-8",
            )
            context = {
                "correlation_id": "correlation",
                "source_revision": "a" * 40,
                "base_revision": "b" * 40,
                "repository": "mindclade/.github",
                "workflow_ref": ".github/workflows/pull-request.yml",
                "workflow_revision": "a" * 40,
            }
            args = argparse.Namespace(
                context=None,
                context_json=json.dumps(context),
                checks='[{"name":"self-test","conclusion":"PASS","report_digest":"sha256:'
                + "c" * 64
                + '"}]',
                checks_path=None,
                report_paths=None,
                artifact_name="self-test",
                schema_version="1.0.0",
                context_digest=None,
                caller_repository=None,
                pipeline_definition_revision="b" * 40,
                producer="self-test",
                plan_id="plan",
                build_id="build",
                conclusion="success",
                reason_code="accepted",
                started_at="2026-01-01T00:00:00Z",
                completed_at="2026-01-01T00:00:01Z",
            )
            document = evidence.build_evidence(args)
            self.assertEqual([], evidence.validate_document(document, schema))
            self.assertEqual("sha256:" + evidence.sha256(context), document["context_digest"])
            document["unexpected"] = "value"
            self.assertIn(
                "$: unexpected property unexpected", evidence.validate_document(document, schema)
            )
            del document["unexpected"]
            document["checks"][0]["report_path"] = "reports/01-report.txt"
            self.assertTrue(
                any(
                    "requires property report_size" in error
                    for error in evidence.validate_document(document, schema)
                )
            )
            document["checks"][0]["report_size"] = -1
            self.assertTrue(
                any(
                    "smaller than minimum" in error
                    for error in evidence.validate_document(document, schema)
                )
            )

    def test_evidence_rejects_non_rfc3339_timestamps(self) -> None:
        schema = ROOT / "schemas/ci_evidence.schema.json"
        document = json.loads(
            (ROOT / "tests/fixtures/protected_release.json").read_text(encoding="utf-8")
        )
        evidence_document = {
            "schema_version": "1.0.0",
            "correlation_id": document["correlation_id"],
            "source_revision": document["source_revision"],
            "base_revision": document["base_revision"],
            "context_digest": "sha256:" + "a" * 64,
            "caller_repository": document["repository"],
            "workflow_ref": document["workflow_ref"],
            "workflow_revision": document["workflow_revision"],
            "pipeline_definition_revision": document["workflow_revision"],
            "producer": "github_actions",
            "plan_id": "plan-001",
            "build_id": "build-001",
            "conclusion": "PASS",
            "reason_code": "EVIDENCE_ACCEPTED",
            "checks": [
                {"name": "contract", "conclusion": "PASS", "report_digest": "sha256:" + "b" * 64}
            ],
            "started_at": "not-a-time",
            "completed_at": "also-not-a-time",
        }
        errors = evidence.validate_document(evidence_document, schema)
        self.assertTrue(any("started_at: invalid RFC3339 date-time" in error for error in errors))
        self.assertTrue(any("completed_at: invalid RFC3339 date-time" in error for error in errors))

    def test_report_digest_uses_file_bytes_and_rejects_outside_workspace(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            workspace = Path(temporary) / "workspace"
            workspace.mkdir()
            report = workspace / "report.txt"
            report.write_bytes(b"report\x00bytes")
            outside = Path(temporary) / "outside.txt"
            outside.write_text("outside", encoding="utf-8")
            old_environment = os.environ.copy()
            try:
                os.environ["GITHUB_WORKSPACE"] = str(workspace)
                args = argparse.Namespace(
                    report_paths=str(report),
                    artifact_name="report",
                    conclusion="PASS",
                    checks=None,
                    checks_path=None,
                )
                checks = evidence.checks_from_args(args)
                outside_is_safe = evidence._is_safe_report_path(str(outside))
            finally:
                os.environ.clear()
                os.environ.update(old_environment)
            self.assertEqual(
                "sha256:" + evidence.sha256(b"report\x00bytes"), checks[0]["report_digest"]
            )
            self.assertFalse(outside_is_safe)

    def test_reports_are_snapshotted_before_hashing_and_upload(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            workspace = root / "workspace"
            runner_temp = root / "runner"
            workspace.mkdir()
            runner_temp.mkdir()
            report = workspace / "report.txt"
            report.write_bytes(b"approved bytes")
            old_environment = os.environ.copy()
            try:
                os.environ["GITHUB_WORKSPACE"] = str(workspace)
                os.environ["RUNNER_TEMP"] = str(runner_temp)
                staged = evidence.stage_reports(str(report), runner_temp / "staging")
                report.write_bytes(b"mutated after staging")
                args = argparse.Namespace(
                    report_paths=str(staged[0]),
                    artifact_name="report",
                    conclusion="PASS",
                    checks=None,
                    checks_path=None,
                )
                checks = evidence.checks_from_args(args)
            finally:
                os.environ.clear()
                os.environ.update(old_environment)
            self.assertEqual(b"approved bytes", staged[0].read_bytes())
            self.assertEqual(
                "sha256:" + evidence.sha256(b"approved bytes"), checks[0]["report_digest"]
            )
            self.assertEqual(0o400, staged[0].stat().st_mode & 0o777)

    def test_downloaded_artifact_verifier_binds_complete_report_bytes(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            workspace = root / "workspace"
            runner_temp = root / "runner"
            workspace.mkdir()
            runner_temp.mkdir()
            source_report = workspace / "report.txt"
            source_report.write_bytes(b"approved report bytes")
            old_environment = os.environ.copy()
            try:
                os.environ["GITHUB_WORKSPACE"] = str(workspace)
                os.environ["RUNNER_TEMP"] = str(runner_temp)
                artifact = runner_temp / "artifact"
                staged = evidence.stage_reports(str(source_report), artifact)
                context = {
                    "correlation_id": "correlation",
                    "source_revision": "a" * 40,
                    "base_revision": "b" * 40,
                    "repository": "mindclade/.github",
                    "workflow_ref": ".github/workflows/pull-request.yml",
                    "workflow_revision": "c" * 40,
                }
                args = argparse.Namespace(
                    context=None,
                    context_json=json.dumps(context),
                    checks=None,
                    checks_path=None,
                    report_paths=str(staged[0]),
                    artifact_name="self-test",
                    schema_version="1.0.0",
                    context_digest=None,
                    caller_repository=None,
                    pipeline_definition_revision="d" * 40,
                    producer="github_actions",
                    plan_id="plan-001",
                    build_id="build-001",
                    conclusion="success",
                    reason_code="accepted",
                    started_at="2026-01-01T00:00:00Z",
                    completed_at="2026-01-01T00:00:01Z",
                )
                document = evidence.build_evidence(args)
                evidence.write_json(artifact / "ci-evidence.json", document)
                digest = "sha256:" + evidence.sha256(evidence.canonical_json(document))
                verified = evidence.verify_artifact_directory(
                    artifact,
                    expected_evidence_digest=digest,
                    expected_source_revision="a" * 40,
                )
                self.assertEqual(1, verified["report_count"])
                self.assertEqual(len(b"approved report bytes"), verified["report_bytes"])

                extra = artifact / "unexpected.txt"
                extra.write_text("unexpected", encoding="utf-8")
                with self.assertRaisesRegex(ValueError, "file set mismatch"):
                    evidence.verify_artifact_directory(artifact)
                extra.unlink()

                staged[0].chmod(0o600)
                staged[0].write_bytes(b"mutated report bytes")
                with self.assertRaisesRegex(ValueError, "report (size|digest) mismatch"):
                    evidence.verify_artifact_directory(artifact)

                staged[0].write_bytes(b"approved report bytes")
                document["checks"][0]["report_size"] += 1
                evidence.write_json(artifact / "ci-evidence.json", document)
                with self.assertRaisesRegex(ValueError, "report size mismatch"):
                    evidence.verify_artifact_directory(artifact)

                document["checks"][0]["report_size"] -= 1
                evidence.write_json(artifact / "ci-evidence.json", document)
                staged[0].unlink()
                staged[0].symlink_to(source_report)
                with self.assertRaisesRegex(ValueError, "non-symlink regular file"):
                    evidence.verify_artifact_directory(artifact)
            finally:
                os.environ.clear()
                os.environ.update(old_environment)

    def test_report_staging_rejects_symlinks_duplicates_and_size_overflow(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            workspace = root / "workspace"
            runner_temp = root / "runner"
            workspace.mkdir()
            runner_temp.mkdir()
            report = workspace / "report.txt"
            report.write_bytes(b"12345")
            symlink = workspace / "report-link.txt"
            symlink.symlink_to(report)
            symlink_directory = workspace / "linked-directory"
            real_directory = workspace / "real-directory"
            real_directory.mkdir()
            nested_report = real_directory / "nested-report.txt"
            nested_report.write_bytes(b"nested")
            symlink_directory.symlink_to(real_directory, target_is_directory=True)
            old_environment = os.environ.copy()
            try:
                os.environ["GITHUB_WORKSPACE"] = str(workspace)
                os.environ["RUNNER_TEMP"] = str(runner_temp)
                with self.assertRaisesRegex(ValueError, "symlinks"):
                    evidence.stage_reports(str(symlink), runner_temp / "symlink-staging")
                with self.assertRaisesRegex(ValueError, "symlinks"):
                    evidence.stage_reports(
                        str(symlink_directory / nested_report.name),
                        runner_temp / "ancestor-symlink-staging",
                    )
                with self.assertRaisesRegex(ValueError, "duplicate"):
                    evidence.stage_reports(f"{report}\n{report}", runner_temp / "duplicate-staging")
                with (
                    mock.patch.object(evidence, "MAX_REPORT_BYTES", 4),
                    self.assertRaisesRegex(ValueError, "per-file limit"),
                ):
                    evidence.stage_reports(str(report), runner_temp / "size-staging")
            finally:
                os.environ.clear()
                os.environ.update(old_environment)

    def test_publish_action_uploads_only_the_private_staging_directory(self) -> None:
        action = (ROOT / ".github/actions/publish-ci-evidence/action.yml").read_text(
            encoding="utf-8"
        )
        upload = action.split("    - id: upload\n", 1)[1].split("    - id: reference\n", 1)[0]
        self.assertIn("path: ${{ steps.emit.outputs.artifact_path }}", upload)
        self.assertNotIn("inputs.report-paths", upload)
        self.assertIn("artifact-ids: ${{ steps.upload.outputs.artifact-id }}", action)
        self.assertIn("verify-artifact", action)
        self.assertLess(
            action.index("Download the exact immutable artifact"),
            action.index("Bind artifact reference"),
        )
        self.assertIn("artifact_digest=%s", action)
        self.assertIn("?evidence_digest=%s&artifact_digest=%s", action)

    def test_gcs_archiver_is_create_only_and_does_not_require_object_read_access(self) -> None:
        workflow = (ROOT / ".github/workflows/reusable-required-check.yml").read_text(
            encoding="utf-8"
        )
        archive = workflow.split("  archive:\n", 1)[1]
        self.assertIn("--if-generation-match=0", archive)
        self.assertIn("--print-created-message", archive)
        self.assertIn("archive_ref=", archive)
        self.assertNotIn("storage objects describe", archive)

    def test_archive_handoff_is_exact_shape_and_validated_before_oidc(self) -> None:
        source = (ROOT / ".github/workflows/reusable-required-check.yml").read_text(
            encoding="utf-8"
        )
        validation_position = source.index("      - name: Validate archive activation inputs")
        verification_position = source.index(
            "      - name: Reverify every downloaded evidence byte before OIDC"
        )
        oidc_position = source.index("        uses: google-github-actions/auth@")
        self.assertLess(validation_position, oidc_position)
        self.assertLess(verification_position, oidc_position)
        self.assertIn("verify-artifact", source)
        for assertion in validator.ARCHIVE_HANDOFF_ASSERTIONS:
            self.assertIn(assertion, source)

        substitutions = (
            ("github-ci-evidence/providers/writer$", "github-ci-evidence/providers/substitute$"),
            ("^ci-evidence-writer@", "^substitute-writer@"),
            ("-production-ci-evidence$", "-staging-ci-evidence$"),
        )
        for approved, substitute in substitutions:
            with self.subTest(substitute=substitute), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                workflow = root / ".github/workflows/reusable-required-check.yml"
                workflow.parent.mkdir(parents=True)
                workflow.write_text(source.replace(approved, substitute, 1), encoding="utf-8")
                outcome = validator.validate_workflows(root)
                self.assertFalse(outcome["ok"])
                self.assertTrue(
                    any("archive activation" in error for error in outcome["errors"]),
                    outcome["errors"],
                )


if __name__ == "__main__":
    unittest.main()
