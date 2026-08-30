from __future__ import annotations

import argparse
import json
import os
import tempfile
import unittest
from pathlib import Path

import emit_ci_evidence as evidence
import validate_reusable_workflows as validator


ROOT = Path(__file__).resolve().parents[1]


class DeclaredPermissionsTest(unittest.TestCase):
    def test_real_repository_permission_blocks_follow_the_allowlist(self) -> None:
        outcome = validator.validate_permissions(ROOT)
        self.assertTrue(outcome["ok"], outcome["errors"])

    def test_permissions_are_explicit_and_disallow_broad_or_wrong_levels(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            workflows = root / ".github/workflows"
            workflows.mkdir(parents=True)
            workflow = workflows / "self-test.yml"
            workflow.write_text("on: [pull_request]\npermissions: write-all\n", encoding="utf-8")
            outcome = validator.validate_permissions(root)
            self.assertFalse(outcome["ok"])
            self.assertIn("permissions: write-all is forbidden", outcome["errors"][0])
            workflow.write_text("on: [pull_request]\npermissions: read-all\n", encoding="utf-8")
            self.assertIn("permissions: read-all is forbidden", validator.validate_permissions(root)["errors"][0])
            workflow.write_text("on: [pull_request]\npermissions:\n  contents: write\n  issues: read\n  id-token: write\n", encoding="utf-8")
            violations = validator.validate_permissions(root)["errors"]
            self.assertTrue(any("contents must be read" in violation for violation in violations))
            self.assertTrue(any("unapproved permission scope issues" in violation for violation in violations))
            self.assertTrue(any("id-token permission is forbidden" in violation for violation in violations))
            workflow.write_text("on: [pull_request]\npermissions:\n  contents: read\n", encoding="utf-8")
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
            self.assertTrue(any("untrusted job cannot request write permission checks" in violation for violation in violations))

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
            self.assertTrue(any("requires an explicit trusted/release execution-tier guard" in violation for violation in violations))
            trusted_prepare = (
                "  prepare:\n"
                "    runs-on: ubuntu-24.04\n"
                "    outputs:\n"
                "      execution_tier: ${{ steps.context.outputs.execution_tier }}\n"
                "    steps:\n"
                "      - id: context\n"
                "        uses: $/.github/actions/validate-trusted-context\n"
                "        with:\n"
                "          expected-source-revision: ${{ inputs.source_revision }}\n"
                "      - name: Verify immutable implementation closure\n"
                "        uses: $/.github/actions/verify-pinned-actions\n"
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
            self.assertTrue(any("requires an explicit trusted/release execution-tier guard" in violation for violation in violations))

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
            self.assertTrue(any("requires an explicit trusted/release execution-tier guard" in violation for violation in violations))

            bypassable_context = trusted_prepare.replace(
                "        uses: $/.github/actions/validate-trusted-context\n",
                "        continue-on-error: true\n        uses: $/.github/actions/validate-trusted-context\n",
            )
            workflow.write_text(
                "on: [workflow_call]\npermissions: {}\njobs:\n" + bypassable_context + protected_scan,
                encoding="utf-8",
            )
            violations = validator.validate_permissions(root)["errors"]
            self.assertTrue(any("requires an explicit trusted/release execution-tier guard" in violation for violation in violations))

            bypassable_job = trusted_prepare.replace(
                "  prepare:\n",
                "  prepare:\n    continue-on-error: true\n",
            )
            workflow.write_text(
                "on: [workflow_call]\npermissions: {}\njobs:\n" + bypassable_job + protected_scan,
                encoding="utf-8",
            )
            violations = validator.validate_permissions(root)["errors"]
            self.assertTrue(any("requires an explicit trusted/release execution-tier guard" in violation for violation in violations))

            wrong_revision = trusted_prepare.replace(
                "          expected-source-revision: ${{ inputs.source_revision }}\n",
                "          expected-source-revision: ${{ github.sha }}\n",
            )
            workflow.write_text(
                "on: [workflow_call]\npermissions: {}\njobs:\n" + wrong_revision + protected_scan,
                encoding="utf-8",
            )
            violations = validator.validate_permissions(root)["errors"]
            self.assertTrue(any("requires an explicit trusted/release execution-tier guard" in violation for violation in violations))

            for bypassable_pins in (
                trusted_prepare.replace(
                    "      - name: Verify immutable implementation closure\n"
                    "        uses: $/.github/actions/verify-pinned-actions\n",
                    "",
                ),
                trusted_prepare.replace(
                    "        uses: $/.github/actions/verify-pinned-actions\n",
                    "        continue-on-error: true\n"
                    "        uses: $/.github/actions/verify-pinned-actions\n",
                ),
                trusted_prepare.replace(
                    "        uses: $/.github/actions/verify-pinned-actions\n",
                    "        if: false\n"
                    "        uses: $/.github/actions/verify-pinned-actions\n",
                ),
                trusted_prepare.replace(
                    "        uses: $/.github/actions/verify-pinned-actions\n",
                    "        uses: $/.github/actions/verify-pinned-actions\n"
                    "        with:\n"
                    "          root: caller\n",
                ),
            ):
                with self.subTest(bypassable_pins=bypassable_pins):
                    workflow.write_text(
                        "on: [workflow_call]\npermissions: {}\njobs:\n" + bypassable_pins + protected_scan,
                        encoding="utf-8",
                    )
                    violations = validator.validate_permissions(root)["errors"]
                    self.assertTrue(
                        any("requires an explicit trusted/release execution-tier guard" in violation for violation in violations)
                    )

            for poisoned_prepare in (
                trusted_prepare.replace(
                    "  prepare:\n",
                    "  prepare:\n    env:\n      BASH_ENV: /tmp/fabricate-context\n",
                ),
                trusted_prepare.replace(
                    "        uses: $/.github/actions/validate-trusted-context\n",
                    "        uses: $/.github/actions/validate-trusted-context\n"
                    "        env:\n"
                    "          BASH_ENV: /tmp/fabricate-context\n",
                ),
                trusted_prepare.replace(
                    "        uses: $/.github/actions/verify-pinned-actions\n",
                    "        uses: $/.github/actions/verify-pinned-actions\n"
                    "        env:\n"
                    "          BASH_ENV: /tmp/bypass-pins\n",
                ),
                trusted_prepare.replace(
                    "    steps:\n",
                    "    steps:\n"
                    "      - name: Poison subsequent steps\n"
                    "        run: echo /tmp/fake-bin >> $GITHUB_PATH\n",
                ),
                trusted_prepare.replace(
                    "      - id: context\n"
                    "        uses: $/.github/actions/validate-trusted-context\n"
                    "        with:\n"
                    "          expected-source-revision: ${{ inputs.source_revision }}\n"
                    "      - name: Verify immutable implementation closure\n"
                    "        uses: $/.github/actions/verify-pinned-actions\n",
                    "      - name: Verify immutable implementation closure\n"
                    "        uses: $/.github/actions/verify-pinned-actions\n"
                    "      - id: context\n"
                    "        uses: $/.github/actions/validate-trusted-context\n"
                    "        with:\n"
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
                        "on: [workflow_call]\npermissions: {}\njobs:\n" + poisoned_prepare + protected_scan,
                        encoding="utf-8",
                    )
                    violations = validator.validate_permissions(root)["errors"]
                    self.assertTrue(
                        any("requires an explicit trusted/release execution-tier guard" in violation for violation in violations)
                    )

            workflow.write_text(
                "on: [workflow_call]\nenv:\n  BASH_ENV: /tmp/fabricate-context\npermissions: {}\njobs:\n"
                + trusted_prepare
                + protected_scan,
                encoding="utf-8",
            )
            violations = validator.validate_permissions(root)["errors"]
            self.assertTrue(any("requires an explicit trusted/release execution-tier guard" in violation for violation in violations))

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
            self.assertTrue(any("missing explicit permissions declaration" in error for error in errors))
            self.assertTrue(any("permissions must be declared at workflow level or directly on a job" in error for error in errors))

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
                    self.assertTrue(any("unsupported canonical YAML" in error for error in outcome["errors"]))

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
                self.assertEqual([], evidence.validate_document(json.loads(fixture.read_text(encoding="utf-8")), schema))

    def test_evidence_requires_exact_schema_fields_and_canonical_digest(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            schema = directory / "evidence.schema.json"
            schema.write_text((ROOT / "schemas/ci_evidence.schema.json").read_text(encoding="utf-8"), encoding="utf-8")
            context = {
                "correlation_id": "correlation",
                "source_revision": "a" * 40,
                "base_revision": "b" * 40,
                "repository": "mindclade/.github",
                "workflow_ref": ".github/workflows/self-test.yml",
                "workflow_revision": "a" * 40,
            }
            args = argparse.Namespace(
                context=None, context_json=json.dumps(context), checks='[{"name":"self-test","conclusion":"PASS","report_digest":"sha256:' + "c" * 64 + '"}]', checks_path=None, report_paths=None, artifact_name="self-test",
                schema_version="1.0.0", context_digest=None, caller_repository=None, pipeline_definition_revision="b" * 40,
                producer="self-test", plan_id="plan", build_id="build", conclusion="success", reason_code="accepted",
                started_at="2026-01-01T00:00:00Z", completed_at="2026-01-01T00:00:01Z",
            )
            document = evidence.build_evidence(args)
            self.assertEqual([], evidence.validate_document(document, schema))
            self.assertEqual("sha256:" + evidence.sha256(context), document["context_digest"])
            document["unexpected"] = "value"
            self.assertIn("$: unexpected property unexpected", evidence.validate_document(document, schema))

    def test_evidence_rejects_non_rfc3339_timestamps(self) -> None:
        schema = ROOT / "schemas/ci_evidence.schema.json"
        document = json.loads((ROOT / "tests/fixtures/protected_release.json").read_text(encoding="utf-8"))
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
            "checks": [{"name": "contract", "conclusion": "PASS", "report_digest": "sha256:" + "b" * 64}],
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
                args = argparse.Namespace(report_paths=str(report), artifact_name="report", conclusion="PASS", checks=None, checks_path=None)
                checks = evidence.checks_from_args(args)
                outside_is_safe = evidence._is_safe_report_path(str(outside))
            finally:
                os.environ.clear()
                os.environ.update(old_environment)
            self.assertEqual("sha256:" + evidence.sha256(b"report\x00bytes"), checks[0]["report_digest"])
            self.assertFalse(outside_is_safe)


if __name__ == "__main__":
    unittest.main()
