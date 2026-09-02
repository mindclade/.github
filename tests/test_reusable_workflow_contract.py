# pyright: basic, reportArgumentType=false, reportAttributeAccessIssue=false, reportCallIssue=false, reportOperatorIssue=false, reportOptionalMemberAccess=false, reportOptionalSubscript=false
from __future__ import annotations

import datetime as dt
import json
import os
import re
import subprocess
import tempfile
import unittest
from pathlib import Path

import validate_reusable_workflows as validator

ROOT = Path(__file__).resolve().parents[1]
SHA = "a" * 40


def reusable_workflow(
    *,
    source_required: str = "true",
    source_type: str = "string",
    extra_inputs: str = "",
    secrets: str = "",
    output_names: tuple[str, ...] = validator.COMMON_WORKFLOW_OUTPUTS,
) -> str:
    inputs = (
        "    inputs:\n"
        "      source_revision:\n"
        f"        required: {source_required}\n"
        f"        type: {source_type}\n"
        f"{extra_inputs}"
    )
    outputs = "    outputs:\n" + "".join(
        f"      {name}:\n        value: output\n" for name in output_names
    )
    return "on:\n  workflow_call:\n" + inputs + secrets + outputs + "permissions: {}\n"


class ReusableWorkflowContractTest(unittest.TestCase):
    def test_python_and_rego_reusable_interface_constants_are_identical(self) -> None:
        policy = (ROOT / "policy/reusable_workflow_interface.rego").read_text(encoding="utf-8")

        def rego_set(name: str) -> set[str]:
            block = policy.split(f"{name} := {{", 1)[1].split("}", 1)[0]
            return set(re.findall(r'"([a-z0-9_-]+)"', block))

        self.assertEqual(set(validator.DERIVED_TRUST_INPUTS), rego_set("derived_trust_inputs"))
        self.assertEqual(set(validator.ALLOWED_INPUT_TYPES), rego_set("allowed_input_types"))
        self.assertEqual(set(validator.BUILDKITE_SECRETS), rego_set("allowed_buildkite_secrets"))
        path_block = policy.split("buildkite_workflow_paths := {", 1)[1].split("}", 1)[0]
        self.assertEqual(
            set(validator.BUILDKITE_WORKFLOW_PATHS), set(re.findall(r'"([^"]+)"', path_block))
        )

    def test_python_and_rego_permission_allowlists_are_identical(self) -> None:
        policy = (ROOT / "policy/workflow_permissions.rego").read_text(encoding="utf-8")
        block = policy.split("allowed_permissions := {", 1)[1].split("}\n", 1)[0]
        permissions = dict(re.findall(r'^[\t ]+"([^"]+)": "([^"]+)"(?:,)?$', block, re.MULTILINE))
        self.assertEqual(validator.ALLOWED_PERMISSIONS, permissions)
        guard_block = policy.split("protected_tier_guards := {", 1)[1].split("}\n", 1)[0]
        self.assertEqual(
            set(validator.PROTECTED_TIER_GUARDS),
            set(re.findall(r'^[\t ]+"([^"]+)"(?:,)?$', guard_block, re.MULTILINE)),
        )

    def test_repository_matches_the_approved_inventory(self) -> None:
        outcome = validator.validate_inventory(ROOT)
        self.assertTrue(outcome["ok"], outcome["errors"])
        self.assertEqual(len(validator.EXPECTED_INVENTORY), outcome["expected"])
        self.assertIn(".github/actionlint.yaml", validator.EXPECTED_INVENTORY)
        self.assertIn(".github/workflows/pull-request.yml", validator.EXPECTED_INVENTORY)
        self.assertIn(
            "policy/tests/reusable_workflow_interface_test.rego", validator.EXPECTED_INVENTORY
        )

    def test_pull_request_workflow_exports_the_governed_required_context(self) -> None:
        workflow = ROOT / ".github/workflows/pull-request.yml"
        document, parse_error = validator._parsed_yaml(workflow, ROOT)
        self.assertIsNone(parse_error)
        self.assertIsInstance(document, dict)
        self.assertEqual("Pull request", document["name"])
        self.assertEqual(
            {"pull_request", "merge_group", "push", "workflow_dispatch"},
            set(document["on"]),
        )
        self.assertEqual(["main"], document["on"]["push"]["branches"])
        self.assertEqual({"contents": "read"}, document["permissions"])
        required = document["jobs"]["required"]
        self.assertEqual("required", required["name"])
        self.assertEqual({"contents": "read"}, required["permissions"])

    def test_nix_config_guards_accept_wrapped_and_scalar_values(self) -> None:
        approved = {
            "substituters": ["https://cache.nixos.org/"],
            "trusted-public-keys": [
                "cache.nixos.org-1:6NCHdD59X431o0gWypbMrAURkbJ16ZPMQFGspcDShjY="
            ],
            "require-sigs": True,
            "accept-flake-config": False,
        }
        fixtures = (
            approved,
            {key: {"value": value, "source": "workflow"} for key, value in approved.items()},
        )
        workflow_paths = (
            ".github/workflows/pull-request.yml",
            ".github/workflows/reusable-nix-validation.yml",
        )
        for workflow_path in workflow_paths:
            source = (ROOT / workflow_path).read_text(encoding="utf-8")
            jq_filter = source.split("nix config show --json | jq -e '\n", 1)[1].split(
                "\n          ' >/dev/null", 1
            )[0]
            for fixture in fixtures:
                with self.subTest(workflow=workflow_path, shape=type(fixture["substituters"])):
                    result = subprocess.run(
                        ["jq", "-e", jq_filter],
                        input=json.dumps(fixture),
                        capture_output=True,
                        check=False,
                        text=True,
                    )
                    self.assertEqual(0, result.returncode, result.stderr)
            rejected = {**approved, "accept-flake-config": True}
            result = subprocess.run(
                ["jq", "-e", jq_filter],
                input=json.dumps(rejected),
                capture_output=True,
                check=False,
                text=True,
            )
            self.assertNotEqual(0, result.returncode)

    def test_complete_validator_accepts_the_real_repository(self) -> None:
        outcome = validator.validate(ROOT)
        self.assertTrue(outcome["ok"], outcome["errors"])

    def test_buildkite_template_has_secretless_fork_and_trusted_dispatch_paths(self) -> None:
        template = ROOT / validator.BUILDKITE_BRIDGE_TEMPLATE_PATH
        document, parse_error = validator._parsed_yaml(template, ROOT)
        self.assertIsNone(parse_error)
        self.assertIsInstance(document, dict)
        self.assertEqual(
            [],
            validator._buildkite_bridge_errors(
                document, Path(validator.BUILDKITE_BRIDGE_TEMPLATE_PATH)
            ),
        )
        self.assertEqual(
            "mindclade-buildkite-bridge-${{ github.repository }}-${{ github.workflow }}-${{ github.event.pull_request.number || github.ref }}",
            document["concurrency"]["group"],
        )
        required_secrets = document["jobs"]["buildkite_required"]["secrets"]
        self.assertEqual(
            "${{ secrets.MINDCLADE_BUILDKITE_CANCEL_TOKEN }}",
            required_secrets["buildkite_cancel_token"],
        )

        source = template.read_text(encoding="utf-8")
        mutations = (
            source.replace("  pull_request:\n", "  pull_request_target:\n", 1),
            source.replace(
                "needs.classify.outputs.trust_classification == 'trusted'",
                "needs.classify.outputs.trust_classification == 'untrusted'",
                1,
            ),
            source.replace(
                "    uses: mindclade/.github/.github/workflows/reusable-documentation-check.yml@",
                "    secrets:\n      leaked: ${{ secrets.MINDCLADE_BUILDKITE_PIPELINE }}\n    uses: mindclade/.github/.github/workflows/reusable-documentation-check.yml@",
                1,
            ),
            source.replace(
                "    permissions:\n      actions: read\n      contents: read\n      id-token: write\n",
                "    permissions: {}\n",
                1,
            ),
            source.replace("-${{ github.workflow }}", "", 1),
            source.replace(
                "${{ github.event.pull_request.number || github.ref }}", "${{ github.sha }}", 1
            ),
        )
        for mutation in mutations:
            with self.subTest(mutation=mutation), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                candidate = root / validator.BUILDKITE_BRIDGE_TEMPLATE_PATH
                candidate.parent.mkdir(parents=True)
                candidate.write_text(mutation, encoding="utf-8")
                self.assertFalse(validator.validate_workflows(root)["ok"])

    def test_buildkite_dispatch_resolves_definition_before_candidate_checkout(self) -> None:
        workflow = ROOT / validator.BUILDKITE_DISPATCH_WORKFLOW_PATH
        document, parse_error = validator._parsed_yaml(workflow, ROOT)
        self.assertIsNone(parse_error)
        self.assertIsInstance(document, dict)
        self.assertEqual(
            [],
            validator._buildkite_dispatch_errors(
                document, Path(validator.BUILDKITE_DISPATCH_WORKFLOW_PATH)
            ),
        )

        source = workflow.read_text(encoding="utf-8")
        mutations = (
            source.replace(
                '--commit "${PIPELINE_DEFINITION_REVISION}"', '--commit "${SOURCE_REVISION}"', 1
            ),
            source.replace(
                'pipeline_definition_revision="${BASE_REVISION}"',
                'pipeline_definition_revision="${SOURCE_REVISION}"',
                1,
            ),
            source.replace(
                '--expected-pipeline-definition-revision "${PIPELINE_DEFINITION_REVISION}"', "", 1
            ),
            source.replace(
                "      pipeline_class:\n",
                "      pipeline_definition_revision:\n        required: true\n        type: string\n      pipeline_class:\n",
                1,
            ),
        )
        for mutation in mutations:
            with self.subTest(mutation=mutation), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                candidate = root / validator.BUILDKITE_DISPATCH_WORKFLOW_PATH
                candidate.parent.mkdir(parents=True)
                candidate.write_text(mutation, encoding="utf-8")
                self.assertFalse(validator.validate_workflows(root)["ok"])

    def test_inventory_rejects_undeclared_executable_sources(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            for relative in validator.EXPECTED_INVENTORY:
                path = root / relative
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text("placeholder\n", encoding="utf-8")
            self.assertTrue(validator.validate_inventory(root)["ok"])
            extra = root / ".github/workflows/evil.yaml"
            extra.write_text("on: [push]\npermissions: {}\n", encoding="utf-8")
            outcome = validator.validate_inventory(root)
            self.assertFalse(outcome["ok"])
            self.assertIn("unexpected: .github/workflows/evil.yaml", outcome["errors"])
            extra.unlink()
            (root / "BLUEPRINT.md").write_text("stale local authority\n", encoding="utf-8")
            outcome = validator.validate_inventory(root)
            self.assertFalse(outcome["ok"])
            self.assertIn("unexpected: BLUEPRINT.md", outcome["errors"])
            (root / "BLUEPRINT.md").unlink()
            for name in ("bazel-bin", "bazel-out", "bazel-testlogs", f"bazel-{root.name}"):
                (root / name).symlink_to(root / "missing-bazel-output")
            self.assertTrue(validator.validate_inventory(root)["ok"])
            previous_directory = Path.cwd()
            try:
                os.chdir(root)
                self.assertTrue(validator.validate_inventory(Path())["ok"])
            finally:
                os.chdir(previous_directory)

    def test_context_interface_writes_all_contract_outputs(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            event = Path(temporary) / "event.json"
            output = Path(temporary) / "github-output"
            event.write_text(
                json.dumps(
                    {
                        "pull_request": {
                            "head": {"sha": SHA, "repo": {"fork": False}},
                            "base": {"sha": "b" * 40},
                        }
                    }
                ),
                encoding="utf-8",
            )
            old_environment = os.environ.copy()
            try:
                os.environ.update(
                    {
                        "GITHUB_EVENT_NAME": "pull_request",
                        "GITHUB_REPOSITORY": "mindclade/.github",
                        "GITHUB_ACTOR": "mindclade-bot",
                        "GITHUB_REF": "refs/heads/main",
                        "GITHUB_SHA": SHA,
                        "GITHUB_RUN_ID": "123",
                        "GITHUB_RUN_ATTEMPT": "1",
                        "GITHUB_WORKFLOW_REF": "mindclade/.github/.github/workflows/reusable-required-check.yml@"
                        + SHA,
                    }
                )
                exit_code = validator.main(
                    [
                        "context",
                        "--event-path",
                        str(event),
                        "--expected-source-revision",
                        SHA,
                        "--allowed-execution-tiers",
                        "untrusted,trusted",
                        "--github-output",
                        str(output),
                    ]
                )
            finally:
                os.environ.clear()
                os.environ.update(old_environment)
            self.assertEqual(0, exit_code)
            values = dict(
                line.split("=", 1) for line in output.read_text(encoding="utf-8").splitlines()
            )
            self.assertEqual("allow", values["verdict"])
            self.assertEqual("accepted", values["reason_code"])
            self.assertEqual(SHA, values["source_revision"])
            self.assertEqual("b" * 40, values["base_revision"])
            self.assertEqual("trusted", values["source_trust"])
            self.assertEqual("untrusted", values["execution_tier"])
            self.assertRegex(values["context_digest"], r"^sha256:[0-9a-f]{64}$")
            context = json.loads(values["context_json"])
            self.assertEqual("mindclade/.github", context["repository"])
            self.assertEqual(SHA, context["workflow_revision"])

    def test_context_rejects_stale_revision_without_side_effects(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            event = Path(temporary) / "event.json"
            event.write_text(json.dumps({"after": SHA}), encoding="utf-8")
            old_environment = os.environ.copy()
            try:
                os.environ.update({"GITHUB_EVENT_NAME": "push", "GITHUB_SHA": SHA})
                outcome = validator.trusted_context(event, "b" * 40, {"trusted"})
            finally:
                os.environ.clear()
                os.environ.update(old_environment)
            self.assertEqual("deny", outcome["verdict"])
            self.assertEqual("source_revision_mismatch", outcome["reason_code"])

    def test_reusable_workflow_requires_workflow_call(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            workflows = root / ".github/workflows"
            workflows.mkdir(parents=True)
            (workflows / "reusable-required-check.yml").write_text(
                "on: [pull_request]\npermissions: {}\n", encoding="utf-8"
            )
            outcome = validator.validate_workflows(root)
            self.assertFalse(outcome["ok"])
            self.assertIn("reusable workflow must declare workflow_call", outcome["errors"][0])

    def test_actual_reusable_workflow_interfaces_pass_the_stdlib_validator(self) -> None:
        outcome = validator.validate_workflows(ROOT)
        self.assertTrue(outcome["ok"], outcome["errors"])

    def test_all_repository_workflows_have_bounded_concurrency(self) -> None:
        workflow_paths = sorted((ROOT / ".github/workflows").glob("*.yml"))
        self.assertEqual(9, len(workflow_paths))
        for path in workflow_paths:
            with self.subTest(workflow=path.name):
                document, parse_error = validator._parsed_yaml(path, ROOT)
                self.assertIsNone(parse_error)
                self.assertEqual(
                    [],
                    validator._bounded_concurrency_errors(document, path.relative_to(ROOT)),
                )

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            workflow = root / ".github/workflows/pull-request.yml"
            workflow.parent.mkdir(parents=True)
            workflow.write_text(
                "on: [push]\npermissions: {}\njobs:\n  test:\n    runs-on: ubuntu-24.04\n",
                encoding="utf-8",
            )
            outcome = validator.validate_workflows(root)
            self.assertFalse(outcome["ok"])
            self.assertTrue(any("bounded concurrency" in error for error in outcome["errors"]))

        reusable_path = Path(".github/workflows/reusable-documentation-check.yml")
        reusable_groups = (
            (
                "reusable-${{ github.repository }}-${{ github.event.pull_request.number || github.ref }}",
                "must include the caller github.workflow",
            ),
            (
                "reusable-${{ github.repository }}-${{ github.workflow }}",
                "must include its stable pull-request/ref boundary",
            ),
            (
                "reusable-${{ github.repository }}-${{ github.workflow }}-${{ github.event.pull_request.number || github.ref }}-${{ inputs.source_revision }}",
                "must not create a lane per source revision",
            ),
        )
        for group, expected_error in reusable_groups:
            with self.subTest(group=group):
                document = {
                    "jobs": {"test": {"runs-on": "ubuntu-24.04"}},
                    "concurrency": {
                        "group": group,
                        "cancel-in-progress": "${{ github.event_name == 'pull_request' }}",
                    },
                }
                errors = validator._bounded_concurrency_errors(document, reusable_path)
                self.assertTrue(any(expected_error in error for error in errors), errors)

        valid_group = (
            "reusable-${{ github.repository }}-${{ github.workflow }}-"
            "${{ github.event.pull_request.number || github.ref }}"
        )
        for cancellation in (True, False, "${{ github.event_name != 'merge_group' }}"):
            with self.subTest(cancellation=cancellation):
                errors = validator._bounded_concurrency_errors(
                    {
                        "jobs": {"test": {"runs-on": "ubuntu-24.04"}},
                        "concurrency": {
                            "group": valid_group,
                            "cancel-in-progress": cancellation,
                        },
                    },
                    reusable_path,
                )
                self.assertTrue(any("only pull_request" in error for error in errors), errors)

    def test_buildkite_secret_classification_uses_the_repository_path_not_display_name(
        self,
    ) -> None:
        secret = "    secrets:\n      buildkite_evidence_token:\n        required: true\n"
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            workflows = root / ".github/workflows"
            workflows.mkdir(parents=True)
            spoof = workflows / "reusable-documentation-check.yml"
            spoof.write_text(
                "name: reusable-required-check\n" + reusable_workflow(secrets=secret),
                encoding="utf-8",
            )
            outcome = validator.validate_workflows(root)
            self.assertFalse(outcome["ok"])
            self.assertTrue(
                any("non-Buildkite reusable workflow" in error for error in outcome["errors"])
            )

            spoof.unlink()
            approved = workflows / "reusable-required-check.yml"
            approved.write_text(
                "name: arbitrary-display-name\n" + reusable_workflow(secrets=secret),
                encoding="utf-8",
            )
            self.assertTrue(validator.validate_workflows(root)["ok"])

    def test_action_policy_rejects_ambiguous_yaml_spellings(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            workflow = root / ".github/workflows/pull-request.yml"
            workflow.parent.mkdir(parents=True)
            rejected = (
                'on: [push]\npermissions: {}\nsteps:\n  - "uses": actions/checkout@main\n',
                'on: [push]\npermissions: {}\nsteps:\n  - {"uses": actions/checkout@main}\n',
                "on: [push]\npermissions: {}\nsteps: [uses: actions/checkout@main]\n",
                "on: [push]\npermissions: {}\nsteps: ['uses': 'actions/checkout@main']\n",
                "on: [push]\npermissions: {}\nsteps:\n  - uses: &checkout actions/checkout@main\n  - uses: *checkout\n",
                f"on: [push]\npermissions: {{}}\nsteps:\n  - uses: actions/checkout@{SHA}\n    uses: actions/checkout@main\n",
            )
            for source in rejected:
                with self.subTest(source=source):
                    workflow.write_text(source, encoding="utf-8")
                    pins = validator.validate_pins(root)
                    workflows = validator.validate_workflows(root)
                    self.assertFalse(pins["ok"])
                    self.assertFalse(workflows["ok"])
                    self.assertTrue(
                        any("unsupported canonical YAML" in error for error in pins["errors"])
                    )
                    self.assertTrue(
                        any("unsupported canonical YAML" in error for error in workflows["errors"])
                    )

    def test_run_scripts_reject_all_caller_input_expression_spellings(self) -> None:
        expressions = (
            "${{ inputs.build_id }}",
            "${{ inputs . build_id }}",
            "${{ inputs .build_id }}",
            "${{ inputs ['build_id'] }}",
            "${{ format('{0}', inputs.build_id) }}",
            "${{ format('}}{0}', inputs.build_id) }}",
            "${{ fromJSON(toJSON(inputs)).build_id }}",
            "${{ INPUTS.build_id }}",
            "${{ Inputs.build_id }}",
        )
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            workflow = root / ".github/workflows/pull-request.yml"
            workflow.parent.mkdir(parents=True)
            for expression in expressions:
                with self.subTest(expression=expression):
                    workflow.write_text(
                        "on: [push]\npermissions: {}\njobs:\n  test:\n    runs-on: ubuntu-24.04\n"
                        f'    steps:\n      - run: echo "{expression}"\n',
                        encoding="utf-8",
                    )
                    outcome = validator.validate_workflows(root)
                    self.assertFalse(outcome["ok"])
                    self.assertTrue(
                        any("through the environment" in error for error in outcome["errors"])
                    )

    def test_reusable_workflow_rejects_invalid_source_and_derived_trust_inputs(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            workflows = root / ".github/workflows"
            workflows.mkdir(parents=True)
            (workflows / "reusable-example.yml").write_text(
                reusable_workflow(
                    source_required="false",
                    source_type="boolean",
                    extra_inputs=(
                        "      execution_tier:\n"
                        "        required: false\n"
                        "        type: string\n"
                        "      Execution_Tier:\n"
                        "        required: false\n"
                        "        type: string\n"
                        "      source_trust:\n"
                        "        required: false\n"
                        "        type: object\n"
                    ),
                ),
                encoding="utf-8",
            )
            outcome = validator.validate_workflows(root)
            self.assertFalse(outcome["ok"])
            joined = "\n".join(outcome["errors"])
            self.assertIn("source_revision input must be required: true", joined)
            self.assertIn("source_revision input must have type: string", joined)
            self.assertIn("workflow_call input execution_tier is derived and forbidden", joined)
            self.assertIn("workflow_call input Execution_Tier is derived and forbidden", joined)
            self.assertIn("workflow_call input source_trust is derived and forbidden", joined)
            self.assertIn(
                "workflow_call input source_trust must declare string, boolean, or number type",
                joined,
            )
            self.assertIn("differ only by case", joined)

    def test_reusable_workflow_rejects_missing_outputs_and_unapproved_secrets(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            workflows = root / ".github/workflows"
            workflows.mkdir(parents=True)
            (workflows / "reusable-example.yml").write_text(
                reusable_workflow(
                    secrets="    secrets:\n      buildkite_dispatch_token:\n        required: false\n",
                    output_names=validator.COMMON_WORKFLOW_OUTPUTS[:-1],
                )
                + "secrets: inherit\n",
                encoding="utf-8",
            )
            outcome = validator.validate_workflows(root)
            self.assertFalse(outcome["ok"])
            joined = "\n".join(outcome["errors"])
            self.assertIn("workflow_call output evidence_ref is required", joined)
            self.assertIn(
                "non-Buildkite reusable workflow may not declare secret buildkite_dispatch_token",
                joined,
            )
            self.assertIn("secrets: inherit is forbidden", joined)

    def test_buildkite_reusable_workflow_rejects_unknown_secret(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            workflows = root / ".github/workflows"
            workflows.mkdir(parents=True)
            (workflows / "reusable-buildkite-dispatch.yml").write_text(
                reusable_workflow(
                    secrets="    secrets:\n      unapproved_token:\n        required: false\n",
                ),
                encoding="utf-8",
            )
            outcome = validator.validate_workflows(root)
            self.assertFalse(outcome["ok"])
            self.assertIn(
                "Buildkite reusable workflow declares unapproved secret unapproved_token",
                "\n".join(outcome["errors"]),
            )

    def test_validate_can_select_an_immutable_closure_subset(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            workflows = root / ".github/workflows"
            workflows.mkdir(parents=True)
            (workflows / "pull-request.yml").write_text(
                "on: [push]\npermissions: {}\n", encoding="utf-8"
            )
            outcome = validator.validate(
                root, validator.selected_checks("pins,permissions,workflows")
            )
            self.assertTrue(outcome["ok"], outcome["errors"])
            self.assertEqual(
                ["pins", "permissions", "workflows"],
                validator.selected_checks("pins,permissions,workflows"),
            )
            with self.assertRaises(ValueError):
                validator.selected_checks("pins,,workflows")
            with self.assertRaises(ValueError):
                validator.selected_checks("pins,unknown")

    def test_source_closure_digest_is_path_independent_and_content_bound(self) -> None:
        with tempfile.TemporaryDirectory() as first, tempfile.TemporaryDirectory() as second:
            first_root = Path(first)
            second_root = Path(second)
            for root in (first_root, second_root):
                workflow = root / ".github/workflows/pull-request.yml"
                workflow.parent.mkdir(parents=True)
                workflow.write_text("on: [push]\npermissions: {}\n", encoding="utf-8")
            baseline = validator.source_closure_digest(first_root)
            self.assertEqual(baseline, validator.source_closure_digest(second_root))
            (second_root / ".github/workflows/pull-request.yml").write_text(
                "on: [pull_request]\npermissions: {}\n", encoding="utf-8"
            )
            self.assertNotEqual(baseline, validator.source_closure_digest(second_root))
            baseline = validator.source_closure_digest(first_root)
            (first_root / "MODULE.bazel").write_text('module(name = "changed")\n', encoding="utf-8")
            self.assertNotEqual(baseline, validator.source_closure_digest(first_root))
            baseline = validator.source_closure_digest(first_root)
            (first_root / ".github/workflows/evil.yaml").write_text(
                "on: [push]\npermissions: {}\n", encoding="utf-8"
            )
            self.assertNotEqual(baseline, validator.source_closure_digest(first_root))

    def test_selected_source_closure_does_not_hash_unrelated_consumer_files(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            component = root / "component.yaml"
            component.write_text("kind: Component\n", encoding="utf-8")
            unrelated = root / "large-build-output.bin"
            unrelated.write_bytes(b"unrelated")
            baseline = validator.source_closure_digest(root, ["component.yaml"])
            unrelated.write_bytes(b"changed")
            self.assertEqual(baseline, validator.source_closure_digest(root, ["component.yaml"]))
            component.write_text("kind: Changed\n", encoding="utf-8")
            self.assertNotEqual(baseline, validator.source_closure_digest(root, ["component.yaml"]))

    def test_composite_action_interface_is_checked_without_actionlint(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            action = root / ".github/actions/example/action.yml"
            action.parent.mkdir(parents=True)
            action.write_text(
                "name: Example\ndescription: Example\nruns:\n  using: node20\n", encoding="utf-8"
            )
            outcome = validator.validate_workflows(root)
            self.assertFalse(outcome["ok"])
            self.assertIn("action must use the composite runtime", outcome["errors"][0])

    def test_component_metadata_is_validated_by_structure_and_type(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            component = root / "component.yaml"
            valid = (
                "apiVersion: mindclade.io/v1alpha1\n"
                "kind: Component\n"
                "metadata:\n"
                "  name: example\n"
                "spec:\n"
                "  owner: developer-platform\n"
                "  maturity: pre-production\n"
                "  repository_class: governance-source\n"
                "  trust_tier: trusted\n"
                "  recovery_tier: tier-1\n"
                "  dependencies: []\n"
                "  release:\n"
                "    strategy: reviewed-main\n"
                "    artifact: source-commit\n"
                "    immutable: true\n"
            )
            component.write_text(valid, encoding="utf-8")
            self.assertTrue(validator.validate_metadata(root)["ok"])
            component.write_text(
                valid.replace(
                    "  dependencies: []", "  dependencies:\n    - component: mindclade/example"
                ),
                encoding="utf-8",
            )
            self.assertTrue(validator.validate_metadata(root)["ok"])

            product = (
                "apiVersion: components.mindclade.dev/v1alpha1\n"
                "kind: Component\n"
                "metadata:\n"
                "  name: example-product\n"
                "spec:\n"
                "  type: repository\n"
                "  owner: '@mindclade/platform-runtime'\n"
                "  maturity: experimental\n"
                "  visibility: private\n"
                "  dataClassification: internal\n"
                "  description: Governed product repository.\n"
                "  dependencies: []\n"
                "  release:\n"
                "    mode: none\n"
                "    artifact: null\n"
                "    version: null\n"
                "    public: false\n"
                "    controls: []\n"
            )
            component.write_text(product, encoding="utf-8")
            self.assertTrue(validator.validate_metadata(root)["ok"])
            component.write_text(
                product.replace("    mode: none", "    mode: null"), encoding="utf-8"
            )
            self.assertFalse(validator.validate_metadata(root)["ok"])
            component.write_text(
                product.replace("    mode: none", "    mode: package"), encoding="utf-8"
            )
            self.assertFalse(validator.validate_metadata(root)["ok"])

            invalid = (
                valid.replace("  owner: developer-platform", "  owner: null"),
                valid.replace("  owner: developer-platform", "  owner: NULL"),
                valid.replace("  owner: developer-platform", "  owner: 1.5"),
                valid.replace("  owner: developer-platform", "  owner: 0b101"),
                valid.replace("  owner: developer-platform", "  owner: 1:20"),
                valid.replace("  maturity: pre-production", "  maturity: Null"),
                valid.replace("  maturity: pre-production", "  maturity: []"),
                valid.replace("  repository_class: governance-source\n", ""),
                valid.replace("  trust_tier: trusted", "  trust_tier: null"),
                valid.replace("  recovery_tier: tier-1", "  recovery_tier: []"),
                valid.replace("  dependencies: []", "  dependencies: null"),
                valid.replace("  dependencies: []", "  dependencies: [NULL]"),
                valid.replace("  dependencies: []", "  dependencies:\n    - null"),
                valid.replace(
                    "  dependencies: []", "  dependencies:\n    - owner: developer-platform"
                ),
                valid.replace(
                    "  release:\n    strategy: reviewed-main\n    artifact: source-commit\n    immutable: true",
                    "  release: TRUE",
                ),
                valid.replace(
                    "  release:\n    strategy: reviewed-main\n    artifact: source-commit\n    immutable: true",
                    "  release: arbitrary-string",
                ),
                valid.replace(
                    "  release:\n    strategy: reviewed-main\n    artifact: source-commit\n    immutable: true",
                    "  release: {}",
                ),
                valid.replace("    strategy: reviewed-main", "    nonsense: complete"),
                valid.replace("    artifact: source-commit\n", ""),
                valid.replace("    immutable: true", "    immutable: yes-please"),
                valid.replace(
                    "spec:\n  owner: developer-platform", "owner: developer-platform\nspec:"
                ),
            )
            for source in invalid:
                with self.subTest(source=source):
                    component.write_text(source, encoding="utf-8")
                    self.assertFalse(validator.validate_metadata(root)["ok"])

    def test_metadata_and_documentation_paths_cannot_escape_repository_root(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            root = base / "repository"
            outside = base / "outside"
            root.mkdir()
            outside.mkdir()
            component_source = (
                "apiVersion: mindclade.io/v1alpha1\n"
                "kind: Component\n"
                "metadata:\n"
                "  name: example\n"
                "spec:\n"
                "  owner: developer-platform\n"
                "  maturity: pre-production\n"
                "  repository_class: governance-source\n"
                "  trust_tier: trusted\n"
                "  recovery_tier: tier-1\n"
                "  dependencies: []\n"
                "  release:\n"
                "    strategy: reviewed-main\n"
                "    artifact: source-commit\n"
                "    immutable: true\n"
            )
            (root / "component.yaml").write_text(component_source, encoding="utf-8")
            (root / "README.md").write_text(
                "# Inside\n\nOwner: @mindclade/developer-platform\n"
                f"Last reviewed: {dt.date.today().isoformat()}\nReview cadence: 365 days\n\n"
                "## Ownership\n\nOwned.\n\n## Activation boundary\n\nSource only.\n",
                encoding="utf-8",
            )
            (outside / "component.yaml").write_text(component_source, encoding="utf-8")
            (outside / "README.md").write_text("# Outside\n", encoding="utf-8")

            self.assertTrue(validator.validate_metadata(root, required_files=["README.md"])["ok"])
            self.assertTrue(validator.validate_documentation(root, ["README.md"])["ok"])
            for path in ("../outside/component.yaml", str(outside / "component.yaml")):
                with self.subTest(component_path=path):
                    self.assertFalse(validator.validate_metadata(root, component_path=path)["ok"])
            for path in ("../outside/README.md", str(outside / "README.md")):
                with self.subTest(required_path=path):
                    self.assertFalse(validator.validate_metadata(root, required_files=[path])["ok"])
                with self.subTest(documentation_path=path):
                    self.assertFalse(validator.validate_documentation(root, [path])["ok"])

            (root / "component-link.yaml").symlink_to(outside / "component.yaml")
            (root / "README-link.md").symlink_to(outside / "README.md")
            self.assertFalse(
                validator.validate_metadata(root, component_path="component-link.yaml")["ok"]
            )
            self.assertFalse(
                validator.validate_metadata(root, required_files=["README-link.md"])["ok"]
            )
            self.assertFalse(validator.validate_documentation(root, ["README-link.md"])["ok"])

    def test_documentation_requires_structure_ownership_and_resolved_local_links(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            readme = root / "README.md"
            readme.write_text("TODO: [missing](missing.md)\n", encoding="utf-8")
            outcome = validator.validate_documentation(root, ["README.md"])
            self.assertFalse(outcome["ok"])
            joined = "\n".join(outcome["errors"])
            self.assertIn("one H1 title", joined)
            self.assertIn("missing required section Ownership", joined)
            self.assertIn("missing explicit Mindclade owner metadata", joined)
            self.assertIn("contains placeholder documentation", joined)
            self.assertIn("local link target does not exist", joined)

    def test_documentation_resolves_nested_parent_and_reference_links_without_root_escape(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            root = base / "repository"
            docs = root / "docs/deep"
            docs.mkdir(parents=True)
            (root / "README.md").write_text("# Root\n", encoding="utf-8")
            (root / "GOVERNANCE.md").write_text("# Governance\n", encoding="utf-8")
            guide = docs / "guide.md"
            guide.write_text(
                "# Guide\n\n[Root](../../README.md) and [governance][gov].\n\n"
                '[gov]: <../../GOVERNANCE.md> "policy"\n',
                encoding="utf-8",
            )
            self.assertTrue(validator.validate_documentation(root, ["docs"])["ok"])

            outside = base / "outside.md"
            outside.write_text("# Outside\n", encoding="utf-8")
            guide.write_text(
                "# Guide\n\n[escape](../../../outside.md) and [missing][unknown].\n",
                encoding="utf-8",
            )
            outcome = validator.validate_documentation(root, ["docs"])
            self.assertFalse(outcome["ok"])
            joined = "\n".join(outcome["errors"])
            self.assertIn("local link target does not exist", joined)
            self.assertIn("undefined Markdown reference", joined)

    def test_documentation_review_metadata_must_be_parseable_and_current(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            readme = root / "README.md"

            def source(reviewed: str, cadence: str) -> str:
                return (
                    "# Repository\n\nOwner: @mindclade/developer-platform\n"
                    f"Last reviewed: {reviewed}\nReview cadence: {cadence}\n\n"
                    "## Ownership\n\nOwned.\n\n## Activation boundary\n\nSource-only.\n"
                )

            readme.write_text(source(dt.date.today().isoformat(), "365 days"), encoding="utf-8")
            self.assertTrue(validator.validate_documentation(root, ["README.md"])["ok"])
            for reviewed, cadence, expected in (
                ("not-a-date", "365 days", "ISO YYYY-MM-DD"),
                ("2000-01-01", "365 days", "stale"),
                (dt.date.today().isoformat(), "annually", "between 1 and 366 days"),
            ):
                with self.subTest(reviewed=reviewed, cadence=cadence):
                    readme.write_text(source(reviewed, cadence), encoding="utf-8")
                    errors = validator.validate_documentation(root, ["README.md"])["errors"]
                    self.assertTrue(any(expected in error for error in errors), errors)

    def test_context_marks_fork_pull_requests_as_untrusted(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            event = Path(temporary) / "event.json"
            event.write_text(
                json.dumps(
                    {
                        "pull_request": {
                            "head": {"sha": SHA, "repo": {"fork": True}},
                            "base": {"sha": "b" * 40},
                        }
                    }
                ),
                encoding="utf-8",
            )
            old_environment = os.environ.copy()
            try:
                os.environ.update({"GITHUB_EVENT_NAME": "pull_request", "GITHUB_SHA": SHA})
                outcome = validator.trusted_context(event, SHA, {"untrusted"})
            finally:
                os.environ.clear()
                os.environ.update(old_environment)
            self.assertEqual("untrusted", outcome["context"]["source_trust"])
            self.assertEqual("untrusted", outcome["context"]["execution_tier"])

    def test_context_maps_review_refresh_to_the_pull_request_head(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            event = Path(temporary) / "event.json"
            event.write_text(
                json.dumps(
                    {
                        "pull_request": {
                            "head": {
                                "sha": SHA,
                                "ref": "feature/review-refresh",
                                "repo": {"fork": False},
                            },
                            "base": {"sha": "b" * 40},
                        },
                        "review": {"state": "approved"},
                    }
                ),
                encoding="utf-8",
            )
            old_environment = os.environ.copy()
            try:
                os.environ.update(
                    {
                        "GITHUB_EVENT_NAME": "pull_request_review",
                        "GITHUB_ACTOR": "mindclade-bot",
                        "GITHUB_REF": "refs/pull/7/merge",
                        "GITHUB_REF_PROTECTED": "false",
                        "GITHUB_REPOSITORY": "mindclade/.github",
                        "GITHUB_SHA": "c" * 40,
                        "GITHUB_WORKFLOW_REF": (
                            "mindclade/.github/.github/workflows/pull-request.yml@" + SHA
                        ),
                    }
                )
                outcome = validator.trusted_context(event, SHA, {"untrusted"})
            finally:
                os.environ.clear()
                os.environ.update(old_environment)
            self.assertEqual("allow", outcome["verdict"])
            self.assertEqual(SHA, outcome["context"]["source_revision"])
            self.assertEqual("refs/heads/feature/review-refresh", outcome["context"]["ref"])
            self.assertEqual("trusted", outcome["context"]["source_trust"])
            self.assertEqual("untrusted", outcome["context"]["execution_tier"])

    def test_context_rejects_ambiguous_pull_request_fork_provenance(self) -> None:
        ambiguous_repositories = (None, {}, {"fork": None}, {"fork": "false"})
        for repository in ambiguous_repositories:
            with self.subTest(repository=repository), tempfile.TemporaryDirectory() as temporary:
                event = Path(temporary) / "event.json"
                event.write_text(
                    json.dumps(
                        {
                            "pull_request": {
                                "head": {"sha": SHA, "repo": repository},
                                "base": {"sha": "b" * 40},
                            }
                        }
                    ),
                    encoding="utf-8",
                )
                old_environment = os.environ.copy()
                try:
                    os.environ.update(
                        {
                            "GITHUB_EVENT_NAME": "pull_request",
                            "GITHUB_SHA": SHA,
                            "GITHUB_REF_PROTECTED": "true",
                        }
                    )
                    outcome = validator.trusted_context(event, SHA, {"untrusted"})
                finally:
                    os.environ.clear()
                    os.environ.update(old_environment)
                self.assertEqual("deny", outcome["verdict"])
                self.assertEqual("ambiguous_fork_context", outcome["reason_code"])
                self.assertIs(outcome["context"]["fork"], True)
                self.assertEqual("untrusted", outcome["context"]["source_trust"])
                self.assertEqual("untrusted", outcome["context"]["execution_tier"])

    def test_protected_base_ref_does_not_elevate_pull_request_source(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            event = Path(temporary) / "event.json"
            event.write_text(
                json.dumps(
                    {
                        "pull_request": {
                            "head": {"sha": SHA, "repo": {"fork": False}},
                            "base": {"sha": "b" * 40},
                        }
                    }
                ),
                encoding="utf-8",
            )
            old_environment = os.environ.copy()
            try:
                os.environ.update(
                    {
                        "GITHUB_EVENT_NAME": "pull_request",
                        "GITHUB_SHA": SHA,
                        "GITHUB_REF_PROTECTED": "true",
                    }
                )
                outcome = validator.trusted_context(event, SHA, {"untrusted"})
            finally:
                os.environ.clear()
                os.environ.update(old_environment)
            self.assertEqual("trusted", outcome["context"]["source_trust"])
            self.assertEqual("untrusted", outcome["context"]["execution_tier"])

    def test_context_marks_unprotected_push_as_untrusted(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            event = Path(temporary) / "event.json"
            event.write_text(json.dumps({"after": SHA}), encoding="utf-8")
            old_environment = os.environ.copy()
            try:
                os.environ.update(
                    {
                        "GITHUB_EVENT_NAME": "push",
                        "GITHUB_SHA": SHA,
                        "GITHUB_REPOSITORY": "mindclade/.github",
                        "GITHUB_ACTOR": "mindclade-bot",
                        "GITHUB_REF": "refs/heads/feature",
                        "GITHUB_WORKFLOW_REF": "mindclade/.github/.github/workflows/pull-request.yml@"
                        + SHA,
                        "GITHUB_REF_PROTECTED": "false",
                    }
                )
                outcome = validator.trusted_context(event, SHA, {"untrusted"})
            finally:
                os.environ.clear()
                os.environ.update(old_environment)
            self.assertEqual("allow", outcome["verdict"])
            self.assertEqual("untrusted", outcome["context"]["execution_tier"])

    def test_pull_request_uses_head_ref_instead_of_github_merge_ref(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            event = Path(temporary) / "event.json"
            event.write_text(
                json.dumps(
                    {
                        "pull_request": {
                            "head": {"sha": SHA, "ref": "feature/x", "repo": {"fork": False}},
                            "base": {"sha": "b" * 40},
                        }
                    }
                ),
                encoding="utf-8",
            )
            old_environment = os.environ.copy()
            try:
                os.environ.update(
                    {
                        "GITHUB_EVENT_NAME": "pull_request",
                        "GITHUB_SHA": SHA,
                        "GITHUB_REPOSITORY": "mindclade/.github",
                        "GITHUB_ACTOR": "mindclade-bot",
                        "GITHUB_REF": "refs/pull/42/merge",
                        "GITHUB_WORKFLOW_REF": "mindclade/.github/.github/workflows/pull-request.yml@"
                        + SHA,
                    }
                )
                outcome = validator.trusted_context(event, SHA, {"untrusted"})
            finally:
                os.environ.clear()
                os.environ.update(old_environment)
            self.assertEqual("allow", outcome["verdict"])
            self.assertEqual("refs/heads/feature/x", outcome["context"]["ref"])

    def test_dependabot_actor_is_accepted_without_changing_pr_execution_tier(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            event = Path(temporary) / "event.json"
            event.write_text(
                json.dumps(
                    {
                        "pull_request": {
                            "head": {
                                "sha": SHA,
                                "ref": "dependabot/bazel/rules_python-2.3.2",
                                "repo": {"fork": False},
                            },
                            "base": {"sha": "b" * 40},
                        }
                    }
                ),
                encoding="utf-8",
            )
            old_environment = os.environ.copy()
            try:
                os.environ.update(
                    {
                        "GITHUB_EVENT_NAME": "pull_request",
                        "GITHUB_SHA": SHA,
                        "GITHUB_REPOSITORY": "mindclade/.github",
                        "GITHUB_ACTOR": "dependabot[bot]",
                        "GITHUB_REF": "refs/pull/43/merge",
                        "GITHUB_WORKFLOW_REF": "mindclade/.github/.github/workflows/pull-request.yml@"
                        + SHA,
                    }
                )
                outcome = validator.trusted_context(event, SHA, {"untrusted"})
            finally:
                os.environ.clear()
                os.environ.update(old_environment)
            self.assertEqual("allow", outcome["verdict"])
            self.assertEqual("trusted", outcome["context"]["source_trust"])
            self.assertEqual("untrusted", outcome["context"]["execution_tier"])

    def test_merge_group_payload_and_real_queue_ref_are_accepted(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            event = Path(temporary) / "event.json"
            event.write_text(
                json.dumps({"merge_group": {"head_sha": SHA, "base_sha": "b" * 40}}),
                encoding="utf-8",
            )
            old_environment = os.environ.copy()
            try:
                os.environ.update(
                    {
                        "GITHUB_EVENT_NAME": "merge_group",
                        "GITHUB_SHA": SHA,
                        "GITHUB_REPOSITORY": "mindclade/.github",
                        "GITHUB_ACTOR": "mindclade-bot",
                        "GITHUB_REF": "refs/heads/gh-readonly-queue/main/pr-42-" + SHA[:8],
                        "GITHUB_REF_PROTECTED": "true",
                        "GITHUB_WORKFLOW_REF": "mindclade/.github/.github/workflows/pull-request.yml@"
                        + SHA,
                    }
                )
                outcome = validator.trusted_context(event, SHA, {"untrusted"})
            finally:
                os.environ.clear()
                os.environ.update(old_environment)
            self.assertEqual("allow", outcome["verdict"])
            self.assertEqual(SHA, outcome["context"]["source_revision"])
            self.assertEqual("b" * 40, outcome["context"]["base_revision"])
            self.assertEqual("protected", outcome["context"]["source_trust"])
            self.assertEqual("untrusted", outcome["context"]["execution_tier"])

    def test_published_protected_non_prerelease_release_is_accepted(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            event = Path(temporary) / "event.json"
            event.write_text(
                json.dumps(
                    {
                        "action": "published",
                        "release": {"target_commitish": SHA, "draft": False, "prerelease": False},
                    }
                ),
                encoding="utf-8",
            )
            old_environment = os.environ.copy()
            try:
                os.environ.update(
                    {
                        "GITHUB_EVENT_NAME": "release",
                        "GITHUB_SHA": SHA,
                        "GITHUB_REPOSITORY": "mindclade/.github",
                        "GITHUB_ACTOR": "release-bot",
                        "GITHUB_REF": "refs/tags/v1.2.3",
                        "GITHUB_REF_PROTECTED": "true",
                        "GITHUB_WORKFLOW_REF": "mindclade/.github/.github/workflows/pull-request.yml@"
                        + SHA,
                    }
                )
                outcome = validator.trusted_context(event, SHA, {"release"})
            finally:
                os.environ.clear()
                os.environ.update(old_environment)
            self.assertEqual("allow", outcome["verdict"])
            self.assertEqual("release", outcome["context"]["execution_tier"])
            self.assertEqual("protected", outcome["context"]["source_trust"])

    def test_release_branch_target_falls_back_to_observed_tag_sha(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            event = Path(temporary) / "event.json"
            event.write_text(
                json.dumps(
                    {
                        "action": "published",
                        "release": {
                            "target_commitish": "main",
                            "draft": False,
                            "prerelease": False,
                        },
                    }
                ),
                encoding="utf-8",
            )
            old_environment = os.environ.copy()
            try:
                os.environ.update(
                    {
                        "GITHUB_EVENT_NAME": "release",
                        "GITHUB_SHA": SHA,
                        "GITHUB_REPOSITORY": "mindclade/.github",
                        "GITHUB_ACTOR": "release-bot",
                        "GITHUB_REF": "refs/tags/v1.2.3",
                        "GITHUB_REF_PROTECTED": "true",
                        "GITHUB_WORKFLOW_REF": "mindclade/.github/.github/workflows/pull-request.yml@"
                        + SHA,
                    }
                )
                outcome = validator.trusted_context(event, SHA, {"release"})
            finally:
                os.environ.clear()
                os.environ.update(old_environment)
            self.assertEqual("allow", outcome["verdict"])
            self.assertEqual(SHA, outcome["context"]["source_revision"])


if __name__ == "__main__":
    unittest.main()
