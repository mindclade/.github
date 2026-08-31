package mindclade.workflow.action_pinning

import rego.v1

allowed_actions := {
	"actions/checkout": "3d3c42e5aac5ba805825da76410c181273ba90b1",
	"github/codeql-action/init": "cdf488f595d80d6e07e03d4674febd5ab45fa938",
	"github/codeql-action/analyze": "cdf488f595d80d6e07e03d4674febd5ab45fa938",
	"github/codeql-action/upload-sarif": "cdf488f595d80d6e07e03d4674febd5ab45fa938",
	"actions/dependency-review-action": "a1d282b36b6f3519aa1f3fc636f609c47dddb294",
	"actions/download-artifact": "3e5f45b2cfb9172054b4087a40e8e0b5a5461e7c",
	"actions/upload-artifact": "043fb46d1a93c77aae656e7c1c64a875d1fc6a0a",
	"google-github-actions/auth": "7c6bc770dae815cd3e89ee6cdf493a5fab2cc093", # gitleaks:allow -- immutable public action commit
	"google-github-actions/setup-gcloud": "aa5489c8933f4cc7a4f7d45035b3b1440c9c10db",
	"DeterminateSystems/nix-installer-action": "ef8a148080ab6020fd15196c2084a2eea5ff2d25",
	"ghcr.io/ossf/scorecard-action": "sha256:ae5104dd3cc28466ebeb11144354be4cac4b7ff829654f9fab89021d71c46670",
	"docker://ghcr.io/ossf/scorecard-action": "sha256:ae5104dd3cc28466ebeb11144354be4cac4b7ff829654f9fab89021d71c46670",
}

self_test_workflow_path := ".github/workflows/self-test.yml"

action_entries := input.actions if {
	is_array(input.actions)
}

action_entries := input.workflow.actions if {
	not is_array(input.actions)
	is_object(input.workflow)
	is_array(input.workflow.actions)
}

action_reference(entry) := entry.uses if {
	is_object(entry)
	is_string(entry.uses)
}

action_reference(entry) := entry if {
	is_string(entry)
}

action_path(entry, _) := entry.path if {
	is_object(entry)
	is_string(entry.path)
}

action_path(_, index) := sprintf("actions[%d]", [index])

# `$/` is the approved GitHub Actions same-implementation-commit form. It is
# deliberately narrower than an ordinary local path: it may address only a
# composite action below .github/actions and may not contain traversal or an
# expression interpolation.
is_implementation_action(reference) if {
	object.get(input, "workflow_path", "") != self_test_workflow_path
	startswith(reference, "$/.github/actions/")
	not contains(reference, "..")
	not contains(reference, "${{")
	action_path := trim_prefix(reference, "$/.github/actions/")
	regex.match("^[A-Za-z0-9][A-Za-z0-9._-]*(/[A-Za-z0-9][A-Za-z0-9._-]*)*$", action_path)
}

# The repository self-test executes from its own exact checkout, so GitHub's
# native local-action form is both required and safe there. Reusable workflows
# retain the implementation-action form because their caller checkout is a
# different trust boundary.
is_self_test_local_action(reference) if {
	input.workflow_path == self_test_workflow_path
	startswith(reference, "./.github/actions/")
	not contains(reference, "..")
	not contains(reference, "${{")
	action_path := trim_prefix(reference, "./.github/actions/")
	regex.match("^[A-Za-z0-9][A-Za-z0-9._-]*(/[A-Za-z0-9][A-Za-z0-9._-]*)*$", action_path)
}

is_same_commit_action(reference) if {
	parts := split(reference, "@")
	count(parts) == 2
	source := parts[0]
	revision := parts[1]
	source == input.repository
	revision == input.source_revision
}

is_same_commit_action(reference) if {
	parts := split(reference, "@")
	count(parts) == 2
	source := parts[0]
	revision := parts[1]
	startswith(source, sprintf("%s/", [input.repository]))
	revision == input.source_revision
}

is_exactly_allowed_action(reference) if {
	parts := split(reference, "@")
	count(parts) == 2
	allowed_actions[parts[0]] == parts[1]
}

valid_action_reference(reference) if {
	is_implementation_action(reference)
}

valid_action_reference(reference) if {
	is_self_test_local_action(reference)
}

valid_action_reference(reference) if {
	is_same_commit_action(reference)
}

valid_action_reference(reference) if {
	is_exactly_allowed_action(reference)
}

denials contains violation if {
	some index
	entry := action_entries[index]
	not action_reference(entry)
	violation := {
		"code": "ACTION_REFERENCE_MISSING",
		"message": "action entry must contain a uses reference",
		"path": action_path(entry, index),
	}
}

denials contains violation if {
	some index
	entry := action_entries[index]
	reference := action_reference(entry)
	not valid_action_reference(reference)
	violation := {
		"code": "ACTION_REFERENCE_UNAPPROVED",
		"message": "action reference is not an implementation, same-commit, or exact allowlisted revision",
		"path": action_path(entry, index),
		"reference": reference,
	}
}

allow if {
	count(denials) == 0
}
