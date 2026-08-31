package mindclade.workflow.reusable_interface_test

import rego.v1

common_outputs := {
	"correlation_id": {"value": "${{ jobs.validate.outputs.correlation_id }}"},
	"source_revision": {"value": "${{ jobs.validate.outputs.source_revision }}"},
	"caller_repository": {"value": "${{ jobs.validate.outputs.caller_repository }}"},
	"trust_classification": {"value": "${{ jobs.validate.outputs.trust_classification }}"},
	"execution_tier": {"value": "${{ jobs.validate.outputs.execution_tier }}"},
	"plan_id": {"value": "${{ jobs.validate.outputs.plan_id }}"},
	"build_id": {"value": "${{ jobs.validate.outputs.build_id }}"},
	"conclusion": {"value": "${{ jobs.validate.outputs.conclusion }}"},
	"reason_code": {"value": "${{ jobs.validate.outputs.reason_code }}"},
	"evidence_digest": {"value": "${{ jobs.validate.outputs.evidence_digest }}"},
	"evidence_ref": {"value": "${{ jobs.validate.outputs.evidence_ref }}"},
}

test_typed_non_buildkite_interface_passes if {
	data.mindclade.workflow.reusable_interface.allow with input as {
		"workflow": {
			"name": "reusable-metadata-validation",
			"workflow_call": {
				"inputs": {
					"source_revision": {"required": true, "type": "string"},
					"metadata_profile": {"required": false, "type": "string"},
				},
				"outputs": common_outputs,
				"secrets": {},
			},
		},
	}
}

test_derived_trust_input_is_denied if {
	denials := data.mindclade.workflow.reusable_interface.denials with input as {
		"workflow": {
			"name": "reusable-metadata-validation",
			"workflow_call": {
				"inputs": {
					"source_revision": {"required": true, "type": "string"},
					"execution_tier": {"required": true, "type": "string"},
				},
				"outputs": common_outputs,
				"secrets": {},
			},
		},
	}
	some violation in denials
	violation.code == "DERIVED_TRUST_INPUT_FORBIDDEN"
}

test_casefolded_source_trust_input_is_denied if {
	denials := data.mindclade.workflow.reusable_interface.denials with input as {
		"workflow": {
			"name": "reusable-metadata-validation",
			"workflow_call": {
				"inputs": {
					"source_revision": {"required": true, "type": "string"},
					"Source_Trust": {"required": false, "type": "string"},
				},
				"outputs": common_outputs,
				"secrets": {},
			},
		},
	}
	some violation in denials
	violation.code == "DERIVED_TRUST_INPUT_FORBIDDEN"
}

test_secrets_inherit_is_denied if {
	denials := data.mindclade.workflow.reusable_interface.denials with input as {
		"workflow": {
			"name": "reusable-buildkite-dispatch",
			"workflow_call": {
				"inputs": {"source_revision": {"required": true, "type": "string"}},
				"outputs": common_outputs,
				"secrets": "inherit",
			},
		},
	}
	some violation in denials
	violation.code == "SECRETS_INHERIT_FORBIDDEN"
}

test_unapproved_non_buildkite_secret_is_denied if {
	denials := data.mindclade.workflow.reusable_interface.denials with input as {
		"workflow": {
			"name": "reusable-documentation-check",
			"workflow_call": {
				"inputs": {"source_revision": {"required": true, "type": "string"}},
				"outputs": common_outputs,
				"secrets": {"buildkite_dispatch_token": {"required": true}},
			},
		},
	}
	some violation in denials
	violation.code == "SECRETS_FORBIDDEN"
}

test_approved_buildkite_secret_requires_exact_workflow_path if {
	data.mindclade.workflow.reusable_interface.allow with input as {
		"workflow_path": ".github/workflows/reusable-required-check.yml",
		"workflow": {
			"name": "an-arbitrary-display-name",
			"workflow_call": {
				"inputs": {"source_revision": {"required": true, "type": "string"}},
				"outputs": common_outputs,
				"secrets": {"buildkite_evidence_token": {"required": true}},
			},
		},
	}
}

test_bound_build_cancellation_secret_is_approved_for_required_check if {
	data.mindclade.workflow.reusable_interface.allow with input as {
		"workflow_path": ".github/workflows/reusable-required-check.yml",
		"workflow": {
			"name": "reusable-required-check",
			"workflow_call": {
				"inputs": {"source_revision": {"required": true, "type": "string"}},
				"outputs": common_outputs,
				"secrets": {"buildkite_cancel_token": {"required": false}},
			},
		},
	}
}

test_buildkite_display_name_cannot_spoof_workflow_path if {
	denials := data.mindclade.workflow.reusable_interface.denials with input as {
		"workflow_path": ".github/workflows/reusable-documentation-check.yml",
		"workflow": {
			"name": "reusable-required-check",
			"workflow_call": {
				"inputs": {"source_revision": {"required": true, "type": "string"}},
				"outputs": common_outputs,
				"secrets": {"buildkite_evidence_token": {"required": true}},
			},
		},
	}
	some violation in denials
	violation.code == "SECRETS_FORBIDDEN"
}
