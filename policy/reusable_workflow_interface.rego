package mindclade.workflow.reusable_interface

import rego.v1

common_outputs := {
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
}

allowed_input_types := {"string", "boolean", "number"}
allowed_buildkite_secrets := {
	"buildkite_cancel_token",
	"buildkite_dispatch_token",
	"buildkite_evidence_token",
	"buildkite_pipeline",
}

buildkite_workflow_paths := {
	".github/workflows/reusable-buildkite-dispatch.yml",
	".github/workflows/reusable-required-check.yml",
}

derived_trust_inputs := {
	"trusted_context",
	"trust_classification",
	"execution_tier",
	"source_trust",
	"fork",
	"ref_protected",
}

workflow_data := input.workflow if {
	is_object(input.workflow)
}

workflow_data := input if {
	not is_object(input.workflow)
}

workflow_call := workflow_data.workflow_call if {
	is_object(workflow_data.workflow_call)
}

is_buildkite_workflow if {
	workflow_path := object.get(input, "workflow_path", "")
	buildkite_workflow_paths[workflow_path]
}

denials contains violation if {
	not is_object(workflow_data.workflow_call)
	violation := {
		"code": "WORKFLOW_CALL_MISSING",
		"message": "reusable workflow must declare a workflow_call interface",
	}
}

denials contains violation if {
	not is_object(workflow_call.inputs)
	violation := {
		"code": "WORKFLOW_INPUTS_MISSING",
		"message": "workflow_call inputs must be an object",
	}
}

denials contains violation if {
	is_object(workflow_call.inputs)
	not is_object(workflow_call.inputs.source_revision)
	violation := {
		"code": "SOURCE_REVISION_INPUT_MISSING",
		"message": "workflow_call must require a typed source_revision input",
	}
}

denials contains violation if {
	definition := workflow_call.inputs.source_revision
	is_object(definition)
	definition.type != "string"
	violation := {
		"code": "SOURCE_REVISION_INPUT_UNTYPED",
		"message": "source_revision must be typed as string",
	}
}

denials contains violation if {
	definition := workflow_call.inputs.source_revision
	is_object(definition)
	definition.required != true
	violation := {
		"code": "SOURCE_REVISION_INPUT_OPTIONAL",
		"message": "source_revision must be required",
	}
}

denials contains violation if {
	some name, definition in workflow_call.inputs
	not is_object(definition)
	violation := {
		"code": "WORKFLOW_INPUT_DEFINITION_INVALID",
		"message": "workflow_call input definition must be an object",
		"input": name,
	}
}

denials contains violation if {
	some name, definition in workflow_call.inputs
	is_object(definition)
	not allowed_input_types[definition.type]
	violation := {
		"code": "WORKFLOW_INPUT_TYPE_UNSUPPORTED",
		"message": "workflow_call input must declare string, boolean, or number type",
		"input": name,
	}
}

denials contains violation if {
	some name
	derived_trust_inputs[lower(name)]
	workflow_call.inputs[name]
	violation := {
		"code": "DERIVED_TRUST_INPUT_FORBIDDEN",
		"message": "trusted context and execution tier are derived from the event and cannot be caller inputs",
		"input": name,
	}
}

denials contains violation if {
	some first, second
	first < second
	workflow_call.inputs[first]
	workflow_call.inputs[second]
	lower(first) == lower(second)
	violation := {
		"code": "WORKFLOW_INPUT_CASE_COLLISION",
		"message": "workflow_call input names must be unique after case folding",
		"input": first,
		"conflict": second,
	}
}

denials contains violation if {
	not is_object(workflow_call.outputs)
	violation := {
		"code": "WORKFLOW_OUTPUTS_MISSING",
		"message": "workflow_call outputs must be an object",
	}
}

denials contains violation if {
	output := common_outputs[_]
	is_object(workflow_call.outputs)
	not workflow_call.outputs[output]
	violation := {
		"code": "COMMON_OUTPUT_MISSING",
		"message": "workflow_call is missing a required common output",
		"output": output,
	}
}

denials contains violation if {
	output := common_outputs[_]
	definition := workflow_call.outputs[output]
	is_object(definition)
	not is_string(definition.value)
	violation := {
		"code": "COMMON_OUTPUT_UNBOUND",
		"message": "common workflow output must define a string value expression",
		"output": output,
	}
}

denials contains violation if {
	workflow_call.secrets == "inherit"
	violation := {
		"code": "SECRETS_INHERIT_FORBIDDEN",
		"message": "secrets: inherit is forbidden",
	}
}

denials contains violation if {
	input.secrets == "inherit"
	violation := {
		"code": "SECRETS_INHERIT_FORBIDDEN",
		"message": "secrets: inherit is forbidden",
	}
}

denials contains violation if {
	is_object(workflow_call.secrets)
	not is_buildkite_workflow
	some name
	workflow_call.secrets[name]
	violation := {
		"code": "SECRETS_FORBIDDEN",
		"message": "only the two Buildkite workflows may declare secrets",
		"secret": name,
	}
}

denials contains violation if {
	is_object(workflow_call.secrets)
	is_buildkite_workflow
	some name
	workflow_call.secrets[name]
	not allowed_buildkite_secrets[lower(name)]
	violation := {
		"code": "BUILDKITE_SECRET_UNAPPROVED",
		"message": "Buildkite workflow secret is not allowlisted",
		"secret": name,
	}
}

denials contains violation if {
	is_object(workflow_call.secrets)
	some name, definition in workflow_call.secrets
	not is_object(definition)
	violation := {
		"code": "WORKFLOW_SECRET_DEFINITION_INVALID",
		"message": "workflow_call secret definition must be an object",
		"secret": name,
	}
}

allow if {
	count(denials) == 0
}
