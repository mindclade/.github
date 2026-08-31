package mindclade.workflow.permissions

import rego.v1

allowed_permissions := {
	"actions": "read",
	"checks": "write",
	"contents": "read",
	"id-token": "write",
	"pull-requests": "read",
	"security-events": "write",
}

protected_tier_guards := {
	"needs.prepare.outputs.execution_tier == 'trusted' || needs.prepare.outputs.execution_tier == 'release'",
	"needs.prepare.outputs.execution_tier == 'release' || needs.prepare.outputs.execution_tier == 'trusted'",
	"needs.prepare.result == 'success' && (needs.prepare.outputs.execution_tier == 'trusted' || needs.prepare.outputs.execution_tier == 'release')",
	"needs.prepare.result == 'success' && (needs.prepare.outputs.execution_tier == 'release' || needs.prepare.outputs.execution_tier == 'trusted')",
	"inputs.archive_evidence && needs.required.result == 'success' && (needs.required.outputs.execution_tier == 'trusted' || needs.required.outputs.execution_tier == 'release')",
}

workflow_data := input.workflow if {
	is_object(input.workflow)
}

workflow_data := input if {
	not is_object(input.workflow)
}

permissions := workflow_data.permissions if {
	is_object(workflow_data.permissions)
}

trusted_context_producer if {
	not "env" in object.keys(workflow_data)
	trusted_context_job(workflow_data.jobs.prepare)
}

trusted_context_producer if {
	not "env" in object.keys(workflow_data)
	trusted_context_job(workflow_data.jobs.required)
}

trusted_context_job(prepare) if {
	is_object(prepare)
	prepare["runs-on"] == "ubuntu-24.04"
	not "env" in object.keys(prepare)
	not "container" in object.keys(prepare)
	object.get(prepare, "continue-on-error", false) == false
	prepare.outputs.execution_tier == "${{ steps.context.outputs.execution_tier }}"

	steps := prepare.steps
	is_array(steps)
	count(steps) >= 2
	context_steps := [step | some step in steps; is_object(step); step.id == "context"]
	count(context_steps) == 1
	pin_steps := [step | some step in steps; is_object(step); step.uses == "$/.github/actions/verify-pinned-actions"]
	count(pin_steps) == 1

	context := steps[0]
	is_object(context)
	context.id == "context"
	context.uses == "$/.github/actions/validate-trusted-context"
	context["with"]["expected-source-revision"] == "${{ inputs.source_revision }}"
	object.get(context, "continue-on-error", false) == false
	not "if" in object.keys(context)
	not "env" in object.keys(context)

	pins := steps[1]
	is_object(pins)
	pins.uses == "$/.github/actions/verify-pinned-actions"
	object.get(pins, "continue-on-error", false) == false
	not "if" in object.keys(pins)
	not "with" in object.keys(pins)
	not "env" in object.keys(pins)
}

protected_oidc_job(job) if {
	trusted_context_producer
	is_object(job)
	is_string(job.if)
	protected_tier_guards[job.if]
}

denials contains violation if {
	not is_object(workflow_data.permissions)
	violation := {
		"code": "PERMISSIONS_NOT_EXPLICIT",
		"message": "workflow permissions must be an explicit object; read-all and write-all are forbidden",
	}
}

denials contains violation if {
	is_string(workflow_data.permissions)
	workflow_data.permissions == "read-all"
	violation := {
		"code": "PERMISSIONS_READ_ALL_FORBIDDEN",
		"message": "permissions: read-all is forbidden",
	}
}

denials contains violation if {
	is_string(workflow_data.permissions)
	workflow_data.permissions == "write-all"
	violation := {
		"code": "PERMISSIONS_WRITE_ALL_FORBIDDEN",
		"message": "permissions: write-all is forbidden",
	}
}

denials contains violation if {
	some permission, level in permissions
	not allowed_permissions[permission]
	violation := {
		"code": "PERMISSION_SCOPE_UNAPPROVED",
		"message": "permission scope is not allowlisted",
		"permission": permission,
		"requested": level,
	}
}

denials contains violation if {
	permissions["id-token"] == "write"
	violation := {
		"code": "OIDC_GUARD_REQUIRED",
		"message": "id-token: write is only allowed on a job guarded by the exact trusted/release prepare contract",
		"permission": "id-token",
	}
}

denials contains violation if {
	some job_name, job in workflow_data.jobs
	is_object(job.permissions)
	job.permissions["id-token"] == "write"
	not protected_oidc_job(job)
	violation := {
		"code": "OIDC_GUARD_REQUIRED",
		"message": "id-token: write is only allowed on a job guarded by the exact trusted/release prepare contract",
		"job": job_name,
		"permission": "id-token",
	}
}

denials contains violation if {
	some permission, level in permissions
	expected := allowed_permissions[permission]
	level != expected
	violation := {
		"code": "PERMISSION_LEVEL_UNAPPROVED",
		"message": "permission level exceeds or differs from the allowlisted level",
		"permission": permission,
		"requested": level,
		"allowed": expected,
	}
}

denials contains violation if {
	some permission, level in permissions
	level == "write"
	input.execution_tier == "untrusted"
	violation := {
		"code": "UNTRUSTED_WRITE_FORBIDDEN",
		"message": "untrusted pull-request execution cannot receive write permissions",
		"permission": permission,
	}
}

allow if {
	count(denials) == 0
}
