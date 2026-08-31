package mindclade.workflow.permissions_test

import rego.v1

trusted_prepare := {
	"runs-on": "ubuntu-24.04",
	"permissions": {"contents": "read"},
	"outputs": {"execution_tier": "${{ steps.context.outputs.execution_tier }}"},
	"steps": [
		{
			"id": "context",
			"uses": "$/.github/actions/validate-trusted-context",
			"with": {"expected-source-revision": "${{ inputs.source_revision }}"},
		},
		{"uses": "$/.github/actions/verify-pinned-actions"},
	],
}

test_minimal_read_permissions_pass if {
	data.mindclade.workflow.permissions.allow with input as {
		"execution_tier": "untrusted",
		"workflow": {"permissions": {"contents": "read", "pull-requests": "read"}},
	}
}

test_write_permission_is_denied_for_untrusted if {
	denials := data.mindclade.workflow.permissions.denials with input as {
		"execution_tier": "untrusted",
		"workflow": {"permissions": {"checks": "write"}},
	}
	some violation in denials
	violation.code == "UNTRUSTED_WRITE_FORBIDDEN"
}

test_oidc_is_denied_for_untrusted_execution if {
	denials := data.mindclade.workflow.permissions.denials with input as {
		"execution_tier": "untrusted",
		"workflow": {"permissions": {"id-token": "write"}},
	}
	some violation in denials
	violation.code == "UNTRUSTED_WRITE_FORBIDDEN"
}

test_oidc_is_allowed_for_exact_protected_job if {
	data.mindclade.workflow.permissions.allow with input as {
		"workflow": {
			"permissions": {},
			"jobs": {
				"prepare": trusted_prepare,
				"archive": {
					"if": "needs.prepare.outputs.execution_tier == 'trusted' || needs.prepare.outputs.execution_tier == 'release'",
					"permissions": {"id-token": "write"},
				},
			},
		},
	}
}

test_oidc_claim_without_structural_producer_is_denied if {
	denials := data.mindclade.workflow.permissions.denials with input as {
		"execution_tier": "release",
		"workflow": {
			"permissions": {},
			"jobs": {
				"archive": {
					"if": "needs.prepare.outputs.execution_tier == 'trusted' || needs.prepare.outputs.execution_tier == 'release'",
					"permissions": {"id-token": "write"},
				},
			},
		},
	}
	some violation in denials
	violation.code == "OIDC_GUARD_REQUIRED"
}

test_oidc_near_match_guard_is_denied if {
	denials := data.mindclade.workflow.permissions.denials with input as {
		"workflow": {
			"permissions": {},
			"jobs": {
				"prepare": trusted_prepare,
				"archive": {
					"if": "needs.prepare.outputs.execution_tier == 'trusted' || inputs.execution_tier == 'release'",
					"permissions": {"id-token": "write"},
				},
			},
		},
	}
	some violation in denials
	violation.code == "OIDC_GUARD_REQUIRED"
}

test_read_all_is_denied if {
	denials := data.mindclade.workflow.permissions.denials with input as {
		"execution_tier": "release",
		"workflow": {"permissions": "read-all"},
	}
	some violation in denials
	violation.code == "PERMISSIONS_NOT_EXPLICIT"
}
