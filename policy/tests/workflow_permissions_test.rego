package mindclade.workflow.permissions_test

import rego.v1

test_minimal_read_permissions_pass if {
  data.mindclade.workflow.permissions.allow with input as {
    "execution_tier": "untrusted",
    "workflow": {"permissions": {"contents": "read", "pull-requests": "read"}}
  }
}

test_write_permission_is_denied_for_untrusted if {
  denials := data.mindclade.workflow.permissions.denials with input as {
    "execution_tier": "untrusted",
    "workflow": {"permissions": {"checks": "write"}}
  }
  some violation in denials
  violation.code == "UNTRUSTED_WRITE_FORBIDDEN"
}

test_oidc_is_denied if {
  denials := data.mindclade.workflow.permissions.denials with input as {
    "execution_tier": "release",
    "workflow": {"permissions": {"id-token": "write"}}
  }
  some violation in denials
  violation.code == "OIDC_FORBIDDEN"
}

test_read_all_is_denied if {
  denials := data.mindclade.workflow.permissions.denials with input as {
    "execution_tier": "release",
    "workflow": {"permissions": "read-all"}
  }
  some violation in denials
  violation.code == "PERMISSIONS_NOT_EXPLICIT"
}
