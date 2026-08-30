package mindclade.workflow.permissions

import rego.v1

allowed_permissions := {
  "actions": "read",
  "checks": "write",
  "contents": "read",
  "pull-requests": "read",
  "security-events": "write"
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

denials contains violation if {
  not is_object(workflow_data.permissions)
  violation := {
    "code": "PERMISSIONS_NOT_EXPLICIT",
    "message": "workflow permissions must be an explicit object; read-all and write-all are forbidden"
  }
}

denials contains violation if {
  is_string(workflow_data.permissions)
  workflow_data.permissions == "read-all"
  violation := {
    "code": "PERMISSIONS_READ_ALL_FORBIDDEN",
    "message": "permissions: read-all is forbidden"
  }
}

denials contains violation if {
  is_string(workflow_data.permissions)
  workflow_data.permissions == "write-all"
  violation := {
    "code": "PERMISSIONS_WRITE_ALL_FORBIDDEN",
    "message": "permissions: write-all is forbidden"
  }
}

denials contains violation if {
  permissions["id-token"]
  violation := {
    "code": "OIDC_FORBIDDEN",
    "message": "id-token permission is forbidden for reusable organization workflows",
    "permission": "id-token"
  }
}

denials contains violation if {
  some permission, level in permissions
  not allowed_permissions[permission]
  violation := {
    "code": "PERMISSION_SCOPE_UNAPPROVED",
    "message": "permission scope is not allowlisted",
    "permission": permission,
    "requested": level
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
    "allowed": expected
  }
}

denials contains violation if {
  some permission, level in permissions
  level == "write"
  input.execution_tier == "untrusted"
  violation := {
    "code": "UNTRUSTED_WRITE_FORBIDDEN",
    "message": "untrusted pull-request execution cannot receive write permissions",
    "permission": permission
  }
}

allow if {
  count(denials) == 0
}
