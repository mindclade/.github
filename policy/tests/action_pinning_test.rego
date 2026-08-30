package mindclade.workflow.action_pinning_test

import rego.v1

test_exact_allowlist_passes if {
  data.mindclade.workflow.action_pinning.allow with input as {
    "repository": "Mindclade/.github",
    "source_revision": "1111111111111111111111111111111111111111",
    "actions": [
      {"path": "checkout", "uses": "actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1"},
      {"path": "codeql", "uses": "github/codeql-action/init@cdf488f595d80d6e07e03d4674febd5ab45fa938"},
      {"path": "dependency", "uses": "actions/dependency-review-action@a1d282b36b6f3519aa1f3fc636f609c47dddb294"},
      {"path": "upload", "uses": "actions/upload-artifact@043fb46d1a93c77aae656e7c1c64a875d1fc6a0a"},
      {"path": "scorecard", "uses": "docker://ghcr.io/ossf/scorecard-action@sha256:ae5104dd3cc28466ebeb11144354be4cac4b7ff829654f9fab89021d71c46670"}
    ]
  }
}

test_implementation_and_same_commit_actions_pass if {
  data.mindclade.workflow.action_pinning.allow with input as {
    "repository": "Mindclade/.github",
    "source_revision": "1111111111111111111111111111111111111111",
    "actions": [
      {"uses": "$/.github/actions/validate-trusted-context"},
      {"uses": "Mindclade/.github/.github/actions/verify-pinned-actions@1111111111111111111111111111111111111111"}
    ]
  }
}

test_repository_self_test_local_action_passes if {
  data.mindclade.workflow.action_pinning.allow with input as {
    "workflow_path": ".github/workflows/self-test.yml",
    "actions": [{"uses": "./.github/actions/validate-trusted-context"}],
  }
}

test_repository_self_test_implementation_action_is_denied if {
  denials := data.mindclade.workflow.action_pinning.denials with input as {
    "workflow_path": ".github/workflows/self-test.yml",
    "actions": [{"uses": "$/.github/actions/validate-trusted-context"}],
  }
  some violation in denials
  violation.code == "ACTION_REFERENCE_UNAPPROVED"
}

test_caller_checkout_local_action_is_denied if {
  denials := data.mindclade.workflow.action_pinning.denials with input as {
    "actions": [{"uses": "./.github/actions/validate-trusted-context"}]
  }
  some violation in denials
  violation.code == "ACTION_REFERENCE_UNAPPROVED"
}

test_implementation_action_outside_actions_is_denied if {
  denials := data.mindclade.workflow.action_pinning.denials with input as {
    "actions": [{"uses": "$/.github/workflows/self-test.yml"}]
  }
  some violation in denials
  violation.code == "ACTION_REFERENCE_UNAPPROVED"
}

test_implementation_action_traversal_is_denied if {
  denials := data.mindclade.workflow.action_pinning.denials with input as {
    "actions": [{"uses": "$/.github/actions/validate-trusted-context/../publish-ci-evidence"}]
  }
  some violation in denials
  violation.code == "ACTION_REFERENCE_UNAPPROVED"
}

test_implementation_action_interpolation_is_denied if {
  denials := data.mindclade.workflow.action_pinning.denials with input as {
    "actions": [{"uses": "$/.github/actions/${{ inputs.action }}"}]
  }
  some violation in denials
  violation.code == "ACTION_REFERENCE_UNAPPROVED"
}

test_tag_is_denied if {
  denials := data.mindclade.workflow.action_pinning.denials with input as {
    "repository": "Mindclade/.github",
    "source_revision": "1111111111111111111111111111111111111111",
    "actions": [{"uses": "actions/checkout@v7"}]
  }
  some violation in denials
  violation.code == "ACTION_REFERENCE_UNAPPROVED"
}

test_prefix_only_digest_is_denied if {
  denials := data.mindclade.workflow.action_pinning.denials with input as {
    "repository": "Mindclade/.github",
    "source_revision": "1111111111111111111111111111111111111111",
    "actions": [{"uses": "github/codeql-action/init@cdf488f"}]
  }
  some violation in denials
  violation.code == "ACTION_REFERENCE_UNAPPROVED"
}
