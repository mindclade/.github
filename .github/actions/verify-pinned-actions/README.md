# Verify pinned actions

This action validates the complete workflow source closure before a reusable
workflow checks out caller-controlled code or exposes a secret to an API client.

It permits only:

- `$/` actions from a reusable workflow's own repository and commit;
- `./.github/actions/` in `self-test.yml`, after its exact source checkout;
- approved GitHub actions and reusable workflows at full 40-character SHAs;
- container images at full `sha256:` digests.

It denies mutable tags and branches, `secrets: inherit`, broad permission
shortcuts, unapproved write/OIDC permissions, and unrecognized dependencies.
The approved external revisions live in `policy/action_pinning.rego`; changing a
workflow pin without updating that reviewed policy fails validation.

Governed workflows, composite actions, workflow templates, and component
metadata use a deterministic YAML subset implemented with the Python standard
library. Plain block mappings and sequences, quoted scalar values, block
scalars, flow sequences, and empty `{}` mappings are supported. Quoted or
explicit keys, non-empty flow mappings, anchors, aliases, tags, merge keys,
duplicate keys, tabs, multiple documents, excessive nesting, and documents
larger than 1 MiB fail closed. Workflow scripts must receive caller inputs
through `env`; `${{ inputs.* }}` interpolation inside `run` is forbidden.
Jobs requesting write permissions must derive their execution tier from the
immutable `validate-trusted-context` action through the `prepare` job contract.
That contract binds `expected-source-revision` to `inputs.source_revision` and
runs both trusted-context and implementation-closure validation without a
conditional, alternate root, inherited environment override, or job/step
failure suppression. Those actions are the first two steps on the approved
GitHub-hosted runner, before any workflow step can modify the process path or
shell startup environment.

The optional `root` input may point at an already checked-out caller repository.
It is treated as untrusted data and is never executed by this action.
