# Validate trusted context

This composite action derives trust from the GitHub event and runner-provided
environment. Callers cannot assert that their own source is trusted.

It rejects malformed events, source-SHA mismatches, `pull_request_target`, false
protected-ref claims, unsupported execution tiers, and ambiguous fork context.
Both fork and same-repository pull requests execute as untrusted code; the
`source_trust` output records their different origins without granting secrets.
For pull requests, `pull_request.head.repo` must be an object and its `fork`
field must be a JSON boolean. Missing, null, or incorrectly typed provenance is
denied with `ambiguous_fork_context`; safely derivable outputs report
`fork: true`, untrusted source trust, and the untrusted execution tier.

## Interface

| Input | Required | Meaning |
|---|---:|---|
| `expected-source-revision` | yes | Exact lowercase 40-character commit SHA expected by the caller. |
| `allowed-execution-tiers` | no | Comma-separated subset of `untrusted,trusted,release`. |

Outputs include the canonical context JSON and digest, correlation ID, observed
source/base revisions, source trust, execution tier, verdict, and reason code.
The action exits non-zero on a denied context after writing any safely derivable
outputs.

Use `$/` from reusable workflows so GitHub resolves the action from the same
repository and exact commit as the running workflow.
This GitHub.com syntax requires Actions runner 2.336.0 or newer and is not
available on GitHub Enterprise Server.
