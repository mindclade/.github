# Governance

Owner: @mindclade/developer-platform
Last reviewed: 2026-08-30
Review cadence: 365 days

## Ownership

`@mindclade/developer-platform` is accountable for the organization GitHub source, including reusable workflow implementations, workflow entry points, issue forms, community health, and governance automation.

`@mindclade/security` reviews security impact. This source declares both developer-platform and security in CODEOWNERS, and requires both reviews for action pinning, permissions, trusted context, CI evidence, and externally connected behavior. Connected activation must independently verify that team access and rulesets enforce both approvals; a single CODEOWNERS rule does not do so by itself.

## Change control

This repository is pre-production. Source-ready status means the source change is prepared for review and validation only. Connected status requires documented approval and independent verification of the associated external organization configuration or integration; it must not be inferred from a merge.

## Connected activation

GitHub organization and repository settings are governed outside this source repository. This repository does not authorize direct live-setting changes, credential storage, or dependency auto-merge automation. Connected activation must verify those external controls separately.

Long-lived CI evidence uses separate source authorities: `bootstrap` owns the exact GitHub Workload Identity claims and dedicated writer/verifier identities; `infrastructure-live` owns the disabled retention bucket, CMEK, lifecycle, IAM grants, and recovery contract; this repository owns only protected evidence publication and archival behavior. The archive must remain disabled until those sources are applied and independently qualified. Locking bucket retention is irreversible and requires a later reviewed plan with recovery evidence; source readiness or a successful GitHub artifact upload is not sufficient authorization.

## Recovery

Workflow recovery selects a retained, reviewed revision whose commit or release signature is independently verified, then uses the `github-config` ruleset rollback path to restore the protected reference. This repository cannot authorize or perform that ruleset mutation itself. Connected qualification must prove both signature verification and the external rollback path before this source is treated as recoverable.
