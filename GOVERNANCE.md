# Governance

`@mindclade/developer-platform` is accountable for the organization GitHub source, including reusable workflow implementations, workflow entry points, issue forms, community health, and governance automation.

`@mindclade/security` reviews security impact. This source declares both developer-platform and security in CODEOWNERS, and requires both reviews for action pinning, permissions, trusted context, CI evidence, and externally connected behavior. Connected activation must independently verify that team access and rulesets enforce both approvals; a single CODEOWNERS rule does not do so by itself.

This repository is pre-production. Source-ready status means the source change is prepared for review and validation only. Connected status requires documented approval and independent verification of the associated external organization configuration or integration; it must not be inferred from a merge.

GitHub organization and repository settings are governed outside this source repository. This repository does not authorize direct live-setting changes, credential storage, or dependency auto-merge automation. Connected activation must verify those external controls separately.
