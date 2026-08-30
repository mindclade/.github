# Mindclade organization GitHub source

Owner: @mindclade/developer-platform
Last reviewed: 2026-08-30
Review cadence: 365 days

This repository contains the pre-production source for Mindclade organization reusable workflows, policy workflow entry points, issue forms, community health, and governance automation. Its target tree is governed by the architecture source's `docs/architecture/repository-path-manifest.yaml`; MC-ARCH-001 Appendix A3.9 and Appendix A6 are deterministic review views, not repository-local authorities or evidence that every path is connected.

## Ownership

`@mindclade/developer-platform` owns this repository. `@mindclade/security` reviews security impact. See [GOVERNANCE.md](GOVERNANCE.md) for the boundary with external organization settings.

## Activation boundary

- **source-ready:** source, metadata, validation, and review evidence are complete. No live organization change, credential use, or production claim follows from this state.
- **connected:** a separately approved external organization connection has been independently verified under the applicable governance and security controls.

The repository remains pre-production until connected activation is explicitly approved and evidenced. Dependabot checks GitHub Actions and Bazel dependencies weekly. This source defines no dependency auto-merge automation; connected governance must separately enforce the required human reviews.

The intended fork behavior is source-only until it is exercised from a dedicated consumer repository: pull requests are classified by the pinned metadata workflow, forks run only secretless metadata and documentation checks, and same-repository trusted pull requests plus merge-queue, protected `main`, and release events use the isolated Buildkite path. A stable final gate rejects ambiguous trust, missing secrets, skipped trusted builds, and any unexpected path. The template must not be converted to `pull_request_target` or used to execute fork code with privileged credentials. Do not claim this behavior as connected until a cross-repository canary proves both paths against the approved immutable workflow revision.

## Evidence retention

CI reports are copied into a private, bounded staging directory before their digests are calculated, and only those staged bytes are uploaded. Each check binds the staged artifact-relative report path, exact byte count, and digest. Publication then downloads the exact non-overwriting artifact ID and rejects missing, extra, symlinked, oversized, size-mismatched, or digest-mismatched files before returning an evidence reference bound to both the canonical evidence digest and GitHub's upload digest. Buildkite verification revalidates the build UUID, build number, source commit, artifact route, and evidence bindings on every poll. Build polling, artifact listing, the artifact redirect, and signed-storage retrieval use bounded retries with jitter and `Retry-After`; every request timeout and retry sleep is capped by the overall verification deadline. The signed-storage request never receives the Buildkite authorization header. Dispatch and cancellation are never automatically retried; cancelling the long required-check verifier uses a separately declared cancellation token and revalidates its environment-bound build UUID and number before the one-shot cancel request.

The required-check workflow has an opt-in archive path for successful protected pushes and published releases. It exchanges GitHub OIDC only inside the strictly guarded archive job, after the handoff has matched the dedicated `projects/<number>/locations/global/workloadIdentityPools/github-ci-evidence/providers/writer` provider, `ci-evidence-writer@<project>.iam.gserviceaccount.com` identity, and `<project-id>-production-ci-evidence` bucket contract. It downloads the exact artifact ID produced by the required job and, before OIDC, reruns the complete file-set, report-size, report-digest, canonical-evidence-digest, and source-revision verification. It then creates generation-addressed GCS objects with a zero-generation precondition and records both evidence and GitHub artifact digests. Pull requests cannot enter this job.

Connected archive activation remains blocked until the reviewed `.github` workflow commit is bound into the bootstrap Workload Identity provider, the dedicated writer identity and disabled `NAM4` bucket source are applied, recovery is qualified, and the caller supplies `archive_evidence`, `gcp_workload_identity_provider`, `gcp_service_account`, and `gcs_evidence_bucket`. The bucket retention lock is a later irreversible, separately reviewed change.

Report security-sensitive concerns privately as described in [SECURITY.md](SECURITY.md). General contribution guidance is in [CONTRIBUTING.md](CONTRIBUTING.md).
