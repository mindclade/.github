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

The repository remains pre-production until connected activation is explicitly approved and evidenced. Renovate checks GitHub Actions, Bazel and Nix dependencies daily from a single organization-wide job in `github-config`; `default.json` in this repository is the shared policy every repository extends. This source defines no dependency auto-merge automation; connected governance must separately enforce the required human reviews.

The repository-local `flake.nix` and `flake.lock` are the system-toolchain lock authority for supported `aarch64-darwin`, `aarch64-linux`, and `x86_64-linux` hosts. The canonical estate defaults live in `config/nix-bazel-policy.json`; `tools/generate_ci_policy.py` renders the imported Nix policy, common Bazel rc, toolchain-manifest defaults, and a digest-bound lock. They expose the reviewed `packages.toolchain`, identical default/CI tool closures, formatter, and toolchain/source checks while leaving Bazel and its module graph authoritative for build inputs. From a clean checkout, run:

```bash
nix build --no-accept-flake-config --no-update-lock-file .#toolchain
nix flake check --no-accept-flake-config --no-update-lock-file
nix develop --no-accept-flake-config --no-update-lock-file .#ci --command just ci
```

Regenerate the policy closure only from its source documents and bind consumer materialization to
an immutable reviewed authority commit:

```bash
python3 tools/generate_ci_policy.py generate \
  --root . \
  --authority-revision <40-character-reviewed-commit>
python3 tools/generate_ci_policy.py check --root .
```

## Estate required workflow

`.github/workflows/pull-request.yml` is the organization-required workflow source. Its workflow
name and final job deliberately remain `Pull request / required`. The generated profile catalog
maps each repository to a fixed Nix or isolated-Buildkite path; callers cannot supply commands,
runners, permissions, or workflow references. Every planned shard must report success and every
non-required shard must report `skipped`, so cancelled, missing, or ambiguously selected work fails
closed. Only superseded `pull_request` runs are cancelled; merge groups and other qualification
events are never cancelled.

Pull-request review policy accepts the ordinary two-account quorum or the evidence protocol
documented in `.github/actions/required-workflow-profile/README.md`. The founder protocol is a
durable PR-review exception, not a CI, merge-queue, history, environment, or deployment bypass.
Review submission/dismissal and label changes refresh the required workflow. After adding or
editing a founder marker comment, toggle the exact label so GitHub creates a new head-bound run.

Remote Bazel execution and remote caching are intentionally disabled. They may be enabled only for workers with the exact reviewed Nix store paths or an immutable, digest-pinned image built from this toolchain closure.

The root developer-quality interface is `just format`, `just format-check`,
`just lint`, and `just check`. Formatting is limited to handwritten source and
configuration; durable JSON fixtures remain unchanged.

The intended fork behavior is source-only until it is exercised from a dedicated consumer repository: pull requests are classified by the pinned metadata workflow, forks run only secretless metadata and documentation checks, and same-repository trusted pull requests plus merge-queue, protected `main`, and release events use the isolated Buildkite path. The pinned dispatcher derives the protected pipeline-definition SHA from GitHub-observed event context, launches Buildkite at that definition revision, and carries the candidate SHA separately as the code-under-test identity; verification and cancellation bind the Buildkite build commit to the definition SHA while evidence remains bound to the candidate SHA. A stable final gate rejects ambiguous trust, missing or caller-selected definition provenance, missing secrets, skipped trusted builds, and any unexpected path. The template must not be converted to `pull_request_target` or used to execute fork code with privileged credentials. Do not claim this behavior as connected until a cross-repository canary proves both paths against the approved immutable workflow revision.

## Evidence retention

CI reports are copied into a private, bounded staging directory before their digests are calculated, and only those staged bytes are uploaded. Each check binds the staged artifact-relative report path, exact byte count, and digest. Publication then downloads the exact non-overwriting artifact ID and rejects missing, extra, symlinked, oversized, size-mismatched, or digest-mismatched files before returning an evidence reference bound to both the canonical evidence digest and GitHub's upload digest. Buildkite verification revalidates the build UUID, build number, source commit, artifact route, and evidence bindings on every poll. Build polling, artifact listing, the artifact redirect, and signed-storage retrieval use bounded retries with jitter and `Retry-After`; every request timeout and retry sleep is capped by the overall verification deadline. The signed-storage request never receives the Buildkite authorization header. Dispatch and cancellation are never automatically retried; cancelling the long required-check verifier uses a separately declared cancellation token and revalidates its environment-bound build UUID and number before the one-shot cancel request.

The required-check workflow has an opt-in archive path for successful protected pushes and published releases. It exchanges GitHub OIDC only inside the strictly guarded archive job, after the handoff has matched the dedicated `projects/<number>/locations/global/workloadIdentityPools/github-ci-evidence/providers/writer` provider, `ci-evidence-writer@<project>.iam.gserviceaccount.com` identity, and `<project-id>-production-ci-evidence` bucket contract. It downloads the exact artifact ID produced by the required job and, before OIDC, reruns the complete file-set, report-size, report-digest, canonical-evidence-digest, and source-revision verification. It then creates generation-addressed GCS objects with a zero-generation precondition and records both evidence and GitHub artifact digests. Pull requests cannot enter this job.

Connected archive activation remains blocked until the reviewed `.github` workflow commit is bound into the bootstrap Workload Identity provider, the dedicated writer identity and disabled `NAM4` bucket source are applied, recovery is qualified, and the caller supplies `archive_evidence`, `gcp_workload_identity_provider`, `gcp_service_account`, and `gcs_evidence_bucket`. The bucket retention lock is a later irreversible, separately reviewed change.

Report security-sensitive concerns privately as described in [SECURITY.md](SECURITY.md). General contribution guidance is in [CONTRIBUTING.md](CONTRIBUTING.md).
