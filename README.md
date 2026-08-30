# Mindclade organization GitHub source

This repository contains the pre-production source for Mindclade organization reusable workflows, policy workflow entry points, issue forms, community health, and governance automation. Its target tree is defined by `BLUEPRINT.md`; that manifest is a target-state specification, not evidence that every path is implemented or connected.

## Ownership

`@mindclade/developer-platform` owns this repository. `@mindclade/security` reviews security impact. See [GOVERNANCE.md](GOVERNANCE.md) for the boundary with external organization settings.

## Activation boundary

- **source-ready:** source, metadata, validation, and review evidence are complete. No live organization change, credential use, or production claim follows from this state.
- **connected:** a separately approved external organization connection has been independently verified under the applicable governance and security controls.

The repository remains pre-production until connected activation is explicitly approved and evidenced. Dependabot checks GitHub Actions and Bazel dependencies weekly. This source defines no dependency auto-merge automation; connected governance must separately enforce the required human reviews.

Report security-sensitive concerns privately as described in [SECURITY.md](SECURITY.md). General contribution guidance is in [CONTRIBUTING.md](CONTRIBUTING.md).
