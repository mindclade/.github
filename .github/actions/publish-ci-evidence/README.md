# Publish CI evidence

This action turns a validated trusted context and bounded execution result into
canonical `ci_evidence.schema.json` data. Before hashing, it snapshots every
declared report into a private runner-temporary directory and uploads only that
bounded snapshot. The non-overwriting GitHub artifact is retained for 90 days.

The action does not sign releases, dispatch Buildkite, deploy, or contact an
arbitrary endpoint. Its artifact is CI run evidence, not a production signing
attestation. The caller must still fail its job when the supplied conclusion is
not `success` or when evidence publication fails.

Report paths are runner-local files only. The implementation rejects paths that
escape the workspace or temporary directory, symlinks, duplicate paths,
non-regular files, more than 32 reports, reports larger than 16 MiB, and an
aggregate larger than 64 MiB. The action exposes both the canonical evidence
digest and GitHub's uploaded-artifact digest for downstream binding. After
upload it downloads the exact returned artifact ID and revalidates the complete
file set, each declared report path, size, and digest, and the canonical evidence
digest. Missing, additional, symlinked, or mutated bytes fail publication.
