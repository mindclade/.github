# Publish CI evidence

This action turns a validated trusted context and bounded execution result into
canonical `ci_evidence.schema.json` data. It computes the content digest before
uploading the record and any declared reports as one non-overwriting GitHub
artifact retained for 90 days.

The action does not sign releases, dispatch Buildkite, deploy, or contact an
arbitrary endpoint. Its artifact is CI run evidence, not a production signing
attestation. The caller must still fail its job when the supplied conclusion is
not `success` or when evidence publication fails.

Report paths are runner-local files only. The implementation rejects paths that
escape the workspace or temporary directory and never follows a report path as
an executable.
