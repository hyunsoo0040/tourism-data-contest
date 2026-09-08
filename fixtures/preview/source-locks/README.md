# PREVIEW source locks

`preview-v1-source-lock.json` is the Git-tracked trust anchor for the exact
four-file PREVIEW v1 source review. It intentionally lives outside
`fixtures/preview/v1`, so a canonical freeze can replace or publish that root
without replacing the source identity used to validate it.

Rights classification and freeze validation compare reconstructed source bytes
to this independently reviewed lock. Re-signing the bundle, candidate,
markdown, current manifest, and approval together therefore remains invalid
while the lock is unchanged.

The protected boundary is artifact-only tampering. A change that modifies both
application code and this lock is outside that boundary and must be accepted as
an ordinary, visible Git code-review change.
