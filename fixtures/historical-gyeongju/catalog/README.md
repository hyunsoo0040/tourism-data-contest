# Historical Gyeongju regression fixtures

These files preserve the minimum legacy dataset required by existing regression
tests. They are retired application data, not an active catalog, a fallback
release, or inputs to the new nationwide collection and analysis.

`retirement-manifest.json` records each source path, fixture path, byte count, and
SHA-256. The copied payloads, their embedded hashes, and their historical source
paths are unchanged. One licensed photograph is retained by its original content
hash for the historical opt-in photo test; the former complete image/model cache
is not included.

The root Docker build excludes `fixtures/`. Deployment and current-release tests
must use the new nationwide artifact paths. Historical evaluation and promotion
reports here do not authorize a new release or measure national recommendation
accuracy.

Official dataset permission snapshots remain shared metadata under
`artifacts/public/catalog/official-permission-snapshots`; they are not legacy
destination scores and are intentionally not duplicated here.

`v2/` preserves nine retired split/Phase 4 authority metadata records. Their
embedded logical paths and toolchain hashes describe the historical operation.
They are not current evaluation authority. Reproducing their original chain also
requires the original restricted split artifacts, which are unavailable. Do not
rewrite these sealed records to make an old reproduction test pass.
