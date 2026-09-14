# Recommendation quality

> Historical v4 implementation notes. Current production defaults, image mood-only
> behavior and verification evidence are documented in
> [출처 기반 추천 운영](source-grounded-recommendations.md). The original evaluation
> material was confirmed unavailable on 2026-09-09; see the
> [new review procedure](evaluation-restart.md).

The production recommendation service creates `recommendation-kernel-v4` runs using
`recommendation-projection-v3`. Existing v3 kernel receipts and photo v1 receipts remain
readable; old photo retries return their sealed result without reinterpreting synthetic
or hash-derived evidence. A new request uses the corrected policy.

## Trip conditions and purposes

The following describes the retired mixed-purpose interface. Since 2026-09-10,
new national collection and the profile CTA use sightseeing only; food and lodging
are excluded. See [the current national scope](nationwide-data.md).

The profile screen offers 볼거리 (`SIGHTSEEING`, the new default), 먹거리 (`FOOD`),
숙소 (`LODGING`), and 전체 (`MIXED`). Categories come from the server's PUBLIC catalog;
eligible IDs are intersected with the current release. The purpose and eligible set
are bound into the stored preference and run hash. Changing purpose creates a new
request ID. A retry of the same purpose retains its pending ID.

`UNDECIDED` visit time and `NO_PREFERENCE` indoor/outdoor are absent targets, not
intensity values. Desired M3 density is `100 - crowd avoidance`; this agrees with
place M3 (`0=quiet`, `100=crowded`). Child and senior access are distinct source facts.
Car access uses explicit parking evidence, transit uses explicit transit evidence.
No suitability is inferred from popularity, historical value, or another score.

Travel conditions with missing user preference or missing place facts have null
value/difference/fit and zero weight. The remaining weights `(400,350,350,350,300,250)`
are scaled to 2,000 basis points using stable largest remainders. All missing means
experience-only relevance. Otherwise relevance remains 80% experience fit and 20%
observed travel-condition fit. Reranking retains 85% relevance and 15% diversity,
duplicate exclusions and cannot-coappear constraints. Confidence adds no score.

The alternative importance-weighted fulfillment formula is evaluated separately;
authored synthetic cases do not justify promoting it as superior for real travelers.

## Facts and place analysis

`source-bound-place-facts.v1` retains source place ID, evidence ID, provider source ID,
response hash, source date, exact supporting quote and FACT/INFERENCE/UNKNOWN status.
The current extractor emits factual values only for narrowly recognized complete
statements. Negative or qualified statements such as `주차 가능 공간이 없습니다.`
must not become positive parking evidence. Unrecognized/contradictory claims remain
unknown. Stroller rental, wheelchair access and senior access are separate fields.

Daily TourAPI common/intro inputs now retain supplied facility fields in source
excerpts. Newly scored outputs preserve unknown condition values as null. Immutable
old releases are not rewritten; v4 resolves available facts from their excerpts.
Exact quotation matching checks provenance, not semantic entailment or real-world
truth. Missing facts need better source collection or human review.

The bundled 2026-08-27 PUBLIC100 release still has one source excerpt per place
(median 246 characters). The final conservative-parser audit found 1,000 unknown
observations across 10 fact fields per place. This is a data-coverage
limitation, not evidence that the facilities do not exist. No live recollection or
production release activation was performed as part of this change.

## Photo semantics

`photo-semantics-v2` uses canonical preference anchors on the same M1–M6 scales as
place profiles. Text hashing is no longer a numeric preference function. Canonical
text formatting changes preserve meaning; unsupported free-text edits have no
numeric authority. Semantic IDs, provider identity, analysis kind and image index
are persisted by migration 0027. Existing legacy/synthetic rows are untrusted for
new recommendation scoring.

`photo-projection-v2` averages each trait over observed images only. Unobserved
dimensions keep their quiz targets. Observed dimensions blend 35% photo /65% quiz
for mismatch expectations. Photo relevance compares the raw confirmed observed
anchors only, then combines 35% photo fit /65% base relevance. The same observed mask
and expected values must apply to all five recommendations. Missing traits are not
zero. An empty image is skipped; if every image is empty the flow offers no-photo
recovery. Job candidates remain capped at 6: one image up to 6, two up to 3 each, three
up to 2 each, with deterministic semantic ordering.

Synthetic providers require explicit test injection. Production defaults to analysis
unavailable until a real vision provider is explicitly configured:

```dotenv
ITDA_PHOTO_VLM_ENABLED=1
ITDA_PHOTO_VLM_ENDPOINT=https://api.z.ai/api/paas/v4/chat/completions
ITDA_PHOTO_VLM_MODEL=glm-4.6v
ITDA_PHOTO_VLM_API_KEY=<provider credential>
```

The adapter sends sanitized PNG bytes, accepts only canonical semantic IDs, bounds
response size/time, and does not log image payloads or retry external calls.
Configuration is forwarded by the Compose/Swarm templates. Use a supported vision
endpoint and an appropriate credential. The adapter was verified with an injected
HTTP transport and a real PostgreSQL lifecycle; real-provider recognition quality
has not been measured in this change.

## Development evaluation and release gates

```sh
PYTHONPATH=backend/src backend/.venv.nosync/bin/python \
  -m itda.cli.evaluate_recommendation_quality \
  --scenarios fixtures/recommendation-quality/development-scenarios.json \
  --release artifacts/public/catalog/mvp-scored-releases/releases/1de50e3e4d4e0b32f0358f0f6fa9611e88dc36cbbf050f8811a3e91cc7b54e49/release.json \
  --output artifacts/reports/recommendation-quality.json
```

The report separates authored behavioral cases, actual PUBLIC-release consistency
checks, factual coverage, scoring/weight alternatives and optional genuine human
judgments. Human NDCG/relevance and entailment metrics remain unavailable without
supplied genuine judgments. BLIND/sealed paths and nondevelopment input membership
are rejected before evaluation. No BLIND data or fabricated human labels are used.

Daily refresh produces a consistency report before both publishing and activation.
The gate binds the exact candidate release, kernel/projection/fact policy versions,
scenario suite and report hash. Missing/stale/failed reports, invalid source bindings
or bounds reject the update. A score change over 40 points requires review and keeps
the predecessor active. Investigate the recorded reason and rerun evaluation before
trying publication again; the workflow never automatically promotes a new weight
set from synthetic results. Full reports/gate results are returned and logged, with
the primary reason retained in the existing daily-run status.
