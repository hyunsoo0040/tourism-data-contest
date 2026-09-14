"""Emit browser fixtures from validated backend code with synthetic transports.

Run at repository root with PYTHONPATH=backend/src:backend and the backend venv.
No live provider requests, production profile promotion, or human labels.
"""
import json
from pathlib import Path

from itda.contracts.destination_mood import DestinationMoodBundle
from itda.contracts.grounded_recommendation import GroundedTripInput
from itda.contracts.grounded_responses import (
    GroundedComparisonResponse,
    GroundedDetailResponse,
    GroundedReleaseDisclosure,
    GroundedResultsResponse,
)
from itda.contracts.visual_mood import MOOD_POLICY_SHA256
from itda.domain.canonical import canonical_sha256
from tests.unit.test_grounded_recommendation import NOW, candidate, run
from tests.unit.test_grounded_runtime_wiring import arguments, registry_for

root = Path(__file__).resolve().parent
candidates = [candidate(i, axes="ER" if i == 0 else "HER") for i in range(8)]
receipt = run(candidates)
disclosure = GroundedReleaseDisclosure(
    raw_release_sha256=receipt.authority.release_sha256,
    source_release_sha256=receipt.authority.source_release_sha256,
    assessment_manifest_sha256=receipt.authority.assessment_manifest_sha256,
    candidate_sha256=receipt.authority.candidate_sha256,
    config_sha256=receipt.authority.config_sha256,
)
results = GroundedResultsResponse(
    preference_profile_id=receipt.preference.profile_id,
    run=receipt,
    release_disclosure=disclosure,
)
details = []
for item in receipt.items:
    member = next(candidate for candidate in candidates if candidate.place_id == item.place_id)
    fields = {
        "schema_version": "destination-mood.v1", "authority_scope": "VISUAL_MOOD_ONLY",
        "place_id": item.place_id, "raw_profile_sha256": item.raw_profile_sha256,
        "source_release_sha256": receipt.authority.source_release_sha256,
        "assessed_at": NOW.isoformat().replace("+00:00", "Z"), "mood_policy_sha256": MOOD_POLICY_SHA256,
        "selection_policy_sha256": "e" * 64, "images": [], "decisions": [], "strata": [],
        "limit_ko": "이 합성 평가 표본은 이미지 관찰이 없습니다.",
    }
    mood = DestinationMoodBundle.model_validate(fields | {"bundle_sha256": canonical_sha256(fields)})
    details.append(GroundedDetailResponse(
        recommendation_run_id=receipt.run_id, release_sha256=receipt.authority.candidate_sha256,
        item=item, assessment=member.assessment, mood=mood,
    ))
comparison = GroundedComparisonResponse(
    recommendation_run_id=receipt.run_id, release_sha256=receipt.authority.candidate_sha256,
    places=tuple(details[:2]),
)
grounded = {
    "provenance": "SYNTHETIC_UNIT_CASE_NOT_FIELD_DATA",
    "results": results.model_dump(mode="json"),
    "assessments": [candidate.assessment.model_dump(mode="json") for candidate in candidates],
    "details": [detail.model_dump(mode="json") for detail in details],
    "comparison": comparison.model_dump(mode="json"),
}
registry, _, _, catalog = registry_for()
context = registry.context(**arguments(catalog))
full_context = registry.context(
    run_id=receipt.run_id, place_ids=tuple(item.place_id for item in receipt.items),
    trip_input=GroundedTripInput.model_validate(receipt.preference.trip_input.model_dump(mode="json")),
    eligible_place_ids=receipt.eligible_place_ids,
)
tourism = {
    "provenance": "SYNTHETIC_TRANSPORT_REAL_NORMALIZERS_NOT_FIELD_DATA",
    "context": context.model_dump(mode="json"), "grounded_context": full_context.model_dump(mode="json"),
}
for name, data in (("grounded-synthetic-v5.json", grounded), ("tourism-synthetic-v2.json", tourism)):
    (root / name).write_text(json.dumps(data, ensure_ascii=False, indent=2) + "\n")
    print(name)
