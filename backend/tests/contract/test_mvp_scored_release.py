from __future__ import annotations

from datetime import UTC, datetime

import pytest
from pydantic import ValidationError

from itda.contracts.mvp_place_scoring import (
    SCORING_DIMENSIONS,
    BoundScoringResult,
    LocalConditionScores,
    ProviderScoringResponse,
)
from itda.contracts.mvp_public_catalog import PublicEvidence
from itda.contracts.mvp_scored_release import (
    FailedPlace,
    InformationState,
    MvpEvidenceExcerpt,
    MvpReleaseLineage,
    MvpScoredProfile,
    MvpScoredRelease,
)
from itda.contracts.recommendation import public_relation_sha256
from itda.domain.canonical import canonical_sha256
from tests.pipeline.test_mvp_public_catalog import _evidence

SHA = "0" * 64
EVIDENCE_ID = f"evidence:{'1' * 64}"


def _release_evidence():
    evidence = _evidence(1).model_copy(update={"evidence_id": EVIDENCE_ID})
    return evidence.model_copy(
        update={
            "evidence_sha256": canonical_sha256(
                evidence.model_dump(exclude={"evidence_sha256"}, mode="json")
            )
        }
    )


def _release_inventory_sha256() -> str:
    evidence = _release_evidence()
    return canonical_sha256(
        {
            "schema_version": "public-evidence-inventory.v1",
            "evidence": [evidence.model_dump(mode="json")],
        }
    )


def profile(
    index: int,
    confidence: int = 50,
    *,
    catalog_sha256: str = SHA,
    evidence_inventory_sha256: str | None = None,
    evidence: PublicEvidence | None = None,
) -> MvpScoredProfile:
    evidence = evidence or _release_evidence()
    evidence_id = evidence.evidence_id
    evidence_inventory_sha256 = evidence_inventory_sha256 or _release_inventory_sha256()
    response = ProviderScoringResponse.model_validate(
        {
            "H": 50,
            "E": 51,
            "R": 52,
            **{dimension: 2 for dimension in SCORING_DIMENSIONS[3:15]},
            **{dimension: 50 for dimension in SCORING_DIMENSIONS[15:]},
            "confidence": confidence,
            "justifications": [
                {
                    "dimension": dimension,
                    "evidence_ids": [evidence_id],
                    "justification_ko": f"{dimension} 합성 근거",
                }
                for dimension in SCORING_DIMENSIONS
            ],
        }
    )
    place_id = f"public:gyeongju:{index:064x}"
    conditions = LocalConditionScores(
        visit_date_time=50,
        companions=50,
        transport=50,
        walking=50,
        indoor_outdoor=50,
        crowd=50,
    )
    result_fields = {
        "schema_version": "mvp-place-scoring-result.v2",
        "place_id": place_id,
        "request_sha256": f"{index + 200:064x}",
        "catalog_sha256": catalog_sha256,
        "evidence_inventory_sha256": evidence_inventory_sha256,
        "model": "glm-5.3-flash",
        "prompt_sha256": SHA,
        "response_sha256": f"{index + 300:064x}",
        "scores": response,
        "condition_scores": conditions,
    }
    scoring_result = BoundScoringResult(
        **result_fields,
        result_sha256=canonical_sha256(
            {
                **result_fields,
                "scores": response.model_dump(mode="json"),
                "condition_scores": conditions.model_dump(mode="json"),
            }
        ),
    )
    fields = {
        "place_id": place_id,
        "place_name_ko": f"합성 공개 장소 {index}",
        "duplicate_group_id": f"duplicate:{index:064x}",
        "source_evidence_ids": (evidence_id,),
        "evidence_excerpts": (
            MvpEvidenceExcerpt(
                evidence_id=evidence_id,
                excerpt_ko=evidence.excerpt,
                source_label_ko="합성 공개 데이터",
                attribution_ko=evidence.attribution_text,
                reference_date=evidence.reference_date,
                evidence=evidence,
            ),
        ),
        "scores": response,
        "condition_scores": conditions,
        "information_state": (
            InformationState.AUDIT_ONLY
            if confidence < 55
            else InformationState.LIMITED_INFORMATION
            if confidence < 70
            else InformationState.SUPPORTED
        ),
        "recommendation_eligible": True,
        "scoring_result": scoring_result,
    }
    serializable = {
        key: (
            value.model_dump(mode="json")
            if hasattr(value, "model_dump")
            else [item.model_dump(mode="json") for item in value]
            if key == "evidence_excerpts"
            else value
        )
        for key, value in fields.items()
    }
    serializable["information_state"] = str(fields["information_state"])
    return MvpScoredProfile(**fields, profile_sha256=canonical_sha256(serializable))


def release(
    count: int,
    *,
    marker: int = 0,
    catalog_sha256: str | None = None,
    evidence_inventory_sha256: str | None = None,
    evidences: tuple[PublicEvidence, ...] | None = None,
) -> MvpScoredRelease:
    catalog_sha256 = catalog_sha256 or f"{marker:064x}"
    evidence_inventory_sha256 = evidence_inventory_sha256 or _release_inventory_sha256()
    profiles = tuple(
        profile(
            index,
            confidence=index % 101,
            catalog_sha256=catalog_sha256,
            evidence_inventory_sha256=evidence_inventory_sha256,
            evidence=evidences[index] if evidences is not None else None,
        )
        for index in range(count)
    )
    failed = tuple(
        FailedPlace(
            place_id=f"public:gyeongju:{index:064x}",
            reason="PROVIDER_ATTEMPT_FAILED",
        )
        for index in range(count, 100)
    )
    fields = {
        "schema_version": "mvp-scored-release.v1",
        "attempted_count": 100,
        "published_count": count,
        "catalog_sha256": catalog_sha256,
        "relation_sha256": public_relation_sha256(tuple(row.place_id for row in profiles), ()),
        "evidence_inventory_sha256": evidence_inventory_sha256,
        "membership_sha256": canonical_sha256([row.place_id for row in profiles]),
        "relation_pairs": (),
        "profiles": profiles,
        "failed": failed,
        "lineage": MvpReleaseLineage(
            prompt_sha256=SHA,
            response_schema_sha256=SHA,
            source_sha256=SHA,
            entitlement_snapshot_sha256=SHA,
            canary_plan_sha256=SHA,
            canary_outcome_sha256=SHA,
            run_plan_sha256=SHA,
        ),
        "created_at": datetime(2026, 8, 25, tzinfo=UTC),
    }
    serializable = {
        **fields,
        "profiles": [row.model_dump(mode="json") for row in profiles],
        "failed": [row.model_dump(mode="json") for row in failed],
        "lineage": fields["lineage"].model_dump(mode="json"),
        "created_at": fields["created_at"].isoformat().replace("+00:00", "Z"),
    }
    return MvpScoredRelease(**fields, release_sha256=canonical_sha256(serializable))


def test_79_profiles_are_rejected() -> None:
    with pytest.raises(ValidationError):
        release(79)


@pytest.mark.parametrize("count", [80, 100])
def test_80_and_100_profile_contracts_are_valid(count: int) -> None:
    snapshot = release(count)
    assert snapshot.published_count == count
    assert snapshot.attempted_count == 100
    assert snapshot.profiles[0].recommendation_eligible is True
    assert snapshot.profiles[0].information_state is InformationState.AUDIT_ONLY


def test_profile_rejects_justification_evidence_outside_local_inventory() -> None:
    row = profile(1)
    payload = row.model_dump(mode="json")
    payload["scores"]["justifications"][0]["evidence_ids"] = [f"evidence:{'f' * 64}"]
    payload["scoring_result"]["scores"] = payload["scores"]
    payload["scoring_result"]["result_sha256"] = canonical_sha256(
        {key: value for key, value in payload["scoring_result"].items() if key != "result_sha256"}
    )
    payload["profile_sha256"] = canonical_sha256(
        {key: value for key, value in payload.items() if key != "profile_sha256"}
    )
    with pytest.raises(ValidationError, match="outside the profile"):
        MvpScoredProfile.model_validate(payload)


def test_profile_rejects_bound_result_projection_mismatch() -> None:
    row = profile(1)
    payload = row.model_dump(mode="json")
    payload["condition_scores"]["crowd"] = 99
    payload["profile_sha256"] = canonical_sha256(
        {key: value for key, value in payload.items() if key != "profile_sha256"}
    )
    with pytest.raises(ValidationError, match="does not match"):
        MvpScoredProfile.model_validate(payload)


def test_release_rejects_conflicting_nested_evidence() -> None:
    payload = release(80).model_dump(mode="json")
    excerpt = payload["profiles"][1]["evidence_excerpts"][0]
    excerpt["evidence"]["provider_source_id"] = "conflicting-source"
    excerpt["evidence"]["evidence_sha256"] = canonical_sha256(
        {
            key: value
            for key, value in excerpt["evidence"].items()
            if key != "evidence_sha256"
        }
    )
    _reseal_profile(payload["profiles"][1])
    _reseal_release(payload)

    with pytest.raises(ValidationError, match="conflicting public evidence"):
        MvpScoredRelease.model_validate(payload)


def _reseal_profile(payload: dict[str, object]) -> None:
    result = payload["scoring_result"]
    result["result_sha256"] = canonical_sha256(
        {key: value for key, value in result.items() if key != "result_sha256"}
    )
    payload["profile_sha256"] = canonical_sha256(
        {key: value for key, value in payload.items() if key != "profile_sha256"}
    )


def _reseal_release(payload: dict[str, object]) -> None:
    payload["release_sha256"] = canonical_sha256(
        {key: value for key, value in payload.items() if key != "release_sha256"}
    )


@pytest.mark.parametrize(
    ("result_field", "release_field"),
    [
        ("catalog_sha256", "catalog_sha256"),
        ("evidence_inventory_sha256", "evidence_inventory_sha256"),
        ("prompt_sha256", "lineage.prompt_sha256"),
        ("model", "lineage.model"),
    ],
)
def test_release_rejects_profile_scoring_lineage_mismatch(
    result_field: str, release_field: str
) -> None:
    snapshot = release(80)
    payload = snapshot.model_dump(mode="json")
    if result_field == "model":
        payload["profiles"][0]["scoring_result"][result_field] = "wrong/model"
    else:
        payload["profiles"][0]["scoring_result"][result_field] = "f" * 64
    _reseal_profile(payload["profiles"][0])
    _reseal_release(payload)
    expected_error = "Input should be" if result_field == "model" else "scoring lineage"
    with pytest.raises(ValidationError, match=expected_error):
        MvpScoredRelease.model_validate(payload)


@pytest.mark.parametrize("hash_field", ["request_sha256", "result_sha256"])
def test_release_rejects_reused_scoring_hashes(hash_field: str) -> None:
    snapshot = release(80)
    payload = snapshot.model_dump(mode="json")
    first_result = payload["profiles"][0]["scoring_result"]
    second_profile = payload["profiles"][1]
    second_result = second_profile["scoring_result"]
    second_result[hash_field] = first_result[hash_field]
    if hash_field == "request_sha256":
        _reseal_profile(second_profile)
    else:
        second_profile["profile_sha256"] = canonical_sha256(
            {key: value for key, value in second_profile.items() if key != "profile_sha256"}
        )
    _reseal_release(payload)
    with pytest.raises(ValidationError, match=f"scoring {hash_field.removesuffix('_sha256')}"):
        MvpScoredRelease.model_validate(payload)
