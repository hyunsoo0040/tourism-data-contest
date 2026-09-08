"""Wave 0 controlled-RED contracts for strict Phase 6 trait candidates.

Freezes the bounded candidate-only authority: strict Korean trait schema,
``CANDIDATE_EVIDENCE_ONLY`` scope, canonical digest binding, import-time
schema tripwire, unknown-field rejection, and HTML-as-text rendering. The
module fails only on the absent ``itda.photo.contracts`` implementation.
"""

from __future__ import annotations

import copy
import hashlib

import pytest
from pydantic import ValidationError

from itda.domain.canonical import canonical_json_bytes, canonical_sha256

CANDIDATE_SCHEMA_VERSION = "photo-trait-candidates.v1"
JOB_ID = "0f1e2d3c4b5a69788796a5b4c3d2e1f0" * 2
PAYLOAD_SHA = hashlib.sha256(b"sanitized-bytes").hexdigest()


def _contracts():
    import itda.photo.contracts as photo_contracts

    return photo_contracts


def _candidate(
    *,
    candidate_id: str = "aa" * 32,
    trait_id: str = "M5",
    text_ko: str = "조용한 산책로",
) -> dict[str, object]:
    return {
        "candidate_id": candidate_id,
        "trait_id": trait_id,
        "text_ko": text_ko,
    }


def _candidate_set_payload(
    candidates: list[dict[str, object]] | None = None,
) -> dict[str, object]:
    payload: dict[str, object] = {
        "schema_version": CANDIDATE_SCHEMA_VERSION,
        "job_id": JOB_ID,
        "payload_sha256": PAYLOAD_SHA,
        "candidates": candidates if candidates is not None else [_candidate()],
        "authority_scope": "CANDIDATE_EVIDENCE_ONLY",
    }
    payload["candidate_set_sha256"] = canonical_sha256(payload)
    return payload


def _reseal(payload: dict[str, object]) -> dict[str, object]:
    sealed = copy.deepcopy(payload)
    sealed["candidate_set_sha256"] = canonical_sha256(
        {key: value for key, value in sealed.items() if key != "candidate_set_sha256"}
    )
    return sealed


def test_candidate_authority_scope_is_candidate_evidence_only() -> None:
    contracts = _contracts()
    assert contracts.CANDIDATE_EVIDENCE_ONLY == "CANDIDATE_EVIDENCE_ONLY"

    restored = contracts.PhotoTraitCandidateSet.model_validate(_candidate_set_payload())
    assert restored.authority_scope == "CANDIDATE_EVIDENCE_ONLY"
    assert restored.job_id == JOB_ID
    assert restored.payload_sha256 == PAYLOAD_SHA


def test_strict_candidates_reject_unknown_fields_and_types() -> None:
    contracts = _contracts()

    unknown = _candidate_set_payload()
    candidates = unknown["candidates"]
    assert isinstance(candidates, list)
    candidates[0]["display_label"] = "조용한 산책로"
    with pytest.raises(ValidationError):
        contracts.PhotoTraitCandidateSet.model_validate(_reseal(unknown))

    top_level_unknown = _candidate_set_payload()
    top_level_unknown["extra_unknown"] = 1
    with pytest.raises(ValidationError):
        contracts.PhotoTraitCandidateSet.model_validate(_reseal(top_level_unknown))

    float_text = _candidate_set_payload()
    float_candidates = float_text["candidates"]
    assert isinstance(float_candidates, list)
    float_candidates[0]["trait_id"] = 5.5
    with pytest.raises(ValidationError):
        contracts.PhotoTraitCandidateSet.model_validate(_reseal(float_text))

    wrong_schema = _candidate_set_payload()
    wrong_schema["schema_version"] = "photo-trait-candidates.v2"
    with pytest.raises(ValidationError):
        contracts.PhotoTraitCandidateSet.model_validate(_reseal(wrong_schema))


def test_forbidden_authority_fields_are_rejected_recursively() -> None:
    contracts = _contracts()

    for forbidden_key in (
        "rank",
        "ranking",
        "recommendation",
        "recommendation_score",
        "release",
        "release_authority",
        "admission",
        "catalog_eligible",
        "confidence",
        "axis_score",
        "axis_scores",
        "fused_score",
        "display_label",
        "internal_score",
        "publishability",
        "selection",
        "eligibility",
    ):
        hostile = _candidate_set_payload()
        candidates = hostile["candidates"]
        assert isinstance(candidates, list)
        candidates[0]["metadata"] = {"nested": [{"deep": {forbidden_key: 1}}]}
        with pytest.raises(ValidationError):
            contracts.PhotoTraitCandidateSet.model_validate(_reseal(hostile))


def test_forbidden_path_and_secret_categories_are_rejected() -> None:
    contracts = _contracts()

    for category in ("path", "file_path", "private_path", "filename", "original_filename"):
        hostile = _candidate_set_payload()
        candidates = hostile["candidates"]
        assert isinstance(candidates, list)
        candidates[0]["metadata"] = {category: "/artifacts/anywhere"}
        with pytest.raises(ValidationError):
            contracts.PhotoTraitCandidateSet.model_validate(_reseal(hostile))

    for category in ("secret", "api_key", "token", "authorization", "credential"):
        hostile = _candidate_set_payload()
        candidates = hostile["candidates"]
        assert isinstance(candidates, list)
        candidates[0]["metadata"] = {"nested": {category: "value"}}
        with pytest.raises(ValidationError):
            contracts.PhotoTraitCandidateSet.model_validate(_reseal(hostile))


def test_korean_trait_text_bounds_are_frozen() -> None:
    contracts = _contracts()

    too_long = _candidate_set_payload([_candidate(text_ko="가" * 25)])
    with pytest.raises(ValidationError):
        contracts.PhotoTraitCandidateSet.model_validate(too_long)

    non_korean = _candidate_set_payload([_candidate(text_ko="english only")])
    with pytest.raises(ValidationError):
        contracts.PhotoTraitCandidateSet.model_validate(non_korean)

    html_payload = _candidate_set_payload([_candidate(text_ko="<b>조용한 산책로</b>")])
    restored = contracts.PhotoTraitCandidateSet.model_validate(html_payload)
    rendered = contracts.render_trait_text_as_data(restored.candidates[0].text_ko)
    assert isinstance(rendered, str)
    assert "<b>" in rendered, "renderer must treat HTML as inert text, not markup"


def test_candidate_count_cap_is_frozen() -> None:
    contracts = _contracts()

    at_cap = _candidate_set_payload(
        [
            _candidate(
                candidate_id=hashlib.sha256(f"id:{index}".encode()).hexdigest(),
                text_ko=f"선호 문구 {index}",
            )
            for index in range(1, 7)
        ]
    )
    contracts.PhotoTraitCandidateSet.model_validate(at_cap)

    over_cap = _candidate_set_payload(
        [
            _candidate(
                candidate_id=hashlib.sha256(f"id:{index}".encode()).hexdigest(),
                text_ko=f"선호 문구 {index}",
            )
            for index in range(1, 8)
        ]
    )
    with pytest.raises(ValidationError):
        contracts.PhotoTraitCandidateSet.model_validate(over_cap)


def test_candidate_set_digest_binds_canonical_content() -> None:
    contracts = _contracts()

    payload = _candidate_set_payload()
    restored = contracts.PhotoTraitCandidateSet.model_validate(payload)
    expected = canonical_sha256(restored.model_dump(mode="json", exclude={"candidate_set_sha256"}))
    assert restored.candidate_set_sha256 == expected

    tampered = _candidate_set_payload()
    tampered["job_id"] = "99999999999999999999999999999999"
    with pytest.raises(ValidationError):
        contracts.PhotoTraitCandidateSet.model_validate(tampered)


def test_candidate_schema_tripwire_is_bound_at_import() -> None:
    contracts = _contracts()

    schema_definition = contracts.photo_trait_candidate_schema_definition()
    assert schema_definition["authority_scope"] == "CANDIDATE_EVIDENCE_ONLY"
    assert schema_definition["candidate_cap"] == 6
    assert schema_definition["trait_text_max_ko_length"] == 24
    approved = contracts.APPROVED_PHOTO_TRAIT_CANDIDATE_SCHEMA_SHA256
    assert contracts.photo_trait_candidate_schema_sha256() == approved


def test_f01_opaque_job_id_accepts_exactly_64_hex_only() -> None:
    """F-01: the provider-facing opaque job identity is exactly 64 lowercase hex."""

    contracts = _contracts()
    definition = contracts.photo_trait_candidate_schema_definition()
    assert definition["job_id"] == "hex-opaque-64"
    for hostile_id in (
        "0f1e2d3c4b5a69788796a5b4c3d2e1f0",
        "0" * 63,
        "0" * 65,
        "F" * 64,
    ):
        hostile = _candidate_set_payload()
        hostile["job_id"] = hostile_id
        with pytest.raises(ValidationError):
            contracts.PhotoTraitCandidateSet.model_validate(_reseal(hostile))


def test_f01_scan_forbids_32_to_64_job_identity_ranges_outside_migrations() -> None:
    """F-01: production and contract surfaces accept only the exact 64-hex identity.

    Historical immutable migration checks (exact ``{64}`` assertions in
    ``backend/migrations``) are intentionally outside the scanned roots.
    """

    import re as re_module
    from pathlib import Path

    repository_root = Path(__file__).resolve().parents[3]
    scanned_roots = (
        repository_root / "backend" / "src",
        repository_root / "backend" / "tests" / "contract",
        repository_root / "backend" / "tests" / "security",
    )
    range_patterns = tuple(
        re_module.compile(pattern) for pattern in (r"\{32,\s*64\}", r"32-to-64", r"32 to 64")
    )
    offenders: list[str] = []
    for root in scanned_roots:
        for path in sorted(root.rglob("*.py")):
            if path.name == Path(__file__).name:
                continue
            text = path.read_text(encoding="utf-8")
            if any(pattern.search(text) for pattern in range_patterns):
                offenders.append(str(path.relative_to(repository_root)))
    assert offenders == [], "F-01: 32..64-hex job identity ranges remain in: " + ", ".join(
        offenders
    )


def test_candidate_ids_are_unique_opaque_and_unordered() -> None:
    contracts = _contracts()

    duplicate_id = "bb" * 32
    duplicated = _candidate_set_payload(
        [
            _candidate(candidate_id=duplicate_id, text_ko="첫 번째 선호"),
            _candidate(candidate_id=duplicate_id, text_ko="두 번째 선호"),
        ]
    )
    with pytest.raises(ValidationError):
        contracts.PhotoTraitCandidateSet.model_validate(duplicated)

    restored = contracts.PhotoTraitCandidateSet.model_validate(_candidate_set_payload())
    assert [candidate.candidate_id for candidate in restored.candidates] == ["aa" * 32]


def test_canonical_bytes_round_trip_is_byte_stable() -> None:
    contracts = _contracts()

    payload = _candidate_set_payload()
    raw = canonical_json_bytes(payload)
    restored = contracts.PhotoTraitCandidateSet.model_validate_raw(raw)
    assert canonical_json_bytes(restored.model_dump(mode="json")) == raw
