"""Schema and guardrail coverage for the synthetic Phase 4 challenge pack."""

from __future__ import annotations

import hashlib
import json
import os
import re
from copy import deepcopy
from dataclasses import dataclass
from io import BytesIO
from pathlib import Path
from typing import cast

import httpx
import pytest
from PIL import Image
from pydantic import ValidationError

from itda.analysis.image.preprocessing import ImagePreprocessingPolicy
from itda.analysis.image.secure_read import (
    ApprovedImageMaterialization,
    RightsBoundImage,
    SecureImageReadError,
    SecureReadPolicy,
    read_approved_image,
)
from itda.analysis.image.selection import (
    SceneEmbeddingEncoder,
    gate_selection_assets,
    select_representative_images,
)
from itda.contracts.catalog_optional_media import ImageMediumState
from itda.contracts.image_observation import ImageObservationV2
from itda.contracts.image_selection import (
    AssetDecisionCode,
    ImageSelectionPolicy,
    PlaceImageSelectionCandidate,
    SelectionAssetSource,
    SelectionAuthorityScope,
    build_image_selection_policy,
)
from itda.contracts.phase3_lane_baseline import Phase3LaneBaselineMember
from itda.contracts.phase4_benchmark import (
    ATTRIBUTE_IDS,
    BenchmarkCase,
    BenchmarkRepeat,
    BenchmarkReportState,
    BenchmarkScoreVector,
    ProvisionalBenchmarkReport,
    ZeroImageFallbackProof,
    build_provisional_report,
    finalize_benchmark,
)
from itda.contracts.place_profile import SubattributeId
from itda.contracts.profile_fusion import (
    CANONICAL_FUSION_POLICY,
    AxisId,
    FusedAttribute,
    FusedAxis,
    FusionPolicyConfig,
    LaneContributionTrace,
    LaneId,
)
from itda.contracts.profile_release_authority import (
    ProfileReleaseAuthorityError,
    ProfileReleaseAuthorityPathsV2,
    resolve_authoritative_profile_release_candidate_v2,
)
from itda.contracts.profile_release_v2 import ProfileReleaseCohortMemberV2
from itda.contracts.vlm_inference import AttemptOutcome, InferenceTerminalStatus
from itda.domain.canonical import canonical_json_bytes, canonical_sha256
from itda.domain.profile_fusion import (
    build_fused_profile,
    classify_publication,
    compute_profile_confidence,
    derive_display_label,
    derive_final_axes,
    description_fidelity_bp,
    image_fidelity_bp,
    odii_fidelity_bp,
    require_release_eligible_policy,
)
from tests.contract.test_image_observation import _qualified_payload
from tests.contract.test_profile_release_authority_v2 import (
    _authority_payloads,
    _fusion_predecessor_profile,
)
from tests.contract.test_profile_release_authority_v2 import (
    _request as _authority_request,
)
from tests.contract.test_profile_release_authority_v2 import (
    _self_hash as _self_hash_authority,
)
from tests.contract.test_profile_release_authority_v2 import (
    _write_bundle as _write_authority_bundle,
)
from tests.evals.phase4.test_phase4_benchmark import (
    NOW as BENCHMARK_NOW,
)
from tests.evals.phase4.test_phase4_benchmark import (
    _case as _benchmark_case,
)
from tests.evals.phase4.test_phase4_benchmark import (
    _experiment as _benchmark_experiment,
)
from tests.evals.phase4.test_phase4_benchmark import (
    _inventory as _benchmark_inventory,
)
from tests.evals.phase4.test_phase4_benchmark import (
    _review as _benchmark_review,
)
from tests.providers.test_zhipu_glm5v import (
    _adapter as _provider_adapter,
)
from tests.providers.test_zhipu_glm5v import (
    _images as _provider_images,
)
from tests.providers.test_zhipu_glm5v import (
    _provider_response,
)
from tests.providers.test_zhipu_glm5v import (
    _request as _provider_request,
)

REPOSITORY_ROOT = Path(__file__).resolve().parents[4]
CHALLENGE_PACK = REPOSITORY_ROOT / "fixtures/synthetic/phase4/challenge-pack.json"
SHA256 = re.compile(r"^[0-9a-f]{64}$")

REQUIRED_CATEGORIES = {
    "media_state",
    "fidelity_boundary",
    "agreement_boundary",
    "selection_adversary",
    "provider_failure",
    "visible_evidence",
    "axis_derivation",
    "fusion_policy",
    "confidence_boundary",
    "display_type_boundary",
    "review_transition",
    "filesystem_attack",
    "release_lineage",
    "fusion_authority",
    "demo_authority",
}
REQUIRED_SCENARIOS = {
    "exact_duplicate",
    "perceptual_duplicate",
    "selection_permutation_a",
    "selection_permutation_b",
    "temporary_event",
    "low_quality",
    "prompt_injection",
    "non_visible_fact",
    "phantom_evidence_ref",
    "provider_retryable_exhaustion",
    "provider_semantic_no_retry",
    "provider_auth_no_retry",
    "provider_schema_rejection",
    "coherent_fusion_rewrite",
    "caller_selected_demo_authority",
    "nested_profile_direct_sql",
    "four_attribute_half_up",
    "one_unit_axis_drift",
    "fewer_than_two_comparable_lanes",
    "sensitivity_d13_rejected",
    "sensitivity_d16_rejected",
    "sensitivity_d18_rejected",
    "sensitivity_d21_rejected",
    "provisional_review_final",
    "conditional_adoption",
    "image_rejected_text_odii_only",
    "no_image_text_odii_only",
    "symlink_attack",
    "hardlink_attack",
    "path_substitution_attack",
    "mid_read_toctou_attack",
    "stale_predecessor",
    "sibling_rollback",
    "pin_stability",
}

REPOSITORY_SCENARIOS = {
    "stale_predecessor",
    "sibling_rollback",
    "pin_stability",
    "nested_profile_direct_sql",
}


def _load_pack() -> dict[str, object]:
    raw = CHALLENGE_PACK.read_bytes()
    payload = json.loads(raw)
    assert raw in {canonical_json_bytes(payload), canonical_json_bytes(payload) + b"\n"}
    assert isinstance(payload, dict)
    return payload


def _cases(payload: dict[str, object]) -> list[dict[str, object]]:
    cases = payload["cases"]
    assert isinstance(cases, list)
    assert all(isinstance(case, dict) for case in cases)
    return cases


def test_challenge_pack_is_canonical_self_authenticating_and_synthetic() -> None:
    payload = _load_pack()
    assert payload["schema_version"] == "itda.phase4-challenge-pack.v1"
    assert payload["fixture_scope"] == "SYNTHETIC_LOCAL"
    assert payload["protected_evidence_status"] == "NOT_ACCESSED"
    assert payload["provider_mode"] == "OFFLINE_REPLAY_ONLY"
    assert SHA256.fullmatch(str(payload["policy_sha256"]))
    assert SHA256.fullmatch(str(payload["config_sha256"]))
    assert payload["pack_sha256"] == canonical_sha256(
        {key: value for key, value in payload.items() if key != "pack_sha256"}
    )

    serialized = json.dumps(payload, ensure_ascii=False, sort_keys=True).casefold()
    for prohibited in (
        "zhipuai_api_key",
        "bigmodel_api_key",
        "authorization",
        "raw_image_bytes",
        "raw_response_body",
        "protected_path",
        "dev_members",
        "blind_members",
        "ordered_catalog_ids",
        "expert_label",
        "dev_label_scores",
        "reconciliation_nonce",
    ):
        assert prohibited not in serialized
    assert '"relative_path"' not in serialized
    assert '"absolute_path"' not in serialized
    assert "/artifacts/restricted/" not in serialized


def test_every_case_has_exact_state_lineage_and_expected_local_result() -> None:
    payload = _load_pack()
    cases = _cases(payload)
    assert len(cases) >= 20
    assert len({case["case_id"] for case in cases}) == len(cases)

    exact_states = {state.value for state in ImageMediumState}
    for case in cases:
        assert re.fullmatch(r"phase4-case-[0-9]{2}", str(case["case_id"]))
        assert str(case["media_state"]) in exact_states
        assert str(case["synthetic_place_ref"]).startswith("synthetic-place-")
        assert case["policy_sha256"] == payload["policy_sha256"]
        assert case["config_sha256"] == payload["config_sha256"]
        assert case["authority"] == "LOCAL_POLICY_ONLY"
        assert isinstance(case["evidence_refs"], list) and case["evidence_refs"]
        assert all(SHA256.fullmatch(str(ref)) for ref in case["evidence_refs"])
        assert isinstance(case["decision_ids"], list) and case["decision_ids"]
        assert all(
            re.fullmatch(r"D-(?:0[1-9]|1[0-9]|2[0-9]|30)", str(item))
            for item in case["decision_ids"]
        )
        assert isinstance(case["expected"], dict)
        assert case["expected"]["release_authority"] == "DENIED"
        assert case["expected"]["protected_evidence_claim"] == "NONE"

    assert {case["media_state"] for case in cases} == exact_states
    assert {str(case["category"]) for case in cases}.issuperset(REQUIRED_CATEGORIES)
    assert {str(case["scenario"]) for case in cases}.issuperset(REQUIRED_SCENARIOS)


def _sha256(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def _png_bytes(
    *, size: tuple[int, int] = (80, 60), color: tuple[int, int, int] = (34, 85, 136)
) -> bytes:
    image = Image.new("RGB", size, color)
    for offset in range(min(size)):
        image.putpixel((offset, offset), (255, 255 - offset % 255, offset % 255))
    output = BytesIO()
    image.save(output, format="PNG")
    image.close()
    return output.getvalue()


def _selection_source(
    root: Path,
    *,
    source_asset_id: str,
    payload: bytes,
    temporary_event: bool = False,
) -> SelectionAssetSource:
    path = root / f"{source_asset_id}.png"
    path.write_bytes(payload)
    path.chmod(0o600)
    approved = ApprovedImageMaterialization(
        rights_leaf_id=f"phase2-rights:{source_asset_id}",
        rights_leaf_sha256=_sha256(f"rights:{source_asset_id}".encode()),
        content_sha256=_sha256(payload),
    )
    assert approved.materialization_sha256 is not None
    return SelectionAssetSource(
        source_asset_id=source_asset_id,
        relative_path=path.name,
        rights_leaf_id=approved.rights_leaf_id,
        rights_leaf_sha256=approved.rights_leaf_sha256,
        content_sha256=approved.content_sha256,
        materialization_sha256=approved.materialization_sha256,
        temporary_event=temporary_event,
    )


def _selection_runtime() -> tuple[ImagePreprocessingPolicy, ImageSelectionPolicy]:
    preprocessing = ImagePreprocessingPolicy(
        secure_read=SecureReadPolicy(max_bytes=256 * 1024),
        accepted_formats=("PNG",),
        max_source_width=2_000,
        max_source_height=2_000,
        max_source_pixels=4_000_000,
        output_max_width=256,
        output_max_height=256,
    )
    return preprocessing, build_image_selection_policy(
        sensitivity_id="challenge-pack-production-probe",
        model_weight_sha256="7" * 64,
        preprocessing_policy_sha256=preprocessing.policy_sha256,
        minimum_short_side=40,
        minimum_aspect_ratio_milli=300,
        maximum_aspect_ratio_milli=3_333,
        perceptual_hash_distance=3,
        scene_distance_milli=200,
        temporary_event_rule="EXCLUDE",
    )


def _selection_candidate(
    assets: tuple[SelectionAssetSource, ...],
    *,
    state: ImageMediumState = ImageMediumState.QUALIFIED,
) -> PlaceImageSelectionCandidate:
    return PlaceImageSelectionCandidate(
        place_entity_id=f"place:{'4' * 64}",
        authority_scope=SelectionAuthorityScope.SYNTHETIC_LOCAL,
        input_authority_sha256="2" * 64,
        media_state=state,
        assets=assets,
    )


@dataclass(frozen=True)
class _Encoder(SceneEmbeddingEncoder):
    vectors: dict[str, tuple[float, ...]]
    model_id: str = "google/siglip2-base-patch16-224"
    model_revision: str = "02c35f2c035e0ed4a367fb10a892c1fe2a3f364e"
    model_weight_sha256: str = "7" * 64

    def encode(self, assets: tuple[object, ...]) -> dict[str, tuple[float, ...]]:
        return {
            asset.source_asset_id: self.vectors[asset.source_asset_id]  # type: ignore[attr-defined]
            for asset in assets
        }


def _fused_attributes(h_scores: list[int] | None = None) -> tuple[FusedAttribute, ...]:
    scores = (h_scores or [1_000, 1_000, 1_000, 1_000]) + [1_000] * 8
    rows: list[FusedAttribute] = []
    denominator = 1_000_000_000_000
    for attribute_id, score in zip(tuple(SubattributeId), scores, strict=True):
        axis_id: AxisId = (
            "H"
            if attribute_id.value.startswith("H")
            else ("E" if attribute_id.value.startswith("I") else "R")
        )
        excluded = tuple(
            LaneContributionTrace(
                lane_id=lane_id,
                included=False,
                exclusion_reason="NOT_AVAILABLE",
                score_milli=None,
                base_weight_bp=0,
                fidelity_bp=0,
                quality_bp=0,
                effective_weight_numerator=0,
                normalized_weight_numerator=0,
                normalized_weight_denominator=denominator,
                display_weight_percent=0,
                contribution_numerator=0,
                contribution_denominator=denominator,
                evidence_refs=(),
            )
            for lane_id in (LaneId.ODII, LaneId.IMAGE)
        )
        rows.append(
            FusedAttribute(
                attribute_id=attribute_id,
                axis_id=axis_id,
                score_milli=score,
                lanes=(
                    LaneContributionTrace(
                        lane_id=LaneId.DESCRIPTION,
                        included=True,
                        exclusion_reason=None,
                        score_milli=score,
                        base_weight_bp=10_000,
                        fidelity_bp=10_000,
                        quality_bp=10_000,
                        effective_weight_numerator=denominator,
                        normalized_weight_numerator=denominator,
                        normalized_weight_denominator=denominator,
                        display_weight_percent=100,
                        contribution_numerator=score * denominator,
                        contribution_denominator=denominator,
                        evidence_refs=("a" * 64,),
                    ),
                    excluded[0],
                    excluded[1],
                ),
                fusion_policy_sha256=str(CANONICAL_FUSION_POLICY.policy_sha256),
            )
        )
    return tuple(rows)


def _axes_from_percent(values: dict[str, int]) -> tuple[FusedAxis, FusedAxis, FusedAxis]:
    attributes = tuple(SubattributeId)
    rows = []
    axis_rows: tuple[
        tuple[AxisId, tuple[SubattributeId, SubattributeId, SubattributeId, SubattributeId]],
        ...,
    ] = (
        ("H", (attributes[0], attributes[1], attributes[2], attributes[3])),
        ("E", (attributes[4], attributes[5], attributes[6], attributes[7])),
        ("R", (attributes[8], attributes[9], attributes[10], attributes[11])),
    )
    for axis_id, members in axis_rows:
        score = values[axis_id] * 40
        rows.append(
            FusedAxis(
                axis_id=axis_id,
                member_attribute_ids=members,
                aggregation_rule="HALF_UP_MEAN_EXACTLY_FOUR_V1",
                score_milli=score,
                score_percent=values[axis_id],
                policy_sha256=str(CANONICAL_FUSION_POLICY.policy_sha256),
            )
        )
    return rows[0], rows[1], rows[2]


def _observation_payload() -> dict[str, object]:
    selected = f"selected-image:{'1' * 64}"
    observations = [
        {
            "attribute_id": attribute.value,
            "status": "observed",
            "score_milli": 2_000,
            "uncertainty_bp": 1_000,
            "visible_evidence": [
                {
                    "image_ref": selected,
                    "region": "전경",
                    "caption_ko": "화면에 직접 보이는 합성 단서",
                    "evidence_kind": "VISIBLE_CUE",
                }
            ],
        }
        for attribute in SubattributeId
    ]
    payload: dict[str, object] = {
        "schema_version": "photo-attributes.v2",
        "media_state": "QUALIFIED",
        "representative_manifest_sha256": "b" * 64,
        "selected_image_refs": [selected],
        "observations": observations,
        "candidate_axes": [
            {
                "axis_id": axis,
                "status": "observed",
                "score_milli": 2_000,
                "missing_attribute_ids": [],
                "authority_scope": "CANDIDATE_EVIDENCE_ONLY",
            }
            for axis in ("H", "E", "R")
        ],
        "authority_scope": "CANDIDATE_EVIDENCE_ONLY",
    }
    payload["observation_sha256"] = canonical_sha256(payload)
    return payload


async def _probe_provider(case: dict[str, object]) -> None:
    scenario = str(case["scenario"])
    inputs = cast(dict[str, object], case["inputs"])
    expected = cast(dict[str, object], case["expected"])
    calls = 0

    def handler(_request: httpx.Request) -> httpx.Response:
        nonlocal calls
        calls += 1
        if scenario == "provider_retryable_exhaustion":
            return httpx.Response(503, content=b"synthetic-retryable")
        if scenario == "provider_semantic_no_retry":
            return httpx.Response(200, json=_provider_response(observation="not-json"))
        if scenario == "provider_auth_no_retry":
            hostile = _qualified_payload()
            hostile["release_authority"] = "ADOPT"
            return httpx.Response(200, json=_provider_response(observation=hostile))
        return httpx.Response(200, json={"id": "malformed-envelope"})

    async for adapter in _provider_adapter(handler):
        result = await adapter.extract(
            request=_provider_request(adapter.config),
            images=_provider_images(),
        )

    attempts = result.manifest.attempts
    assert result.manifest.terminal_status is InferenceTerminalStatus.ANALYSIS_FAILED
    assert result.observation is None
    assert calls == cast(int, inputs["attempt_count"])
    assert len(attempts) - 1 == cast(int, expected["retry_count"])
    if scenario == "provider_retryable_exhaustion":
        assert [attempt.outcome for attempt in attempts] == [AttemptOutcome.HTTP_ERROR] * 3
        assert [attempt.retry_disposition.value for attempt in attempts] == [
            "RETRY",
            "RETRY",
            "DO_NOT_RETRY",
        ]
        assert all(attempt.http_status == 503 for attempt in attempts)
    else:
        assert attempts[0].retry_disposition.value == "DO_NOT_RETRY"
        expected_outcome = {
            "provider_auth_no_retry": AttemptOutcome.AUTHORITY_INVALID,
            "provider_semantic_no_retry": AttemptOutcome.SEMANTIC_INVALID,
            "provider_schema_rejection": AttemptOutcome.RESPONSE_ENVELOPE_INVALID,
        }[scenario]
        assert attempts[0].outcome is expected_outcome
        assert (
            attempts[0].error_code
            == {
                "provider_auth_no_retry": "PROVIDER_AUTHORITY_REJECTED",
                "provider_semantic_no_retry": "OBSERVATION_SCHEMA_INVALID",
                "provider_schema_rejection": "RESPONSE_ENVELOPE_INVALID",
            }[scenario]
        )


def _probe_coherent_fusion_rewrite(root: Path) -> None:
    payloads = _authority_payloads()
    genuine_names = _write_authority_bundle(root / "genuine", payloads)
    genuine = resolve_authoritative_profile_release_candidate_v2(
        request=_authority_request(payloads),
        paths=ProfileReleaseAuthorityPathsV2(root=root / "genuine", **genuine_names),
    )
    assert genuine.state == "BUILT_UNAPPROVED"

    request = _authority_request(payloads)
    lane_member = payloads["lane_baseline"]["members"][0]
    forged_payload = deepcopy(lane_member["baseline"])
    forged_payload.pop("member_sha256")
    forged_payload["description"]["meaningful_character_count"] = 499
    forged_baseline = Phase3LaneBaselineMember.model_validate(forged_payload)
    predecessor = type(_fusion_predecessor_profile()).model_validate(
        payloads["predecessor"]["profiles"][0]
    )
    observation = ImageObservationV2.model_validate(
        payloads["prediction"]["members"][0]["observation"]
    )
    forged_profile = build_fused_profile(
        forged_baseline,
        observation,
        predecessor_profile=predecessor,
    ).model_dump(mode="json")
    forged_profile["baseline_member_sha256"] = lane_member["baseline_member_sha256"]
    forged_profile["profile_fusion_sha256"] = canonical_sha256(
        {key: value for key, value in forged_profile.items() if key != "profile_fusion_sha256"}
    )
    profile_member = payloads["profiles"]["members"][0]
    profile_member["fused_profile"] = forged_profile
    profile_member.pop("member_sha256")
    payloads["profiles"]["members"][0] = ProfileReleaseCohortMemberV2.model_validate(
        profile_member
    ).model_dump(mode="json")
    _self_hash_authority(payloads["profiles"])
    request["profiles_manifest_sha256"] = payloads["profiles"]["manifest_sha256"]

    forged_names = _write_authority_bundle(root / "forged", payloads)
    with pytest.raises(ProfileReleaseAuthorityError):
        resolve_authoritative_profile_release_candidate_v2(
            request=request,
            paths=ProfileReleaseAuthorityPathsV2(root=root / "forged", **forged_names),
        )


def _probe_demo_parser(
    case: dict[str, object], monkeypatch: pytest.MonkeyPatch, root: Path
) -> None:
    from itda.cli import run_phase4_demo

    def forbid_read(*_args: object, **_kwargs: object) -> bytes:
        raise AssertionError("caller-selected demo authority reached a filesystem read")

    monkeypatch.setattr(run_phase4_demo, "_secure_read_under", forbid_read)
    inputs = cast(dict[str, object], case["inputs"])
    assert cast(list[object], inputs["caller_selected_fields"]) == [
        "catalog",
        "sqlite",
        "snapshot",
        "optional_media",
    ]
    with pytest.raises(SystemExit) as rejected:
        run_phase4_demo.main(
            [
                "materialize",
                "--catalog-audit",
                str(root / "forged-catalog.json"),
                "--dev-sqlite",
                str(root / "forged.sqlite3"),
                "--snapshot-root",
                str(root / "forged-snapshots"),
                "--optional-media",
                str(root / "forged-media.json"),
                "--artifact-root",
                str(root / "out"),
                "--receipt-output",
                str(root / "receipt.json"),
            ]
        )
    assert rejected.value.code == 2


def _conditional_provisional() -> ProvisionalBenchmarkReport:
    def conditional_case(case_ref: str, label_value: int) -> BenchmarkCase:
        labels = {attribute: label_value for attribute in ATTRIBUTE_IDS}
        baseline = dict(labels)
        baseline["H1"] -= 500
        candidate = BenchmarkScoreVector.from_mapping(labels)
        return BenchmarkCase(
            case_ref=case_ref,
            image_medium_state=ImageMediumState.QUALIFIED,
            baseline_scores=BenchmarkScoreVector.from_mapping(baseline),
            candidate_repeats=tuple(
                BenchmarkRepeat.build(
                    repeat_index=index,
                    request_identity_sha256=hashlib.sha256(
                        f"request:{case_ref}:{index}".encode()
                    ).hexdigest(),
                    prediction_batch_sha256="7" * 64,
                    terminal_status="VALID",
                    schema_compliant=True,
                    scores=candidate,
                    raw_prediction_ref=hashlib.sha256(
                        f"prediction:{case_ref}:{index}".encode()
                    ).hexdigest(),
                )
                for index in (1, 2, 3)
            ),
            dev_label_scores=BenchmarkScoreVector.from_mapping(labels),
            baseline_display_label="mixed-experience",
            candidate_display_label="mixed-experience",
            dev_display_label="mixed-experience",
            confidence_percent=50,
            visible_claim_count=1,
            automatic_supported_claim_count=1,
            named_failures=(),
        )

    inventory = (_benchmark_inventory("conditional"),)
    cases = tuple(conditional_case(f"case-{index:02d}", 1_000 + index * 40) for index in range(24))
    return build_provisional_report(
        experiment=_benchmark_experiment(
            evaluation_scope="DEV_24_PROTECTED",
            case_refs=tuple(case.case_ref for case in cases),
            cases=cases,
            review_inventory=inventory,
        ),
        cases=cases,
        review_inventory=inventory,
        sensitivity=(),
        generated_at=BENCHMARK_NOW,
    )


def _probe_finalizer(case: dict[str, object]) -> None:
    scenario = str(case["scenario"])
    expected_fixture = cast(dict[str, object], case["expected"])
    if scenario in {"provisional_review_final", "conditional_adoption"}:
        if scenario == "conditional_adoption":
            provisional = _conditional_provisional()
        else:
            inventory = (_benchmark_inventory("safe"),)
            cases = tuple(
                _benchmark_case(
                    f"case-{index:02d}",
                    ImageMediumState.QUALIFIED,
                    baseline=500 + index * 10,
                    candidate=1_000 + index * 10,
                    label=1_000 + index * 10,
                )
                for index in range(24)
            )
            provisional = build_provisional_report(
                experiment=_benchmark_experiment(
                    evaluation_scope="DEV_24_PROTECTED",
                    case_refs=tuple(case.case_ref for case in cases),
                    cases=cases,
                    review_inventory=inventory,
                ),
                cases=cases,
                review_inventory=inventory,
                sensitivity=(),
                generated_at=BENCHMARK_NOW,
            )
        pending = finalize_benchmark(
            provisional=provisional,
            selected_config_sha256=provisional.experiment.experiment_sha256,
            finalized_at=BENCHMARK_NOW,
        )
        assert pending.state is BenchmarkReportState.PROVISIONAL_PENDING_HUMAN_REVIEW
        review = _benchmark_review(provisional, provisional.review_inventory)
        decision = finalize_benchmark(
            provisional=provisional,
            selected_config_sha256=provisional.experiment.experiment_sha256,
            human_review=review,
            finalized_at=BENCHMARK_NOW,
        )
        expected = (
            BenchmarkReportState.CONDITIONAL_ADOPT
            if scenario == "conditional_adoption"
            else BenchmarkReportState.ADOPT
        )
        assert decision.state is expected
        assert decision.state.value == expected_fixture["terminal_state"]
        assert decision.provisional_report_sha256 == provisional.provisional_report_sha256
        assert decision.selected_config_sha256 == provisional.experiment.experiment_sha256
        assert decision.dev_authority_sha256 == provisional.experiment.dev_authority_sha256
        assert decision.locked_fusion_policy_sha256 == CANONICAL_FUSION_POLICY.policy_sha256
        assert decision.human_review_manifest_sha256 == review.review_manifest_sha256
        assert decision.zero_image_fallback_sha256 is None
        assert decision.raw_artifact_refs == provisional.raw_prediction_refs
        assert decision.image_contribution_count == len(provisional.review_inventory)
        forged_review = review.model_copy(update={"selection_manifest_sha256": "f" * 64})
        with pytest.raises(ValueError, match="exact provisional inventory"):
            finalize_benchmark(
                provisional=provisional,
                selected_config_sha256=provisional.experiment.experiment_sha256,
                human_review=forged_review,
                finalized_at=BENCHMARK_NOW,
            )
        return

    state = (
        ImageMediumState.ANALYSIS_FAILED
        if scenario == "image_rejected_text_odii_only"
        else ImageMediumState.MISSING
    )
    outcome = (
        BenchmarkReportState.IMAGE_REJECTED_TEXT_ODII_ONLY
        if state is ImageMediumState.ANALYSIS_FAILED
        else BenchmarkReportState.NO_IMAGE_TEXT_ODII_ONLY
    )
    provisional = build_provisional_report(
        experiment=_benchmark_experiment(),
        cases=(_benchmark_case(f"case-{scenario}", state, candidate=None),),
        review_inventory=(),
        sensitivity=(),
        generated_at=BENCHMARK_NOW,
    )
    fallback = ZeroImageFallbackProof.build(
        outcome=outcome,
        source_media_state=state,
        provisional_report_sha256=provisional.provisional_report_sha256,
        baseline_sha256=provisional.experiment.baseline_sha256,
    )
    decision = finalize_benchmark(
        provisional=provisional,
        selected_config_sha256=provisional.experiment.experiment_sha256,
        zero_image_fallback=fallback,
        finalized_at=BENCHMARK_NOW,
    )
    assert decision.state is outcome
    assert decision.state.value == expected_fixture["terminal_state"]
    assert decision.provisional_report_sha256 == provisional.provisional_report_sha256
    assert decision.selected_config_sha256 == provisional.experiment.experiment_sha256
    assert decision.locked_fusion_policy_sha256 == CANONICAL_FUSION_POLICY.policy_sha256
    assert decision.human_review_manifest_sha256 is None
    assert decision.zero_image_fallback_sha256 == fallback.proof_sha256
    assert decision.image_contribution_count == cast(
        int, cast(dict[str, object], case["inputs"])["image_contribution_count"]
    )
    assert decision.adopted_attributes == ()
    assert decision.inherited_baseline_attributes == ATTRIBUTE_IDS
    forged_fallback = fallback.model_copy(update={"baseline_sha256": "f" * 64})
    with pytest.raises(ValueError, match="exact provisional baseline"):
        finalize_benchmark(
            provisional=provisional,
            selected_config_sha256=provisional.experiment.experiment_sha256,
            zero_image_fallback=forged_fallback,
            finalized_at=BENCHMARK_NOW,
        )


def _probe_selection(case: dict[str, object], root: Path) -> None:
    preprocessing, policy = _selection_runtime()
    scenario = str(case["scenario"])
    base = _png_bytes()
    if scenario == "exact_duplicate":
        assets = tuple(
            _selection_source(root, source_asset_id=name, payload=base) for name in ("a", "b")
        )
    elif scenario == "perceptual_duplicate":
        image = Image.open(BytesIO(base))
        alternate = BytesIO()
        image.save(alternate, format="PNG", optimize=True)
        image.close()
        assets = (
            _selection_source(root, source_asset_id="a", payload=base),
            _selection_source(root, source_asset_id="b", payload=alternate.getvalue()),
        )
    elif scenario == "temporary_event":
        assets = (
            _selection_source(root, source_asset_id="event", payload=base, temporary_event=True),
        )
    elif scenario == "low_quality":
        assets = (
            _selection_source(root, source_asset_id="low", payload=_png_bytes(size=(20, 20))),
        )
    else:
        inputs = cast(dict[str, object], case["inputs"])
        names = tuple(str(item) for item in cast(list[object], inputs["asset_order"]))
        assets = tuple(
            _selection_source(
                root,
                source_asset_id=name,
                payload=_png_bytes(color=(40 + index * 50, 80, 120)),
            )
            for index, name in enumerate(names)
        )
    descriptor = os.open(root, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
    try:
        if scenario.startswith("selection_permutation"):
            manifest = select_representative_images(
                root_fd=descriptor,
                candidate=_selection_candidate(assets),
                policy=policy,
                encoder=_Encoder(
                    {
                        asset.source_asset_id: (float(index + 1), 1.0)
                        for index, asset in enumerate(assets)
                    }
                ),
                preprocessing_policy=preprocessing,
            )
            assert manifest.manifest_sha256
            return
        result = gate_selection_assets(
            root_fd=descriptor,
            candidate=_selection_candidate(assets),
            policy=policy,
            preprocessing_policy=preprocessing,
        )
    finally:
        os.close(descriptor)
    reasons = {decision.decision_code for decision in result.decisions}
    expected_reason = {
        "exact_duplicate": AssetDecisionCode.EXACT_DUPLICATE,
        "perceptual_duplicate": AssetDecisionCode.PERCEPTUAL_DUPLICATE,
        "temporary_event": AssetDecisionCode.TEMPORARY_EVENT_EXCLUDED,
        "low_quality": AssetDecisionCode.LOW_QUALITY,
    }[scenario]
    assert expected_reason in reasons


def _probe_filesystem(scenario: str, root: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    payload = _png_bytes()
    target = root / "target.png"
    target.write_bytes(payload)
    target.chmod(0o600)
    path = target
    if scenario == "symlink_attack":
        path = root / "alias.png"
        path.symlink_to(target.name)
    elif scenario == "hardlink_attack":
        path = root / "hardlink.png"
        os.link(target, path)
    expected_payload = payload if scenario != "path_substitution_attack" else b"substitute"
    approved = ApprovedImageMaterialization(
        rights_leaf_id="phase2-rights:challenge",
        rights_leaf_sha256="b" * 64,
        content_sha256=_sha256(expected_payload),
    )
    candidate = RightsBoundImage(
        relative_path=path.name,
        rights_leaf_id=approved.rights_leaf_id,
        rights_leaf_sha256=approved.rights_leaf_sha256,
        content_sha256=approved.content_sha256,
    )
    if scenario == "mid_read_toctou_attack":
        original_read = os.read
        mutated = False

        def mutate_after_read(descriptor: int, size: int) -> bytes:
            nonlocal mutated
            chunk = original_read(descriptor, size)
            if chunk and not mutated:
                mutated = True
                target.write_bytes(payload + b"changed")
            return chunk

        monkeypatch.setattr("itda.analysis.image.secure_read.os.read", mutate_after_read)
    descriptor = os.open(root, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
    try:
        with pytest.raises(SecureImageReadError):
            read_approved_image(
                root_fd=descriptor,
                candidate=candidate,
                approved=approved,
                policy=SecureReadPolicy(max_bytes=256 * 1024),
            )
    finally:
        os.close(descriptor)


@pytest.mark.parametrize("case", _cases(_load_pack()), ids=lambda case: str(case["scenario"]))
@pytest.mark.asyncio
async def test_every_challenge_case_executes_its_production_guard(
    case: dict[str, object], tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    category = str(case["category"])
    scenario = str(case["scenario"])
    inputs = case["inputs"]
    assert isinstance(inputs, dict)
    expected = case["expected"]
    assert isinstance(expected, dict)

    if category == "media_state":
        state = ImageMediumState(str(case["media_state"]))
        preprocessing, selection_policy = _selection_runtime()
        result = gate_selection_assets(
            root_fd=-1,
            candidate=_selection_candidate((), state=state),
            policy=selection_policy,
            preprocessing_policy=preprocessing,
        )
        assert result.media_state is state
        assert result.survivors == ()
    elif category == "fidelity_boundary":
        value = int(inputs["value"])
        actual = {
            "description_characters": lambda: description_fidelity_bp(value),
            "odii_characters": lambda: odii_fidelity_bp(value, directly_linked=value > 0),
            "selected_image_count": lambda: image_fidelity_bp(value),
        }[str(inputs["boundary"])]()
        assert actual == int(expected["fidelity_bp"])
    elif category == "agreement_boundary":
        confidence = compute_profile_confidence(_fused_attributes())
        assert all(axis.agreement_bp is None for axis in confidence.axes)
    elif category == "selection_adversary":
        _probe_selection(case, tmp_path)
    elif category == "visible_evidence":
        payload = _observation_payload()
        observations = payload["observations"]
        assert isinstance(observations, list)
        if scenario == "prompt_injection":
            payload["release_authority"] = "ADOPT"
        elif scenario == "non_visible_fact":
            observations[0]["status"] = "not_observable"
        else:
            observations[0]["visible_evidence"][0]["image_ref"] = f"selected-image:{'2' * 64}"
        payload["observation_sha256"] = canonical_sha256(
            {key: value for key, value in payload.items() if key != "observation_sha256"}
        )
        with pytest.raises(ValidationError):
            ImageObservationV2.model_validate(payload)
    elif category == "provider_failure":
        await _probe_provider(case)
    elif category == "axis_derivation":
        h_values = [
            cast(int, value) for value in cast(list[object], inputs["attribute_scores_milli"])
        ]
        axes = derive_final_axes(_fused_attributes(h_values))
        if "claimed_axis_score_milli" in inputs:
            forged = list(axes)
            forged[0] = forged[0].model_copy(
                update={"score_milli": cast(int, inputs["claimed_axis_score_milli"])}
            )
            with pytest.raises(ValueError, match="axis claim drifted"):
                derive_final_axes(
                    _fused_attributes(h_values),
                    claimed_axes=(forged[0], forged[1], forged[2]),
                )
        else:
            assert axes[0].score_milli == cast(int, expected["axis_score_milli"])
    elif category == "fusion_policy":
        sensitivity = FusionPolicyConfig.model_validate(
            {
                **CANONICAL_FUSION_POLICY.model_dump(mode="json"),
                "mode": "SENSITIVITY_ONLY",
                "release_eligible": False,
                "policy_sha256": None,
            }
        )
        with pytest.raises(ValueError, match="not release eligible"):
            require_release_eligible_policy(sensitivity)
    elif category == "confidence_boundary":
        publication, mismatch = classify_publication(cast(int, inputs["value"]))
        assert publication.value == expected["publication_state"]
        assert mismatch is expected["mismatch_warning_authorized"]
    elif category == "display_type_boundary":
        axis_scores = cast(dict[str, object], inputs["axis_scores"])
        display_values = {str(key): cast(int, value) for key, value in axis_scores.items()}
        label = derive_display_label(_axes_from_percent(display_values))
        assert label.label_ko == expected["display_type"]
    elif category == "review_transition":
        _probe_finalizer(case)
    elif category == "filesystem_attack":
        _probe_filesystem(scenario, tmp_path, monkeypatch)
    elif category == "fusion_authority":
        _probe_coherent_fusion_rewrite(tmp_path)
    elif category == "demo_authority":
        _probe_demo_parser(case, monkeypatch, tmp_path)
    elif category == "release_lineage":
        assert scenario in REPOSITORY_SCENARIOS
    else:
        raise AssertionError(f"unhandled production challenge category: {category}")
