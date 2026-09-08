from __future__ import annotations

import asyncio
import fcntl
import json
import os
import shutil
import stat
from collections.abc import Callable, Iterator, Mapping
from contextlib import contextmanager
from copy import deepcopy
from datetime import UTC, datetime
from inspect import signature
from pathlib import Path

import httpx
import pytest

from itda.contracts.demo_profile_materialization import seal_demo_contract
from itda.contracts.hard_duplicate_adjudication import (
    HARD_DUPLICATE_ADJUDICATION_PATH,
    HARD_DUPLICATE_ADJUDICATION_SHA256,
    HardDuplicateAdjudication,
    load_hard_duplicate_adjudication,
)
from itda.domain.canonical import canonical_json_bytes, canonical_sha256
from itda.pipeline.demo_profile_materialization import (
    DemoProfileMaterializationResult,
    _finalize_result,
    _replay_payload,
    build_synthetic_replay_sources,
    publish_demo_profile_generation,
)


@contextmanager
def _patch_nvidia_http_client(
    client_factory: Callable[..., httpx.AsyncClient],
) -> Iterator[None]:
    """Patch the private HTTP constructor only for one synchronous test attempt."""

    import itda.providers.nvidia_minimax_profile as provider

    with pytest.MonkeyPatch.context() as monkeypatch:
        monkeypatch.setattr(provider, "_new_httpx_async_client", client_factory)
        yield


def _write_private(path: Path, payload: bytes) -> None:
    path.write_bytes(payload)
    path.chmod(0o600)


def _nvidia_mock_client_factory(
    payload: dict[str, object],
) -> Callable[..., httpx.AsyncClient]:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json=payload, request=request)

    def factory(**kwargs: object) -> httpx.AsyncClient:
        return httpx.AsyncClient(
            transport=httpx.MockTransport(handler),
            headers=kwargs["headers"],  # type: ignore[arg-type]
            timeout=kwargs["timeout"],  # type: ignore[arg-type]
        )

    return factory


def _nvidia_test_journal(root: Path):
    from itda.contracts.demo_profile_materialization import NVIDIA_AUTHORITY_SHA256
    from itda.pipeline.demo_profile_materialization import DurableNvidiaJournal

    return DurableNvidiaJournal(
        root=root / "nvidia-journal",
        authority_receipt={
            "schema_version": "itda.phase5-nvidia-authority.v3",
            "authority_sha256": NVIDIA_AUTHORITY_SHA256,
        },
    )


def _canonical_dev_fixture() -> dict[str, object]:
    fixture = json.loads(
        (
            Path(__file__).resolve().parents[3]
            / "fixtures/synthetic/phase5/provider-profile-replay.json"
        ).read_text(encoding="utf-8")
    )
    fixture["place_ids"] = list(load_hard_duplicate_adjudication().group_id_by_place)
    return fixture


def _live_generation(root: Path) -> tuple[Path, tuple[str, ...]]:
    from itda.providers.zhipu_glm5v_profile import ZhipuGlm5vProfileAdapter

    fixture = _canonical_dev_fixture()
    bundles = build_synthetic_replay_sources(fixture)
    template = fixture["response_template"]
    assert isinstance(template, dict)
    replay_adapter = ZhipuGlm5vProfileAdapter(secret="synthetic-replay-noncredential")
    raw_payloads: list[dict[str, object]] = []
    results = []
    for index, bundle in enumerate(bundles):
        payload = deepcopy(_replay_payload(bundle=bundle, template=template))
        content = payload["content"]
        assert isinstance(content, dict)
        axis_scores = content["axis_scores"]
        assert isinstance(axis_scores, dict)
        axis_scores["H"] = 60 + index
        axis_scores["E"] = 83 - index
        axis_scores["R"] = 50 + ((index * 7) % 24)
        raw_payloads.append(payload)
        results.append(
            replay_adapter.validate_replay_response(
                place_id=bundle.place_id,
                payload=payload,
            )
        )
    result = _finalize_result(
        mode="replay",
        results=tuple(results),
        reported_cost_micro_usd=0,
    )
    root.mkdir(parents=True, mode=0o700)
    root.chmod(0o700)
    _write_private(
        root / "source-bundles.json",
        canonical_json_bytes([bundle.model_dump(mode="json") for bundle in bundles]),
    )

    generation_fields = {
        "mode": "live",
        "profile_sha256": [profile.profile_sha256 for profile in result.profiles],
        "attempt_sha256": [attempt.attempt_sha256 for attempt in result.attempts],
        "pricing_snapshot_sha256": result.receipt.pricing_snapshot_sha256,
    }
    receipt_fields = result.receipt.model_dump(mode="json", exclude={"receipt_sha256"})
    receipt_fields.update(
        {
            "status": "COMPLETE_UNACTIVATED",
            "committed_cost_micro_usd": sum(
                attempt.committed_micro_usd for attempt in result.attempts
            ),
            "generation_sha256": canonical_sha256(generation_fields),
        }
    )
    receipt = seal_demo_contract(receipt_fields, digest_field="receipt_sha256")
    generation = root / "generations" / str(receipt["generation_sha256"])
    generation.mkdir(parents=True, mode=0o700)
    generation.chmod(0o700)
    _write_private(
        generation / "profiles.json",
        canonical_json_bytes([profile.model_dump(mode="json") for profile in result.profiles]),
    )
    _write_private(
        generation / "attempts.json",
        canonical_json_bytes([attempt.model_dump(mode="json") for attempt in result.attempts]),
    )
    _write_private(generation / "receipt.json", canonical_json_bytes(receipt))
    for payload, attempt in zip(raw_payloads, result.attempts, strict=True):
        raw = canonical_json_bytes(payload)
        assert canonical_sha256(json.loads(raw)) == attempt.response_sha256
        _write_private(generation / f"raw-{attempt.attempt_sha256}.json", raw)
    return generation, tuple(bundle.place_id for bundle in bundles)


def _coding_live_generation(root: Path) -> tuple[Path, tuple[str, ...]]:
    from itda.contracts.demo_profile_materialization import (
        CODING_PLAN_AUTHORITY_SHA256,
        CODING_PLAN_BASE_URL,
        CODING_PLAN_ENTITLEMENT_EVIDENCE_SHA256,
        CodingPlanProfileMaterializationConfig,
    )
    from itda.providers.zhipu_glm5v_profile import (
        CodingPlanAttemptLedger,
        ZhipuGlm5vProfileAdapter,
    )

    fixture = _canonical_dev_fixture()
    bundles = build_synthetic_replay_sources(fixture)
    config = CodingPlanProfileMaterializationConfig.for_authorized_base(
        base_url=CODING_PLAN_BASE_URL,
        entitlement_evidence_sha256=CODING_PLAN_ENTITLEMENT_EVIDENCE_SHA256,
    )
    adapter = ZhipuGlm5vProfileAdapter(
        secret="synthetic-coding-plan-noncredential",
        config=config,
        coding_plan_ledger=CodingPlanAttemptLedger(),
    )
    template = fixture["response_template"]
    results = []
    raw_responses = []
    for index, bundle in enumerate(bundles):
        payload = deepcopy(_replay_payload(bundle=bundle, template=template, config=config))
        content = payload["content"]
        assert isinstance(content, dict)
        axis_scores = content["axis_scores"]
        assert isinstance(axis_scores, dict)
        axis_scores["H"] = 60 + index
        axis_scores["E"] = 83 - index
        axis_scores["R"] = 50 + ((index * 7) % 24)
        result = adapter.validate_replay_response(
            place_id=bundle.place_id,
            payload=payload,
        )
        results.append(result)
        raw = canonical_json_bytes(payload)
        assert result.attempt.response_sha256 == canonical_sha256(json.loads(raw))
        raw_responses.append((result.attempt.attempt_sha256, raw))
    finalized = _finalize_result(
        mode="live",
        results=tuple(results),
        reported_cost_micro_usd=0,
        coding_plan_authority_sha256=CODING_PLAN_AUTHORITY_SHA256,
        config=config,
    )
    complete = DemoProfileMaterializationResult(
        mode=finalized.mode,
        profiles=finalized.profiles,
        attempts=finalized.attempts,
        receipt=finalized.receipt,
        raw_responses=tuple(raw_responses),
    )
    root.mkdir(parents=True, mode=0o700)
    root.chmod(0o700)
    _write_private(
        root / "source-bundles.json",
        canonical_json_bytes([bundle.model_dump(mode="json") for bundle in bundles]),
    )
    generation = publish_demo_profile_generation(
        complete,
        output_root=root / "generations",
    )
    return generation, tuple(bundle.place_id for bundle in bundles)


def _nvidia_live_generation(
    root: Path,
    *,
    swap_axis_justifications: bool = False,
) -> tuple[Path, tuple[str, ...]]:
    from itda.contracts.demo_profile_materialization import (
        NVIDIA_JSON_END_SENTINEL,
        NVIDIA_JSON_START_SENTINEL,
        NvidiaMinimaxProfileMaterializationConfig,
    )
    from itda.pipeline.demo_profile_materialization import (
        _finalize_nvidia_result,
        _live_nvidia_request_bytes,
        _nvidia_lineage_for,
    )
    from itda.providers.nvidia_minimax_profile import (
        NvidiaAttemptLedger,
        NvidiaMinimaxProfileAdapter,
    )

    fixture = _canonical_dev_fixture()
    bundles = build_synthetic_replay_sources(fixture)
    config = NvidiaMinimaxProfileMaterializationConfig()
    ledger = NvidiaAttemptLedger()
    template = fixture["response_template"]
    content = {
        "axis_scores": template["axis_scores"],
        "subattributes": template["subattributes"],
        "mismatch_traits": template["mismatch_traits"],
        "evidence_justifications": {
            key: [
                "odii-transcript-01"
                if key in {"E", "I1", "I2", "I3", "I4", "M2"}
                else "tour-description-01"
            ]
            for key in (
                "H",
                "E",
                "R",
                *(f"{prefix}{index}" for prefix in ("H", "I", "R") for index in range(1, 5)),
                *(f"M{index}" for index in range(1, 7)),
            )
        },
        "evidence_ids": ["tour-description-01", "odii-transcript-01"],
        "confidence": template["confidence"],
        "publishable": template["publishable"],
    }
    if swap_axis_justifications:
        justifications = content["evidence_justifications"]
        assert isinstance(justifications, dict)
        justifications["H"], justifications["E"] = justifications["E"], justifications["H"]
    results = []
    raw_responses = []
    journal = _nvidia_test_journal(root)
    journal.record_live_start()
    for index, bundle in enumerate(bundles):
        varied = json.loads(json.dumps(content))
        varied["axis_scores"]["H"] = 60 + index
        varied["axis_scores"]["E"] = 83 - index
        varied["axis_scores"]["R"] = 50 + ((index * 7) % 24)
        serialized = json.dumps(varied, ensure_ascii=False, separators=(",", ":"))
        payload = {
            "model": config.model,
            "choices": [
                {
                    "finish_reason": "stop",
                    "message": {
                        "role": "assistant",
                        "content": (
                            f"{NVIDIA_JSON_START_SENTINEL}{serialized}{NVIDIA_JSON_END_SENTINEL}"
                        ),
                    },
                }
            ],
            "usage": {
                "prompt_tokens": 1_000,
                "completion_tokens": 100,
                "total_tokens": 1_100,
            },
        }
        request_body = _live_nvidia_request_bytes(bundle, config)
        adapter = NvidiaMinimaxProfileAdapter(
            secret="synthetic-nvidia-noncredential",
            config=config,
            ledger=ledger,
        )
        with _patch_nvidia_http_client(_nvidia_mock_client_factory(payload)):
            result = asyncio.run(
                journal._execute_adapter_attempt(
                    adapter=adapter,
                    place_id=bundle.place_id,
                    request_body=request_body,
                    lineage=_nvidia_lineage_for(bundle, config),
                )
            )
        results.append(result)
        assert result.raw_response is not None
        raw_responses.append((result.attempt.attempt_sha256, result.raw_response))
        journal.record_attempt(
            result,
            started_at=datetime.now(UTC),
            completed_at=datetime.now(UTC),
        )
    results_tuple = tuple(results)
    finalized = _finalize_nvidia_result(
        bundles=bundles,
        attempts=results_tuple,
        terminal=results_tuple,
        config=config,
        journal=journal,
    )
    complete = DemoProfileMaterializationResult(
        mode=finalized.mode,
        profiles=finalized.profiles,
        attempts=finalized.attempts,
        receipt=finalized.receipt,
        raw_responses=tuple(raw_responses),
    )
    root.mkdir(parents=True, mode=0o700, exist_ok=True)
    root.chmod(0o700)
    _write_private(
        root / "source-bundles.json",
        canonical_json_bytes([bundle.model_dump(mode="json") for bundle in bundles]),
    )
    generation = publish_demo_profile_generation(
        complete,
        output_root=root / "generations",
    )
    return generation, tuple(bundle.place_id for bundle in bundles)


def _nvidia_v5_live_generation(root: Path) -> tuple[Path, tuple[str, ...]]:
    """Build a synthetic eligible V5 generation without provider or private evidence."""

    from itda.contracts.demo_profile_materialization import (
        NVIDIA_JSON_END_SENTINEL,
        NVIDIA_JSON_START_SENTINEL,
        NVIDIA_V5_TWO_PROBE_RESUME_AUTHORITY_SHA256,
        NVIDIA_V5_TWO_PROBE_RESUME_BINDINGS,
        NvidiaMinimaxProfileMaterializationConfig,
    )
    from itda.pipeline.demo_profile_materialization import (
        NvidiaV5TwoProbeResumePlan,
        _finalize_nvidia_result,
        _live_nvidia_request_bytes,
        _nvidia_lineage_for,
        _nvidia_v5_lineage_for,
        build_nvidia_v5_request_bytes,
    )
    from itda.providers.nvidia_minimax_profile import (
        NvidiaAttemptLedger,
        NvidiaMinimaxProfileAdapter,
    )

    fixture = _canonical_dev_fixture()
    bundles = build_synthetic_replay_sources(fixture)
    config = NvidiaMinimaxProfileMaterializationConfig()
    ledger = NvidiaAttemptLedger()
    journal = _nvidia_test_journal(root)
    journal.record_live_start()
    template = fixture["response_template"]
    content = {
        "axis_scores": template["axis_scores"],
        "subattributes": template["subattributes"],
        "mismatch_traits": template["mismatch_traits"],
        "evidence_justifications": {
            key: ["tour-description-01"]
            for key in (
                "H",
                "E",
                "R",
                *(f"{prefix}{index}" for prefix in ("H", "I", "R") for index in range(1, 5)),
                *(f"M{index}" for index in range(1, 7)),
            )
        },
        "evidence_ids": ["tour-description-01", "odii-transcript-01"],
        "confidence": 69,
        "publishable": True,
    }

    def response_payload(profile: dict[str, object]) -> dict[str, object]:
        serialized = json.dumps(profile, ensure_ascii=False, separators=(",", ":"))
        return {
            "model": config.model,
            "choices": [
                {
                    "finish_reason": "stop",
                    "message": {
                        "role": "assistant",
                        "content": (
                            f"{NVIDIA_JSON_START_SENTINEL}{serialized}{NVIDIA_JSON_END_SENTINEL}"
                        ),
                    },
                }
            ],
            "usage": {
                "prompt_tokens": 1_000,
                "completion_tokens": 100,
                "total_tokens": 1_100,
            },
        }

    def live_result(
        *,
        place_id: str,
        payload: dict[str, object],
        request_body: bytes,
        lineage: Mapping[str, object],
    ):
        adapter = NvidiaMinimaxProfileAdapter(
            secret="synthetic-nvidia-noncredential",
            config=config,
            ledger=ledger,
        )
        with _patch_nvidia_http_client(_nvidia_mock_client_factory(payload)):
            result = asyncio.run(
                journal._execute_adapter_attempt(
                    adapter=adapter,
                    place_id=place_id,
                    request_body=request_body,
                    lineage=lineage,
                )
            )
        assert result.raw_response is not None
        journal.record_attempt(
            result,
            started_at=datetime.now(UTC),
            completed_at=datetime.now(UTC),
        )
        return result

    predecessor_results = []
    raw_payloads: list[tuple[object, bytes]] = []
    for _ in range(2):
        payload = response_payload(deepcopy(content))
        result = live_result(
            place_id=bundles[0].place_id,
            payload=payload,
            request_body=_live_nvidia_request_bytes(bundles[0], config),
            lineage=_nvidia_lineage_for(bundles[0], config),
        )
        assert result.candidate is None
        predecessor_results.append(result)
        raw_payloads.append((result, result.raw_response))

    terminal = []
    for index, bundle in enumerate(bundles):
        varied = deepcopy(content)
        varied["confidence"] = 70
        varied["axis_scores"] = {
            "H": 60 + index,
            "E": 83 - index,
            "R": 50 + ((index * 7) % 24),
        }
        payload = response_payload(varied)
        result = live_result(
            place_id=bundle.place_id,
            payload=payload,
            request_body=build_nvidia_v5_request_bytes(bundle, config),
            lineage=_nvidia_v5_lineage_for(bundle, config),
        )
        assert result.candidate is not None
        terminal.append(result)
        raw_payloads.append((result, result.raw_response))

    plan = NvidiaV5TwoProbeResumePlan(
        replayed_profiles=(),
        predecessor_attempts=tuple(result.attempt for result in predecessor_results),
        predecessor_raw_responses=tuple(
            (result.attempt.attempt_sha256, payload) for result, payload in raw_payloads[:2]
        ),
        remaining_place_ids=tuple(bundle.place_id for bundle in bundles),
        attempt1_file_sha256={},
        attempt1_manifest_sha256=str(
            NVIDIA_V5_TWO_PROBE_RESUME_BINDINGS["attempt1_root_manifest_sha256"]
        ),
        attempt1_failure_file_sha256={},
        attempt2_file_sha256={},
        attempt2_manifest_sha256=str(
            NVIDIA_V5_TWO_PROBE_RESUME_BINDINGS["attempt2_root_manifest_sha256"]
        ),
        attempt2_failure_file_sha256={},
        v4_request_sha256_by_place={},
        v5_request_sha256_by_place={},
        schema_example_sha256_by_place={},
    )
    all_results = (*predecessor_results, *terminal)
    finalized = _finalize_nvidia_result(
        bundles=bundles,
        attempts=all_results,
        terminal=terminal,
        config=config,
        resume_plan=plan,
        resume_authority_sha256=NVIDIA_V5_TWO_PROBE_RESUME_AUTHORITY_SHA256,
        journal=journal,
    )
    complete = DemoProfileMaterializationResult(
        mode=finalized.mode,
        profiles=finalized.profiles,
        attempts=finalized.attempts,
        receipt=finalized.receipt,
        raw_responses=tuple(
            (result.attempt.attempt_sha256, payload) for result, payload in raw_payloads
        ),
    )
    root.mkdir(parents=True, mode=0o700, exist_ok=True)
    root.chmod(0o700)
    _write_private(
        root / "source-bundles.json",
        canonical_json_bytes([bundle.model_dump(mode="json") for bundle in bundles]),
    )
    generation = publish_demo_profile_generation(complete, output_root=root / "generations")
    return generation, tuple(bundle.place_id for bundle in bundles)


def _patch_synthetic_v5_predecessor_bindings(
    monkeypatch: pytest.MonkeyPatch,
    generation: Path,
) -> None:
    """Bind the release validator to this test-only synthetic predecessor prefix."""

    from itda.contracts.demo_profile_materialization import (
        NVIDIA_V5_TWO_PROBE_RESUME_BINDINGS,
    )
    from itda.db import phase5_demo_release

    attempt_rows = json.loads((generation / "attempts.json").read_text(encoding="utf-8"))
    synthetic_bindings = dict(NVIDIA_V5_TWO_PROBE_RESUME_BINDINGS)
    for index, attempt in enumerate(attempt_rows[:2], start=1):
        synthetic_bindings[f"attempt{index}_attempt_sha256"] = attempt["attempt_sha256"]
        synthetic_bindings[f"attempt{index}_contract_request_sha256"] = attempt["request_sha256"]
        synthetic_bindings[f"attempt{index}_response_sha256"] = attempt["response_sha256"]
    monkeypatch.setattr(
        phase5_demo_release,
        "NVIDIA_V5_TWO_PROBE_RESUME_BINDINGS",
        synthetic_bindings,
    )


def _reseal_adjudication(payload: dict[str, object]) -> dict[str, object]:
    payload["partition_sha256"] = canonical_sha256(payload["equivalence_classes"])
    payload["approver_decision_sha256"] = canonical_sha256(
        {
            "approver_id": payload["approver_id"],
            "approver_decision_ref": payload["approver_decision_ref"],
            "approved_at": payload["approved_at"],
            "decision": payload["decision"],
            "decision_statement": payload["decision_statement"],
            "non_promotion_statement": payload["non_promotion_statement"],
            "dev_membership_sha256": payload["dev_membership_sha256"],
            "partition_sha256": payload["partition_sha256"],
            "relationship_resolution": payload["relationship_resolution"],
        }
    )
    payload["adjudication_sha256"] = canonical_sha256(
        {key: value for key, value in payload.items() if key != "adjudication_sha256"}
    )
    return payload


def test_hard_duplicate_adjudication_is_fixed_human_sealed_and_all_singleton() -> None:
    adjudication = load_hard_duplicate_adjudication()

    assert signature(load_hard_duplicate_adjudication).parameters == {}
    assert adjudication.adjudication_sha256 == HARD_DUPLICATE_ADJUDICATION_SHA256
    assert adjudication.relationship_resolution.relationship_unresolved_count == 3
    assert adjudication.relationship_resolution.reviewed_relationship_leaf_count == 0
    assert adjudication.relationship_resolution.hard_duplicate_relationship_count == 0
    assert len(adjudication.group_id_by_place) == 24
    assert len(set(adjudication.group_id_by_place.values())) == 24
    assert all(len(row.member_place_ids) == 1 for row in adjudication.equivalence_classes)


def test_hard_duplicate_adjudication_rejects_rehashed_merge_and_unresolved_promotion() -> None:
    original = json.loads(HARD_DUPLICATE_ADJUDICATION_PATH.read_text(encoding="utf-8"))
    merged = deepcopy(original)
    merged["equivalence_classes"][1]["duplicate_group_id"] = merged["equivalence_classes"][0][
        "duplicate_group_id"
    ]
    with pytest.raises(ValueError, match="singleton group identity drifted"):
        HardDuplicateAdjudication.model_validate(_reseal_adjudication(merged))

    promoted = deepcopy(original)
    promoted["relationship_resolution"]["reviewed_relationship_leaf_count"] = 1
    promoted["relationship_resolution"]["hard_duplicate_relationship_count"] = 1
    with pytest.raises(ValueError):
        HardDuplicateAdjudication.model_validate(_reseal_adjudication(promoted))


def test_complete_test_only_generation_builds_but_cannot_activate_unsealed_dimensions(
    tmp_path: Path,
) -> None:
    from itda.db.phase5_demo_release import Phase5DemoReleaseError, Phase5DemoReleaseStore

    root = tmp_path / "restricted"
    generation, expected = _live_generation(root)
    store = Phase5DemoReleaseStore(root=root, expected_place_ids=expected)

    candidate = store.build(generation.name)
    replay_bytes = canonical_json_bytes(candidate.model_dump(mode="json"))
    assert all(
        canonical_json_bytes(store.verify(candidate.release_sha256).model_dump(mode="json"))
        == replay_bytes
        for _ in range(100)
    )

    with pytest.raises(Phase5DemoReleaseError, match="PROFILE_DIMENSION_EVIDENCE_UNSEALED"):
        store.activate(candidate.release_sha256, expected_current_sha256=None)
    assert store.resolve_active() is None


@pytest.mark.parametrize(
    ("confidence", "publication_state", "eligible", "publishability"),
    (
        (0, "EXCLUDED_MANUAL_REVIEW", False, "EXCLUDED"),
        (64, "LIMITED_INFORMATION", False, "LIMITED_INFORMATION"),
        (70, "PUBLISHABLE", True, "PUBLISHABLE"),
    ),
)
def test_public_release_freezes_confidence_qualification_before_candidate_projection(
    tmp_path: Path,
    confidence: int,
    publication_state: str,
    eligible: bool,
    publishability: str,
) -> None:
    from itda.application.recommendations import _recommendation_candidates
    from itda.contracts.demo_profile_materialization import (
        PublicScoredProfile,
        PublicScoredReleaseSnapshot,
    )
    from itda.db.phase5_demo_release import Phase5DemoReleaseStore

    root = tmp_path / f"qualification-{confidence}"
    generation, expected = _nvidia_live_generation(root)
    store = Phase5DemoReleaseStore(root=root, expected_place_ids=expected)
    candidate = store.build(generation.name)
    store.activate(candidate.release_sha256, expected_current_sha256=None)
    snapshot = store.resolve_active()
    assert snapshot is not None

    profile_fields = snapshot.profiles[0].model_dump(mode="json", exclude={"projection_sha256"})
    profile_fields.update(
        confidence=confidence,
        publication_state=publication_state,
        recommendation_eligible=eligible,
    )
    profile = PublicScoredProfile.model_validate(
        seal_demo_contract(profile_fields, digest_field="projection_sha256")
    )
    snapshot_fields = snapshot.model_dump(mode="json", exclude={"snapshot_sha256"})
    snapshot_fields["profiles"] = [
        profile.model_dump(mode="json"),
        *(row.model_dump(mode="json") for row in snapshot.profiles[1:]),
    ]
    qualified_snapshot = PublicScoredReleaseSnapshot.model_validate(
        seal_demo_contract(snapshot_fields, digest_field="snapshot_sha256")
    )

    projected = _recommendation_candidates(qualified_snapshot)[0]
    assert projected.recommendation_eligible is eligible
    assert projected.publishability == publishability
    assert projected.profile_sha256 == profile.projection_sha256
    assert projected.duplicate_group_id == profile.duplicate_group_id
    assert projected.evidence[0].excerpt_ko == profile.evidence_excerpts[0].excerpt_ko
    assert projected.evidence[0].source_label_ko == profile.evidence_excerpts[0].source_label_ko
    assert projected.evidence[0].contest_rights_qualified is True


def test_complete_coding_plan_generation_builds_but_cannot_activate_unsealed_dimensions(
    tmp_path: Path,
) -> None:
    from itda.contracts.demo_profile_materialization import Phase5CodingPlanReleaseCandidate
    from itda.db.phase5_demo_release import Phase5DemoReleaseStore

    root = tmp_path / "restricted-coding-plan"
    generation, expected = _coding_live_generation(root)
    store = Phase5DemoReleaseStore(root=root, expected_place_ids=expected)

    candidate = store.build(generation.name)
    assert isinstance(candidate, Phase5CodingPlanReleaseCandidate)
    assert candidate.provider_lane == "CODING_PLAN_SUBSCRIPTION"
    assert candidate.attempt_count == 24
    assert candidate.subscription_total_weight == 24
    assert not hasattr(candidate, "committed_cost_micro_usd")

    from itda.db.phase5_demo_release import Phase5DemoReleaseError

    with pytest.raises(Phase5DemoReleaseError, match="PROFILE_DIMENSION_EVIDENCE_UNSEALED"):
        store.activate(candidate.release_sha256, expected_current_sha256=None)
    assert store.resolve_active() is None


def test_complete_nvidia_generation_independently_builds_and_activates(
    tmp_path: Path,
) -> None:
    from itda.cli.manage_phase5_demo_release import _safe_candidate
    from itda.contracts.demo_profile_materialization import (
        Phase5NvidiaMinimaxReleaseCandidate,
    )
    from itda.db.phase5_demo_release import Phase5DemoReleaseStore
    from itda.pipeline.demo_profile_materialization import verify_demo_profile_generation

    root = tmp_path / "restricted-nvidia"
    generation, expected = _nvidia_live_generation(root)
    receipt = verify_demo_profile_generation(generation)
    store = Phase5DemoReleaseStore(root=root, expected_place_ids=expected)

    candidate = store.build(generation.name)
    assert isinstance(candidate, Phase5NvidiaMinimaxReleaseCandidate)
    assert candidate.schema_version == "itda.phase5-nvidia-minimax-release-candidate.v4"
    assert candidate.prompt_version == "phase5-demo-profile-sentinel-json.v4"
    assert candidate.provider_lane == "NVIDIA_NIM_API"
    assert candidate.attempt_count == 24
    assert receipt.receipt_sha256 == candidate.generation_receipt_sha256
    public_safe = _safe_candidate(candidate)
    assert public_safe["provider_lane"] == "NVIDIA_NIM_API"
    assert public_safe["endpoint"] == "https://integrate.api.nvidia.com/v1/chat/completions"
    assert public_safe["authority_sha256"] == candidate.authority_sha256
    assert public_safe["config_sha256"] == candidate.config_sha256
    assert public_safe["hard_duplicate_adjudication_sha256"] == HARD_DUPLICATE_ADJUDICATION_SHA256
    assert "pricing_snapshot_sha256" not in public_safe
    assert "committed_cost_micro_usd" not in public_safe

    activation = store.activate(candidate.release_sha256, expected_current_sha256=None)
    snapshot = store.resolve_active()
    assert activation.active_release_sha256 == candidate.release_sha256
    assert snapshot is not None
    assert snapshot.schema_version == "itda.public-scored-release-snapshot.v4"
    assert snapshot.prompt_version == "phase5-demo-profile-sentinel-json.v4"
    assert snapshot.model == "minimaxai/minimax-m3"
    assert len(snapshot.profiles) == 24
    assert tuple(profile.place_id for profile in snapshot.profiles) == expected
    assert (
        snapshot.hard_duplicate_adjudication.adjudication_sha256
        == snapshot.hard_duplicate_adjudication_sha256
    )
    assert snapshot.hard_duplicate_adjudication.group_id_by_place == {
        profile.place_id: profile.duplicate_group_id for profile in snapshot.profiles
    }
    public_profile = snapshot.profiles[0]
    assert public_profile.evidence_justifications is not None
    assert public_profile.evidence_justifications["H"] == ("tour-description-01",)
    assert public_profile.evidence_justifications["E"] == ("odii-transcript-01",)
    source_rows = json.loads((root / "source-bundles.json").read_text(encoding="utf-8"))
    source = source_rows[0]["sources"][0]
    public_evidence = public_profile.evidence_excerpts[0]
    assert public_evidence.evidence_id == source["evidence_id"]
    assert public_evidence.excerpt_ko == " ".join(source["text"].split())
    assert public_evidence.source_sha256 == source["source_sha256"]
    assert public_evidence.span_sha256 == source["span_sha256"]
    assert public_evidence.source_label_ko == "한국관광공사 TourAPI 공식 관광정보"
    assert public_evidence.contest_rights_qualified is True
    from itda.application.recommendations import _recommendation_candidates

    service_candidate = _recommendation_candidates(snapshot)[0]
    assert service_candidate.axis_scores[0].evidence_ids == ("tour-description-01",)
    assert service_candidate.axis_scores[1].evidence_ids == ("odii-transcript-01",)


def test_release_build_reports_uncertain_when_canonical_parent_is_replaced(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from itda.db import phase5_demo_release
    from itda.db.phase5_demo_release import Phase5DemoReleaseError, Phase5DemoReleaseStore

    root = tmp_path / "replaced-releases"
    generation, expected = _nvidia_live_generation(root)
    releases = root / "releases"
    pinned = root / "releases-pinned"
    outside = tmp_path / "outside"
    outside.mkdir()
    original_mkdir = phase5_demo_release.os.mkdir

    def replace_parent_after_staging(path: object, *args: object, **kwargs: object) -> object:
        result = original_mkdir(path, *args, **kwargs)
        if isinstance(path, str) and path.startswith(".phase5-release-"):
            releases.rename(pinned)
            releases.symlink_to(outside, target_is_directory=True)
        return result

    monkeypatch.setattr(phase5_demo_release.os, "mkdir", replace_parent_after_staging)
    with pytest.raises(Phase5DemoReleaseError, match="RELEASE_PUBLICATION_UNCERTAIN"):
        Phase5DemoReleaseStore(root=root, expected_place_ids=expected).build(generation.name)
    assert len(tuple(path for path in pinned.iterdir() if path.is_dir())) == 1
    assert tuple(outside.iterdir()) == ()


def test_release_build_rejects_symlinked_releases_parent(tmp_path: Path) -> None:
    from itda.db.phase5_demo_release import Phase5DemoReleaseError, Phase5DemoReleaseStore

    root = tmp_path / "symlinked-releases"
    generation, expected = _nvidia_live_generation(root)
    outside = tmp_path / "outside-releases"
    outside.mkdir()
    (root / "releases").symlink_to(outside, target_is_directory=True)

    with pytest.raises(Phase5DemoReleaseError, match="RESTRICTED_PATH_SYMLINK"):
        Phase5DemoReleaseStore(root=root, expected_place_ids=expected).build(generation.name)
    assert tuple(outside.iterdir()) == ()


def test_activation_reports_uncertain_when_active_parent_is_replaced(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from itda.db import phase5_demo_release
    from itda.db.phase5_demo_release import Phase5DemoReleaseError, Phase5DemoReleaseStore

    root = tmp_path / "replaced-active"
    generation, expected = _nvidia_live_generation(root)
    store = Phase5DemoReleaseStore(root=root, expected_place_ids=expected)
    candidate = store.build(generation.name)
    outside = tmp_path / "outside-active"
    outside.mkdir()
    active = root / "active"
    pinned = root / "active-pinned"
    original_temporary = phase5_demo_release._create_private_temporary_at

    def replace_active_after_temporary(descriptor: int, payload: bytes) -> str:
        name = original_temporary(descriptor, payload)
        active.rename(pinned)
        active.symlink_to(outside, target_is_directory=True)
        return name

    monkeypatch.setattr(
        phase5_demo_release,
        "_create_private_temporary_at",
        replace_active_after_temporary,
    )
    with pytest.raises(Phase5DemoReleaseError, match="ACTIVATION_COMMIT_UNCERTAIN"):
        store.activate(candidate.release_sha256, expected_current_sha256=None)
    assert not (outside / "current.json").exists()


def test_activation_rejects_root_replacement_after_candidate_verification(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Specified oracle: activation never binds an old-root release to a new root."""

    from itda.db import phase5_demo_release
    from itda.db.phase5_demo_release import Phase5DemoReleaseError, Phase5DemoReleaseStore

    root = tmp_path / "replaced-root-after-verify"
    generation, expected = _nvidia_live_generation(root)
    store = Phase5DemoReleaseStore(root=root, expected_place_ids=expected)
    candidate = store.build(generation.name)
    moved_root = tmp_path / "verified-root"
    original_load = phase5_demo_release.load_hard_duplicate_adjudication
    loader_calls = 0

    def replace_root_after_candidate_verification():
        nonlocal loader_calls
        loader_calls += 1
        if loader_calls == 2:
            root.rename(moved_root)
            root.mkdir()
        return original_load()

    monkeypatch.setattr(
        phase5_demo_release,
        "load_hard_duplicate_adjudication",
        replace_root_after_candidate_verification,
    )

    with pytest.raises(
        Phase5DemoReleaseError,
        match="ACTIVATION_PATH_DRIFT|ACTIVATION_COMMIT_UNCERTAIN",
    ):
        store.activate(candidate.release_sha256, expected_current_sha256=None)

    assert not (root / "active" / "current.json").exists()
    assert (moved_root / "releases" / candidate.release_sha256).is_dir()


def test_activation_rejects_temporary_foreign_root_during_candidate_verification(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Specified oracle: verification reads only through the root pinned by activate()."""

    from itda.db import phase5_demo_release
    from itda.db.phase5_demo_release import Phase5DemoReleaseError, Phase5DemoReleaseStore

    root = tmp_path / "activation-root"
    foreign_root = tmp_path / "foreign-root"
    _nvidia_live_generation(root)
    foreign_generation, foreign_expected = _nvidia_live_generation(
        foreign_root,
        swap_axis_justifications=True,
    )
    store = Phase5DemoReleaseStore(root=root, expected_place_ids=foreign_expected)
    foreign_store = Phase5DemoReleaseStore(root=foreign_root, expected_place_ids=foreign_expected)
    foreign_candidate = foreign_store.build(foreign_generation.name)
    moved_root = tmp_path / "activation-root-pinned"
    original_read_beneath = phase5_demo_release._read_regular_beneath
    attack_exercised = False

    def read_during_temporary_foreign_root(
        root_descriptor: int,
        components: tuple[str, ...],
        *,
        maximum_bytes: int,
    ) -> bytes:
        nonlocal attack_exercised
        if components != ("releases", foreign_candidate.release_sha256, "candidate.json"):
            return original_read_beneath(
                root_descriptor,
                components,
                maximum_bytes=maximum_bytes,
            )
        attack_exercised = True
        root.rename(moved_root)
        foreign_root.rename(root)
        try:
            return original_read_beneath(
                root_descriptor,
                components,
                maximum_bytes=maximum_bytes,
            )
        finally:
            root.rename(foreign_root)
            moved_root.rename(root)

    monkeypatch.setattr(
        phase5_demo_release,
        "_read_regular_beneath",
        read_during_temporary_foreign_root,
    )

    with pytest.raises(Phase5DemoReleaseError):
        store.activate(foreign_candidate.release_sha256, expected_current_sha256=None)

    assert attack_exercised is True
    assert not (root / "active" / "current.json").exists()


def test_descriptor_generation_load_forwards_pinned_root_to_source_verifier(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Specified oracle: production source verification receives the activation root fd."""

    from itda.cli import collect_phase5_demo_sources
    from itda.db.phase5_demo_release import (
        Phase5DemoReleaseStore,
        _open_directory_chain,
    )

    class PinnedSourceVerifierReached(RuntimeError):
        pass

    root = tmp_path / "pinned-source-verifier"
    generation, expected = _nvidia_live_generation(root)
    store = Phase5DemoReleaseStore(root=root, expected_place_ids=expected)
    store._production_authority = True
    root_descriptor = _open_directory_chain(root)

    def require_pinned_root(
        verifier_root: Path,
        *,
        expected_rows: object = None,
        root_descriptor: int | None = None,
    ) -> tuple[object, ...]:
        del expected_rows
        assert verifier_root == root
        assert root_descriptor == root_descriptor_under_test
        raise PinnedSourceVerifierReached

    root_descriptor_under_test = root_descriptor
    monkeypatch.setattr(
        collect_phase5_demo_sources,
        "verify_source_collection",
        require_pinned_root,
    )
    try:
        with pytest.raises(PinnedSourceVerifierReached):
            store._load_generation(
                generation.name,
                _root_descriptor=root_descriptor,
            )
    finally:
        os.close(root_descriptor)


def test_complete_nvidia_v5_generation_preserves_v5_release_and_snapshot_lineage(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Derived oracle: V5 profile lineage must never be reconstructed or labeled as V4."""

    from pydantic import ValidationError

    from itda.contracts.demo_profile_materialization import (
        NVIDIA_V5_THREE_VALIDATED_RESUME_AUTHORITY_SHA256,
        Phase5NvidiaMinimaxReleaseCandidate,
        PublicScoredReleaseSnapshot,
    )
    from itda.db.phase5_demo_release import Phase5DemoReleaseStore

    root = tmp_path / "restricted-nvidia-v5"
    generation, expected = _nvidia_v5_live_generation(root)
    _patch_synthetic_v5_predecessor_bindings(monkeypatch, generation)
    store = Phase5DemoReleaseStore(root=root, expected_place_ids=expected)

    candidate = store.build(generation.name)

    assert isinstance(candidate, Phase5NvidiaMinimaxReleaseCandidate)
    assert candidate.schema_version == "itda.phase5-nvidia-minimax-release-candidate.v5"
    assert candidate.prompt_version == "phase5-demo-profile-sentinel-json.v5"
    assert all(
        profile.schema_version == "itda.nvidia-minimax-model-derived-profile.v5"
        for profile in candidate.profiles
    )
    assert store.verify(candidate.release_sha256) == candidate
    drifted_candidate = candidate.model_dump(mode="json", exclude={"release_sha256"})
    drifted_candidate["schema_version"] = "itda.phase5-nvidia-minimax-release-candidate.v4"
    with pytest.raises(ValidationError, match="schema/prompt lineage drifted"):
        Phase5NvidiaMinimaxReleaseCandidate.model_validate(
            seal_demo_contract(drifted_candidate, digest_field="release_sha256")
        )
    stale_candidate = candidate.model_dump(mode="json", exclude={"release_sha256"})
    stale_candidate["resume_authority_sha256"] = NVIDIA_V5_THREE_VALIDATED_RESUME_AUTHORITY_SHA256
    with pytest.raises(ValidationError, match="stale retained-profile V5 authority"):
        Phase5NvidiaMinimaxReleaseCandidate.model_validate(
            seal_demo_contract(stale_candidate, digest_field="release_sha256")
        )

    store.activate(candidate.release_sha256, expected_current_sha256=None)
    snapshot = store.resolve_active()
    assert snapshot is not None
    assert snapshot.schema_version == "itda.public-scored-release-snapshot.v5"
    assert snapshot.prompt_version == "phase5-demo-profile-sentinel-json.v5"
    drifted_snapshot = snapshot.model_dump(mode="json", exclude={"snapshot_sha256"})
    drifted_snapshot["schema_version"] = "itda.public-scored-release-snapshot.v4"
    with pytest.raises(ValidationError, match="schema/prompt lineage drifted"):
        PublicScoredReleaseSnapshot.model_validate(
            seal_demo_contract(drifted_snapshot, digest_field="snapshot_sha256")
        )

    v4_root = tmp_path / "restricted-nvidia-v4-neighbor"
    v4_generation, v4_expected = _nvidia_live_generation(v4_root)
    v4_store = Phase5DemoReleaseStore(root=v4_root, expected_place_ids=v4_expected)
    v4_candidate = v4_store.build(v4_generation.name)
    mixed_candidate = candidate.model_dump(mode="json", exclude={"release_sha256"})
    mixed_candidate["profiles"][0] = v4_candidate.profiles[0].model_dump(mode="json")
    with pytest.raises(ValidationError, match="nested profile lineage drifted"):
        Phase5NvidiaMinimaxReleaseCandidate.model_validate(
            seal_demo_contract(mixed_candidate, digest_field="release_sha256")
        )

    v4_store.activate(v4_candidate.release_sha256, expected_current_sha256=None)
    v4_snapshot = v4_store.resolve_active()
    assert v4_snapshot is not None
    mixed_snapshot = snapshot.model_dump(mode="json", exclude={"snapshot_sha256"})
    mixed_snapshot["profiles"][0] = v4_snapshot.profiles[0].model_dump(mode="json")
    with pytest.raises(ValidationError, match="nested profile lineage drifted"):
        PublicScoredReleaseSnapshot.model_validate(
            seal_demo_contract(mixed_snapshot, digest_field="snapshot_sha256")
        )


def test_nvidia_v5_release_rejects_unbound_predecessor_attempt_prefix(
    tmp_path: Path,
) -> None:
    """Derived oracle: a fixed V5 authority cannot admit an arbitrary attempt prefix."""

    from itda.db.phase5_demo_release import Phase5DemoReleaseError, Phase5DemoReleaseStore

    root = tmp_path / "restricted-nvidia-v5-unbound-prefix"
    generation, expected = _nvidia_v5_live_generation(root)

    with pytest.raises(Phase5DemoReleaseError, match="NVIDIA_V5_TWO_PROBE_ATTEMPT_DRIFT"):
        Phase5DemoReleaseStore(root=root, expected_place_ids=expected).build(generation.name)


def test_nvidia_v5_release_rejects_resealed_receipt_profile_schema_drift(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Derived oracle: receipt lineage must match reconstructed V5 profile lineage."""

    from itda.db.phase5_demo_release import Phase5DemoReleaseError, Phase5DemoReleaseStore

    root = tmp_path / "restricted-nvidia-v5-receipt-drift"
    generation, expected = _nvidia_v5_live_generation(root)
    _patch_synthetic_v5_predecessor_bindings(monkeypatch, generation)
    receipt = json.loads((generation / "receipt.json").read_text(encoding="utf-8"))
    receipt.pop("receipt_sha256")
    receipt["profile_schema_sha256"] = "0" * 64
    _write_private(
        generation / "receipt.json",
        canonical_json_bytes(seal_demo_contract(receipt, digest_field="receipt_sha256")),
    )

    with pytest.raises(Phase5DemoReleaseError, match="PROFILE_LINEAGE_DRIFT"):
        Phase5DemoReleaseStore(root=root, expected_place_ids=expected).build(generation.name)


def test_production_release_rejects_consumed_v5_authority_before_evidence_loading(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Specified oracle: consumed V5 authority IDs are never release authority."""

    from itda.db import phase5_demo_release
    from itda.db.phase5_demo_release import Phase5DemoReleaseError, Phase5DemoReleaseStore

    root = tmp_path / "restricted-nvidia-v5-consumed-authority"
    generation, expected = _nvidia_v5_live_generation(root)
    monkeypatch.setattr(phase5_demo_release, "PRODUCTION_ROOT", root.resolve())
    monkeypatch.setattr(phase5_demo_release, "_production_expected_ids", lambda: expected)
    original_read_json = phase5_demo_release._read_json
    read_paths: list[Path] = []

    def receipt_only(path: Path, *, maximum_bytes: int = 64 * 1024 * 1024) -> object:
        read_paths.append(path)
        if path.name != "receipt.json":
            raise AssertionError("consumed V5 authority loaded non-receipt evidence")
        return original_read_json(path, maximum_bytes=maximum_bytes)

    monkeypatch.setattr(phase5_demo_release, "_read_json", receipt_only)

    with pytest.raises(Phase5DemoReleaseError, match="NVIDIA_V5_AUTHORITY_SUPERSEDED"):
        Phase5DemoReleaseStore(root=root).build(generation.name)
    assert [path.name for path in read_paths] == ["receipt.json"]


def test_historical_snapshot_replays_its_embedded_singleton_adjudication(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from itda.contracts.demo_profile_materialization import PublicScoredReleaseSnapshot
    from itda.db import phase5_demo_release
    from itda.db.phase5_demo_release import Phase5DemoReleaseStore

    root = tmp_path / "historical-adjudication"
    generation, expected = _nvidia_live_generation(root)
    store = Phase5DemoReleaseStore(root=root, expected_place_ids=expected)
    candidate = store.build(generation.name)
    store.activate(candidate.release_sha256, expected_current_sha256=None)
    snapshot = store.resolve_active()
    assert snapshot is not None
    serialized = snapshot.model_dump_json()
    next_root = tmp_path / "new-activation"
    next_generation, next_expected = _nvidia_live_generation(next_root)
    next_store = Phase5DemoReleaseStore(root=next_root, expected_place_ids=next_expected)
    next_candidate = next_store.build(next_generation.name)

    def current_adjudication_unavailable() -> object:
        raise AssertionError("historical replay consulted the current adjudication")

    monkeypatch.setattr(
        phase5_demo_release,
        "load_hard_duplicate_adjudication",
        current_adjudication_unavailable,
    )
    restored = PublicScoredReleaseSnapshot.model_validate_json(serialized)
    assert restored == snapshot
    assert store.resolve_active() == snapshot

    with pytest.raises(AssertionError, match="consulted the current adjudication"):
        next_store.activate(next_candidate.release_sha256, expected_current_sha256=None)


def test_all_provider_releases_reject_rank_effective_degenerate_vectors(
    tmp_path: Path,
) -> None:
    from itda.db.phase5_demo_release import (
        Phase5DemoReleaseError,
        Phase5DemoReleaseStore,
        _require_nondegenerate_profiles,
    )

    nvidia_root = tmp_path / "restricted-nvidia-degenerate"
    nvidia_generation, nvidia_expected = _nvidia_live_generation(nvidia_root)
    nvidia_candidate = Phase5DemoReleaseStore(
        root=nvidia_root, expected_place_ids=nvidia_expected
    ).build(nvidia_generation.name)
    nvidia_profile = nvidia_candidate.profiles[0]

    metadata_distinct_nvidia = tuple(
        nvidia_profile.model_copy(
            update={
                "subattributes": {
                    **nvidia_profile.subattributes,
                    "H1": index % 5,
                },
                "confidence": 70 + (index % 11),
            }
        )
        for index in range(24)
    )

    with pytest.raises(Phase5DemoReleaseError, match="PROFILE_COHORT_DEGENERATE"):
        _require_nondegenerate_profiles(metadata_distinct_nvidia)

    with pytest.raises(
        Phase5DemoReleaseError,
        match="INSUFFICIENT_RECOMMENDATION_ELIGIBLE_PROFILES",
    ):
        _require_nondegenerate_profiles(nvidia_candidate.profiles[:4])

    zero_nvidia = nvidia_profile.model_copy(
        update={
            "axis_scores": {"H": 0, "E": 0, "R": 0},
            "confidence": 100,
        }
    )
    with pytest.raises(Phase5DemoReleaseError, match="PROFILE_SCHEMA_ECHO_DETECTED"):
        _require_nondegenerate_profiles((zero_nvidia, *nvidia_candidate.profiles[1:]))

    stale_low_confidence_nvidia = nvidia_profile.model_copy(update={"confidence": 69})
    with pytest.raises(Phase5DemoReleaseError, match="PROFILE_CONTRACT_INVALID"):
        _require_nondegenerate_profiles(
            (stale_low_confidence_nvidia, *nvidia_candidate.profiles[1:])
        )

    low_confidence_payload = nvidia_profile.model_dump(mode="json")
    low_confidence_payload.update(confidence=69)
    from itda.contracts.demo_profile_materialization import (
        NvidiaMinimaxModelDerivedProfile,
    )

    low_confidence_nvidia = NvidiaMinimaxModelDerivedProfile.model_validate(
        seal_demo_contract(low_confidence_payload, digest_field="profile_sha256")
    )
    _require_nondegenerate_profiles((low_confidence_nvidia, *nvidia_candidate.profiles[1:]))

    zhipu_root = tmp_path / "restricted-zhipu-degenerate"
    zhipu_generation, zhipu_expected = _live_generation(zhipu_root)
    zhipu_candidate = Phase5DemoReleaseStore(
        root=zhipu_root, expected_place_ids=zhipu_expected
    ).build(zhipu_generation.name)
    zero_zhipu = zhipu_candidate.profiles[0].model_copy(
        update={"axis_scores": {"H": 0, "E": 0, "R": 0}, "confidence": 100}
    )
    with pytest.raises(Phase5DemoReleaseError, match="PROFILE_SCHEMA_ECHO_DETECTED"):
        _require_nondegenerate_profiles((zero_zhipu, *zhipu_candidate.profiles[1:]))

    coding_root = tmp_path / "restricted-coding-plan-degenerate"
    coding_generation, coding_expected = _coding_live_generation(coding_root)
    coding_candidate = Phase5DemoReleaseStore(
        root=coding_root, expected_place_ids=coding_expected
    ).build(coding_generation.name)
    coding_profile = coding_candidate.profiles[0]
    metadata_distinct_coding = tuple(
        coding_profile.model_copy(
            update={
                "mismatch_traits": {
                    **coding_profile.mismatch_traits,
                    "M1": index,
                },
                "confidence": 70 + (index % 11),
            }
        )
        for index in range(24)
    )
    with pytest.raises(Phase5DemoReleaseError, match="PROFILE_COHORT_DEGENERATE"):
        _require_nondegenerate_profiles(metadata_distinct_coding)

    for profiles in (
        nvidia_candidate.profiles,
        zhipu_candidate.profiles,
        coding_candidate.profiles,
    ):
        diagonal = tuple(
            profile.model_copy(
                update={"axis_scores": {"H": 10 + index, "E": 10 + index, "R": 10 + index}}
            )
            for index, profile in enumerate(profiles)
        )
        assert len({tuple(profile.axis_scores.values()) for profile in diagonal}) == 24
        with pytest.raises(Phase5DemoReleaseError, match="PROFILE_RANK_INSENSITIVE"):
            _require_nondegenerate_profiles(diagonal)


def test_nvidia_dimension_justification_swap_survives_public_candidate_projection(
    tmp_path: Path,
) -> None:
    from itda.application.recommendations import _recommendation_candidates
    from itda.db.phase5_demo_release import Phase5DemoReleaseStore

    snapshots = []
    for swapped in (False, True):
        root = tmp_path / ("nvidia-swapped" if swapped else "nvidia-baseline")
        generation, expected = _nvidia_live_generation(
            root,
            swap_axis_justifications=swapped,
        )
        store = Phase5DemoReleaseStore(root=root, expected_place_ids=expected)
        candidate = store.build(generation.name)
        store.activate(candidate.release_sha256, expected_current_sha256=None)
        snapshot = store.resolve_active()
        assert snapshot is not None
        snapshots.append(snapshot)

    baseline, swapped = snapshots
    assert baseline.profiles[0].evidence_ids == swapped.profiles[0].evidence_ids
    assert baseline.profiles[0].axis_scores == swapped.profiles[0].axis_scores
    baseline_candidate = _recommendation_candidates(baseline)[0]
    swapped_candidate = _recommendation_candidates(swapped)[0]
    assert baseline_candidate.axis_scores[0].evidence_ids == ("tour-description-01",)
    assert baseline_candidate.axis_scores[1].evidence_ids == ("odii-transcript-01",)
    assert swapped_candidate.axis_scores[0].evidence_ids == ("odii-transcript-01",)
    assert swapped_candidate.axis_scores[1].evidence_ids == ("tour-description-01",)
    assert {
        row.evidence_id: (row.excerpt_ko, row.source_label_ko, row.attribution_ko)
        for row in baseline_candidate.evidence
    } == {
        row.evidence_id: (row.excerpt_ko, row.source_label_ko, row.attribution_ko)
        for row in swapped_candidate.evidence
    }

    from pydantic import ValidationError

    from itda.contracts.demo_profile_materialization import PublicScoredProfile

    for prompt_version in ("phase5-demo-profile.v1", "phase5-demo-profile-json.v2"):
        fields = baseline.profiles[0].model_dump(mode="json", exclude={"projection_sha256"})
        fields.update(model="glm-5v-turbo", prompt_version=prompt_version)
        justifications = fields["evidence_justifications"]
        assert isinstance(justifications, dict)
        justifications["H"], justifications["E"] = (
            justifications["E"],
            justifications["H"],
        )
        with pytest.raises(ValidationError, match="no sealed dimension authority"):
            PublicScoredProfile.model_validate(
                seal_demo_contract(fields, digest_field="projection_sha256")
            )


def test_activation_is_compare_and_swap_and_failure_keeps_active_state(tmp_path: Path) -> None:
    from itda.db.phase5_demo_release import Phase5DemoReleaseError, Phase5DemoReleaseStore

    root = tmp_path / "restricted"
    generation, expected = _nvidia_live_generation(root)
    store = Phase5DemoReleaseStore(root=root, expected_place_ids=expected)
    candidate = store.build(generation.name)
    store.activate(candidate.release_sha256, expected_current_sha256=None)
    before = (root / "active" / "current.json").read_bytes()

    with pytest.raises(Phase5DemoReleaseError, match="EXPECTED_CURRENT"):
        store.activate(candidate.release_sha256, expected_current_sha256="f" * 64)
    assert (root / "active" / "current.json").read_bytes() == before


def test_activation_recovers_unowned_lock_file_and_rejects_live_owner(
    tmp_path: Path,
) -> None:
    """Specified oracle: lock ownership follows a live descriptor, not path existence."""

    from itda.db.phase5_demo_release import Phase5DemoReleaseError, Phase5DemoReleaseStore

    root = tmp_path / "activation-lock-recovery"
    generation, expected = _nvidia_live_generation(root)
    store = Phase5DemoReleaseStore(root=root, expected_place_ids=expected)
    candidate = store.build(generation.name)
    active = root / "active"
    active.mkdir(mode=0o700)
    lock_path = active / ".activation.lock"
    lock_path.write_bytes(b"")
    lock_path.chmod(0o600)

    first = store.activate(candidate.release_sha256, expected_current_sha256=None)
    assert lock_path.exists()

    lock_descriptor = os.open(lock_path, os.O_RDWR | os.O_NOFOLLOW)
    try:
        fcntl.flock(lock_descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        with pytest.raises(Phase5DemoReleaseError, match="ACTIVATION_BUSY"):
            store.activate(
                candidate.release_sha256,
                expected_current_sha256=first.active_release_sha256,
            )
    finally:
        fcntl.flock(lock_descriptor, fcntl.LOCK_UN)
        os.close(lock_descriptor)

    second = store.activate(
        candidate.release_sha256,
        expected_current_sha256=first.active_release_sha256,
    )
    assert second.previous_release_sha256 == first.active_release_sha256
    assert lock_path.exists()


def test_activation_reports_uncertain_after_post_replace_directory_fsync_error(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from itda.db import phase5_demo_release
    from itda.db.phase5_demo_release import Phase5DemoReleaseError, Phase5DemoReleaseStore

    root = tmp_path / "post-replace-fsync"
    generation, expected = _nvidia_live_generation(root)
    store = Phase5DemoReleaseStore(root=root, expected_place_ids=expected)
    candidate = store.build(generation.name)

    original_replace = phase5_demo_release.os.replace
    original_fsync = phase5_demo_release.os.fsync
    pointer_replaced = False

    def track_replace(*args: object, **kwargs: object) -> None:
        nonlocal pointer_replaced
        original_replace(*args, **kwargs)
        if len(args) >= 2 and args[1] == "current.json":
            pointer_replaced = True

    def fail_post_replace_directory_fsync(descriptor: int) -> None:
        if pointer_replaced and stat.S_ISDIR(os.fstat(descriptor).st_mode):
            raise OSError("simulated post-replace directory fsync failure")
        original_fsync(descriptor)

    monkeypatch.setattr(phase5_demo_release.os, "replace", track_replace)
    monkeypatch.setattr(phase5_demo_release.os, "fsync", fail_post_replace_directory_fsync)
    with pytest.raises(Phase5DemoReleaseError, match="ACTIVATION_COMMIT_UNCERTAIN"):
        store.activate(candidate.release_sha256, expected_current_sha256=None)


def test_activation_fsyncs_receipt_directory_before_pointer_replace(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Specified oracle: archival receipt durability precedes active pointer publication."""

    from itda.db import phase5_demo_release
    from itda.db.phase5_demo_release import Phase5DemoReleaseStore

    root = tmp_path / "receipt-directory-fsync"
    generation, expected = _nvidia_live_generation(root)
    store = Phase5DemoReleaseStore(root=root, expected_place_ids=expected)
    candidate = store.build(generation.name)
    original_replace = phase5_demo_release.os.replace
    original_fsync = phase5_demo_release.os.fsync
    synced_directory_inodes: set[int] = set()
    receipt_fsynced_before_pointer = False

    def track_fsync(descriptor: int) -> None:
        metadata = os.fstat(descriptor)
        if stat.S_ISDIR(metadata.st_mode):
            synced_directory_inodes.add(metadata.st_ino)
        original_fsync(descriptor)

    def inspect_replace(*args: object, **kwargs: object) -> None:
        nonlocal receipt_fsynced_before_pointer
        if len(args) >= 2 and args[1] == "current.json":
            receipt_fsynced_before_pointer = (
                root / "active" / "receipts"
            ).stat().st_ino in synced_directory_inodes
        original_replace(*args, **kwargs)

    monkeypatch.setattr(phase5_demo_release.os, "fsync", track_fsync)
    monkeypatch.setattr(phase5_demo_release.os, "replace", inspect_replace)
    store.activate(candidate.release_sha256, expected_current_sha256=None)

    assert receipt_fsynced_before_pointer is True


def test_activation_fsyncs_root_directory_before_pointer_replace(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Specified oracle: first-time active/ creation is durable before its pointer."""

    from itda.db import phase5_demo_release
    from itda.db.phase5_demo_release import Phase5DemoReleaseStore

    root = tmp_path / "root-directory-fsync"
    generation, expected = _nvidia_live_generation(root)
    store = Phase5DemoReleaseStore(root=root, expected_place_ids=expected)
    candidate = store.build(generation.name)
    original_replace = phase5_demo_release.os.replace
    original_fsync = phase5_demo_release.os.fsync
    synced_directory_inodes: set[int] = set()
    root_fsynced_before_pointer = False

    def track_fsync(descriptor: int) -> None:
        metadata = os.fstat(descriptor)
        if stat.S_ISDIR(metadata.st_mode):
            synced_directory_inodes.add(metadata.st_ino)
        original_fsync(descriptor)

    def inspect_replace(*args: object, **kwargs: object) -> None:
        nonlocal root_fsynced_before_pointer
        if len(args) >= 2 and args[1] == "current.json":
            root_fsynced_before_pointer = root.stat().st_ino in synced_directory_inodes
        original_replace(*args, **kwargs)

    monkeypatch.setattr(phase5_demo_release.os, "fsync", track_fsync)
    monkeypatch.setattr(phase5_demo_release.os, "replace", inspect_replace)
    store.activate(candidate.release_sha256, expected_current_sha256=None)

    assert root_fsynced_before_pointer is True


def test_exact_invalidated_legacy_predecessor_is_read_only_and_server_pinned(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Specified oracle: only the recorded production predecessor admits v4 materialization."""

    from itda.db import phase5_demo_release
    from itda.db.phase5_demo_release import Phase5DemoReleaseStore

    source_root = phase5_demo_release.PRODUCTION_ROOT
    root = tmp_path / "production"
    pointer = source_root / "active" / "current.json"
    pointer_value = json.loads(pointer.read_bytes())
    release_sha256 = pointer_value["active_release_sha256"]
    candidate = source_root / "releases" / release_sha256 / "candidate.json"
    candidate_value = json.loads(candidate.read_bytes())
    generation_sha256 = candidate_value["generation_sha256"]
    generation_receipt = source_root / "generations" / generation_sha256 / "receipt.json"

    (root / "active").mkdir(parents=True)
    (root / "releases" / release_sha256).mkdir(parents=True)
    (root / "generations" / generation_sha256).mkdir(parents=True)
    shutil.copy2(pointer, root / "active" / "current.json")
    shutil.copy2(candidate, root / "releases" / release_sha256 / "candidate.json")
    shutil.copy2(
        generation_receipt,
        root / "generations" / generation_sha256 / "receipt.json",
    )
    monkeypatch.setattr(phase5_demo_release, "PRODUCTION_ROOT", root.resolve())

    before = {
        path.relative_to(root).as_posix(): path.read_bytes()
        for path in root.rglob("*")
        if path.is_file()
    }
    binding = Phase5DemoReleaseStore(root=root).require_invalidated_legacy_predecessor()
    after = {
        path.relative_to(root).as_posix(): path.read_bytes()
        for path in root.rglob("*")
        if path.is_file()
    }

    assert binding == {
        "legacy_predecessor_release_sha256": release_sha256,
        "legacy_predecessor_receipt_sha256": pointer_value["receipt_sha256"],
        "legacy_predecessor_generation_sha256": generation_sha256,
    }
    assert after == before


@pytest.mark.parametrize(
    "mutation",
    (
        "pointer-receipt",
        "pointer-release",
        "candidate-generation",
        "candidate-score",
        "generation-receipt",
    ),
)
def test_invalidated_legacy_predecessor_rejects_hostile_substitutions(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    mutation: str,
) -> None:
    """Derived oracle: caller-selected, stale, altered, and mixed lineage stays barred."""

    from itda.db import phase5_demo_release
    from itda.db.phase5_demo_release import Phase5DemoReleaseError, Phase5DemoReleaseStore
    from itda.domain.canonical import canonical_json_bytes, canonical_sha256

    source_root = phase5_demo_release.PRODUCTION_ROOT
    root = tmp_path / mutation
    pointer_value = json.loads((source_root / "active" / "current.json").read_bytes())
    release_sha256 = pointer_value["active_release_sha256"]
    candidate_value = json.loads(
        (source_root / "releases" / release_sha256 / "candidate.json").read_bytes()
    )
    generation_sha256 = candidate_value["generation_sha256"]
    generation_receipt_value = json.loads(
        (source_root / "generations" / generation_sha256 / "receipt.json").read_bytes()
    )

    if mutation == "pointer-receipt":
        pointer_value["receipt_sha256"] = "f" * 64
    elif mutation == "pointer-release":
        pointer_value["active_release_sha256"] = "a" * 64
        pointer_value["receipt_sha256"] = canonical_sha256(
            {key: value for key, value in pointer_value.items() if key != "receipt_sha256"}
        )
    elif mutation == "candidate-generation":
        candidate_value["generation_sha256"] = "b" * 64
        candidate_value["release_sha256"] = canonical_sha256(
            {key: value for key, value in candidate_value.items() if key != "release_sha256"}
        )
    elif mutation == "candidate-score":
        candidate_value["profiles"][0]["axis_scores"]["H"] = 99
        candidate_value["release_sha256"] = canonical_sha256(
            {key: value for key, value in candidate_value.items() if key != "release_sha256"}
        )
    elif mutation == "generation-receipt":
        generation_receipt_value["generation_sha256"] = "c" * 64
        generation_receipt_value["receipt_sha256"] = canonical_sha256(
            {
                key: value
                for key, value in generation_receipt_value.items()
                if key != "receipt_sha256"
            }
        )

    (root / "active").mkdir(parents=True)
    (root / "releases" / release_sha256).mkdir(parents=True)
    (root / "generations" / generation_sha256).mkdir(parents=True)
    (root / "active" / "current.json").write_bytes(canonical_json_bytes(pointer_value))
    (root / "releases" / release_sha256 / "candidate.json").write_bytes(
        canonical_json_bytes(candidate_value)
    )
    (root / "generations" / generation_sha256 / "receipt.json").write_bytes(
        canonical_json_bytes(generation_receipt_value)
    )
    monkeypatch.setattr(phase5_demo_release, "PRODUCTION_ROOT", root.resolve())

    with pytest.raises(Phase5DemoReleaseError, match="LEGACY_PREDECESSOR"):
        Phase5DemoReleaseStore(root=root).require_invalidated_legacy_predecessor()


def test_invalidated_legacy_predecessor_rejects_caller_selected_root(tmp_path: Path) -> None:
    """Specified oracle: test or caller roots never acquire production predecessor authority."""

    from itda.db.phase5_demo_release import Phase5DemoReleaseError, Phase5DemoReleaseStore

    with pytest.raises(Phase5DemoReleaseError, match="LEGACY_PREDECESSOR_ROOT_FORBIDDEN"):
        Phase5DemoReleaseStore(
            root=tmp_path,
            expected_place_ids=tuple(f"place:{index:064x}" for index in range(24)),
        ).require_invalidated_legacy_predecessor()


def test_partial_or_drifted_raw_inventory_cannot_build_or_change_active(tmp_path: Path) -> None:
    from itda.db.phase5_demo_release import Phase5DemoReleaseError, Phase5DemoReleaseStore

    root = tmp_path / "restricted"
    generation, expected = _live_generation(root)
    store = Phase5DemoReleaseStore(root=root, expected_place_ids=expected)
    raw = sorted(generation.glob("raw-*.json"))[0]
    raw.unlink()

    with pytest.raises(Phase5DemoReleaseError, match="RAW_INVENTORY"):
        store.build(generation.name)
    assert store.resolve_active() is None

    generation, expected = _live_generation(tmp_path / "drifted")
    store = Phase5DemoReleaseStore(root=generation.parents[1], expected_place_ids=expected)
    raw = sorted(generation.glob("raw-*.json"))[0]
    raw.write_bytes(raw.read_bytes() + b" ")
    os.chmod(raw, 0o600)
    with pytest.raises(Phase5DemoReleaseError, match="RAW_RESPONSE"):
        store.build(generation.name)
    assert store.resolve_active() is None
