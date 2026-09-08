from __future__ import annotations

import asyncio
import hashlib
import json
from copy import deepcopy
from datetime import UTC, datetime
from pathlib import Path

import httpx
import pytest
from pydantic import ValidationError

SHA = tuple(character * 64 for character in "abcdef1234567890")
NOW = datetime(2026, 8, 10, tzinfo=UTC)
AXES = {"H": 76, "E": 61, "R": 84}
SUBATTRIBUTES = {
    **{f"H{index}": 3 for index in range(1, 5)},
    **{f"I{index}": 2 for index in range(1, 5)},
    **{f"R{index}": 4 for index in range(1, 5)},
}
MISMATCH = {f"M{index}": index * 10 for index in range(1, 7)}


def _contracts():
    from itda.contracts.demo_profile_materialization import (
        DemoModelDerivedProfile,
        DemoProfileMaterializationConfig,
        DemoProfileMaterializationReceipt,
        DemoSourceBundle,
        PricingSnapshot,
        ProviderTokenUsage,
        seal_demo_contract,
    )

    return (
        DemoModelDerivedProfile,
        DemoProfileMaterializationConfig,
        DemoProfileMaterializationReceipt,
        DemoSourceBundle,
        PricingSnapshot,
        ProviderTokenUsage,
        seal_demo_contract,
    )


def _source_payload(*, place_id: str = "canonical-dev-01", split: str = "DEV") -> dict[str, object]:
    tour_text = "신라 시대의 유적과 역사 해설이 있는 장소입니다."
    odii_text = "오디오 해설은 장소의 역사와 현재의 관람 경험을 설명합니다."
    tour_sha256 = hashlib.sha256(tour_text.encode("utf-8")).hexdigest()
    odii_sha256 = hashlib.sha256(odii_text.encode("utf-8")).hexdigest()
    payload: dict[str, object] = {
        "schema_version": "itda.demo-source-bundle.v1",
        "place_id": place_id,
        "split": split,
        "sources": [
            {
                "evidence_id": "tour-description-01",
                "source_kind": "TOUR_API_DESCRIPTION",
                "source_sha256": tour_sha256,
                "span_sha256": tour_sha256,
                "text": tour_text,
            },
            {
                "evidence_id": "odii-transcript-01",
                "source_kind": "ODII_TRANSCRIPT",
                "source_sha256": odii_sha256,
                "span_sha256": odii_sha256,
                "text": odii_text,
            },
        ],
        "optional_image": None,
        "source_inventory_sha256": SHA[4],
    }
    _, _, _, _, _, _, seal = _contracts()
    return seal(payload, digest_field="source_bundle_sha256")


def _profile_payload(*, place_id: str = "canonical-dev-01") -> dict[str, object]:
    _, _, _, _, Pricing, _, _ = _contracts()
    payload: dict[str, object] = {
        "schema_version": "itda.demo-model-derived-profile.v1",
        "analysis_origin": "DEMO_MODEL_DERIVED",
        "place_id": place_id,
        "split": "DEV",
        "axis_scores": AXES,
        "subattributes": SUBATTRIBUTES,
        "mismatch_traits": MISMATCH,
        "evidence_ids": ["tour-description-01", "odii-transcript-01"],
        "confidence": 78,
        "publishable": True,
        "model": "glm-5v-turbo",
        "prompt_version": "phase5-demo-profile.v1",
        "prompt_sha256": SHA[0],
        "profile_schema_sha256": SHA[1],
        "config_sha256": SHA[2],
        "source_bundle_sha256": SHA[3],
        "evidence_inventory_sha256": SHA[4],
        "request_sha256": SHA[5],
        "response_sha256": SHA[6],
        "pricing_snapshot_sha256": Pricing().pricing_snapshot_sha256,
        "created_at": NOW.isoformat().replace("+00:00", "Z"),
    }
    _, _, _, _, _, _, seal = _contracts()
    return seal(payload, digest_field="profile_sha256")


def test_contract_config_freezes_provider_timeout_attempt_and_cost_policy() -> None:
    _, Config, _, _, Pricing, _, _ = _contracts()
    from itda.domain.canonical import canonical_sha256

    config = Config()

    assert config.endpoint == "https://api.z.ai/api/paas/v4/chat/completions"
    assert config.model == "glm-5v-turbo"
    assert config.authorization_scheme == "Bearer"
    assert config.max_tokens == 2048
    assert config.connect_seconds == 10
    assert config.pool_seconds == 10
    assert config.write_seconds == 30
    assert config.read_seconds == 180
    assert config.attempt_deadline_seconds == 300
    assert config.concurrency == 1
    assert config.follow_redirects is False
    assert config.trust_env is False
    assert config.max_http_attempts == 30
    assert config.max_run_cost_micro_usd == 5_000_000
    assert config.attempt_reservation_micro_usd == 248_192
    assert config.pricing == Pricing()
    assert canonical_sha256(config.model_dump(mode="json")) == (
        "794d02eeead0d4ae1ced93ba9322d511f9f82d2fb421c1ad70b20f9cb281ee13"
    )

    for field, value in (
        ("max_tokens", 2049),
        ("max_http_attempts", 31),
        ("max_run_cost_micro_usd", 5_000_001),
        ("attempt_deadline_seconds", 301),
    ):
        with pytest.raises(ValidationError):
            Config.model_validate({field: value})


def test_contract_derives_authorized_coding_plan_endpoint_without_changing_general_default() -> (
    None
):
    from itda.contracts.demo_profile_materialization import (
        CODING_PLAN_BASE_URL,
        CODING_PLAN_ENDPOINT,
        CODING_PLAN_ENTITLEMENT_EVIDENCE_SHA256,
        CodingPlanProfileMaterializationConfig,
        DemoProfileMaterializationConfig,
    )

    general = DemoProfileMaterializationConfig()
    coding = CodingPlanProfileMaterializationConfig.for_authorized_base(
        base_url=CODING_PLAN_BASE_URL,
        entitlement_evidence_sha256=CODING_PLAN_ENTITLEMENT_EVIDENCE_SHA256,
    )

    assert general.endpoint == "https://api.z.ai/api/paas/v4/chat/completions"
    assert coding.endpoint == CODING_PLAN_ENDPOINT
    assert coding.endpoint == "https://api.z.ai/api/coding/paas/v4/chat/completions"
    assert coding.model == "glm-5v-turbo"
    assert coding.provider_lane == "CODING_PLAN_SUBSCRIPTION"
    assert coding.accounting_mode == "CODING_PLAN_WEIGHT"
    assert coding.entitlement_evidence_sha256 == CODING_PLAN_ENTITLEMENT_EVIDENCE_SHA256
    assert coding.model_weight == 1

    for base_url, evidence_sha256 in (
        (
            "https://api.z.ai/api/coding/paas/v4/chat/completions",
            CODING_PLAN_ENTITLEMENT_EVIDENCE_SHA256,
        ),
        ("https://api.z.ai/api/coding/paas/v4/", CODING_PLAN_ENTITLEMENT_EVIDENCE_SHA256),
        (CODING_PLAN_BASE_URL, "0" * 64),
    ):
        with pytest.raises((ValidationError, ValueError)):
            CodingPlanProfileMaterializationConfig.for_authorized_base(
                base_url=base_url,
                entitlement_evidence_sha256=evidence_sha256,
            )


def test_contract_pricing_snapshot_and_category_ceiling_arithmetic() -> None:
    _, _, _, _, Pricing, Usage, _ = _contracts()
    pricing = Pricing()

    assert pricing.version == "zai-glm-5v-turbo-2026-08-10"
    assert pricing.source_url == "https://docs.z.ai/guides/overview/pricing"
    assert pricing.currency == "USD"
    assert pricing.billing_unit_tokens == 1_000_000
    assert pricing.uncached_input_rate_numerator == 1_200_000
    assert pricing.cached_input_rate_numerator == 240_000
    assert pricing.output_rate_numerator == 4_000_000
    assert pricing.cached_input_storage_label == "Limited-time Free"
    assert pricing.worst_case_input_tokens == 200_000
    assert pricing.max_output_tokens == 2048
    assert pricing.attempt_reservation_micro_usd == 248_192

    usage = Usage(prompt_tokens=3, completion_tokens=1, cached_tokens=2)
    charge = pricing.charge(usage)
    assert charge.uncached_input_micro_usd == 2
    assert charge.cached_input_micro_usd == 1
    assert charge.output_micro_usd == 4
    assert charge.total_micro_usd == 7


def test_contract_usage_rejects_missing_negative_inconsistent_and_over_limit_values() -> None:
    _, _, _, _, _, Usage, _ = _contracts()
    for payload in (
        {"prompt_tokens": 1, "completion_tokens": 1},
        {"prompt_tokens": -1, "completion_tokens": 1, "cached_tokens": 0},
        {"prompt_tokens": 1, "completion_tokens": 1, "cached_tokens": 2},
        {"prompt_tokens": 200_001, "completion_tokens": 1, "cached_tokens": 0},
        {"prompt_tokens": 1, "completion_tokens": 2049, "cached_tokens": 0},
    ):
        with pytest.raises(ValidationError):
            Usage.model_validate(payload)


def test_contract_source_bundle_is_dev_text_first_and_self_authenticating() -> None:
    _, _, _, SourceBundle, _, _, _ = _contracts()
    bundle = SourceBundle.model_validate(_source_payload())
    assert bundle.split == "DEV"
    assert tuple(source.source_kind for source in bundle.sources) == (
        "TOUR_API_DESCRIPTION",
        "ODII_TRANSCRIPT",
    )

    for mutation in ("blind", "unknown_source", "digest_drift"):
        hostile = _source_payload()
        if mutation == "blind":
            hostile["split"] = "BLIND"
        elif mutation == "unknown_source":
            hostile["sources"][0]["source_kind"] = "UNVERIFIED_WEB"
        else:
            hostile["source_bundle_sha256"] = SHA[9]
        with pytest.raises(ValidationError):
            SourceBundle.model_validate(hostile)


def test_contract_profile_requires_complete_scored_canonical_ordered_shape() -> None:
    Profile, _, _, _, _, _, seal = _contracts()
    restored = Profile.model_validate(_profile_payload())

    assert restored.analysis_origin == "DEMO_MODEL_DERIVED"
    assert restored.split == "DEV"
    assert tuple(restored.axis_scores) == ("H", "E", "R")
    assert tuple(restored.subattributes) == tuple(SUBATTRIBUTES)
    assert tuple(restored.mismatch_traits) == tuple(MISMATCH)
    assert restored.publishable is True

    for field, invalid in (
        ("axis_scores", {"H": 76, "E": 61}),
        ("subattributes", {key: value for key, value in SUBATTRIBUTES.items() if key != "R4"}),
        ("mismatch_traits", {key: value for key, value in MISMATCH.items() if key != "M6"}),
        ("split", "BLIND"),
        ("analysis_origin", "SOURCE_EVIDENCE_ONLY"),
        ("confidence", None),
    ):
        hostile = _profile_payload()
        hostile[field] = invalid
        hostile = seal(hostile, digest_field="profile_sha256")
        with pytest.raises(ValidationError):
            Profile.model_validate(hostile)


def test_contract_profile_rejects_unknown_evidence_extra_fields_and_image_observation() -> None:
    Profile, _, _, _, _, _, seal = _contracts()
    hostile = _profile_payload()
    hostile["evidence_ids"] = ["unknown-evidence"]
    hostile = seal(hostile, digest_field="profile_sha256")
    with pytest.raises(ValidationError):
        Profile.model_validate(hostile, context={"known_evidence_ids": {"tour-description-01"}})

    hostile = _profile_payload()
    hostile["unexpected"] = "forbidden"
    hostile = seal(hostile, digest_field="profile_sha256")
    with pytest.raises(ValidationError):
        Profile.model_validate(hostile)

    image_observation = {
        "schema_version": "photo-attributes.v2",
        "authority_scope": "CANDIDATE_EVIDENCE_ONLY",
    }
    with pytest.raises(ValidationError):
        Profile.model_validate(image_observation)


def test_contract_receipt_requires_all_24_profiles_and_matching_attempts() -> None:
    _, _, Receipt, _, Pricing, _, seal = _contracts()
    profile_digests = tuple(f"{index:064x}" for index in range(1, 25))
    attempt_digests = tuple(f"{index:064x}" for index in range(25, 49))
    payload: dict[str, object] = {
        "schema_version": "itda.demo-profile-materialization-receipt.v1",
        "status": "COMPLETE_REPLAY_ONLY",
        "analysis_origin": "DEMO_MODEL_DERIVED",
        "profile_count": 24,
        "profile_sha256": profile_digests,
        "attempt_sha256": attempt_digests,
        "pricing_snapshot_sha256": Pricing().pricing_snapshot_sha256,
        "committed_cost_micro_usd": 0,
        "outstanding_cost_micro_usd": 0,
        "generation_sha256": SHA[1],
    }
    receipt = Receipt.model_validate(seal(payload, digest_field="receipt_sha256"))
    assert receipt.profile_count == 24

    for field, invalid in (
        ("profile_count", 23),
        ("profile_sha256", profile_digests[:-1]),
        ("status", "ACTIVE_PUBLIC_RELEASE"),
    ):
        hostile = deepcopy(payload)
        hostile[field] = invalid
        hostile = seal(hostile, digest_field="receipt_sha256")
        with pytest.raises(ValidationError):
            Receipt.model_validate(hostile)


def test_contract_coding_plan_receipt_binds_endpoint_model_evidence_and_weight_not_paygo() -> None:
    from itda.contracts.demo_profile_materialization import (
        CODING_PLAN_AUTHORITY_SHA256,
        CODING_PLAN_ENDPOINT,
        CODING_PLAN_ENTITLEMENT_EVIDENCE_SHA256,
        CodingPlanProfileMaterializationReceipt,
        seal_demo_contract,
    )

    profile_digests = tuple(f"{index:064x}" for index in range(1, 25))
    attempt_digests = tuple(f"{index:064x}" for index in range(25, 49))
    payload: dict[str, object] = {
        "schema_version": "itda.coding-plan-profile-materialization-receipt.v1",
        "status": "COMPLETE_UNACTIVATED",
        "analysis_origin": "DEMO_MODEL_DERIVED",
        "profile_count": 24,
        "profile_sha256": profile_digests,
        "attempt_sha256": attempt_digests,
        "provider_lane": "CODING_PLAN_SUBSCRIPTION",
        "base_url": "https://api.z.ai/api/coding/paas/v4",
        "endpoint": CODING_PLAN_ENDPOINT,
        "model": "glm-5v-turbo",
        "accounting_mode": "CODING_PLAN_WEIGHT",
        "entitlement_evidence_sha256": CODING_PLAN_ENTITLEMENT_EVIDENCE_SHA256,
        "model_weight": 1,
        "subscription_attempt_count": 24,
        "subscription_total_weight": 24,
        "coding_plan_authority_sha256": CODING_PLAN_AUTHORITY_SHA256,
        "generation_sha256": SHA[1],
    }
    receipt = CodingPlanProfileMaterializationReceipt.model_validate(
        seal_demo_contract(payload, digest_field="receipt_sha256")
    )

    assert receipt.subscription_attempt_count == 24
    assert receipt.subscription_total_weight == 24
    assert receipt.coding_plan_authority_sha256 == CODING_PLAN_AUTHORITY_SHA256

    for field, invalid in (
        ("endpoint", "https://api.z.ai/api/paas/v4/chat/completions"),
        ("entitlement_evidence_sha256", "0" * 64),
        ("subscription_total_weight", 23),
        ("accounting_mode", "PAY_GO_MICRO_USD"),
    ):
        hostile = deepcopy(payload)
        hostile[field] = invalid
        with pytest.raises(ValidationError):
            CodingPlanProfileMaterializationReceipt.model_validate(
                seal_demo_contract(hostile, digest_field="receipt_sha256")
            )


def test_replay_fixture_is_sanitized_unmistakably_test_only_and_dev_24() -> None:
    fixture_path = Path("fixtures/synthetic/phase5/provider-profile-replay.json")
    raw = fixture_path.read_text(encoding="utf-8")
    payload = json.loads(raw)

    assert payload["fixture_scope"] == "SYNTHETIC_REPLAY_ONLY"
    assert len(payload["place_ids"]) == 24
    assert len(set(payload["place_ids"])) == 24
    assert payload["response_template"]["model"] == "glm-5v-turbo"
    assert payload["response_template"]["finish_reason"] == "stop"
    forbidden = (
        "bearer ",
        "api_key",
        "authorization",
        '"prompt":',
        "evidence_body",
        "raw_response",
        "protected_path",
        "blind",
        "active_public_release",
    )
    assert all(fragment not in raw.casefold() for fragment in forbidden)


def _source_inventory() -> tuple[object, ...]:
    _, _, _, SourceBundle, _, _, _ = _contracts()
    return tuple(
        SourceBundle.model_validate(_source_payload(place_id=f"canonical-dev-{index:02d}"))
        for index in range(1, 25)
    )


def test_pipeline_validates_exact_canonical_dev_inventory_and_rejects_partial_or_blind() -> None:
    from itda.pipeline.demo_profile_materialization import (
        validate_demo_source_bundle,
        validate_demo_source_inventory,
    )

    inventory = _source_inventory()
    validated = validate_demo_source_inventory(inventory)
    assert tuple(bundle.place_id for bundle in validated) == tuple(
        f"canonical-dev-{index:02d}" for index in range(1, 25)
    )
    assert all(validate_demo_source_bundle(bundle) == bundle for bundle in inventory)

    with pytest.raises(ValueError, match="24"):
        validate_demo_source_inventory(inventory[:-1])
    with pytest.raises(ValidationError):
        type(inventory[0]).model_validate(_source_payload(split="BLIND"))


def test_pipeline_replay_materializes_all_24_through_strict_candidate_path() -> None:
    from itda.pipeline.demo_profile_materialization import materialize_demo_profiles

    fixture = json.loads(
        Path("fixtures/synthetic/phase5/provider-profile-replay.json").read_text(encoding="utf-8")
    )
    result = materialize_demo_profiles(
        source_bundles=_source_inventory(),
        mode="replay",
        replay_fixture=fixture,
    )

    assert len(result.profiles) == 24
    assert len(result.attempts) == 24
    assert result.receipt.profile_count == 24
    assert result.receipt.status == "COMPLETE_REPLAY_ONLY"
    assert result.receipt.committed_cost_micro_usd == 0
    assert result.receipt.outstanding_cost_micro_usd == 0
    assert tuple(profile.place_id for profile in result.profiles) == tuple(fixture["place_ids"])


def test_pipeline_publish_is_private_fsynced_content_addressed_and_no_replace(
    tmp_path: Path,
) -> None:
    from itda.pipeline.demo_profile_materialization import (
        materialize_demo_profiles,
        publish_demo_profile_generation,
        verify_demo_profile_generation,
    )

    fixture = json.loads(
        Path("fixtures/synthetic/phase5/provider-profile-replay.json").read_text(encoding="utf-8")
    )
    result = materialize_demo_profiles(
        source_bundles=_source_inventory(),
        mode="replay",
        replay_fixture=fixture,
    )
    generation = publish_demo_profile_generation(result, output_root=tmp_path)

    assert generation.parent == tmp_path
    assert generation.stat().st_mode & 0o777 == 0o700
    assert all(path.stat().st_mode & 0o777 == 0o600 for path in generation.iterdir())
    assert verify_demo_profile_generation(generation) == result.receipt
    assert publish_demo_profile_generation(result, output_root=tmp_path) == generation

    profile_path = generation / "profiles.json"
    profile_path.chmod(0o600)
    profile_path.write_bytes(b"tampered")
    with pytest.raises(FileExistsError, match="differs"):
        publish_demo_profile_generation(result, output_root=tmp_path)


def test_terminal_failure_publishes_sanitized_attempt_and_exact_raw_bytes(
    tmp_path: Path,
) -> None:
    from itda.pipeline.demo_profile_materialization import (
        DemoProfileMaterializationFailure,
        publish_demo_profile_failure,
    )
    from itda.providers.zhipu_glm5v_profile import ZhipuGlm5vProfileAdapter

    raw = b'{"error":{"code":"provider_rejected","message":"bounded detail"}}'
    adapter = ZhipuGlm5vProfileAdapter(secret="must-never-be-persisted")
    result = adapter.consume_replay_chunks(
        place_id="canonical-dev-01",
        chunks=(raw,),
    )
    failure = DemoProfileMaterializationFailure(
        failed_place_id="canonical-dev-01",
        results=(result,),
        committed_cost_micro_usd=adapter.ledger.committed_micro_usd,
        outstanding_cost_micro_usd=adapter.ledger.outstanding_micro_usd,
    )

    published = publish_demo_profile_failure(failure, output_root=tmp_path)
    descriptor = json.loads((published / "failure.json").read_bytes())
    attempts = json.loads((published / "attempts.json").read_bytes())
    raw_path = published / f"raw-{result.attempt.attempt_sha256}.bin"

    assert descriptor["status"] == "FAILED_UNACTIVATED"
    assert descriptor["failed_place_ids"] == ["canonical-dev-01"]
    assert descriptor["attempt_count"] == 1
    assert attempts[0]["error_code"] == "PROVIDER_RESPONSE_TERMINAL_INVALID"
    assert raw_path.read_bytes() == raw
    assert published.stat().st_mode & 0o777 == 0o700
    assert all(path.stat().st_mode & 0o777 == 0o600 for path in published.iterdir())
    assert "must-never-be-persisted" not in repr(failure)
    assert publish_demo_profile_failure(failure, output_root=tmp_path) == published


def test_live_materializer_surfaces_pre_socket_budget_exhaustion_with_prior_evidence(
    tmp_path: Path,
) -> None:
    from itda.contracts.demo_profile_materialization import (
        RERUN_AUTHORITY_SHA256,
    )
    from itda.pipeline.demo_profile_materialization import (
        DemoProfileMaterializationFailure,
        DurableRerunJournal,
        materialize_live_demo_profiles,
    )
    from itda.providers.zhipu_glm5v_profile import (
        AttemptCostLedger,
        ZhipuGlm5vProfileAdapter,
    )

    adapter = ZhipuGlm5vProfileAdapter(
        secret="test-only-secret",
        ledger=AttemptCostLedger(committed_micro_usd=4_751_809),
        client_factory=lambda **_: (_ for _ in ()).throw(
            AssertionError("budget failure must happen before client construction")
        ),
    )
    journal = DurableRerunJournal(
        root=tmp_path / RERUN_AUTHORITY_SHA256,
        authority_receipt={"authority_sha256": RERUN_AUTHORITY_SHA256},
    )

    with pytest.raises(DemoProfileMaterializationFailure) as captured:
        asyncio.run(
            materialize_live_demo_profiles(
                source_bundles=_source_inventory(),
                adapter=adapter,
                journal=journal,
            )
        )

    assert captured.value.failure_code == "COST_BUDGET_EXHAUSTED"
    assert captured.value.results == ()
    assert captured.value.committed_cost_micro_usd == 4_751_809
    assert captured.value.outstanding_cost_micro_usd == 0


def test_client_factory_failure_returns_structured_result_and_settles_reservation(
    tmp_path: Path,
) -> None:
    from itda.contracts.demo_profile_materialization import (
        RERUN_AUTHORITY_SHA256,
        RERUN_COST_CAP_MICRO_USD,
    )
    from itda.pipeline.demo_profile_materialization import (
        DemoProfileMaterializationFailure,
        DurableRerunJournal,
        materialize_live_demo_profiles,
    )
    from itda.providers.zhipu_glm5v_profile import (
        ATTEMPT_RESERVATION_MICRO_USD,
        AttemptCostLedger,
        ZhipuGlm5vProfileAdapter,
    )

    secret = "factory-secret-must-not-escape"

    def factory(**_: object) -> object:
        raise RuntimeError(f"factory failed for {secret}")

    ledger = AttemptCostLedger(max_cost_micro_usd=RERUN_COST_CAP_MICRO_USD)
    adapter = ZhipuGlm5vProfileAdapter(
        secret=secret,
        ledger=ledger,
        client_factory=factory,
    )
    journal = DurableRerunJournal(
        root=tmp_path / "rerun-journal",
        authority_receipt={"authority_sha256": RERUN_AUTHORITY_SHA256},
    )
    with pytest.raises(DemoProfileMaterializationFailure) as captured:
        asyncio.run(
            materialize_live_demo_profiles(
                source_bundles=_source_inventory(),
                adapter=adapter,
                journal=journal,
            )
        )

    assert captured.value.failure_code == "PROFILE_TERMINAL_FAILURE"
    assert ledger.outstanding_micro_usd == 0
    assert ledger.committed_micro_usd == 24 * ATTEMPT_RESERVATION_MICRO_USD
    terminal = json.loads((journal.root / "terminal" / "terminal.json").read_bytes())
    assert terminal["failure_code"] == "PROFILE_TERMINAL_FAILURE"
    assert terminal["attempt_count"] == 24
    persisted = b"".join(path.read_bytes() for path in journal.root.rglob("*.*"))
    assert secret.encode() not in persisted


def test_rerun_journal_fsyncs_each_attempt_and_redacts_secret_echo(tmp_path: Path) -> None:
    from itda.contracts.demo_profile_materialization import RERUN_AUTHORITY_SHA256
    from itda.pipeline.demo_profile_materialization import DurableRerunJournal
    from itda.providers.zhipu_glm5v_profile import ZhipuGlm5vProfileAdapter

    secret = b"secret-must-not-survive"
    raw = b'{"error":"secret-must-not-survive"}'
    adapter = ZhipuGlm5vProfileAdapter(secret=secret.decode())
    result = adapter.consume_replay_chunks(place_id="canonical-dev-01", chunks=(raw,))
    authority = {
        "schema_version": "itda.phase5-zai-rerun-authority.v1",
        "authority_sha256": RERUN_AUTHORITY_SHA256,
    }
    journal = DurableRerunJournal(
        root=tmp_path / RERUN_AUTHORITY_SHA256,
        authority_receipt=authority,
    )
    started = datetime(2026, 8, 10, 1, 2, 3, tzinfo=UTC)
    completed = datetime(2026, 8, 10, 1, 2, 4, tzinfo=UTC)
    published = journal.record_attempt(
        result,
        started_at=started,
        completed_at=completed,
        redaction_token=secret,
    )
    record = json.loads((published / "attempt.json").read_bytes())

    assert record["started_at"] == "2026-08-10T01:02:03Z"
    assert record["completed_at"] == "2026-08-10T01:02:04Z"
    assert record["raw_response_redacted"] is True
    assert (published / "raw-response.bin").read_bytes() == b'{"error":"[REDACTED]"}'
    assert secret not in b"".join(path.read_bytes() for path in published.iterdir())
    assert all(path.stat().st_mode & 0o777 == 0o600 for path in published.iterdir())
    with pytest.raises(PermissionError, match="already been consumed"):
        journal.require_pristine()


def test_provider_1113_stops_after_one_attempt_and_persists_terminal_evidence(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    from itda.contracts.demo_profile_materialization import (
        RERUN_AUTHORITY_SHA256,
        RERUN_COST_CAP_MICRO_USD,
    )
    from itda.pipeline.demo_profile_materialization import (
        DemoProfileMaterializationFailure,
        DurableRerunJournal,
        materialize_live_demo_profiles,
    )
    from itda.providers.zhipu_glm5v_profile import (
        AttemptCostLedger,
        ZhipuGlm5vProfileAdapter,
    )

    secret = "secret-never-persist-or-log"
    raw = b'{"error":{"code":"1113","message":"Insufficient balance"}}'
    requests = 0

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal requests
        requests += 1
        return httpx.Response(429, content=raw, request=request)

    def factory(**kwargs: object) -> httpx.AsyncClient:
        return httpx.AsyncClient(
            transport=httpx.MockTransport(handler),
            headers=kwargs["headers"],  # type: ignore[arg-type]
            timeout=kwargs["timeout"],  # type: ignore[arg-type]
        )

    ledger = AttemptCostLedger(max_cost_micro_usd=RERUN_COST_CAP_MICRO_USD)
    adapter = ZhipuGlm5vProfileAdapter(
        secret=secret,
        ledger=ledger,
        client_factory=factory,
    )
    journal = DurableRerunJournal(
        root=tmp_path / RERUN_AUTHORITY_SHA256,
        authority_receipt={"authority_sha256": RERUN_AUTHORITY_SHA256},
    )

    with pytest.raises(DemoProfileMaterializationFailure) as captured:
        asyncio.run(
            materialize_live_demo_profiles(
                source_bundles=_source_inventory(),
                adapter=adapter,
                journal=journal,
                redaction_token=secret.encode(),
                rerun_authority_sha256=RERUN_AUTHORITY_SHA256,
            )
        )

    attempt_files = tuple((journal.root / "attempts").glob("*/attempt.json"))
    raw_files = tuple((journal.root / "attempts").glob("*/raw-response.bin"))
    terminal = json.loads((journal.root / "terminal/terminal.json").read_bytes())
    persisted = b"".join(path.read_bytes() for path in journal.root.rglob("*.*"))

    assert requests == 1
    assert len(captured.value.results) == 1
    assert captured.value.results[0].attempt.error_code == "HTTP_429_PROVIDER_1113"
    assert captured.value.results[0].retry is False
    assert ledger.committed_micro_usd == 248_192
    assert ledger.outstanding_micro_usd == 0
    assert len(attempt_files) == 1
    assert len(raw_files) == 1 and raw_files[0].read_bytes() == raw
    assert terminal["failure_code"] == "PROVIDER_ACCOUNT_BALANCE_UNAVAILABLE"
    assert terminal["attempt_count"] == 1
    assert secret.encode() not in persisted
    captured_output = capsys.readouterr()
    assert secret not in captured_output.out + captured_output.err


def _coding_plan_chat_response() -> bytes:
    content = {
        "axis_scores": AXES,
        "subattributes": SUBATTRIBUTES,
        "mismatch_traits": MISMATCH,
        "evidence_ids": ["tour-description-01", "odii-transcript-01"],
        "confidence": 78,
        "publishable": True,
    }
    return json.dumps(
        {
            "model": "glm-5v-turbo",
            "choices": [
                {
                    "finish_reason": "stop",
                    "message": {
                        "role": "assistant",
                        "content": json.dumps(content, ensure_ascii=False),
                    },
                }
            ],
            "usage": {
                "prompt_tokens": 1_000,
                "completion_tokens": 100,
                "prompt_tokens_details": {"cached_tokens": 200},
            },
        },
        ensure_ascii=False,
    ).encode("utf-8")


def test_coding_plan_first_attempt_is_single_probe_and_failure_stops_before_dev24(
    tmp_path: Path,
) -> None:
    from itda.contracts.demo_profile_materialization import (
        CODING_PLAN_AUTHORITY_SHA256,
        CODING_PLAN_BASE_URL,
        CODING_PLAN_ENTITLEMENT_EVIDENCE_SHA256,
        CodingPlanProfileMaterializationConfig,
    )
    from itda.pipeline.demo_profile_materialization import (
        DemoProfileMaterializationFailure,
        DurableCodingPlanJournal,
        materialize_live_demo_profiles,
    )
    from itda.providers.zhipu_glm5v_profile import (
        CodingPlanAttemptLedger,
        ZhipuGlm5vProfileAdapter,
    )

    requests = 0
    raw = b'{"error":{"code":"invalid_request","message":"probe rejected"}}'

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal requests
        requests += 1
        return httpx.Response(422, content=raw, request=request)

    def factory(**kwargs: object) -> httpx.AsyncClient:
        return httpx.AsyncClient(
            transport=httpx.MockTransport(handler),
            headers=kwargs["headers"],  # type: ignore[arg-type]
            timeout=kwargs["timeout"],  # type: ignore[arg-type]
        )

    config = CodingPlanProfileMaterializationConfig.for_authorized_base(
        base_url=CODING_PLAN_BASE_URL,
        entitlement_evidence_sha256=CODING_PLAN_ENTITLEMENT_EVIDENCE_SHA256,
    )
    ledger = CodingPlanAttemptLedger()
    adapter = ZhipuGlm5vProfileAdapter(
        secret="never-persist",
        config=config,
        coding_plan_ledger=ledger,
        client_factory=factory,
    )
    journal = DurableCodingPlanJournal(
        root=tmp_path / "coding-plan" / CODING_PLAN_AUTHORITY_SHA256,
        authority_receipt={"authority_sha256": CODING_PLAN_AUTHORITY_SHA256},
    )

    with pytest.raises(DemoProfileMaterializationFailure) as captured:
        asyncio.run(
            materialize_live_demo_profiles(
                source_bundles=_source_inventory(),
                adapter=adapter,
                journal=journal,
                redaction_token=b"never-persist",
                coding_plan_authority_sha256=CODING_PLAN_AUTHORITY_SHA256,
                require_first_probe_valid=True,
            )
        )

    assert requests == 1
    assert ledger.attempt_count == 1
    assert ledger.total_weight == 1
    assert captured.value.failure_code == "CODING_PLAN_PROBE_FAILED"
    assert len(captured.value.results) == 1
    assert (journal.root / "attempts").is_dir()
    terminal = json.loads((journal.root / "terminal/terminal.json").read_bytes())
    assert terminal["attempt_count"] == 1
    assert terminal["subscription_total_weight"] == 1
    assert terminal["coding_plan_authority_sha256"] == CODING_PLAN_AUTHORITY_SHA256


def test_coding_plan_valid_probe_continues_exact_dev24_with_weight_receipt(
    tmp_path: Path,
) -> None:
    from itda.contracts.demo_profile_materialization import (
        CODING_PLAN_AUTHORITY_SHA256,
        CODING_PLAN_BASE_URL,
        CODING_PLAN_ENTITLEMENT_EVIDENCE_SHA256,
        CodingPlanProfileMaterializationConfig,
        CodingPlanProfileMaterializationReceipt,
    )
    from itda.pipeline.demo_profile_materialization import (
        DurableCodingPlanJournal,
        materialize_live_demo_profiles,
    )
    from itda.providers.zhipu_glm5v_profile import (
        CodingPlanAttemptLedger,
        ZhipuGlm5vProfileAdapter,
    )

    requests = 0
    raw = _coding_plan_chat_response()

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal requests
        requests += 1
        return httpx.Response(200, content=raw, request=request)

    def factory(**kwargs: object) -> httpx.AsyncClient:
        return httpx.AsyncClient(
            transport=httpx.MockTransport(handler),
            headers=kwargs["headers"],  # type: ignore[arg-type]
            timeout=kwargs["timeout"],  # type: ignore[arg-type]
        )

    config = CodingPlanProfileMaterializationConfig.for_authorized_base(
        base_url=CODING_PLAN_BASE_URL,
        entitlement_evidence_sha256=CODING_PLAN_ENTITLEMENT_EVIDENCE_SHA256,
    )
    ledger = CodingPlanAttemptLedger()
    adapter = ZhipuGlm5vProfileAdapter(
        secret="never-persist",
        config=config,
        coding_plan_ledger=ledger,
        client_factory=factory,
    )
    journal = DurableCodingPlanJournal(
        root=tmp_path / "coding-plan" / CODING_PLAN_AUTHORITY_SHA256,
        authority_receipt={"authority_sha256": CODING_PLAN_AUTHORITY_SHA256},
    )
    result = asyncio.run(
        materialize_live_demo_profiles(
            source_bundles=_source_inventory(),
            adapter=adapter,
            journal=journal,
            coding_plan_authority_sha256=CODING_PLAN_AUTHORITY_SHA256,
            require_first_probe_valid=True,
        )
    )

    assert requests == 24
    assert ledger.attempt_count == 24
    assert ledger.total_weight == 24
    assert len(result.profiles) == 24
    assert len(result.attempts) == 24
    assert isinstance(result.receipt, CodingPlanProfileMaterializationReceipt)
    assert result.receipt.subscription_attempt_count == 24
    assert result.receipt.subscription_total_weight == 24
    assert result.receipt.coding_plan_authority_sha256 == CODING_PLAN_AUTHORITY_SHA256
    assert len(result.raw_responses) == 24
