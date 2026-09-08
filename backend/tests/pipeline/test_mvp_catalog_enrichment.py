from __future__ import annotations

import json
from pathlib import Path

import httpx
import pytest
from pydantic import ValidationError

from itda.cli import collect_mvp_public_catalog
from itda.collectors import base as collector_base
from itda.collectors.kto import KorService2Client
from itda.contracts.mvp_catalog_enrichment import (
    MvpCatalogEnrichmentPlan,
    MvpCatalogEnrichmentResult,
    TourApiDiagnosticCanaryPlan,
    TourApiDiagnosticCanaryResult,
)
from itda.contracts.mvp_public_catalog import OfficialDatasetPermissionMetadata
from itda.domain.canonical import canonical_json_bytes
from itda.pipeline.mvp_catalog_enrichment import (
    APPROVAL_PREFIX,
    CANARY_APPROVAL_PREFIX,
    RESPONSE_BODY_MAX_BYTES,
    EnrichmentResponse,
    TourApiDetailTransport,
    build_diagnostic_canary_plan,
    build_enrichment_plan,
    run_diagnostic_canary,
    run_enrichment,
    validate_canary_approval,
    validate_collection_approval,
)
from itda.pipeline.offline_guard import LiveCollectionRefused

REPO_ROOT = Path(__file__).resolve().parents[3]
SOURCE_UNIVERSE = (
    REPO_ROOT
    / "artifacts/catalog/optional-media-v2/policy"
    / "573e21213f7c0d157e33c7a510b9bcdb612dd517dfc70ba506ef7281ca0e9243"
    / "projected-candidates.json"
)
OFFICIAL_PERMISSION_ROOT = (
    REPO_ROOT / "artifacts/public/catalog/official-permission-snapshots"
)
CONSUMED_RESULT_PATH = (
    REPO_ROOT
    / "artifacts/public/catalog/mvp-public-enrichment-runs"
    / "dc5f4adea93b0e94ebe597bdaf6e140bea73a09a70a8909ef43f7735b88277ce"
    / "result.json"
)
V4_PLAN_PATH = REPO_ROOT / "artifacts/public/catalog/mvp-public-enrichment-plan-v4.json"
V4_RESULT_PATH = (
    REPO_ROOT
    / "artifacts/public/catalog/mvp-public-enrichment-runs"
    / "73f3911e324067bf09a1c35554885605e87d9700e04987f7ba90e5eff865526b"
    / "result.json"
)
V1_CANARY_RESULT_PATH = (
    REPO_ROOT / "artifacts/public/catalog/tourapi-diagnostic-canary-result-v1.json"
)
V2_CANARY_RESULT_PATH = (
    REPO_ROOT / "artifacts/public/catalog/tourapi-diagnostic-canary-result-v2.json"
)
V5_PLAN_PATH = REPO_ROOT / "artifacts/public/catalog/mvp-public-enrichment-plan-v5.json"
V5_RESULT_PATH = (
    REPO_ROOT
    / "artifacts/public/catalog/mvp-public-enrichment-runs"
    / "7a70a63b472980b12afa17250be87aab7cefc1d26204ffb65ddb858f8c6aaeb9"
    / "result.json"
)


def _official_permissions() -> tuple[
    tuple[OfficialDatasetPermissionMetadata, ...],
    dict[str, bytes],
]:
    permissions = tuple(
        OfficialDatasetPermissionMetadata.model_validate_json(
            (OFFICIAL_PERMISSION_ROOT / f"{dataset}.metadata.json").read_bytes()
        )
        for dataset in ("15101578", "15101971")
    )
    snapshots = {
        row.metadata_sha256: (
            OFFICIAL_PERMISSION_ROOT / f"{row.official_dataset_id}.raw"
        ).read_bytes()
        for row in permissions
    }
    return permissions, snapshots


def _consumed_result() -> MvpCatalogEnrichmentResult:
    return MvpCatalogEnrichmentResult.model_validate_json(CONSUMED_RESULT_PATH.read_bytes())


def _build_plan(source: Path, *, spare_count: int = 20) -> MvpCatalogEnrichmentPlan:
    permissions, snapshots = _official_permissions()
    return build_enrichment_plan(
        source,
        permissions=permissions,
        permission_snapshots=snapshots,
        previous_attempt_result=_consumed_result(),
        successful_canary_result=TourApiDiagnosticCanaryResult.model_validate_json(
            V2_CANARY_RESULT_PATH.read_bytes()
        ),
        spare_count=spare_count,
    )


def _build_v6_plan(source: Path = SOURCE_UNIVERSE) -> MvpCatalogEnrichmentPlan:
    permissions, snapshots = _official_permissions()
    return build_enrichment_plan(
        source,
        permissions=permissions,
        permission_snapshots=snapshots,
        previous_attempt_result=MvpCatalogEnrichmentResult.model_validate_json(
            V5_RESULT_PATH.read_bytes()
        ),
        successful_canary_result=TourApiDiagnosticCanaryResult.model_validate_json(
            V2_CANARY_RESULT_PATH.read_bytes()
        ),
    )


def _build_synthetic_v6_plan(tmp_path: Path) -> MvpCatalogEnrichmentPlan:
    payload = json.loads(SOURCE_UNIVERSE.read_bytes())
    payload["candidates"].append({"synthetic_non_candidate": True})
    source = tmp_path / "synthetic-v6-source.json"
    source.write_text(json.dumps(payload), encoding="utf-8")
    return _build_v6_plan(source)


class FakeTransport:
    def __init__(self, bodies: dict[str, bytes | EnrichmentResponse | Exception]) -> None:
        self.bodies = bodies
        self.calls: list[str] = []

    def fetch(self, request: object) -> EnrichmentResponse:
        content_id = request.provider_content_id  # type: ignore[attr-defined]
        self.calls.append(content_id)
        value = self.bodies[content_id]
        if isinstance(value, Exception):
            raise value
        if isinstance(value, EnrichmentResponse):
            return value
        return EnrichmentResponse(body=value)

    def close(self) -> None:
        return None


def _response(content_id: str, overview: str | None = "공개 관광 설명") -> bytes:
    item: dict[str, str] = {"contentid": content_id, "title": f"관광지 {content_id}"}
    if overview is not None:
        item["overview"] = overview
    return json.dumps(
        {"response": {"body": {"items": {"item": [item]}}}},
        ensure_ascii=False,
    ).encode()


def _write_source(path: Path, *, description_ready: int, gap_candidates: int) -> Path:
    rows: list[dict[str, object]] = []
    for index in range(description_ready):
        rows.append(
            {
                "place_entity_id": f"place:{index:064x}",
                "provider_place_candidate_id": f"candidate:tour-api:q{index}",
                "source_row_sha256": f"{index:064x}",
                "non_image_gates": {
                    "canonical_identity": "PASS",
                    "coordinates": "PASS",
                    "dataset_rights": "PASS",
                    "description": "PASS",
                },
            }
        )
    for ordinal in range(gap_candidates):
        index = description_ready + ordinal
        rows.append(
            {
                "place_entity_id": f"place:{index:064x}",
                "provider_place_candidate_id": f"candidate:tour-api:{1000 + index}",
                "source_row_sha256": f"{index:064x}",
                "non_image_gates": {
                    "canonical_identity": "PASS",
                    "coordinates": "PASS",
                    "dataset_rights": "PASS",
                    "description": "MISSING",
                },
            }
        )
    path.write_text(json.dumps({"candidates": rows}), encoding="utf-8")
    return path


def test_real_tracked_plan_is_deterministic_gap_plus_spares() -> None:
    first = _build_plan(SOURCE_UNIVERSE)
    second = _build_plan(SOURCE_UNIVERSE)

    assert first == second
    assert first.schema_version == "mvp-public-catalog-enrichment-plan.v5"
    assert first.parser_contract_version == "provider-envelope.v1"
    assert first.previous_attempt_result_sha256 == (
        "5504aca4abdc16714142269fcd97b67ad56bfa0ca2fd2155f10871530014c638"
    )
    assert first.request_grammar_version == "detail-common-fixed.v1"
    assert first.successful_canary_result_sha256 == (
        "c6c7a89ef4d2a94ca9390e5a286987378c79f33a00644926fe7a0ededf66aa30"
    )
    assert first.strict_rights_state == "PERMISSION_METADATA_VERIFIED"
    assert tuple(row.official_dataset_id for row in first.permission_bindings) == (
        "15101578",
        "15101971",
    )
    assert first.description_ready_historical_count == 40
    assert first.description_success_required == 60
    assert first.spare_count == 20
    assert first.max_requests == len(first.requests) == 80
    assert len({row.place_entity_id for row in first.requests}) == 80
    assert len({row.provider_content_id for row in first.requests}) == 80
    assert all(row.provider == "TOUR_API" for row in first.requests)
    assert all(row.operation == "detailCommon2" for row in first.requests)
    serialized = canonical_json_bytes(first.model_dump(mode="json"))
    for forbidden in (b"secret", b"api_key", b"authorization", b"openrouter", b"blind"):
        assert forbidden not in serialized.lower()


def test_real_v5_result_builds_disjoint_v6_continuation() -> None:
    permissions, snapshots = _official_permissions()
    v5_plan = MvpCatalogEnrichmentPlan.model_validate_json(V5_PLAN_PATH.read_bytes())
    v5_result = MvpCatalogEnrichmentResult.model_validate_json(V5_RESULT_PATH.read_bytes())

    plan = build_enrichment_plan(
        SOURCE_UNIVERSE,
        permissions=permissions,
        permission_snapshots=snapshots,
        previous_attempt_result=v5_result,
        successful_canary_result=TourApiDiagnosticCanaryResult.model_validate_json(
            V2_CANARY_RESULT_PATH.read_bytes()
        ),
    )

    assert plan.schema_version == "mvp-public-catalog-enrichment-plan.v6"
    assert plan.previous_attempt_result_sha256 == v5_result.result_sha256
    assert plan.description_ready_historical_count == 0
    assert plan.carried_success_count == 77
    assert plan.description_success_required == 23
    assert plan.spare_count == 20
    assert plan.max_requests == len(plan.requests) == 43
    assert {row.place_entity_id for row in plan.requests}.isdisjoint(
        row.place_entity_id for row in v5_plan.requests
    )


def test_plan_rejects_unbound_previous_attempt(tmp_path: Path) -> None:
    source = _write_source(tmp_path / "source.json", description_ready=99, gap_candidates=1)
    permissions, snapshots = _official_permissions()
    drifted = _consumed_result().model_copy(update={"plan_sha256": "0" * 64})

    with pytest.raises(ValueError, match="consumed collection plan"):
        build_enrichment_plan(
            source,
            permissions=permissions,
            permission_snapshots=snapshots,
            previous_attempt_result=drifted,
            successful_canary_result=TourApiDiagnosticCanaryResult.model_validate_json(
                V2_CANARY_RESULT_PATH.read_bytes()
            ),
            spare_count=0,
        )


def test_plan_rejects_unsuccessful_canary(tmp_path: Path) -> None:
    source = _write_source(tmp_path / "source.json", description_ready=99, gap_candidates=1)
    permissions, snapshots = _official_permissions()
    unsuccessful = TourApiDiagnosticCanaryResult.model_validate_json(
        V1_CANARY_RESULT_PATH.read_bytes()
    )

    with pytest.raises(ValueError, match="corrected canary"):
        build_enrichment_plan(
            source,
            permissions=permissions,
            permission_snapshots=snapshots,
            previous_attempt_result=_consumed_result(),
            successful_canary_result=unsuccessful,
            spare_count=0,
        )


def test_plan_rejects_permission_snapshot_drift_before_requests(tmp_path: Path) -> None:
    source = _write_source(tmp_path / "source.json", description_ready=99, gap_candidates=1)
    permissions, snapshots = _official_permissions()
    drifted = dict(snapshots)
    drifted[permissions[0].metadata_sha256] += b" drift"

    with pytest.raises(ValueError, match="hash does not match"):
        build_enrichment_plan(
            source,
            permissions=permissions,
            permission_snapshots=drifted,
            previous_attempt_result=_consumed_result(),
            successful_canary_result=TourApiDiagnosticCanaryResult.model_validate_json(
                V2_CANARY_RESULT_PATH.read_bytes()
            ),
            spare_count=0,
        )


def test_plan_uses_spares_after_empty_descriptions_and_closes_gap(tmp_path: Path) -> None:
    source = _write_source(tmp_path / "source.json", description_ready=40, gap_candidates=80)
    plan = _build_plan(source)
    bodies = {
        row.provider_content_id: _response(
            row.provider_content_id,
            None if index < 20 else f"공개 설명 {index}",
        )
        for index, row in enumerate(plan.requests)
    }

    result = run_enrichment(plan, transport=FakeTransport(bodies), output_root=tmp_path / "out")

    assert result.attempted_count == 80
    assert result.successful_count == 60
    assert result.description_gap_remaining == 0
    assert result.strict_rights_state == "PERMISSION_METADATA_VERIFIED"
    assert result.catalog_ready is False
    assert result.public_artifact_written is False
    assert collect_mvp_public_catalog._execution_exit_code(result) == 2
    assert len(tuple((tmp_path / "out/responses").glob("*.json"))) == 60


def test_cli_prints_description_only_gap_and_never_catalog_ready(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    plan = _build_synthetic_v6_plan(tmp_path)
    plan_path = tmp_path / "plan.json"
    plan_path.write_bytes(canonical_json_bytes(plan.model_dump(mode="json")))
    transport = FakeTransport(
        {
            row.provider_content_id: _response(row.provider_content_id)
            for row in plan.requests
        }
    )

    monkeypatch.setattr(
        collect_mvp_public_catalog,
        "TourApiDetailTransport",
        lambda service_key: transport,
    )
    monkeypatch.delenv("ITDA_OFFLINE", raising=False)
    monkeypatch.delenv("ITDA_NO_NETWORK", raising=False)
    monkeypatch.delenv("CI", raising=False)
    monkeypatch.setenv("TOUR_API_SERVICE_KEY", "synthetic-test-key")

    exit_code = collect_mvp_public_catalog.main(
        [
            "execute",
            str(plan_path),
            "--expected-plan-sha256",
            plan.plan_sha256,
            "--approval",
            f"{APPROVAL_PREFIX}{plan.plan_sha256}",
            "--output-root",
            str(tmp_path / "out"),
            "--live",
        ]
    )

    output = capsys.readouterr().out
    assert exit_code == 2
    assert "description_gap_remaining=0" in output
    assert "catalog_ready=false" in output
    assert "public_artifact_written=false" in output
    assert "remaining_gap=" not in output.replace("description_gap_remaining=", "")


def test_insufficient_enrichment_reports_truthful_remaining_gap(tmp_path: Path) -> None:
    source = _write_source(tmp_path / "source.json", description_ready=40, gap_candidates=80)
    plan = _build_plan(source)
    bodies = {
        row.provider_content_id: _response(
            row.provider_content_id,
            "설명" if index < 30 else None,
        )
        for index, row in enumerate(plan.requests)
    }

    result = run_enrichment(plan, transport=FakeTransport(bodies), output_root=tmp_path / "out")

    assert result.successful_count == 30
    assert result.description_gap_remaining == 30
    assert not (tmp_path / "out/public-place-catalog.json").exists()


@pytest.mark.parametrize(
    ("body", "reason"),
    [
        (b"not json", "MALFORMED_RESPONSE"),
        (_response("other-id"), "CONTENT_ID_MISMATCH"),
        (b"{" + b'\"x\":\"' + b"x" * RESPONSE_BODY_MAX_BYTES + b'\"}', "RESPONSE_BODY_LIMIT"),
    ],
)
def test_response_failures_are_sanitized_and_do_not_persist_raw(
    tmp_path: Path,
    body: bytes,
    reason: str,
) -> None:
    source = _write_source(tmp_path / "source.json", description_ready=99, gap_candidates=1)
    plan = _build_plan(source, spare_count=0)
    row = plan.requests[0]

    result = run_enrichment(
        plan,
        transport=FakeTransport({row.provider_content_id: body}),
        output_root=tmp_path / "out",
    )

    assert result.outcomes[0].reason == reason
    assert result.outcomes[0].raw_response_sha256 is None
    assert not (tmp_path / "out/responses").exists()


@pytest.mark.parametrize(
    "response",
    [
        EnrichmentResponse(
            body=json.dumps(
                {
                    "response": {
                        "header": {
                            "resultCode": "30",
                            "resultMsg": "SERVICE KEY IS NOT REGISTERED ERROR.",
                        }
                    }
                }
            ).encode()
        ),
        EnrichmentResponse(
            body=(
                b"<OpenAPI_ServiceResponse><cmmMsgHeader>"
                b"<returnReasonCode>30</returnReasonCode>"
                b"<returnAuthMsg>SERVICE KEY IS NOT REGISTERED ERROR.</returnAuthMsg>"
                b"</cmmMsgHeader></OpenAPI_ServiceResponse>"
            ),
            content_type="application/xml",
        ),
        EnrichmentResponse(body=b'{"response":{"body":{"items":""}}}'),
    ],
)
def test_provider_error_envelope_is_not_reported_as_empty_description(
    tmp_path: Path,
    response: EnrichmentResponse,
) -> None:
    source = _write_source(tmp_path / "source.json", description_ready=99, gap_candidates=1)
    plan = _build_plan(source, spare_count=0)
    row = plan.requests[0]

    result = run_enrichment(
        plan,
        transport=FakeTransport({row.provider_content_id: response}),
        output_root=tmp_path / "out",
    )

    assert result.outcomes[0].status == "FAILED"
    assert result.outcomes[0].reason == "PROVIDER_REJECTED"
    assert result.outcomes[0].raw_response_sha256 is None
    assert not (tmp_path / "out/responses").exists()


def test_success_envelope_without_overview_remains_empty_description(
    tmp_path: Path,
) -> None:
    source = _write_source(tmp_path / "source.json", description_ready=99, gap_candidates=1)
    plan = _build_plan(source, spare_count=0)
    row = plan.requests[0]
    payload = json.loads(_response(row.provider_content_id, None))
    payload["response"]["header"] = {"resultCode": "0000", "resultMsg": "OK"}

    result = run_enrichment(
        plan,
        transport=FakeTransport(
            {
                row.provider_content_id: json.dumps(payload).encode(),
            }
        ),
        output_root=tmp_path / "out",
    )

    assert result.outcomes[0].status == "EMPTY"
    assert result.outcomes[0].reason == "DESCRIPTION_EMPTY"


def _diagnostic_canary_plan(
    *,
    corrected: bool = False,
) -> TourApiDiagnosticCanaryPlan:
    enrichment_plan = MvpCatalogEnrichmentPlan.model_validate_json(V4_PLAN_PATH.read_bytes())
    enrichment_result = MvpCatalogEnrichmentResult.model_validate_json(
        V4_RESULT_PATH.read_bytes()
    )
    previous = (
        TourApiDiagnosticCanaryResult.model_validate_json(
            V1_CANARY_RESULT_PATH.read_bytes()
        )
        if corrected
        else None
    )
    return build_diagnostic_canary_plan(
        enrichment_plan,
        enrichment_result,
        previous_canary_result=previous,
    )


def test_diagnostic_canary_plan_is_bound_and_deterministic() -> None:
    consumed = _diagnostic_canary_plan()
    first = _diagnostic_canary_plan(corrected=True)
    second = _diagnostic_canary_plan(corrected=True)

    assert first == second
    assert first.schema_version == "tourapi-diagnostic-canary-plan.v2"
    assert first.request_grammar_version == "detail-common-fixed.v1"
    assert first.previous_canary_result_sha256 == (
        "9b9b305764ed14443cde5701a1d99acc72af775716712fb804955ebccf919a30"
    )
    assert first.max_requests == 1
    assert first.request == MvpCatalogEnrichmentPlan.model_validate_json(
        V4_PLAN_PATH.read_bytes()
    ).requests[0]
    assert first.enrichment_result_sha256 == (
        "603349b5eaee45ca79903bb4c10c7ac4df93864b2a97f8640df0a08af925755d"
    )
    with pytest.raises(PermissionError, match="consumed"):
        validate_canary_approval(
            consumed,
            expected_plan_sha256=consumed.plan_sha256,
            approval=f"{CANARY_APPROVAL_PREFIX}{consumed.plan_sha256}",
        )
    with pytest.raises(PermissionError, match="consumed"):
        validate_canary_approval(
            first,
            expected_plan_sha256=first.plan_sha256,
            approval=f"{CANARY_APPROVAL_PREFIX}{first.plan_sha256}",
        )


@pytest.mark.parametrize(
    ("body", "expected_code", "expected_outcome"),
    [
        (
            b'{"response":{"header":{"resultCode":"0000","resultMsg":"OK"}}}',
            "0000",
            "SUCCESS",
        ),
        (
            b'{"response":{"header":{"resultCode":"30","resultMsg":"REJECTED"}}}',
            "30",
            "TERMINAL_OPERATOR_ACTION",
        ),
        (b'{"response":{"body":{"items":""}}}', None, "MISSING_RESULT_CODE"),
        (b"not-json", None, "MALFORMED_RESPONSE"),
    ],
)
def test_diagnostic_canary_classifies_without_persisting_body(
    tmp_path: Path,
    body: bytes,
    expected_code: str | None,
    expected_outcome: str,
) -> None:
    plan = _diagnostic_canary_plan()
    result = run_diagnostic_canary(
        plan,
        transport=FakeTransport({plan.request.provider_content_id: body}),
        output_path=tmp_path / "canary-result.json",
    )

    assert result.provider_result_code == expected_code
    assert result.normalized_outcome == expected_outcome
    stored = (tmp_path / "canary-result.json").read_bytes()
    assert body not in stored
    assert result.raw_response_persisted is False


@pytest.mark.parametrize(
    ("value", "expected_outcome"),
    [
        (b"x" * (RESPONSE_BODY_MAX_BYTES + 1), "RESPONSE_BODY_LIMIT"),
        (RuntimeError("sensitive transport detail"), "TRANSPORT_FAILURE"),
    ],
)
def test_diagnostic_canary_sanitizes_local_failures(
    tmp_path: Path,
    value: bytes | Exception,
    expected_outcome: str,
) -> None:
    plan = _diagnostic_canary_plan()
    result = run_diagnostic_canary(
        plan,
        transport=FakeTransport({plan.request.provider_content_id: value}),
        output_path=tmp_path / "canary-result.json",
    )

    assert result.provider_result_code is None
    assert result.normalized_outcome == expected_outcome
    assert b"sensitive transport detail" not in (tmp_path / "canary-result.json").read_bytes()


def test_plan_rejects_duplicate_and_non_tourapi_candidates(tmp_path: Path) -> None:
    source = _write_source(tmp_path / "source.json", description_ready=99, gap_candidates=1)
    payload = json.loads(source.read_text())
    duplicate = dict(payload["candidates"][-1])
    payload["candidates"].append(duplicate)
    source.write_text(json.dumps(payload), encoding="utf-8")
    with pytest.raises(ValueError, match="duplicate enrichment identity"):
        _build_plan(source, spare_count=0)

    duplicate["provider_place_candidate_id"] = "candidate:odii:outside"
    payload["candidates"][-2] = duplicate
    payload["candidates"].pop()
    source.write_text(json.dumps(payload), encoding="utf-8")
    with pytest.raises(ValueError, match="not enough TourAPI"):
        _build_plan(source, spare_count=0)


def test_transport_exception_text_is_not_persisted(tmp_path: Path) -> None:
    source = _write_source(tmp_path / "source.json", description_ready=99, gap_candidates=1)
    plan = _build_plan(source, spare_count=0)
    row = plan.requests[0]
    sensitive = "serviceKey=must-not-appear"

    run_enrichment(
        plan,
        transport=FakeTransport({row.provider_content_id: RuntimeError(sensitive)}),
        output_root=tmp_path / "out",
    )

    stored = (tmp_path / "out/result.json").read_text(encoding="utf-8")
    assert sensitive not in stored
    assert "TRANSPORT_FAILURE" in stored


def test_plan_hash_and_collection_approval_are_exact(tmp_path: Path) -> None:
    source = _write_source(tmp_path / "source.json", description_ready=99, gap_candidates=1)
    plan = _build_plan(source, spare_count=0)

    v5_plan = MvpCatalogEnrichmentPlan.model_validate_json(V5_PLAN_PATH.read_bytes())
    consumed_v6_plan = MvpCatalogEnrichmentPlan.model_validate_json(
        (REPO_ROOT / "artifacts/public/catalog/mvp-public-enrichment-plan-v6.json").read_bytes()
    )
    v6_plan = _build_synthetic_v6_plan(tmp_path)
    validate_collection_approval(
        v6_plan,
        expected_plan_sha256=v6_plan.plan_sha256,
        approval=f"{APPROVAL_PREFIX}{v6_plan.plan_sha256}",
    )
    for consumed in (v5_plan, consumed_v6_plan):
        with pytest.raises(PermissionError, match="consumed"):
            validate_collection_approval(
                consumed,
                expected_plan_sha256=consumed.plan_sha256,
                approval=f"{APPROVAL_PREFIX}{consumed.plan_sha256}",
            )
    v3_plan = MvpCatalogEnrichmentPlan.model_validate_json(
        (REPO_ROOT / "artifacts/public/catalog/mvp-public-enrichment-plan-v3.json").read_bytes()
    )
    v4_plan = MvpCatalogEnrichmentPlan.model_validate_json(V4_PLAN_PATH.read_bytes())
    for superseded in (v3_plan, v4_plan):
        with pytest.raises(PermissionError, match="superseded"):
            validate_collection_approval(
                superseded,
                expected_plan_sha256=superseded.plan_sha256,
                approval=f"{APPROVAL_PREFIX}{superseded.plan_sha256}",
            )
    with pytest.raises(PermissionError, match="SHA-256 mismatch"):
        validate_collection_approval(
            v6_plan,
            expected_plan_sha256="0" * 64,
            approval=f"{APPROVAL_PREFIX}{v6_plan.plan_sha256}",
        )
    with pytest.raises(PermissionError, match="approval mismatch"):
        validate_collection_approval(
            v6_plan,
            expected_plan_sha256=v6_plan.plan_sha256,
            approval="approve-openrouter:" + v6_plan.plan_sha256,
        )

    payload = plan.model_dump(mode="json")
    payload["max_requests"] = 2
    with pytest.raises(ValidationError):
        MvpCatalogEnrichmentPlan.model_validate(payload)


def test_cli_offline_refuses_before_credential_or_client(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    plan = _build_synthetic_v6_plan(tmp_path)
    plan_path = tmp_path / "plan.json"
    plan_path.write_bytes(canonical_json_bytes(plan.model_dump(mode="json")))
    constructed = False

    class ForbiddenTransport:
        def __init__(self, service_key: str) -> None:
            nonlocal constructed
            constructed = True

    monkeypatch.setattr(collect_mvp_public_catalog, "TourApiDetailTransport", ForbiddenTransport)
    monkeypatch.setenv("ITDA_OFFLINE", "1")
    monkeypatch.delenv("TOUR_API_SERVICE_KEY", raising=False)

    with pytest.raises(LiveCollectionRefused, match="offline"):
        collect_mvp_public_catalog.main(
            [
                "execute",
                str(plan_path),
                "--expected-plan-sha256",
                plan.plan_sha256,
                "--approval",
                f"{APPROVAL_PREFIX}{plan.plan_sha256}",
                "--output-root",
                str(tmp_path / "out"),
                "--live",
            ]
        )
    assert constructed is False


def test_cli_requires_explicit_live_before_credential_or_client(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    plan = _build_synthetic_v6_plan(tmp_path)
    plan_path = tmp_path / "plan.json"
    plan_path.write_bytes(canonical_json_bytes(plan.model_dump(mode="json")))
    constructed = False

    class ForbiddenTransport:
        def __init__(self, service_key: str) -> None:
            nonlocal constructed
            constructed = True

    monkeypatch.setattr(collect_mvp_public_catalog, "TourApiDetailTransport", ForbiddenTransport)
    monkeypatch.delenv("ITDA_OFFLINE", raising=False)
    monkeypatch.delenv("ITDA_NO_NETWORK", raising=False)
    monkeypatch.delenv("CI", raising=False)
    monkeypatch.delenv("TOUR_API_SERVICE_KEY", raising=False)

    with pytest.raises(LiveCollectionRefused, match="explicit-opt-in-required"):
        collect_mvp_public_catalog.main(
            [
                "execute",
                str(plan_path),
                "--expected-plan-sha256",
                plan.plan_sha256,
                "--approval",
                f"{APPROVAL_PREFIX}{plan.plan_sha256}",
                "--output-root",
                str(tmp_path / "out"),
            ]
        )
    assert constructed is False


def test_cli_canary_offline_refuses_before_credential_or_client(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    canary = _diagnostic_canary_plan(corrected=True)
    plan_path = tmp_path / "canary-plan.json"
    plan_path.write_bytes(canonical_json_bytes(canary.model_dump(mode="json")))
    constructed = False

    class ForbiddenTransport:
        def __init__(self, service_key: str) -> None:
            nonlocal constructed
            constructed = True

    monkeypatch.setattr(collect_mvp_public_catalog, "TourApiDetailTransport", ForbiddenTransport)
    monkeypatch.delenv("ITDA_OFFLINE", raising=False)
    monkeypatch.delenv("ITDA_NO_NETWORK", raising=False)
    monkeypatch.delenv("CI", raising=False)
    monkeypatch.delenv("TOUR_API_SERVICE_KEY", raising=False)

    with pytest.raises(PermissionError, match="consumed"):
        collect_mvp_public_catalog.main(
            [
                "execute-canary",
                str(plan_path),
                "--expected-plan-sha256",
                canary.plan_sha256,
                "--approval",
                f"{CANARY_APPROVAL_PREFIX}{canary.plan_sha256}",
                "--output",
                str(tmp_path / "canary-result.json"),
                "--live",
            ]
        )
    assert constructed is False
    assert not (tmp_path / "canary-result.json").exists()


def test_live_transport_preserves_content_type_without_exposing_secret(
    tmp_path: Path,
) -> None:
    service_key = "synthetic-test-key"
    plan = _build_plan(
        _write_source(tmp_path / "source.json", description_ready=99, gap_candidates=1),
        spare_count=0,
    )
    request = plan.requests[0]

    def handler(http_request: httpx.Request) -> httpx.Response:
        assert set(http_request.url.params) == {
            "MobileOS",
            "MobileApp",
            "_type",
            "contentId",
            "numOfRows",
            "pageNo",
            "serviceKey",
        }
        assert http_request.url.params["contentId"] == request.provider_content_id
        assert http_request.url.params["numOfRows"] == "1"
        assert http_request.url.params["pageNo"] == "1"
        assert http_request.url.params["serviceKey"] == service_key
        return httpx.Response(
            200,
            headers={"content-type": "application/xml; charset=UTF-8"},
            content=b"<response><header><resultCode>30</resultCode></header></response>",
        )

    with httpx.Client(transport=httpx.MockTransport(handler)) as http_client:
        transport = TourApiDetailTransport(service_key, http_client=http_client)
        response = transport.fetch(request)

    assert response.content_type == "application/xml; charset=UTF-8"
    assert service_key.encode() not in response.body


@pytest.mark.parametrize(
    ("body", "error"),
    [
        (b"x" * (RESPONSE_BODY_MAX_BYTES + 1), ValueError),
        (b'{"reflected":"synthetic-test-key"}', RuntimeError),
    ],
)
def test_live_transport_fails_closed_on_unsafe_response(
    tmp_path: Path,
    body: bytes,
    error: type[Exception],
) -> None:
    service_key = "synthetic-test-key"
    plan = _build_plan(
        _write_source(tmp_path / "source.json", description_ready=99, gap_candidates=1),
        spare_count=0,
    )

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, content=body)

    with httpx.Client(transport=httpx.MockTransport(handler)) as http_client:
        transport = TourApiDetailTransport(service_key, http_client=http_client)
        with pytest.raises(error):
            transport.fetch(plan.requests[0])


def test_owned_official_client_disables_environment_trust(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    kwargs: dict[str, object] = {}

    class FakeClient:
        def __init__(self, **values: object) -> None:
            kwargs.update(values)

        def close(self) -> None:
            return None

    monkeypatch.setattr(collector_base.httpx, "Client", FakeClient)
    client = KorService2Client(service_key="not-recorded")
    client.close()

    assert kwargs == {"follow_redirects": False, "trust_env": False}
