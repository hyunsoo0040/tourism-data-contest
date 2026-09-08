"""Wave 0 contract for DATA-01 (02-W0-DATA01; T-02-01, T-02-02, T-02-03)."""

from __future__ import annotations

import hashlib
import importlib
import importlib.util
import json
import os
import stat
from base64 import b64decode, b64encode
from datetime import UTC, datetime
from pathlib import Path
from types import ModuleType

import httpx
import pytest
from pydantic import ValidationError

from itda.collectors import snapshots as snapshots_module
from itda.collectors.base import CollectedResponse, CollectionError, RequestPolicy
from itda.collectors.diagnostics import ProviderDiagnostics
from itda.collectors.kto import KorService2Client
from itda.contracts.catalog_collection import TOURAPI_CLASSIFICATION_FIELDS
from itda.domain.canonical import canonical_sha256

REPOSITORY_ROOT = Path(__file__).resolve().parents[3]
SEED_PATH = (
    REPOSITORY_ROOT / "fixtures" / "catalog" / "v1" / "public" / "proposal-36-coverage-seed.json"
)
CAPABILITY_MODULE = "itda.contracts.catalog_collection"
SOURCE_ATTACHMENT_SHA256 = "4263d6b81e4e04e1558fad8012a716823cae3c4109bfab0ec4bd84086ed41363"
EXPECTED_GROUPS = (
    ("HISTORY_CULTURE", 12),
    ("HISTORY_SCENERY_BOUNDARY", 8),
    ("IMAGE_MODERN_CONTENT", 8),
    ("REST_WALK_IMMERSION", 8),
)
EXPECTED_NAMES = (
    "불국사",
    "석굴암",
    "대릉원·천마총",
    "첨성대",
    "동궁과 월지",
    "국립경주박물관",
    "분황사",
    "황룡사지",
    "월정교",
    "교촌마을",
    "양동마을",
    "옥산서원",
    "포석정",
    "감은사지",
    "문무대왕릉",
    "김유신묘",
    "무열왕릉",
    "오릉",
    "계림",
    "월성·반월성",
    "황리단길",
    "보문정",
    "경주엑스포대공원",
    "솔거미술관",
    "경주동궁원",
    "한국대중음악박물관",
    "구황동 원지 유적",
    "경주월드",
    "보문호반길",
    "경주 남산",
    "삼릉숲",
    "토함산 자연휴양림",
    "주상절리 파도소리길",
    "오류고아라해변",
    "나정고운모래해변",
    "화랑마을",
)
FIXED_NOW = datetime(2026, 7, 27, 5, 0, tzinfo=UTC)
SYNTHETIC_SERVICE_KEY = "synthetic-catalog-transport-key"


def _seed_payload() -> dict[str, object]:
    return json.loads(SEED_PATH.read_text(encoding="utf-8"))


def _capability_or_skip() -> ModuleType:
    if importlib.util.find_spec(CAPABILITY_MODULE) is None:
        pytest.skip("catalog collection production capability is implemented in Plan 02-05")
    return importlib.import_module(CAPABILITY_MODULE)


def _all_mapping_keys(value: object) -> set[str]:
    if isinstance(value, dict):
        return set(value) | {key for child in value.values() for key in _all_mapping_keys(child)}
    if isinstance(value, list):
        return {key for child in value for key in _all_mapping_keys(child)}
    return set()


def test_proposal_seed_is_exact_ordered_and_hash_bound() -> None:
    payload = _seed_payload()
    rows = payload["rows"]
    assert isinstance(rows, list)
    assert payload["schema_version"] == "proposal-coverage-seed-v1"
    assert payload["source_attachment_name"] == "pasted-text.txt"
    assert payload["source_attachment_sha256"] == SOURCE_ATTACHMENT_SHA256
    assert len(rows) == 36
    assert [row["seed_id"] for row in rows] == [
        f"proposal:gyeongju:{index:03d}" for index in range(1, 37)
    ]
    assert [row["proposal_order"] for row in rows] == list(range(1, 37))
    assert [row["name_ko"] for row in rows] == list(EXPECTED_NAMES)
    assert [
        (group, sum(row["hypothesis_group"] == group for row in rows))
        for group, _ in EXPECTED_GROUPS
    ] == list(EXPECTED_GROUPS)

    digest_payload = dict(payload)
    recorded_digest = digest_payload.pop("seed_manifest_sha256")
    assert isinstance(recorded_digest, str) and len(recorded_digest) == 64
    assert canonical_sha256(digest_payload) == recorded_digest
    assert hashlib.sha256(SEED_PATH.read_bytes()).hexdigest() != recorded_digest


def test_proposal_seed_is_membership_free_coverage_not_catalog_truth() -> None:
    payload = _seed_payload()
    forbidden_keys = {
        "canonical_place_id",
        "canonical_status",
        "catalog_membership",
        "split",
        "split_membership",
        "dev_membership",
        "blind_membership",
        "selected",
        "selection_status",
    }
    assert _all_mapping_keys(payload).isdisjoint(forbidden_keys)
    serialized = SEED_PATH.read_text(encoding="utf-8").casefold()
    assert '"dev"' not in serialized
    assert '"blind"' not in serialized


def test_official_provider_contract_uses_current_datasets_hosts_and_operations() -> None:
    capability = _capability_or_skip()
    assert capability.OFFICIAL_DATASETS == {
        "TOUR_API": {
            "official_dataset_id": "15101578",
            "host": "apis.data.go.kr",
            "service": "KorService2",
            "operations": (
                "areaBasedList2",
                "detailCommon2",
                "detailIntro2",
                "detailInfo2",
                "detailImage2",
            ),
        },
        "ODII": {
            "official_dataset_id": "15101971",
            "host": "apis.data.go.kr",
            "service": "Odii",
            "operations": ("themeSearchList", "themeBasedList", "storyBasedList"),
        },
        "TOURISM_PHOTO": {
            "official_dataset_id": "15101914",
            "host": "apis.data.go.kr",
            "service": "PhotoGalleryService1",
            "operations": ("list", "search", "detail", "sync"),
            "dataset_rights": "KOGL_TYPE_1_ATTRIBUTION",
        },
    }
    assert capability.TOURAPI_CLASSIFICATION_FIELDS == (
        "lDongRegnCd",
        "lDongSignguCd",
        "lclsSystm1",
        "lclsSystm2",
        "lclsSystm3",
    )


@pytest.mark.parametrize(
    ("provider_code", "expected"),
    [
        ("00", "SUCCESS"),
        ("03", "NO_DATA"),
        ("02", "RETRYABLE_FOR_RESUME"),
        ("04", "RETRYABLE_FOR_RESUME"),
        ("05", "RETRYABLE_FOR_RESUME"),
        ("21", "RETRYABLE_FOR_RESUME"),
        ("22", "RETRYABLE_FOR_RESUME"),
        ("99", "RETRYABLE_FOR_RESUME"),
        ("10", "TERMINAL_OPERATOR_ACTION"),
        ("11", "TERMINAL_OPERATOR_ACTION"),
        ("12", "TERMINAL_OPERATOR_ACTION"),
        ("20", "TERMINAL_OPERATOR_ACTION"),
        ("30", "TERMINAL_OPERATOR_ACTION"),
        ("31", "TERMINAL_OPERATOR_ACTION"),
        ("32", "TERMINAL_OPERATOR_ACTION"),
        ("33", "TERMINAL_OPERATOR_ACTION"),
    ],
)
def test_provider_envelopes_have_explicit_bounded_retry_classification(
    provider_code: str,
    expected: str,
) -> None:
    capability = _capability_or_skip()
    assert capability.classify_provider_result(provider_code) == expected


def test_request_identity_is_secret_free_immutable_and_resume_safe() -> None:
    capability = _capability_or_skip()
    identity = capability.build_request_identity(
        provider="TOUR_API",
        official_dataset_id="15101578",
        operation="areaBasedList2",
        secret_free_parameters={
            "MobileApp": "IT-DA",
            "MobileOS": "ETC",
            "lDongRegnCd": "47",
            "lDongSignguCd": "130",
            "pageNo": "1",
        },
        page=1,
        collection_plan_version="catalog-plan-v1",
        collector_version="catalog-collector-v1",
        schema_version="catalog-collection-v1",
        plan_sha256="1" * 64,
    )
    assert (
        identity.request_identity
        == capability.build_request_identity(
            **identity.model_dump(exclude={"request_identity"})
        ).request_identity
    )
    assert "serviceKey" not in identity.model_dump_json()

    success = capability.CollectionAttempt(
        request_identity=identity.request_identity,
        attempt_number=1,
        terminal_state="SUCCESS",
        provider_result_code="00",
        provider_result_value="NORMAL_SERVICE",
        normalized_failure_reason=None,
        raw_body_sha256="2" * 64,
        raw_body_retention="IMMUTABLE",
        safe_headers={"content-type": "application/json"},
    )
    assert capability.select_resume_identities([identity], [success]) == ()


def test_retryable_provider_exhaustion_is_durable_and_resume_eligible(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delenv("CI", raising=False)
    monkeypatch.delenv("ITDA_NO_NETWORK", raising=False)
    attempts = 0
    delays: list[float] = []
    raw_body = (
        b'{"response":{"header":{"resultCode":"22",'
        b'"resultMsg":"LIMITED NUMBER OF SERVICE REQUESTS EXCEEDS ERROR"}}}'
    )

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal attempts
        attempts += 1
        return httpx.Response(
            200,
            content=raw_body,
            headers={
                "content-type": "application/json",
                "retry-after": "2",
                "set-cookie": "must-not-be-retained",
            },
            request=request,
        )

    diagnostics = ProviderDiagnostics.create(tmp_path / "diagnostics")
    diagnostics.bind_credentials(SYNTHETIC_SERVICE_KEY)
    operation = diagnostics.operation(
        candidate_place_id="synthetic:catalog:001",
        candidate_name="synthetic catalog fixture",
        provider="TOUR_API",
        operation="detailCommon2",
        plan_sha256="1" * 64,
    )
    diagnostics.run_started()
    try:
        with httpx.Client(transport=httpx.MockTransport(handler)) as http_client:
            client = KorService2Client(
                service_key=SYNTHETIC_SERVICE_KEY,
                http_client=http_client,
                policy=RequestPolicy(
                    timeout_seconds=300,
                    max_attempts=2,
                    initial_backoff_seconds=0.25,
                    max_backoff_seconds=5,
                    jitter_fraction=0,
                ),
                clock=lambda: FIXED_NOW,
                sleeper=delays.append,
            )
            with pytest.raises(CollectionError) as caught:
                client.request(
                    "detailCommon2",
                    {"contentId": "synthetic-001"},
                    explicit_opt_in=True,
                    diagnostics=diagnostics,
                    diagnostic_operation=operation,
                )
    finally:
        diagnostics.close()

    assert attempts == 2
    assert delays == [2.0]
    assert caught.value.outcome == "retryable_for_resume"
    assert caught.value.provider_result_code == "22"
    assert caught.value.retry_disposition == "RETRYABLE_FOR_RESUME"

    log = next((tmp_path / "diagnostics").glob("provider-collection-*.jsonl"))
    events = [json.loads(line) for line in log.read_text(encoding="utf-8").splitlines()]
    attempts_logged = [event for event in events if event["event"] == "request_attempt"]
    assert len(attempts_logged) == 2
    for event in attempts_logged:
        assert event["provider_result_code"] == "22"
        assert event["provider_result_value"].startswith("LIMITED NUMBER")
        assert event["normalized_outcome"] == "RETRYABLE_FOR_RESUME"
        assert event["retry_disposition"] == "RETRY"
        assert event["raw_body_sha256"] == hashlib.sha256(raw_body).hexdigest()
        assert event["raw_body_retention"] == "IMMUTABLE_ATTEMPT_SNAPSHOT"
        assert event["safe_headers"] == {
            "content-type": "application/json",
            "retry-after": "2",
        }
        assert isinstance(event["elapsed_ms"], int) and event["elapsed_ms"] >= 0
        assert len(event["request_sha256"]) == 64
        assert event["plan_sha256"] == "1" * 64
        body_path = tmp_path / "diagnostics" / event["raw_body_file"]
        assert body_path.read_bytes() == raw_body
        assert stat.S_IMODE(body_path.stat().st_mode) == 0o600
        assert not body_path.is_symlink()
    serialized = log.read_text(encoding="utf-8")
    assert SYNTHETIC_SERVICE_KEY not in serialized
    assert "must-not-be-retained" not in serialized

    capability = _capability_or_skip()
    identity = capability.build_request_identity(
        provider="TOUR_API",
        official_dataset_id="15101578",
        operation="detailCommon2",
        secret_free_parameters={"contentId": "synthetic-001"},
        page=1,
        collection_plan_version="catalog-plan-v1",
        collector_version="catalog-collector-v1",
        schema_version="catalog-collection-v1",
        plan_sha256="1" * 64,
    )
    failed = capability.CollectionAttempt(
        request_identity=identity.request_identity,
        attempt_number=2,
        terminal_state="RETRYABLE_FOR_RESUME",
        provider_result_code="22",
        provider_result_value="LIMITED NUMBER OF SERVICE REQUESTS EXCEEDS ERROR",
        normalized_failure_reason="provider quota exhausted",
        raw_body_sha256=hashlib.sha256(raw_body).hexdigest(),
        raw_body_retention="IMMUTABLE_ATTEMPT_SNAPSHOT",
        safe_headers={"content-type": "application/json", "retry-after": "2"},
    )
    assert capability.select_resume_identities([identity], [failed]) == (identity,)


@pytest.mark.parametrize(
    "provider_code",
    ["10", "11", "12", "20", "30", "31", "32", "33"],
)
def test_operator_action_provider_codes_are_immediate_terminal(
    provider_code: str,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delenv("CI", raising=False)
    monkeypatch.delenv("ITDA_NO_NETWORK", raising=False)
    attempts = 0

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal attempts
        attempts += 1
        return httpx.Response(
            200,
            json={
                "response": {
                    "header": {
                        "resultCode": provider_code,
                        "resultMsg": "OPERATOR ACTION REQUIRED",
                    }
                }
            },
            request=request,
        )

    with httpx.Client(transport=httpx.MockTransport(handler)) as http_client:
        client = KorService2Client(
            service_key=SYNTHETIC_SERVICE_KEY,
            http_client=http_client,
            policy=RequestPolicy(max_attempts=5),
            sleeper=lambda _delay: pytest.fail("terminal result must not back off"),
        )
        with pytest.raises(CollectionError) as caught:
            client.request(
                "detailCommon2",
                {"contentId": "synthetic-001"},
                explicit_opt_in=True,
            )

    assert attempts == 1
    assert caught.value.outcome == "terminal_operator_action"
    assert caught.value.provider_result_code == provider_code
    assert caught.value.retry_disposition == "DO_NOT_RETRY"
    assert caught.value.normalized_failure_reason


def test_xml_no_data_envelope_is_terminal_without_retry_and_retains_raw_values(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delenv("CI", raising=False)
    monkeypatch.delenv("ITDA_NO_NETWORK", raising=False)
    attempts = 0
    raw_body = (
        b'<?xml version="1.0" encoding="UTF-8"?>'
        b"<OpenAPI_ServiceResponse><cmmMsgHeader>"
        b"<returnReasonCode>03</returnReasonCode>"
        b"<returnAuthMsg>NO DATA</returnAuthMsg>"
        b"</cmmMsgHeader></OpenAPI_ServiceResponse>"
    )

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal attempts
        attempts += 1
        return httpx.Response(
            200,
            content=raw_body,
            headers={"content-type": "application/xml"},
            request=request,
        )

    with httpx.Client(transport=httpx.MockTransport(handler)) as http_client:
        result = KorService2Client(
            service_key=SYNTHETIC_SERVICE_KEY,
            http_client=http_client,
            policy=RequestPolicy(max_attempts=3),
            clock=lambda: FIXED_NOW,
            sleeper=lambda _delay: pytest.fail("no-data must not retry"),
        ).request(
            "detailCommon2",
            {"contentId": "synthetic-001"},
            explicit_opt_in=True,
        )

    assert attempts == 1
    assert result.provider_result_code == "03"
    assert result.provider_result_value == "NO DATA"
    assert result.normalized_outcome == "NO_DATA"
    assert result.retry_disposition == "DO_NOT_RETRY"
    assert result.raw_response_sha256 == hashlib.sha256(raw_body).hexdigest()
    assert b64decode(result.raw_body_base64) == raw_body


def test_http_retry_after_is_bounded_and_success_is_not_retried(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delenv("CI", raising=False)
    monkeypatch.delenv("ITDA_NO_NETWORK", raising=False)
    attempts = 0
    delays: list[float] = []

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal attempts
        attempts += 1
        if attempts == 1:
            return httpx.Response(
                429,
                json={"response": {"header": {"resultCode": "22"}}},
                headers={"retry-after": "9999"},
                request=request,
            )
        return httpx.Response(
            200,
            json={"response": {"header": {"resultCode": "00", "resultMsg": "NORMAL"}}},
            request=request,
        )

    with httpx.Client(transport=httpx.MockTransport(handler)) as http_client:
        result = KorService2Client(
            service_key=SYNTHETIC_SERVICE_KEY,
            http_client=http_client,
            policy=RequestPolicy(
                timeout_seconds=300,
                max_attempts=5,
                initial_backoff_seconds=1,
                max_backoff_seconds=300,
                jitter_fraction=0,
            ),
            sleeper=delays.append,
        ).request(
            "detailCommon2",
            {"contentId": "synthetic-001"},
            explicit_opt_in=True,
        )

    assert attempts == 2
    assert delays == [300.0]
    assert result.normalized_outcome == "SUCCESS"
    assert result.retry_disposition == "DO_NOT_RETRY"


@pytest.mark.parametrize("status", [408, 429, 500, 501, 502, 503, 504, 599])
def test_http_transient_matrix_retries_every_5xx_with_finite_budget(
    status: int,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delenv("CI", raising=False)
    monkeypatch.delenv("ITDA_NO_NETWORK", raising=False)
    attempts = 0

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal attempts
        attempts += 1
        if attempts == 1:
            return httpx.Response(status, content=b"synthetic transient", request=request)
        return httpx.Response(
            200,
            json={"response": {"header": {"resultCode": "00", "resultMsg": "NORMAL"}}},
            request=request,
        )

    with httpx.Client(transport=httpx.MockTransport(handler)) as http_client:
        KorService2Client(
            service_key=SYNTHETIC_SERVICE_KEY,
            http_client=http_client,
            policy=RequestPolicy(max_attempts=2),
            sleeper=lambda _delay: None,
        ).request(
            "detailCommon2",
            {"contentId": "synthetic-001"},
            explicit_opt_in=True,
        )
    assert attempts == 2


def test_resume_snapshot_preserves_success_bytes_and_mtime(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delenv("CI", raising=False)
    monkeypatch.delenv("ITDA_NO_NETWORK", raising=False)

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            json={"response": {"header": {"resultCode": "00", "resultMsg": "NORMAL"}}},
            request=request,
        )

    with httpx.Client(transport=httpx.MockTransport(handler)) as http_client:
        collected = KorService2Client(
            service_key=SYNTHETIC_SERVICE_KEY,
            http_client=http_client,
            clock=lambda: FIXED_NOW,
        ).request(
            "detailCommon2",
            {"contentId": "synthetic-001"},
            explicit_opt_in=True,
        )

    path = snapshots_module.write_snapshot_for_resume(collected, tmp_path)
    original = path.read_bytes()
    old_ns = 1_700_000_000_000_000_000
    os.utime(path, ns=(old_ns, old_ns))
    resumed = snapshots_module.write_snapshot_for_resume(collected, tmp_path)
    assert resumed == path
    assert resumed.read_bytes() == original
    assert resumed.stat().st_mtime_ns == old_ns


def test_exact_official_adapters_keep_dataset_and_rights_identities_distinct() -> None:
    photo_module = importlib.import_module("itda.collectors.tourism_photo")
    photo_client_type = photo_module.TourismPhotoGalleryClient

    assert KorService2Client.official_dataset_id == "15101578"
    assert KorService2Client.service_name == "KorService2"
    assert KorService2Client.base_url == "https://apis.data.go.kr/B551011/KorService2"
    assert KorService2Client.classification_fields == TOURAPI_CLASSIFICATION_FIELDS
    assert {
        "areaBasedList2",
        "detailCommon2",
        "detailIntro2",
        "detailInfo2",
        "detailImage2",
    }.issubset(KorService2Client.allowed_operations)

    odii_module = importlib.import_module("itda.collectors.odii")
    assert odii_module.OdiiClient.official_dataset_id == "15101971"
    assert odii_module.OdiiClient.dataset_rights_identity == "ODII_DATASET_15101971"
    assert odii_module.OdiiClient.provenance_fields == (
        "tid",
        "tlid",
        "storyId",
        "themeName",
        "storyTitle",
    )

    assert photo_client_type.official_dataset_id == "15101914"
    assert photo_client_type.service_name == "PhotoGalleryService1"
    assert photo_client_type.base_url == "https://apis.data.go.kr/B551011/PhotoGalleryService1"
    assert photo_client_type.allowed_operations == frozenset(
        {
            "galleryList1",
            "gallerySearchList1",
            "galleryDetailList1",
            "gallerySyncDetailList1",
        }
    )
    assert photo_client_type.dataset_rights_identity == "KOGL_TYPE_1_ATTRIBUTION"
    assert photo_client_type.dataset_rights_identity != (
        odii_module.OdiiClient.dataset_rights_identity
    )
    assert photo_client_type.provenance_fields == (
        "galContentId",
        "galTitle",
        "galWebImageUrl",
        "galPhotographyLocation",
        "galPhotographer",
        "galSearchKeyword",
    )


def test_tourapi_rejects_obsolete_area_and_category_parameters_before_transport(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delenv("CI", raising=False)
    monkeypatch.delenv("ITDA_NO_NETWORK", raising=False)
    transport_calls = 0

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal transport_calls
        transport_calls += 1
        raise AssertionError("obsolete parameters must be rejected before transport")

    with httpx.Client(transport=httpx.MockTransport(handler)) as http_client:
        client = KorService2Client(
            service_key=SYNTHETIC_SERVICE_KEY,
            http_client=http_client,
        )
        with pytest.raises(CollectionError, match="obsolete"):
            client.request(
                "areaBasedList2",
                {
                    "areaCode": "35",
                    "sigunguCode": "2",
                    "cat1": "A02",
                    "cat2": "A0201",
                    "cat3": "A02010100",
                },
                explicit_opt_in=True,
            )
    assert transport_calls == 0


def test_photo_adapter_uses_only_fixed_api_target_and_never_dereferences_evidence_url(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delenv("CI", raising=False)
    monkeypatch.delenv("ITDA_NO_NETWORK", raising=False)
    photo_module = importlib.import_module("itda.collectors.tourism_photo")
    requests: list[httpx.Request] = []
    evidence_url = "https://evidence.invalid/photo.jpg"

    def handler(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        return httpx.Response(
            200,
            json={
                "response": {
                    "header": {"resultCode": "0000", "resultMsg": "OK"},
                    "body": {
                        "items": {
                            "item": [
                                {
                                    "galContentId": "synthetic-photo-001",
                                    "galTitle": "synthetic photo",
                                    "galWebImageUrl": evidence_url,
                                    "galPhotographyLocation": "경상북도 경주시",
                                    "galPhotographer": "synthetic photographer",
                                    "galSearchKeyword": "경주, synthetic",
                                }
                            ]
                        }
                    },
                }
            },
            request=request,
        )

    with httpx.Client(transport=httpx.MockTransport(handler)) as http_client:
        result = photo_module.TourismPhotoGalleryClient(
            service_key=SYNTHETIC_SERVICE_KEY,
            http_client=http_client,
            clock=lambda: FIXED_NOW,
        ).request(
            "gallerySearchList1",
            {"keyword": "경주", "pageNo": 1, "numOfRows": 10},
            explicit_opt_in=True,
        )

    assert len(requests) == 1
    request = requests[0]
    assert request.url.host == "apis.data.go.kr"
    assert request.url.path == "/B551011/PhotoGalleryService1/gallerySearchList1"
    assert request.url.params["MobileOS"] == "ETC"
    assert request.url.params["MobileApp"] == "IT-DA"
    assert request.url.params["_type"] == "json"
    assert request.url.params["keyword"] == "경주"
    assert result.official_dataset_id == "15101914"
    assert result.dataset_rights_identity == "KOGL_TYPE_1_ATTRIBUTION"
    assert evidence_url in json.dumps(result.payload)


def test_redirects_remain_disabled_even_for_injected_client_policy(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delenv("CI", raising=False)
    monkeypatch.delenv("ITDA_NO_NETWORK", raising=False)
    requests: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        if request.url.host == "apis.data.go.kr":
            return httpx.Response(
                302,
                headers={"location": "https://evidence.invalid/redirect-target"},
                request=request,
            )
        raise AssertionError("redirect target must never be dereferenced")

    with httpx.Client(
        transport=httpx.MockTransport(handler),
        follow_redirects=True,
    ) as http_client:
        client = KorService2Client(
            service_key=SYNTHETIC_SERVICE_KEY,
            http_client=http_client,
        )
        with pytest.raises(CollectionError) as caught:
            client.request(
                "detailCommon2",
                {"contentId": "synthetic-001"},
                explicit_opt_in=True,
            )

    assert caught.value.http_status == 302
    assert len(requests) == 1
    assert requests[0].url.host == "apis.data.go.kr"


def test_missing_catalog_collection_is_controlled_red() -> None:
    if importlib.util.find_spec(CAPABILITY_MODULE) is None:
        pytest.fail("PHASE2-MISSING:catalog-collection", pytrace=False)
    importlib.import_module(CAPABILITY_MODULE)


def test_collection_plan_is_deterministic_secret_free_and_three_dataset_bound() -> None:
    pipeline = importlib.import_module("itda.pipeline.collect_catalog")
    seed = pipeline.load_coverage_seed(SEED_PATH)
    plan = pipeline.build_collection_plan(seed)

    assert plan.collection_plan_version == "catalog-v1"
    assert plan.seed_manifest_sha256 == _seed_payload()["seed_manifest_sha256"]
    assert tuple(item.official_dataset_id for item in plan.permission_requirements) == (
        "15101578",
        "15101971",
        "15101914",
    )
    assert tuple(item.scope for item in plan.requests[:3]) == ("TINY", "TINY", "TINY")
    assert all(item.scope == "BROAD" for item in plan.requests[3:])
    assert all(item.per_attempt_timeout_seconds <= 300 for item in plan.requests)
    assert all(1 <= item.max_attempts <= 5 for item in plan.requests)
    assert (
        plan.collection_plan_sha256
        == pipeline.build_collection_plan(
            pipeline.load_coverage_seed(SEED_PATH)
        ).collection_plan_sha256
    )
    rendered = plan.model_dump_json()
    assert "serviceKey" not in rendered
    assert SYNTHETIC_SERVICE_KEY not in rendered
    assert ".secrets/itda-api.env:TOUR_API_SERVICE_KEY" in rendered
    assert ".secrets/itda-odii.env:ODII_SERVICE_KEY" in rendered


def test_coverage_disposition_requires_evidence_and_never_promotes_alias_to_place_id() -> None:
    capability = _capability_or_skip()
    linked = capability.SeedCoverageDisposition(
        seed_id="proposal:gyeongju:001",
        status="LINKED",
        candidate_id="candidate:tourapi:126508",
        reason="TourAPI name and coordinates match the proposal seed",
        evidence_sha256=("1" * 64,),
    )
    assert linked.candidate_id == "candidate:tourapi:126508"
    assert not hasattr(linked, "canonical_place_id")

    with pytest.raises(ValidationError):
        capability.SeedCoverageDisposition(
            seed_id="proposal:gyeongju:002",
            status="MISSING_WITH_EVIDENCE",
            candidate_id=None,
            reason="",
            evidence_sha256=("2" * 64,),
        )
    with pytest.raises(ValidationError):
        capability.SeedCoverageDisposition(
            seed_id="proposal:gyeongju:003",
            status="EXCLUDED_WITH_EVIDENCE",
            candidate_id="provider-alias-must-not-link",
            reason="explicit upstream restriction",
            evidence_sha256=("3" * 64,),
        )


def test_permission_evidence_set_is_exact_ordered_and_rejects_cross_dataset_reuse() -> None:
    capability = _capability_or_skip()
    pipeline = importlib.import_module("itda.pipeline.collect_catalog")
    snapshots = tuple(
        pipeline.build_permission_snapshot(
            official_dataset_id=dataset_id,
            official_url=f"https://www.data.go.kr/data/{dataset_id}/openapi.do",
            retrieved_at=FIXED_NOW,
            terms_projection={
                "commercial_use": True,
                "derivative_use": True,
                "attribution_required": dataset_id == "15101914",
                "availability": "AVAILABLE",
            },
            response_bytes=f"fixture-permission-{dataset_id}".encode(),
        )
        for dataset_id in ("15101578", "15101971", "15101914")
    )
    evidence = capability.PermissionEvidenceSet.from_snapshots(snapshots)
    assert evidence.permission_evidence_sha256 == (
        capability.PermissionEvidenceSet.from_snapshots(snapshots).permission_evidence_sha256
    )

    wrong_parent = snapshots[0].model_copy(update={"official_dataset_id": "15101971"})
    with pytest.raises(ValidationError):
        capability.PermissionEvidenceSet.from_snapshots((snapshots[0], wrong_parent, snapshots[2]))


def test_credential_preflight_reports_shape_only_and_rejects_symlink(
    tmp_path: Path,
) -> None:
    pipeline = importlib.import_module("itda.pipeline.collect_catalog")
    credential = tmp_path / "itda-api.env"
    credential.write_text("TOUR_API_SERVICE_KEY=fixture-secret-never-returned\n", encoding="utf-8")
    credential.chmod(0o600)

    result = pipeline.preflight_credential_reference(
        provider_label="tourapi",
        credential_reference=f"{credential}:TOUR_API_SERVICE_KEY",
        expected_path=credential,
        expected_variable_name="TOUR_API_SERVICE_KEY",
    )
    assert result.model_dump() == {
        "provider_label": "tourapi",
        "reference": f"{credential}:TOUR_API_SERVICE_KEY",
        "regular_file": True,
        "no_symlink": True,
        "owned_by_current_user": True,
        "mode_0600": True,
        "variable_name_present": True,
    }
    assert "fixture-secret-never-returned" not in result.model_dump_json()

    symlink = tmp_path / "credential-link.env"
    symlink.symlink_to(credential)
    with pytest.raises(ValueError, match="symlink"):
        pipeline.preflight_credential_reference(
            provider_label="tourapi",
            credential_reference=f"{symlink}:TOUR_API_SERVICE_KEY",
            expected_path=symlink,
            expected_variable_name="TOUR_API_SERVICE_KEY",
        )


def test_cli_exposes_plan_preflight_resume_and_read_only_validation_flags() -> None:
    cli = importlib.import_module("itda.cli.collect_catalog")
    help_text = cli.build_parser().format_help()
    for flag in (
        "--plan",
        "--request-plan",
        "--output-root",
        "--live",
        "--resume",
        "--recover-tourism-photo-access",
        "--recovery-signal",
        "--credential-ref",
        "--preflight-credential-ref",
        "--no-print-values",
        "--import-permission-page",
        "--report-json",
        "--validate-report",
        "--validation-output",
        "--require-dataset",
        "--min-candidates",
        "--require-terminal-plan-completeness",
        "--require-resume-proof",
    ):
        assert flag in help_text
    for forbidden in ("--service-key", "--api-key", "--token", "--secret"):
        assert forbidden not in help_text


def test_collection_orchestrator_validates_then_strips_adapter_common_parameters(
    tmp_path: Path,
) -> None:
    pipeline = importlib.import_module("itda.pipeline.collect_catalog")
    seed = pipeline.load_coverage_seed(SEED_PATH)
    plan = pipeline.build_collection_plan(seed)
    snapshots = tuple(
        pipeline.build_permission_snapshot(
            official_dataset_id=dataset_id,
            official_url=f"https://www.data.go.kr/data/{dataset_id}/openapi.do",
            retrieved_at=FIXED_NOW,
            terms_projection={
                "commercial_use": True,
                "derivative_use": True,
                "attribution_required": dataset_id == "15101914",
                "availability": "AVAILABLE",
            },
            response_bytes=f"fixture-permission-{dataset_id}".encode(),
        )
        for dataset_id in ("15101578", "15101971", "15101914")
    )
    permission_evidence = _capability_or_skip().PermissionEvidenceSet.from_snapshots(snapshots)

    class RecordingClient:
        def __init__(
            self,
            *,
            common_parameters: dict[str, str],
        ) -> None:
            self.common_parameters = common_parameters
            self.calls: list[dict[str, object]] = []

        def request(
            self,
            operation: str,
            params: dict[str, object],
            *,
            explicit_opt_in: bool,
            diagnostics: object | None = None,
            diagnostic_operation: object | None = None,
        ) -> object:
            del operation, explicit_opt_in, diagnostics, diagnostic_operation
            self.calls.append(params)
            assert set(params).isdisjoint(self.common_parameters)
            raise CollectionError(
                "fixture terminal after transport parameter validation",
                normalized_failure_reason="fixture terminal",
            )

    clients = {
        "TOUR_API": RecordingClient(
            common_parameters={
                "MobileOS": "ETC",
                "MobileApp": "IT-DA",
                "_type": "json",
            }
        ),
        "ODII": RecordingClient(
            common_parameters={
                "MobileOS": "ETC",
                "MobileApp": "IT-DA",
                "_type": "json",
                "langCode": "ko",
            }
        ),
        "TOURISM_PHOTO": RecordingClient(
            common_parameters={
                "MobileOS": "ETC",
                "MobileApp": "IT-DA",
                "_type": "json",
            }
        ),
    }

    report = pipeline.collect_catalog(
        plan=plan,
        seed=seed,
        permission_evidence=permission_evidence,
        clients=clients,
        output_root=tmp_path / "collection",
        clock=lambda: FIXED_NOW,
    )

    assert report.collection_plan_sha256 == plan.collection_plan_sha256
    assert sum(len(client.calls) for client in clients.values()) == 33


def test_photo_gallery_access_recovery_retries_only_prior_11_and_preserves_evidence(
    tmp_path: Path,
) -> None:
    pipeline = importlib.import_module("itda.pipeline.collect_catalog")
    cli = importlib.import_module("itda.cli.collect_catalog")
    seed = pipeline.load_coverage_seed(SEED_PATH)
    plan = pipeline.build_collection_plan(seed)
    snapshots = tuple(
        pipeline.build_permission_snapshot(
            official_dataset_id=dataset_id,
            official_url=f"https://www.data.go.kr/data/{dataset_id}/openapi.do",
            retrieved_at=FIXED_NOW,
            terms_projection={
                "commercial_use": True,
                "derivative_use": True,
                "attribution_required": dataset_id == "15101914",
                "availability": "AVAILABLE",
            },
            response_bytes=f"fixture-permission-{dataset_id}".encode(),
        )
        for dataset_id in ("15101578", "15101971", "15101914")
    )
    permission_evidence = _capability_or_skip().PermissionEvidenceSet.from_snapshots(snapshots)

    class RecoveryFixtureClient:
        def __init__(
            self,
            *,
            provider: str,
            dataset_id: str,
            common_parameters: dict[str, str],
            blocked: bool = False,
        ) -> None:
            self.provider = provider
            self.dataset_id = dataset_id
            self.common_parameters = common_parameters
            self.blocked = blocked
            self.calls: list[tuple[str, dict[str, object]]] = []

        def request(
            self,
            operation: str,
            params: dict[str, object],
            *,
            explicit_opt_in: bool,
            diagnostics: object | None = None,
            diagnostic_operation: object | None = None,
        ) -> CollectedResponse:
            del explicit_opt_in, diagnostics, diagnostic_operation
            self.calls.append((operation, params))
            if self.blocked:
                raise CollectionError(
                    "HTTP 403 requires operator review",
                    http_status=403,
                    retry_disposition="DO_NOT_RETRY",
                    normalized_failure_reason="HTTP status requires operator review",
                    raw_body_sha256=hashlib.sha256(b"Forbidden\n").hexdigest(),
                )
            raw_body = json.dumps(
                {
                    "provider": self.provider,
                    "operation": operation,
                    "parameters": params,
                },
                sort_keys=True,
            ).encode()
            return CollectedResponse(
                provider=self.provider,
                endpoint=f"https://apis.data.go.kr/fixture/{operation}",
                request_scope={key: str(value) for key, value in params.items()},
                retrieved_at=FIXED_NOW,
                http_status=200,
                raw_response_sha256=hashlib.sha256(raw_body).hexdigest(),
                raw_body_base64=b64encode(raw_body).decode(),
                modifiedtime=None,
                rights=(),
                payload={
                    "response": {
                        "header": {"resultCode": "0000", "resultMsg": "OK"},
                        "body": {"items": {"item": []}},
                    }
                },
                provider_result_code="0000",
                provider_result_value="OK",
                official_dataset_id=self.dataset_id,
            )

    common = {
        "MobileOS": "ETC",
        "MobileApp": "IT-DA",
        "_type": "json",
    }
    initial_clients = {
        "TOUR_API": RecoveryFixtureClient(
            provider="TOUR_API",
            dataset_id="15101578",
            common_parameters=common,
        ),
        "ODII": RecoveryFixtureClient(
            provider="ODII",
            dataset_id="15101971",
            common_parameters={**common, "langCode": "ko"},
        ),
        "TOURISM_PHOTO": RecoveryFixtureClient(
            provider="TOURISM_PHOTO",
            dataset_id="15101914",
            common_parameters=common,
            blocked=True,
        ),
    }
    output_root = tmp_path / "collection"
    initial_report = pipeline.collect_catalog(
        plan=plan,
        seed=seed,
        permission_evidence=permission_evidence,
        clients=initial_clients,
        output_root=output_root,
        clock=lambda: FIXED_NOW,
    )
    assert len(initial_report.resume_evidence) == 22
    report_path = output_root / "collection-report.json"
    report_path.write_bytes(initial_report.model_dump_json().encode() + b"\n")
    validation_path = output_root / "live-report-validation.json"
    validation_path.write_bytes(b'{"fixture":"prior-validation"}\n')
    success_before = {
        evidence.relative_path: (
            (output_root / evidence.relative_path).read_bytes(),
            (output_root / evidence.relative_path).stat().st_mtime_ns,
        )
        for evidence in initial_report.resume_evidence
    }
    for relative_path, (_, expected_mtime_ns) in success_before.items():
        path = output_root / relative_path
        metadata = path.stat()
        os.utime(
            path,
            ns=(metadata.st_atime_ns, expected_mtime_ns + 100),
        )

    recovery_root = cli._prepare_photo_gallery_recovery(
        output_root=output_root,
        report_path=report_path,
    )
    inventory = json.loads((recovery_root / "pre-network-inventory.json").read_bytes())
    assert inventory["recovery_signal"] == "photo-gallery-access-repaired:15101914"
    assert len(inventory["target_request_identities"]) == 11
    assert len(inventory["successful_snapshot_records"]) == 22
    assert {
        item["mtime_normalization_delta_ns"] for item in inventory["successful_snapshot_records"]
    } == {100}
    assert (recovery_root / "prior-collection-report.json").read_bytes() == (
        initial_report.model_dump_json().encode() + b"\n"
    )
    assert (recovery_root / "prior-live-report-validation.json").read_bytes() == (
        b'{"fixture":"prior-validation"}\n'
    )

    recovered_photo = RecoveryFixtureClient(
        provider="TOURISM_PHOTO",
        dataset_id="15101914",
        common_parameters=common,
    )
    recovered_report = pipeline.collect_catalog(
        plan=plan,
        seed=seed,
        permission_evidence=permission_evidence,
        clients={"TOURISM_PHOTO": recovered_photo},
        output_root=output_root,
        resume_report=initial_report,
        terminal_recovery_dataset_id="15101914",
        clock=lambda: FIXED_NOW,
    )
    assert len(recovered_photo.calls) == 11
    assert recovered_report.attempts[: len(initial_report.attempts)] == (initial_report.attempts)
    latest = cli._latest_attempts(recovered_report)
    assert len(latest) == 33
    assert all(attempt.terminal_state == "SUCCESS" for attempt in latest.values())
    for relative_path, (before_bytes, before_mtime_ns) in success_before.items():
        path = output_root / relative_path
        assert path.read_bytes() == before_bytes
        assert path.stat().st_mtime_ns == before_mtime_ns

    report_path.write_bytes(recovered_report.model_dump_json().encode() + b"\n")
    cli._finalize_photo_gallery_recovery(
        recovery_root=recovery_root,
        output_root=output_root,
        report_path=report_path,
        elapsed_ms=123,
    )
    result = json.loads((recovery_root / "post-network-result.json").read_bytes())
    assert result["latest_terminal_state_counts"] == {
        "NO_DATA": 0,
        "RETRYABLE_FOR_RESUME": 0,
        "SUCCESS": 33,
        "TERMINAL_OPERATOR_ACTION": 0,
    }
    assert result["prior_success_snapshots_preserved"] is True
    assert result["elapsed_ms"] == 123
