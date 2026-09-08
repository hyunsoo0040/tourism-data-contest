from __future__ import annotations

from collections.abc import Iterator

import pytest
from fastapi.testclient import TestClient
from pydantic import ValidationError

from itda.api.dependencies import (
    ProfileSessionPrincipal,
    get_optional_profile_session,
    get_recommendation_service,
)
from itda.api.main import create_app
from itda.application.recommendations import (
    InsufficientEligibleCandidates,
    InvalidRecommendationOutput,
    NoActiveScoredRelease,
    PhotoRecommendationUnavailable,
    PreferenceProfileUnavailable,
)
from itda.contracts.recommendation import (
    OperatingInformationResponse,
    PlaceOperatingInformation,
    RecommendationRequest,
)
from itda.db.recommendation_repositories import (
    RecommendationPinInvalid,
    RecommendationPlaceUnavailable,
    RecommendationRequestConflict,
    RecommendationRunNotFound,
)

REQUEST_PAYLOAD = {
    "request_id": "anonymous:recommendation:request-1",
    "preference_profile_id": "profile:confirmed-current-trip",
}


class FailingService:
    def __init__(self, error: Exception) -> None:
        self.error = error

    def create_run(self, request: object) -> object:
        raise self.error

    def create_run_response(self, request: object) -> object:
        raise self.error

    def get_run(self, run_id: str) -> object:
        raise self.error

    def get_results(self, run_id: str) -> object:
        raise self.error

    def get_detail(self, run_id: str, place_id: str) -> object:
        raise self.error

    def get_comparison(self, run_id: str, place_ids: tuple[str, ...]) -> object:
        raise self.error

    def get_operating_information(
        self,
        run_id: str,
        place_ids: tuple[str, ...],
    ) -> object:
        raise self.error

    def resolve_saved_place_reference(self, release_sha256: str, place_id: str) -> object:
        raise self.error


@pytest.fixture
def client_factory() -> Iterator[object]:
    applications = []

    def build(error: Exception) -> TestClient:
        application = create_app()
        application.dependency_overrides[get_recommendation_service] = lambda: FailingService(error)
        applications.append(application)
        return TestClient(application)

    yield build
    for application in applications:
        application.dependency_overrides.clear()


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("release_id", "client-selected-release"),
        ("release_sha256", "a" * 64),
        ("path", "/restricted/profile-release.json"),
        ("candidates", ["place:1"]),
        ("scores", {"place:1": 100}),
        ("readiness", True),
        ("confidence", 100),
        ("photo", "data:image/png;base64,forbidden"),
        ("status_copy", "show success"),
    ],
)
def test_request_contract_rejects_every_client_authority_field(
    field: str,
    value: object,
) -> None:
    with pytest.raises(ValidationError):
        RecommendationRequest.model_validate({**REQUEST_PAYLOAD, field: value})


@pytest.mark.parametrize("authority_field", ["path", "scores", "photo", "unknown"])
def test_public_validation_error_is_bounded_and_does_not_echo_request(
    client_factory: object,
    authority_field: str,
) -> None:
    secret_canary = "must-not-appear-in-response"
    payload = {**REQUEST_PAYLOAD, authority_field: secret_canary}

    with client_factory(RuntimeError("must not be called")) as client:
        response = client.post("/v1/recommendation-runs", json=payload)

    assert response.status_code == 422
    assert response.json() == {
        "detail": {
            "code": "INVALID_RECOMMENDATION_REQUEST",
            "message_ko": "추천 요청 형식을 확인해 주세요.",
            "request_id": None,
            "preference_profile_id": None,
            "release_id": None,
        }
    }
    assert secret_canary not in response.text


@pytest.mark.parametrize(
    ("error", "expected_status", "expected_code"),
    [
        (
            NoActiveScoredRelease(
                request_id=str(REQUEST_PAYLOAD["request_id"]),
                preference_profile_id=str(REQUEST_PAYLOAD["preference_profile_id"]),
            ),
            503,
            "NO_ACTIVE_SCORED_RELEASE",
        ),
        (PreferenceProfileUnavailable("missing"), 404, "PREFERENCE_PROFILE_UNAVAILABLE"),
        (
            InsufficientEligibleCandidates("insufficient"),
            422,
            "INSUFFICIENT_ELIGIBLE_CANDIDATES",
        ),
        (
            RecommendationRequestConflict("conflict"),
            409,
            "RECOMMENDATION_REQUEST_CONFLICT",
        ),
        (InvalidRecommendationOutput("invalid"), 500, "INVALID_RECOMMENDATION_OUTPUT"),
        (RecommendationPinInvalid("invalid"), 500, "INVALID_RECOMMENDATION_OUTPUT"),
    ],
)
def test_create_route_maps_stable_failures_without_sensitive_payloads(
    client_factory: object,
    error: Exception,
    expected_status: int,
    expected_code: str,
) -> None:
    with client_factory(error) as client:
        response = client.post("/v1/recommendation-runs", json=REQUEST_PAYLOAD)

    assert response.status_code == expected_status
    assert response.json()["detail"]["code"] == expected_code
    assert set(response.json()["detail"]) == {
        "code",
        "message_ko",
        "request_id",
        "preference_profile_id",
        "release_id",
    }
    assert all(
        marker not in response.text.lower()
        for marker in ("answers", "evidence", "secret", "photo", "/artifacts/")
    )


@pytest.mark.parametrize(
    ("path", "error", "expected_status", "expected_code"),
    [
        (
            "/v1/recommendation-runs/recommendation-run:missing",
            RecommendationRunNotFound("missing"),
            404,
            "RECOMMENDATION_RUN_NOT_FOUND",
        ),
        (
            "/v1/recommendation-runs/recommendation-run:stale",
            RecommendationPinInvalid("stale"),
            409,
            "RECOMMENDATION_PIN_INVALID",
        ),
        (
            "/v1/recommendation-runs/recommendation-run:missing/places/place:missing",
            RecommendationPlaceUnavailable("missing"),
            404,
            "RECOMMENDATION_PLACE_UNAVAILABLE",
        ),
    ],
)
def test_pinned_read_routes_return_named_stale_and_missing_states(
    client_factory: object,
    path: str,
    error: Exception,
    expected_status: int,
    expected_code: str,
) -> None:
    with client_factory(error) as client:
        response = client.get(path)

    assert response.status_code == expected_status
    assert response.json()["detail"]["code"] == expected_code


def test_photo_request_requires_same_origin_and_matching_profile_session(
    client_factory: object,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("ITDA_CANONICAL_APP_ORIGIN", "https://app.test")
    payload = {**REQUEST_PAYLOAD, "photo_job_id": "a" * 64}

    with client_factory(RuntimeError("must not be called")) as client:
        cross_origin = client.post(
            "/v1/recommendation-runs",
            json=payload,
            headers={"Origin": "https://cross-origin.test"},
        )
        missing_session = client.post(
            "/v1/recommendation-runs",
            json=payload,
            headers={"Origin": "https://app.test", "Sec-Fetch-Site": "same-origin"},
        )

    assert cross_origin.status_code == 403
    assert cross_origin.json() == {"detail": "same-origin request required"}
    assert missing_session.status_code == 403
    assert missing_session.json()["detail"]["code"] == "INVALID_RECOMMENDATION_REQUEST"
    assert "photo_job_id" not in missing_session.text


def test_photo_request_rejects_foreign_session_and_unavailable_projection(
    client_factory: object,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("ITDA_CANONICAL_APP_ORIGIN", "https://app.test")
    payload = {**REQUEST_PAYLOAD, "photo_job_id": "b" * 64}
    principal = ProfileSessionPrincipal(
        profile_id="profile:foreign",
        session_digest="d" * 64,
        raw_reference="r" * 43,
    )

    with client_factory(RuntimeError("must not be called")) as client:
        app = client.app
        app.dependency_overrides[get_optional_profile_session] = lambda: principal
        foreign = client.post(
            "/v1/recommendation-runs",
            json=payload,
            headers={"Origin": "https://app.test", "Sec-Fetch-Site": "same-origin"},
        )
        app.dependency_overrides[get_optional_profile_session] = lambda: principal.__class__(
            profile_id=str(REQUEST_PAYLOAD["preference_profile_id"]),
            session_digest=principal.session_digest,
            raw_reference=principal.raw_reference,
        )
        app.dependency_overrides[get_recommendation_service] = lambda: FailingService(
            PhotoRecommendationUnavailable("unavailable")
        )
        unavailable = client.post(
            "/v1/recommendation-runs",
            json=payload,
            headers={"Origin": "https://app.test", "Sec-Fetch-Site": "same-origin"},
        )

    assert foreign.status_code == 403
    assert foreign.json()["detail"]["code"] == "INVALID_RECOMMENDATION_REQUEST"
    assert unavailable.status_code == 422
    assert unavailable.json()["detail"]["code"] == "INVALID_RECOMMENDATION_REQUEST"
    assert "photo_job_id" not in foreign.text
    assert "photo_job_id" not in unavailable.text


def test_operating_information_route_preserves_order_and_disables_shared_cache() -> None:
    class OperatingService:
        def get_operating_information(
            self,
            run_id: str,
            place_ids: tuple[str, ...],
        ) -> OperatingInformationResponse:
            return OperatingInformationResponse(
                run_id=run_id,
                places=tuple(
                    PlaceOperatingInformation(
                        place_id=place_id,
                        state="UNVERIFIED",
                        unavailable_reason="ENRICHMENT_DISABLED",
                    )
                    for place_id in place_ids
                ),
            )

    application = create_app()
    application.dependency_overrides[get_recommendation_service] = OperatingService
    try:
        with TestClient(application) as client:
            response = client.get(
                "/v1/recommendation-runs/recommendation-run:test/operating-information",
                params=[("place_id", "place:b"), ("place_id", "place:a")],
            )
    finally:
        application.dependency_overrides.clear()

    assert response.status_code == 200
    assert response.headers["cache-control"] == "no-store"
    assert [row["place_id"] for row in response.json()["places"]] == [
        "place:b",
        "place:a",
    ]


@pytest.mark.parametrize(
    ("error", "expected_status", "expected_code"),
    [
        (RecommendationRunNotFound("missing"), 404, "RECOMMENDATION_RUN_NOT_FOUND"),
        (
            RecommendationPlaceUnavailable("outside"),
            422,
            "RECOMMENDATION_PLACE_UNAVAILABLE",
        ),
        (RecommendationPinInvalid("stale"), 409, "RECOMMENDATION_PIN_INVALID"),
    ],
)
def test_operating_information_route_maps_pinned_run_failures(
    client_factory: object,
    error: Exception,
    expected_status: int,
    expected_code: str,
) -> None:
    with client_factory(error) as client:
        response = client.get(
            "/v1/recommendation-runs/recommendation-run:test/operating-information",
            params={"place_id": "place:a"},
        )

    assert response.status_code == expected_status
    assert response.json()["detail"]["code"] == expected_code


def test_operating_information_route_rejects_missing_or_oversized_batches() -> None:
    application = create_app()
    application.dependency_overrides[get_recommendation_service] = lambda: FailingService(
        AssertionError("invalid batch must not reach the service")
    )
    try:
        with TestClient(application) as client:
            missing = client.get(
                "/v1/recommendation-runs/recommendation-run:test/operating-information"
            )
            oversized = client.get(
                "/v1/recommendation-runs/recommendation-run:test/operating-information",
                params=[("place_id", f"place:{index}") for index in range(6)],
            )
    finally:
        application.dependency_overrides.clear()

    assert missing.status_code == 422
    assert oversized.status_code == 422


def test_router_has_stable_operation_ids_and_closed_models() -> None:
    document = create_app().openapi()
    expected = {
        ("/v1/recommendation-runs", "post"): "createRecommendationRun",
        ("/v1/recommendation-runs/{run_id}", "get"): "getRecommendationRun",
        (
            "/v1/recommendation-runs/{run_id}/places/{place_id}",
            "get",
        ): "getRecommendationPlaceDetail",
        (
            "/v1/recommendation-runs/{run_id}/operating-information",
            "get",
        ): "getRecommendationOperatingInformation",
        (
            "/v1/recommendation-runs/{run_id}/comparison",
            "get",
        ): "getRecommendationComparison",
        (
            "/v1/saved-place-references/{release_sha256}/{place_id}",
            "get",
        ): "resolveSavedPlaceReference",
    }

    for (path, method), operation_id in expected.items():
        assert document["paths"][path][method]["operationId"] == operation_id
    create = document["paths"]["/v1/recommendation-runs"]["post"]
    results = document["paths"]["/v1/recommendation-runs/{run_id}"]["get"]
    assert create["requestBody"]["content"]["application/json"]["schema"] == {
        "$ref": "#/components/schemas/RecommendationRequest"
    }
    assert create["responses"]["201"]["content"]["application/json"]["schema"] == {
        "$ref": "#/components/schemas/RecommendationRunCreated"
    }
    assert set(create["responses"]) >= {"201", "403", "409", "422", "500", "503"}
    for status_code in ("403", "409", "422", "500", "503"):
        assert create["responses"][status_code]["content"]["application/json"]["schema"] == {
            "$ref": "#/components/schemas/RecommendationErrorResponse"
        }
    assert results["responses"]["200"]["content"]["application/json"]["schema"][
        "anyOf"
    ] == [
        {"$ref": "#/components/schemas/RecommendationResultsResponse"},
        {"$ref": "#/components/schemas/MvpRecommendationResultsResponse"},
    ]


def test_public_results_expose_server_stored_contributions_not_client_targets() -> None:
    schemas = create_app().openapi()["components"]["schemas"]
    request_properties = schemas["RecommendationRequest"]["properties"]
    assert set(request_properties) == {
        "request_id",
        "preference_profile_id",
        "photo_job_id",
    }
    condition_properties = schemas["ConditionContribution"]["properties"]
    assert {
        "condition_id",
        "expected_value",
        "place_value",
        "absolute_difference",
        "fit_score",
        "total_score_weight_bp",
        "weighted_numerator",
    } <= set(condition_properties)
    score_properties = schemas["ScoreContribution"]["properties"]
    assert {
        "axis_components",
        "condition_components",
        "experience_fit_score",
        "travel_condition_fit_score",
        "relevance_score",
        "relevance_numerator",
    } <= set(score_properties)
    assert "condition_targets" not in request_properties
    assert "traits" not in request_properties
    assert "confirmed_traits" not in request_properties
    assert "receipt" not in request_properties
    assert "scores" not in request_properties
