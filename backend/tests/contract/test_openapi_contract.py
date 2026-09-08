from __future__ import annotations

import json
from pathlib import Path

from fastapi.testclient import TestClient

from itda.api.main import app
from itda.cli.export_openapi import openapi_document_bytes
from itda.contracts.questionnaire_v2 import QUESTIONNAIRE_DEFINITION_V2

REPOSITORY_ROOT = Path(__file__).resolve().parents[3]
MAKEFILE = REPOSITORY_ROOT / "Makefile"
OPENAPI_ARTIFACT = REPOSITORY_ROOT / "contracts" / "openapi.json"
QUESTIONNAIRE_ARTIFACT = REPOSITORY_ROOT / "contracts" / "questionnaire-v2.json"


def test_committed_openapi_matches_deterministic_export_byte_for_byte() -> None:
    assert OPENAPI_ARTIFACT.read_bytes() == openapi_document_bytes()


def test_questionnaire_source_artifact_and_served_response_are_exactly_equal() -> None:
    artifact = json.loads(QUESTIONNAIRE_ARTIFACT.read_text())
    source = QUESTIONNAIRE_DEFINITION_V2.model_dump(mode="json")

    with TestClient(app) as client:
        response = client.get("/v1/questionnaires/current")

    assert source == artifact
    assert response.status_code == 200
    assert response.json() == artifact
    assert [question["question_id"] for question in artifact["questions"]] == [
        f"q{ordinal}" for ordinal in artifact["question_order"]
    ]


def test_openapi_paths_use_pydantic_request_and_response_schemas() -> None:
    document = app.openapi()
    paths = document["paths"]

    questionnaire_response = paths["/v1/questionnaires/current"]["get"]["responses"]["200"]
    create_operation = paths["/v1/preference-profiles"]["post"]
    get_operation = paths["/v1/preference-profiles/{profile_id}"]["get"]

    assert questionnaire_response["content"]["application/json"]["schema"] == {
        "$ref": "#/components/schemas/QuestionnaireDefinitionV2"
    }
    assert create_operation["requestBody"]["content"]["application/json"]["schema"] == {
        "$ref": "#/components/schemas/QuestionnaireSubmission"
    }
    assert create_operation["responses"]["201"]["content"]["application/json"]["schema"] == {
        "$ref": "#/components/schemas/PreferenceProfile"
    }
    assert create_operation["responses"]["409"]["content"]["application/json"]["schema"] == {
        "$ref": "#/components/schemas/ErrorResponse"
    }
    assert get_operation["responses"]["200"]["content"]["application/json"]["schema"] == {
        "$ref": "#/components/schemas/PreferenceProfile"
    }
    assert get_operation["responses"]["404"]["content"]["application/json"]["schema"] == {
        "$ref": "#/components/schemas/ErrorResponse"
    }


def test_contract_target_compiles_generated_consumer_types() -> None:
    contract_recipe = MAKEFILE.read_text().split("contract:\n", maxsplit=1)[1]

    assert "$(PNPM) typecheck" in contract_recipe
    assert "$(PNPM) exec tsc -p tsconfig.e2e.json --noEmit" in contract_recipe


def test_profile_release_operations_publish_security_and_failure_contracts() -> None:
    document = app.openapi()
    assert document["components"]["securitySchemes"]["Phase3Capability"] == {
        "in": "header",
        "name": "X-ITDA-Phase3-Capability",
        "type": "apiKey",
    }
    operations = [
        (path, operation)
        for path, path_item in document["paths"].items()
        if path.startswith("/internal/evaluation/profile-releases")
        for method, operation in path_item.items()
        if method in {"get", "post"}
    ]
    assert operations
    for path, operation in operations:
        assert operation["security"] == [{"Phase3Capability": []}]
        for status_code in ("401", "403", "404", "409"):
            assert operation["responses"][status_code]["content"]["application/json"][
                "schema"
            ] == {"$ref": "#/components/schemas/ProfileReleaseErrorResponse"}
        unavailable_schema = operation["responses"]["503"]["content"]["application/json"][
            "schema"
        ]
        if (
            operation["operationId"].startswith("get_profile_release_")
            or path == "/internal/evaluation/profile-releases/build-drafts"
        ):
            assert unavailable_schema == {
                "$ref": "#/components/schemas/ProfileReleaseErrorResponse"
            }
        elif path == "/internal/evaluation/profile-releases/build-drafts/build":
            assert unavailable_schema["anyOf"] == [
                {"$ref": "#/components/schemas/ProfileReleaseUnknownOutcomeResponse"},
                {"$ref": "#/components/schemas/ProfileReleaseRetryableAbortResponse"},
                {
                    "$ref": (
                        "#/components/schemas/"
                        "ProfileReleaseBuildUnavailableResponse"
                    )
                },
                {
                    "$ref": (
                        "#/components/schemas/"
                        "ProfileReleaseDraftCleanupUnknownResponse"
                    )
                },
            ]
        elif path == "/internal/evaluation/profile-releases/build":
            assert unavailable_schema["anyOf"] == [
                {"$ref": "#/components/schemas/ProfileReleaseUnknownOutcomeResponse"},
                {"$ref": "#/components/schemas/ProfileReleaseRetryableAbortResponse"},
                {
                    "$ref": (
                        "#/components/schemas/"
                        "ProfileReleaseBuildUnavailableResponse"
                    )
                },
            ]
        else:
            assert unavailable_schema["anyOf"] == [
                {"$ref": "#/components/schemas/ProfileReleaseUnknownOutcomeResponse"},
                {"$ref": "#/components/schemas/ProfileReleaseRetryableAbortResponse"},
            ]

        assert operation["responses"]["422"]["content"]["application/json"][
            "schema"
        ] == {"$ref": "#/components/schemas/ProfileReleaseErrorResponse"}
