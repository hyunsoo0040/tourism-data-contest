from __future__ import annotations

import hashlib
import json
import os
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from itda.cli.catalog_optional_media_closure import (
    build_closure_authority_context,
    build_current_closure_plan,
    derive_closure_plan,
    execute_captured_replay,
    execute_fresh_collection,
    inspect_closure_response_bounded,
    preflight_fresh_collection,
)
from itda.contracts.authority import AuthorityReplayError
from itda.contracts.catalog_optional_media_closure import (
    CapturedEvidenceRoute,
    ClosureEvidenceCoverage,
    ClosurePlan,
    FreshCollectionBounds,
    FreshCollectionRoute,
)
from itda.domain.canonical import canonical_json_bytes, canonical_sha256

REPO_ROOT = Path(__file__).resolve().parents[3]
NOW = datetime(2026, 7, 31, 8, 0, tzinfo=UTC)


def _digest(label: str) -> str:
    return hashlib.sha256(label.encode()).hexdigest()


def _coverage(plan: ClosurePlan) -> tuple[ClosureEvidenceCoverage, ...]:
    return tuple(
        ClosureEvidenceCoverage(
            place_entity_id=row.place_entity_id,
            provider_candidate_id=row.provider_candidate_id,
            evidence_types=row.non_image_deficits,
        )
        for row in plan.target_rows
    )


def _fresh_plan() -> ClosurePlan:
    terminal = build_current_closure_plan(REPO_ROOT)
    current_parameters = {
        "MobileOS": "ETC",
        "MobileApp": "IT-DA",
        "_type": "json",
        "numOfRows": str(len(terminal.target_rows)),
    }
    predecessor = {**current_parameters, "numOfRows": "1"}
    route = FreshCollectionRoute(
        source_id="official:tour-api:15101578",
        provider="TOUR_API",
        official_dataset_id="15101578",
        source_manifest_sha256=_digest("source"),
        source_approval_sha256=_digest("approval"),
        deterministic_id_join_sha256=_digest("join"),
        host="apis.data.go.kr",
        path="/B551011/KorService2/detailIntro2",
        operation="detailIntro2",
        secret_free_parameters=current_parameters,
        predecessor_request_identity_sha256=None,
        predecessor_secret_free_parameters=predecessor,
        changed_fields=("numOfRows",),
        expected_evidence_types=("description", "operating_information"),
        coverage=_coverage(terminal),
        bounds=FreshCollectionBounds(),
        credential_reference=".secrets/itda-api.env:TOUR_API_SERVICE_KEY",
        alternate_approved_source=False,
    )
    return derive_closure_plan(
        frontier=terminal.frontier,
        provider_ids_by_place=terminal.provider_ids_by_place,
        attempted_provider_ids=frozenset(terminal.attempted_provider_ids),
        captured_routes=(),
        fresh_routes=(route,),
    )


def _captured_plan(tmp_path: Path) -> ClosurePlan:
    terminal = build_current_closure_plan(REPO_ROOT)
    evidence_path = tmp_path / "captured" / "evidence.json"
    evidence_path.parent.mkdir()
    rows = []
    for target in terminal.target_rows:
        facts = {field: f"{target.place_entity_id}:{field}" for field in target.non_image_deficits}
        rows.append(
            {
                "place_entity_id": target.place_entity_id,
                "provider_candidate_id": target.provider_candidate_id,
                "normalized_facts": facts,
                "response_sha256": _digest(target.place_entity_id + ":response"),
                "evidence_sha256": _digest(target.place_entity_id + ":evidence"),
            }
        )
    evidence_path.write_bytes(canonical_json_bytes({"rows": rows}))
    file_digest = hashlib.sha256(evidence_path.read_bytes()).hexdigest()
    source_root = canonical_sha256({"evidence_files": {"captured/evidence.json": file_digest}})
    evidence_root = canonical_sha256([file_digest])
    manifest = {
        "schema_version": "itda.catalog-optional-media-captured-evidence.v1",
        "source_root_sha256": source_root,
        "evidence_root_sha256": evidence_root,
        "rights_manifest_sha256": _digest("rights"),
        "identity_manifest_sha256": _digest("identity"),
        "lineage_manifest_sha256": _digest("lineage"),
        "evidence_files": {"captured/evidence.json": file_digest},
    }
    (tmp_path / "captured" / "manifest.json").write_bytes(canonical_json_bytes(manifest))
    route = CapturedEvidenceRoute(
        source_id="captured:test-fixture:v1",
        source_root_sha256=source_root,
        evidence_root_sha256=evidence_root,
        rights_manifest_sha256=manifest["rights_manifest_sha256"],
        identity_manifest_sha256=manifest["identity_manifest_sha256"],
        lineage_manifest_sha256=manifest["lineage_manifest_sha256"],
        manifest_relative_path="captured/manifest.json",
        evidence_relative_paths=("captured/evidence.json",),
        coverage=_coverage(terminal),
        admissible=True,
    )
    return derive_closure_plan(
        frontier=terminal.frontier,
        provider_ids_by_place=terminal.provider_ids_by_place,
        attempted_provider_ids=frozenset(terminal.attempted_provider_ids),
        captured_routes=(route,),
        fresh_routes=(),
    )


def test_captured_replay_rejects_every_external_capability(tmp_path: Path) -> None:
    plan = _captured_plan(tmp_path)

    def forbidden(*args, **kwargs):
        raise AssertionError("external")

    for kwargs in (
        {"authorization_token": "forbidden"},
        {"credential_path": tmp_path / "secret"},
        {"dns_resolver": forbidden},
        {"requester": forbidden},
    ):
        with pytest.raises(ValueError, match="captured|forbidden|external"):
            execute_captured_replay(tmp_path, plan=plan, **kwargs)

    evidence = execute_captured_replay(tmp_path, plan=plan)
    assert evidence.execution_mode == "captured_replay"
    assert evidence.attempts == ()
    assert evidence.provider_traffic_performed is False


def test_fresh_preflight_requires_authority_before_all_external_opens() -> None:
    plan = _fresh_plan()
    calls: list[str] = []

    result = preflight_fresh_collection(
        plan,
        authorization_token=None,
        credential_opener=lambda: calls.append("credential"),
        dns_resolver=lambda: calls.append("dns"),
        requester_factory=lambda: calls.append("requester"),
        nonce_mutator=lambda: calls.append("nonce"),
    )

    assert result["status"] == "AUTHORIZATION_REQUIRED"
    assert calls == []


def test_fresh_authority_is_exact_and_precedes_credential_open(tmp_path: Path) -> None:
    plan = _fresh_plan()
    context = build_closure_authority_context(
        plan,
        reviewer_id="closure-reviewer",
        nonce="a" * 64,
        issued_at=NOW,
        expires_at=NOW + timedelta(minutes=10),
    )
    forged = context.expected_token().model_copy(update={"target_sha256": "f" * 64}).serialize()
    opened = False

    def credential_opener() -> str:
        nonlocal opened
        opened = True
        return "never-read"

    with pytest.raises(ValueError, match="authority|target|stale"):
        execute_fresh_collection(
            tmp_path,
            plan=plan,
            authorization_token=forged,
            issuance_context=context,
            reviewer_id="closure-reviewer",
            now=NOW + timedelta(minutes=1),
            credential_opener=credential_opener,
            requester=object(),
        )
    assert opened is False


def test_fresh_credential_is_protected_and_never_serialized(tmp_path: Path) -> None:
    plan = _fresh_plan()
    context = build_closure_authority_context(
        plan,
        reviewer_id="closure-reviewer",
        nonce="b" * 64,
        issued_at=NOW,
        expires_at=NOW + timedelta(minutes=10),
    )
    credential = "super-secret-service-key"
    credential_file = tmp_path / "itda-api.env"
    credential_file.write_text(f"TOUR_API_SERVICE_KEY={credential}\n", encoding="utf-8")
    os.chmod(credential_file, 0o644)

    with pytest.raises(ValueError) as error:
        execute_fresh_collection(
            tmp_path,
            plan=plan,
            authorization_token=context.expected_token().serialize(),
            issuance_context=context,
            reviewer_id="closure-reviewer",
            now=NOW + timedelta(minutes=1),
            credential_path=credential_file,
            requester=object(),
        )
    assert credential not in str(error.value)


class _Response:
    def __init__(self, body: bytes, *, status: int = 200, headers=None) -> None:
        self.status_code = status
        self.headers = headers or {}
        self._body = body

    def iter_bytes(self):
        yield self._body

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, traceback):
        return False


class _Requester:
    def __init__(self, responses: list[_Response]) -> None:
        self.responses = responses
        self.calls: list[tuple[str, str, dict[str, object]]] = []

    def stream(self, method: str, url: str, **kwargs):
        self.calls.append((method, url, kwargs))
        return self.responses.pop(0)


def test_response_is_bounded_before_json_and_redirects_are_denied() -> None:
    bounds = FreshCollectionBounds(max_response_bytes=128, max_items=2, max_json_depth=4)
    oversized = _Response(b"{" + b"x" * 128)
    with pytest.raises(ValueError, match="byte|size|limit"):
        inspect_closure_response_bounded(oversized, bounds=bounds)

    redirect = _Response(b"{}", status=302, headers={"location": "https://evil.invalid"})
    with pytest.raises(ValueError, match="redirect|HTTP"):
        inspect_closure_response_bounded(redirect, bounds=bounds)

    deep = _Response(json.dumps({"a": {"b": {"c": {"d": {"e": 1}}}}}).encode())
    with pytest.raises(ValueError, match="depth"):
        inspect_closure_response_bounded(deep, bounds=bounds)


def test_exact_authority_and_private_credential_enable_only_bounded_route(
    tmp_path: Path,
) -> None:
    plan = _fresh_plan()
    context = build_closure_authority_context(
        plan,
        reviewer_id="closure-reviewer",
        nonce="c" * 64,
        issued_at=NOW,
        expires_at=NOW + timedelta(minutes=10),
    )
    credential = "test-only-secret"
    credential_file = tmp_path / "itda-api.env"
    credential_file.write_text(f"TOUR_API_SERVICE_KEY={credential}\n", encoding="utf-8")
    os.chmod(credential_file, 0o600)
    items = [
        {
            "contentid": target.provider_candidate_id.removeprefix("candidate:tour-api:"),
            "overview": f"description for {target.place_entity_id}",
            "infocenter": f"operations for {target.place_entity_id}",
        }
        for target in plan.target_rows
    ]
    success_body = canonical_json_bytes(
        {
            "response": {
                "header": {"resultCode": "0000", "resultMsg": "OK"},
                "body": {"items": {"item": items}},
            }
        }
    )
    requester = _Requester(
        [
            _Response(b"{}", status=429),
            _Response(success_body),
        ]
    )
    token = context.expected_token().serialize()

    evidence = execute_fresh_collection(
        tmp_path,
        plan=plan,
        authorization_token=token,
        issuance_context=context,
        reviewer_id="closure-reviewer",
        now=NOW + timedelta(minutes=1),
        credential_path=credential_file,
        requester=requester,
    )

    assert [attempt.outcome for attempt in evidence.attempts] == [
        "TRANSIENT_RETRY",
        "SUCCESS",
    ]
    assert all(
        url == "https://apis.data.go.kr/B551011/KorService2/detailIntro2"
        and kwargs["follow_redirects"] is False
        and kwargs["timeout"] == 300
        for _, url, kwargs in requester.calls
    )
    assert credential not in evidence.model_dump_json()
    with pytest.raises(AuthorityReplayError):
        execute_fresh_collection(
            tmp_path,
            plan=plan,
            authorization_token=token,
            issuance_context=context,
            reviewer_id="closure-reviewer",
            now=NOW + timedelta(minutes=1),
            credential_path=credential_file,
            requester=_Requester([_Response(success_body)]),
        )
