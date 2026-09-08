from __future__ import annotations

import hashlib
import json
import os
from base64 import b64encode
from datetime import UTC, datetime
from pathlib import Path
from types import SimpleNamespace

import httpx
import pytest
from pydantic import ValidationError

import itda.cli.collect_preview as collect_preview_module
import itda.contracts.candidate_review as candidate_review_module
from itda.cli.collect_preview import CHECK_MALFORMED, CHECK_RESOLVED, CHECK_UNRESOLVED
from itda.cli.collect_preview import main as collect_preview_main
from itda.collectors.base import CollectedResponse, RequestPolicy
from itda.collectors.diagnostics import ProviderDiagnosticsError
from itda.contracts.candidate_review import (
    BLOCKED_RIGHTS_STATUS,
    LOCKED_PREVIEW_CANDIDATES,
    CandidateReview,
    RawProviderBundle,
    RawProviderBundleRow,
    build_review_manifest,
    canonical_json_bytes,
    check_candidate_review,
    check_review_manifest,
    render_candidate_review_markdown,
)
from itda.contracts.provenance import MAX_PROVIDER_JSON_NODES

PROVIDER_RAW_LIMIT = 2_000_000
PROVIDER_BASE64_LIMIT = 4 * ((PROVIDER_RAW_LIMIT + 2) // 3)
SELECTED_LIVE_IDENTITIES = (
    ("불국사", "126166", "2", "5", "불국사"),
    ("석굴암", "126216", "2983", "4639", "석굴암"),
    ("첨성대", "126207", "2967", "4623", "첨성대"),
    ("동궁과 월지", "128526", "2961", "4617", "동궁과 월지"),
    ("대릉원 일원", "1492402", "2960", "4616", "대릉원"),
    ("황리단길", "2658227", "1312", "2357", "황리단길"),
)


def _sha(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def test_source_lock_read_fails_closed_before_open_without_nofollow(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    real_os = candidate_review_module.os
    opened = False

    def unexpected_open(*args: object, **kwargs: object) -> int:
        nonlocal opened
        opened = True
        raise AssertionError("source lock must not be opened without secure platform flags")

    unsupported_os = SimpleNamespace(
        O_RDONLY=real_os.O_RDONLY,
        O_DIRECTORY=real_os.O_DIRECTORY,
        open=unexpected_open,
        stat=real_os.stat,
        supports_dir_fd=frozenset({unexpected_open, real_os.stat}),
        supports_follow_symlinks=frozenset({real_os.stat}),
    )
    monkeypatch.setattr(candidate_review_module, "os", unsupported_os)

    with pytest.raises(ValueError, match="O_NOFOLLOW"):
        candidate_review_module.load_preview_source_lock(tmp_path / "preview-v1-source-lock.json")

    assert not opened


def _raw_body(provider: str, index: int) -> bytes:
    return json.dumps(
        {
            "candidate": index,
            "provider": provider,
            "rightsRows": ([{"cpyrhtDivCd": "Type3"}] if provider == "TOUR_API" else []),
        },
        sort_keys=True,
        separators=(",", ":"),
    ).encode()


def _pathological_provider_json(shape: str) -> bytes:
    if shape == "deep":
        return b"[" * 1_100 + b"{}" + b"]" * 1_100
    assert shape == "wide"
    return ("[" + ",".join("0" for _ in range(MAX_PROVIDER_JSON_NODES)) + "]").encode()


def _provider_json_body_of_size(size: int) -> bytes:
    prefix = b'{"payload":"'
    suffix = b'"}'
    assert size >= len(prefix) + len(suffix)
    return prefix + b"x" * (size - len(prefix) - len(suffix)) + suffix


def _candidate(index: int, *, resolved: bool = True) -> dict[str, object]:
    name = LOCKED_PREVIEW_CANDIDATES[index]
    evidence: list[dict[str, object]] = []
    for provider in ("TOUR_API", "ODII"):
        evidence.append(
            {
                "provider": provider,
                "source_id": f"{provider.lower()}-{index}" if resolved else None,
                "endpoint": (
                    "KorService2/detailCommon2" if provider == "TOUR_API" else "Odii/storyBasedList"
                ),
                "request_scope": {"candidate": name},
                "retrieved_at": "2026-07-22T12:00:00Z",
                "http_status": 200,
                "raw_response_sha256": _sha(_raw_body(provider, index)),
                "modifiedtime": None,
                "upstream_rights": ([{"cpyrhtDivCd": "Type3"}] if provider == "TOUR_API" else []),
                "asset_usage_status": BLOCKED_RIGHTS_STATUS,
                "unresolved_reason": None if resolved else "upstream evidence missing",
            }
        )
    return {
        "place_id": f"preview:{index + 1}",
        "name_ko": name,
        "split": "PREVIEW",
        "assessment_status": "NOT_SCORED",
        "resolution_status": "RESOLVED" if resolved else "UNRESOLVED",
        "evidence": evidence,
    }


def _bundle_rows(candidates: list[dict[str, object]]) -> list[dict[str, object]]:
    rows: list[dict[str, object]] = []
    for index, candidate in enumerate(candidates):
        for evidence in candidate["evidence"]:
            provider = evidence["provider"]
            raw_body = _raw_body(provider, index)
            rights = [{"cpyrhtDivCd": "Type3"}] if provider == "TOUR_API" else []
            rows.append(
                {
                    "candidate_place_id": candidate["place_id"],
                    "provider": provider,
                    "endpoint": evidence["endpoint"],
                    "request_scope": evidence["request_scope"],
                    "source_id": evidence["source_id"],
                    "retrieved_at": evidence["retrieved_at"],
                    "http_status": evidence["http_status"],
                    "raw_response_sha256": _sha(raw_body),
                    "raw_body_base64": b64encode(raw_body).decode(),
                    "modifiedtime": evidence["modifiedtime"],
                    "rights": rights,
                    "asset_usage_status": evidence["asset_usage_status"],
                }
            )
    return rows


def _write_review(
    root: Path,
    *,
    unresolved_index: int | None = None,
    all_unresolved: bool = False,
    bundle_name: str = "provider-bundle.json",
) -> tuple[Path, Path, bytes]:
    candidates = [
        _candidate(index, resolved=not all_unresolved and index != unresolved_index)
        for index in range(6)
    ]
    bundle = root / bundle_name
    bundle_bytes = (
        json.dumps(
            {
                "schema_version": "provider-bundle-v1",
                "redacted": True,
                "rows": _bundle_rows(candidates),
            },
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        )
        + "\n"
    ).encode()
    bundle.write_bytes(bundle_bytes)
    review_payload = {
        "schema_version": "candidate-review-v1",
        "artifact_status": "REVIEW_ONLY",
        "bundle_path": bundle.name,
        "redacted_bundle_sha256": _sha(bundle_bytes),
        "candidates": candidates,
    }
    review_bytes = (
        json.dumps(review_payload, ensure_ascii=False, sort_keys=True, separators=(",", ":")) + "\n"
    ).encode()
    review = root / "candidate-review.json"
    review.write_bytes(review_bytes)
    return review, bundle, review_bytes


def test_candidate_review_v1_rejects_explicit_null_rights_review(tmp_path: Path) -> None:
    review_path, _, review_bytes = _write_review(tmp_path)
    legacy_payload = json.loads(review_bytes)
    assert CandidateReview.model_validate(legacy_payload).schema_version == "candidate-review-v1"

    legacy_payload["rights_review"] = None
    with pytest.raises(ValidationError, match="candidate-review-v1 must omit rights_review"):
        CandidateReview.model_validate(legacy_payload)

    assert CandidateReview.model_validate_json(review_path.read_bytes()).rights_review is None


def test_candidate_review_v1_canonical_round_trip_preserves_rights_review_omission(
    tmp_path: Path,
) -> None:
    review_path, _, _ = _write_review(tmp_path)
    review = CandidateReview.model_validate_json(review_path.read_bytes())

    payload = review.model_dump(mode="json")
    assert "rights_review" not in payload
    canonical = canonical_json_bytes(payload)
    revalidated = CandidateReview.model_validate_json(canonical)

    assert "rights_review" not in revalidated.model_fields_set
    assert canonical_json_bytes(revalidated.model_dump(mode="json")) == canonical


def test_candidate_review_v2_canonical_round_trip_preserves_rights_review_hash() -> None:
    review_path = (
        Path(__file__).resolve().parents[3]
        / "fixtures/preview/v1/review/candidate-review.json"
    )
    original = review_path.read_bytes()
    review = CandidateReview.model_validate_json(original)

    payload = review.model_dump(mode="json")
    assert review.schema_version == "candidate-review-v2"
    assert payload["rights_review"] is not None
    assert review.rights_review is not None
    assert review.rights_review.policy_version == "official-public-data-contest-v2"
    assert all(
        candidate.selected_odii_story is not None
        for candidate in review.rights_review.candidates
    )
    canonical = canonical_json_bytes(payload)
    assert canonical == original
    assert _sha(canonical) == "12875e60d591e8824b32642df204ea2ce626bada22000e75ca1dd16e37a6d89d"

    revalidated = CandidateReview.model_validate_json(canonical)
    assert canonical_json_bytes(revalidated.model_dump(mode="json")) == canonical


def _replace_first_review_raw_body(review: Path, bundle: Path, raw_body: bytes) -> None:
    review_payload = json.loads(review.read_text(encoding="utf-8"))
    bundle_payload = json.loads(bundle.read_text(encoding="utf-8"))
    raw_hash = _sha(raw_body)
    encoded = b64encode(raw_body).decode("ascii")
    row = bundle_payload["rows"][0]
    row["raw_body_base64"] = encoded
    row["raw_response_sha256"] = raw_hash
    row["rights"] = []
    evidence = review_payload["candidates"][0]["evidence"][0]
    evidence["raw_response_sha256"] = raw_hash
    evidence["upstream_rights"] = []
    bundle_bytes = (
        json.dumps(
            bundle_payload,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        )
        + "\n"
    ).encode()
    bundle.write_bytes(bundle_bytes)
    review_payload["redacted_bundle_sha256"] = _sha(bundle_bytes)
    review.write_bytes(
        (
            json.dumps(
                review_payload,
                ensure_ascii=False,
                sort_keys=True,
                separators=(",", ":"),
            )
            + "\n"
        ).encode()
    )


def _collected(
    provider: str,
    operation: str,
    payload: object,
    *,
    scope: dict[str, str],
    rights: tuple[dict[str, str], ...] | None = None,
) -> CollectedResponse:
    effective_rights = (
        rights
        if rights is not None
        else (({"cpyrhtDivCd": "Type3"},) if provider == "TOUR_API" else ())
    )
    payload_with_rights = (
        {**payload, "testRightsRows": list(effective_rights)}
        if isinstance(payload, dict) and effective_rights
        else payload
    )
    raw_body = json.dumps(payload_with_rights, ensure_ascii=False, separators=(",", ":")).encode()
    return CollectedResponse(
        provider=provider,
        endpoint=(f"KorService2/{operation}" if provider == "TOUR_API" else f"Odii/{operation}"),
        request_scope=scope,
        retrieved_at=datetime(2026, 7, 22, 12, 0, tzinfo=UTC),
        http_status=200,
        raw_response_sha256=_sha(raw_body),
        raw_body_base64=b64encode(raw_body).decode(),
        modifiedtime=None,
        rights=effective_rights,
        payload=payload_with_rights,
    )


def _install_live_clients(
    monkeypatch: pytest.MonkeyPatch,
    *,
    mismatch: str | None = None,
    tour_rights: tuple[dict[str, str], ...] | None = None,
) -> list[tuple[str, str, dict[str, object]]]:
    calls: list[tuple[str, str, dict[str, object]]] = []
    candidate_index = {name: index for index, name in enumerate(LOCKED_PREVIEW_CANDIDATES)}

    class FakeClient:
        provider = ""

        def __init__(self, *, service_key: str, policy: RequestPolicy) -> None:
            assert service_key
            assert policy.timeout_seconds == 5.0

        def __enter__(self) -> FakeClient:
            return self

        def __exit__(self, *args: object) -> None:
            return None

        def request(
            self,
            operation: str,
            params: dict[str, object],
            *,
            explicit_opt_in: bool,
        ) -> CollectedResponse:
            assert explicit_opt_in is True
            calls.append((self.provider, operation, dict(params)))
            name = str(params.get("keyword") or params.get("searchKeyword") or "")
            if name:
                index = candidate_index[name]
            else:
                identifier = str(params.get("contentId") or params.get("tid") or "")
                index = int(identifier.rsplit("-", maxsplit=1)[-1])
                name = LOCKED_PREVIEW_CANDIDATES[index]
            title = name
            address = "경상북도 경주시 테스트로 1"
            longitude = 129.20 + index * 0.001
            latitude = 35.80 + index * 0.001
            content_id = f"tour-discovered-{index}"
            tid = f"theme-discovered-{index}"
            tlid = f"location-discovered-{index}"

            if operation == "searchKeyword2":
                rows: list[dict[str, object]] = [
                    {
                        "contentid": content_id,
                        "title": title,
                        "addr1": address,
                        "mapx": longitude,
                        "mapy": latitude,
                    }
                ]
                if mismatch == "absent" and index == 0:
                    rows = []
                elif mismatch == "ambiguous" and index == 0:
                    rows.append({**rows[0], "contentid": "tour-other"})
                elif mismatch == "duplicate" and index == 0:
                    rows.append(dict(rows[0]))
                elif mismatch == "wrong-title" and index == 0:
                    rows[0]["title"] = "다른 관광지"
                elif mismatch == "wrong-address" and index == 0:
                    rows[0]["addr1"] = "서울특별시"
                return _collected(
                    self.provider,
                    operation,
                    {"response": {"body": {"items": {"item": rows}}}},
                    scope={"keyword": name},
                    rights=tour_rights if self.provider == "TOUR_API" else None,
                )

            if operation == "themeSearchList":
                row = {
                    "tid": tid,
                    "tlid": tlid,
                    "title": title,
                    "addr1": address,
                    "mapx": longitude,
                    "mapy": latitude,
                }
                if mismatch == "wrong-coordinates" and index == 0:
                    row["mapx"] = 127.0
                return _collected(
                    self.provider,
                    operation,
                    {"response": {"body": {"items": {"item": [row]}}}},
                    scope={"keyword": name},
                    rights=tour_rights if self.provider == "TOUR_API" else None,
                )

            if operation == "detailCommon2":
                requested_id = str(params["contentId"])
                row_id = (
                    "wrong-detail-id" if mismatch == "wrong-id" and index == 0 else requested_id
                )
                payload = {
                    "response": {
                        "body": {
                            "items": {
                                "item": [
                                    {
                                        "contentid": row_id,
                                        "title": title,
                                        "addr1": address,
                                        "mapx": longitude,
                                        "mapy": latitude,
                                    }
                                ]
                            }
                        }
                    }
                }
                return _collected(
                    self.provider,
                    operation,
                    payload,
                    scope={"contentId": requested_id},
                    rights=tour_rights if self.provider == "TOUR_API" else None,
                )

            if operation == "detailImage2":
                requested_id = str(params["contentId"])
                return _collected(
                    self.provider,
                    operation,
                    {"response": {"body": {"items": {"item": []}}}},
                    scope={"contentId": requested_id},
                    rights=tour_rights if self.provider == "TOUR_API" else None,
                )

            assert operation == "storyBasedList"
            return _collected(
                self.provider,
                operation,
                {
                    "response": {
                        "body": {
                            "items": {
                                "item": [
                                    {
                                        "storyid": f"story-discovered-{index}",
                                        "tid": params["tid"],
                                        "tlid": params["tlid"],
                                        "title": title,
                                        "addr1": address,
                                        "mapx": longitude,
                                        "mapy": latitude,
                                    }
                                ]
                            }
                        }
                    }
                },
                scope={"tid": str(params["tid"]), "tlid": str(params["tlid"])},
                rights=tour_rights if self.provider == "TOUR_API" else None,
            )

    class FakeKto(FakeClient):
        provider = "TOUR_API"

    class FakeOdii(FakeClient):
        provider = "ODII"

    monkeypatch.setattr(collect_preview_module, "KorService2Client", FakeKto)
    monkeypatch.setattr(collect_preview_module, "OdiiClient", FakeOdii)
    monkeypatch.setattr(
        collect_preview_module,
        "_load_live_credentials",
        lambda: ("tour-key", "odii-key"),
    )
    monkeypatch.setenv("TOUR_API_SERVICE_KEY", "tour-key")
    monkeypatch.setenv("ODII_SERVICE_KEY", "odii-key")
    monkeypatch.delenv("CI", raising=False)
    monkeypatch.delenv("ITDA_NO_NETWORK", raising=False)
    return calls


def _selected_live_args() -> list[str]:
    args: list[str] = []
    for selection in SELECTED_LIVE_IDENTITIES:
        args.extend(("--candidate-selection", *selection))
    return args


def _install_selected_live_clients(
    monkeypatch: pytest.MonkeyPatch,
    *,
    mismatch: str | None = None,
) -> list[tuple[str, str, dict[str, object]]]:
    calls: list[tuple[str, str, dict[str, object]]] = []
    by_name = {item[0]: (index, item) for index, item in enumerate(SELECTED_LIVE_IDENTITIES)}
    by_keyword = {item[4]: (index, item) for index, item in enumerate(SELECTED_LIVE_IDENTITIES)}
    by_tour_id = {item[1]: (index, item) for index, item in enumerate(SELECTED_LIVE_IDENTITIES)}
    by_odii_ids = {
        (item[2], item[3]): (index, item) for index, item in enumerate(SELECTED_LIVE_IDENTITIES)
    }

    class FakeClient:
        provider = ""

        def __init__(self, *, service_key: str, policy: RequestPolicy) -> None:
            assert service_key
            assert policy.timeout_seconds == 5.0

        def __enter__(self) -> FakeClient:
            return self

        def __exit__(self, *args: object) -> None:
            return None

        def request(
            self,
            operation: str,
            params: dict[str, object],
            *,
            explicit_opt_in: bool,
        ) -> CollectedResponse:
            assert explicit_opt_in is True
            calls.append((self.provider, operation, dict(params)))
            if operation == "searchKeyword2":
                index, selection = by_name[str(params["keyword"])]
            elif operation == "themeSearchList":
                index, selection = by_keyword[str(params["keyword"])]
            elif operation in {"detailCommon2", "detailImage2"}:
                index, selection = by_tour_id[str(params["contentId"])]
            else:
                assert operation == "storyBasedList"
                index, selection = by_odii_ids[(str(params["tid"]), str(params["tlid"]))]

            name, tour_id, tid, tlid, _keyword = selection
            longitude = 129.20 + index * 0.001
            latitude = 35.80 + index * 0.001
            tour_title = f"경주 {name}"
            odii_title = "경주 대릉원" if name == "대릉원 일원" else f"경주 {name}"
            if operation == "searchKeyword2":
                rows = [
                    {
                        "contentid": tour_id,
                        "title": tour_title,
                        "addr1": "경상북도 경주시 테스트로 1",
                        "mapx": longitude,
                        "mapy": latitude,
                    }
                ]
                if mismatch == "duplicate-selected-search-row" and index == 0:
                    rows.append(dict(rows[0]))
                return _collected(
                    self.provider,
                    operation,
                    {"response": {"body": {"items": {"item": rows}}}},
                    scope={"keyword": str(params["keyword"])},
                )
            if operation == "themeSearchList":
                row = {
                    "tid": tid,
                    "tlid": tlid,
                    "title": odii_title,
                    "addr1": "경상북도",
                    "mapx": longitude + 0.0001,
                    "mapy": latitude + 0.0001,
                }
                if mismatch == "wrong-tid" and index == 0:
                    row["tid"] = "9998"
                elif mismatch == "wrong-tlid" and index == 0:
                    row["tlid"] = "9999"
                elif mismatch == "coordinate-drift" and index == 0:
                    row["mapx"] = 127.0
                return _collected(
                    self.provider,
                    operation,
                    {"response": {"body": {"items": {"item": [row]}}}},
                    scope={"keyword": str(params["keyword"])},
                )
            if operation == "detailCommon2":
                detail_row = {
                    "contentid": tour_id,
                    "title": tour_title,
                    "addr1": "경상북도 경주시 테스트로 1",
                    "mapx": longitude,
                    "mapy": latitude,
                }
                if mismatch == "wrong-detail-id" and index == 0:
                    detail_row["contentid"] = "9997"
                elif mismatch == "wrong-detail-coordinates" and index == 0:
                    detail_row["mapx"] = 127.0
                return _collected(
                    self.provider,
                    operation,
                    {"response": {"body": {"items": {"item": [detail_row]}}}},
                    scope={"contentId": tour_id},
                )
            if operation == "detailImage2":
                return _collected(
                    self.provider,
                    operation,
                    {"response": {"body": {"items": {"item": []}}}},
                    scope={"contentId": tour_id},
                )
            story_rows = [
                {
                    "stid": f"story-theme-{index}",
                    "stlid": f"story-location-{index}",
                    "tid": tid,
                    "tlid": tlid,
                    "title": odii_title,
                    "mapX": longitude + 0.0001,
                    "mapY": latitude + 0.0001,
                },
                {
                    "stid": f"story-supplement-{index}",
                    "stlid": f"story-supplement-location-{index}",
                    "tid": tid,
                    "tlid": tlid,
                    "title": "보조 이야기",
                    "mapX": longitude + 0.0002,
                    "mapY": latitude + 0.0002,
                },
            ]
            if mismatch == "mixed-pair-stories" and index == 0:
                story_rows[1]["tlid"] = "9996"
            elif mismatch == "supplementary-only-stories" and index == 0:
                story_rows[0]["title"] = "보조 이야기"
            return _collected(
                self.provider,
                operation,
                {"response": {"body": {"items": {"item": story_rows}}}},
                scope={"tid": tid, "tlid": tlid},
            )

    class FakeKto(FakeClient):
        provider = "TOUR_API"

    class FakeOdii(FakeClient):
        provider = "ODII"

    monkeypatch.setattr(collect_preview_module, "KorService2Client", FakeKto)
    monkeypatch.setattr(collect_preview_module, "OdiiClient", FakeOdii)
    monkeypatch.setattr(
        collect_preview_module,
        "_load_live_credentials",
        lambda: ("tour-key", "odii-key"),
    )
    monkeypatch.delenv("CI", raising=False)
    monkeypatch.delenv("ITDA_NO_NETWORK", raising=False)
    return calls


def test_check_review_returns_zero_for_exact_six_resolved_candidates(tmp_path: Path) -> None:
    review, _, _ = _write_review(tmp_path)

    result = check_candidate_review(review)

    assert result.exit_code == CHECK_RESOLVED == 0
    assert result.review is not None
    assert tuple(candidate.name_ko for candidate in result.review.candidates) == (
        LOCKED_PREVIEW_CANDIDATES
    )
    assert result.exit_code == 0


def test_check_review_returns_two_for_explicit_unresolved_evidence(tmp_path: Path) -> None:
    review, _, _ = _write_review(tmp_path, unresolved_index=3)

    result = check_candidate_review(review)

    assert result.exit_code == CHECK_UNRESOLVED == 2
    assert result.review is not None
    assert result.exit_code == 2


def test_live_collection_cli_refuses_ci_before_creating_output(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("CI", "true")
    output = tmp_path / "live-review"

    assert collect_preview_main(["--live", "--output", str(output)]) == 78
    assert not output.exists()


def test_live_collection_persists_safe_transport_failure_diagnostics(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    attempts = 0
    synthetic_tour_key = "synthetic-tour-diagnostic-key"
    synthetic_odii_key = "synthetic-odii-diagnostic-key"
    real_kto_client = collect_preview_module.KorService2Client
    real_odii_client = collect_preview_module.OdiiClient

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal attempts
        attempts += 1
        raise httpx.ConnectError(
            "sensitive transport detail must never be persisted",
            request=request,
        )

    http_client = httpx.Client(transport=httpx.MockTransport(handler))
    monkeypatch.setattr(
        collect_preview_module,
        "KorService2Client",
        lambda *, service_key, policy: real_kto_client(
            service_key=service_key,
            http_client=http_client,
            policy=policy,
        ),
    )
    monkeypatch.setattr(
        collect_preview_module,
        "OdiiClient",
        lambda *, service_key, policy: real_odii_client(
            service_key=service_key,
            http_client=http_client,
            policy=policy,
        ),
    )
    monkeypatch.setattr(
        collect_preview_module,
        "_load_live_credentials",
        lambda: (synthetic_tour_key, synthetic_odii_key),
    )
    monkeypatch.delenv("CI", raising=False)
    monkeypatch.delenv("ITDA_NO_NETWORK", raising=False)
    output = tmp_path / "review"
    diagnostics = tmp_path / "diagnostics"

    try:
        exit_code = collect_preview_main(
            [
                "--live",
                "--output",
                str(output),
                "--diagnostics-dir",
                str(diagnostics),
            ]
        )
    finally:
        http_client.close()

    assert exit_code == CHECK_MALFORMED
    assert attempts == 3
    assert not output.exists()
    logs = list(diagnostics.glob("provider-collection-*.jsonl"))
    assert len(logs) == 1
    events = [json.loads(line) for line in logs[0].read_text(encoding="utf-8").splitlines()]
    attempt_events = [event for event in events if event["event"] == "request_attempt"]
    assert [event["attempt"] for event in attempt_events] == [1, 2, 3]
    assert len({event["attempt_id"] for event in attempt_events}) == 3
    assert all(
        event["schema_version"] == "provider-collection-diagnostic-v1"
        and event["candidate_place_id"] == "preview:1"
        and event["candidate_name"] == "불국사"
        and event["provider"] == "TOUR_API"
        and event["operation"] == "searchKeyword2"
        and event["max_attempts"] == 3
        and event["timeout_seconds"] == 5.0
        and event["outcome"] == "transport_error"
        and event["category"] == "network"
        and event["exception_class"] == "ConnectError"
        and event["retryable"] is True
        and "http_status" not in event
        for event in attempt_events
    )
    assert [event["terminal_failure"] for event in attempt_events] == [
        False,
        False,
        True,
    ]
    terminal = events[-1]
    assert terminal["event"] == "terminal_failure"
    assert terminal["completed_operation_count"] == 0
    assert terminal["completed_operations"] == []
    serialized = logs[0].read_text(encoding="utf-8")
    assert synthetic_tour_key not in serialized
    assert synthetic_odii_key not in serialized
    assert "sensitive transport detail" not in serialized
    stderr = capsys.readouterr().err
    assert logs[0].name in stderr
    assert str(diagnostics) not in stderr
    assert str(tmp_path) not in stderr
    assert synthetic_tour_key not in stderr
    assert synthetic_odii_key not in stderr
    assert "sensitive transport detail" not in stderr


def test_live_collection_discovers_then_resolves_each_candidate(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls = _install_live_clients(monkeypatch)
    monkeypatch.setattr(collect_preview_module, "_repository_root", lambda: tmp_path)
    output = tmp_path / "live-review"

    assert collect_preview_main(["--live", "--output", str(output)]) == CHECK_RESOLVED
    assert check_candidate_review(output / "candidate-review.json").exit_code == CHECK_RESOLVED
    assert check_review_manifest(output / "review-manifest.json").exit_code == CHECK_RESOLVED
    assert {path.name for path in output.iterdir()} == {
        "raw-provider-bundle.redacted.json",
        "candidate-review.json",
        "candidate-review.md",
        "review-manifest.json",
    }
    assert len(calls) == 30
    diagnostics = tmp_path / ".diagnostics" / "provider-collection"
    logs = list(diagnostics.glob("provider-collection-*.jsonl"))
    assert len(logs) == 1
    diagnostic_events = [
        json.loads(line) for line in logs[0].read_text(encoding="utf-8").splitlines()
    ]
    assert diagnostic_events[-1]["event"] == "run_completed"
    assert diagnostic_events[-1]["completed_operation_count"] == 30
    markdown = (output / "candidate-review.md").read_text(encoding="utf-8")
    assert "| Odii tid/tlid | Odii story ID |" in markdown
    assert "Canonical Odii theme pair (tid/tlid)" not in markdown
    assert "multiple subordinate story rows" not in markdown
    for offset, name in enumerate(LOCKED_PREVIEW_CANDIDATES):
        candidate_calls = calls[offset * 5 : offset * 5 + 5]
        assert [(provider, operation) for provider, operation, _ in candidate_calls] == [
            ("TOUR_API", "searchKeyword2"),
            ("ODII", "themeSearchList"),
            ("TOUR_API", "detailCommon2"),
            ("TOUR_API", "detailImage2"),
            ("ODII", "storyBasedList"),
        ]
        assert candidate_calls[0][2]["keyword"] == name
        assert candidate_calls[1][2]["keyword"] == name
        assert candidate_calls[2][2]["contentId"] == f"tour-discovered-{offset}"
        assert candidate_calls[3][2]["contentId"] == f"tour-discovered-{offset}"
        assert candidate_calls[4][2] == {
            "tid": f"theme-discovered-{offset}",
            "tlid": f"location-discovered-{offset}",
        }


def test_live_collection_never_records_success_before_artifact_publication(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _install_live_clients(monkeypatch)
    output = tmp_path / "live-review"
    diagnostics = tmp_path / "diagnostics"
    real_write_regular_file_at = collect_preview_module._write_regular_file_at
    injected_failure = False

    def fail_candidate_review_write(
        directory_descriptor: int,
        name: str,
        payload: bytes,
    ) -> None:
        nonlocal injected_failure
        if name == "candidate-review.json" and not injected_failure:
            injected_failure = True
            raise OSError("private artifact filesystem detail")
        real_write_regular_file_at(directory_descriptor, name, payload)

    monkeypatch.setattr(
        collect_preview_module,
        "_write_regular_file_at",
        fail_candidate_review_write,
    )

    args = [
        "--live",
        "--output",
        str(output),
        "--diagnostics-dir",
        str(diagnostics),
    ]
    assert collect_preview_main(args) == CHECK_MALFORMED
    assert not output.exists()
    assert not list(tmp_path.glob(".live-review-*"))
    logs = list(diagnostics.glob("provider-collection-*.jsonl"))
    assert len(logs) == 1
    events = [json.loads(line) for line in logs[0].read_text(encoding="utf-8").splitlines()]
    assert "run_completed" not in {event["event"] for event in events}
    assert events[-1]["event"] == "terminal_failure"
    assert events[-1]["category"] == "filesystem"

    assert collect_preview_main(args) == CHECK_RESOLVED
    assert {path.name for path in output.iterdir()} == {
        "raw-provider-bundle.redacted.json",
        "candidate-review.json",
        "candidate-review.md",
        "review-manifest.json",
    }
    assert check_candidate_review(output / "candidate-review.json").exit_code == CHECK_RESOLVED
    assert check_review_manifest(output / "review-manifest.json").exit_code == CHECK_RESOLVED
    assert not list(tmp_path.glob(".live-review-*"))


def test_live_collection_keeps_committed_result_when_success_diagnostic_fails(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _install_live_clients(monkeypatch)
    output = tmp_path / "live-review"
    diagnostics = tmp_path / "diagnostics"
    terminal_success_attempted = False

    def fail_terminal_success(diagnostic: object) -> None:
        nonlocal terminal_success_attempted
        terminal_success_attempted = True
        raise ProviderDiagnosticsError

    monkeypatch.setattr(
        collect_preview_module.ProviderDiagnostics,
        "terminal_success",
        fail_terminal_success,
    )

    assert (
        collect_preview_main(
            [
                "--live",
                "--output",
                str(output),
                "--diagnostics-dir",
                str(diagnostics),
            ]
        )
        == CHECK_RESOLVED
    )
    assert terminal_success_attempted
    assert check_review_manifest(output / "review-manifest.json").exit_code == CHECK_RESOLVED
    assert {path.name for path in output.iterdir()} == {
        "raw-provider-bundle.redacted.json",
        "candidate-review.json",
        "candidate-review.md",
        "review-manifest.json",
    }


def test_live_collection_preserves_publication_on_parent_fsync_failure(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _install_live_clients(monkeypatch)
    output = tmp_path / "live-review"
    diagnostics = tmp_path / "diagnostics"
    real_fsync = collect_preview_module.os.fsync
    parent_identity = (output.parent.stat().st_dev, output.parent.stat().st_ino)
    failed = False

    def fail_first_post_rename_parent_fsync(descriptor: int) -> None:
        nonlocal failed
        metadata = collect_preview_module.os.fstat(descriptor)
        if (
            not failed
            and os.path.lexists(output)
            and (metadata.st_dev, metadata.st_ino) == parent_identity
        ):
            failed = True
            raise OSError("injected post-rename parent fsync failure")
        real_fsync(descriptor)

    monkeypatch.setattr(
        collect_preview_module.os,
        "fsync",
        fail_first_post_rename_parent_fsync,
    )
    args = [
        "--live",
        "--output",
        str(output),
        "--diagnostics-dir",
        str(diagnostics),
    ]

    assert collect_preview_main(args) == CHECK_MALFORMED
    assert failed
    assert output.is_dir() and not output.is_symlink()
    assert check_review_manifest(output / "review-manifest.json").exit_code == CHECK_RESOLVED
    assert not list(tmp_path.glob(".live-review-*"))

    assert collect_preview_main(args) == CHECK_MALFORMED
    assert check_review_manifest(output / "review-manifest.json").exit_code == CHECK_RESOLVED


def test_live_collection_uncertain_publication_preserves_racing_staging_name(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _install_live_clients(monkeypatch)
    output = tmp_path / "live-review"
    diagnostics = tmp_path / "diagnostics"
    real_rename = collect_preview_module._atomic_rename_directory_noreplace_at
    real_fsync = collect_preview_module.os.fsync
    staging_name: str | None = None

    def observed_rename(parent_descriptor: int, source_name: str, destination_name: str) -> None:
        nonlocal staging_name
        real_rename(parent_descriptor, source_name, destination_name)
        staging_name = source_name

    def occupy_staging_before_failure(descriptor: int) -> None:
        if staging_name is not None and output.exists():
            racing_staging = tmp_path / staging_name
            racing_staging.mkdir()
            (racing_staging / "winner.txt").write_text("preserve me", encoding="utf-8")
            raise OSError("injected parent fsync failure")
        real_fsync(descriptor)

    monkeypatch.setattr(
        collect_preview_module,
        "_atomic_rename_directory_noreplace_at",
        observed_rename,
    )
    monkeypatch.setattr(collect_preview_module.os, "fsync", occupy_staging_before_failure)

    assert (
        collect_preview_main(
            [
                "--live",
                "--output",
                str(output),
                "--diagnostics-dir",
                str(diagnostics),
            ]
        )
        == CHECK_MALFORMED
    )
    assert staging_name is not None
    assert (tmp_path / staging_name / "winner.txt").read_text(encoding="utf-8") == "preserve me"
    assert check_review_manifest(output / "review-manifest.json").exit_code == CHECK_RESOLVED


def test_live_collection_rejects_pre_rename_staging_replacement(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _install_live_clients(monkeypatch)
    output = tmp_path / "live-review"
    diagnostics = tmp_path / "diagnostics"
    displaced = tmp_path / "validated-live-review"
    real_rename = collect_preview_module._atomic_rename_directory_noreplace_at

    def replace_staging_before_rename(
        parent_descriptor: int,
        source_name: str,
        destination_name: str,
    ) -> None:
        os.rename(
            source_name,
            displaced.name,
            src_dir_fd=parent_descriptor,
            dst_dir_fd=parent_descriptor,
        )
        os.mkdir(source_name, dir_fd=parent_descriptor)
        winner_descriptor = os.open(
            f"{source_name}/winner.txt",
            os.O_WRONLY | os.O_CREAT | os.O_EXCL,
            0o600,
            dir_fd=parent_descriptor,
        )
        try:
            os.write(winner_descriptor, b"unvalidated replacement")
        finally:
            os.close(winner_descriptor)
        real_rename(parent_descriptor, source_name, destination_name)

    monkeypatch.setattr(
        collect_preview_module,
        "_atomic_rename_directory_noreplace_at",
        replace_staging_before_rename,
    )

    assert (
        collect_preview_main(
            [
                "--live",
                "--output",
                str(output),
                "--diagnostics-dir",
                str(diagnostics),
            ]
        )
        == CHECK_MALFORMED
    )
    assert (output / "winner.txt").read_text(encoding="utf-8") == "unvalidated replacement"
    assert check_review_manifest(displaced / "review-manifest.json").exit_code == CHECK_RESOLVED


def test_review_staging_cleanup_preserves_primary_failure_and_attempts_all_teardown(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    payloads = {
        "raw-provider-bundle.redacted.json": b"first",
        "candidate-review.json": b"second",
        "candidate-review.md": b"third",
        "review-manifest.json": b"fourth",
    }
    parent_descriptor = os.open(tmp_path, os.O_RDONLY | os.O_DIRECTORY)
    real_write = collect_preview_module._write_regular_file_at
    real_unlink = collect_preview_module.os.unlink
    real_close = collect_preview_module.os.close
    real_rmdir = collect_preview_module.os.rmdir
    staging_descriptor: int | None = None
    write_count = 0
    unlink_attempts: list[str] = []
    staging_close_attempted = False
    rmdir_attempted = False

    def fail_second_write(descriptor: int, name: str, payload: bytes) -> None:
        nonlocal staging_descriptor, write_count
        staging_descriptor = descriptor
        write_count += 1
        if write_count == 2:
            raise collect_preview_module.CollectionError("primary staged write failure")
        real_write(descriptor, name, payload)

    def fail_first_unlink(
        name: str,
        *,
        dir_fd: int | None = None,
    ) -> None:
        unlink_attempts.append(name)
        if len(unlink_attempts) == 1:
            raise PermissionError("injected cleanup refusal")
        real_unlink(name, dir_fd=dir_fd)

    def observed_close(descriptor: int) -> None:
        nonlocal staging_close_attempted
        if descriptor == staging_descriptor:
            staging_close_attempted = True
        real_close(descriptor)

    def observed_rmdir(
        name: str,
        *,
        dir_fd: int | None = None,
    ) -> None:
        nonlocal rmdir_attempted
        rmdir_attempted = True
        real_rmdir(name, dir_fd=dir_fd)

    monkeypatch.setattr(collect_preview_module, "_write_regular_file_at", fail_second_write)
    monkeypatch.setattr(collect_preview_module.os, "unlink", fail_first_unlink)
    monkeypatch.setattr(collect_preview_module.os, "close", observed_close)
    monkeypatch.setattr(collect_preview_module.os, "rmdir", observed_rmdir)
    try:
        with pytest.raises(
            collect_preview_module.CollectionError,
            match="primary staged write failure",
        ):
            collect_preview_module._publish_review_artifacts(
                tmp_path / "output",
                output_parent_descriptor=parent_descriptor,
                payloads=payloads,
                expected_exit_code=CHECK_RESOLVED,
                staging_prefix=".cleanup-test-",
            )
    finally:
        real_close(parent_descriptor)

    assert unlink_attempts == list(payloads)
    assert staging_close_attempted
    assert rmdir_attempted


def test_live_collection_opens_output_parent_before_diagnostics(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    diagnostics_created = False

    def unexpected_diagnostics_create(path: Path) -> object:
        nonlocal diagnostics_created
        diagnostics_created = True
        raise AssertionError(f"diagnostics must not open before output parent: {path}")

    def fail_output_parent_open(path: Path) -> int:
        raise OSError(f"injected unsafe output parent: {path}")

    monkeypatch.setattr(
        collect_preview_module,
        "require_live_collection_allowed",
        lambda *, explicit_opt_in: None,
    )
    monkeypatch.setattr(
        collect_preview_module.ProviderDiagnostics,
        "create",
        unexpected_diagnostics_create,
    )
    monkeypatch.setattr(
        collect_preview_module,
        "_open_directory_fd_nofollow",
        fail_output_parent_open,
    )

    with pytest.raises(OSError, match="injected unsafe output parent"):
        collect_preview_module._collect_live(
            tmp_path / "output" / "review",
            selections=None,
            diagnostics_dir=tmp_path / "diagnostics",
            policy=RequestPolicy(),
        )
    assert not diagnostics_created


def test_collection_teardown_closes_parent_when_reporting_and_diagnostics_close_fail(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    parent_descriptor = os.open(
        tmp_path,
        os.O_RDONLY | getattr(os, "O_DIRECTORY", 0),
    )
    diagnostics_close_attempted = False
    parent_close_attempted = False
    real_close = os.close

    class BrokenDiagnostics:
        file_name = "provider-collection-safe.jsonl"

        def close(self) -> None:
            nonlocal diagnostics_close_attempted
            diagnostics_close_attempted = True
            raise OSError("injected diagnostics close failure")

    def fail_print(*args: object, **kwargs: object) -> None:
        raise OSError("injected diagnostics report failure")

    def close_parent_then_fail(descriptor: int) -> None:
        nonlocal parent_close_attempted
        if descriptor == parent_descriptor:
            parent_close_attempted = True
            real_close(descriptor)
            raise OSError("injected parent close failure")
        real_close(descriptor)

    monkeypatch.setattr("builtins.print", fail_print)
    monkeypatch.setattr(collect_preview_module.os, "close", close_parent_then_fail)

    collect_preview_module._teardown_collection(
        BrokenDiagnostics(),
        output_parent_descriptor=parent_descriptor,
    )

    assert diagnostics_close_attempted
    assert parent_close_attempted
    with pytest.raises(OSError):
        os.fstat(parent_descriptor)


@pytest.mark.parametrize(
    ("ignored_args", "expected_message"),
    [
        (("--output", "ignored-output"), "--output"),
        (
            (
                "--candidate-selection",
                "불국사",
                "126166",
                "2",
                "5",
                "불국사",
            ),
            "--candidate-selection",
        ),
    ],
)
def test_check_review_rejects_ignored_live_output_options(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    ignored_args: tuple[str, ...],
    expected_message: str,
) -> None:
    result = collect_preview_main(
        [
            "--check-review",
            str(tmp_path / "review-manifest.json"),
            *ignored_args,
        ]
    )

    assert result == CHECK_MALFORMED
    assert expected_message in capsys.readouterr().err


def test_live_collection_applies_exact_user_selected_ids_and_bounded_aliases(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls = _install_selected_live_clients(monkeypatch)
    output = tmp_path / "selected-live-review"

    assert (
        collect_preview_main(["--live", "--output", str(output), *_selected_live_args()])
        == CHECK_RESOLVED
    )
    checked = check_review_manifest(output / "review-manifest.json")
    assert checked.exit_code == CHECK_RESOLVED, checked.reason
    assert checked.review is not None
    assert len(calls) == 30
    for candidate, selection in zip(
        checked.review.candidates, SELECTED_LIVE_IDENTITIES, strict=True
    ):
        name, tour_id, tid, tlid, odii_keyword = selection
        assert candidate.name_ko == name
        assert candidate.evidence[0].source_id == tour_id
        assert candidate.evidence[1].source_id == f"{tid}/{tlid}"
        assert candidate.evidence[1].request_scope["tid"] == tid
        assert candidate.evidence[1].request_scope["tlid"] == tlid
        candidate_calls = calls[(int(candidate.place_id.split(":")[1]) - 1) * 5 :][:5]
        assert candidate_calls[1][2]["keyword"] == odii_keyword
    bundle_payload = json.loads(
        (output / "raw-provider-bundle.redacted.json").read_text(encoding="utf-8")
    )
    assert len(bundle_payload["rows"]) == 30
    markdown = (output / "candidate-review.md").read_text(encoding="utf-8")
    assert "| Odii request pair (tid/tlid) | Canonical Odii theme pair (tid/tlid) |" in markdown
    assert "Odii story ID" not in markdown
    assert "multiple subordinate story rows" in markdown
    assert "| 1 | 불국사 |" in markdown
    assert "| 2/5 | 2/5 |" in markdown


def test_synthetic_persisted_legacy_v7_markdown_remains_byte_stable_and_unresolved(
    tmp_path: Path,
) -> None:
    review_path, bundle_path, _ = _write_review(
        tmp_path,
        all_unresolved=True,
        bundle_name="raw-provider-bundle.redacted.json",
    )
    review = CandidateReview.model_validate_json(review_path.read_bytes())
    bundle = RawProviderBundle.model_validate_json(bundle_path.read_bytes())
    legacy_markdown = render_candidate_review_markdown(review, bundle)
    assert (
        _sha(legacy_markdown) == "7bc81ab8b986a07e22c14eff02d0ce1b4f7c2b98a297e6772b5ffb62888804d9"
    )
    (tmp_path / "candidate-review.md").write_bytes(legacy_markdown)
    manifest_path = tmp_path / "review-manifest.json"
    manifest_path.write_bytes(build_review_manifest(tmp_path))

    checked = check_review_manifest(manifest_path)

    assert checked.exit_code == CHECK_UNRESOLVED, checked.reason
    assert render_candidate_review_markdown(review, bundle) == legacy_markdown


@pytest.mark.parametrize(
    "case",
    [
        "locked-count",
        "locked-order",
        "nonnumeric-tour-id",
        "duplicate-tour-id",
        "duplicate-odii-pair",
        "unapproved-alias",
    ],
)
def test_live_collection_rejects_invalid_selection_contract_before_network(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    case: str,
) -> None:
    calls = _install_selected_live_clients(monkeypatch)
    args = _selected_live_args()
    if case == "locked-count":
        del args[:6]
    elif case == "locked-order":
        args[:12] = [*args[6:12], *args[:6]]
    elif case == "nonnumeric-tour-id":
        args[2] = "not-an-id"
    elif case == "duplicate-tour-id":
        args[8] = args[2]
    elif case == "duplicate-odii-pair":
        args[9:11] = args[3:5]
    else:
        assert case == "unapproved-alias"
        args[args.index("대릉원")] = "천마총"
    output = tmp_path / "invalid-selected-live-review"

    assert collect_preview_main(["--live", "--output", str(output), *args]) == CHECK_MALFORMED
    assert calls == []
    assert not output.exists()


@pytest.mark.parametrize("case", ["incomplete-selection", "extra-token"])
def test_live_collection_normalizes_malformed_argparse_syntax_to_exit_one(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    case: str,
) -> None:
    calls = _install_selected_live_clients(monkeypatch)
    args = _selected_live_args()
    if case == "incomplete-selection":
        args.pop()
    else:
        args.append("unexpected-extra-token")
    output = tmp_path / "malformed-cli-review"

    assert collect_preview_main(["--live", "--output", str(output), *args]) == CHECK_MALFORMED
    assert calls == []
    assert not output.exists()


def test_live_collection_help_preserves_success_exit(
    capsys: pytest.CaptureFixture[str],
) -> None:
    with pytest.raises(SystemExit) as exc_info:
        collect_preview_main(["--help"])

    assert exc_info.value.code == 0
    help_text = capsys.readouterr().out
    assert "--diagnostics-dir PATH" in help_text
    assert ".diagnostics/provider-collection" in help_text
    assert "private provider JSONL directory" in help_text
    assert "--request-timeout-seconds SECONDS" in help_text
    assert "maximum 300 seconds" in help_text


@pytest.mark.parametrize(
    "mismatch",
    [
        "wrong-tid",
        "wrong-tlid",
        "duplicate-selected-search-row",
        "coordinate-drift",
        "wrong-detail-id",
        "wrong-detail-coordinates",
        "mixed-pair-stories",
        "supplementary-only-stories",
    ],
)
def test_selected_live_collection_keeps_provider_identity_mismatches_unresolved(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    mismatch: str,
) -> None:
    calls = _install_selected_live_clients(monkeypatch, mismatch=mismatch)
    output = tmp_path / f"selected-{mismatch}"

    assert (
        collect_preview_main(["--live", "--output", str(output), *_selected_live_args()])
        == CHECK_UNRESOLVED
    )
    checked = check_review_manifest(output / "review-manifest.json")
    assert checked.exit_code == CHECK_UNRESOLVED, checked.reason
    assert checked.review is not None
    assert checked.review.candidates[0].resolution_status.value == "UNRESOLVED"
    assert len(calls) == 30
    bundle_payload = json.loads(
        (output / "raw-provider-bundle.redacted.json").read_text(encoding="utf-8")
    )
    assert len(bundle_payload["rows"]) == 30


@pytest.mark.parametrize(
    ("mismatch", "expected_exit"),
    [(None, CHECK_RESOLVED), ("absent", CHECK_UNRESOLVED)],
)
def test_live_collection_preserves_multiple_tourapi_rights_rows(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    mismatch: str | None,
    expected_exit: int,
) -> None:
    tour_rights = (
        {"cpyrhtDivCd": "Type1"},
        {"cpyrhtDivCd": "Type3"},
    )
    _install_live_clients(monkeypatch, mismatch=mismatch, tour_rights=tour_rights)
    output = tmp_path / "live-review"

    assert collect_preview_main(["--live", "--output", str(output)]) == expected_exit
    checked = check_candidate_review(output / "candidate-review.json")
    assert checked.exit_code == expected_exit, checked.reason
    assert checked.review is not None
    assert checked.review.candidates[0].evidence[0].upstream_rights == tour_rights
    assert check_review_manifest(output / "review-manifest.json").exit_code == expected_exit


@pytest.mark.parametrize(
    "mismatch",
    [
        "absent",
        "ambiguous",
        "duplicate",
        "wrong-title",
        "wrong-address",
        "wrong-coordinates",
        "wrong-id",
    ],
)
def test_live_collection_marks_non_unique_or_identity_mismatches_unresolved(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    mismatch: str,
) -> None:
    _install_live_clients(monkeypatch, mismatch=mismatch)
    output = tmp_path / "live-review"

    assert collect_preview_main(["--live", "--output", str(output)]) == CHECK_UNRESOLVED
    checked = check_candidate_review(output / "candidate-review.json")
    assert checked.exit_code == CHECK_UNRESOLVED
    assert checked.review is not None
    assert checked.review.candidates[0].resolution_status.value == "UNRESOLVED"


@pytest.mark.parametrize("case", ["five-candidates", "bundle-hash", "rights", "traversal"])
def test_check_review_returns_one_for_malformed_or_tampered_artifacts(
    tmp_path: Path,
    case: str,
) -> None:
    review, bundle, _ = _write_review(tmp_path)
    payload = json.loads(review.read_text())
    if case == "five-candidates":
        payload["candidates"].pop()
    elif case == "bundle-hash":
        bundle.write_bytes(b"tampered")
    elif case == "rights":
        payload["candidates"][0]["evidence"][0]["asset_usage_status"] = "ALLOWED_WITH_ATTRIBUTION"
    else:
        payload["bundle_path"] = "../provider-bundle.json"
    if case != "bundle-hash":
        review.write_text(json.dumps(payload, ensure_ascii=False), encoding="utf-8")

    result = check_candidate_review(review)

    assert result.exit_code == CHECK_MALFORMED == 1
    assert result.review is None
    assert collect_preview_main(["--check-review", str(review)]) == 1


def test_review_schema_rejects_duplicate_provider_and_wrong_candidate_order(
    tmp_path: Path,
) -> None:
    review, _, _ = _write_review(tmp_path)
    payload = json.loads(review.read_text())
    payload["candidates"][0]["evidence"][1]["provider"] = "TOUR_API"
    payload["candidates"][0], payload["candidates"][1] = (
        payload["candidates"][1],
        payload["candidates"][0],
    )
    review.write_text(json.dumps(payload, ensure_ascii=False), encoding="utf-8")

    assert check_candidate_review(review).exit_code == 1


def test_review_rejects_legacy_scalar_rights_projection(tmp_path: Path) -> None:
    review, _, _ = _write_review(tmp_path)
    payload = json.loads(review.read_text(encoding="utf-8"))
    evidence = payload["candidates"][0]["evidence"][0]
    evidence.pop("upstream_rights")
    evidence["upstream_rights_code"] = "Type3"
    review.write_bytes(
        (
            json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":")) + "\n"
        ).encode("utf-8")
    )

    result = check_candidate_review(review)

    assert result.exit_code == CHECK_MALFORMED
    assert "upstream_rights_code" in result.reason


@pytest.mark.parametrize(
    "mutation",
    [
        "empty",
        "extra",
        "missing",
        "provider",
        "endpoint",
        "scope",
        "source-id",
        "rights",
        "rights-extra",
        "bundle-schema",
        "invalid-base64",
        "raw-hash",
        "raw-body",
        "raw-json",
        "raw-schema",
        "raw-rights",
    ],
)
def test_review_requires_exact_strict_raw_bundle_binding(
    tmp_path: Path,
    mutation: str,
) -> None:
    review, bundle, _ = _write_review(tmp_path)
    review_payload = json.loads(review.read_text())
    bundle_payload = json.loads(bundle.read_text())
    rows = bundle_payload["rows"]
    if mutation == "empty":
        bundle_payload["rows"] = []
    elif mutation == "extra":
        rows.append(dict(rows[0]))
    elif mutation == "missing":
        rows.pop()
    elif mutation == "provider":
        rows[0]["provider"] = "ODII"
    elif mutation == "endpoint":
        rows[0]["endpoint"] = "KorService2/searchKeyword2"
    elif mutation == "scope":
        rows[0]["request_scope"] = {"candidate": "다른 장소"}
    elif mutation == "source-id":
        rows[0]["source_id"] = "wrong-source"
    elif mutation == "rights":
        rows[0]["rights"] = []
    elif mutation == "rights-extra":
        rows[0]["rights"].append({"cpyrhtDivCd": "Type1"})
    elif mutation == "bundle-schema":
        bundle_payload["schema_version"] = "provider-bundle-v2"
    elif mutation == "invalid-base64":
        rows[0]["raw_body_base64"] = "%%%"
    elif mutation == "raw-hash":
        rows[0]["raw_response_sha256"] = "0" * 64
    elif mutation == "raw-body":
        rows[0]["raw_body_base64"] = b64encode(b"tampered").decode()
    else:
        raw_body = {
            "raw-json": b"not-json",
            "raw-schema": b'"scalar"',
            "raw-rights": b'{"candidate":0,"provider":"TOUR_API"}',
        }[mutation]
        raw_hash = _sha(raw_body)
        rows[0]["raw_body_base64"] = b64encode(raw_body).decode()
        rows[0]["raw_response_sha256"] = raw_hash
        review_payload["candidates"][0]["evidence"][0]["raw_response_sha256"] = raw_hash
    bundle_bytes = (
        json.dumps(
            bundle_payload,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        )
        + "\n"
    ).encode()
    bundle.write_bytes(bundle_bytes)
    review_payload["redacted_bundle_sha256"] = _sha(bundle_bytes)
    review.write_text(
        json.dumps(review_payload, ensure_ascii=False, separators=(",", ":")),
        encoding="utf-8",
    )

    assert check_candidate_review(review).exit_code == CHECK_MALFORMED


@pytest.mark.parametrize("shape", ["deep", "wide"])
def test_check_review_returns_one_for_pathological_valid_provider_json(
    tmp_path: Path,
    shape: str,
) -> None:
    review, bundle, _ = _write_review(tmp_path)
    review_payload = json.loads(review.read_text(encoding="utf-8"))
    bundle_payload = json.loads(bundle.read_text(encoding="utf-8"))
    raw_body = _pathological_provider_json(shape)
    raw_hash = _sha(raw_body)

    row = bundle_payload["rows"][0]
    row["raw_body_base64"] = b64encode(raw_body).decode()
    row["raw_response_sha256"] = raw_hash
    row["rights"] = []
    evidence = review_payload["candidates"][0]["evidence"][0]
    evidence["raw_response_sha256"] = raw_hash
    evidence["upstream_rights"] = []

    bundle_bytes = (
        json.dumps(
            bundle_payload,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        )
        + "\n"
    ).encode()
    bundle.write_bytes(bundle_bytes)
    review_payload["redacted_bundle_sha256"] = _sha(bundle_bytes)
    review.write_bytes(
        (
            json.dumps(
                review_payload,
                ensure_ascii=False,
                sort_keys=True,
                separators=(",", ":"),
            )
            + "\n"
        ).encode()
    )

    checked = check_candidate_review(review)
    assert checked.exit_code == CHECK_MALFORMED
    assert collect_preview_main(["--check-review", str(review)]) == CHECK_MALFORMED


@pytest.mark.parametrize(
    ("size", "padding", "expected_exit"),
    [
        (PROVIDER_RAW_LIMIT - 1, 2, CHECK_RESOLVED),
        (PROVIDER_RAW_LIMIT, 1, CHECK_RESOLVED),
        (PROVIDER_RAW_LIMIT + 1, 0, CHECK_MALFORMED),
        (PROVIDER_RAW_LIMIT + 2, 2, CHECK_MALFORMED),
    ],
)
def test_review_raw_byte_and_canonical_base64_boundaries(
    tmp_path: Path,
    size: int,
    padding: int,
    expected_exit: int,
) -> None:
    review, bundle, _ = _write_review(tmp_path)
    raw_body = _provider_json_body_of_size(size)
    encoded = b64encode(raw_body).decode("ascii")
    assert len(encoded) == 4 * ((size + 2) // 3)
    assert len(encoded) - len(encoded.rstrip("=")) == padding
    if size <= PROVIDER_RAW_LIMIT + 1:
        assert len(encoded) == PROVIDER_BASE64_LIMIT
    else:
        assert len(encoded) == PROVIDER_BASE64_LIMIT + 4
    _replace_first_review_raw_body(review, bundle, raw_body)

    checked = check_candidate_review(review)
    assert checked.exit_code == expected_exit


def test_review_rejects_overlong_base64_before_decode(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    candidate = _candidate(0)
    row = _bundle_rows([candidate])[0]
    row["raw_body_base64"] = "A" * (PROVIDER_BASE64_LIMIT + 4)
    decode_called = False

    def unexpected_decode(*args: object, **kwargs: object) -> bytes:
        nonlocal decode_called
        decode_called = True
        raise AssertionError("overlong base64 must be rejected before decode")

    monkeypatch.setattr(candidate_review_module, "b64decode", unexpected_decode)
    with pytest.raises(ValidationError):
        RawProviderBundleRow.model_validate(row)
    assert decode_called is False


def test_review_rejects_noncanonical_base64_pad_bits() -> None:
    raw_body = b"{}"
    noncanonical = "e31="
    assert candidate_review_module.b64decode(noncanonical, validate=True) == raw_body
    assert b64encode(raw_body).decode("ascii") == "e30="
    candidate = _candidate(0)
    row = _bundle_rows([candidate])[0]
    row["raw_body_base64"] = noncanonical
    row["raw_response_sha256"] = _sha(raw_body)
    row["rights"] = []

    with pytest.raises(ValidationError, match="canonical standard base64"):
        RawProviderBundleRow.model_validate(row)
