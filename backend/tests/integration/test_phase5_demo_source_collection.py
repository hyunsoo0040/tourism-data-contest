from __future__ import annotations

from pathlib import Path

import httpx
import pytest

from itda.cli.collect_phase5_demo_sources import (
    AuthorizedDevRow,
    Phase5DemoSourceCollectionError,
    _authority_payload,
    collect_authorized_dev_sources,
    verify_source_collection,
)
from itda.collectors.base import RequestPolicy
from itda.collectors.diagnostics import ProviderDiagnostics
from itda.collectors.kto import KorService2Client
from itda.domain.canonical import canonical_json_bytes

KEY = "fixture-tourapi-key-never-persist"


def _rows() -> tuple[AuthorizedDevRow, ...]:
    return tuple(
        AuthorizedDevRow(
            place_id=f"place:{index:064x}",
            name_ko=f"검증장소{index:02d}",
            content_id=str(100_000 + index),
            canonical_row_sha256=f"{index % 10}" * 64,
            dataset_grant_sha256="a" * 64,
            dataset_grant_leaf_sha256="b" * 64,
            dataset_grant_page_sha256="c" * 64,
            dataset_grant_response_sha256="d" * 64,
        )
        for index in range(1, 25)
    )


def _response(request: httpx.Request, *, overview: bool = True) -> httpx.Response:
    content_id = request.url.params["contentId"]
    item = {
        "contentid": content_id,
        "modifiedtime": "20260810000000",
    }
    if overview:
        item["overview"] = f"{content_id}의 실제 TourAPI 설명 본문"
    body = canonical_json_bytes(
        {
            "response": {
                "header": {"resultCode": "0000", "resultMsg": "OK"},
                "body": {"items": {"item": [item]}, "totalCount": 1},
            }
        }
    )
    return httpx.Response(
        200,
        content=body,
        headers={"content-type": "application/json"},
        request=request,
    )


def _write_authority(
    root: Path,
    *,
    bundles: tuple[object, ...],
    members: tuple[dict[str, object], ...],
    diagnostics_file: str,
) -> None:
    root.mkdir(parents=True, mode=0o700, exist_ok=True)
    authority = _authority_payload(
        bundles,  # type: ignore[arg-type]
        members,
        collection_run_id="run-test",
        diagnostics_file=diagnostics_file,
    )
    for name, value in (
        (
            "source-bundles.json",
            [bundle.model_dump(mode="json") for bundle in bundles],  # type: ignore[attr-defined]
        ),
        ("source-authority-members.json", list(members)),
        ("source-authority.json", authority),
    ):
        path = root / name
        path.write_bytes(canonical_json_bytes(value))
        path.chmod(0o600)


def test_exact_dev24_collection_preserves_raw_provenance_and_builds_authority(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # This test injects MockTransport; clearing the process guard cannot open a socket.
    monkeypatch.delenv("CI", raising=False)
    monkeypatch.delenv("ITDA_NO_NETWORK", raising=False)
    rows = _rows()
    requested: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        requested.append(request)
        return _response(request)

    published = tmp_path / "published"
    run_root = published / "source-collection" / "run-test"
    diagnostics = ProviderDiagnostics.create(run_root / "diagnostics")
    diagnostics.bind_credentials(KEY)
    try:
        with httpx.Client(transport=httpx.MockTransport(handler)) as http_client:
            client = KorService2Client(
                service_key=KEY,
                http_client=http_client,
                policy=RequestPolicy(timeout_seconds=300, max_attempts=3),
            )
            bundles, members = collect_authorized_dev_sources(
                rows=rows,
                client=client,
                run_root=run_root,
                diagnostics=diagnostics,
            )
    finally:
        diagnostics.close()

    _write_authority(
        published,
        bundles=bundles,
        members=members,
        diagnostics_file=diagnostics.file_name,
    )
    verified = verify_source_collection(published, expected_rows=rows)

    assert len(verified) == 24
    assert tuple(bundle.place_id for bundle in verified) == tuple(row.place_id for row in rows)
    assert all(len(bundle.sources) == 1 for bundle in verified)
    assert all(bundle.sources[0].source_kind == "TOUR_API_DESCRIPTION" for bundle in verified)
    assert len(requested) == 24
    assert all(request.url.path.endswith("/KorService2/detailCommon2") for request in requested)
    assert all(request.url.params["numOfRows"] == "1" for request in requested)
    assert all(request.url.params["pageNo"] == "1" for request in requested)
    durable = b"".join(path.read_bytes() for path in tmp_path.rglob("*") if path.is_file())
    assert KEY.encode() not in durable


def test_missing_overview_fails_closed_before_source_publication(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # This test injects MockTransport; clearing the process guard cannot open a socket.
    monkeypatch.delenv("CI", raising=False)
    monkeypatch.delenv("ITDA_NO_NETWORK", raising=False)
    rows = _rows()

    def handler(request: httpx.Request) -> httpx.Response:
        return _response(request, overview=False)

    run_root = tmp_path / "run"
    diagnostics = ProviderDiagnostics.create(run_root / "diagnostics")
    diagnostics.bind_credentials(KEY)
    try:
        with httpx.Client(transport=httpx.MockTransport(handler)) as http_client:
            client = KorService2Client(service_key=KEY, http_client=http_client)
            with pytest.raises(Phase5DemoSourceCollectionError, match="OVERVIEW_MISSING"):
                collect_authorized_dev_sources(
                    rows=rows,
                    client=client,
                    run_root=run_root,
                    diagnostics=diagnostics,
                )
    finally:
        diagnostics.close()
    assert not (tmp_path / "source-bundles.json").exists()
