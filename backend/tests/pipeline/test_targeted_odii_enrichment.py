from __future__ import annotations

import hashlib
import json
import os
from base64 import b64encode
from datetime import UTC, datetime
from pathlib import Path

import httpx
import pytest

import itda.cli.collect_preview as collect_preview_module
from itda.cli.collect_preview import CHECK_MALFORMED, CHECK_UNRESOLVED
from itda.cli.collect_preview import main as collect_preview_main
from itda.collectors.base import CollectedResponse, CollectionError, RequestPolicy
from itda.collectors.diagnostics import ProviderDiagnosticsError
from itda.contracts.candidate_review import (
    BLOCKED_RIGHTS_STATUS,
    LOCKED_PREVIEW_CANDIDATES,
    CandidateReview,
    RawProviderBundle,
    build_review_manifest,
    check_review_manifest,
    render_candidate_review_markdown,
)

_APPROVED = {
    "preview:1": ("126166", "2/5"),
    "preview:2": ("126216", "2983/4639"),
    "preview:3": ("126207", "2967/4623"),
    "preview:4": ("128526", "2961/4617"),
    "preview:5": ("1492402", "2960/4616"),
    "preview:6": ("2658227", "1312/2357"),
}
_SYNTHETIC_ODII_KEY = "synthetic-targeted-odii-key"


def _canonical(payload: object) -> bytes:
    return (
        json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":")) + "\n"
    ).encode()


def _sha(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def _provider_row(
    *,
    place_id: str,
    provider: str,
    endpoint: str,
    source_id: str | None,
    scope: dict[str, str],
    payload: object,
) -> dict[str, object]:
    raw = _canonical(payload)
    return {
        "candidate_place_id": place_id,
        "provider": provider,
        "endpoint": endpoint,
        "request_scope": scope,
        "source_id": source_id,
        "retrieved_at": "2026-07-23T09:00:00Z",
        "http_status": 200,
        "raw_response_sha256": _sha(raw),
        "raw_body_base64": b64encode(raw).decode(),
        "modifiedtime": None,
        "rights": [],
        "asset_usage_status": BLOCKED_RIGHTS_STATUS,
    }


def _write_source(
    root: Path,
    *,
    first_place_id: str = "preview:1",
    first_tour_id: str = "126166",
    first_tour_endpoint: str = "KorService2/searchKeyword2",
) -> Path:
    root.mkdir()
    rows: list[dict[str, object]] = []
    candidates: list[dict[str, object]] = []
    for index, name in enumerate(LOCKED_PREVIEW_CANDIDATES, start=1):
        if first_place_id == "swap":
            place_id = (
                "preview:2" if index == 1 else "preview:1" if index == 2 else f"preview:{index}"
            )
        else:
            place_id = first_place_id if index == 1 else f"preview:{index}"
        tour_id, odii_pair = _APPROVED.get(place_id, ("1492402", "2960/4616"))
        if index == 1:
            tour_id = first_tour_id
        tid, tlid = odii_pair.split("/")
        longitude = 129.2 + index / 1000
        latitude = 35.8 + index / 1000
        responses = (
            (
                "TOUR_API",
                first_tour_endpoint if index == 1 else "KorService2/searchKeyword2",
                None,
                {"keyword": name},
                {
                    "item": [
                        {
                            "contentid": tour_id,
                            "title": name,
                            "addr1": "경상북도 경주시",
                            "mapx": longitude,
                            "mapy": latitude,
                        }
                    ]
                },
            ),
            (
                "ODII",
                "Odii/themeSearchList",
                None,
                {"keyword": "대릉원" if place_id == "preview:5" else name},
                {
                    "item": [
                        {
                            "tid": tid,
                            "tlid": tlid,
                            "title": name,
                            "mapx": longitude,
                            "mapy": latitude,
                        }
                    ]
                },
            ),
        )
        response_rows = [
            _provider_row(
                place_id=place_id,
                provider=provider,
                endpoint=endpoint,
                source_id=source_id,
                scope=scope,
                payload=payload,
            )
            for provider, endpoint, source_id, scope, payload in responses
        ]
        rows.extend(response_rows)
        candidates.append(
            {
                "place_id": place_id,
                "name_ko": name,
                "address_ko": f"경상북도 경주시 검토로 {index}",
                "longitude": longitude,
                "latitude": latitude,
                "split": "PREVIEW",
                "assessment_status": "NOT_SCORED",
                "resolution_status": "UNRESOLVED",
                "evidence": [
                    {
                        "provider": "TOUR_API",
                        "source_id": None,
                        "endpoint": response_rows[0]["endpoint"],
                        "request_scope": response_rows[0]["request_scope"],
                        "retrieved_at": response_rows[0]["retrieved_at"],
                        "http_status": 200,
                        "raw_response_sha256": response_rows[0]["raw_response_sha256"],
                        "modifiedtime": None,
                        "upstream_rights": [],
                        "asset_usage_status": BLOCKED_RIGHTS_STATUS,
                        "unresolved_reason": "awaiting reviewed identity",
                    },
                    {
                        "provider": "ODII",
                        "source_id": None,
                        "endpoint": response_rows[1]["endpoint"],
                        "request_scope": response_rows[1]["request_scope"],
                        "retrieved_at": response_rows[1]["retrieved_at"],
                        "http_status": 200,
                        "raw_response_sha256": response_rows[1]["raw_response_sha256"],
                        "modifiedtime": None,
                        "upstream_rights": [],
                        "asset_usage_status": BLOCKED_RIGHTS_STATUS,
                        "unresolved_reason": "awaiting reviewed identity",
                    },
                ],
            }
        )
    bundle_bytes = _canonical(
        {"schema_version": "provider-bundle-v1", "redacted": True, "rows": rows}
    )
    (root / "raw-provider-bundle.redacted.json").write_bytes(bundle_bytes)
    review = CandidateReview.model_validate(
        {
            "schema_version": "candidate-review-v1",
            "artifact_status": "REVIEW_ONLY",
            "bundle_path": "raw-provider-bundle.redacted.json",
            "redacted_bundle_sha256": _sha(bundle_bytes),
            "candidates": candidates,
        }
    )
    (root / "candidate-review.json").write_bytes(_canonical(review.model_dump(mode="json")))
    bundle = RawProviderBundle.model_validate_json(bundle_bytes)
    (root / "candidate-review.md").write_bytes(render_candidate_review_markdown(review, bundle))
    manifest = root / "review-manifest.json"
    manifest.write_bytes(build_review_manifest(root))
    assert check_review_manifest(manifest).exit_code == CHECK_UNRESOLVED
    return manifest


def _collected(operation: str, payload: object, scope: dict[str, str]) -> CollectedResponse:
    raw = _canonical(payload)
    return CollectedResponse(
        provider="ODII",
        endpoint=f"Odii/{operation}",
        request_scope=scope,
        retrieved_at=datetime(2026, 7, 23, 10, 0, tzinfo=UTC),
        http_status=200,
        raw_response_sha256=_sha(raw),
        raw_body_base64=b64encode(raw).decode(),
        modifiedtime=None,
        rights=(),
        payload=payload,
    )


def _target_args(source: Path, output: Path, diagnostics: Path) -> list[str]:
    return [
        "--targeted-odii-review-enrichment",
        str(source),
        "--output",
        str(output),
        "--candidate-id",
        "preview:5",
        "--provider",
        "ODII",
        "--keyword",
        "대릉원",
        "--request-timeout-seconds",
        "300",
        "--diagnostics-dir",
        str(diagnostics),
    ]


def _pin_source(
    monkeypatch: pytest.MonkeyPatch,
    source: Path,
) -> None:
    monkeypatch.setattr(
        collect_preview_module,
        "_TARGETED_SOURCE_MANIFEST_SHA256",
        _sha(source.read_bytes()),
        raising=False,
    )


@pytest.mark.parametrize("fail_terminal_success", [False, True])
def test_targeted_odii_enrichment_publishes_new_unresolved_exact_four(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    fail_terminal_success: bool,
) -> None:
    source = _write_source(tmp_path / "source")
    _pin_source(monkeypatch, source)
    source_snapshot = {
        path.name: path.read_bytes() for path in source.parent.iterdir() if path.is_file()
    }
    calls: list[tuple[str, dict[str, object]]] = []
    policies: list[RequestPolicy] = []
    tour_constructions = 0

    class FakeOdii:
        def __init__(self, *, service_key: str, policy: RequestPolicy) -> None:
            assert service_key == _SYNTHETIC_ODII_KEY
            policies.append(policy)

        def __enter__(self) -> FakeOdii:
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
            calls.append((operation, dict(params)))
            if operation == "themeSearchList":
                return _collected(
                    operation,
                    {
                        "item": [
                            {"tid": "900", "tlid": "901", "title": "경주 대릉원"},
                            {"tid": "902", "tlid": "903", "title": "대릉원 일원"},
                        ]
                    },
                    {"keyword": "대릉원"},
                )
            assert operation == "storyBasedList"
            return _collected(
                operation,
                {"item": [{"tid": "900", "tlid": "901", "title": "경주 대릉원"}]},
                {"tid": "900", "tlid": "901"},
            )

    def refuse_tour(*args: object, **kwargs: object) -> object:
        nonlocal tour_constructions
        tour_constructions += 1
        raise AssertionError("TourAPI must not be constructed")

    monkeypatch.setattr(collect_preview_module, "KorService2Client", refuse_tour)
    monkeypatch.setattr(collect_preview_module, "OdiiClient", FakeOdii)
    monkeypatch.setattr(
        collect_preview_module,
        "_load_targeted_odii_credential",
        lambda: _SYNTHETIC_ODII_KEY,
        raising=False,
    )
    monkeypatch.setattr(
        collect_preview_module,
        "require_live_collection_allowed",
        lambda *, explicit_opt_in: None,
    )
    terminal_success_attempted = False
    if fail_terminal_success:

        def injected_terminal_success_failure(diagnostic: object) -> None:
            nonlocal terminal_success_attempted
            terminal_success_attempted = True
            raise ProviderDiagnosticsError

        monkeypatch.setattr(
            collect_preview_module.ProviderDiagnostics,
            "terminal_success",
            injected_terminal_success_failure,
        )
    output = tmp_path / "output"
    diagnostics = tmp_path / "diagnostics"

    assert collect_preview_main(_target_args(source, output, diagnostics)) == CHECK_UNRESOLVED
    assert terminal_success_attempted is fail_terminal_success
    assert tour_constructions == 0
    assert [(operation, params) for operation, params in calls] == [
        ("themeSearchList", {"keyword": "대릉원"}),
        ("storyBasedList", {"tid": "900", "tlid": "901"}),
    ]
    assert [policy.timeout_seconds for policy in policies] == [300.0]
    assert source_snapshot == {
        path.name: path.read_bytes() for path in source.parent.iterdir() if path.is_file()
    }
    assert {path.name for path in output.iterdir()} == {
        "candidate-review.json",
        "candidate-review.md",
        "raw-provider-bundle.redacted.json",
        "review-manifest.json",
    }
    checked = check_review_manifest(output / "review-manifest.json")
    assert checked.exit_code == CHECK_UNRESOLVED, checked.reason
    assert checked.review is not None and checked.bundle_path is not None
    by_id = {candidate.place_id: candidate for candidate in checked.review.candidates}
    assert all(
        candidate.resolution_status.value == "UNRESOLVED" for candidate in checked.review.candidates
    )
    assert by_id["preview:5"].evidence[1].endpoint == "Odii/storyBasedList"
    assert by_id["preview:5"].evidence[1].source_id is None
    assert collect_preview_module._TARGETED_APPROVED_IDENTITIES == _APPROVED
    source_bundle_bytes = (source.parent / "raw-provider-bundle.redacted.json").read_bytes()
    output_bundle_bytes = checked.bundle_path.read_bytes()
    source_bundle_payload = json.loads(source_bundle_bytes)
    output_bundle_payload = json.loads(output_bundle_bytes)
    source_bundle = RawProviderBundle.model_validate_json(source_bundle_bytes)
    output_bundle = RawProviderBundle.model_validate_json(output_bundle_bytes)
    assert len(output_bundle.rows) == len(source_bundle.rows) + 2
    assert output_bundle_payload["rows"][: len(source_bundle.rows)] == source_bundle_payload["rows"]
    assert [row.raw_response_sha256 for row in output_bundle.rows[: len(source_bundle.rows)]] == [
        row.raw_response_sha256 for row in source_bundle.rows
    ]
    assert all(
        row.candidate_place_id == "preview:5" and row.provider.value == "ODII"
        for row in output_bundle.rows[len(source_bundle.rows) :]
    )
    source_review_payload = json.loads((source.parent / "candidate-review.json").read_bytes())
    output_review_payload = json.loads((output / "candidate-review.json").read_bytes())
    assert [
        candidate
        for candidate in output_review_payload["candidates"]
        if candidate["place_id"] != "preview:5"
    ] == [
        candidate
        for candidate in source_review_payload["candidates"]
        if candidate["place_id"] != "preview:5"
    ]


@pytest.mark.parametrize(
    "mutation",
    ["candidate", "provider", "keyword", "source", "output-overlap", "out-of-mode"],
)
def test_targeted_odii_enrichment_rejects_invalid_forms_before_sensitive_work(
    mutation: str,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    source = _write_source(tmp_path / "source")
    _pin_source(monkeypatch, source)
    output = tmp_path / "output"
    diagnostics = tmp_path / "diagnostics"
    args = _target_args(source, output, diagnostics)
    if mutation == "candidate":
        args[args.index("preview:5")] = "preview:4"
    elif mutation == "provider":
        args[args.index("ODII")] = "TOUR_API"
    elif mutation == "keyword":
        args[args.index("대릉원")] = "대릉원 일원"
    elif mutation == "source":
        args[1] = str(tmp_path / "missing" / "review-manifest.json")
    elif mutation == "output-overlap":
        args[args.index(str(output))] = str(source.parent)
    else:
        args.extend(["--candidate-selection", "불국사", "1", "2", "3", "불국사"])
    credential_loads = 0
    client_constructions = 0

    def load_credential() -> str:
        nonlocal credential_loads
        credential_loads += 1
        return _SYNTHETIC_ODII_KEY

    def construct_client(*args: object, **kwargs: object) -> object:
        nonlocal client_constructions
        client_constructions += 1
        raise AssertionError("client construction was not expected")

    monkeypatch.setattr(
        collect_preview_module,
        "_load_targeted_odii_credential",
        load_credential,
        raising=False,
    )
    monkeypatch.setattr(collect_preview_module, "OdiiClient", construct_client)

    assert collect_preview_main(args) == CHECK_MALFORMED
    assert credential_loads == 0
    assert client_constructions == 0
    assert not output.exists()
    assert not diagnostics.exists()


def test_targeted_odii_transport_failure_logs_safely_and_publishes_nothing(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    source = _write_source(tmp_path / "source")
    _pin_source(monkeypatch, source)
    attempts = 0

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal attempts
        attempts += 1
        return httpx.Response(503, json={"status": "temporary"}, request=request)

    http_client = httpx.Client(transport=httpx.MockTransport(handler))
    real_odii = collect_preview_module.OdiiClient
    monkeypatch.setattr(
        collect_preview_module,
        "OdiiClient",
        lambda *, service_key, policy: real_odii(
            service_key=service_key,
            policy=policy,
            http_client=http_client,
        ),
    )
    monkeypatch.setattr(
        collect_preview_module,
        "_load_targeted_odii_credential",
        lambda: _SYNTHETIC_ODII_KEY,
        raising=False,
    )
    monkeypatch.setattr(
        collect_preview_module,
        "require_live_collection_allowed",
        lambda *, explicit_opt_in: None,
    )
    output = tmp_path / "output"
    diagnostics = tmp_path / "diagnostics"
    try:
        assert collect_preview_main(_target_args(source, output, diagnostics)) == CHECK_MALFORMED
    finally:
        http_client.close()

    assert attempts == 3
    assert not output.exists()
    logs = list(diagnostics.glob("provider-collection-*.jsonl"))
    assert len(logs) == 1
    serialized = logs[0].read_text(encoding="utf-8")
    assert '"event":"terminal_failure"' in serialized
    assert '"provider":"ODII"' in serialized
    assert '"candidate_place_id":"preview:5"' in serialized
    assert _SYNTHETIC_ODII_KEY not in serialized


def test_targeted_odii_enrichment_help_documents_the_fail_closed_contract(
    capsys: pytest.CaptureFixture[str],
) -> None:
    with pytest.raises(SystemExit) as exc_info:
        collect_preview_main(["--help"])

    assert exc_info.value.code == 0
    help_text = capsys.readouterr().out
    assert "--targeted-odii-review-enrichment SOURCE_MANIFEST" in help_text
    assert "--candidate-id preview:5" in help_text
    assert "--provider ODII" in help_text
    assert "--keyword 대릉원" in help_text


def test_targeted_publication_never_replaces_a_concurrent_empty_directory(
    tmp_path: Path,
) -> None:
    temporary = tmp_path / "temporary"
    temporary.mkdir()
    (temporary / "artifact").write_text("new", encoding="utf-8")
    output = tmp_path / "output"
    output.mkdir()

    with pytest.raises(CollectionError):
        collect_preview_module._atomic_rename_directory_noreplace(temporary, output)

    assert temporary.is_dir()
    assert output.is_dir()
    assert list(output.iterdir()) == []


def test_targeted_credential_loader_never_opens_combined_tour_secret_file(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    separate = tmp_path / "itda-odii.env"
    separate.write_text(f"ODII_SERVICE_KEY={_SYNTHETIC_ODII_KEY}\n", encoding="utf-8")
    separate.chmod(0o600)
    combined = tmp_path / "itda-api.env"
    combined.write_text(
        "TOUR_API_SERVICE_KEY=tour-canary-must-not-be-materialized\n",
        encoding="utf-8",
    )
    real_open = Path.open

    def open_spy(path: Path, *args: object, **kwargs: object) -> object:
        if path == combined:
            raise AssertionError("combined TourAPI credential file was opened")
        return real_open(path, *args, **kwargs)

    monkeypatch.setattr(
        collect_preview_module,
        "_validated_targeted_odii_credential_path",
        lambda: separate,
        raising=False,
    )
    monkeypatch.setattr(Path, "open", open_spy)

    assert collect_preview_module._load_targeted_odii_credential() == _SYNTHETIC_ODII_KEY


@pytest.mark.parametrize(
    ("source_kwargs", "use_symlink"),
    [
        ({"first_place_id": "swap"}, False),
        ({"first_tour_id": "999999"}, False),
        ({"first_tour_endpoint": "KorService2/detailCommon2"}, False),
        ({}, True),
    ],
    ids=["candidate-id", "approved-identity", "baseline-endpoint", "symlink-ancestor"],
)
def test_targeted_source_preflight_rejects_substitution_before_sensitive_work(
    source_kwargs: dict[str, str],
    use_symlink: bool,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    source = _write_source(tmp_path / "source", **source_kwargs)
    _pin_source(monkeypatch, source)
    selected_source = source
    if use_symlink:
        alias = tmp_path / "source-alias"
        alias.symlink_to(source.parent, target_is_directory=True)
        selected_source = alias / "review-manifest.json"
    credential_loads = 0

    def load_credential() -> str:
        nonlocal credential_loads
        credential_loads += 1
        return _SYNTHETIC_ODII_KEY

    monkeypatch.setattr(
        collect_preview_module,
        "_load_targeted_odii_credential",
        load_credential,
    )

    assert (
        collect_preview_main(
            _target_args(
                selected_source,
                tmp_path / "output",
                tmp_path / "diagnostics",
            )
        )
        == CHECK_MALFORMED
    )
    assert credential_loads == 0
    assert not (tmp_path / "output").exists()
    assert not (tmp_path / "diagnostics").exists()


def test_targeted_source_is_pinned_against_check_time_substitution(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    source = _write_source(tmp_path / "source")
    _pin_source(monkeypatch, source)
    real_check = collect_preview_module.check_review_manifest
    credential_loads = 0

    def substituting_check(path: Path) -> object:
        result = real_check(path)
        path.write_bytes(path.read_bytes() + b" ")
        return result

    def load_credential() -> str:
        nonlocal credential_loads
        credential_loads += 1
        return _SYNTHETIC_ODII_KEY

    monkeypatch.setattr(collect_preview_module, "check_review_manifest", substituting_check)
    monkeypatch.setattr(
        collect_preview_module,
        "_load_targeted_odii_credential",
        load_credential,
    )

    assert (
        collect_preview_main(
            _target_args(
                source,
                tmp_path / "output",
                tmp_path / "diagnostics",
            )
        )
        == CHECK_MALFORMED
    )
    assert credential_loads == 0
    assert not (tmp_path / "output").exists()
    assert not (tmp_path / "diagnostics").exists()


def test_targeted_credential_failure_writes_safe_terminal_diagnostic(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    source = _write_source(tmp_path / "source")
    _pin_source(monkeypatch, source)
    diagnostics = tmp_path / "diagnostics"
    monkeypatch.setattr(
        collect_preview_module,
        "_load_targeted_odii_credential",
        lambda: (_ for _ in ()).throw(CollectionError("private credential detail")),
    )
    monkeypatch.setattr(
        collect_preview_module,
        "require_live_collection_allowed",
        lambda *, explicit_opt_in: None,
    )

    assert (
        collect_preview_main(_target_args(source, tmp_path / "output", diagnostics))
        == CHECK_MALFORMED
    )
    logs = list(diagnostics.glob("provider-collection-*.jsonl"))
    assert len(logs) == 1
    serialized = logs[0].read_text(encoding="utf-8")
    assert '"event":"terminal_failure"' in serialized
    assert "private credential detail" not in serialized


def test_targeted_diagnostics_rejects_symlinked_ancestor_before_sensitive_work(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    source = _write_source(tmp_path / "source")
    _pin_source(monkeypatch, source)
    real_diagnostics_parent = tmp_path / "real-diagnostics"
    real_diagnostics_parent.mkdir()
    (real_diagnostics_parent / "provider").mkdir(mode=0o700)
    diagnostics_alias = tmp_path / "diagnostics-alias"
    diagnostics_alias.symlink_to(real_diagnostics_parent, target_is_directory=True)
    credential_loads = 0

    def load_credential() -> str:
        nonlocal credential_loads
        credential_loads += 1
        return _SYNTHETIC_ODII_KEY

    monkeypatch.setattr(
        collect_preview_module,
        "_load_targeted_odii_credential",
        load_credential,
    )

    assert (
        collect_preview_main(
            _target_args(
                source,
                tmp_path / "output",
                diagnostics_alias / "provider",
            )
        )
        == CHECK_MALFORMED
    )
    assert credential_loads == 0
    assert (real_diagnostics_parent / "provider").is_dir()
    assert not any((real_diagnostics_parent / "provider").iterdir())


@pytest.mark.parametrize("output", [Path("."), Path("/")], ids=["dot", "root"])
def test_targeted_rejects_empty_output_basename_before_sensitive_work(
    output: Path,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    sensitive_accesses: list[str] = []

    def record_sensitive_access(*args: object, **kwargs: object) -> None:
        sensitive_accesses.append("accessed")

    monkeypatch.setattr(
        collect_preview_module,
        "_preflight_targeted_source",
        record_sensitive_access,
    )
    monkeypatch.setattr(
        collect_preview_module,
        "_load_targeted_odii_credential",
        record_sensitive_access,
    )
    monkeypatch.setattr(
        collect_preview_module.ProviderDiagnostics,
        "ensure_directory",
        record_sensitive_access,
    )
    monkeypatch.setattr(
        collect_preview_module,
        "OdiiClient",
        record_sensitive_access,
    )

    with pytest.raises(CollectionError, match="output name"):
        collect_preview_module._collect_targeted_odii(
            tmp_path / "unread-source" / "review-manifest.json",
            output,
            diagnostics_dir=tmp_path / "unused-diagnostics",
            policy=RequestPolicy(timeout_seconds=300, max_attempts=1),
        )

    assert sensitive_accesses == []


def test_source_directory_fd_pins_original_across_ancestor_swap(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    source = _write_source(tmp_path / "source")
    expected_manifest = source.read_bytes()
    moved = tmp_path / "source-original"
    real_open = collect_preview_module._open_directory_fd_nofollow
    swapped = False

    def swapping_open(path: Path) -> int:
        nonlocal swapped
        descriptor = real_open(path)
        if not swapped:
            swapped = True
            source.parent.rename(moved)
            source.parent.mkdir()
            (source.parent / "review-manifest.json").write_text(
                "attacker",
                encoding="utf-8",
            )
        return descriptor

    monkeypatch.setattr(
        collect_preview_module,
        "_open_directory_fd_nofollow",
        swapping_open,
    )

    artifacts = collect_preview_module._read_targeted_source_artifacts_nofollow(source)

    assert artifacts["review-manifest.json"] == expected_manifest


def test_credential_directory_fd_pins_original_across_ancestor_swap(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    credentials_parent = tmp_path / "secrets"
    credentials_parent.mkdir()
    credential = credentials_parent / "itda-odii.env"
    credential.write_text(
        f"ODII_SERVICE_KEY={_SYNTHETIC_ODII_KEY}\n",
        encoding="utf-8",
    )
    credential.chmod(0o600)
    moved = tmp_path / "secrets-original"
    real_open = collect_preview_module._open_directory_fd_nofollow
    swapped = False

    def swapping_open(path: Path) -> int:
        nonlocal swapped
        descriptor = real_open(path)
        if not swapped:
            swapped = True
            credentials_parent.rename(moved)
            credentials_parent.mkdir()
            attacker = credentials_parent / "itda-odii.env"
            attacker.write_text("ODII_SERVICE_KEY=attacker\n", encoding="utf-8")
            attacker.chmod(0o600)
        return descriptor

    monkeypatch.setattr(
        collect_preview_module,
        "_open_directory_fd_nofollow",
        swapping_open,
    )

    assert (
        collect_preview_module._read_targeted_odii_credential_nofollow(credential)
        == _SYNTHETIC_ODII_KEY
    )


def test_output_directory_fd_pins_atomic_publish_across_ancestor_swap(
    tmp_path: Path,
) -> None:
    parent = tmp_path / "publish"
    parent.mkdir()
    staging = parent / "staging"
    staging.mkdir()
    (staging / "artifact").write_text("original", encoding="utf-8")
    parent_descriptor = collect_preview_module._open_directory_fd_nofollow(parent)
    moved = tmp_path / "publish-original"
    parent.rename(moved)
    parent.mkdir()
    try:
        collect_preview_module._atomic_rename_directory_noreplace_at(
            parent_descriptor,
            "staging",
            "output",
        )
    finally:
        os.close(parent_descriptor)

    assert (moved / "output" / "artifact").read_text(encoding="utf-8") == "original"
    assert not (parent / "output").exists()
