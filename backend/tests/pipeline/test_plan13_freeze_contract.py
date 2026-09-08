from __future__ import annotations

import hashlib
import json
import os
import subprocess
from base64 import b64encode
from contextlib import suppress
from pathlib import Path

import pytest
from pydantic import ValidationError

import itda.cli.collect_preview as collect_preview_module
import itda.cli.freeze_preview as freeze_preview_module
from itda.cli.freeze_preview import main as freeze_preview_main
from itda.cli.pipeline_demo import main as pipeline_demo_main
from itda.collectors.base import CollectionError, credential_material_present
from itda.contracts.candidate_review import (
    BLOCKED_RIGHTS_STATUS,
    CHECK_MALFORMED,
    CHECK_RESOLVED,
    CHECK_UNRESOLVED,
    LOCKED_PREVIEW_CANDIDATES,
    CandidateReview,
    RawProviderBundle,
    build_review_manifest,
    check_review_manifest,
    render_candidate_review_markdown,
)


def _canonical(payload: object) -> bytes:
    return (
        json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":")) + "\n"
    ).encode("utf-8")


def _sha(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


_TOUR_RIGHTS = [
    {"cpyrhtDivCd": "Type1"},
    {"cpyrhtDivCd": "Type3"},
]
PROVIDER_RAW_LIMIT = 2_000_000
_CURRENT_RIGHTS_FIXTURE = Path(__file__).resolve().parents[3] / "fixtures/preview/v1/review"
_SOURCE_LOCK_FIXTURE = (
    Path(__file__).resolve().parents[3]
    / "fixtures/preview/source-locks/preview-v1-source-lock.json"
)


def _provider_json_body_of_size(size: int) -> bytes:
    prefix = b'{"payload":"'
    suffix = b'"}'
    assert size >= len(prefix) + len(suffix)
    return prefix + b"x" * (size - len(prefix) - len(suffix)) + suffix


def _write_review_directory(root: Path, *, unresolved_index: int | None = None) -> Path:
    review_root = root / "review"
    review_root.mkdir(parents=True)
    candidates: list[dict[str, object]] = []
    bundle_rows: list[dict[str, object]] = []
    for index, name in enumerate(LOCKED_PREVIEW_CANDIDATES):
        resolved = index != unresolved_index
        response_specs = (
            ("TOUR_API", "KorService2/searchKeyword2", "tour-search"),
            ("ODII", "Odii/themeSearchList", "odii-theme"),
            ("TOUR_API", "KorService2/detailCommon2", "tour_api"),
            ("TOUR_API", "KorService2/detailImage2", "tour-image"),
            ("ODII", "Odii/storyBasedList", "odii"),
        )
        response_bodies: dict[str, bytes] = {}
        for provider, endpoint, source_prefix in response_specs:
            raw_payload: dict[str, object] = {
                "candidate": index,
                "endpoint": endpoint,
                "provider": provider,
                "rightsRows": _TOUR_RIGHTS if provider == "TOUR_API" else [],
            }
            if provider == "TOUR_API":
                raw_payload["modifiedtime"] = "20260722090000"
                raw_payload["versions"] = [{"modifiedtime": "20260721080000"}]
            raw_body = _canonical(raw_payload)
            response_bodies[endpoint] = raw_body
            source_id = f"{source_prefix}-{index}" if resolved else None
            bundle_rows.append(
                {
                    "candidate_place_id": f"preview:{index + 1}",
                    "provider": provider,
                    "endpoint": endpoint,
                    "request_scope": {"candidate": name},
                    "source_id": source_id,
                    "retrieved_at": "2026-07-22T12:00:00Z",
                    "http_status": 200,
                    "raw_response_sha256": _sha(raw_body),
                    "raw_body_base64": b64encode(raw_body).decode("ascii"),
                    "modifiedtime": "20260722090000" if provider == "TOUR_API" else None,
                    "rights": _TOUR_RIGHTS if provider == "TOUR_API" else [],
                    "asset_usage_status": BLOCKED_RIGHTS_STATUS,
                }
            )
        evidence = [
            {
                "provider": provider,
                "source_id": f"{source_prefix}-{index}" if resolved else None,
                "endpoint": endpoint,
                "request_scope": {"candidate": name},
                "retrieved_at": "2026-07-22T12:00:00Z",
                "http_status": 200,
                "raw_response_sha256": _sha(response_bodies[endpoint]),
                "modifiedtime": "20260722090000" if provider == "TOUR_API" else None,
                "upstream_rights": _TOUR_RIGHTS if provider == "TOUR_API" else [],
                "asset_usage_status": BLOCKED_RIGHTS_STATUS,
                "unresolved_reason": None if resolved else "upstream evidence missing",
            }
            for provider, endpoint, source_prefix in (
                ("TOUR_API", "KorService2/detailCommon2", "tour_api"),
                ("ODII", "Odii/storyBasedList", "odii"),
            )
        ]
        candidates.append(
            {
                "place_id": f"preview:{index + 1}",
                "name_ko": name,
                "address_ko": f"경상북도 경주시 검토로 {index + 1}",
                "longitude": 129.2 + index * 0.001,
                "latitude": 35.8 + index * 0.001,
                "split": "PREVIEW",
                "assessment_status": "NOT_SCORED",
                "resolution_status": "RESOLVED" if resolved else "UNRESOLVED",
                "evidence": evidence,
            }
        )

    bundle_path = review_root / "raw-provider-bundle.redacted.json"
    bundle_path.write_bytes(
        _canonical(
            {
                "schema_version": "provider-bundle-v1",
                "redacted": True,
                "rows": bundle_rows,
            }
        )
    )
    review = CandidateReview.model_validate(
        {
            "schema_version": "candidate-review-v1",
            "artifact_status": "REVIEW_ONLY",
            "bundle_path": bundle_path.name,
            "redacted_bundle_sha256": _sha(bundle_path.read_bytes()),
            "candidates": candidates,
        }
    )
    candidate_path = review_root / "candidate-review.json"
    candidate_path.write_bytes(
        _canonical(review.model_dump(mode="json", exclude={"rights_review"}))
    )
    markdown_path = review_root / "candidate-review.md"
    bundle = RawProviderBundle.model_validate_json(bundle_path.read_bytes())
    markdown_path.write_bytes(render_candidate_review_markdown(review, bundle))
    manifest_path = review_root / "review-manifest.json"
    manifest_path.write_bytes(build_review_manifest(review_root))
    return manifest_path


def _write_current_rights_review_directory(root: Path) -> Path:
    review_root = root / "review"
    review_root.mkdir(parents=True)
    source_lock = root.parent / "source-locks/preview-v1-source-lock.json"
    source_lock.parent.mkdir(parents=True, exist_ok=True)
    source_lock.write_bytes(_SOURCE_LOCK_FIXTURE.read_bytes())
    for name in (
        "raw-provider-bundle.redacted.json",
        "candidate-review.json",
        "candidate-review.md",
        "review-manifest.json",
    ):
        (review_root / name).write_bytes((_CURRENT_RIGHTS_FIXTURE / name).read_bytes())
    return review_root / "review-manifest.json"


def _resign_coordinated_rights_tamper(manifest_path: Path, *, mutation: str) -> None:
    review_root = manifest_path.parent
    bundle_path = review_root / "raw-provider-bundle.redacted.json"
    candidate_path = review_root / "candidate-review.json"
    markdown_path = review_root / "candidate-review.md"
    bundle_payload = json.loads(bundle_path.read_text(encoding="utf-8"))
    candidate_payload = json.loads(candidate_path.read_text(encoding="utf-8"))
    evidence = candidate_payload["candidates"][0]["evidence"][0]
    row = next(
        item
        for item in bundle_payload["rows"]
        if item["candidate_place_id"] == "preview:1"
        and item["provider"] == "TOUR_API"
        and item["endpoint"] == evidence["endpoint"]
    )
    tampered_rights = [row["rights"][0]] if mutation == "remove" else list(reversed(row["rights"]))
    row["rights"] = tampered_rights
    evidence["upstream_rights"] = tampered_rights
    bundle_path.write_bytes(_canonical(bundle_payload))
    candidate_payload["redacted_bundle_sha256"] = _sha(bundle_path.read_bytes())
    candidate_path.write_bytes(_canonical(candidate_payload))
    old_rights = json.dumps(_TOUR_RIGHTS, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    new_rights = json.dumps(
        tampered_rights, ensure_ascii=False, sort_keys=True, separators=(",", ":")
    )
    markdown_lines = markdown_path.read_text(encoding="utf-8").splitlines()
    target_prefix = "| preview:1 | TOUR_API | KorService2/detailCommon2 |"
    target_index = next(
        index for index, line in enumerate(markdown_lines) if line.startswith(target_prefix)
    )
    markdown_lines[target_index] = markdown_lines[target_index].replace(old_rights, new_rights)
    markdown_path.write_text("\n".join(markdown_lines) + "\n", encoding="utf-8")
    manifest_payload = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest_payload["redacted_provider_bundle_sha256"] = _sha(bundle_path.read_bytes())
    manifest_payload["candidate_review_sha256"] = _sha(candidate_path.read_bytes())
    manifest_payload["candidate_review_markdown_sha256"] = _sha(markdown_path.read_bytes())
    manifest_path.write_bytes(_canonical(manifest_payload))


def _resign_coordinated_modifiedtime_tamper(manifest_path: Path, *, mutation: str) -> None:
    review_root = manifest_path.parent
    bundle_path = review_root / "raw-provider-bundle.redacted.json"
    candidate_path = review_root / "candidate-review.json"
    markdown_path = review_root / "candidate-review.md"
    bundle_payload = json.loads(bundle_path.read_text(encoding="utf-8"))
    candidate_payload = json.loads(candidate_path.read_text(encoding="utf-8"))
    provider = "ODII" if mutation == "add" else "TOUR_API"
    evidence = next(
        item
        for item in candidate_payload["candidates"][0]["evidence"]
        if item["provider"] == provider
    )
    row = next(
        item
        for item in bundle_payload["rows"]
        if item["candidate_place_id"] == "preview:1"
        and item["provider"] == provider
        and item["endpoint"] == evidence["endpoint"]
    )
    old_modifiedtime = row["modifiedtime"]
    tampered_modifiedtime = {
        "add": "20260722090000",
        "change": "20260722090001",
        "remove": None,
    }[mutation]
    row["modifiedtime"] = tampered_modifiedtime
    evidence["modifiedtime"] = tampered_modifiedtime
    bundle_path.write_bytes(_canonical(bundle_payload))
    candidate_payload["redacted_bundle_sha256"] = _sha(bundle_path.read_bytes())
    candidate_path.write_bytes(_canonical(candidate_payload))

    markdown_lines = markdown_path.read_text(encoding="utf-8").splitlines()
    target_prefix = f"| preview:1 | {provider} | {evidence['endpoint']} |"
    target_index = next(
        index for index, line in enumerate(markdown_lines) if line.startswith(target_prefix)
    )
    columns = markdown_lines[target_index].split(" | ")
    assert columns[8] == (old_modifiedtime or "UNRESOLVED")
    columns[8] = tampered_modifiedtime or "UNRESOLVED"
    markdown_lines[target_index] = " | ".join(columns)
    markdown_path.write_text("\n".join(markdown_lines) + "\n", encoding="utf-8")

    manifest_payload = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest_payload["redacted_provider_bundle_sha256"] = _sha(bundle_path.read_bytes())
    manifest_payload["candidate_review_sha256"] = _sha(candidate_path.read_bytes())
    manifest_payload["candidate_review_markdown_sha256"] = _sha(markdown_path.read_bytes())
    manifest_path.write_bytes(_canonical(manifest_payload))


def _resign_candidate_review_schema_version(manifest_path: Path, version: str) -> None:
    review_root = manifest_path.parent
    candidate_path = review_root / "candidate-review.json"
    candidate_payload = json.loads(candidate_path.read_text(encoding="utf-8"))
    candidate_payload["schema_version"] = version
    candidate_path.write_bytes(_canonical(candidate_payload))

    manifest_payload = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest_payload["candidate_review_sha256"] = _sha(candidate_path.read_bytes())
    manifest_path.write_bytes(_canonical(manifest_payload))


def _resign_raw_body(manifest_path: Path, raw_body: bytes) -> None:
    review_root = manifest_path.parent
    bundle_path = review_root / "raw-provider-bundle.redacted.json"
    candidate_path = review_root / "candidate-review.json"
    markdown_path = review_root / "candidate-review.md"
    bundle_payload = json.loads(bundle_path.read_text(encoding="utf-8"))
    candidate_payload = json.loads(candidate_path.read_text(encoding="utf-8"))
    evidence = candidate_payload["candidates"][0]["evidence"][0]
    row = next(
        item
        for item in bundle_payload["rows"]
        if item["candidate_place_id"] == "preview:1"
        and item["provider"] == "TOUR_API"
        and item["endpoint"] == evidence["endpoint"]
    )
    old_hash = row["raw_response_sha256"]
    new_hash = _sha(raw_body)
    row["raw_body_base64"] = b64encode(raw_body).decode("ascii")
    row["raw_response_sha256"] = new_hash
    row["rights"] = []
    evidence["raw_response_sha256"] = new_hash
    evidence["upstream_rights"] = []
    bundle_path.write_bytes(_canonical(bundle_payload))
    candidate_payload["redacted_bundle_sha256"] = _sha(bundle_path.read_bytes())
    candidate_path.write_bytes(_canonical(candidate_payload))
    old_rights = json.dumps(_TOUR_RIGHTS, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    markdown_lines = markdown_path.read_text(encoding="utf-8").splitlines()
    target_prefix = "| preview:1 | TOUR_API | KorService2/detailCommon2 |"
    target_index = next(
        index for index, line in enumerate(markdown_lines) if line.startswith(target_prefix)
    )
    markdown_lines[target_index] = markdown_lines[target_index].replace(old_hash, new_hash)
    markdown_lines[target_index] = markdown_lines[target_index].replace(old_rights, "[]")
    markdown_path.write_text("\n".join(markdown_lines) + "\n", encoding="utf-8")
    manifest_payload = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest_payload["redacted_provider_bundle_sha256"] = _sha(bundle_path.read_bytes())
    manifest_payload["candidate_review_sha256"] = _sha(candidate_path.read_bytes())
    manifest_payload["candidate_review_markdown_sha256"] = _sha(markdown_path.read_bytes())
    manifest_path.write_bytes(_canonical(manifest_payload))


def _write_approval(review_manifest: Path, *, manifest_sha: str | None = None) -> Path:
    manifest = json.loads(review_manifest.read_text(encoding="utf-8"))
    candidate_path = review_manifest.parent / "candidate-review.json"
    candidate = json.loads(candidate_path.read_text(encoding="utf-8"))
    markdown_path = review_manifest.parent / "candidate-review.md"
    source_lock = review_manifest.parents[2] / "source-locks" / "preview-v1-source-lock.json"
    identities = [
        {
            "name_ko": candidate_row["name_ko"],
            "place_id": candidate_row["place_id"],
            "selected_odii_story": rights_row["selected_odii_story"],
            "tour_source_id": candidate_row["evidence"][0]["source_id"],
        }
        for candidate_row, rights_row in zip(
            candidate["candidates"],
            candidate["rights_review"]["candidates"],
            strict=True,
        )
    ]
    approval = review_manifest.parent / "APPROVAL.md"
    approval.write_text(
        "\n".join(
            (
                "# IT-DA six-place PREVIEW approval",
                "",
                "schema_version: preview-freeze-approval-v1",
                "approval_signal: approved-six-preview",
                "status: APPROVED",
                "canonical_candidate_review_sha256: " + _sha(candidate_path.read_bytes()),
                "canonical_candidate_review_markdown_sha256: " + _sha(markdown_path.read_bytes()),
                "canonical_source_lock_sha256: " + _sha(source_lock.read_bytes()),
                "approved_redacted_provider_bundle_sha256: "
                + manifest["redacted_provider_bundle_sha256"],
                "approved_review_manifest_sha256: "
                + (manifest_sha or _sha(review_manifest.read_bytes())),
                "approved_candidate_identities: "
                + json.dumps(
                    identities,
                    ensure_ascii=False,
                    sort_keys=True,
                    separators=(",", ":"),
                ),
                "rights_acknowledgement_version: official-public-data-contest-v2",
                "reviewer: phase-1-reviewer",
                "approved_at: 2026-07-22T12:30:00Z",
                "",
            )
        ),
        encoding="utf-8",
    )
    return approval


def test_review_manifest_binds_exact_artifacts_and_keeps_three_exit_semantics(
    tmp_path: Path,
) -> None:
    resolved = _write_review_directory(tmp_path / "resolved")
    unresolved = _write_review_directory(tmp_path / "unresolved", unresolved_index=2)

    assert check_review_manifest(resolved).exit_code == CHECK_RESOLVED == 0
    assert check_review_manifest(unresolved).exit_code == CHECK_UNRESOLVED == 2

    manifest = json.loads(resolved.read_text(encoding="utf-8"))
    assert manifest["candidate_names"] == list(LOCKED_PREVIEW_CANDIDATES)
    assert manifest["redacted_provider_bundle_path"] == "raw-provider-bundle.redacted.json"
    assert manifest["candidate_review_path"] == "candidate-review.json"
    assert manifest["candidate_review_markdown_path"] == "candidate-review.md"

    manifest["candidate_review_sha256"] = "0" * 64
    resolved.write_bytes(_canonical(manifest))
    assert check_review_manifest(resolved).exit_code == CHECK_MALFORMED == 1


def test_candidate_review_requires_exact_v1_schema_directly(tmp_path: Path) -> None:
    manifest = _write_review_directory(tmp_path)
    candidate_path = manifest.parent / "candidate-review.json"
    candidate_payload = json.loads(candidate_path.read_text(encoding="utf-8"))
    candidate_payload["schema_version"] = "candidate-review-v2"

    with pytest.raises(ValidationError, match="schema_version"):
        CandidateReview.model_validate(candidate_payload)


def test_review_manifest_rejects_fully_rehashed_candidate_review_v2(tmp_path: Path) -> None:
    manifest = _write_review_directory(tmp_path, unresolved_index=0)
    assert check_review_manifest(manifest).exit_code == CHECK_UNRESOLVED

    _resign_candidate_review_schema_version(manifest, "candidate-review-v2")

    assert check_review_manifest(manifest).exit_code == CHECK_MALFORMED
    assert collect_preview_module.main(["--check-review", str(manifest)]) == CHECK_MALFORMED


def test_collect_check_review_plumbs_the_current_source_lock(tmp_path: Path) -> None:
    manifest = _write_current_rights_review_directory(tmp_path / "preview" / "v1")
    source_lock = tmp_path / "preview" / "source-locks" / "preview-v1-source-lock.json"

    assert (
        collect_preview_module.main(
            [
                "--check-review",
                str(manifest),
                "--source-lock",
                str(source_lock),
            ]
        )
        == CHECK_RESOLVED
    )
    assert collect_preview_module.main(["--check-review", str(manifest)]) == CHECK_MALFORMED

    source_lock_payload = json.loads(source_lock.read_text(encoding="utf-8"))
    source_lock_payload["source_candidate_review_sha256"] = "0" * 64
    source_lock.write_bytes(_canonical(source_lock_payload))
    assert (
        collect_preview_module.main(
            [
                "--check-review",
                str(manifest),
                "--source-lock",
                str(source_lock),
            ]
        )
        == CHECK_MALFORMED
    )


def test_review_manifest_requires_exact_v1_schema(tmp_path: Path) -> None:
    manifest = _write_review_directory(tmp_path)
    payload = json.loads(manifest.read_text(encoding="utf-8"))
    payload["schema_version"] = "review-manifest-v2"
    manifest.write_bytes(_canonical(payload))

    assert check_review_manifest(manifest).exit_code == CHECK_MALFORMED
    assert collect_preview_module.main(["--check-review", str(manifest)]) == CHECK_MALFORMED


@pytest.mark.parametrize(
    "mutation",
    [
        "extra-entry",
        "manifest-symlink",
        "manifest-directory",
        "manifest-special",
        "artifact-symlink",
        "artifact-directory",
        "artifact-special",
    ],
)
def test_direct_review_requires_exact_four_regular_non_symlink_entries(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    mutation: str,
) -> None:
    manifest = _write_review_directory(tmp_path / "source", unresolved_index=0)
    assert check_review_manifest(manifest).exit_code == CHECK_UNRESOLVED
    review_root = manifest.parent

    if mutation == "extra-entry":
        (review_root / "unexpected.txt").write_text("unexpected", encoding="utf-8")
    elif mutation.startswith("manifest-"):
        manifest_bytes = manifest.read_bytes()
        manifest.unlink()
        if mutation == "manifest-symlink":
            target = tmp_path / "external-review-manifest.json"
            target.write_bytes(manifest_bytes)
            manifest.symlink_to(target)
        elif mutation == "manifest-directory":
            manifest.mkdir()
        else:
            os.mkfifo(manifest)
            real_read_bytes = Path.read_bytes

            def guarded_read_bytes(path: Path) -> bytes:
                if path == manifest:
                    raise AssertionError("special manifest entry must be rejected before read")
                return real_read_bytes(path)

            monkeypatch.setattr(Path, "read_bytes", guarded_read_bytes)
    else:
        artifact = review_root / "candidate-review.md"
        artifact_bytes = artifact.read_bytes()
        artifact.unlink()
        if mutation == "artifact-symlink":
            target = tmp_path / "external-candidate-review.md"
            target.write_bytes(artifact_bytes)
            artifact.symlink_to(target)
        elif mutation == "artifact-directory":
            artifact.mkdir()
        else:
            os.mkfifo(artifact)

    assert check_review_manifest(manifest).exit_code == CHECK_MALFORMED
    assert collect_preview_module.main(["--check-review", str(manifest)]) == CHECK_MALFORMED


def test_review_accepts_absent_and_first_preorder_modifiedtime_projections(
    tmp_path: Path,
) -> None:
    manifest = _write_review_directory(tmp_path)

    checked = check_review_manifest(manifest)

    assert checked.exit_code == CHECK_RESOLVED
    assert checked.bundle_path is not None
    bundle = RawProviderBundle.model_validate_json(checked.bundle_path.read_bytes())
    tour = next(
        row
        for row in bundle.rows
        if row.candidate_place_id == "preview:1" and row.endpoint == "KorService2/detailCommon2"
    )
    odii = next(
        row
        for row in bundle.rows
        if row.candidate_place_id == "preview:1" and row.endpoint == "Odii/storyBasedList"
    )
    assert tour.modifiedtime == "20260722090000"
    assert odii.modifiedtime is None


@pytest.mark.parametrize("mutation", ["remove", "reorder"])
def test_review_rejects_coordinated_resigned_rights_tampering(
    tmp_path: Path,
    mutation: str,
) -> None:
    manifest = _write_review_directory(tmp_path, unresolved_index=0)
    assert check_review_manifest(manifest).exit_code == CHECK_UNRESOLVED

    _resign_coordinated_rights_tamper(manifest, mutation=mutation)

    assert check_review_manifest(manifest).exit_code == CHECK_MALFORMED


@pytest.mark.parametrize("mutation", ["remove", "add", "change"])
def test_review_rejects_coordinated_resigned_modifiedtime_tampering(
    tmp_path: Path,
    mutation: str,
) -> None:
    manifest = _write_review_directory(tmp_path, unresolved_index=0)
    assert check_review_manifest(manifest).exit_code == CHECK_UNRESOLVED

    _resign_coordinated_modifiedtime_tamper(manifest, mutation=mutation)

    assert check_review_manifest(manifest).exit_code == CHECK_MALFORMED
    assert collect_preview_module.main(["--check-review", str(manifest)]) == CHECK_MALFORMED


def test_review_manifest_rejects_resigned_oversized_provider_body(tmp_path: Path) -> None:
    manifest = _write_review_directory(tmp_path, unresolved_index=0)
    assert check_review_manifest(manifest).exit_code == CHECK_UNRESOLVED

    _resign_raw_body(manifest, _provider_json_body_of_size(PROVIDER_RAW_LIMIT + 1))

    assert check_review_manifest(manifest).exit_code == CHECK_MALFORMED
    assert collect_preview_module.main(["--check-review", str(manifest)]) == CHECK_MALFORMED


def test_candidate_review_markdown_is_human_readable_and_complete(tmp_path: Path) -> None:
    manifest = _write_review_directory(tmp_path)
    markdown = (manifest.parent / "candidate-review.md").read_text(encoding="utf-8")

    for name in LOCKED_PREVIEW_CANDIDATES:
        assert name in markdown
    assert "경상북도 경주시 검토로 1" in markdown
    assert "tour_api-0" in markdown
    assert "odii-0" in markdown
    assert "BLOCKED_PENDING_PHASE2_RIGHTS_REVIEW" in markdown
    assert "PREVIEW / NOT_SCORED" in markdown


@pytest.mark.parametrize(
    "echoed",
    [
        "MiXeD-Secret%2fValue",
        "MiXeD-Secret%252fValue",
        "MiXeD-Secret\\u0025\\u0032fValue",
    ],
)
def test_credential_reflection_normalization_remains_fail_closed(echoed: str) -> None:
    assert credential_material_present(
        _canonical({"echo": echoed}),
        "MiXeD-Secret/Value",
    )


def test_live_credentials_require_ignore_proof_regular_file_and_mode_0600(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    secret_dir = tmp_path / ".secrets"
    secret_dir.mkdir()
    credentials = secret_dir / "itda-api.env"
    credentials.write_text(
        "TOUR_API_SERVICE_KEY=synthetic-tour\nODII_SERVICE_KEY=synthetic-odii\n",
        encoding="utf-8",
    )
    credentials.chmod(0o644)

    tracked = False

    def fake_git(
        args: list[str],
        **kwargs: object,
    ) -> subprocess.CompletedProcess[str]:
        if args[1:3] == ["rev-parse", "--show-toplevel"]:
            return subprocess.CompletedProcess(args, 0, stdout=f"{tmp_path}\n", stderr="")
        if "ls-files" in args:
            return subprocess.CompletedProcess(args, 0 if tracked else 1, stdout="", stderr="")
        return subprocess.CompletedProcess(args, 0, stdout="", stderr="")

    monkeypatch.setattr(collect_preview_module.subprocess, "run", fake_git)
    with pytest.raises(CollectionError, match="0600"):
        collect_preview_module._load_live_credentials()

    credentials.chmod(0o600)
    assert collect_preview_module._load_live_credentials() == (
        "synthetic-tour",
        "synthetic-odii",
    )

    tracked = True
    with pytest.raises(CollectionError, match="tracked"):
        collect_preview_module._load_live_credentials()
    tracked = False

    credentials.unlink()
    credentials.symlink_to(tmp_path / "outside")
    with pytest.raises((CollectionError, FileNotFoundError)):
        collect_preview_module._load_live_credentials()


def test_approved_freeze_materializes_exact_top_level_boundary_and_stage_proof(
    tmp_path: Path,
) -> None:
    review_manifest = _write_current_rights_review_directory(tmp_path / "preview" / "approved")
    approval = _write_approval(review_manifest)
    output_root = tmp_path / "preview" / "v1"

    assert (
        freeze_preview_main(
            [
                "--check-approved",
                "--approval",
                str(approval),
                "--review-manifest",
                str(review_manifest),
                "--output-root",
                str(output_root),
            ]
        )
        == 0
    )
    assert {path.name for path in output_root.iterdir()} == {
        "review",
        "raw",
        "sanitized",
        "normalized",
        "manifest.json",
        "stage-manifest.json",
    }
    for relative in (
        "raw/six-places.json",
        "sanitized/six-places.json",
        "normalized/six-places.json",
        "manifest.json",
        "stage-manifest.json",
    ):
        path = output_root / relative
        assert path.is_file()
        assert not path.is_symlink()

    manifest = json.loads((output_root / "manifest.json").read_text(encoding="utf-8"))
    assert manifest["approval_sha256"] == _sha(
        (output_root / "review" / "APPROVAL.md").read_bytes()
    )
    assert manifest["split"] == "PREVIEW"
    assert manifest["assessment_status"] == "NOT_SCORED"
    assert manifest["candidate_names"] == list(LOCKED_PREVIEW_CANDIDATES)
    sanitized = json.loads(
        (output_root / "sanitized" / "six-places.json").read_text(encoding="utf-8")
    )
    assert all(
        asset["cpyrht_div_cd"] == "Type1"
        for place in sanitized["places"]
        for asset in place["allowed_assets"]
    )
    excluded = [asset for place in sanitized["places"] for asset in place["excluded_assets"]]
    assert excluded
    assert all(
        asset["cpyrht_div_cd"] == "Type3"
        and asset["transform_allowed"] is False
        and asset["model_input_allowed"] is False
        and asset["normalized_asset_allowed"] is False
        for asset in excluded
    )
    assert (
        pipeline_demo_main(["--check-stage-manifest", str(output_root / "stage-manifest.json")])
        == 0
    )

    frozen_bytes = {
        path.relative_to(output_root).as_posix(): path.read_bytes()
        for path in output_root.rglob("*")
        if path.is_file()
    }
    assert (
        freeze_preview_main(
            [
                "--check-approved",
                "--approval",
                str(approval),
                "--review-manifest",
                str(review_manifest),
                "--output-root",
                str(output_root),
            ]
        )
        == 1
    )
    assert frozen_bytes == {
        path.relative_to(output_root).as_posix(): path.read_bytes()
        for path in output_root.rglob("*")
        if path.is_file()
    }


@pytest.mark.parametrize(
    "mutation",
    [
        "extra-entry",
        "approval-symlink",
        "approval-directory",
        "approval-special",
    ],
)
def test_approved_freeze_requires_exact_five_regular_non_symlink_entries(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    mutation: str,
) -> None:
    review_manifest = _write_current_rights_review_directory(tmp_path / "preview" / "approved")
    approval = _write_approval(review_manifest)
    output_root = tmp_path / "preview" / "v1"

    if mutation == "extra-entry":
        (review_manifest.parent / "unexpected.txt").write_text(
            "unexpected",
            encoding="utf-8",
        )
    else:
        approval_bytes = approval.read_bytes()
        approval.unlink()
        if mutation == "approval-symlink":
            target = tmp_path / "external-approval.md"
            target.write_bytes(approval_bytes)
            approval.symlink_to(target)
        elif mutation == "approval-directory":
            approval.mkdir()
        else:
            os.mkfifo(approval)
            real_read_text = Path.read_text

            def guarded_read_text(path: Path, *args: object, **kwargs: object) -> str:
                if path == approval:
                    raise AssertionError("special approval entry must be rejected before read")
                return real_read_text(path, *args, **kwargs)

            monkeypatch.setattr(Path, "read_text", guarded_read_text)

    assert (
        freeze_preview_main(
            [
                "--check-approved",
                "--approval",
                str(approval),
                "--review-manifest",
                str(review_manifest),
                "--output-root",
                str(output_root),
            ]
        )
        == 1
    )
    assert not output_root.exists()


def test_approved_review_snapshot_close_failures_preserve_artifact_validation_error(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    review_manifest = _write_current_rights_review_directory(tmp_path / "preview" / "approved")
    _write_approval(review_manifest)
    real_open = freeze_preview_module.os.open
    real_close = freeze_preview_module.os.close
    real_isreg = freeze_preview_module.S_ISREG
    opened_descriptors: list[int] = []
    close_attempts: list[int] = []
    regular_file_checks = 0

    def observed_open(
        path: str | bytes | os.PathLike[str],
        flags: int,
        mode: int = 0o777,
        *,
        dir_fd: int | None = None,
    ) -> int:
        descriptor = real_open(path, flags, mode, dir_fd=dir_fd)
        opened_descriptors.append(descriptor)
        return descriptor

    def fail_opened_artifact_validation(mode: int) -> bool:
        nonlocal regular_file_checks
        regular_file_checks += 1
        if regular_file_checks == 2:
            return False
        return real_isreg(mode)

    def fail_snapshot_closes(descriptor: int) -> None:
        close_attempts.append(descriptor)
        if descriptor == opened_descriptors[1]:
            raise OSError("injected artifact close failure")
        if descriptor == opened_descriptors[0]:
            raise OSError("injected directory close failure")
        real_close(descriptor)

    monkeypatch.setattr(freeze_preview_module.os, "open", observed_open)
    monkeypatch.setattr(freeze_preview_module, "S_ISREG", fail_opened_artifact_validation)
    monkeypatch.setattr(freeze_preview_module.os, "close", fail_snapshot_closes)

    try:
        with pytest.raises(
            ValueError,
            match="approved review artifact changed before read",
        ) as caught:
            freeze_preview_module._read_approved_review_snapshot(review_manifest.parent)

        assert len(opened_descriptors) == 2
        assert close_attempts == list(reversed(opened_descriptors))
        notes = getattr(caught.value, "__notes__", ())
        assert any("injected artifact close failure" in note for note in notes)
        assert any("injected directory close failure" in note for note in notes)
    finally:
        for descriptor in opened_descriptors:
            with suppress(OSError):
                real_close(descriptor)


def test_freeze_publishes_the_complete_boundary_with_one_no_replace_rename(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    review_manifest = _write_current_rights_review_directory(tmp_path / "preview" / "approved")
    approval = _write_approval(review_manifest)
    output_root = tmp_path / "preview" / "v1"
    real_rename = freeze_preview_module._atomic_rename_directory_noreplace_at
    real_load_source_lock = freeze_preview_module.load_preview_source_lock_snapshot
    observations: list[tuple[str, str]] = []
    source_lock_loads = 0

    def observed_rename(parent_descriptor: int, prepared: str, visible: str) -> None:
        observations.append((prepared, visible))
        real_rename(parent_descriptor, prepared, visible)

    def observed_load_source_lock(path: Path) -> object:
        nonlocal source_lock_loads
        source_lock_loads += 1
        return real_load_source_lock(path)

    monkeypatch.setattr(
        freeze_preview_module,
        "_atomic_rename_directory_noreplace_at",
        observed_rename,
    )
    monkeypatch.setattr(
        freeze_preview_module,
        "load_preview_source_lock_snapshot",
        observed_load_source_lock,
    )
    assert (
        freeze_preview_main(
            [
                "--check-approved",
                "--approval",
                str(approval),
                "--review-manifest",
                str(review_manifest),
                "--output-root",
                str(output_root),
            ]
        )
        == 0
    )
    assert len(observations) == 1
    assert source_lock_loads == 1
    assert observations[0][0].startswith(".preview-freeze-")
    assert observations[0][1] == "v1"


def test_freeze_preserves_publication_on_parent_fsync_failure(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    review_manifest = _write_current_rights_review_directory(tmp_path / "preview" / "approved")
    approval = _write_approval(review_manifest)
    output_root = tmp_path / "preview" / "v1"
    real_fsync = freeze_preview_module.os.fsync
    parent_identity = (
        output_root.parent.stat().st_dev,
        output_root.parent.stat().st_ino,
    )
    failed = False

    def fail_first_post_rename_parent_fsync(descriptor: int) -> None:
        nonlocal failed
        metadata = freeze_preview_module.os.fstat(descriptor)
        if (
            not failed
            and os.path.lexists(output_root)
            and (metadata.st_dev, metadata.st_ino) == parent_identity
        ):
            failed = True
            raise OSError("injected post-rename parent fsync failure")
        real_fsync(descriptor)

    monkeypatch.setattr(
        freeze_preview_module.os,
        "fsync",
        fail_first_post_rename_parent_fsync,
    )
    args = [
        "--check-approved",
        "--approval",
        str(approval),
        "--review-manifest",
        str(review_manifest),
        "--output-root",
        str(output_root),
    ]

    assert freeze_preview_main(args) == 1
    assert failed
    assert output_root.is_dir() and not output_root.is_symlink()
    assert not list(output_root.parent.glob(".preview-freeze-*"))

    assert freeze_preview_main(args) == 1
    assert output_root.is_dir() and not output_root.is_symlink()


def test_freeze_uncertain_publication_preserves_racing_staging_name(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    review_manifest = _write_current_rights_review_directory(tmp_path / "preview" / "approved")
    approval = _write_approval(review_manifest)
    output_root = tmp_path / "preview" / "v1"
    real_rename = freeze_preview_module._atomic_rename_directory_noreplace_at
    real_fsync = freeze_preview_module.os.fsync
    staging_name: str | None = None

    def observed_rename(parent_descriptor: int, source_name: str, destination_name: str) -> None:
        nonlocal staging_name
        real_rename(parent_descriptor, source_name, destination_name)
        staging_name = source_name

    def occupy_staging_before_failure(descriptor: int) -> None:
        if staging_name is not None and output_root.exists():
            racing_staging = output_root.parent / staging_name
            racing_staging.mkdir()
            (racing_staging / "winner.txt").write_text("preserve me", encoding="utf-8")
            raise OSError("injected parent fsync failure")
        real_fsync(descriptor)

    monkeypatch.setattr(
        freeze_preview_module,
        "_atomic_rename_directory_noreplace_at",
        observed_rename,
    )
    monkeypatch.setattr(freeze_preview_module.os, "fsync", occupy_staging_before_failure)

    assert (
        freeze_preview_main(
            [
                "--check-approved",
                "--approval",
                str(approval),
                "--review-manifest",
                str(review_manifest),
                "--output-root",
                str(output_root),
            ]
        )
        == 1
    )
    assert staging_name is not None
    assert (output_root.parent / staging_name / "winner.txt").read_text(
        encoding="utf-8"
    ) == "preserve me"
    assert output_root.is_dir() and not output_root.is_symlink()


def test_freeze_fails_closed_on_approval_or_review_identity_mismatch(tmp_path: Path) -> None:
    review_manifest = _write_current_rights_review_directory(tmp_path / "preview" / "approved")
    approval = _write_approval(review_manifest, manifest_sha="0" * 64)
    output_root = tmp_path / "preview" / "v1"

    assert (
        freeze_preview_main(
            [
                "--check-approved",
                "--approval",
                str(approval),
                "--review-manifest",
                str(review_manifest),
                "--output-root",
                str(output_root),
            ]
        )
        == 1
    )
    assert not (output_root / "raw").exists()
    assert not (output_root / "manifest.json").exists()

    payload = json.loads(review_manifest.read_text(encoding="utf-8"))
    payload["candidate_names"][0] = "다른 장소"
    review_manifest.write_bytes(_canonical(payload))
    assert check_review_manifest(review_manifest).exit_code == CHECK_MALFORMED


@pytest.mark.parametrize(
    ("field", "replacement"),
    [
        ("approval_signal", "not-approved"),
        ("canonical_candidate_review_sha256", "0" * 64),
        ("canonical_candidate_review_markdown_sha256", "0" * 64),
        ("canonical_source_lock_sha256", "0" * 64),
        ("rights_acknowledgement_version", "official-public-data-contest-v1"),
    ],
)
def test_freeze_rejects_unbound_approval_claims(
    tmp_path: Path,
    field: str,
    replacement: str,
) -> None:
    review_manifest = _write_current_rights_review_directory(tmp_path / "preview" / "approved")
    approval = _write_approval(review_manifest)
    lines = approval.read_text(encoding="utf-8").splitlines()
    index = next(index for index, line in enumerate(lines) if line.startswith(f"{field}:"))
    lines[index] = f"{field}: {replacement}"
    approval.write_text("\n".join(lines) + "\n", encoding="utf-8")
    output_root = tmp_path / "preview" / "v1"

    assert (
        freeze_preview_main(
            [
                "--check-approved",
                "--approval",
                str(approval),
                "--review-manifest",
                str(review_manifest),
                "--output-root",
                str(output_root),
            ]
        )
        == 1
    )
    assert not output_root.exists()


def test_freeze_rejects_reordered_approved_identities(tmp_path: Path) -> None:
    review_manifest = _write_current_rights_review_directory(tmp_path / "preview" / "approved")
    approval = _write_approval(review_manifest)
    lines = approval.read_text(encoding="utf-8").splitlines()
    index = next(
        index
        for index, line in enumerate(lines)
        if line.startswith("approved_candidate_identities:")
    )
    prefix, encoded = lines[index].split(":", maxsplit=1)
    identities = json.loads(encoded)
    identities[0], identities[1] = identities[1], identities[0]
    lines[index] = (
        prefix
        + ": "
        + json.dumps(
            identities,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        )
    )
    approval.write_text("\n".join(lines) + "\n", encoding="utf-8")
    output_root = tmp_path / "preview" / "v1"

    assert (
        freeze_preview_main(
            [
                "--check-approved",
                "--approval",
                str(approval),
                "--review-manifest",
                str(review_manifest),
                "--output-root",
                str(output_root),
            ]
        )
        == 1
    )
    assert not output_root.exists()


def test_freeze_preserves_a_racing_publication(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    review_manifest = _write_current_rights_review_directory(tmp_path / "preview" / "approved")
    approval = _write_approval(review_manifest)
    output_root = tmp_path / "preview" / "v1"
    real_rename = freeze_preview_module._atomic_rename_directory_noreplace_at

    def racing_rename(parent_descriptor: int, prepared: str, visible: str) -> None:
        os.mkdir(visible, dir_fd=parent_descriptor)
        winner_descriptor = os.open(
            f"{visible}/winner.txt",
            os.O_WRONLY | os.O_CREAT | os.O_EXCL,
            0o600,
            dir_fd=parent_descriptor,
        )
        try:
            os.write(winner_descriptor, b"concurrent winner")
        finally:
            os.close(winner_descriptor)
        real_rename(parent_descriptor, prepared, visible)

    monkeypatch.setattr(
        freeze_preview_module,
        "_atomic_rename_directory_noreplace_at",
        racing_rename,
    )
    assert (
        freeze_preview_main(
            [
                "--check-approved",
                "--approval",
                str(approval),
                "--review-manifest",
                str(review_manifest),
                "--output-root",
                str(output_root),
            ]
        )
        == 1
    )
    winner = output_root / "winner.txt"
    assert winner.read_text(encoding="utf-8") == "concurrent winner"
    assert {path.name for path in output_root.iterdir()} == {"winner.txt"}


def test_freeze_rejects_pre_rename_prepared_replacement(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    review_manifest = _write_current_rights_review_directory(tmp_path / "preview" / "approved")
    approval = _write_approval(review_manifest)
    output_root = tmp_path / "preview" / "v1"
    displaced = output_root.parent / "validated-frozen-boundary"
    real_rename = freeze_preview_module._atomic_rename_directory_noreplace_at

    def replace_prepared_before_rename(
        parent_descriptor: int,
        prepared: str,
        visible: str,
    ) -> None:
        os.rename(
            prepared,
            displaced.name,
            src_dir_fd=parent_descriptor,
            dst_dir_fd=parent_descriptor,
        )
        os.mkdir(prepared, dir_fd=parent_descriptor)
        winner_descriptor = os.open(
            f"{prepared}/winner.txt",
            os.O_WRONLY | os.O_CREAT | os.O_EXCL,
            0o600,
            dir_fd=parent_descriptor,
        )
        try:
            os.write(winner_descriptor, b"unvalidated replacement")
        finally:
            os.close(winner_descriptor)
        real_rename(parent_descriptor, prepared, visible)

    monkeypatch.setattr(
        freeze_preview_module,
        "_atomic_rename_directory_noreplace_at",
        replace_prepared_before_rename,
    )

    assert (
        freeze_preview_main(
            [
                "--check-approved",
                "--approval",
                str(approval),
                "--review-manifest",
                str(review_manifest),
                "--output-root",
                str(output_root),
            ]
        )
        == 1
    )
    assert (output_root / "winner.txt").read_text(encoding="utf-8") == ("unvalidated replacement")
    freeze_preview_module.validate_frozen_preview_boundary(
        displaced / "stage-manifest.json",
        source_lock_path=(
            review_manifest.parents[2] / "source-locks" / "preview-v1-source-lock.json"
        ),
    )


def test_stage_validation_rejects_byte_hash_or_stage_tampering(tmp_path: Path) -> None:
    review_manifest = _write_current_rights_review_directory(tmp_path / "preview" / "approved")
    approval = _write_approval(review_manifest)
    output_root = tmp_path / "preview" / "v1"
    assert (
        freeze_preview_main(
            [
                "--check-approved",
                "--approval",
                str(approval),
                "--review-manifest",
                str(review_manifest),
                "--output-root",
                str(output_root),
            ]
        )
        == 0
    )
    stage_manifest = output_root / "stage-manifest.json"
    os.chmod(stage_manifest, 0o644)
    payload = json.loads(stage_manifest.read_text(encoding="utf-8"))
    payload["stages"][3]["input_hash"] = "0" * 64
    stage_manifest.write_bytes(_canonical(payload))

    assert pipeline_demo_main(["--check-stage-manifest", str(stage_manifest)]) == 1


def test_stage_validation_rejects_swap_after_canonical_comparison(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    review_manifest = _write_current_rights_review_directory(tmp_path / "preview" / "approved")
    approval = _write_approval(review_manifest)
    output_root = tmp_path / "preview" / "v1"
    assert (
        freeze_preview_main(
            [
                "--check-approved",
                "--approval",
                str(approval),
                "--review-manifest",
                str(review_manifest),
                "--output-root",
                str(output_root),
            ]
        )
        == 0
    )
    stage_manifest = output_root / "stage-manifest.json"
    captured_bytes = stage_manifest.read_bytes()
    replacement_payload = json.loads(captured_bytes)
    replacement_payload["unapproved_extra_field"] = True
    replacement_bytes = _canonical(replacement_payload)
    replacement = output_root / ".replacement-stage-manifest.json"
    os.chmod(output_root, 0o755)
    real_loads = freeze_preview_module.json.loads
    swapped = False

    def swap_visible_stage_after_capture(
        payload: object, *args: object, **kwargs: object
    ) -> object:
        nonlocal swapped
        parsed = real_loads(payload, *args, **kwargs)
        if not swapped and payload == captured_bytes:
            replacement.write_bytes(replacement_bytes)
            os.replace(replacement, stage_manifest)
            swapped = True
        return parsed

    monkeypatch.setattr(freeze_preview_module.json, "loads", swap_visible_stage_after_capture)

    assert pipeline_demo_main(["--check-stage-manifest", str(stage_manifest)]) == 1
    assert swapped
    assert json.loads(stage_manifest.read_bytes())["unapproved_extra_field"] is True


def test_frozen_snapshot_accepts_ctime_only_drift(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    review_manifest = _write_current_rights_review_directory(tmp_path / "preview" / "approved")
    approval = _write_approval(review_manifest)
    output_root = tmp_path / "preview" / "v1"
    assert (
        freeze_preview_main(
            [
                "--check-approved",
                "--approval",
                str(approval),
                "--review-manifest",
                str(review_manifest),
                "--output-root",
                str(output_root),
            ]
        )
        == 0
    )
    real_fstat = freeze_preview_module.os.fstat
    ctime_drift = 0

    class CtimeOnlyDrift:
        def __init__(self, metadata: os.stat_result, ctime_ns: int) -> None:
            self._metadata = metadata
            self.st_ctime_ns = ctime_ns

        def __getattr__(self, name: str) -> object:
            return getattr(self._metadata, name)

    def drifting_fstat(descriptor: int) -> CtimeOnlyDrift:
        nonlocal ctime_drift
        metadata = real_fstat(descriptor)
        ctime_drift += 1
        return CtimeOnlyDrift(metadata, metadata.st_ctime_ns + ctime_drift)

    monkeypatch.setattr(freeze_preview_module.os, "fstat", drifting_fstat)

    freeze_preview_module.validate_frozen_preview_boundary(
        output_root / "stage-manifest.json",
        source_lock_path=(
            review_manifest.parents[2] / "source-locks" / "preview-v1-source-lock.json"
        ),
    )
    assert ctime_drift > 1


def test_frozen_snapshot_rejects_same_metadata_byte_change(tmp_path: Path) -> None:
    review_manifest = _write_current_rights_review_directory(tmp_path / "preview" / "approved")
    approval = _write_approval(review_manifest)
    output_root = tmp_path / "preview" / "v1"
    assert (
        freeze_preview_main(
            [
                "--check-approved",
                "--approval",
                str(approval),
                "--review-manifest",
                str(review_manifest),
                "--output-root",
                str(output_root),
            ]
        )
        == 0
    )
    artifact = output_root / "manifest.json"
    original = artifact.read_bytes()
    metadata = artifact.stat()
    replacement = bytes([original[0] ^ 1]) + original[1:]

    with (
        pytest.raises(ValueError, match="frozen artifact changed during validation"),
        freeze_preview_module._frozen_boundary_snapshot(output_root),
    ):
        os.chmod(artifact, 0o644)
        artifact.write_bytes(replacement)
        os.chmod(artifact, metadata.st_mode & 0o7777)
        os.utime(
            artifact,
            ns=(metadata.st_atime_ns, metadata.st_mtime_ns),
        )


def test_prepared_snapshot_closes_child_when_first_fstat_fails(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    prepared = tmp_path / "prepared"
    (prepared / "child").mkdir(parents=True)
    (prepared / "child" / "artifact.json").write_text("{}", encoding="utf-8")
    real_open = freeze_preview_module.os.open
    real_fstat = freeze_preview_module.os.fstat
    opened_descriptors: list[int] = []
    root_descriptor: int | None = None
    failed = False

    def observed_open(
        path: str | bytes | os.PathLike[str],
        flags: int,
        mode: int = 0o777,
        *,
        dir_fd: int | None = None,
    ) -> int:
        nonlocal root_descriptor
        descriptor = real_open(path, flags, mode, dir_fd=dir_fd)
        opened_descriptors.append(descriptor)
        if root_descriptor is None:
            root_descriptor = descriptor
        return descriptor

    def fail_first_child_fstat(descriptor: int) -> os.stat_result:
        nonlocal failed
        metadata = real_fstat(descriptor)
        if (
            not failed
            and root_descriptor is not None
            and descriptor != root_descriptor
            and freeze_preview_module.S_ISDIR(metadata.st_mode)
        ):
            failed = True
            raise OSError("injected child fstat failure")
        return metadata

    monkeypatch.setattr(freeze_preview_module.os, "open", observed_open)
    monkeypatch.setattr(freeze_preview_module.os, "fstat", fail_first_child_fstat)

    with (
        pytest.raises(OSError, match="injected child fstat failure"),
        freeze_preview_module.prepared_directory_snapshot(prepared),
    ):
        pytest.fail("snapshot must fail before yielding")

    assert failed
    assert opened_descriptors
    for descriptor in opened_descriptors:
        with pytest.raises(OSError):
            real_fstat(descriptor)


def test_prepared_snapshot_close_failure_preserves_primary_error_and_closes_rest(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    prepared = tmp_path / "prepared"
    (prepared / "child").mkdir(parents=True)
    (prepared / "first.json").write_text("{}", encoding="utf-8")
    (prepared / "child" / "second.json").write_text("{}", encoding="utf-8")
    real_open = freeze_preview_module.os.open
    real_close = freeze_preview_module.os.close
    real_fstat = freeze_preview_module.os.fstat
    opened_descriptors: list[int] = []
    close_attempts: list[int] = []
    failed_descriptor: int | None = None

    def observed_open(
        path: str | bytes | os.PathLike[str],
        flags: int,
        mode: int = 0o777,
        *,
        dir_fd: int | None = None,
    ) -> int:
        descriptor = real_open(path, flags, mode, dir_fd=dir_fd)
        opened_descriptors.append(descriptor)
        return descriptor

    def fail_first_close(descriptor: int) -> None:
        nonlocal failed_descriptor
        close_attempts.append(descriptor)
        if failed_descriptor is None:
            failed_descriptor = descriptor
            raise OSError("injected descriptor close failure")
        real_close(descriptor)

    monkeypatch.setattr(freeze_preview_module.os, "open", observed_open)
    monkeypatch.setattr(freeze_preview_module.os, "close", fail_first_close)

    with (
        pytest.raises(RuntimeError, match="primary validation failure") as caught,
        freeze_preview_module.prepared_directory_snapshot(prepared),
    ):
        raise RuntimeError("primary validation failure")

    assert set(close_attempts) == set(opened_descriptors)
    assert failed_descriptor is not None
    assert any(
        "injected descriptor close failure" in note
        for note in getattr(caught.value, "__notes__", ())
    )
    for descriptor in opened_descriptors:
        if descriptor == failed_descriptor:
            real_fstat(descriptor)
            real_close(descriptor)
        else:
            with pytest.raises(OSError):
                real_fstat(descriptor)


@pytest.mark.parametrize(
    ("artifact_name", "target"),
    [
        ("manifest.json", "root"),
        ("manifest.json", "files"),
        ("stage-manifest.json", "root"),
        ("stage-manifest.json", "stages"),
    ],
    ids=["manifest", "manifest-descriptor", "stage-manifest", "stage-row"],
)
def test_stage_validation_rejects_unapproved_object_fields(
    tmp_path: Path,
    artifact_name: str,
    target: str,
) -> None:
    review_manifest = _write_current_rights_review_directory(tmp_path / "preview" / "approved")
    approval = _write_approval(review_manifest)
    output_root = tmp_path / "preview" / "v1"
    assert (
        freeze_preview_main(
            [
                "--check-approved",
                "--approval",
                str(approval),
                "--review-manifest",
                str(review_manifest),
                "--output-root",
                str(output_root),
            ]
        )
        == 0
    )
    artifact = output_root / artifact_name
    os.chmod(artifact, 0o644)
    payload = json.loads(artifact.read_bytes())
    if target == "root":
        payload["unapproved_extra_field"] = True
    else:
        payload[target][0]["unapproved_extra_field"] = True
    artifact.write_bytes(_canonical(payload))

    assert (
        pipeline_demo_main(["--check-stage-manifest", str(output_root / "stage-manifest.json")])
        == 1
    )


def test_validation_rejects_resigned_derived_artifact_tampering(tmp_path: Path) -> None:
    review_manifest = _write_current_rights_review_directory(tmp_path / "preview" / "approved")
    approval = _write_approval(review_manifest)
    output_root = tmp_path / "preview" / "v1"
    assert (
        freeze_preview_main(
            [
                "--check-approved",
                "--approval",
                str(approval),
                "--review-manifest",
                str(review_manifest),
                "--output-root",
                str(output_root),
            ]
        )
        == 0
    )
    sanitized_path = output_root / "sanitized" / "six-places.json"
    sanitized = json.loads(sanitized_path.read_text(encoding="utf-8"))
    sanitized["places"][3]["excluded_assets"] = []
    sanitized_path.write_bytes(_canonical(sanitized))
    sanitized_hash = _sha(sanitized_path.read_bytes())
    manifest_path = output_root / "manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest["files"][1]["sha256"] = sanitized_hash
    manifest["files"][2]["derived_from_sha256"] = sanitized_hash
    manifest_path.write_bytes(_canonical(manifest))

    assert (
        pipeline_demo_main(["--check-stage-manifest", str(output_root / "stage-manifest.json")])
        == 1
    )
