from __future__ import annotations

import hashlib
import json
import os
from base64 import b64encode
from datetime import UTC, datetime
from pathlib import Path
from types import SimpleNamespace

import pytest

import itda.cli.classify_preview_rights as classify_module
from itda.cli.classify_preview_rights import derive_rights_review
from itda.cli.freeze_preview import main as freeze_preview_main
from itda.contracts.candidate_review import (
    CHECK_RESOLVED,
    CandidateReview,
    RawProviderBundle,
    RightsDispositionStatus,
    build_review_manifest,
    build_review_manifest_from_bytes,
    build_rights_review,
    canonical_json_bytes,
    check_review_manifest,
    render_candidate_review_markdown,
)
from itda.contracts.provenance import extract_upstream_rights

_IDENTITIES = (
    ("126166", "2/5"),
    ("126216", "2983/4639"),
    ("126207", "2967/4623"),
    ("128526", "2961/4617"),
    ("1492402", "2960/4616"),
    ("2658227", "1312/2357"),
)
_NAMES = ("불국사", "석굴암", "첨성대", "동궁과 월지", "대릉원 일원", "황리단길")
_SELECTED_ODII_STORIES = (
    ("불국사", "2/5", "5499/16497", "경주 불국사"),
    ("석굴암", "2983/4639", "5348/16346", "경주 석굴암 석굴"),
    ("첨성대", "2967/4623", "5288/16286", "경주 첨성대"),
    ("동궁과 월지", "2961/4617", "5278/16276", "동궁과 월지"),
    ("대릉원 일원", "2960/4616", "5272/16270", "경주 대릉원"),
    ("황리단길", "1312/2357", "2933/6824", "경주 황리단길"),
)
_FIXTURE_ROOT = Path(__file__).resolve().parents[3] / "fixtures/preview/v1"
_HISTORY_FIXTURE_ROOT = _FIXTURE_ROOT.parent / "review-history/preview-v1"
_COMMITTED_SOURCE_LOCK = _FIXTURE_ROOT.parent / "source-locks/preview-v1-source-lock.json"


def test_classification_source_read_fails_closed_before_open_without_fd_listdir(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    real_os = classify_module.os
    opened = False

    def unexpected_open(*args: object, **kwargs: object) -> int:
        nonlocal opened
        opened = True
        raise AssertionError("source directory must not be opened without secure capabilities")

    unsupported_os = SimpleNamespace(
        O_RDONLY=real_os.O_RDONLY,
        O_DIRECTORY=real_os.O_DIRECTORY,
        O_NOFOLLOW=real_os.O_NOFOLLOW,
        open=unexpected_open,
        stat=real_os.stat,
        listdir=real_os.listdir,
        supports_dir_fd=frozenset({unexpected_open, real_os.stat}),
        supports_follow_symlinks=frozenset({real_os.stat}),
        supports_fd=frozenset(),
    )
    monkeypatch.setattr(classify_module, "os", unsupported_os)

    with pytest.raises(ValueError, match=r"os\.listdir\(fd\)"):
        classify_module._read_source_snapshot(tmp_path / "review-manifest.json")

    assert not opened


def _raw_row(
    *,
    place_id: str,
    provider: str,
    endpoint: str,
    source_id: str,
    payload: object,
) -> dict[str, object]:
    body = canonical_json_bytes(payload)
    return {
        "candidate_place_id": place_id,
        "provider": provider,
        "endpoint": endpoint,
        "request_scope": {"fixture": place_id},
        "source_id": source_id,
        "retrieved_at": datetime(2026, 7, 23, tzinfo=UTC),
        "http_status": 200,
        "raw_response_sha256": hashlib.sha256(body).hexdigest(),
        "raw_body_base64": b64encode(body).decode("ascii"),
        "modifiedtime": None,
        "rights": list(extract_upstream_rights(payload)),
        "asset_usage_status": "BLOCKED_PENDING_PHASE2_RIGHTS_REVIEW",
    }


def _source_review(
    *,
    odii_rights: bool = False,
    unselected_odii_rights: bool = False,
    same_pair_other_story_rights: bool = False,
) -> tuple[CandidateReview, RawProviderBundle]:
    rows: list[dict[str, object]] = []
    candidates: list[dict[str, object]] = []
    for index, (name, identity) in enumerate(zip(_NAMES, _IDENTITIES, strict=True), start=1):
        content_id, odii_id = identity
        tid, tlid = odii_id.split("/")
        place_id = f"preview:{index}"
        common_payload = {
            "response": {
                "body": {
                    "items": {
                        "item": [
                            {
                                "contentid": content_id,
                                "firstimage": f"https://example.test/{content_id}/representative.jpg",
                                "cpyrhtDivCd": "Type3" if index == 4 else "Type1",
                            }
                        ]
                    }
                }
            }
        }
        story_items = [
            {
                "tid": tid,
                "tlid": tlid,
                "stid": f"story-{index}",
                "stlid": f"story-location-{index}",
                "title": name,
                "mapX": str(129.0 + index / 100),
                "mapY": str(35.0 + index / 100),
                **({"rights": "unexpected"} if odii_rights else {}),
            }
        ]
        if same_pair_other_story_rights:
            story_items.append(
                {
                    "tid": tid,
                    "tlid": tlid,
                    "stid": f"other-story-{index}",
                    "stlid": f"other-story-location-{index}",
                    "title": f"선택되지 않은 이야기 {index}",
                    "mapX": str(129.0 + index / 100 + 0.005),
                    "mapY": str(35.0 + index / 100 + 0.005),
                    "rights": "unselected-sibling-only",
                }
            )
        story_payload = {"response": {"body": {"items": {"item": story_items}}}}
        theme_items = [
            {
                "tid": tid,
                "tlid": tlid,
                "title": name,
                "mapX": str(129.0 + index / 100),
                "mapY": str(35.0 + index / 100),
            }
        ]
        if unselected_odii_rights:
            theme_items.append(
                {
                    "tid": f"unselected-{tid}",
                    "tlid": f"unselected-{tlid}",
                    "rights": "unselected-only",
                }
            )
        common_row = _raw_row(
            place_id=place_id,
            provider="TOUR_API",
            endpoint="KorService2/detailCommon2",
            source_id=content_id,
            payload=common_payload,
        )
        story_row = _raw_row(
            place_id=place_id,
            provider="ODII",
            endpoint="Odii/storyBasedList",
            source_id=odii_id,
            payload=story_payload,
        )
        rows.extend(
            (
                _raw_row(
                    place_id=place_id,
                    provider="TOUR_API",
                    endpoint="KorService2/searchKeyword2",
                    source_id=content_id,
                    payload={
                        "items": [
                            {"contentid": content_id, "cpyrhtDivCd": "Type1"},
                            {"contentid": "unrelated", "cpyrhtDivCd": "Type3"},
                        ]
                    },
                ),
                _raw_row(
                    place_id=place_id,
                    provider="ODII",
                    endpoint="Odii/themeSearchList",
                    source_id=odii_id,
                    payload={"items": {"item": theme_items}},
                ),
                common_row,
                _raw_row(
                    place_id=place_id,
                    provider="TOUR_API",
                    endpoint="KorService2/detailImage2",
                    source_id=content_id,
                    payload={
                        "response": {
                            "body": {
                                "items": {
                                    "item": [
                                        {
                                            "serialnum": f"{content_id}-detail",
                                            "originimgurl": (
                                                f"https://example.test/{content_id}/detail.jpg"
                                            ),
                                            "cpyrhtDivCd": "Type1",
                                        }
                                    ]
                                }
                            }
                        }
                    },
                ),
                story_row,
            )
        )
        candidates.append(
            {
                "place_id": place_id,
                "name_ko": name,
                "address_ko": "경상북도 경주시",
                "longitude": 129.0 + index / 100,
                "latitude": 35.0 + index / 100,
                "split": "PREVIEW",
                "assessment_status": "NOT_SCORED",
                "resolution_status": "RESOLVED",
                "evidence": [
                    {
                        "provider": "TOUR_API",
                        "source_id": content_id,
                        "endpoint": common_row["endpoint"],
                        "request_scope": common_row["request_scope"],
                        "retrieved_at": common_row["retrieved_at"],
                        "http_status": 200,
                        "raw_response_sha256": common_row["raw_response_sha256"],
                        "modifiedtime": None,
                        "upstream_rights": common_row["rights"],
                        "asset_usage_status": "BLOCKED_PENDING_PHASE2_RIGHTS_REVIEW",
                    },
                    {
                        "provider": "ODII",
                        "source_id": odii_id,
                        "endpoint": story_row["endpoint"],
                        "request_scope": story_row["request_scope"],
                        "retrieved_at": story_row["retrieved_at"],
                        "http_status": 200,
                        "raw_response_sha256": story_row["raw_response_sha256"],
                        "modifiedtime": None,
                        "upstream_rights": [],
                        "asset_usage_status": "BLOCKED_PENDING_PHASE2_RIGHTS_REVIEW",
                    },
                ],
            }
        )
    bundle = RawProviderBundle.model_validate(
        {"schema_version": "provider-bundle-v1", "redacted": True, "rows": rows}
    )
    bundle_bytes = canonical_json_bytes(bundle.model_dump(mode="json"))
    review = CandidateReview.model_validate(
        {
            "schema_version": "candidate-review-v1",
            "artifact_status": "REVIEW_ONLY",
            "bundle_path": "raw-provider-bundle.redacted.json",
            "redacted_bundle_sha256": hashlib.sha256(bundle_bytes).hexdigest(),
            "candidates": candidates,
        }
    )
    return review, bundle


def test_rights_review_uses_selected_assets_and_scoped_dataset_grants() -> None:
    source, bundle = _source_review()

    reviewed = build_rights_review(
        source,
        bundle,
        source_review_manifest_sha256="0" * 64,
    )

    assert reviewed.schema_version == "candidate-review-v2"
    assert reviewed.rights_review is not None
    assert {row.odii_content.license_code for row in reviewed.rights_review.candidates} == {"Type0"}
    assert all(
        row.odii_content.attribution_required is False for row in reviewed.rights_review.candidates
    )
    assert all(len(row.detail_images) == 1 for row in reviewed.rights_review.candidates)
    assert reviewed.rights_review.candidates[0].representative_image.cpyrht_div_cd == "Type1"
    donggung = reviewed.rights_review.candidates[3].representative_image
    assert donggung.cpyrht_div_cd == "Type3"
    assert donggung.status is RightsDispositionStatus.ORIGINAL_DISPLAY_ONLY
    assert donggung.transform_allowed is False
    assert donggung.model_input_allowed is False
    assert donggung.normalized_asset_allowed is False


def test_rights_review_refuses_dataset_inheritance_when_odii_row_has_rights() -> None:
    source, bundle = _source_review(odii_rights=True)

    with pytest.raises(ValueError, match="Odii dataset inheritance"):
        build_rights_review(
            source,
            bundle,
            source_review_manifest_sha256="0" * 64,
        )


def test_rights_review_ignores_rights_on_unselected_odii_alternative() -> None:
    source, bundle = _source_review(unselected_odii_rights=True)

    reviewed = build_rights_review(
        source,
        bundle,
        source_review_manifest_sha256="0" * 64,
    )

    assert reviewed.rights_review is not None
    assert {row.odii_content.license_code for row in reviewed.rights_review.candidates} == {"Type0"}


def test_rights_review_ignores_rights_on_same_pair_unselected_story() -> None:
    source, bundle = _source_review(same_pair_other_story_rights=True)

    reviewed = build_rights_review(
        source,
        bundle,
        source_review_manifest_sha256="0" * 64,
    )

    assert reviewed.rights_review is not None
    assert {row.odii_content.license_code for row in reviewed.rights_review.candidates} == {"Type0"}


def _write_source_review(root: Path) -> Path:
    root.mkdir(parents=True)
    source, bundle = _source_review()
    bundle_bytes = canonical_json_bytes(bundle.model_dump(mode="json"))
    (root / "raw-provider-bundle.redacted.json").write_bytes(bundle_bytes)
    source = source.model_copy(
        update={"redacted_bundle_sha256": hashlib.sha256(bundle_bytes).hexdigest()}
    )
    (root / "candidate-review.json").write_bytes(
        canonical_json_bytes(source.model_dump(mode="json", exclude={"rights_review"}))
    )
    (root / "candidate-review.md").write_bytes(render_candidate_review_markdown(source, bundle))
    manifest_path = root / "review-manifest.json"
    manifest_path.write_bytes(build_review_manifest(root))
    return manifest_path


def _write_source_lock(source_manifest: Path) -> Path:
    source_root = source_manifest.parent
    lock_path = source_root.parent / "source-locks/preview-v1-source-lock.json"
    lock_path.parent.mkdir(parents=True, exist_ok=True)
    lock_path.write_bytes(
        canonical_json_bytes(
            {
                "schema_version": "preview-source-lock-v1",
                "data_version": "preview-v1",
                "source_candidate_review_path": "candidate-review.json",
                "source_candidate_review_sha256": hashlib.sha256(
                    (source_root / "candidate-review.json").read_bytes()
                ).hexdigest(),
                "source_candidate_review_markdown_path": "candidate-review.md",
                "source_candidate_review_markdown_sha256": hashlib.sha256(
                    (source_root / "candidate-review.md").read_bytes()
                ).hexdigest(),
                "source_redacted_provider_bundle_path": ("raw-provider-bundle.redacted.json"),
                "source_redacted_provider_bundle_sha256": hashlib.sha256(
                    (source_root / "raw-provider-bundle.redacted.json").read_bytes()
                ).hexdigest(),
                "source_review_manifest_path": "review-manifest.json",
                "source_review_manifest_sha256": hashlib.sha256(
                    source_manifest.read_bytes()
                ).hexdigest(),
                "source_candidate_schema_version": "candidate-review-v1",
                "source_manifest_schema_version": "review-manifest-v1",
            }
        )
    )
    return lock_path


def _write_approval(review_manifest: Path, *, source_lock: Path) -> Path:
    approval = review_manifest.parent / "APPROVAL.md"
    bundle = review_manifest.parent / "raw-provider-bundle.redacted.json"
    candidate_path = review_manifest.parent / "candidate-review.json"
    candidate = json.loads(candidate_path.read_text(encoding="utf-8"))
    markdown_path = review_manifest.parent / "candidate-review.md"
    rights_review = candidate.get("rights_review")
    identities = (
        [
            {
                "name_ko": candidate_row["name_ko"],
                "place_id": candidate_row["place_id"],
                "selected_odii_story": rights_row["selected_odii_story"],
                "tour_source_id": candidate_row["evidence"][0]["source_id"],
            }
            for candidate_row, rights_row in zip(
                candidate["candidates"],
                rights_review["candidates"],
                strict=True,
            )
        ]
        if isinstance(rights_review, dict)
        else []
    )
    approval.write_text(
        "\n".join(
            (
                "# Synthetic approval for freeze integration test",
                "schema_version: preview-freeze-approval-v1",
                "approval_signal: approved-six-preview",
                "status: APPROVED",
                "canonical_candidate_review_sha256: "
                f"{hashlib.sha256(candidate_path.read_bytes()).hexdigest()}",
                "canonical_candidate_review_markdown_sha256: "
                f"{hashlib.sha256(markdown_path.read_bytes()).hexdigest()}",
                "canonical_source_lock_sha256: "
                f"{hashlib.sha256(source_lock.read_bytes()).hexdigest()}",
                "approved_redacted_provider_bundle_sha256: "
                f"{hashlib.sha256(bundle.read_bytes()).hexdigest()}",
                "approved_review_manifest_sha256: "
                f"{hashlib.sha256(review_manifest.read_bytes()).hexdigest()}",
                "approved_candidate_identities: "
                + json.dumps(
                    identities,
                    ensure_ascii=False,
                    sort_keys=True,
                    separators=(",", ":"),
                ),
                "rights_acknowledgement_version: official-public-data-contest-v2",
                "reviewer: synthetic-test",
                "approved_at: 2026-07-24T00:00:00Z",
                "",
            )
        ),
        encoding="utf-8",
    )
    return approval


def test_rights_review_publication_is_atomic_retryable_and_no_replace(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    source_manifest = _write_source_review(tmp_path / "source")
    output = tmp_path / "review-rights-v2"
    real_manifest_builder = classify_module.build_review_manifest_from_bytes

    def fail_after_three_artifacts(*args: object, **kwargs: object) -> bytes:
        raise OSError("injected manifest write failure")

    monkeypatch.setattr(
        classify_module,
        "build_review_manifest_from_bytes",
        fail_after_three_artifacts,
    )
    with pytest.raises(OSError, match="injected manifest write failure"):
        derive_rights_review(
            source_manifest=source_manifest,
            source_lock_path=_write_source_lock(source_manifest),
            output=output,
        )
    assert not output.exists()
    assert not list(tmp_path.glob(".review-rights-v2.*"))

    monkeypatch.setattr(
        classify_module,
        "build_review_manifest_from_bytes",
        real_manifest_builder,
    )
    real_rename = classify_module._rename_directory_noreplace

    def fail_after_verification(source: Path, target: Path) -> None:
        assert (source / "review-manifest.json").is_file()
        raise OSError("injected publication failure")

    monkeypatch.setattr(classify_module, "_rename_directory_noreplace", fail_after_verification)
    with pytest.raises(OSError, match="injected publication failure"):
        derive_rights_review(
            source_manifest=source_manifest,
            source_lock_path=_write_source_lock(source_manifest),
            output=output,
        )
    assert not output.exists()
    assert not list(tmp_path.glob(".review-rights-v2.*"))

    race_output = tmp_path / "review-rights-race"

    def publish_concurrent_winner(source: Path, target: Path) -> None:
        target.mkdir()
        (target / "winner").write_text("preserve me", encoding="utf-8")
        real_rename(source, target)

    monkeypatch.setattr(
        classify_module,
        "_rename_directory_noreplace",
        publish_concurrent_winner,
    )
    with pytest.raises(OSError):
        derive_rights_review(
            source_manifest=source_manifest,
            source_lock_path=_write_source_lock(source_manifest),
            output=race_output,
        )
    assert (race_output / "winner").read_text(encoding="utf-8") == "preserve me"
    assert not list(tmp_path.glob(".review-rights-race.*"))

    monkeypatch.setattr(classify_module, "_rename_directory_noreplace", real_rename)
    derive_rights_review(
        source_manifest=source_manifest,
        source_lock_path=_write_source_lock(source_manifest),
        output=output,
    )
    assert {path.name for path in output.iterdir()} == {
        "raw-provider-bundle.redacted.json",
        "candidate-review.json",
        "candidate-review.md",
        "review-manifest.json",
    }
    frozen = {path.name: path.read_bytes() for path in output.iterdir()}
    with pytest.raises(FileExistsError):
        derive_rights_review(
            source_manifest=source_manifest,
            source_lock_path=_write_source_lock(source_manifest),
            output=output,
        )
    assert frozen == {path.name: path.read_bytes() for path in output.iterdir()}


def test_rights_review_preserves_publication_on_parent_fsync_failure(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    source_manifest = _write_source_review(tmp_path / "source")
    source_lock = _write_source_lock(source_manifest)
    output = tmp_path / "review-rights-v2"
    real_fsync = classify_module.os.fsync
    parent_identity = (output.parent.stat().st_dev, output.parent.stat().st_ino)
    failed = False

    def fail_first_post_rename_parent_fsync(descriptor: int) -> None:
        nonlocal failed
        metadata = classify_module.os.fstat(descriptor)
        if (
            not failed
            and os.path.lexists(output)
            and (metadata.st_dev, metadata.st_ino) == parent_identity
        ):
            failed = True
            raise OSError("injected post-rename parent fsync failure")
        real_fsync(descriptor)

    monkeypatch.setattr(
        classify_module.os,
        "fsync",
        fail_first_post_rename_parent_fsync,
    )

    with pytest.raises(OSError, match="publication state is uncertain"):
        derive_rights_review(
            source_manifest=source_manifest,
            source_lock_path=source_lock,
            output=output,
        )
    assert failed
    assert output.is_dir() and not output.is_symlink()
    assert not list(tmp_path.glob(".review-rights-v2.*"))

    assert (
        check_review_manifest(
            output / "review-manifest.json",
            source_lock_path=source_lock,
        ).exit_code
        == CHECK_RESOLVED
    )


def test_rights_review_uncertain_publication_preserves_racing_staging_name(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    source_manifest = _write_source_review(tmp_path / "source")
    source_lock = _write_source_lock(source_manifest)
    output = tmp_path / "review-rights-v2"
    real_rename = classify_module._rename_directory_noreplace
    real_fsync = classify_module.os.fsync
    prepared: Path | None = None

    def observed_rename(source: Path, target: Path) -> None:
        nonlocal prepared
        real_rename(source, target)
        prepared = source

    def occupy_staging_before_failure(descriptor: int) -> None:
        if prepared is not None and output.exists():
            prepared.mkdir()
            (prepared / "winner.txt").write_text("preserve me", encoding="utf-8")
            raise OSError("injected parent fsync failure")
        real_fsync(descriptor)

    monkeypatch.setattr(classify_module, "_rename_directory_noreplace", observed_rename)
    monkeypatch.setattr(classify_module.os, "fsync", occupy_staging_before_failure)

    with pytest.raises(OSError, match="publication state is uncertain"):
        derive_rights_review(
            source_manifest=source_manifest,
            source_lock_path=source_lock,
            output=output,
        )
    assert prepared is not None
    assert (prepared / "winner.txt").read_text(encoding="utf-8") == "preserve me"
    assert (
        check_review_manifest(
            output / "review-manifest.json",
            source_lock_path=source_lock,
        ).exit_code
        == CHECK_RESOLVED
    )


def test_rights_review_rejects_pre_rename_source_replacement(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    source_manifest = _write_source_review(tmp_path / "source")
    source_lock = _write_source_lock(source_manifest)
    output = tmp_path / "review-rights-v2"
    displaced = tmp_path / "validated-rights-review"
    real_rename = classify_module._rename_directory_noreplace

    def replace_prepared_before_rename(source: Path, target: Path) -> None:
        source.rename(displaced)
        source.mkdir()
        (source / "winner.txt").write_text("unvalidated replacement", encoding="utf-8")
        real_rename(source, target)

    monkeypatch.setattr(
        classify_module,
        "_rename_directory_noreplace",
        replace_prepared_before_rename,
    )

    with pytest.raises(OSError, match="publication state is uncertain"):
        derive_rights_review(
            source_manifest=source_manifest,
            source_lock_path=source_lock,
            output=output,
        )

    assert (output / "winner.txt").read_text(encoding="utf-8") == "unvalidated replacement"
    assert (
        check_review_manifest(
            displaced / "review-manifest.json",
            source_lock_path=source_lock,
        ).exit_code
        == CHECK_RESOLVED
    )


def test_rights_review_cli_refuses_existing_output_and_cleans_failed_temp(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    source_manifest = _write_source_review(tmp_path / "source")
    output = tmp_path / "review-rights-v2"
    output.mkdir()
    assert (
        classify_module.main(
            [
                "--source-review-manifest",
                str(source_manifest),
                "--source-lock",
                str(_write_source_lock(source_manifest)),
                "--output",
                str(output),
            ]
        )
        == 1
    )

    output.rmdir()
    monkeypatch.setattr(
        classify_module,
        "_rename_directory_noreplace",
        lambda source, target: (_ for _ in ()).throw(OSError("injected")),
    )
    assert (
        classify_module.main(
            [
                "--source-review-manifest",
                str(source_manifest),
                "--source-lock",
                str(_write_source_lock(source_manifest)),
                "--output",
                str(output),
            ]
        )
        == 1
    )
    assert not output.exists()
    assert not list(tmp_path.glob(".review-rights-v2.*"))


def test_rights_review_reads_each_source_artifact_once(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    source_manifest = _write_source_review(tmp_path / "source")
    output = tmp_path / "review-rights-v2"
    counts: dict[str, int] = {}
    real_read_once = classify_module._read_regular_bytes_once

    def counted(directory_descriptor: int, name: str) -> bytes:
        counts[name] = counts.get(name, 0) + 1
        payload = real_read_once(directory_descriptor, name)
        if name == "candidate-review.md":
            (source_manifest.parent / name).write_bytes(b"mutated after snapshot")
        return payload

    monkeypatch.setattr(classify_module, "_read_regular_bytes_once", counted)
    derive_rights_review(
        source_manifest=source_manifest,
        source_lock_path=_write_source_lock(source_manifest),
        output=output,
    )

    assert set(counts.values()) == {1}
    assert (output / "candidate-review.md").read_bytes() != b"mutated after snapshot"


def test_rights_review_pins_source_directory_across_whole_directory_swap(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    source_manifest = _write_source_review(tmp_path / "source")
    replacement_manifest = _write_source_review(tmp_path / "replacement")
    replacement_root = replacement_manifest.parent
    replacement_bundle_path = replacement_root / "raw-provider-bundle.redacted.json"
    replacement_candidate_path = replacement_root / "candidate-review.json"
    replacement_bundle_payload = json.loads(replacement_bundle_path.read_text(encoding="utf-8"))
    replacement_candidate_payload = json.loads(
        replacement_candidate_path.read_text(encoding="utf-8")
    )
    replacement_time = "2026-07-24T12:00:00Z"
    for row in replacement_bundle_payload["rows"]:
        row["retrieved_at"] = replacement_time
    for candidate in replacement_candidate_payload["candidates"]:
        for evidence in candidate["evidence"]:
            evidence["retrieved_at"] = replacement_time
    replacement_bundle_path.write_bytes(canonical_json_bytes(replacement_bundle_payload))
    replacement_candidate_payload["redacted_bundle_sha256"] = hashlib.sha256(
        replacement_bundle_path.read_bytes()
    ).hexdigest()
    replacement = CandidateReview.model_validate(replacement_candidate_payload)
    replacement_candidate_path.write_bytes(
        canonical_json_bytes(replacement.model_dump(mode="json", exclude_unset=True))
    )
    replacement_bundle = RawProviderBundle.model_validate_json(replacement_bundle_path.read_bytes())
    (replacement_root / "candidate-review.md").write_bytes(
        render_candidate_review_markdown(replacement, replacement_bundle)
    )
    replacement_manifest.write_bytes(build_review_manifest(replacement_root))
    assert check_review_manifest(replacement_manifest).exit_code == CHECK_RESOLVED

    source_root = source_manifest.parent
    displaced_root = tmp_path / "displaced-source"
    real_open = classify_module._open
    swapped = False

    def swap_after_source_root_open(
        path: str | bytes | Path,
        flags: int,
        *args: object,
        **kwargs: object,
    ) -> int:
        nonlocal swapped
        descriptor = real_open(path, flags, *args, **kwargs)
        if (
            not swapped
            and Path(path) == source_root
            and flags & getattr(classify_module.os, "O_DIRECTORY", 0)
        ):
            source_root.rename(displaced_root)
            replacement_root.rename(source_root)
            swapped = True
        return descriptor

    monkeypatch.setattr(classify_module, "_open", swap_after_source_root_open)
    output = tmp_path / "review-rights-v2"
    derive_rights_review(
        source_manifest=source_manifest,
        source_lock_path=_write_source_lock(source_manifest),
        output=output,
    )

    assert swapped
    reviewed = CandidateReview.model_validate_json((output / "candidate-review.json").read_bytes())
    assert reviewed.rights_review is not None
    assert {
        row.odii_content.retrieved_at.isoformat() for row in reviewed.rights_review.candidates
    } == {"2026-07-23T00:00:00+00:00"}


def test_rights_review_rejects_child_inode_swap_between_stat_and_open(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    source_manifest = _write_source_review(tmp_path / "source")
    source_root = source_manifest.parent
    victim = source_root / "candidate-review.json"
    displaced = tmp_path / "candidate-review.displaced.json"
    replacement = tmp_path / "candidate-review.replacement.json"
    replacement.write_bytes(victim.read_bytes())
    real_open = classify_module._open
    swapped = False

    def swap_after_preopen_stat(
        path: str | bytes | Path,
        flags: int,
        *args: object,
        **kwargs: object,
    ) -> int:
        nonlocal swapped
        if not swapped and path == "candidate-review.json" and kwargs.get("dir_fd") is not None:
            victim.rename(displaced)
            replacement.rename(victim)
            swapped = True
        return real_open(path, flags, *args, **kwargs)

    descriptor = real_open(
        source_root,
        classify_module.os.O_RDONLY
        | getattr(classify_module.os, "O_DIRECTORY", 0)
        | getattr(classify_module.os, "O_NOFOLLOW", 0),
    )
    try:
        monkeypatch.setattr(classify_module, "_open", swap_after_preopen_stat)
        with pytest.raises(ValueError, match="changed between stat and open"):
            classify_module._read_regular_bytes_once(
                descriptor,
                "candidate-review.json",
            )
    finally:
        classify_module.os.close(descriptor)
    assert swapped


@pytest.mark.parametrize(
    "input_name",
    ["candidate-review.json", "raw-provider-bundle.redacted.json"],
)
def test_rights_review_rejects_symlink_inputs(tmp_path: Path, input_name: str) -> None:
    source_manifest = _write_source_review(tmp_path / "source")
    source = source_manifest.parent / input_name
    external = tmp_path / f"external-{input_name}"
    external.write_bytes(source.read_bytes())
    source.unlink()
    source.symlink_to(external)

    with pytest.raises(ValueError, match="regular non-symlink"):
        derive_rights_review(
            source_manifest=source_manifest,
            source_lock_path=_write_source_lock(source_manifest),
            output=tmp_path / "review-rights-v2",
        )


def test_rights_review_rejects_nonregular_input(tmp_path: Path) -> None:
    source_manifest = _write_source_review(tmp_path / "source")
    source_lock = _write_source_lock(source_manifest)
    candidate_path = source_manifest.parent / "candidate-review.json"
    candidate_path.unlink()
    candidate_path.mkdir()

    with pytest.raises(ValueError, match="regular non-symlink"):
        derive_rights_review(
            source_manifest=source_manifest,
            source_lock_path=source_lock,
            output=tmp_path / "review-rights-v2",
        )


def test_approved_v2_freeze_keeps_type1_and_excludes_type3_derivatives(tmp_path: Path) -> None:
    source_manifest = _write_source_review(tmp_path / "source")
    source_lock = _write_source_lock(source_manifest)
    preview_root = tmp_path / "preview" / "v1"
    review_root = tmp_path / "approved-review"
    derive_rights_review(
        source_manifest=source_manifest,
        source_lock_path=source_lock,
        output=review_root,
    )
    approval = _write_approval(
        review_root / "review-manifest.json",
        source_lock=source_lock,
    )

    assert (
        freeze_preview_main(
            [
                "--check-approved",
                "--approval",
                str(approval),
                "--review-manifest",
                str(review_root / "review-manifest.json"),
                "--source-lock",
                str(source_lock),
                "--output-root",
                str(preview_root),
            ]
        )
        == 0
    )

    sanitized = json.loads(
        (preview_root / "sanitized" / "six-places.json").read_text(encoding="utf-8")
    )
    normalized = json.loads(
        (preview_root / "normalized" / "six-places.json").read_text(encoding="utf-8")
    )
    assert all(
        {source["scope"] for source in place["allowed_sources"]}
        == {"TOUR_METADATA_TEXT", "ODII_VOICE_SCRIPT_PHOTO"}
        for place in sanitized["places"]
    )
    assert all(
        asset["cpyrht_div_cd"] == "Type1"
        for place in sanitized["places"]
        for asset in place["allowed_assets"]
    )
    excluded = [
        asset
        for place in sanitized["places"]
        for asset in place["excluded_assets"]
        if asset.get("cpyrht_div_cd") == "Type3"
    ]
    assert excluded
    assert all(
        asset["transform_allowed"] is False
        and asset["model_input_allowed"] is False
        and asset["normalized_asset_allowed"] is False
        for asset in excluded
    )
    assert all(
        all(asset_id not in place["allowed_asset_ids"] for asset_id in place["blocked_asset_ids"])
        for place in normalized["places"]
    )
    blocked_type3_url = "https://example.test/128526/representative.jpg"
    assert blocked_type3_url not in json.dumps(sanitized, ensure_ascii=False)
    assert blocked_type3_url not in json.dumps(normalized, ensure_ascii=False)


def test_freeze_rejects_legacy_v1_even_with_matching_approval(tmp_path: Path) -> None:
    preview_root = tmp_path / "preview" / "v1"
    review_root = tmp_path / "approved-review"
    manifest = _write_source_review(review_root)
    source_lock = _write_source_lock(manifest)
    approval = _write_approval(manifest, source_lock=source_lock)

    assert (
        freeze_preview_main(
            [
                "--check-approved",
                "--approval",
                str(approval),
                "--review-manifest",
                str(manifest),
                "--source-lock",
                str(source_lock),
                "--output-root",
                str(preview_root),
            ]
        )
        == 1
    )
    assert not preview_root.exists()


@pytest.mark.parametrize(
    ("schema_version", "rights_review"),
    [
        ("candidate-review-v2", None),
        ("candidate-review-v1", None),
    ],
)
def test_freeze_rejects_missing_or_invalid_rights_review(
    tmp_path: Path,
    schema_version: str,
    rights_review: object,
) -> None:
    preview_root = tmp_path / "preview" / "v1"
    review_root = tmp_path / "approved-review"
    manifest = _write_source_review(review_root)
    source_lock = _write_source_lock(manifest)
    candidate_path = review_root / "candidate-review.json"
    candidate_payload = json.loads(candidate_path.read_text(encoding="utf-8"))
    candidate_payload["schema_version"] = schema_version
    candidate_payload["rights_review"] = rights_review
    candidate_path.write_bytes(canonical_json_bytes(candidate_payload))
    manifest_payload = json.loads(manifest.read_text(encoding="utf-8"))
    manifest_payload["candidate_review_sha256"] = hashlib.sha256(
        candidate_path.read_bytes()
    ).hexdigest()
    manifest.write_bytes(canonical_json_bytes(manifest_payload))
    approval = _write_approval(manifest, source_lock=source_lock)

    assert (
        freeze_preview_main(
            [
                "--check-approved",
                "--approval",
                str(approval),
                "--review-manifest",
                str(manifest),
                "--source-lock",
                str(source_lock),
                "--output-root",
                str(preview_root),
            ]
        )
        == 1
    )
    assert not preview_root.exists()


def test_freeze_rejects_coordinated_resigned_source_manifest_hash(
    tmp_path: Path,
) -> None:
    source_manifest = _write_source_review(tmp_path / "source")
    source_lock = _write_source_lock(source_manifest)
    preview_root = tmp_path / "preview" / "v1"
    review_root = tmp_path / "approved-review"
    derive_rights_review(
        source_manifest=source_manifest,
        source_lock_path=source_lock,
        output=review_root,
    )
    candidate_path = review_root / "candidate-review.json"
    candidate_payload = json.loads(candidate_path.read_text(encoding="utf-8"))
    candidate_payload["rights_review"]["source_review_manifest_sha256"] = "f" * 64
    resigned = CandidateReview.model_validate(candidate_payload)
    candidate_bytes = canonical_json_bytes(resigned.model_dump(mode="json"))
    bundle_bytes = (review_root / "raw-provider-bundle.redacted.json").read_bytes()
    bundle = RawProviderBundle.model_validate_json(bundle_bytes)
    markdown_bytes = render_candidate_review_markdown(resigned, bundle)
    candidate_path.write_bytes(candidate_bytes)
    (review_root / "candidate-review.md").write_bytes(markdown_bytes)
    (review_root / "review-manifest.json").write_bytes(
        build_review_manifest_from_bytes(
            bundle_bytes=bundle_bytes,
            candidate_bytes=candidate_bytes,
            markdown_bytes=markdown_bytes,
        )
    )
    approval = _write_approval(
        review_root / "review-manifest.json",
        source_lock=source_lock,
    )

    assert (
        freeze_preview_main(
            [
                "--check-approved",
                "--approval",
                str(approval),
                "--review-manifest",
                str(review_root / "review-manifest.json"),
                "--source-lock",
                str(source_lock),
                "--output-root",
                str(preview_root),
            ]
        )
        == 1
    )
    assert not preview_root.exists()


def test_freeze_rejects_fully_coordinated_artifact_resign_against_external_lock(
    tmp_path: Path,
) -> None:
    source_manifest = _write_source_review(tmp_path / "source")
    source_lock = _write_source_lock(source_manifest)
    source_root = source_manifest.parent
    legacy_payload = json.loads((source_root / "candidate-review.json").read_text(encoding="utf-8"))
    bundle_payload = json.loads(
        (source_root / "raw-provider-bundle.redacted.json").read_text(encoding="utf-8")
    )
    resigned_time = "2026-07-24T12:00:00Z"
    for row in bundle_payload["rows"]:
        row["retrieved_at"] = resigned_time
    for candidate in legacy_payload["candidates"]:
        for evidence in candidate["evidence"]:
            evidence["retrieved_at"] = resigned_time
    bundle_bytes = canonical_json_bytes(bundle_payload)
    legacy_payload["redacted_bundle_sha256"] = hashlib.sha256(bundle_bytes).hexdigest()
    legacy = CandidateReview.model_validate(legacy_payload)
    bundle = RawProviderBundle.model_validate(bundle_payload)
    legacy_bytes = canonical_json_bytes(legacy.model_dump(mode="json", exclude={"rights_review"}))
    legacy_markdown = render_candidate_review_markdown(legacy, bundle)
    malicious_source_manifest = build_review_manifest_from_bytes(
        bundle_bytes=bundle_bytes,
        candidate_bytes=legacy_bytes,
        markdown_bytes=legacy_markdown,
    )
    resigned = build_rights_review(
        legacy,
        bundle,
        source_review_manifest_sha256=hashlib.sha256(malicious_source_manifest).hexdigest(),
    )
    candidate_bytes = canonical_json_bytes(resigned.model_dump(mode="json"))
    markdown_bytes = render_candidate_review_markdown(resigned, bundle)

    preview_root = tmp_path / "preview" / "v1"
    review_root = tmp_path / "approved-review"
    review_root.mkdir(parents=True)
    (review_root / "raw-provider-bundle.redacted.json").write_bytes(bundle_bytes)
    (review_root / "candidate-review.json").write_bytes(candidate_bytes)
    (review_root / "candidate-review.md").write_bytes(markdown_bytes)
    review_manifest = review_root / "review-manifest.json"
    review_manifest.write_bytes(
        build_review_manifest_from_bytes(
            bundle_bytes=bundle_bytes,
            candidate_bytes=candidate_bytes,
            markdown_bytes=markdown_bytes,
        )
    )
    approval = _write_approval(review_manifest, source_lock=source_lock)

    assert (
        freeze_preview_main(
            [
                "--check-approved",
                "--approval",
                str(approval),
                "--review-manifest",
                str(review_manifest),
                "--source-lock",
                str(source_lock),
                "--output-root",
                str(preview_root),
            ]
        )
        == 1
    )
    assert not preview_root.exists()


@pytest.mark.parametrize("lock_case", ["missing", "malformed", "wrong"])
def test_freeze_fails_closed_on_invalid_external_source_lock(
    tmp_path: Path,
    lock_case: str,
    capsys: pytest.CaptureFixture[str],
) -> None:
    source_manifest = _write_source_review(tmp_path / "source")
    source_lock = _write_source_lock(source_manifest)
    preview_root = tmp_path / "preview" / "v1"
    review_root = tmp_path / "approved-review"
    derive_rights_review(
        source_manifest=source_manifest,
        source_lock_path=source_lock,
        output=review_root,
    )
    approval = _write_approval(
        review_root / "review-manifest.json",
        source_lock=source_lock,
    )
    approval.write_text("not an approval\n", encoding="utf-8")

    if lock_case == "missing":
        source_lock.unlink()
    elif lock_case == "malformed":
        source_lock.write_text('{"schema_version":"preview-source-lock-v1"}\n')
    else:
        payload = json.loads(source_lock.read_text(encoding="utf-8"))
        payload["source_review_manifest_sha256"] = "f" * 64
        source_lock.write_bytes(canonical_json_bytes(payload))

    assert (
        freeze_preview_main(
            [
                "--check-approved",
                "--approval",
                str(approval),
                "--review-manifest",
                str(review_root / "review-manifest.json"),
                "--source-lock",
                str(source_lock),
                "--output-root",
                str(preview_root),
            ]
        )
        == 1
    )
    assert "source lock" in capsys.readouterr().err
    assert not preview_root.exists()


def test_committed_v16_is_valid_legacy_but_v18_is_current() -> None:
    legacy = check_review_manifest(
        _HISTORY_FIXTURE_ROOT / "review-rights-v16/review-manifest.json",
        source_lock_path=_COMMITTED_SOURCE_LOCK,
    )
    current = check_review_manifest(
        _HISTORY_FIXTURE_ROOT / "review-rights-v18/review-manifest.json",
        source_lock_path=_COMMITTED_SOURCE_LOCK,
    )

    assert legacy.exit_code == CHECK_RESOLVED
    assert legacy.review is not None and legacy.review.rights_review is not None
    assert legacy.review.rights_review.policy_version == "official-public-data-contest-v1"
    assert current.exit_code == CHECK_RESOLVED
    assert current.review is not None and current.review.rights_review is not None
    assert current.review.rights_review.policy_version == "official-public-data-contest-v2"
    assert all(
        candidate.selected_odii_story is not None
        for candidate in current.review.rights_review.candidates
    )


def test_current_rights_markdown_pins_selected_odii_story_for_human_review() -> None:
    review_root = _FIXTURE_ROOT / "review"
    review = CandidateReview.model_validate_json(
        (review_root / "candidate-review.json").read_bytes()
    )
    bundle = RawProviderBundle.model_validate_json(
        (review_root / "raw-provider-bundle.redacted.json").read_bytes()
    )

    markdown = render_candidate_review_markdown(review, bundle).decode("utf-8")

    assert (
        "| 장소 | Selected Odii theme (tid/tlid) | Selected Odii story (stid/stlid) | "
        "선택 story 제목 |"
    ) in markdown
    for name, theme_pair, story_pair, title in _SELECTED_ODII_STORIES:
        assert f"| {name} | {theme_pair} | {story_pair} | {title} |" in markdown
    assert (
        "Policy v2 pins each selected Odii story by tid/tlid/stid/stlid/title and "
        "its bound response SHA-256"
    ) in markdown
    assert (
        "Canonical Odii identity is the selected theme pair (tid/tlid); "
        "storyBasedList may preserve multiple subordinate story rows as evidence and "
        "does not imply one story ID."
    ) not in markdown


def test_freeze_rejects_legacy_v16_rights_policy(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    preview_root = tmp_path / "preview" / "v1"
    review_root = tmp_path / "approved-review"
    review_root.mkdir(parents=True)
    source_root = _HISTORY_FIXTURE_ROOT / "review-rights-v16"
    for name in (
        "raw-provider-bundle.redacted.json",
        "candidate-review.json",
        "candidate-review.md",
        "review-manifest.json",
    ):
        (review_root / name).write_bytes((source_root / name).read_bytes())
    approval = review_root / "APPROVAL.md"
    approval.write_text(
        "legacy policy must be rejected before approval parsing\n",
        encoding="utf-8",
    )

    assert (
        freeze_preview_main(
            [
                "--check-approved",
                "--approval",
                str(approval),
                "--review-manifest",
                str(review_root / "review-manifest.json"),
                "--source-lock",
                str(_COMMITTED_SOURCE_LOCK),
                "--output-root",
                str(preview_root),
            ]
        )
        == 1
    )
    assert "current validated candidate-review-v2" in capsys.readouterr().err
    assert not preview_root.exists()


def test_current_rights_review_rejects_resigned_sibling_story_identity(
    tmp_path: Path,
) -> None:
    review_root = tmp_path / "review"
    review_root.mkdir()
    source_root = _HISTORY_FIXTURE_ROOT / "review-rights-v18"
    for name in (
        "raw-provider-bundle.redacted.json",
        "candidate-review.json",
        "candidate-review.md",
        "review-manifest.json",
    ):
        (review_root / name).write_bytes((source_root / name).read_bytes())
    candidate_path = review_root / "candidate-review.json"
    candidate_payload = json.loads(candidate_path.read_text(encoding="utf-8"))
    selected = candidate_payload["rights_review"]["candidates"][0]["selected_odii_story"]
    selected.update(
        {
            "stid": "5500",
            "stlid": "16498",
            "title": "불국사 천왕문",
        }
    )
    resigned = CandidateReview.model_validate(candidate_payload)
    candidate_path.write_bytes(canonical_json_bytes(resigned.model_dump(mode="json")))
    manifest_payload = json.loads(
        (review_root / "review-manifest.json").read_text(encoding="utf-8")
    )
    manifest_payload["candidate_review_sha256"] = hashlib.sha256(
        candidate_path.read_bytes()
    ).hexdigest()
    (review_root / "review-manifest.json").write_bytes(canonical_json_bytes(manifest_payload))

    assert check_review_manifest(review_root / "review-manifest.json").exit_code != CHECK_RESOLVED
