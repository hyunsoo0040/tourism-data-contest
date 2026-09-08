from __future__ import annotations

from argparse import Namespace
from datetime import UTC, datetime, timedelta
from pathlib import Path
from types import SimpleNamespace

import pytest
from pydantic import ValidationError

from itda.contracts.phase4_benchmark import (
    BenchmarkAuthorityBinding,
    HumanReviewInventoryItem,
    HumanVisibleEvidenceReviewEntry,
    HumanVisibleEvidenceReviewManifest,
    ReviewVerdict,
    bind_evaluator_authority,
)
from itda.domain.canonical import canonical_json_bytes, canonical_sha256

NOW = datetime(2026, 8, 7, 9, 0, tzinfo=UTC)
SHA = "a" * 64
DEV_CASES = ("dev-place-a", "dev-place-b")
DEV_CASE_INVENTORY_SHA256 = canonical_sha256(list(DEV_CASES))


def _authority(**updates: object) -> dict[str, object]:
    values: dict[str, object] = {
        "schema_version": "itda.phase4-benchmark-authority.v2",
        "dev_authority_sha256": "1" * 64,
        "selection_manifest_sha256": "2" * 64,
        "prediction_batch_sha256": "3" * 64,
        "prediction_freeze_receipt_sha256": "4" * 64,
        "dev_case_inventory_sha256": DEV_CASE_INVENTORY_SHA256,
        "label_case_inventory_sha256": DEV_CASE_INVENTORY_SHA256,
        "prediction_case_records_sha256": "7" * 64,
        "label_case_records_sha256": "8" * 64,
        "review_inventory_sha256": "9" * 64,
        "label_capability_sha256": "5" * 64,
        "evaluator_authority_sha256": "6" * 64,
        "prediction_frozen_at": NOW,
        "label_capability_created_at": NOW + timedelta(seconds=1),
    }
    values.update(updates)
    values["authority_binding_sha256"] = canonical_sha256(
        {
            key: value.isoformat().replace("+00:00", "Z") if isinstance(value, datetime) else value
            for key, value in values.items()
            if key != "authority_binding_sha256"
        }
    )
    return values


def test_authority_requires_freeze_before_label_and_exact_self_digest() -> None:
    authority = BenchmarkAuthorityBinding.model_validate(_authority())
    assert authority.prediction_freeze_receipt_sha256 == "4" * 64

    with pytest.raises(ValidationError, match="cannot precede prediction freeze"):
        BenchmarkAuthorityBinding.model_validate(
            _authority(label_capability_created_at=NOW - timedelta(seconds=1))
        )

    with pytest.raises(ValidationError, match="digest"):
        BenchmarkAuthorityBinding.model_validate({**_authority(), "authority_binding_sha256": SHA})


@pytest.mark.parametrize(
    "forbidden",
    [
        {"provider_credential": "secret"},
        {"raw_image": b"jpeg"},
        {"image_path": "/protected/image.jpg"},
        {"provider_request_capability": "live"},
        {"blind_membership": ["hidden"]},
        {"complement": ["hidden"]},
        {"release_authority": "activate"},
    ],
)
def test_evaluator_authority_rejects_provider_image_blind_and_release_capabilities(
    forbidden: dict[str, object],
) -> None:
    with pytest.raises(ValidationError, match="digest-only evaluator authority"):
        BenchmarkAuthorityBinding.model_validate({**_authority(), **forbidden})


def _inventory(item_id: str, *, critical: bool = False) -> HumanReviewInventoryItem:
    return HumanReviewInventoryItem.build(
        stable_observation_id=f"observation-{item_id}",
        claim_id=f"claim-{item_id}",
        evidence_ref_id=f"evidence-{item_id}",
        representative_id=f"representative-{item_id}",
        region_caption_sha256="7" * 64,
        critical=critical,
        prediction_batch_sha256="3" * 64,
        selection_manifest_sha256="2" * 64,
    )


def test_human_review_is_complete_canonical_and_raw_image_free() -> None:
    expected = (_inventory("a"), _inventory("b", critical=True))
    entries = tuple(
        HumanVisibleEvidenceReviewEntry(
            inventory_item_sha256=item.inventory_item_sha256,
            verdict=ReviewVerdict.SUPPORTED,
            notes_sha256="8" * 64,
        )
        for item in expected
    )
    review = HumanVisibleEvidenceReviewManifest.build(
        prediction_batch_sha256="3" * 64,
        provisional_report_sha256="9" * 64,
        selection_manifest_sha256="2" * 64,
        expected_inventory=expected,
        entries=entries,
        reviewer_pseudonym="reviewer-01",
        completed_at=NOW,
    )
    assert tuple(row.inventory_item_sha256 for row in review.entries) == tuple(
        sorted(row.inventory_item_sha256 for row in expected)
    )

    with pytest.raises(ValueError, match="complete expected inventory"):
        HumanVisibleEvidenceReviewManifest.build(
            prediction_batch_sha256="3" * 64,
            provisional_report_sha256="9" * 64,
            selection_manifest_sha256="2" * 64,
            expected_inventory=expected,
            entries=entries[:1],
            reviewer_pseudonym="reviewer-01",
            completed_at=NOW,
        )

    payload = review.model_dump(mode="json")
    payload["entries"][0]["raw_image"] = "base64"
    with pytest.raises(ValidationError):
        HumanVisibleEvidenceReviewManifest.model_validate(payload)


def test_review_verdict_vocabulary_is_closed() -> None:
    assert {verdict.value for verdict in ReviewVerdict} == {
        "SUPPORTED",
        "NON_VISIBLE",
        "PHANTOM_REF",
        "UNSUPPORTED",
    }


def test_upstream_selection_freeze_and_label_capability_must_join_exactly() -> None:
    selection = SimpleNamespace(batch_sha256="2" * 64)
    predictions = SimpleNamespace(
        selection_manifest_sha256="2" * 64,
        batch_sha256="3" * 64,
        frozen_at=NOW,
    )
    freeze = SimpleNamespace(
        prediction_batch_sha256="3" * 64,
        selection_manifest_sha256="2" * 64,
        frozen_at=NOW,
        receipt_sha256="4" * 64,
        dev_case_inventory=DEV_CASES,
        dev_case_inventory_sha256=DEV_CASE_INVENTORY_SHA256,
    )
    labels = SimpleNamespace(
        prediction_batch_sha256="3" * 64,
        prediction_freeze_receipt_sha256="4" * 64,
        capability_sha256="5" * 64,
        evaluator_authority_sha256="6" * 64,
        prediction_dev_case_inventory=DEV_CASES,
        prediction_dev_case_inventory_sha256=DEV_CASE_INVENTORY_SHA256,
        label_case_inventory_sha256=DEV_CASE_INVENTORY_SHA256,
        prediction_case_records_sha256="7" * 64,
        label_case_records_sha256="8" * 64,
        review_inventory_sha256="9" * 64,
        created_at=NOW + timedelta(seconds=1),
    )
    binding = bind_evaluator_authority(
        dev_authority_sha256="1" * 64,
        selection=selection,
        predictions=predictions,
        freeze_receipt=freeze,
        label_capability=labels,
    )
    assert binding.selection_manifest_sha256 == selection.batch_sha256

    with pytest.raises(ValueError, match="selection manifest"):
        bind_evaluator_authority(
            dev_authority_sha256="1" * 64,
            selection=SimpleNamespace(batch_sha256="f" * 64),
            predictions=predictions,
            freeze_receipt=freeze,
            label_capability=labels,
        )

    with pytest.raises(ValueError, match="lacks a protected DEV case inventory"):
        bind_evaluator_authority(
            dev_authority_sha256="1" * 64,
            selection=selection,
            predictions=predictions,
            freeze_receipt=SimpleNamespace(
                **{
                    **vars(freeze),
                    "dev_case_inventory": None,
                    "dev_case_inventory_sha256": None,
                }
            ),
            label_capability=labels,
        )


def test_evaluator_source_imports_no_provider_or_image_runtime() -> None:
    backend_root = Path(__file__).resolve().parents[2]
    sources = (
        backend_root / "src/itda/contracts/phase4_benchmark.py",
        backend_root / "src/itda/cli/evaluate_phase4.py",
    )
    joined = "\n".join(path.read_text(encoding="utf-8") for path in sources)
    assert "from itda.providers" not in joined
    assert "import itda.providers" not in joined
    assert "from PIL" not in joined
    assert "import PIL" not in joined
    assert "httpx" not in joined


def test_authority_cli_is_canonical_no_replace_and_mode_0600(tmp_path: Path) -> None:
    from itda.cli.evaluate_phase4 import main

    authority = BenchmarkAuthorityBinding.model_validate(_authority())
    manifest = tmp_path / "authority.json"
    report = tmp_path / "report.json"
    manifest.write_bytes(canonical_json_bytes(authority.model_dump(mode="json")))
    assert (
        main(
            [
                "--verify-authority",
                "--manifest",
                str(manifest),
                "--report",
                str(report),
            ]
        )
        == 0
    )
    assert report.stat().st_mode & 0o777 == 0o600

    with pytest.raises(SystemExit, match="rejected invalid authority"):
        main(
            [
                "--verify-authority",
                "--manifest",
                str(manifest),
                "--report",
                str(report),
            ]
        )


def test_protected_benchmark_rejects_caller_selected_bundle_path(tmp_path: Path) -> None:
    from itda.cli.evaluate_phase4 import _require_protected_authority_path

    with pytest.raises(PermissionError, match="server-held authority root"):
        _require_protected_authority_path(
            tmp_path / "fabricated-provisional-input.json",
            artifact_name="provisional-input.json",
        )


def test_phase4_demo_tracked_materialization_receipt_has_only_safe_aggregates(
    tmp_path: Path,
) -> None:
    import itda.cli.run_phase4_demo as demo
    from itda.cli.run_phase4_demo import _load_materialized_run, _materialize_from_explicit_inputs

    repository_root = demo._REPOSITORY_ROOT
    receipt_path = tmp_path / "receipt.json"
    assert (
        _materialize_from_explicit_inputs(
            Namespace(
                catalog_audit=repository_root
                / "artifacts/restricted/catalog/v2/release/final-audit/canonical-36.json",
                dev_sqlite=repository_root
                / "artifacts/restricted/catalog/v2/sqlite/releases"
                / "e45fae2e591542c1ecd8cc041ce4d2af863944f57be593ad38bfc196cf289ed0"
                / "evaluation-authority.sqlite3",
                snapshot_root=repository_root
                / "artifacts/restricted/catalog/v1/collection/snapshots",
                optional_media=repository_root
                / "artifacts/catalog/optional-media-v2/policy"
                / "573e21213f7c0d157e33c7a510b9bcdb612dd517dfc70ba506ef7281ca0e9243"
                / "projected-candidates.json",
                artifact_root=tmp_path / "private",
                receipt_output=receipt_path,
                image_root=None,
                rights_manifest=None,
                image_selection_manifest=None,
            ),
            allow_synthetic_test_inputs=True,
        )
        == 0
    )
    receipt_text = receipt_path.read_text(encoding="utf-8")
    assert str(repository_root) not in receipt_text
    assert "place:" not in receipt_text
    for prohibited in (
        "raw_body",
        "raw_image",
        "credential",
        "member_id",
        "label",
        "complement",
    ):
        assert prohibited not in receipt_text.casefold()
    assert receipt_path.stat().st_mode & 0o777 == 0o600
    with pytest.raises(ValueError, match="fixed demo input authority"):
        _load_materialized_run(
            receipt_path=receipt_path,
            artifact_root=tmp_path / "private",
        )


def test_phase4_demo_explicit_input_seam_defaults_fail_closed(tmp_path: Path) -> None:
    from itda.cli.run_phase4_demo import _materialize_from_explicit_inputs

    with pytest.raises(PermissionError, match="synthetic-test-only"):
        _materialize_from_explicit_inputs(
            Namespace(
                catalog_audit=tmp_path / "untrusted-catalog.json",
                dev_sqlite=tmp_path / "untrusted.sqlite3",
                snapshot_root=tmp_path / "untrusted-snapshots",
                optional_media=tmp_path / "untrusted-media.json",
                artifact_root=tmp_path / "private",
                receipt_output=tmp_path / "receipt.json",
                image_root=None,
                rights_manifest=None,
                image_selection_manifest=None,
            )
        )


def test_materialization_truth_is_derived_only_from_private_manifest(tmp_path: Path) -> None:
    import hashlib

    from itda.cli.run_phase4_demo import _load_materialized_run
    from itda.contracts.catalog_optional_media import ImageMediumState
    from itda.contracts.phase4_demo import (
        DemoDevPlace,
        Phase4DemoManifest,
        Phase4DemoMaterializationReceipt,
        derive_materialization_receipt,
    )

    places = tuple(
        sorted(
            (
                DemoDevPlace(
                    place_ref=f"place:{hashlib.sha256(f'place-{index}'.encode()).hexdigest()}",
                    catalog_row_sha256=f"{index + 1:064x}",
                    optional_media_row_sha256=f"{index + 101:064x}",
                    image_medium_state=ImageMediumState.MISSING,
                    selected_image_count=0,
                    odii_lineage="ODII_UNAVAILABLE",
                )
                for index in range(24)
            ),
            key=lambda row: row.place_ref,
        )
    )
    fields: dict[str, object] = {
        "schema_version": "itda.phase4-demo-manifest.v2",
        "input_sha256": {"synthetic": "a" * 64},
        "snapshot_inventory_sha256": canonical_sha256([]),
        "dev_projection_sha256": canonical_sha256(
            [place.model_dump(mode="json") for place in places]
        ),
        "selected_image_inventory_sha256": canonical_sha256([]),
        "source_inventory": [],
        "dev_places": [place.model_dump(mode="json") for place in places],
        "selected_images": [],
        "source_truth": "LOCAL_COLLECTION_AUTHORITY_PARTIAL",
        "profile_truth": "SOURCE_EVIDENCE_ONLY",
        "profile_score_truth": "NO_LOCAL_PROFILE_SCORES",
        "image_truth": "NO_IMAGE_TEXT_ODII_ONLY",
        "benchmark_truth": "NO_REAL_IMAGE_BENCHMARK",
    }
    manifest = Phase4DemoManifest.model_validate(
        {**fields, "manifest_sha256": canonical_sha256(fields)}
    )
    receipt = derive_materialization_receipt(manifest)
    hostile_fields = {
        **receipt.model_dump(mode="json", exclude={"receipt_sha256"}),
        "source_truth": "REAL_LOCAL_DATA",
    }
    hostile = Phase4DemoMaterializationReceipt.model_validate(
        {**hostile_fields, "receipt_sha256": canonical_sha256(hostile_fields)}
    )
    artifact_root = tmp_path / "private"
    run_root = artifact_root / manifest.manifest_sha256
    run_root.mkdir(parents=True)
    manifest_path = run_root / "phase4-demo-manifest.json"
    receipt_path = tmp_path / "materialization.json"
    manifest_path.write_bytes(canonical_json_bytes(manifest.model_dump(mode="json")))
    receipt_path.write_bytes(canonical_json_bytes(hostile.model_dump(mode="json")))

    with pytest.raises(ValueError, match="private manifest authority"):
        _load_materialized_run(receipt_path=receipt_path, artifact_root=artifact_root)
