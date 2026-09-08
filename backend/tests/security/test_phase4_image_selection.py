from __future__ import annotations

import hashlib
from pathlib import Path

import pytest
from pydantic import ValidationError

from itda.analysis.image.preprocessing import ImagePreprocessingPolicy
from itda.analysis.image.selection import gate_selection_assets
from itda.cli.select_dev_images import _write_no_replace
from itda.contracts.catalog_optional_media import ImageMediumState
from itda.contracts.image_selection import (
    PlaceImageSelectionCandidate,
    SelectionAssetSource,
    SelectionAuthorityScope,
    build_image_selection_policy,
)


def _selection_policy(preprocessing: ImagePreprocessingPolicy) -> object:
    return build_image_selection_policy(
        sensitivity_id="synthetic-security",
        model_weight_sha256="4" * 64,
        preprocessing_policy_sha256=preprocessing.policy_sha256,
        minimum_short_side=32,
        minimum_aspect_ratio_milli=250,
        maximum_aspect_ratio_milli=4_000,
        perceptual_hash_distance=4,
        scene_distance_milli=200,
        temporary_event_rule="EXCLUDE",
    )


@pytest.mark.parametrize(
    "relative_path",
    ("../asset.png", "/asset.png", "images\\asset.png", "images/../asset.png"),
)
def test_unbounded_and_platform_ambiguous_paths_are_rejected(relative_path: str) -> None:
    payload_sha256 = hashlib.sha256(b"synthetic").hexdigest()
    with pytest.raises(ValidationError, match="safe normalized relative path"):
        SelectionAssetSource(
            source_asset_id="asset",
            relative_path=relative_path,
            rights_leaf_id="leaf",
            rights_leaf_sha256="1" * 64,
            content_sha256=payload_sha256,
            materialization_sha256="2" * 64,
            temporary_event=False,
        )


def test_materialization_substitution_and_split_authority_fields_fail_closed() -> None:
    with pytest.raises(ValidationError):
        SelectionAssetSource(
            source_asset_id="asset",
            relative_path="asset.png",
            rights_leaf_id="leaf",
            rights_leaf_sha256="1" * 64,
            content_sha256="2" * 64,
            materialization_sha256="3" * 64,
            temporary_event=False,
        )

    payload = {
        "place_entity_id": f"place:{'a' * 64}",
        "authority_scope": "SYNTHETIC_LOCAL",
        "input_authority_sha256": "b" * 64,
        "media_state": "MISSING",
        "assets": [],
        "blind_membership": True,
    }
    with pytest.raises(ValidationError):
        PlaceImageSelectionCandidate.model_validate(payload)


def test_terminal_rights_state_does_not_touch_filesystem_or_retain_raw_bytes(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    preprocessing = ImagePreprocessingPolicy()
    policy = _selection_policy(preprocessing)

    def forbidden_preprocess(**_: object) -> object:
        raise AssertionError("rights failure must terminate before image work")

    monkeypatch.setattr(
        "itda.analysis.image.selection.preprocess_image",
        forbidden_preprocess,
    )
    candidate = PlaceImageSelectionCandidate(
        place_entity_id=f"place:{'c' * 64}",
        authority_scope=SelectionAuthorityScope.SYNTHETIC_LOCAL,
        input_authority_sha256="d" * 64,
        media_state=ImageMediumState.RIGHTS_RESTRICTED,
        assets=(),
    )
    result = gate_selection_assets(
        root_fd=-1,
        candidate=candidate,
        policy=policy,
        preprocessing_policy=preprocessing,
    )

    assert result.media_state is ImageMediumState.RIGHTS_RESTRICTED
    assert "relative_path" not in repr(result)
    assert "source_bytes" not in repr(result)
    assert not tuple(tmp_path.iterdir())


def test_selection_output_is_no_replace_and_preserves_existing_bytes(tmp_path: Path) -> None:
    output = tmp_path / "selection.json"
    _write_no_replace(output, b"first-canonical-output")

    with pytest.raises(FileExistsError):
        _write_no_replace(output, b"hostile-replacement")

    assert output.read_bytes() == b"first-canonical-output"
