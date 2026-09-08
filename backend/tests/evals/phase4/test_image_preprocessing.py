from __future__ import annotations

import hashlib
import os
from io import BytesIO
from pathlib import Path

import pytest
from PIL import Image, PngImagePlugin

from itda.analysis.image.preprocessing import (
    ImagePreprocessingCandidate,
    ImagePreprocessingPolicy,
    ImagePreprocessingResult,
    preprocess_image,
)
from itda.analysis.image.secure_read import (
    ApprovedImageMaterialization,
    RightsBoundImage,
    SecureReadPolicy,
)
from itda.contracts.catalog_optional_media import ImageMediumState


def _sha256(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def _oriented_jpeg_bytes() -> bytes:
    image = Image.new("RGB", (2, 4), (21, 89, 144))
    exif = Image.Exif()
    exif[274] = 6
    exif[270] = "synthetic location metadata must be removed"
    output = BytesIO()
    image.save(output, format="JPEG", quality=95, subsampling=0, exif=exif)
    image.close()
    return output.getvalue()


def _png_bytes(*, size: tuple[int, int] = (5, 3)) -> bytes:
    image = Image.new("RGBA", size, (50, 100, 150, 160))
    metadata = PngImagePlugin.PngInfo()
    metadata.add_text("location", "synthetic location metadata must be removed")
    output = BytesIO()
    image.save(output, format="PNG", pnginfo=metadata, icc_profile=b"synthetic-icc")
    image.close()
    return output.getvalue()


def _qualified(
    relative_path: str,
    payload: bytes,
) -> tuple[ImagePreprocessingCandidate, ApprovedImageMaterialization]:
    approved = ApprovedImageMaterialization(
        rights_leaf_id="asset-rights:synthetic-approved-leaf",
        rights_leaf_sha256="a" * 64,
        content_sha256=_sha256(payload),
    )
    candidate = ImagePreprocessingCandidate(
        media_state=ImageMediumState.QUALIFIED,
        image=RightsBoundImage(
            relative_path=relative_path,
            rights_leaf_id=approved.rights_leaf_id,
            rights_leaf_sha256=approved.rights_leaf_sha256,
            content_sha256=approved.content_sha256,
        ),
    )
    return candidate, approved


def _root_descriptor(root: Path) -> int:
    return os.open(
        root,
        os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_CLOEXEC", 0),
    )


@pytest.mark.parametrize(
    "state",
    tuple(state for state in ImageMediumState if state is not ImageMediumState.QUALIFIED),
)
def test_non_qualified_states_pass_through_exactly_and_never_read_bytes(
    state: ImageMediumState,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def forbidden(*_: object, **__: object) -> None:
        raise AssertionError("non-qualified media must not reach the byte reader")

    monkeypatch.setattr(
        "itda.analysis.image.preprocessing.read_approved_image",
        forbidden,
    )

    result = preprocess_image(
        root_fd=-1,
        candidate=ImagePreprocessingCandidate(media_state=state, image=None),
        approved=None,
    )

    assert result.media_state is state
    assert result.projection is None
    assert result.failure_reason is None
    assert result.is_fact_free


def test_alternate_media_state_vocabulary_is_rejected() -> None:
    with pytest.raises(TypeError, match="exact ImageMediumState"):
        ImagePreprocessingCandidate(media_state="QUALIFIED", image=None)  # type: ignore[arg-type]
    with pytest.raises(TypeError, match="exact ImageMediumState"):
        ImagePreprocessingResult(  # type: ignore[arg-type]
            media_state="MISSING",
            projection=None,
            failure_reason=None,
        )


def test_orientation_resize_metadata_removal_and_reencoding_are_deterministic(
    tmp_path: Path,
) -> None:
    payload = _oriented_jpeg_bytes()
    image_path = tmp_path / "oriented.jpg"
    image_path.write_bytes(payload)
    image_path.chmod(0o600)
    candidate, approved = _qualified(image_path.name, payload)
    policy = ImagePreprocessingPolicy(
        secure_read=SecureReadPolicy(max_bytes=128 * 1024),
        accepted_formats=("JPEG",),
        max_source_width=100,
        max_source_height=100,
        max_source_pixels=10_000,
        output_max_width=3,
        output_max_height=1,
        quality_short_side_candidates=(320, 640),
        quality_aspect_ratio_milli_candidates=(400, 2500),
        temporary_event_policy_candidates=("EXCLUDE", "DOWNWEIGHT"),
    )
    root_fd = _root_descriptor(tmp_path)
    try:
        first = preprocess_image(
            root_fd=root_fd,
            candidate=candidate,
            approved=approved,
            policy=policy,
        )
        second = preprocess_image(
            root_fd=root_fd,
            candidate=candidate,
            approved=approved,
            policy=policy,
        )
    finally:
        os.close(root_fd)

    assert first == second
    assert first.media_state is ImageMediumState.QUALIFIED
    assert first.failure_reason is None
    assert first.projection is not None
    projection = first.projection
    assert projection.source_format == "JPEG"
    assert (projection.source_width, projection.source_height) == (2, 4)
    assert (projection.oriented_width, projection.oriented_height) == (4, 2)
    assert (projection.width, projection.height) == (2, 1)
    assert projection.mode == "RGB"
    assert projection.output_format == "PNG"
    assert projection.source_content_sha256 == approved.content_sha256
    assert projection.asset_sha256 == _sha256(projection.encoded_bytes)
    assert projection.preprocessing_policy_sha256 == policy.policy_sha256
    assert projection.operation_order == (
        "VERIFY",
        "DECODE",
        "EXIF_TRANSPOSE",
        "ALPHA_COMPOSITE",
        "RGB_CONVERT",
        "FIT_WITHIN_BOUNDS",
        "FRESH_RGB_COPY",
        "PNG_REENCODE",
    )
    assert projection.rights_leaf_id == approved.rights_leaf_id
    assert projection.rights_leaf_sha256 == approved.rights_leaf_sha256

    with Image.open(BytesIO(projection.encoded_bytes)) as restored:
        restored.load()
        assert restored.format == "PNG"
        assert restored.mode == "RGB"
        assert restored.size == (2, 1)
        assert not restored.getexif()
        assert "exif" not in restored.info
        assert "icc_profile" not in restored.info
        assert "text" not in restored.info
        assert projection.normalized_pixel_sha256 == _sha256(restored.tobytes())


def test_rgba_projection_is_fresh_bounded_and_policy_candidates_are_audit_bound(
    tmp_path: Path,
) -> None:
    payload = _png_bytes(size=(5, 3))
    image_path = tmp_path / "rgba.png"
    image_path.write_bytes(payload)
    image_path.chmod(0o600)
    candidate, approved = _qualified(image_path.name, payload)
    policy = ImagePreprocessingPolicy(
        secure_read=SecureReadPolicy(max_bytes=64 * 1024),
        accepted_formats=("PNG",),
        max_source_width=10,
        max_source_height=10,
        max_source_pixels=100,
        output_max_width=4,
        output_max_height=4,
        quality_short_side_candidates=(320, 640, 960),
        quality_aspect_ratio_milli_candidates=(400, 2500),
        temporary_event_policy_candidates=("EXCLUDE", "DOWNWEIGHT"),
    )
    root_fd = _root_descriptor(tmp_path)
    try:
        result = preprocess_image(
            root_fd=root_fd,
            candidate=candidate,
            approved=approved,
            policy=policy,
        )
    finally:
        os.close(root_fd)

    assert result.projection is not None
    projection = result.projection
    assert (projection.width, projection.height) == (4, 2)
    assert projection.encoded_bytes != payload
    assert projection.audit_sha256 == projection.recompute_audit_sha256()
    assert policy.quality_short_side_candidates == (320, 640, 960)
    assert policy.quality_aspect_ratio_milli_candidates == (400, 2500)
    assert policy.temporary_event_policy_candidates == ("EXCLUDE", "DOWNWEIGHT")
    assert policy.policy_sha256 == policy.recompute_policy_sha256()
    with Image.open(BytesIO(payload)) as source:
        assert "icc_profile" in source.info
        assert source.info["location"] == "synthetic location metadata must be removed"
    with Image.open(BytesIO(projection.encoded_bytes)) as restored:
        assert "icc_profile" not in restored.info
        assert "location" not in restored.info

    rendered = repr(result)
    assert "encoded_bytes" not in rendered
    assert repr(payload[:8]) not in rendered
    assert repr(projection.encoded_bytes[:8]) not in rendered


@pytest.mark.parametrize(
    ("kind", "expected_pixel"),
    (
        ("fully-transparent", (255, 255, 255)),
        ("partially-transparent", (127, 127, 127)),
        ("palette-transparent", (255, 255, 255)),
    ),
)
def test_alpha_is_composited_before_rgb_projection(
    tmp_path: Path,
    kind: str,
    expected_pixel: tuple[int, int, int],
) -> None:
    if kind == "palette-transparent":
        source = Image.new("P", (2, 1), 0)
        source.putpalette([255, 0, 0] + [0, 0, 0] * 255)
        source.info["transparency"] = 0
    else:
        alpha = 0 if kind == "fully-transparent" else 128
        source = Image.new("RGBA", (2, 1), (0, 0, 0, alpha))
    encoded = BytesIO()
    source.save(encoded, format="PNG", transparency=0 if kind == "palette-transparent" else None)
    source.close()
    payload = encoded.getvalue()
    path = tmp_path / f"{kind}.png"
    path.write_bytes(payload)
    path.chmod(0o600)
    candidate, approved = _qualified(path.name, payload)
    root_fd = _root_descriptor(tmp_path)
    try:
        result = preprocess_image(
            root_fd=root_fd,
            candidate=candidate,
            approved=approved,
        )
    finally:
        os.close(root_fd)

    assert result.projection is not None
    with Image.open(BytesIO(result.projection.encoded_bytes)) as projected:
        projected.load()
        assert projected.getpixel((0, 0)) == expected_pixel
