from __future__ import annotations

import hashlib
import os
from dataclasses import replace
from io import BytesIO
from pathlib import Path

import pytest
from PIL import Image

from itda.analysis.image import preprocessing, secure_read
from itda.analysis.image.preprocessing import (
    IMAGE_PREPROCESSING_FAILURE_REASON,
    ImagePreprocessingCandidate,
    ImagePreprocessingPolicy,
    preprocess_image,
)
from itda.analysis.image.secure_read import (
    ApprovedImageMaterialization,
    FileIdentity,
    RightsBoundImage,
    SecureImageReadError,
    SecureReadPolicy,
    VerifiedImageRead,
    read_approved_image,
)
from itda.contracts.catalog_optional_media import ImageMediumState


def _sha256(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def _png_bytes(*, size: tuple[int, int] = (8, 6)) -> bytes:
    image = Image.new("RGB", size, (34, 85, 136))
    output = BytesIO()
    image.save(output, format="PNG")
    image.close()
    return output.getvalue()


def _gif_bytes() -> bytes:
    image = Image.new("P", (8, 6), 2)
    output = BytesIO()
    image.save(output, format="GIF")
    image.close()
    return output.getvalue()


def _animated_png_bytes() -> bytes:
    frames = [Image.new("RGB", (8, 6), color) for color in ((1, 2, 3), (4, 5, 6))]
    output = BytesIO()
    frames[0].save(output, format="PNG", save_all=True, append_images=frames[1:])
    for frame in frames:
        frame.close()
    return output.getvalue()


def _binding(
    relative_path: str,
    payload: bytes,
) -> tuple[RightsBoundImage, ApprovedImageMaterialization]:
    approved = ApprovedImageMaterialization(
        rights_leaf_id="phase2-rights-leaf:synthetic-photo",
        rights_leaf_sha256="b" * 64,
        content_sha256=_sha256(payload),
    )
    candidate = RightsBoundImage(
        relative_path=relative_path,
        rights_leaf_id=approved.rights_leaf_id,
        rights_leaf_sha256=approved.rights_leaf_sha256,
        content_sha256=approved.content_sha256,
    )
    return candidate, approved


def _preprocessing_candidate(binding: RightsBoundImage) -> ImagePreprocessingCandidate:
    return ImagePreprocessingCandidate(
        media_state=ImageMediumState.QUALIFIED,
        image=binding,
    )


def _root_descriptor(root: Path) -> int:
    return os.open(
        root,
        os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_CLOEXEC", 0),
    )


@pytest.mark.parametrize(
    "relative_path",
    (
        "",
        ".",
        "./image.png",
        "images//image.png",
        "images/../image.png",
        "../image.png",
        "/absolute/image.png",
        "images\\image.png",
        "image.png/",
    ),
)
def test_non_normalized_traversal_and_platform_ambiguous_paths_are_rejected(
    relative_path: str,
) -> None:
    with pytest.raises(ValueError, match="safe normalized relative path"):
        RightsBoundImage(
            relative_path=relative_path,
            rights_leaf_id="leaf",
            rights_leaf_sha256="a" * 64,
            content_sha256="b" * 64,
        )


@pytest.mark.parametrize(
    ("field", "replacement"),
    (
        ("rights_leaf_id", "phase2-rights-leaf:substitute"),
        ("rights_leaf_sha256", "c" * 64),
        ("content_sha256", "d" * 64),
    ),
)
def test_rights_leaf_id_leaf_digest_and_content_digest_must_join_before_open(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    field: str,
    replacement: str,
) -> None:
    payload = _png_bytes()
    path = tmp_path / "approved.png"
    path.write_bytes(payload)
    binding, approved = _binding(path.name, payload)
    hostile = replace(binding, **{field: replacement})

    def forbidden_open(*_: object, **__: object) -> int:
        raise AssertionError("rights mismatch must stop before filesystem open")

    monkeypatch.setattr(secure_read.os, "open", forbidden_open)

    with pytest.raises(SecureImageReadError) as captured:
        read_approved_image(
            root_fd=99,
            candidate=hostile,
            approved=approved,
            policy=SecureReadPolicy(max_bytes=64 * 1024),
        )

    assert str(captured.value) == "approved image read failed"


def test_symlink_hardlink_unsafe_mode_owner_and_oversize_fail_generically(
    tmp_path: Path,
) -> None:
    payload = _png_bytes()
    target = tmp_path / "target.png"
    target.write_bytes(payload)
    target.chmod(0o600)
    symlink = tmp_path / "symlink.png"
    symlink.symlink_to(target.name)
    hardlink = tmp_path / "hardlink.png"
    os.link(target, hardlink)
    unsafe = tmp_path / "unsafe.png"
    unsafe.write_bytes(payload)
    unsafe.chmod(0o620)
    oversize = tmp_path / "oversize.bin"
    oversize.write_bytes(b"x" * 65)
    oversize.chmod(0o600)
    cases = (
        (symlink, payload, SecureReadPolicy(max_bytes=64 * 1024)),
        (target, payload, SecureReadPolicy(max_bytes=64 * 1024)),
        (unsafe, payload, SecureReadPolicy(max_bytes=64 * 1024)),
        (
            unsafe,
            payload,
            SecureReadPolicy(
                max_bytes=64 * 1024,
                forbidden_mode_bits=0,
                allowed_owner_uids=(os.geteuid() + 1,),
            ),
        ),
        (oversize, oversize.read_bytes(), SecureReadPolicy(max_bytes=64)),
    )
    root_fd = _root_descriptor(tmp_path)
    try:
        for path, content, policy in cases:
            binding, approved = _binding(path.name, content)
            with pytest.raises(SecureImageReadError) as captured:
                read_approved_image(
                    root_fd=root_fd,
                    candidate=binding,
                    approved=approved,
                    policy=policy,
                )
            assert str(captured.value) == "approved image read failed"
    finally:
        os.close(root_fd)


@pytest.mark.parametrize("mutation", ("replace", "grow", "truncate"))
def test_path_substitution_and_mid_read_growth_or_truncation_are_detected(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    mutation: str,
) -> None:
    payload = (b"approved-source-" * 16_384)[:180_000]
    path = tmp_path / "mutable.bin"
    path.write_bytes(payload)
    path.chmod(0o600)
    binding, approved = _binding(path.name, payload)
    root_fd = _root_descriptor(tmp_path)
    original_read = os.read
    mutated = False

    def adversarial_read(descriptor: int, count: int) -> bytes:
        nonlocal mutated
        chunk = original_read(descriptor, count)
        if chunk and not mutated:
            mutated = True
            if mutation == "replace":
                displaced = tmp_path / "displaced.bin"
                path.rename(displaced)
                path.write_bytes(payload)
                path.chmod(0o600)
            elif mutation == "grow":
                with path.open("ab") as stream:
                    stream.write(b"growth")
            else:
                os.truncate(path, 70_000)
        return chunk

    monkeypatch.setattr(secure_read.os, "read", adversarial_read)
    try:
        with pytest.raises(SecureImageReadError) as captured:
            read_approved_image(
                root_fd=root_fd,
                candidate=binding,
                approved=approved,
                policy=SecureReadPolicy(max_bytes=256_000),
            )
    finally:
        os.close(root_fd)

    assert mutated
    assert str(captured.value) == "approved image read failed"


def test_parent_directory_substitution_is_detected(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    payload = (b"approved-nested-source-" * 12_000)[:180_000]
    approved_parent = tmp_path / "approved"
    approved_parent.mkdir()
    path = approved_parent / "nested.bin"
    path.write_bytes(payload)
    path.chmod(0o600)
    binding, approved = _binding("approved/nested.bin", payload)
    root_fd = _root_descriptor(tmp_path)
    original_read = os.read
    mutated = False

    def adversarial_read(descriptor: int, count: int) -> bytes:
        nonlocal mutated
        chunk = original_read(descriptor, count)
        if chunk and not mutated:
            mutated = True
            approved_parent.rename(tmp_path / "displaced")
            approved_parent.mkdir()
            replacement = approved_parent / path.name
            replacement.write_bytes(payload)
            replacement.chmod(0o600)
        return chunk

    monkeypatch.setattr(secure_read.os, "read", adversarial_read)
    try:
        with pytest.raises(SecureImageReadError) as captured:
            read_approved_image(
                root_fd=root_fd,
                candidate=binding,
                approved=approved,
                policy=SecureReadPolicy(max_bytes=256_000),
            )
    finally:
        os.close(root_fd)

    assert mutated
    assert str(captured.value) == "approved image read failed"


def test_stat_open_race_to_fifo_fails_without_blocking(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    payload = _png_bytes()
    path = tmp_path / "race.png"
    path.write_bytes(payload)
    path.chmod(0o600)
    binding, approved = _binding(path.name, payload)
    root_fd = _root_descriptor(tmp_path)
    original_stat = os.stat
    replaced = False

    def adversarial_stat(*args: object, **kwargs: object) -> os.stat_result:
        nonlocal replaced
        result = original_stat(*args, **kwargs)
        if kwargs.get("dir_fd") is not None and not replaced:
            replaced = True
            path.unlink()
            os.mkfifo(path, 0o600)
        return result

    monkeypatch.setattr(secure_read.os, "stat", adversarial_stat)
    monkeypatch.setattr(secure_read, "_require_secure_capabilities", lambda: None)
    try:
        with pytest.raises(SecureImageReadError) as captured:
            read_approved_image(
                root_fd=root_fd,
                candidate=binding,
                approved=approved,
                policy=SecureReadPolicy(max_bytes=64 * 1024),
            )
    finally:
        os.close(root_fd)

    assert replaced
    assert str(captured.value) == "approved image read failed"


def test_digest_mismatch_stops_before_pillow_decode(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    payload = _png_bytes()
    path = tmp_path / "digest-drift.png"
    path.write_bytes(payload)
    path.chmod(0o600)
    binding, approved = _binding(path.name, payload)
    approved = ApprovedImageMaterialization(
        rights_leaf_id=approved.rights_leaf_id,
        rights_leaf_sha256=approved.rights_leaf_sha256,
        content_sha256="e" * 64,
    )
    binding = replace(binding, content_sha256=approved.content_sha256)

    def forbidden_decode(*_: object, **__: object) -> None:
        raise AssertionError("digest mismatch must stop before Pillow decode")

    monkeypatch.setattr(preprocessing, "_decode_and_project", forbidden_decode)
    root_fd = _root_descriptor(tmp_path)
    try:
        result = preprocess_image(
            root_fd=root_fd,
            candidate=_preprocessing_candidate(binding),
            approved=approved,
        )
    finally:
        os.close(root_fd)

    assert result.media_state is ImageMediumState.ANALYSIS_FAILED
    assert result.failure_reason == IMAGE_PREPROCESSING_FAILURE_REASON
    assert result.projection is None
    assert path.name not in repr(result)
    assert approved.content_sha256 not in repr(result)


@pytest.mark.parametrize(
    "case",
    ("corrupt", "format", "frames", "dimension", "pixels", "decompression"),
)
def test_corrupt_unsupported_and_decode_bound_violations_are_fact_free_failures(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    case: str,
) -> None:
    if case == "corrupt":
        payload = b"not-an-image"
    elif case == "format":
        payload = _gif_bytes()
    elif case == "frames":
        payload = _animated_png_bytes()
    else:
        payload = _png_bytes(size=(20, 10))
    path = tmp_path / f"{case}.asset"
    path.write_bytes(payload)
    path.chmod(0o600)
    binding, approved = _binding(path.name, payload)
    policy = ImagePreprocessingPolicy(
        secure_read=SecureReadPolicy(max_bytes=64 * 1024),
        accepted_formats=("PNG",),
        max_source_width=10 if case == "dimension" else 100,
        max_source_height=100,
        max_source_pixels=199 if case == "pixels" else 10_000,
        output_max_width=100,
        output_max_height=100,
    )
    if case == "decompression":
        monkeypatch.setattr(Image, "MAX_IMAGE_PIXELS", 50)
    root_fd = _root_descriptor(tmp_path)
    try:
        result = preprocess_image(
            root_fd=root_fd,
            candidate=_preprocessing_candidate(binding),
            approved=approved,
            policy=policy,
        )
    finally:
        os.close(root_fd)

    assert result.media_state is ImageMediumState.ANALYSIS_FAILED
    assert result.failure_reason == IMAGE_PREPROCESSING_FAILURE_REASON
    assert result.projection is None
    assert result.is_fact_free


def test_secure_platform_capabilities_are_required(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    payload = _png_bytes()
    path = tmp_path / "approved.png"
    path.write_bytes(payload)
    binding, approved = _binding(path.name, payload)
    root_fd = _root_descriptor(tmp_path)
    monkeypatch.setattr(secure_read, "O_NOFOLLOW", 0)
    try:
        with pytest.raises(SecureImageReadError) as captured:
            read_approved_image(
                root_fd=root_fd,
                candidate=binding,
                approved=approved,
                policy=SecureReadPolicy(max_bytes=64 * 1024),
            )
    finally:
        os.close(root_fd)

    assert str(captured.value) == "approved image read failed"


def test_raw_verified_buffer_is_zeroed_after_metadata_free_projection(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    payload = _png_bytes()
    raw_buffer = bytearray(payload)
    binding, approved = _binding("synthetic.png", payload)
    verified = VerifiedImageRead(
        payload=raw_buffer,
        content_sha256=approved.content_sha256,
        identity=FileIdentity(
            device=1,
            inode=2,
            size=len(payload),
            mtime_ns=3,
            ctime_ns=4,
        ),
    )

    monkeypatch.setattr(preprocessing, "read_approved_image", lambda **_: verified)
    result = preprocess_image(
        root_fd=-1,
        candidate=_preprocessing_candidate(binding),
        approved=approved,
    )

    assert result.media_state is ImageMediumState.QUALIFIED
    assert result.projection is not None
    assert raw_buffer == bytearray(len(payload))
    assert not hasattr(result.projection, "source_bytes")


def test_verified_raw_buffer_repr_is_redacted_and_context_cleanup_is_enforced() -> None:
    raw_buffer = bytearray(b"protected-source-bytes")
    verified = VerifiedImageRead(
        payload=raw_buffer,
        content_sha256=_sha256(bytes(raw_buffer)),
        identity=FileIdentity(
            device=1,
            inode=2,
            size=len(raw_buffer),
            mtime_ns=3,
            ctime_ns=4,
        ),
    )

    assert "protected-source-bytes" not in repr(verified)
    with verified:
        assert any(raw_buffer)
    assert raw_buffer == bytearray(len(raw_buffer))
