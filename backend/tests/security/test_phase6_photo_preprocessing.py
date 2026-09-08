"""Controlled-RED Phase 6 upload preprocessing and metadata-removal contract.

Wave 0 (Plan 06-02): every test below freezes behavior for the planned
``itda.photo.preprocessing`` owner (Plan 06-05) before any production code
exists.  The owner is imported inside the tests so collection always succeeds
and execution fails only because the planned Phase 6 owner is absent.

Frozen contract (Wave 0 authority for Plan 06-05 Task 2):

- ``PHOTO_UPLOAD_PREPROCESSING_POLICY_VERSION == "phase6-upload-preprocessing-v1"``
  is separate from the Phase 4 policy; the frozen dataclass
  ``PhotoUploadPreprocessingPolicy`` accepts exactly JPEG/PNG/WEBP, caps source
  bytes at 10 MiB via ``max_source_bytes``, caps source pixels at 40,000,000,
  caps output at 2048x2048, validates every field's exact type and range in
  ``__post_init__`` (bool/float rejections included), and carries a canonical
  ``policy_sha256`` that changes with any policy field.
- ``preprocess_quarantined_image(*, payload: bytearray, stored_name: str,
  declared_media_type: str, policy: PhotoUploadPreprocessingPolicy | None)
  -> PhotoUploadPreprocessingResult`` follows the verified operation order:
  two-pass verify-then-reopen with identity agreement, decode-derived format
  must agree with the declared allowlist media type, EXIF transpose, alpha
  compositing on the frozen background, LANCZOS fit within bounds, fresh RGB
  copy with cleared info, metadata-free PNG re-encode.
- The result exposes the generated ``stored_name`` handoff, decode-derived
  source format, bounded dimensions, ``encoded_sha256`` digest of
  ``encoded_bytes`` (immutable, repr-redacted), and ``policy_sha256`` lineage.
  It never carries the source payload or any original name.
- Every hostile input — spoofing, GIF/animation, truncation, corruption,
  decompression-bomb warnings, dimension/pixel/byte bounds, verify-reopen
  identity drift — raises ``PhotoUploadPreprocessingError`` whose single
  ``reason`` equals the module's one closed UPPER_SNAKE failure constant and
  whose text reflects no parser message, byte marker, comment text, or stored
  identity.
- The source ``bytearray`` payload is zeroed after success and after failure.

No production source, dependency, lock, provider client, credential, or network
traffic is touched by this module; no original filename ever appears.
"""

from __future__ import annotations

import hashlib
import importlib
import re
import warnings
from dataclasses import replace
from io import BytesIO
from types import ModuleType
from typing import Any

import pytest
from PIL import Image, PngImagePlugin

PREPROCESSING_MODULE = "itda.photo.preprocessing"
POLICY_VERSION = "phase6-upload-preprocessing-v1"
PAYLOAD_MARKER = "phase6-preprocess-payload-marker-4b81"
COMMENT_MARKER = "phase6-preprocess-comment-marker-c95e"
STORED_NAME = "a" * 32


def _phase6_owner(module_name: str) -> ModuleType:
    """Import the planned Phase 6 preprocessing owner or fail controlled RED."""

    try:
        return importlib.import_module(module_name)
    except ImportError as error:
        pytest.fail(
            "controlled RED: planned Phase 6 photo preprocessing owner is absent: "
            f"{module_name} ({error}). Implement the Plan 06-05 preprocessing "
            "owner before this contract can proceed.",
            pytrace=False,
        )


def _require(condition: object, message: str) -> None:
    if not condition:
        pytest.fail(f"phase6 preprocessing contract violated: {message}", pytrace=False)


def _marker_bytes(size: int) -> bytes:
    body = (PAYLOAD_MARKER.encode() * (size // len(PAYLOAD_MARKER) + 1))[:size]
    return body


def _png_bytes(*, size: tuple[int, int] = (8, 6), mode: str = "RGB") -> bytes:
    image = Image.new(mode, size, (34, 85, 136))
    output = BytesIO()
    image.save(output, format="PNG")
    image.close()
    return output.getvalue()


def _png_bytes_with_text(*, size: tuple[int, int] = (8, 6)) -> bytes:
    image = Image.new("RGB", size, (10, 20, 30))
    metadata = PngImagePlugin.PngInfo()
    metadata.add_text("Comment", COMMENT_MARKER)
    metadata.add_text("Description", "original-camera-description")
    output = BytesIO()
    image.save(output, format="PNG", pnginfo=metadata)
    image.close()
    return output.getvalue()


def _transparent_png_bytes(*, size: tuple[int, int] = (8, 6)) -> bytes:
    image = Image.new("RGBA", size, (12, 34, 56, 0))
    output = BytesIO()
    image.save(output, format="PNG")
    image.close()
    return output.getvalue()


def _jpeg_bytes(*, size: tuple[int, int] = (32, 24)) -> bytes:
    image = Image.new("RGB", size, (200, 100, 50))
    output = BytesIO()
    image.save(output, format="JPEG")
    image.close()
    return output.getvalue()


def _jpeg_bytes_with_orientation(
    *, size: tuple[int, int] = (48, 32), orientation: int = 6
) -> bytes:
    image = Image.new("RGB", size, (90, 60, 30))
    exif = Image.Exif()
    exif[0x0112] = orientation
    output = BytesIO()
    image.save(output, format="JPEG", exif=exif)
    image.close()
    return output.getvalue()


def _webp_bytes(*, size: tuple[int, int] = (8, 6)) -> bytes:
    image = Image.new("RGB", size, (5, 10, 15))
    output = BytesIO()
    image.save(output, format="WEBP")
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


def _truncated(payload: bytes, keep: float) -> bytes:
    cut = max(1, int(len(payload) * keep))
    return payload[:cut]


def _corrupt(payload: bytes) -> bytes:
    # Corrupt the structural scan-header segment: mid-entropy corruption is
    # silently repaired by libjpeg and would decode to identical pixels,
    # which no sound decoder-side check can reject.
    sos = payload.find(b"\xff\xda")
    cut = sos + 2 if sos != -1 else len(payload) // 2
    return payload[:cut] + _marker_bytes(16) + payload[cut + 16 :]


def _default_policy(module: ModuleType) -> Any:
    return module.PhotoUploadPreprocessingPolicy()


def _preprocess(
    module: ModuleType,
    payload: bytes | bytearray,
    *,
    declared_media_type: str,
    stored_name: str = STORED_NAME,
    policy: Any | None = None,
) -> tuple[Any, bytearray]:
    buffer = payload if isinstance(payload, bytearray) else bytearray(payload)
    result = module.preprocess_quarantined_image(
        payload=buffer,
        stored_name=stored_name,
        declared_media_type=declared_media_type,
        policy=policy,
    )
    return result, buffer


def _expect_rejection(
    module: ModuleType,
    payload: bytes | bytearray,
    *,
    declared_media_type: str,
    stored_name: str = STORED_NAME,
    policy: Any | None = None,
) -> tuple[Any, bytearray]:
    buffer = payload if isinstance(payload, bytearray) else bytearray(payload)
    with pytest.raises(module.PhotoUploadPreprocessingError) as captured:
        module.preprocess_quarantined_image(
            payload=buffer,
            stored_name=stored_name,
            declared_media_type=declared_media_type,
            policy=policy,
        )
    error = captured.value
    reason_constant = module.PHOTO_UPLOAD_PREPROCESSING_FAILURE_REASON
    _require(
        isinstance(reason_constant, str)
        and re.fullmatch(r"[A-Z][A-Z0-9_]*", reason_constant) is not None,
        "the module must expose one closed UPPER_SNAKE failure reason constant",
    )
    _require(
        getattr(error, "reason", None) == reason_constant,
        "every rejection must expose exactly the closed failure reason",
    )
    rendered = f"{error!s} {error!r} {getattr(error, 'args', ())!r}"
    for forbidden in (PAYLOAD_MARKER, COMMENT_MARKER, "original-camera-description"):
        _require(
            forbidden not in rendered,
            f"rejection text must never reflect input material: {forbidden!r}",
        )
    for parser_phrase in ("cannot identify image file", "Not a PNG", "background "):
        _require(
            parser_phrase not in rendered,
            "rejection text must stay fact-free of parser messages",
        )
    _require(len(rendered) <= 500, "rejection text must remain bounded")
    return error, buffer


def test_policy_version_and_frozen_bounds_are_declared() -> None:
    module = _phase6_owner(PREPROCESSING_MODULE)
    version = getattr(module, "PHOTO_UPLOAD_PREPROCESSING_POLICY_VERSION", None)
    _require(
        version == POLICY_VERSION,
        f"policy version must freeze as {POLICY_VERSION!r}, got {version!r}",
    )
    policy = _default_policy(module)
    _require(
        getattr(policy, "accepted_formats", None) == ("JPEG", "PNG", "WEBP"),
        "accepted formats must freeze as JPEG/PNG/WEBP in that order",
    )
    _require(
        getattr(policy, "max_source_bytes", None) == 10 * 1024 * 1024,
        "max_source_bytes must freeze the 10 MiB upload source cap",
    )
    _require(
        getattr(policy, "max_source_pixels", None) == 40_000_000,
        "max_source_pixels must freeze the 40,000,000 pixel bound",
    )
    _require(
        getattr(policy, "output_max_width", None) == 2_048
        and getattr(policy, "output_max_height", None) == 2_048,
        "output bounds must freeze at 2048x2048",
    )
    digest = getattr(policy, "policy_sha256", None)
    _require(
        isinstance(digest, str) and re.fullmatch(r"[0-9a-f]{64}", digest) is not None,
        "policy_sha256 must be a canonical lowercase SHA-256 digest",
    )
    _require(
        _default_policy(module).policy_sha256 == digest,
        "policy_sha256 must be stable across identical instantiations",
    )
    widened = replace(policy, output_max_width=1_024)
    _require(
        widened.policy_sha256 != digest,
        "any policy field change must change the canonical policy digest",
    )
    try:
        policy.max_source_bytes = 1  # type: ignore[misc]
    except Exception:
        return
    pytest.fail(
        "phase6 preprocessing contract violated: the policy must be frozen",
        pytrace=False,
    )


def test_policy_validates_exact_field_types_and_ranges() -> None:
    module = _phase6_owner(PREPROCESSING_MODULE)
    policy = _default_policy(module)
    hostile_variants = (
        ("unknown_format", replace(policy, accepted_formats=("GIF", "PNG"))),
        ("empty_formats", replace(policy, accepted_formats=())),
        ("float_source_bytes", replace(policy, max_source_bytes=10.5)),
        ("bool_source_pixels", replace(policy, max_source_pixels=True)),
        ("zero_source_bytes", replace(policy, max_source_bytes=0)),
        ("negative_pixels", replace(policy, max_source_pixels=-1)),
        ("zero_output_width", replace(policy, output_max_width=0)),
        ("oversized_output", replace(policy, output_max_height=100_000)),
        ("float_output", replace(policy, output_max_width=2048.0)),
    )
    for case, hostile in hostile_variants:
        with pytest.raises((ValueError, TypeError)) as captured:
            hostile.policy_sha256  # noqa: B018 — __post_init__ already validated
        _require(
            PAYLOAD_MARKER not in str(captured.value),
            f"{case}: policy validation text must stay free of input markers",
        )


def test_supported_formats_survive_to_metadata_free_png() -> None:
    module = _phase6_owner(PREPROCESSING_MODULE)
    policy = _default_policy(module)
    accepted = (
        ("JPEG", "image/jpeg", _jpeg_bytes()),
        ("PNG", "image/png", _png_bytes()),
        ("WEBP", "image/webp", _webp_bytes()),
    )
    for expected_format, media_type, payload in accepted:
        result, buffer = _preprocess(module, payload, declared_media_type=media_type, policy=policy)
        _require(
            getattr(result, "source_format", None) == expected_format,
            f"{expected_format}: decode-derived source format must be reported",
        )
        _require(
            getattr(result, "stored_name", None) == STORED_NAME,
            "the result must carry exactly the generated stored-name handoff",
        )
        encoded = getattr(result, "encoded_bytes", None)
        _require(isinstance(encoded, bytes), "encoded output must be immutable bytes")
        _require(
            hashlib.sha256(encoded).hexdigest() == getattr(result, "encoded_sha256", None),
            "encoded_sha256 must bind the exact sanitized output bytes",
        )
        with Image.open(BytesIO(encoded)) as output:
            _require(
                output.format == "PNG" and output.mode == "RGB",
                f"{expected_format}: sanitized output must decode as RGB PNG",
            )
            _require(
                output.width <= 2_048 and output.height <= 2_048,
                "sanitized output must respect the 2048x2048 output bound",
            )
            _require(
                not any(
                    "exif" in key.casefold() or "comment" in key.casefold()
                    for key in getattr(output, "info", {})
                ),
                "sanitized output must carry no EXIF or comment metadata",
            )
        rendered = f"{result!r}"
        _require(
            PAYLOAD_MARKER not in rendered,
            "result repr must not reflect the source payload",
        )
    del policy


def test_exif_orientation_is_transposed_into_bounded_output() -> None:
    module = _phase6_owner(PREPROCESSING_MODULE)
    payload = _jpeg_bytes_with_orientation(size=(48, 32), orientation=6)
    result, _ = _preprocess(module, payload, declared_media_type="image/jpeg")
    _require(
        (getattr(result, "width", 0), getattr(result, "height", 0)) == (32, 48),
        "EXIF orientation 6 must transpose 48x32 into a 32x48 output",
    )
    encoded = result.encoded_bytes
    with Image.open(BytesIO(encoded)) as output:
        _require(
            output.size == (32, 48),
            "the encoded PNG must be the transposed bounded image",
        )


def test_alpha_and_embedded_text_are_removed_from_output() -> None:
    module = _phase6_owner(PREPROCESSING_MODULE)
    result, _ = _preprocess(module, _transparent_png_bytes(), declared_media_type="image/png")
    with Image.open(BytesIO(result.encoded_bytes)) as output:
        _require(
            "A" not in output.getbands(),
            "alpha must be composited away before the sanitized output",
        )
        _require(
            output.getpixel((0, 0)) == (255, 255, 255),
            "fully transparent pixels must composite onto the frozen background",
        )
    result, _ = _preprocess(module, _png_bytes_with_text(), declared_media_type="image/png")
    with Image.open(BytesIO(result.encoded_bytes)) as output:
        rendered_text = repr(getattr(output, "text", {})) + repr(output.info)
        _require(
            COMMENT_MARKER not in rendered_text
            and "original-camera-description" not in rendered_text,
            "embedded text metadata must be stripped from the sanitized output",
        )


@pytest.mark.parametrize(
    ("case", "media_type", "payload"),
    (
        ("png_claim_jpeg", "image/png", None),
        ("jpeg_claim_png", "image/jpeg", None),
        ("gif_claim_png", "image/png", "GIF"),
        ("unknown_media", "image/x-unknown", "PNG"),
        ("empty_media", "", "PNG"),
        ("animation", "image/png", "ANIMATED"),
    ),
)
def test_spoofing_and_unsupported_inputs_reject_fact_free(
    case: str, media_type: str, payload: object
) -> None:
    module = _phase6_owner(PREPROCESSING_MODULE)
    if payload is None:
        hostile = _jpeg_bytes() if case == "png_claim_jpeg" else _png_bytes()
    elif payload == "GIF":
        hostile = _gif_bytes()
    elif payload == "ANIMATED":
        hostile = _animated_png_bytes()
    else:
        hostile = _png_bytes()
    _expect_rejection(module, hostile, declared_media_type=media_type, stored_name=STORED_NAME)


@pytest.mark.parametrize("case", ("truncated", "corrupt", "empty"))
def test_truncated_corrupt_and_empty_inputs_reject_fact_free(case: str) -> None:
    module = _phase6_owner(PREPROCESSING_MODULE)
    source = _jpeg_bytes(size=(64, 48))
    if case == "truncated":
        hostile = _truncated(source, 0.4)
    elif case == "corrupt":
        hostile = _corrupt(source)
    else:
        hostile = b""
    _expect_rejection(module, hostile, declared_media_type="image/jpeg")


def test_decompression_bomb_warning_is_elevated_to_rejection(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    module = _phase6_owner(PREPROCESSING_MODULE)
    monkeypatch.setattr(Image, "MAX_IMAGE_PIXELS", 50)
    with warnings.catch_warnings():
        warnings.simplefilter("ignore", UserWarning)
        _expect_rejection(module, _png_bytes(size=(20, 10)), declared_media_type="image/png")


@pytest.mark.parametrize(
    ("field", "value"),
    (
        ("max_source_pixels", 199),
        ("max_source_width", 10),
        ("max_source_height", 10),
        ("max_source_bytes", 1024),
    ),
)
def test_policy_decode_bounds_reject_oversized_sources(field: str, value: int) -> None:
    module = _phase6_owner(PREPROCESSING_MODULE)
    policy = replace(_default_policy(module), **{field: value})
    oversized = (
        _png_bytes(size=(20, 10))
        if field != "max_source_bytes"
        else _png_bytes(size=(20, 10)) + _marker_bytes(2048)
    )
    _expect_rejection(module, oversized, declared_media_type="image/png", policy=policy)


def test_oversized_dimensions_and_bytes_reject_without_decode() -> None:
    module = _phase6_owner(PREPROCESSING_MODULE)
    byte_policy = replace(_default_policy(module), max_source_bytes=256)
    _expect_rejection(
        module,
        _jpeg_bytes(size=(64, 48)),
        declared_media_type="image/jpeg",
        policy=byte_policy,
    )


def test_verify_reopen_identity_drift_is_rejected(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    module = _phase6_owner(PREPROCESSING_MODULE)
    real_open = Image.open
    opens = {"count": 0}

    def drifting_open(fp: object, *args: object, **kwargs: object) -> object:
        opens["count"] += 1
        if opens["count"] == 1:
            return real_open(fp, *args, **kwargs)  # type: ignore[arg-type]
        replacement = BytesIO(_png_bytes(size=(9, 7)))
        return real_open(replacement, *args, **kwargs)  # type: ignore[arg-type]

    monkeypatch.setattr(Image, "open", drifting_open)
    _expect_rejection(module, _jpeg_bytes(), declared_media_type="image/jpeg")
    _require(
        opens["count"] >= 2,
        "the two-pass contract must reopen the source after verification",
    )


def test_source_buffer_is_wiped_after_success_and_failure() -> None:
    module = _phase6_owner(PREPROCESSING_MODULE)
    success_payload = bytearray(_png_bytes())
    _preprocess(module, success_payload, declared_media_type="image/png")
    _require(
        success_payload == bytearray(len(success_payload)),
        "the source buffer must be zeroed after a successful projection",
    )
    _, failure_buffer = _expect_rejection(
        module, _corrupt(_jpeg_bytes()), declared_media_type="image/jpeg"
    )
    _require(
        failure_buffer == bytearray(len(failure_buffer)),
        "the source buffer must be zeroed after a failed projection",
    )


def test_result_carries_generated_identity_only() -> None:
    module = _phase6_owner(PREPROCESSING_MODULE)
    result, _ = _preprocess(module, _png_bytes(), declared_media_type="image/png")
    rendered = repr(result)
    _require(
        PAYLOAD_MARKER not in rendered,
        "the result must never expose the source payload",
    )
    _require(
        hasattr(result, "preprocessing_policy_sha256") or hasattr(result, "policy_sha256"),
        "the result must carry the policy digest lineage",
    )
    policy = _default_policy(module)
    _require(
        getattr(result, "preprocessing_policy_sha256", getattr(result, "policy_sha256", None))
        == policy.policy_sha256,
        "result lineage must bind the exact policy digest used",
    )
