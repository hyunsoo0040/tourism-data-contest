"""Metadata-free bounded decode and re-encode for quarantined photo uploads.

Quarantined source bytes enter as a mutable ``bytearray``; the module decodes
with the verified two-pass verify/reopen order, transposes EXIF orientation,
composites alpha away, fits within frozen bounds, and re-encodes a fresh RGB
PNG carrying no metadata. Every hostile input fails closed with one closed
reason code; the source buffer is zeroed on both success and failure paths.
"""

from __future__ import annotations

import hashlib
import warnings
from dataclasses import dataclass, field
from io import BytesIO
from typing import Final

from PIL import Image, ImageOps

from itda.domain.canonical import canonical_sha256

PHOTO_UPLOAD_PREPROCESSING_POLICY_VERSION: Final[str] = (
    "phase6-upload-preprocessing-v1"
)
PHOTO_UPLOAD_PREPROCESSING_FAILURE_REASON: Final[str] = (
    "PHOTO_UPLOAD_PREPROCESSING_FAILED"
)
_OPERATION_ORDER: Final[tuple[str, ...]] = (
    "VERIFY",
    "DECODE",
    "EXIF_TRANSPOSE",
    "ALPHA_COMPOSITE",
    "RGB_CONVERT",
    "FIT_WITHIN_BOUNDS",
    "FRESH_RGB_COPY",
    "PNG_REENCODE",
)
_ALLOWED_FORMATS: Final[frozenset[str]] = frozenset({"JPEG", "PNG", "WEBP"})
_DECLARED_MEDIA_TYPES: Final[dict[str, str]] = {
    "image/jpeg": "JPEG",
    "image/png": "PNG",
    "image/webp": "WEBP",
}


class PhotoUploadPreprocessingError(Exception):
    """One closed, fact-free failure for every rejected upload projection."""

    def __init__(self) -> None:
        self.reason = PHOTO_UPLOAD_PREPROCESSING_FAILURE_REASON
        super().__init__(PHOTO_UPLOAD_PREPROCESSING_FAILURE_REASON)


@dataclass(frozen=True, slots=True)
class PhotoUploadPreprocessingPolicy:
    """Frozen upload decode, bound, and encoding policy with canonical digest."""

    accepted_formats: tuple[str, ...] = ("JPEG", "PNG", "WEBP")
    max_source_bytes: int = 10 * 1024 * 1024
    max_source_width: int = 12_000
    max_source_height: int = 12_000
    max_source_pixels: int = 40_000_000
    output_max_width: int = 2_048
    output_max_height: int = 2_048
    alpha_background_rgb: tuple[int, int, int] = (255, 255, 255)
    max_frames: int = 1

    def _validate(self) -> None:
        if (
            not self.accepted_formats
            or tuple(sorted(set(self.accepted_formats))) != self.accepted_formats
            or any(
                type(value) is not str or value not in _ALLOWED_FORMATS
                for value in self.accepted_formats
            )
        ):
            raise ValueError("accepted upload image formats are invalid")
        numeric_fields = {
            "max_source_bytes": self.max_source_bytes,
            "max_source_width": self.max_source_width,
            "max_source_height": self.max_source_height,
            "max_source_pixels": self.max_source_pixels,
            "output_max_width": self.output_max_width,
            "output_max_height": self.output_max_height,
            "max_frames": self.max_frames,
        }
        for field_name, value in numeric_fields.items():
            if type(value) is not int or value <= 0:
                raise ValueError(f"{field_name} must be a positive integer")
        if (
            len(self.alpha_background_rgb) != 3
            or any(
                type(value) is not int or not 0 <= value <= 255
                for value in self.alpha_background_rgb
            )
        ):
            raise ValueError("alpha compositing background must be an RGB triplet")
        if (
            self.output_max_width > self.max_source_width
            or self.output_max_height > self.max_source_height
        ):
            raise ValueError("output bounds exceed the acceptable source envelope")
        if self.max_source_pixels > self.max_source_width * self.max_source_height:
            raise ValueError("source pixel bound exceeds the dimension envelope")

    def _canonical_payload(self) -> dict[str, object]:
        return {
            "policy_version": PHOTO_UPLOAD_PREPROCESSING_POLICY_VERSION,
            "accepted_formats": self.accepted_formats,
            "max_source_bytes": self.max_source_bytes,
            "max_source_width": self.max_source_width,
            "max_source_height": self.max_source_height,
            "max_source_pixels": self.max_source_pixels,
            "output_max_width": self.output_max_width,
            "output_max_height": self.output_max_height,
            "alpha_composite": {
                "rule": "COMPOSITE_VISIBLE_PIXELS_ON_FROZEN_BACKGROUND",
                "background_rgb": self.alpha_background_rgb,
            },
            "max_frames": self.max_frames,
            "operation_order": _OPERATION_ORDER,
            "resize_filter": "LANCZOS",
            "output": {
                "format": "PNG",
                "mode": "RGB",
                "compress_level": 9,
                "optimize": False,
                "metadata": "OMITTED",
            },
        }

    @property
    def policy_sha256(self) -> str:
        self._validate()
        return canonical_sha256(self._canonical_payload())


@dataclass(frozen=True, slots=True)
class PhotoUploadPreprocessingResult:
    """Digest-bound sanitized output; never carries the source payload."""

    stored_name: str
    source_format: str
    source_width: int
    source_height: int
    width: int
    height: int
    encoded_sha256: str
    preprocessing_policy_sha256: str
    encoded_bytes: bytes = field(repr=False)

    def __post_init__(self) -> None:
        if hashlib.sha256(self.encoded_bytes).hexdigest() != self.encoded_sha256:
            raise ValueError("sanitized output digest is stale")


def _wipe(buffer: bytearray) -> None:
    buffer[:] = b"\x00" * len(buffer)


def _validate_source_image(
    image: Image.Image,
    policy: PhotoUploadPreprocessingPolicy,
) -> None:
    width, height = image.size
    source_format = image.format
    if (
        source_format not in policy.accepted_formats
        or width <= 0
        or height <= 0
        or width > policy.max_source_width
        or height > policy.max_source_height
        or width * height > policy.max_source_pixels
        or int(getattr(image, "n_frames", 1)) > policy.max_frames
    ):
        raise ValueError("image violates the frozen upload decode policy")


def _fit_within_bounds(
    image: Image.Image,
    *,
    maximum_width: int,
    maximum_height: int,
) -> Image.Image:
    width, height = image.size
    if width <= maximum_width and height <= maximum_height:
        return image
    if width * maximum_height >= height * maximum_width:
        target_width = maximum_width
        target_height = max(1, (height * maximum_width + width // 2) // width)
    else:
        target_height = maximum_height
        target_width = max(1, (width * maximum_height + height // 2) // height)
    return image.resize(
        (target_width, target_height),
        resample=Image.Resampling.LANCZOS,
        reducing_gap=3.0,
    )


def _convert_visible_rgb(
    image: Image.Image,
    *,
    background_rgb: tuple[int, int, int],
) -> Image.Image:
    if "A" not in image.getbands() and "transparency" not in image.info:
        return image.convert("RGB")
    rgba = image.convert("RGBA")
    background = Image.new("RGBA", image.size, (*background_rgb, 255))
    try:
        composited = Image.alpha_composite(background, rgba)
        try:
            return composited.convert("RGB")
        finally:
            composited.close()
    finally:
        background.close()
        rgba.close()


def preprocess_quarantined_image(
    *,
    payload: bytearray,
    stored_name: str,
    declared_media_type: str,
    policy: PhotoUploadPreprocessingPolicy | None = None,
) -> PhotoUploadPreprocessingResult:
    """Project one quarantined upload into sanitized metadata-free PNG bytes."""

    selected_policy = policy or PhotoUploadPreprocessingPolicy()
    try:
        return _preprocess_checked(
            payload=payload,
            stored_name=stored_name,
            declared_media_type=declared_media_type,
            policy=selected_policy,
        )
    except PhotoUploadPreprocessingError:
        _wipe(payload)
        raise
    except Exception:
        _wipe(payload)
        raise PhotoUploadPreprocessingError() from None


def _preprocess_checked(
    *,
    payload: bytearray,
    stored_name: str,
    declared_media_type: str,
    policy: PhotoUploadPreprocessingPolicy,
) -> PhotoUploadPreprocessingResult:
    if type(stored_name) is not str or len(stored_name) != 32:
        raise ValueError("stored name must be the generated quarantine identity")
    if len(payload) == 0 or len(payload) > policy.max_source_bytes:
        raise ValueError("quarantined payload is outside the frozen source byte bound")
    declared_format = _DECLARED_MEDIA_TYPES.get(declared_media_type.casefold())
    if declared_format is None:
        raise ValueError("declared media type is outside the accepted allowlist")

    warning_type = Image.DecompressionBombWarning
    with warnings.catch_warnings():
        warnings.simplefilter("error", warning_type)
        with Image.open(BytesIO(bytes(payload)), formats=list(policy.accepted_formats)) as probe:
            _validate_source_image(probe, policy)
            source_format = str(probe.format)
            source_width, source_height = probe.size
            probe.verify()

        with Image.open(
            BytesIO(bytes(payload)), formats=list(policy.accepted_formats)
        ) as decoded:
            _validate_source_image(decoded, policy)
            if decoded.format != source_format or decoded.size != (source_width, source_height):
                raise ValueError("image identity changed between verify and decode")
            if source_format != declared_format:
                raise ValueError("decoded format disagrees with the declared media type")
            decoded.load()
            oriented = ImageOps.exif_transpose(decoded)
            try:
                converted = _convert_visible_rgb(
                    oriented,
                    background_rgb=policy.alpha_background_rgb,
                )
                try:
                    resized = _fit_within_bounds(
                        converted,
                        maximum_width=policy.output_max_width,
                        maximum_height=policy.output_max_height,
                    )
                    try:
                        clean = Image.new("RGB", resized.size)
                        try:
                            clean.paste(resized)
                            clean.info.clear()
                            encoded = BytesIO()
                            clean.save(encoded, format="PNG", compress_level=9, optimize=False)
                            encoded_bytes = encoded.getvalue()
                            width, height = clean.size
                        finally:
                            clean.close()
                    finally:
                        if resized is not converted:
                            resized.close()
                finally:
                    converted.close()
            finally:
                oriented.close()

    _wipe(payload)
    return PhotoUploadPreprocessingResult(
        stored_name=stored_name,
        source_format=source_format,
        source_width=source_width,
        source_height=source_height,
        width=width,
        height=height,
        encoded_sha256=hashlib.sha256(encoded_bytes).hexdigest(),
        preprocessing_policy_sha256=policy.policy_sha256,
        encoded_bytes=encoded_bytes,
    )


__all__ = [
    "PHOTO_UPLOAD_PREPROCESSING_FAILURE_REASON",
    "PHOTO_UPLOAD_PREPROCESSING_POLICY_VERSION",
    "PhotoUploadPreprocessingError",
    "PhotoUploadPreprocessingPolicy",
    "PhotoUploadPreprocessingResult",
    "preprocess_quarantined_image",
]
