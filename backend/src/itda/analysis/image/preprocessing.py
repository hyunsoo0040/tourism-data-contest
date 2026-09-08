"""Deterministic metadata-free image projection after exact rights binding."""

from __future__ import annotations

import hashlib
import warnings
from dataclasses import dataclass, field
from io import BytesIO

from PIL import Image, ImageOps

from itda.analysis.image.secure_read import (
    ApprovedImageMaterialization,
    RightsBoundImage,
    SecureImageReadError,
    SecureReadPolicy,
    VerifiedImageRead,
    read_approved_image,
)
from itda.contracts.catalog_optional_media import ImageMediumState
from itda.domain.canonical import canonical_sha256

IMAGE_PREPROCESSING_FAILURE_REASON = "IMAGE_PREPROCESSING_FAILED"
IMAGE_PREPROCESSING_POLICY_VERSION = "phase4-image-preprocessing-v2"
_OPERATION_ORDER = (
    "VERIFY",
    "DECODE",
    "EXIF_TRANSPOSE",
    "ALPHA_COMPOSITE",
    "RGB_CONVERT",
    "FIT_WITHIN_BOUNDS",
    "FRESH_RGB_COPY",
    "PNG_REENCODE",
)


@dataclass(frozen=True, slots=True)
class ImagePreprocessingCandidate:
    """Exact D-01 state plus facts only when the image is qualified."""

    media_state: ImageMediumState
    image: RightsBoundImage | None

    def __post_init__(self) -> None:
        if not isinstance(self.media_state, ImageMediumState):
            raise TypeError("media state must use the exact ImageMediumState contract")
        if self.media_state is ImageMediumState.QUALIFIED and self.image is None:
            raise ValueError("qualified image preprocessing requires a rights-bound image")
        if self.media_state is not ImageMediumState.QUALIFIED and self.image is not None:
            raise ValueError("non-qualified image preprocessing input must remain fact-free")


@dataclass(frozen=True, slots=True)
class ImagePreprocessingPolicy:
    """Frozen decode, resize, encoding, and sensitivity-candidate policy."""

    secure_read: SecureReadPolicy = field(default_factory=SecureReadPolicy)
    accepted_formats: tuple[str, ...] = ("JPEG", "PNG", "WEBP")
    max_frames: int = 1
    max_source_width: int = 12_000
    max_source_height: int = 12_000
    max_source_pixels: int = 40_000_000
    output_max_width: int = 2_048
    output_max_height: int = 2_048
    alpha_background_rgb: tuple[int, int, int] = (255, 255, 255)
    quality_short_side_candidates: tuple[int, ...] = (320, 640, 960)
    quality_aspect_ratio_milli_candidates: tuple[int, ...] = (400, 2500)
    temporary_event_policy_candidates: tuple[str, ...] = ("EXCLUDE", "DOWNWEIGHT")
    policy_sha256: str = field(init=False)

    def __post_init__(self) -> None:
        allowed_formats = frozenset({"JPEG", "PNG", "WEBP"})
        if (
            not self.accepted_formats
            or tuple(sorted(set(self.accepted_formats))) != self.accepted_formats
            or any(value not in allowed_formats for value in self.accepted_formats)
        ):
            raise ValueError("accepted image formats are invalid")
        bounds = (
            self.max_frames,
            self.max_source_width,
            self.max_source_height,
            self.max_source_pixels,
            self.output_max_width,
            self.output_max_height,
        )
        if any(value <= 0 for value in bounds):
            raise ValueError("image preprocessing bounds must be positive")
        if (
            len(self.alpha_background_rgb) != 3
            or any(
                type(value) is not int or not 0 <= value <= 255
                for value in self.alpha_background_rgb
            )
        ):
            raise ValueError("alpha compositing background must be an RGB triplet")
        if (
            not self.quality_short_side_candidates
            or any(value <= 0 for value in self.quality_short_side_candidates)
            or tuple(sorted(set(self.quality_short_side_candidates)))
            != self.quality_short_side_candidates
        ):
            raise ValueError("quality short-side candidates are invalid")
        if (
            len(self.quality_aspect_ratio_milli_candidates) != 2
            or self.quality_aspect_ratio_milli_candidates[0] <= 0
            or self.quality_aspect_ratio_milli_candidates[0]
            >= self.quality_aspect_ratio_milli_candidates[1]
        ):
            raise ValueError("quality aspect-ratio candidates are invalid")
        allowed_event_policies = {"EXCLUDE", "DOWNWEIGHT"}
        if (
            not self.temporary_event_policy_candidates
            or len(set(self.temporary_event_policy_candidates))
            != len(self.temporary_event_policy_candidates)
            or any(
                value not in allowed_event_policies
                for value in self.temporary_event_policy_candidates
            )
        ):
            raise ValueError("temporary-event policy candidates are invalid")
        object.__setattr__(self, "policy_sha256", self.recompute_policy_sha256())

    def _canonical_payload(self) -> dict[str, object]:
        return {
            "policy_version": IMAGE_PREPROCESSING_POLICY_VERSION,
            "secure_read": {
                "max_bytes": self.secure_read.max_bytes,
                "chunk_size": self.secure_read.chunk_size,
                "allowed_owner_uids": self.secure_read.allowed_owner_uids,
                "forbidden_mode_bits": self.secure_read.forbidden_mode_bits,
            },
            "accepted_formats": self.accepted_formats,
            "max_frames": self.max_frames,
            "max_source_width": self.max_source_width,
            "max_source_height": self.max_source_height,
            "max_source_pixels": self.max_source_pixels,
            "output_max_width": self.output_max_width,
            "output_max_height": self.output_max_height,
            "alpha_composite": {
                "rule": "COMPOSITE_VISIBLE_PIXELS_ON_FROZEN_BACKGROUND",
                "background_rgb": self.alpha_background_rgb,
                "palette_transparency": "EXPAND_TO_RGBA",
            },
            "quality_short_side_candidates": self.quality_short_side_candidates,
            "quality_aspect_ratio_milli_candidates": (self.quality_aspect_ratio_milli_candidates),
            "temporary_event_policy_candidates": self.temporary_event_policy_candidates,
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

    def recompute_policy_sha256(self) -> str:
        return canonical_sha256(self._canonical_payload())


DEFAULT_IMAGE_PREPROCESSING_POLICY = ImagePreprocessingPolicy()


@dataclass(frozen=True, slots=True)
class ImageProjection:
    """Derived metadata-free bytes plus digest-only audit lineage."""

    rights_leaf_id: str
    rights_leaf_sha256: str
    materialization_sha256: str
    source_content_sha256: str
    source_descriptor_identity_sha256: str
    preprocessing_policy_sha256: str
    source_format: str
    source_width: int
    source_height: int
    oriented_width: int
    oriented_height: int
    width: int
    height: int
    mode: str
    output_format: str
    normalized_pixel_sha256: str
    asset_sha256: str
    operation_order: tuple[str, ...]
    encoded_bytes: bytes = field(repr=False)
    audit_sha256: str = field(init=False)

    def __post_init__(self) -> None:
        if hashlib.sha256(self.encoded_bytes).hexdigest() != self.asset_sha256:
            raise ValueError("preprocessed asset digest is stale")
        object.__setattr__(self, "audit_sha256", self.recompute_audit_sha256())

    def _audit_payload(self) -> dict[str, object]:
        return {
            "rights_leaf_id": self.rights_leaf_id,
            "rights_leaf_sha256": self.rights_leaf_sha256,
            "materialization_sha256": self.materialization_sha256,
            "source_content_sha256": self.source_content_sha256,
            "source_descriptor_identity_sha256": self.source_descriptor_identity_sha256,
            "preprocessing_policy_sha256": self.preprocessing_policy_sha256,
            "source_format": self.source_format,
            "source_width": self.source_width,
            "source_height": self.source_height,
            "oriented_width": self.oriented_width,
            "oriented_height": self.oriented_height,
            "width": self.width,
            "height": self.height,
            "mode": self.mode,
            "output_format": self.output_format,
            "normalized_pixel_sha256": self.normalized_pixel_sha256,
            "asset_sha256": self.asset_sha256,
            "operation_order": self.operation_order,
        }

    def recompute_audit_sha256(self) -> str:
        return canonical_sha256(self._audit_payload())


@dataclass(frozen=True, slots=True)
class ImagePreprocessingResult:
    """Exact D-01 state with either one projection or no image facts."""

    media_state: ImageMediumState
    projection: ImageProjection | None
    failure_reason: str | None

    def __post_init__(self) -> None:
        if not isinstance(self.media_state, ImageMediumState):
            raise TypeError("media state must use the exact ImageMediumState contract")
        if self.media_state is ImageMediumState.QUALIFIED:
            if self.projection is None or self.failure_reason is not None:
                raise ValueError("qualified preprocessing result requires one projection")
        elif self.projection is not None:
            raise ValueError("non-qualified preprocessing result must remain fact-free")
        if self.failure_reason not in {None, IMAGE_PREPROCESSING_FAILURE_REASON}:
            raise ValueError("preprocessing failure reason is not externally safe")

    @property
    def is_fact_free(self) -> bool:
        return self.projection is None


def _failed_result() -> ImagePreprocessingResult:
    return ImagePreprocessingResult(
        media_state=ImageMediumState.ANALYSIS_FAILED,
        projection=None,
        failure_reason=IMAGE_PREPROCESSING_FAILURE_REASON,
    )


def _validate_source_image(image: Image.Image, policy: ImagePreprocessingPolicy) -> None:
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
        raise ValueError("image violates the frozen decode policy")


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
    """Composite every alpha representation before any RGB pixels reach the model."""

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


def _decode_and_project(
    *,
    verified: VerifiedImageRead,
    approved: ApprovedImageMaterialization,
    policy: ImagePreprocessingPolicy,
) -> ImageProjection:
    warning_type = Image.DecompressionBombWarning
    with warnings.catch_warnings():
        warnings.simplefilter("error", warning_type)
        with Image.open(BytesIO(verified.payload), formats=list(policy.accepted_formats)) as probe:
            _validate_source_image(probe, policy)
            source_format = str(probe.format)
            source_width, source_height = probe.size
            probe.verify()

        with Image.open(
            BytesIO(verified.payload), formats=list(policy.accepted_formats)
        ) as decoded:
            _validate_source_image(decoded, policy)
            if decoded.format != source_format or decoded.size != (source_width, source_height):
                raise ValueError("image identity changed between verify and decode")
            decoded.load()
            oriented = ImageOps.exif_transpose(decoded)
            try:
                oriented_width, oriented_height = oriented.size
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
                            normalized_pixel_sha256 = hashlib.sha256(clean.tobytes()).hexdigest()
                            encoded = BytesIO()
                            clean.save(
                                encoded,
                                format="PNG",
                                compress_level=9,
                                optimize=False,
                            )
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

    materialization_sha256 = approved.materialization_sha256
    if materialization_sha256 is None:
        raise ValueError("approved materialization is not self-authenticating")
    return ImageProjection(
        rights_leaf_id=approved.rights_leaf_id,
        rights_leaf_sha256=approved.rights_leaf_sha256,
        materialization_sha256=materialization_sha256,
        source_content_sha256=verified.content_sha256,
        source_descriptor_identity_sha256=canonical_sha256(verified.identity.as_payload()),
        preprocessing_policy_sha256=policy.policy_sha256,
        source_format=source_format,
        source_width=source_width,
        source_height=source_height,
        oriented_width=oriented_width,
        oriented_height=oriented_height,
        width=width,
        height=height,
        mode="RGB",
        output_format="PNG",
        normalized_pixel_sha256=normalized_pixel_sha256,
        asset_sha256=hashlib.sha256(encoded_bytes).hexdigest(),
        operation_order=_OPERATION_ORDER,
        encoded_bytes=encoded_bytes,
    )


def preprocess_image(
    *,
    root_fd: int,
    candidate: ImagePreprocessingCandidate,
    approved: ApprovedImageMaterialization | None,
    policy: ImagePreprocessingPolicy | None = None,
) -> ImagePreprocessingResult:
    """Project one D-01 image state without retaining unverified raw bytes."""

    if candidate.media_state is not ImageMediumState.QUALIFIED:
        return ImagePreprocessingResult(
            media_state=candidate.media_state,
            projection=None,
            failure_reason=None,
        )
    if candidate.image is None or approved is None:
        return _failed_result()

    selected_policy = policy or DEFAULT_IMAGE_PREPROCESSING_POLICY
    try:
        verified = read_approved_image(
            root_fd=root_fd,
            candidate=candidate.image,
            approved=approved,
            policy=selected_policy.secure_read,
        )
    except SecureImageReadError:
        return _failed_result()

    with verified:
        try:
            projection = _decode_and_project(
                verified=verified,
                approved=approved,
                policy=selected_policy,
            )
        except Exception:
            return _failed_result()
    return ImagePreprocessingResult(
        media_state=ImageMediumState.QUALIFIED,
        projection=projection,
        failure_reason=None,
    )


__all__ = [
    "DEFAULT_IMAGE_PREPROCESSING_POLICY",
    "IMAGE_PREPROCESSING_FAILURE_REASON",
    "IMAGE_PREPROCESSING_POLICY_VERSION",
    "ImagePreprocessingCandidate",
    "ImagePreprocessingPolicy",
    "ImagePreprocessingResult",
    "ImageProjection",
    "preprocess_image",
]
