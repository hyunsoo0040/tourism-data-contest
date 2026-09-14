"""Private upload processing: sanitize in memory, retain observations only."""

from __future__ import annotations

import hashlib
import io
import secrets
from datetime import UTC, datetime
from typing import Literal, Self

from PIL import Image, ImageOps
from pydantic import Field, model_validator

from itda.contracts.base import Sha256, StrictContract
from itda.contracts.visual_mood import PhotoMoodCandidateSet, VisualMoodDimension
from itda.domain.canonical import canonical_sha256
from itda.domain.grounded_scoring import half_up
from itda.photo.provider.mood import MoodProvider


class PhotoReview(StrictContract):
    photo_id: str
    state: Literal["REVIEW", "CONFIRMED", "DELETED", "FAILED"]
    batches: tuple[PhotoMoodCandidateSet, ...] = Field(max_length=3)
    selected_candidate_ids: tuple[Sha256, ...] = ()
    targets: dict[VisualMoodDimension, int] = Field(default_factory=dict)
    receipt_sha256: Sha256 | None = None
    original_retained: Literal[False] = False
    deletion_state: Literal["ORIGINAL_DISCARDED"] = "ORIGINAL_DISCARDED"
    created_at: datetime

    @model_validator(mode="after")
    def no_false_confirmation(self) -> Self:
        if self.state == "CONFIRMED":
            if not self.targets or self.receipt_sha256 is None:
                raise ValueError("CONFIRMATION_REQUIRES_OBSERVED_TARGETS")
            expected = canonical_sha256(
                {
                    "photo_id": self.photo_id,
                    "selected_candidate_ids": list(self.selected_candidate_ids),
                    "targets": {k.value: v for k, v in self.targets.items()},
                    "batch_sha256": [b.candidate_set_sha256 for b in self.batches],
                }
            )
            if self.receipt_sha256 != expected:
                raise ValueError("PHOTO_CONFIRMATION_HASH_MISMATCH")
        if self.state == "DELETED" and (self.batches or self.targets or self.receipt_sha256):
            raise ValueError("DELETED_PHOTO_RECEIPT_RETAINS_OBSERVATIONS")
        return self


def sanitize_upload(raw: bytearray) -> bytes:
    try:
        if not 0 < len(raw) <= 10 * 1024 * 1024:
            raise ValueError("PHOTO_FILE_LIMIT")
        with Image.open(io.BytesIO(raw)) as image:
            if (
                image.format not in {"JPEG", "PNG", "WEBP"}
                or image.width * image.height > 24_000_000
            ):
                raise ValueError("PHOTO_DECODE_LIMIT")
            image.load()
            oriented = ImageOps.exif_transpose(image)
            rgb = Image.new("RGB", oriented.size, "white")
            if oriented.mode == "RGBA":
                rgb.paste(oriented, mask=oriented.getchannel("A"))
            else:
                rgb.paste(oriented.convert("RGB"))
            rgb.thumbnail((1024, 1024))
            out = io.BytesIO()
            rgb.save(out, format="PNG")
            result = out.getvalue()
            if len(result) > 8 * 1024 * 1024:
                raise ValueError("PHOTO_SANITIZED_LIMIT")
            return result
    finally:
        raw[:] = b"\0" * len(raw)


def analyze_uploads(raw_images: list[bytearray], provider: MoodProvider) -> PhotoReview:
    if not 1 <= len(raw_images) <= 3:
        for raw in raw_images:
            raw[:] = b"\0" * len(raw)
        raise ValueError("PHOTO_COUNT_LIMIT")
    photo_id = secrets.token_urlsafe(24)
    job_id = hashlib.sha256(photo_id.encode()).hexdigest()
    batches = []
    try:
        for index, raw in enumerate(raw_images, 1):
            png = sanitize_upload(raw)
            try:
                batch = provider.analyze(image_png=png, job_id=job_id, image_index=index)
                PhotoMoodCandidateSet.model_validate_json(batch.model_dump_json())
                if (
                    batch.job_id != job_id
                    or batch.payload_sha256 != hashlib.sha256(png).hexdigest()
                ):
                    raise ValueError("PHOTO_MODEL_INPUT_BINDING_MISMATCH")
                batches.append(batch)
            finally:
                del png
    finally:
        for raw in raw_images:
            raw[:] = b"\0" * len(raw)
    return PhotoReview(
        photo_id=photo_id, state="REVIEW", batches=tuple(batches), created_at=datetime.now(UTC)
    )


def confirm(review: PhotoReview, ids: tuple[str, ...]) -> PhotoReview:
    if review.state not in {"REVIEW", "CONFIRMED"}:
        raise ValueError("PHOTO_REVIEW_NOT_AVAILABLE")
    if len(set(ids)) != len(ids):
        raise ValueError("DUPLICATE_PHOTO_SELECTION")
    available = {
        c.candidate_id: (b.payload_sha256, c.observation)
        for b in review.batches
        for c in b.candidates
    }
    groups: dict[VisualMoodDimension, dict[str, int]] = {}
    for cid in ids:
        if cid not in available:
            raise ValueError("FOREIGN_PHOTO_CANDIDATE")
        image, observation = available[cid]
        if observation.state != "OBSERVED" or observation.level is None:
            raise ValueError("UNOBSERVED_PHOTO_CANDIDATE")
        groups.setdefault(observation.dimension, {})[image] = observation.level
    targets = {d: half_up(sum(values.values()), len(values)) for d, values in groups.items()}
    if not targets:
        raise ValueError("NO_CONFIRMED_VISUAL_TARGETS")
    selected = tuple(sorted(ids))
    receipt = canonical_sha256(
        {
            "photo_id": review.photo_id,
            "selected_candidate_ids": list(selected),
            "targets": {k.value: v for k, v in targets.items()},
            "batch_sha256": [b.candidate_set_sha256 for b in review.batches],
        }
    )
    return PhotoReview.model_validate(
        review.model_dump()
        | {
            "state": "CONFIRMED",
            "selected_candidate_ids": selected,
            "targets": targets,
            "receipt_sha256": receipt,
        }
    )
