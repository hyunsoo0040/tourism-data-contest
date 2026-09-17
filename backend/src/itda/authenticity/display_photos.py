"""Display-only official photos. Never supplied to scoring or mood analysis."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Literal, Self
from urllib.parse import urlsplit

from pydantic import Field, model_validator

from itda.contracts.base import Sha256, StableId, StrictContract
from itda.domain.canonical import canonical_sha256

PhotoLicense = Literal["KOGL_TYPE_0", "KOGL_TYPE_1", "KOGL_TYPE_2", "KOGL_TYPE_3", "KOGL_TYPE_4"]


def official_image_url(value: str) -> str:
    parsed = urlsplit(value)
    if (
        parsed.scheme not in {"http", "https"}
        or parsed.netloc != "tong.visitkorea.or.kr"
        or not parsed.path.startswith("/cms/resource/")
        or parsed.query
        or parsed.fragment
    ):
        raise ValueError("DISPLAY_PHOTO_NOT_OFFICIAL_IMAGE")
    return parsed._replace(scheme="https").geturl()


class DisplayPhoto(StrictContract):
    url: str
    attribution_ko: str = Field(min_length=1)
    license: PhotoLicense
    source_url: str
    source_record_sha256: Sha256
    source_response_sha256: Sha256
    retrieved_at: str

    @model_validator(mode="after")
    def official_source(self) -> Self:
        if self.url != official_image_url(self.url):
            raise ValueError("DISPLAY_PHOTO_REQUIRES_HTTPS")
        if not self.source_url.startswith("https://data.visitkorea.or.kr/page/"):
            raise ValueError("DISPLAY_PHOTO_SOURCE_REQUIRED")
        return self


class DisplayPhotoCatalog(StrictContract):
    schema_version: Literal["display-photos.v1"] = "display-photos.v1"
    release_sha256: Sha256
    photos: dict[StableId, tuple[DisplayPhoto, ...]]
    catalog_sha256: Sha256

    @model_validator(mode="after")
    def seal(self) -> Self:
        if self.catalog_sha256 != canonical_sha256(
            self.model_dump(mode="json", exclude={"catalog_sha256"})
        ):
            raise ValueError("DISPLAY_PHOTO_CATALOG_DIGEST_MISMATCH")
        for photos in self.photos.values():
            if len({p.url for p in photos}) != len(photos):
                raise ValueError("DISPLAY_PHOTO_DUPLICATE_URL")
        return self

    def for_place(
        self, release_sha256: str, place_id: str, *, noncommercial: bool
    ) -> tuple[dict[str, str], ...]:
        if release_sha256 != self.release_sha256:
            return ()
        return tuple(
            photo.model_dump()
            for photo in self.photos.get(place_id, ())
            if noncommercial or photo.license not in {"KOGL_TYPE_2", "KOGL_TYPE_4"}
        )


def load_display_photos(directory: Path | None) -> DisplayPhotoCatalog | None:
    if directory is None or not (directory / "display-photos.json").is_file():
        return None
    catalog = DisplayPhotoCatalog.model_validate_json(
        (directory / "display-photos.json").read_bytes()
    )
    release = json.loads((directory / "release.json").read_text())
    if catalog.release_sha256 != release["release_sha256"] or not set(catalog.photos) <= {
        member["place_id"] for member in release["members"]
    }:
        raise ValueError("DISPLAY_PHOTOS_OUTSIDE_PINNED_RELEASE")
    return catalog
