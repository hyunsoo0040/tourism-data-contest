"""Production image selection and mood artifacts, with no external provider calls."""

from __future__ import annotations

import hashlib
from dataclasses import replace
from datetime import UTC, date, datetime
from io import BytesIO

import pytest
from itda.contracts.destination_mood import DestinationMoodBundle
from itda.contracts.source_assessment import PlaceMatch, SourceReceipt, SourceService
from itda.contracts.visual_mood import MoodObservation, VisualMoodDimension
from itda.domain.canonical import canonical_sha256
from itda.domain.visual_mood import build_candidate_set
from itda.pipeline.destination_mood import DestinationImageAsset, analyze_destination_mood
from PIL import Image, ImageDraw

NOW = datetime(2026, 9, 9, tzinfo=UTC)


class Provider:
    provider_id = "mood-fixture-provider"

    def __init__(self, *, unknown=False):
        self.calls = []
        self.unknown = unknown

    def analyze(self, *, image_png, job_id, image_index):
        assert image_png.startswith(b"\x89PNG\r\n\x1a\n")
        assert b"PRIVATE_METADATA" not in image_png
        with Image.open(BytesIO(image_png)) as image:
            assert image.mode == "RGB" and not image.getexif()
        self.calls.append((job_id, image_index, hashlib.sha256(image_png).hexdigest()))
        return build_candidate_set(
            job_id=job_id,
            image_index=image_index,
            image_sha256=hashlib.sha256(image_png).hexdigest(),
            provider_id=self.provider_id,
            analysis_kind="MODEL",
            model="glm-5.3-flash",
            observations=tuple(
                MoodObservation(
                    dimension=d,
                    state="UNKNOWN" if self.unknown else "OBSERVED",
                    level=None if self.unknown else image_index,
                    certainty="LOW" if self.unknown else "HIGH",
                )
                for d in VisualMoodDimension
            ),
        )


def asset(tmp_path, name, *, color=(30, 150, 60), size=(640, 480), shape=0, **changes):
    picture = Image.new("RGB", size, color)
    draw = ImageDraw.Draw(picture)
    if shape == 0:
        draw.rectangle((20, 20, size[0] // 2, size[1] // 2), fill="white")
    elif shape == 1:
        draw.ellipse((size[0] // 3, 30, size[0] - 20, size[1] - 20), fill="black")
    else:
        draw.polygon([(0, size[1]), (size[0], size[1]), (size[0] // 2, 0)], fill="red")
    exif = Image.Exif()
    exif[0x010E] = "PRIVATE_METADATA"
    path = tmp_path / (name + ".jpg")
    picture.save(path, format="JPEG", exif=exif, quality=95)
    receipt = SourceReceipt(
        service=SourceService.GALLERY,
        operation="gallerySearchList1",
        dataset_id="15101914",
        request_scope={"keyword": "불국사"},
        retrieved_at=NOW,
        reference_date=NOW.date(),
        status="AVAILABLE",
        http_status=200,
        response_sha256="a" * 64,
        reason="recorded official shape",
    )
    match = PlaceMatch(
        place_id="place:bulguksa",
        service=SourceService.GALLERY,
        provider_entity_id=name,
        state="MATCHED",
        method="CURATED_CROSSWALK",
        region_code="47130",
        evidence=("fixture exact place crosswalk",),
    )
    data = dict(
        asset_id=name,
        place_id="place:bulguksa",
        path=path,
        original_sha256=hashlib.sha256(path.read_bytes()).hexdigest(),
        receipt=receipt,
        match=match,
        license="KOGL_TYPE_1",
        attribution_ko="한국관광공사 · 촬영자 표본",
    )
    data.update(changes)
    return DestinationImageAsset(**data)


def analyze(assets, provider):
    return analyze_destination_mood(
        place_id="place:bulguksa",
        raw_profile_sha256="b" * 64,
        source_release_sha256="c" * 64,
        assets=tuple(assets),
        provider=provider,
        assessed_at=NOW,
    )


def test_authorized_original_is_sanitized_and_bound_to_replayable_mood(tmp_path):
    sample = asset(
        tmp_path,
        "gallery-photo",
        capture_date=date(2014, 4, 1),
        capture_month="2014-04",
        season="SPRING",
        light_context="DAY",
    )
    provider = Provider()
    result = analyze((sample,), provider)
    assert len(provider.calls) == 1 and len(result.images) == 1
    image = result.images[0]
    assert image.original_sha256 == sample.original_sha256
    assert image.sanitized_sha256 == provider.calls[0][2]
    assert image.original_sha256 != image.sanitized_sha256
    assert image.capture_date == date(2014, 4, 1) and image.evidence.image_license == "KOGL_TYPE_1"
    assert image.evidence.place_match.place_id == "place:bulguksa"
    assert all(mood.value == 25 for mood in result.strata[0].moods)
    assert DestinationMoodBundle.model_validate_json(result.model_dump_json()) == result
    assert "PRIVATE_METADATA" not in result.model_dump_json()
    assert str(tmp_path) not in result.model_dump_json()
    assert set(result.model_dump()).isdisjoint({"H", "E", "R", "M3", "facts", "opening_hours"})


def test_batch_quota_stop_is_not_recorded_as_a_rejected_photo(tmp_path):
    import pytest
    from itda.photo.model_control import ModelBatchPaused

    class LimitedProvider:
        provider_id = "quota-fixture"

        def analyze(self, **kwargs):
            raise ModelBatchPaused({"http_status": 429})

    with pytest.raises(ModelBatchPaused):
        analyze((asset(tmp_path, "quota-photo"),), LimitedProvider())


def test_rights_wrong_place_unavailable_event_and_hash_failure_never_reach_model(tmp_path):
    source = asset(tmp_path, "original")
    assets = (
        replace(source, asset_id="type3", license="KOGL_TYPE_3"),
        replace(source, asset_id="unknown-rights", license="UNKNOWN"),
        replace(source, asset_id="wrong-place", place_id="place:other"),
        replace(source, asset_id="event", temporary_event=True),
        replace(source, asset_id="tamper", original_sha256="f" * 64),
        replace(
            source,
            asset_id="source-unavailable",
            receipt=source.receipt.model_copy(update={"status": "UNAVAILABLE"}),
        ),
    )
    provider = Provider()
    result = analyze(assets, provider)
    assert not provider.calls and not result.images and not result.strata
    reasons = {row.asset_id: row.decision for row in result.decisions}
    assert reasons == {
        "type3": "RIGHTS_EXCLUDED",
        "unknown-rights": "RIGHTS_EXCLUDED",
        "wrong-place": "MATCH_REJECTED",
        "event": "TEMPORARY_EVENT_EXCLUDED",
        "tamper": "PREPROCESSING_FAILED",
        "source-unavailable": "SOURCE_UNAVAILABLE",
    }


def test_selection_is_order_invariant_and_exact_duplicates_have_no_weight(tmp_path):
    original = asset(tmp_path, "good-large", size=(960, 720))
    duplicate = replace(original, asset_id="duplicate")
    blue = asset(tmp_path, "blue", color=(10, 70, 220), shape=1)
    night = asset(tmp_path, "night", color=(10, 10, 20), shape=2, light_context="NIGHT")
    small = asset(tmp_path, "small", size=(100, 100))
    provider = Provider()
    first = analyze((original, duplicate, blue, night, small), provider)
    second = analyze((small, night, blue, duplicate, original), Provider())
    assert first == second
    assert len(first.images) == 3 and len(provider.calls) == 3
    decisions = {d.asset_id: d.decision for d in first.decisions}
    assert sum(code == "EXACT_DUPLICATE" for code in decisions.values()) == 1
    assert decisions["small"] == "LOW_QUALITY"
    assert len({image.original_sha256 for image in first.images}) == 3


def test_near_duplicates_and_same_scene_do_not_dominate(tmp_path):
    original = asset(tmp_path, "original", color=(30, 150, 60))
    # Different original encoding, identical decoded scene: pHash should remove
    # it even though byte hashing cannot identify an exact source duplicate.
    near_path = tmp_path / "near.png"
    with Image.open(original.path) as decoded:
        decoded.save(near_path, format="PNG")
    near = replace(
        original,
        asset_id="near",
        path=near_path,
        original_sha256=hashlib.sha256(near_path.read_bytes()).hexdigest(),
    )
    scene_a = asset(tmp_path, "scene-a", color=(10, 50, 220), shape=1, scene_group="lake")
    scene_b = asset(tmp_path, "scene-b", color=(10, 20, 25), shape=2, scene_group="lake")
    result = analyze((original, near, scene_a, scene_b), Provider())
    codes = [decision.decision for decision in result.decisions]
    assert "PERCEPTUAL_DUPLICATE" in codes and "SCENE_ALTERNATE" in codes
    assert len(result.images) == 2


def test_season_and_night_contexts_are_not_collapsed_into_one_current_mood(tmp_path):
    day = asset(tmp_path, "day", season="SPRING", light_context="DAY")
    night = asset(
        tmp_path, "night", color=(5, 10, 50), shape=1, season="WINTER", light_context="NIGHT"
    )
    result = analyze((day, night), Provider())
    assert [(stratum.season, stratum.light_context) for stratum in result.strata] == [
        ("SPRING", "DAY"),
        ("WINTER", "NIGHT"),
    ]
    assert all(len(stratum.asset_ids) == 1 for stratum in result.strata)
    assert result.images[0].capture_date is None


def test_quality_and_diversity_choose_representatives_instead_of_first_three(tmp_path):
    samples = (
        asset(tmp_path, "first-green", color=(20, 180, 40)),
        asset(tmp_path, "second-blue", color=(20, 40, 180), shape=1),
        asset(tmp_path, "third-night", color=(5, 5, 15), shape=2, light_context="NIGHT"),
        asset(tmp_path, "last-high-quality", color=(170, 80, 20), size=(1200, 900), shape=2),
    )
    result = analyze(samples, Provider())
    assert len(result.images) == 3
    assert "last-high-quality" in {image.asset_id for image in result.images}
    assert sum(d.decision == "CAPACITY_EXCLUDED" for d in result.decisions) == 1


def test_missing_or_unknown_images_have_no_fabricated_mood(tmp_path):
    assert not analyze((), Provider()).strata
    source = asset(tmp_path, "image")
    unavailable = analyze((source,), None)
    assert not unavailable.images and unavailable.decisions[0].decision == "MODEL_UNAVAILABLE"
    unknown = analyze((source,), Provider(unknown=True))
    assert all(mood.value is None and mood.distinct_images == 0 for mood in unknown.strata[0].moods)


def test_wrong_image_provider_output_and_tampered_aggregate_are_rejected(tmp_path):
    source = asset(tmp_path, "image")

    class WrongImage(Provider):
        def analyze(self, **kwargs):
            return super().analyze(**kwargs).model_copy(update={"payload_sha256": "f" * 64})

    rejected = analyze((source,), WrongImage())
    assert rejected.decisions[0].decision == "MODEL_REJECTED" and not rejected.strata
    valid = analyze((source,), Provider()).model_dump(mode="json")
    valid["strata"][0]["moods"][0]["value"] = 100
    valid["bundle_sha256"] = canonical_sha256(
        {k: v for k, v in valid.items() if k != "bundle_sha256"}
    )
    with pytest.raises(ValueError, match="aggregate differs"):
        DestinationMoodBundle.model_validate(valid)


def test_symlink_image_is_rejected_without_reading_or_provider_call(tmp_path):
    source = asset(tmp_path, "source")
    alias = tmp_path / "linked.jpg"
    alias.symlink_to(source.path)
    provider = Provider()
    result = analyze((replace(source, path=alias),), provider)
    assert not provider.calls and result.decisions[0].decision == "PREPROCESSING_FAILED"
