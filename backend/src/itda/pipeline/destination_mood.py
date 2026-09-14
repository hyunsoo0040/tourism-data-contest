"""Versioned rights-bound original photos → independent stratified visual mood."""

from __future__ import annotations

import hashlib
import os
from dataclasses import dataclass
from datetime import date, datetime
from pathlib import Path

from itda.analysis.image.preprocessing import (
    ImagePreprocessingCandidate,
    ImagePreprocessingPolicy,
    ImageProjection,
    preprocess_image,
)
from itda.analysis.image.secure_read import ApprovedImageMaterialization, RightsBoundImage
from itda.analysis.image.selection import (
    AppearanceSelectionFeature,
    appearance_selection_feature,
    select_diverse_appearance,
)
from itda.contracts.catalog_optional_media import ImageMediumState
from itda.contracts.destination_mood import (
    DestinationImageDecision,
    DestinationMoodBundle,
    DestinationMoodImage,
    DestinationMoodStratum,
    LightContext,
    Season,
)
from itda.contracts.source_assessment import (
    PlaceMatch,
    SourceEvidence,
    SourceReceipt,
    SourceService,
)
from itda.contracts.visual_mood import MOOD_POLICY_SHA256, PhotoMoodCandidateSet
from itda.domain.canonical import canonical_sha256
from itda.domain.visual_mood import aggregate_moods, build_candidate_set
from itda.photo.model_control import ModelBatchControl, ModelBatchPaused
from itda.photo.provider.mood import GlmMoodProvider, MoodProvider
from itda.pipeline.destination_evidence import atomic_json, cache_lock

_PREPROCESSING = ImagePreprocessingPolicy(output_max_width=1024, output_max_height=1024)
SELECTION_POLICY = {
    "version": "destination-appearance-selection-v1",
    "max_images": 3,
    "minimum_short_side": 320,
    "aspect_ratio_milli": [400, 2500],
    "perceptual_duplicate": {"phash_max_distance": 6, "rgb_histogram_l1_max": 600},
    "selection": "quality-first, then context coverage and max-min perceptual/color diversity",
    "temporary_event": "EXCLUDE",
    "rights": "KOGL_TYPE_1_ONLY",
    "strata": "season and light context; UNKNOWN stays explicit",
    "aggregation": "one representative per distinct scene; equal supported-image means",
    "preprocessing_policy_sha256": _PREPROCESSING.policy_sha256,
}
SELECTION_POLICY_SHA256 = canonical_sha256(SELECTION_POLICY)


class CachedDestinationMoodProvider:
    """Official-photo cache only; never used for private uploaded user images."""

    provider_id = GlmMoodProvider.provider_id

    def __init__(
        self,
        *,
        api_key: str,
        cache_directory: Path,
        live: bool = True,
        batch_control: ModelBatchControl | None = None,
    ) -> None:
        self._directory = cache_directory
        self._live = live

        def audit(exchange):
            exchange["exchange_sha256"] = canonical_sha256(exchange)
            atomic_json(
                self._directory
                / "exchanges"
                / (exchange["image_sha256"] + "-" + exchange["response_bytes_sha256"] + ".json"),
                exchange,
            )

        self._provider = GlmMoodProvider(
            api_key=api_key,
            explicit_opt_in=True,
            audit_sink=audit,
            batch_control=batch_control,
        )

    def analyze(self, *, image_png: bytes, job_id: str, image_index: int) -> PhotoMoodCandidateSet:
        image_sha = hashlib.sha256(image_png).hexdigest()
        key = canonical_sha256(
            {
                "image_sha256": image_sha,
                "policy_sha256": MOOD_POLICY_SHA256,
                "provider_id": self.provider_id,
            }
        )
        path = self._directory / (key + ".json")
        with cache_lock(path):
            if path.is_file():
                batch = PhotoMoodCandidateSet.model_validate_json(path.read_bytes())
                if batch.payload_sha256 != image_sha or batch.provider_id != self.provider_id:
                    raise ValueError("destination mood cache identity mismatch")
                return build_candidate_set(
                    job_id=job_id,
                    image_index=image_index,
                    image_sha256=image_sha,
                    observations=tuple(c.observation for c in batch.candidates),
                    provider_id=self.provider_id,
                    analysis_kind="MODEL",
                    model="glm-5.3-flash",
                )
            if not self._live:
                raise ValueError("OFFLINE_DESTINATION_MOOD_CACHE_MISS")
            batch = self._provider.analyze(
                image_png=image_png, job_id=job_id, image_index=image_index
            )
            atomic_json(path, batch.model_dump(mode="json"))
            return batch


@dataclass(frozen=True, slots=True)
class DestinationImageAsset:
    asset_id: str
    place_id: str
    path: Path
    original_sha256: str
    receipt: SourceReceipt
    match: PlaceMatch
    license: str
    attribution_ko: str
    capture_date: date | None = None
    capture_month: str | None = None
    season: Season = "UNKNOWN"
    light_context: LightContext = "UNKNOWN"
    scene_group: str | None = None
    temporary_event: bool = False


def _decision(
    asset: DestinationImageAsset, code: str, reason: str, **extra: object
) -> DestinationImageDecision:
    return DestinationImageDecision.model_validate(
        {
            "asset_id": asset.asset_id,
            "original_sha256": asset.original_sha256,
            "license": asset.license
            if asset.license in {"KOGL_TYPE_1", "KOGL_TYPE_3"}
            else "UNKNOWN",
            "receipt": asset.receipt,
            "match": asset.match,
            "capture_date": asset.capture_date,
            "capture_month": asset.capture_month,
            "season": asset.season,
            "light_context": asset.light_context,
            "decision": code,
            "reason": reason,
            **extra,
        }
    )


def _preprocess(asset: DestinationImageAsset) -> ImageProjection | None:
    rights_digest = canonical_sha256(
        {
            "asset_id": asset.asset_id,
            "license": asset.license,
            "receipt": asset.receipt.model_dump(mode="json"),
            "match": asset.match.model_dump(mode="json"),
            "attribution_ko": asset.attribution_ko,
        }
    )
    approved = ApprovedImageMaterialization(
        rights_leaf_id=asset.asset_id,
        rights_leaf_sha256=rights_digest,
        content_sha256=asset.original_sha256,
    )
    path = Path(asset.path)
    # Reuse the audited no-follow read, byte hash, decoder bounds, EXIF orientation,
    # visible-alpha composite and metadata-free RGB PNG encoder. No raw-path output.
    descriptor = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        result = preprocess_image(
            root_fd=descriptor,
            candidate=ImagePreprocessingCandidate(
                media_state=ImageMediumState.QUALIFIED,
                image=RightsBoundImage(
                    relative_path=path.name,
                    rights_leaf_id=asset.asset_id,
                    rights_leaf_sha256=rights_digest,
                    content_sha256=asset.original_sha256,
                ),
            ),
            approved=approved,
            policy=_PREPROCESSING,
        )
        return result.projection
    finally:
        os.close(descriptor)


def analyze_destination_mood(
    *,
    place_id: str,
    raw_profile_sha256: str,
    source_release_sha256: str,
    assets: tuple[DestinationImageAsset, ...],
    provider: MoodProvider | None,
    assessed_at: datetime,
) -> DestinationMoodBundle:
    """No image can enter textual scores; missing photos/provider preserve empty mood."""
    if len({asset.asset_id for asset in assets}) != len(assets) or len(assets) > 100:
        raise ValueError("destination image inventory is duplicated or unbounded")
    by_id = {asset.asset_id: asset for asset in assets}
    decisions: dict[str, DestinationImageDecision] = {}
    projected: dict[str, ImageProjection] = {}
    features: dict[str, AppearanceSelectionFeature] = {}
    for asset in sorted(assets, key=lambda row: row.asset_id):
        if asset.license != "KOGL_TYPE_1":
            decisions[asset.asset_id] = _decision(
                asset, "RIGHTS_EXCLUDED", "원본 표시 전용 또는 분석 이용권 미확인"
            )
            continue
        if asset.receipt.status != "AVAILABLE" or asset.receipt.service not in {
            SourceService.TOUR,
            SourceService.GALLERY,
            SourceService.CAMPING,
        }:
            decisions[asset.asset_id] = _decision(
                asset, "SOURCE_UNAVAILABLE", "사용 가능한 공식 사진 출처 미확인"
            )
            continue
        if (
            asset.place_id != place_id
            or asset.match.place_id != place_id
            or asset.match.state != "MATCHED"
            or asset.match.service != asset.receipt.service
        ):
            decisions[asset.asset_id] = _decision(
                asset, "MATCH_REJECTED", "공식 사진의 관광지 동일성이 확인되지 않음"
            )
            continue
        if asset.temporary_event:
            decisions[asset.asset_id] = _decision(
                asset, "TEMPORARY_EVENT_EXCLUDED", "일시적 행사 장면은 대표 분위기에서 제외"
            )
            continue
        try:
            projection = _preprocess(asset)
        except (OSError, ValueError):
            projection = None
        if projection is None:
            decisions[asset.asset_id] = _decision(
                asset, "PREPROCESSING_FAILED", "원본 바이트·권한·안전한 이미지 디코딩 검증 실패"
            )
            continue
        width, height = projection.width, projection.height
        feature = appearance_selection_feature(
            asset_id=asset.asset_id,
            projection=projection,
            stratum=(asset.season, asset.light_context),
            scene_group=asset.scene_group,
        )
        common = {
            "sanitized_sha256": projection.asset_sha256,
            "perceptual_hash": feature.perceptual_hash,
            "quality_score_milli": feature.quality_score_milli,
        }
        if min(width, height) < 320 or not 400 <= width * 1000 // height <= 2500:
            decisions[asset.asset_id] = _decision(
                asset, "LOW_QUALITY", "해상도 또는 잘린 구도가 대표 사진 기준에 미달", **common
            )
            continue
        projected[asset.asset_id] = projection
        features[asset.asset_id] = feature
    selected, rejected = select_diverse_appearance(tuple(features.values()))
    for asset_id, (code, duplicate) in rejected.items():
        feature = features[asset_id]
        decisions[asset_id] = _decision(
            by_id[asset_id],
            code,
            "중복·동일 장면 또는 대표 사진 상한에 따른 제외",
            duplicate_of_asset_id=duplicate,
            sanitized_sha256=projected[asset_id].asset_sha256,
            perceptual_hash=feature.perceptual_hash,
            quality_score_milli=feature.quality_score_milli,
        )
    job_id = canonical_sha256(
        {
            "scope": "destination-mood.v1",
            "place_id": place_id,
            "raw_profile_sha256": raw_profile_sha256,
            "source_release_sha256": source_release_sha256,
            "selection_policy_sha256": SELECTION_POLICY_SHA256,
        }
    )
    images = []
    for index, asset_id in enumerate(selected, 1):
        asset = by_id[asset_id]
        projection = projected[asset_id]
        feature = features[asset_id]
        common = {
            "sanitized_sha256": projection.asset_sha256,
            "perceptual_hash": feature.perceptual_hash,
            "quality_score_milli": feature.quality_score_milli,
        }
        if provider is None:
            decisions[asset_id] = _decision(
                asset, "MODEL_UNAVAILABLE", "분위기 분석 모델이 연결되지 않음", **common
            )
            continue
        try:
            batch = provider.analyze(
                image_png=projection.encoded_bytes, job_id=job_id, image_index=index
            )
            batch = PhotoMoodCandidateSet.model_validate_json(batch.model_dump_json())
            if (
                batch.job_id != job_id
                or batch.image_index != index
                or batch.payload_sha256 != projection.asset_sha256
                or batch.provider_id != provider.provider_id
            ):
                raise ValueError("provider response does not bind actual image input")
        except ModelBatchPaused:
            raise
        except Exception:
            # A bounded provider's typed failure is preserved per image; its raw
            # message may contain request data and never belongs in the artifact.
            decisions[asset_id] = _decision(
                asset, "MODEL_REJECTED", "모델 응답 실패 또는 입력·분위기 계약 검증 실패", **common
            )
            continue
        excerpt = f"사진 식별자 {asset.asset_id}; {asset.attribution_ko}; {asset.license}"
        evidence = SourceEvidence(
            evidence_id="image:"
            + canonical_sha256(
                {
                    "asset": asset.asset_id,
                    "original": asset.original_sha256,
                    "receipt": asset.receipt.model_dump(mode="json"),
                }
            ),
            receipt=asset.receipt,
            place_match=asset.match,
            scope="PLACE",
            modality="IMAGE_PIXELS",
            source_field="official_image_metadata",
            excerpt=excerpt,
            quote=excerpt,
            image_sha256=asset.original_sha256,
            image_license="KOGL_TYPE_1",
        )
        images.append(
            DestinationMoodImage(
                asset_id=asset_id,
                original_sha256=asset.original_sha256,
                sanitized_sha256=projection.asset_sha256,
                preprocessing_policy_sha256=projection.preprocessing_policy_sha256,
                preprocessing_audit_sha256=projection.audit_sha256,
                capture_date=asset.capture_date,
                capture_month=asset.capture_month,
                season=asset.season,
                light_context=asset.light_context,
                scene_group=canonical_sha256(
                    {
                        "scene": asset.scene_group or asset.original_sha256,
                        "season": asset.season,
                        "light": asset.light_context,
                    }
                ),
                attribution_ko=asset.attribution_ko,
                evidence=evidence,
                candidate_set=batch,
            )
        )
        decisions[asset_id] = _decision(
            asset, "ANALYZED", "직접 입력한 사진의 외관·빛·색·구도만 분석", **common
        )
    strata = []
    for season, light in sorted({(image.season, image.light_context) for image in images}):
        group = tuple(
            image for image in images if (image.season, image.light_context) == (season, light)
        )
        strata.append(
            DestinationMoodStratum(
                season=season,
                light_context=light,
                asset_ids=tuple(sorted(image.asset_id for image in group)),
                moods=aggregate_moods(tuple(image.candidate_set for image in group)),
            )
        )
    payload = {
        "schema_version": "destination-mood.v1",
        "authority_scope": "VISUAL_MOOD_ONLY",
        "place_id": place_id,
        "raw_profile_sha256": raw_profile_sha256,
        "source_release_sha256": source_release_sha256,
        "assessed_at": assessed_at.isoformat().replace("+00:00", "Z"),
        "mood_policy_sha256": MOOD_POLICY_SHA256,
        "selection_policy_sha256": SELECTION_POLICY_SHA256,
        "images": [i.model_dump(mode="json") for i in images],
        "decisions": [decisions[k].model_dump(mode="json") for k in sorted(decisions)],
        "strata": [s.model_dump(mode="json") for s in strata],
        "limit_ko": "사진은 촬영 당시의 대략적인 분위기만 보여줍니다. "
        "계절·밤낮 자료는 나누어 해석하며, 촬영 시점이 없으면 미확인입니다. "
        "유사한 사진은 중복 제외하며 현재 혼잡·운영·시설·역사 사실을 뜻하지 않습니다.",
    }
    return DestinationMoodBundle.model_validate(
        payload | {"bundle_sha256": canonical_sha256(payload)}
    )
