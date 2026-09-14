"""Live-capable public destination sources with immutable resumable response cache."""

from __future__ import annotations

import base64
import fcntl
import hashlib
import json
import math
import os
import re
import tempfile
import threading
from contextlib import contextmanager
from dataclasses import asdict
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any, Literal
from urllib.parse import urlsplit, urlunsplit
from zoneinfo import ZoneInfo

import httpx
from pydantic import model_validator

from itda.collectors.base import (
    CollectionError,
    OfficialApiClient,
    RequestPolicy,
)
from itda.collectors.kto import KorService2Client
from itda.collectors.odii import OdiiClient
from itda.collectors.tourism_photo import TourismPhotoGalleryClient
from itda.contracts.base import Sha256, StrictContract
from itda.contracts.mvp_public_catalog import PublicPlace
from itda.contracts.source_assessment import (
    SOURCE_DATASETS,
    PlaceMatch,
    SourceEvidence,
    SourceReceipt,
    SourceService,
)
from itda.domain.canonical import canonical_sha256
from itda.operating.service import CATEGORY_CONTENT_TYPE
from itda.pipeline.source_authority import prepare_source_text
from itda.tourism.accessibility import (
    CanonicalTourismPlace,
    provider_items,
    region_location_matches,
)

SOURCE_COLLECTION_VERSION = "destination-evidence-v1"
_SOURCE_HTTP_SEMAPHORE = threading.BoundedSemaphore(3)


@contextmanager
def cache_lock(path: Path):
    path.parent.mkdir(parents=True, exist_ok=True)
    with (path.parent / ("." + path.name + ".lock")).open("a+b") as lock:
        fcntl.flock(lock.fileno(), fcntl.LOCK_EX)
        try:
            yield
        finally:
            fcntl.flock(lock.fileno(), fcntl.LOCK_UN)


def atomic_bytes(path: Path, payload: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, temporary = tempfile.mkstemp(prefix=".pending-", dir=path.parent)
    try:
        with os.fdopen(fd, "wb") as stream:
            stream.write(payload)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def atomic_json(path: Path, payload: Any) -> None:
    atomic_bytes(
        path, (json.dumps(payload, ensure_ascii=False, sort_keys=True, indent=2) + "\n").encode()
    )


def normalized(value: object) -> str:
    return re.sub(r"[\W_]+", "", str(value or "").casefold())


def aliases_for(name: str, region_name: str | None = None) -> tuple[str, ...]:
    plain = re.sub(r"\[[^]]*\]|\([^)]*\)", "", name).strip()
    if region_name is not None:
        # New national inputs derive search aliases only from their own official
        # administrative label. A whitespace boundary preserves names like 서울숲.
        prefixes = set(region_name.split())
        prefixes.update(
            re.sub(r"(?:특별자치도|특별자치시|특별시|광역시|도|시|군|구)$", "", token)
            for token in tuple(prefixes)
        )
        prefixes = {prefix for prefix in prefixes if len(prefix) >= 2}
        aliases = {name, plain}
        shortened = plain
        while True:
            prefix = next((p for p in sorted(prefixes) if shortened.startswith(p + " ")), None)
            if prefix is None:
                break
            shortened = shortened[len(prefix) :].strip()
            aliases.add(shortened)
        return tuple(sorted(alias for alias in aliases if alias))
    aliases = {name, plain, re.sub(r"^경주\s*", "", plain).strip()}
    # Explicit place-name aliases verified against official gallery metadata in
    # the September 2026 source audit; these never bypass the locality check.
    if normalized(plain) == "흥무로벚꽃길":
        aliases.update({"경주 흥무로", "흥무로"})
    return tuple(sorted(a for a in aliases if a))


def canonical_place(place: PublicPlace) -> CanonicalTourismPlace:
    return CanonicalTourismPlace(
        place_id=place.place_id,
        name_ko=place.name_ko,
        address=place.address_ko,
        latitude=place.latitude,
        longitude=place.longitude,
        region_code=place.region_code or "47130",
        region_name=place.administrative_area if place.region_code else None,
        aliases=aliases_for(
            place.name_ko,
            place.administrative_area if place.place_id.startswith("public:korea:") else None,
        ),
        provider_content_id=next(
            (r.source_id for r in place.provider_crosswalk if r.provider == "TOUR_API"), None
        ),
    )


def _distance(place: CanonicalTourismPlace, row: dict[str, Any]) -> float | None:
    try:
        lat, lon = (
            float(str(row.get("mapY", row.get("mapy")))),
            float(str(row.get("mapX", row.get("mapx")))),
        )
        if (
            not (-90 <= lat <= 90 and -180 <= lon <= 180)
            or place.latitude is None
            or place.longitude is None
        ):
            return None
        p, q = math.radians(place.latitude), math.radians(lat)
        a = (
            math.sin((q - p) / 2) ** 2
            + math.cos(p) * math.cos(q) * math.sin(math.radians(lon - place.longitude) / 2) ** 2
        )
        return 6_371_000 * 2 * math.asin(min(1, math.sqrt(a)))
    except (TypeError, ValueError):
        return None


def _match(
    place: CanonicalTourismPlace,
    service: SourceService,
    entity: str | None,
    accepted: bool,
    reason: str,
    *,
    distance: float | None = None,
    method: str = "EXACT_NAME_AND_LOCATION",
) -> PlaceMatch:
    return PlaceMatch.model_validate(
        {
            "place_id": place.place_id,
            "service": service,
            "provider_entity_id": entity if accepted else None,
            "state": "MATCHED" if accepted else "NOT_MATCHED",
            "method": method if accepted else None,
            "region_code": place.region_code,
            "evidence": [reason],
            "distance_meters": distance,
        }
    )


def match_odii(place: CanonicalTourismPlace, row: dict[str, Any]) -> PlaceMatch:
    distance = _distance(place, row)
    accepted = bool(
        row.get("tid")
        and normalized(row.get("title"))
        in {normalized(a) for a in (*aliases_for(place.name_ko, place.region_name), *place.aliases)}
        and distance is not None
        and distance <= 150
    )
    return _match(
        place,
        SourceService.ODII,
        str(row.get("tid", "")),
        accepted,
        "정확한 명칭과 기준좌표 150m 이내 일치" if accepted else "정확한 명칭·좌표 연결 근거 없음",
        distance=distance,
    )


def match_gallery(
    place: CanonicalTourismPlace, row: dict[str, Any], *, name_unique: bool = True
) -> PlaceMatch:
    locality = row.get("galPhotographyLocation")
    accepted = bool(
        name_unique
        and row.get("galContentId")
        and region_location_matches(place, locality)
        and normalized(row.get("galTitle"))
        in {normalized(a) for a in (*aliases_for(place.name_ko, place.region_name), *place.aliases)}
    )
    return _match(
        place,
        SourceService.GALLERY,
        str(row.get("galContentId", "")),
        accepted,
        (
            f"공식 촬영지역 {place.region_label} 및 목록 내 유일한 정확한 장소명/명시적 별칭 일치; "
            "사진 좌표는 미제공"
        )
        if accepted
        else "공식 촬영지역·유일한 명칭 연결 근거 없음",
        method="EXACT_NAME_AND_OFFICIAL_LOCATION",
    )


def evidence_from_fields(
    receipt: SourceReceipt,
    match: PlaceMatch,
    row: dict[str, Any],
    fields: tuple[str, ...],
    *,
    identity_version: Literal["v1", "v2"] = "v1",
) -> tuple[tuple[SourceEvidence, ...], tuple[dict[str, Any], ...]]:
    if receipt.status != "AVAILABLE" or match.state != "MATCHED":
        return (), ()
    evidence: list[SourceEvidence] = []
    lineage: list[dict[str, Any]] = []
    for field in fields:
        raw = row.get(field)
        if not isinstance(raw, str) or not raw.strip():
            continue
        prepared = prepare_source_text(raw, character_limit=4000)
        if not prepared.text:
            continue
        payload: dict[str, Any] = {
            "receipt": receipt.model_dump(mode="json"),
            "match": match.model_dump(mode="json"),
            "field": field,
            "text": prepared.text,
        }
        if identity_version == "v2":
            payload = {
                "identity_version": "semantic-evidence-v2",
                "place_id": match.place_id,
                "service": receipt.service.value,
                "operation": receipt.operation,
                "provider_entity_id": match.provider_entity_id,
                "field": field,
                "excerpt": prepared.text,
                "raw_response_sha256": receipt.response_sha256,
            }
        evidence.append(
            SourceEvidence(
                evidence_id="evidence:" + canonical_sha256(payload),
                receipt=receipt,
                place_match=match,
                scope="PLACE",
                modality="TEXT" if field in {"overview", "script", "infotext"} else "STRUCTURED",
                source_field=field,
                excerpt=prepared.text,
                quote=prepared.text,
            )
        )
        lineage.append(
            {
                "evidence_id": evidence[-1].evidence_id,
                "identity_version": identity_version,
                "field": field,
                **asdict(prepared),
            }
        )
    return tuple(evidence), tuple(lineage)


class DestinationEvidenceSnapshot(StrictContract):
    schema_version: Literal["destination-evidence.v1"] = "destination-evidence.v1"
    place: CanonicalTourismPlace
    category: str
    catalog_row_sha256: Sha256
    collected_at: datetime
    receipts: tuple[SourceReceipt, ...]
    raw_responses: tuple[dict[str, Any], ...]
    evidence: tuple[SourceEvidence, ...]
    text_lineage: tuple[dict[str, Any], ...]
    images: tuple[dict[str, Any], ...]
    coverage: dict[str, Any]
    snapshot_sha256: Sha256

    @model_validator(mode="after")
    def validate_snapshot(self):
        raw_hashes = set()
        for row in self.raw_responses:
            raw = base64.b64decode(row["raw_body_base64"], validate=True)
            if hashlib.sha256(raw).hexdigest() != row["raw_response_sha256"]:
                raise ValueError("raw response hash mismatch")
            if json.loads(raw) != row["payload"]:
                raise ValueError("parsed raw response mismatch")
            raw_hashes.add(row["raw_response_sha256"])
        if any(
            r.status != "UNAVAILABLE" and r.response_sha256 not in raw_hashes for r in self.receipts
        ):
            raise ValueError("source receipt lacks exact raw bytes")
        if any(
            e.place_match is None
            or e.place_match.place_id != self.place.place_id
            or e.receipt not in self.receipts
            for e in self.evidence
        ):
            raise ValueError("destination evidence source/place binding mismatch")
        if self.snapshot_sha256 != canonical_sha256(
            self.model_dump(mode="json", exclude={"snapshot_sha256"})
        ):
            raise ValueError("destination source snapshot hash mismatch")
        return self


class OfficialSourceCache:
    """One sanitized response per request identity; live-enabled misses only."""

    def __init__(
        self,
        root: Path,
        *,
        clients: dict[SourceService, OfficialApiClient],
        live: bool,
        ttl_days: float = 1,
    ) -> None:
        self.root = root
        self.clients = clients
        self.live = live
        self.ttl = timedelta(days=ttl_days)
        self._semaphore = _SOURCE_HTTP_SEMAPHORE
        self.root.mkdir(parents=True, exist_ok=True)

    def fetch(
        self, service: SourceService, operation: str, params: dict[str, str]
    ) -> tuple[SourceReceipt, dict[str, Any] | None]:
        identity = canonical_sha256(
            {
                "service": service,
                "operation": operation,
                "scope": {**self.clients[service].common_parameters, **params},
            }
        )
        with cache_lock(self.root / (identity + ".json")):
            return self._fetch(service, operation, params)

    def _fetch(self, service, operation, params):
        scope = {**self.clients[service].common_parameters, **params}
        identity = canonical_sha256({"service": service, "operation": operation, "scope": scope})
        path = self.root / (identity + ".json")
        response = None
        cached_hit = False
        if path.is_file():
            cached = json.loads(path.read_text())
            if cached.get("cache_sha256") != canonical_sha256(
                {k: v for k, v in cached.items() if k != "cache_sha256"}
            ):
                raise ValueError("source cache integrity mismatch")
            if (
                cached.get("service") != service
                or cached.get("operation") != operation
                or cached.get("scope") != scope
            ):
                raise ValueError("source cache request identity mismatch")
            response = cached["response"]
            raw = base64.b64decode(response["raw_body_base64"], validate=True)
            if (
                response.get("request_scope") != scope
                or response.get("http_status") != 200
                or hashlib.sha256(raw).hexdigest() != response.get("raw_response_sha256")
                or json.loads(raw) != response.get("payload")
            ):
                raise ValueError("source cache response provenance mismatch")
            stamp = datetime.fromisoformat(response["retrieved_at"].replace("Z", "+00:00"))
            if datetime.now(UTC) - stamp > self.ttl:
                response = None
            else:
                cached_hit = True
        if response is None:
            if not self.live:
                return SourceReceipt(
                    service=service,
                    operation=operation,
                    dataset_id=SOURCE_DATASETS[service],
                    request_scope=scope,
                    retrieved_at=datetime.now(UTC),
                    status="UNAVAILABLE",
                    http_status=None,
                    response_sha256=None,
                    reason="OFFLINE_CACHE_MISS",
                ), None
            try:
                with self._semaphore:
                    collected = self.clients[service].request(
                        operation, params, explicit_opt_in=True
                    )
                response = collected.to_dict()
                payload = {
                    "service": service,
                    "operation": operation,
                    "scope": scope,
                    "response": response,
                }
                atomic_json(path, payload | {"cache_sha256": canonical_sha256(payload)})
            except CollectionError as error:
                return SourceReceipt(
                    service=service,
                    operation=operation,
                    dataset_id=SOURCE_DATASETS[service],
                    request_scope=scope,
                    retrieved_at=datetime.now(UTC),
                    status="UNAVAILABLE",
                    http_status=error.http_status,
                    response_sha256=error.raw_body_sha256,
                    reason=error.normalized_failure_reason or "PROVIDER_UNAVAILABLE",
                ), None
        stamp = datetime.fromisoformat(response["retrieved_at"].replace("Z", "+00:00"))
        rows = provider_items(response["payload"])
        receipt = SourceReceipt(
            service=service,
            operation=operation,
            dataset_id=SOURCE_DATASETS[service],
            request_scope=response["request_scope"],
            retrieved_at=stamp,
            reference_date=stamp.date(),
            status="AVAILABLE" if rows else "EMPTY",
            http_status=200,
            response_sha256=response["raw_response_sha256"],
            reason="OFFICIAL_RESPONSE" if rows else "NO_ROWS",
        )
        return receipt, {**response, "cache_reused": cached_hit}


def official_clients(
    key: str, odii_key: str | None = None
) -> dict[SourceService, OfficialApiClient]:
    policy = RequestPolicy(timeout_seconds=30, max_attempts=2, max_backoff_seconds=2)
    return {
        SourceService.TOUR: KorService2Client(service_key=key, policy=policy),
        SourceService.ODII: OdiiClient(service_key=odii_key or key, policy=policy),
        SourceService.GALLERY: TourismPhotoGalleryClient(service_key=key, policy=policy),
    }


def download_official_image(url: str, directory: Path) -> tuple[Path, str]:
    with (
        cache_lock(directory / (canonical_sha256({"url": url}) + ".image")),
        _SOURCE_HTTP_SEMAPHORE,
    ):
        return _download_official_image(url, directory)


def _download_official_image(url: str, directory: Path) -> tuple[Path, str]:
    parsed = urlsplit(url)
    if (
        parsed.hostname
        not in {"tong.visitkorea.or.kr", "cdn.visitkorea.or.kr", "korean.visitkorea.or.kr"}
        or parsed.username
        or parsed.password
        or parsed.query
        or parsed.port
    ):
        raise ValueError("unapproved official image URL")
    actual = urlunsplit(("https", parsed.netloc, parsed.path, "", ""))
    directory.mkdir(parents=True, exist_ok=True)
    index = directory / (canonical_sha256({"url": actual}) + ".json")
    if index.is_file():
        record = json.loads(index.read_text())
        if (
            record.get("url") != actual
            or re.fullmatch(r"[0-9a-f]{64}", str(record.get("sha256", ""))) is None
        ):
            raise ValueError("official photo cache URL identity mismatch")
        path = directory / record["sha256"]
        if path.is_file() and hashlib.sha256(path.read_bytes()).hexdigest() == record["sha256"]:
            return path, record["sha256"]
        raise ValueError("official photo cache mismatch")
    with (
        httpx.Client(timeout=30, follow_redirects=False, trust_env=False) as client,
        client.stream("GET", actual) as response,
    ):
        response.raise_for_status()
        body = bytearray()
        for chunk in response.iter_bytes():
            if len(body) + len(chunk) > 10 * 1024 * 1024:
                raise ValueError("official image exceeds bound")
            body.extend(chunk)
    digest = hashlib.sha256(body).hexdigest()
    path = directory / digest
    if not path.exists():
        atomic_bytes(path, bytes(body))
    atomic_json(
        index, {"url": actual, "sha256": digest, "retrieved_at": datetime.now(UTC).isoformat()}
    )
    return path, digest


def collect_destination(
    place: PublicPlace,
    cache: OfficialSourceCache,
    *,
    image_directory: Path,
    unique_names: set[str] | None = None,
    identity_version: Literal["v1", "v2"] = "v1",
) -> DestinationEvidenceSnapshot:
    canonical = canonical_place(place)
    receipts = []
    raws = []
    evidence: list[SourceEvidence] = []
    lineage: list[dict[str, Any]] = []
    images = []
    counts: dict[str, Any] = {}

    def get(service, operation, params):
        receipt, raw = cache.fetch(service, operation, params)
        if identity_version == "v2" and raw and isinstance(raw.get("modifiedtime"), str):
            try:
                modified = (
                    datetime.strptime(raw["modifiedtime"], "%Y%m%d%H%M%S")
                    .replace(tzinfo=ZoneInfo("Asia/Seoul"))
                    .astimezone(UTC)
                )
                receipt = SourceReceipt.model_validate(
                    receipt.model_dump(mode="json") | {"source_modified_at": modified}
                )
            except ValueError:
                pass
        receipts.append(receipt)
        if raw is not None:
            raws.append(raw)
        rows = provider_items(raw["payload"]) if raw else ()
        return receipt, rows

    cid = canonical.provider_content_id
    common = None
    tour_match = _match(canonical, SourceService.TOUR, cid, False, "공식 기본정보 연결 미확인")
    for operation in ("detailCommon2", "detailIntro2", "detailInfo2", "detailImage2"):
        params = {"contentId": cid or "", "numOfRows": "100", "pageNo": "1"}
        if operation in {"detailIntro2", "detailInfo2"}:
            params["contentTypeId"] = CATEGORY_CONTENT_TYPE[place.category]
        if operation == "detailImage2":
            params["imageYN"] = "Y"
        receipt, rows = get(SourceService.TOUR, operation, params)
        counts[operation] = len(rows)
        if operation == "detailCommon2":
            matched = [r for r in rows if str(r.get("contentid")) == cid]
            if len(matched) == 1:
                common = matched[0]
                distance = _distance(canonical, common)
                accepted = (
                    normalized(common.get("title")) in {normalized(a) for a in canonical.aliases}
                    and distance is not None
                    and distance <= 150
                )
                tour_match = _match(
                    canonical,
                    SourceService.TOUR,
                    cid,
                    accepted,
                    "TourAPI contentId·명칭·기준좌표 일치",
                    distance=distance,
                    method="EXACT_ID_AND_LOCATION",
                )
        for row in rows:
            if str(row.get("contentid")) != cid:
                continue
            fields: tuple[str, ...]
            if operation == "detailCommon2":
                fields = ("overview",)
            elif operation == "detailIntro2":
                fields = (
                    "expguide",
                    "expguideleports",
                    "expagerange",
                    "usetime",
                    "usetimeculture",
                    "usetimeleports",
                    "opentime",
                    "opentimefood",
                    "restdate",
                    "restdateshopping",
                    "parking",
                    "heritage1",
                    "heritage2",
                    "heritage3",
                )
            elif operation == "detailInfo2" and not re.search(
                r"시간|운영|휴무|주차|요금|문의", str(row.get("infoname", ""))
            ):
                fields = ("infotext",)
            else:
                fields = ()
            new, meta = evidence_from_fields(
                receipt, tour_match, row, fields, identity_version=identity_version
            )
            evidence.extend(new)
            lineage.extend(meta)
            if operation == "detailImage2" and row.get("originimgurl"):
                images.append(
                    {
                        "asset_id": "tour:" + str(row.get("serialnum") or canonical_sha256(row)),
                        "url": row["originimgurl"],
                        "license": "KOGL_TYPE_1"
                        if row.get("cpyrhtDivCd") == "Type1"
                        else str(row.get("cpyrhtDivCd", "UNKNOWN")),
                        "receipt": receipt.model_dump(mode="json"),
                        "match": tour_match.model_dump(mode="json"),
                        "attribution_ko": "한국관광공사 TourAPI · " + place.name_ko,
                        "metadata": row,
                    }
                )
    query = re.sub(r"^경주\s*", "", re.sub(r"\[[^]]*\]|\([^)]*\)", "", place.name_ko)).strip()
    if place.place_id.startswith("public:korea:"):
        query = min(canonical.aliases, key=lambda alias: (len(alias), alias))
        counts["name_alias_policy"] = "official-region-prefix-v1"
    odii_receipt, themes = get(
        SourceService.ODII, "themeSearchList", {"keyword": query, "numOfRows": "100", "pageNo": "1"}
    )
    odii_matches = [(r, match_odii(canonical, r)) for r in themes]
    odii_matches = [(r, m) for r, m in odii_matches if m.state == "MATCHED"]
    counts["odii_matched_themes"] = len(odii_matches)
    counts["odii_scripts"] = 0
    if len(odii_matches) == 1:
        theme, match = odii_matches[0]
        receipt, stories = get(
            SourceService.ODII,
            "storyBasedList",
            {
                "tid": str(theme["tid"]),
                "tlid": str(theme["tlid"]),
                "numOfRows": "100",
                "pageNo": "1",
            },
        )
        for row in stories:
            if str(row.get("tid")) != str(theme["tid"]):
                continue
            new, meta = evidence_from_fields(
                receipt, match, row, ("script",), identity_version=identity_version
            )
            evidence.extend(new)
            lineage.extend(meta)
            counts["odii_scripts"] += len(new)
    gallery_receipt, photos = get(
        SourceService.GALLERY,
        "gallerySearchList1",
        {"keyword": query, "numOfRows": "100", "pageNo": "1"},
    )
    if not photos and len(canonical.aliases) > 1:
        alternate = next((a for a in canonical.aliases if a != query and a != place.name_ko), None)
        if alternate:
            gallery_receipt, photos = get(
                SourceService.GALLERY,
                "gallerySearchList1",
                {"keyword": alternate, "numOfRows": "100", "pageNo": "1"},
            )
    matched_titles = sorted(
        {str(r.get("galTitle")) for r in photos if match_gallery(canonical, r).state == "MATCHED"}
    )
    detail_by_id = {}
    for title in matched_titles[:4]:
        detail_receipt, detail_rows = get(
            SourceService.GALLERY,
            "galleryDetailList1",
            {"title": title, "numOfRows": "100", "pageNo": "1"},
        )
        for r in detail_rows:
            if match_gallery(canonical, r).state == "MATCHED":
                detail_by_id[str(r["galContentId"])] = (detail_receipt, r)
    counts["gallery_matches"] = 0
    for row in photos:
        image_receipt, row = detail_by_id.get(str(row.get("galContentId")), (gallery_receipt, row))
        match = match_gallery(
            canonical,
            row,
            name_unique=unique_names is None or normalized(row.get("galTitle")) in unique_names,
        )
        if match.state != "MATCHED":
            continue
        counts["gallery_matches"] += 1
        images.append(
            {
                "asset_id": "gallery:" + str(row["galContentId"]),
                "url": row.get("galWebImageUrl", ""),
                "license": "KOGL_TYPE_1",
                "receipt": image_receipt.model_dump(mode="json"),
                "match": match.model_dump(mode="json"),
                "capture_month": str(row.get("galPhotographyMonth", "")) or None,
                "attribution_ko": "한국관광공사 관광사진갤러리 · "
                + str(row.get("galPhotographer", "촬영자 미상")),
                "metadata": row,
            }
        )
    seen = set()
    downloads = 0
    # Spread the bounded download pool across source/month strata before
    # pixel-level quality/scene selection; upstream first-N order is not priority.
    strata: dict[tuple[str, str], list[dict[str, Any]]] = {}
    for image in sorted(images, key=lambda r: r["asset_id"]):
        strata.setdefault(
            (image["receipt"]["service"], image.get("capture_month") or "UNKNOWN"), []
        ).append(image)
    ordered = []
    while any(strata.values()):
        for key in sorted(strata):
            if strata[key]:
                ordered.append(strata[key].pop(0))
    for image in ordered:
        image["place_id"] = place.place_id
        if image["license"] != "KOGL_TYPE_1" or image["match"]["state"] != "MATCHED":
            image["download_status"] = "RIGHTS_OR_MATCH_EXCLUDED"
            continue
        if image["url"] in seen:
            image["download_status"] = "DUPLICATE_URL"
            continue
        seen.add(image["url"])
        if downloads >= 12:
            image["download_status"] = "DOWNLOAD_POOL_BOUND"
            continue
        if not cache.live:
            image["download_status"] = "OFFLINE_NO_PIXEL_REQUEST"
            continue
        try:
            path, digest = download_official_image(image["url"], image_directory)
            image.update(path=str(path), original_sha256=digest, download_status="DOWNLOADED")
            downloads += 1
        except (ValueError, httpx.HTTPError):
            image["download_status"] = "DOWNLOAD_UNAVAILABLE"
    counts["downloaded_images"] = downloads
    counts["semantic_evidence_version"] = identity_version
    counts["coverage_note"] = (
        "정확한 장소명 검색 첫100건, 명칭·좌표/공식촬영지역 연결 범위; "
        "미연결은 자료 부재 확정이 아님."
    )
    unique_evidence = {e.evidence_id: e for e in evidence}
    payload = {
        "schema_version": "destination-evidence.v1",
        "place": canonical.model_dump(mode="json"),
        "category": place.category,
        "catalog_row_sha256": place.row_sha256,
        "collected_at": datetime.now(UTC).isoformat().replace("+00:00", "Z"),
        "receipts": [r.model_dump(mode="json") for r in receipts],
        "raw_responses": raws,
        "evidence": [unique_evidence[k].model_dump(mode="json") for k in sorted(unique_evidence)],
        "text_lineage": lineage,
        "images": images,
        "coverage": counts,
    }
    return DestinationEvidenceSnapshot.model_validate(
        payload | {"snapshot_sha256": canonical_sha256(payload)}
    )
