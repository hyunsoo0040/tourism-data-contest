"""Registered course estimates, explicit route scope, and bounded official GPX."""

from __future__ import annotations

import hashlib
import math
import re
import xml.etree.ElementTree as ET
from base64 import b64decode, b64encode
from collections.abc import Callable, Sequence
from datetime import UTC, datetime
from decimal import Decimal, InvalidOperation
from threading import BoundedSemaphore
from typing import Literal, Self, cast
from urllib.parse import parse_qs, urlsplit
from zoneinfo import ZoneInfo

import httpx
from pydantic import model_validator

from itda.collectors.kto_walking import WalkingClient
from itda.contracts.base import Sha256, StableId, StrictContract, require_utc
from itda.contracts.place_enrichment import CuratedCourseCrosswalk, WalkingContext, WalkingCourse
from itda.contracts.source_assessment import SourceService
from itda.domain.canonical import canonical_sha256
from itda.tourism.accessibility import CanonicalTourismPlace, region_location_matches
from itda.tourism.camping import source_modified_date
from itda.tourism.temporal import TemporalContextService, TemporalPolicy
from itda.tourism.temporal_cache import TemporalSourceSnapshot


def official_gpx_url(value: object) -> str | None:
    rendered = str(value or "")
    try:
        url = urlsplit(rendered)
        params = parse_qs(url.query, strict_parsing=True)
    except ValueError:
        return None
    if (
        url.scheme != "https"
        or url.netloc != "www.durunubi.kr"
        or url.path != "/editImgUp.do"
        or url.fragment
    ):
        return None
    if set(params) != {"filePath"} or len(params["filePath"]) != 1:
        return None
    if (
        re.fullmatch(
            r"/data/koreamobility/file/\d{4}/\d{2}/[0-9a-f]{32}\.gpx", params["filePath"][0]
        )
        is None
    ):
        return None
    return rendered


def _gpx_points(raw: bytes) -> tuple[tuple[float, float], ...]:
    if not raw or len(raw) > 2_000_000 or b"<!DOCTYPE" in raw.upper() or b"<!ENTITY" in raw.upper():
        raise ValueError("unsafe or oversized GPX")
    try:
        root = ET.fromstring(raw)
    except ET.ParseError as error:
        raise ValueError("invalid GPX XML") from error
    points = []
    for index, node in enumerate(root.iter()):
        if index > 100_000:
            raise ValueError("GPX node limit exceeded")
        if node.tag.rsplit("}", 1)[-1] not in {"trkpt", "rtept"}:
            continue
        lat, lon = float(node.attrib.get("lat", "nan")), float(node.attrib.get("lon", "nan"))
        if (
            not math.isfinite(lat)
            or not math.isfinite(lon)
            or not -90 <= lat <= 90
            or not -180 <= lon <= 180
        ):
            raise ValueError("invalid GPX coordinates")
        points.append((lat, lon))
        if len(points) > 50_000:
            raise ValueError("GPX point limit exceeded")
    if len(points) < 2:
        raise ValueError("GPX requires a polyline")
    return tuple(points)


class VerifiedRouteGeometry(StrictContract):
    schema_version: Literal["durunubi-route-geometry.v1"] = "durunubi-route-geometry.v1"
    course_id: StableId
    route_id: StableId
    source_url: str
    raw_body_base64: str
    raw_sha256: Sha256
    retrieved_at: datetime
    points: tuple[tuple[float, float], ...]
    geometry_sha256: Sha256

    @model_validator(mode="after")
    def verify_geometry(self) -> Self:
        require_utc(self.retrieved_at, field_name="retrieved_at")
        if official_gpx_url(self.source_url) is None:
            raise ValueError("untrusted GPX source")
        raw = b64decode(self.raw_body_base64, validate=True)
        if hashlib.sha256(raw).hexdigest() != self.raw_sha256 or _gpx_points(raw) != self.points:
            raise ValueError("GPX bytes and geometry mismatch")
        if self.geometry_sha256 != canonical_sha256(
            self.model_dump(mode="json", exclude={"geometry_sha256"})
        ):
            raise ValueError("geometry content hash mismatch")
        return self


def parse_official_gpx(
    raw: bytes, *, course_id: str, route_id: str, source_url: str, retrieved_at: datetime
) -> VerifiedRouteGeometry:
    draft = VerifiedRouteGeometry.model_construct(
        course_id=course_id,
        route_id=route_id,
        source_url=source_url,
        raw_body_base64=b64encode(raw).decode(),
        raw_sha256=hashlib.sha256(raw).hexdigest(),
        retrieved_at=retrieved_at,
        points=_gpx_points(raw),
        geometry_sha256="0" * 64,
    )
    payload = draft.model_dump(mode="json", exclude={"geometry_sha256"})
    return VerifiedRouteGeometry.model_validate(
        {**payload, "geometry_sha256": canonical_sha256(payload)}
    )


def _distance_to_geometry(
    place: CanonicalTourismPlace, geometry: VerifiedRouteGeometry
) -> float | None:
    if place.latitude is None or place.longitude is None:
        return None
    scale_y = 6_371_000 * math.pi / 180
    scale_x = scale_y * math.cos(math.radians(place.latitude))
    points = [
        ((lon - place.longitude) * scale_x, (lat - place.latitude) * scale_y)
        for lat, lon in geometry.points
    ]
    best = float("inf")
    for (ax, ay), (bx, by) in zip(points, points[1:], strict=False):
        dx, dy = bx - ax, by - ay
        length = dx * dx + dy * dy
        t = max(0, min(1, -(ax * dx + ay * dy) / length)) if length else 0
        best = min(best, math.hypot(ax + t * dx, ay + t * dy))
    return round(best, 1)


class WalkingEnrichmentService:
    def __init__(
        self,
        *,
        places: Sequence[CanonicalTourismPlace],
        client: WalkingClient | None,
        loader: TemporalContextService | None = None,
        policy: TemporalPolicy | None = None,
        clock: Callable[[], datetime] = lambda: datetime.now(UTC),
        exact_course_crosswalk: Sequence[CuratedCourseCrosswalk] = (),
        geometries: Sequence[VerifiedRouteGeometry] = (),
        max_source_age_days: int = 730,
    ) -> None:
        self.places = {row.place_id: row for row in places}
        self.client = client
        self.clock = clock
        self.crosswalk = {row.place_id: row for row in exact_course_crosswalk}
        self.geometries = {row.course_id: row for row in geometries}
        if (
            set(self.crosswalk) - set(self.places)
            or len(self.places) != len(places)
            or not 1 <= max_source_age_days <= 1825
        ):
            raise ValueError("invalid canonical route mapping or freshness")
        self.max_source_age_days = max_source_age_days
        self.loader = loader or TemporalContextService(places=places, policy=policy, clock=clock)
        self._gpx_requests = BoundedSemaphore(self.loader.policy.http_concurrency)

    def fetch_geometry(
        self, course: WalkingCourse, *, http_client: httpx.Client
    ) -> VerifiedRouteGeometry:
        """Optional public GPX download; never follows redirects or arbitrary URLs."""
        url = official_gpx_url(course.gpx_url)
        if url is None:
            raise ValueError("official GPX source is unavailable")
        with (
            self._gpx_requests,
            http_client.stream("GET", url, timeout=15, follow_redirects=False) as response,
        ):
            if response.status_code != 200:
                raise ValueError("official GPX unavailable")
            chunks = []
            length = 0
            for chunk in response.iter_bytes():
                length += len(chunk)
                if length > 2_000_000:
                    raise ValueError("GPX exceeds byte limit")
                chunks.append(chunk)
        return parse_official_gpx(
            b"".join(chunks),
            course_id=course.course_id,
            route_id=course.route_id,
            source_url=url,
            retrieved_at=self.clock(),
        )

    def get_context_with_sources(
        self, place_id: str
    ) -> tuple[WalkingContext, tuple[TemporalSourceSnapshot | VerifiedRouteGeometry, ...]]:
        place = self.places[place_id]
        now = self.clock()
        today = now.astimezone(ZoneInfo("Asia/Seoul")).date()
        courses_source = self.loader.collect_source_batch(
            SourceService.WALKING, "courseList", {}, self.client
        )
        routes_source = self.loader.collect_source_batch(
            SourceService.WALKING, "routeList", {}, self.client
        )
        sources: list[TemporalSourceSnapshot | VerifiedRouteGeometry] = [
            courses_source,
            routes_source,
        ]
        reason = "NONE"
        courses = []
        if any(not source.complete for source in (courses_source, routes_source)):
            reason = next(
                source.reason for source in (courses_source, routes_source) if not source.complete
            )
        elif now >= min(courses_source.expires_at, routes_source.expires_at):
            reason = "STALE"
        else:
            route_ids = [str(row.get("routeIdx")) for row in routes_source.rows]
            candidates = [
                row
                for row in courses_source.rows
                if region_location_matches(place, row.get("sigun")) and row.get("brdDiv") == "DNWW"
            ]
            course_ids = [str(row.get("crsIdx")) for row in candidates]
            for row in candidates:
                course_id = str(row.get("crsIdx", ""))
                route_id = str(row.get("routeIdx", ""))
                name = str(row.get("crsKorNm", ""))
                if (
                    not course_id
                    or not route_id
                    or not name
                    or course_ids.count(course_id) != 1
                    or route_ids.count(route_id) != 1
                ):
                    reason = "PARTIAL_SERIES"
                    continue
                modified = source_modified_date(row.get("modifiedtime"))
                course_reason = "NONE"
                distance = None
                duration = None
                difficulty = None
                if modified and (today - modified).days > self.max_source_age_days:
                    course_reason = "STALE"
                elif modified and modified > today:
                    course_reason = "INVALID_SOURCE_DATE"
                else:
                    try:
                        distance = Decimal(str(row.get("crsDstnc", "")))
                        raw_duration = str(row.get("crsTotlRqrmHour", ""))
                        difficulty = str(row.get("crsLevel", ""))
                        if (
                            not distance.is_finite()
                            or distance <= 0
                            or re.fullmatch(r"[1-9]\d{0,5}", raw_duration) is None
                            or difficulty not in {"1", "2", "3"}
                        ):
                            raise ValueError("invalid course values")
                        duration = int(raw_duration)
                    except (ValueError, InvalidOperation):
                        course_reason = "INVALID_VALUE"
                        distance = None
                        duration = None
                        difficulty = None
                if course_reason != "NONE":
                    distance = None
                    duration = None
                    difficulty = None
                gpx = official_gpx_url(row.get("gpxpath"))
                geometry = self.geometries.get(course_id)
                meters = None
                link = "REGIONAL_COURSE"
                label = f"{place.region_label} 권역 걷기 코스"
                reviewed = self.crosswalk.get(place_id)
                if (
                    reviewed is not None
                    and reviewed.course_id == course_id
                    and reviewed.route_id == route_id
                ):
                    link = "EXACT_CANONICAL_COURSE"
                    label = "명시적으로 연결한 전체 걷기 코스"
                elif any(
                    place.name_ko in str(row.get(field, ""))
                    for field in ("crsContents", "crsSummary", "crsTourInfo")
                ):
                    link = "MENTIONED_ON_COURSE"
                    label = "관광지가 공식 코스 설명에 언급됨"
                if geometry and geometry.route_id == route_id and geometry.source_url == gpx:
                    meters = _distance_to_geometry(place, geometry)
                    if meters is not None and meters <= 2000 and link != "EXACT_CANONICAL_COURSE":
                        link = "VERIFIED_NEARBY_COURSE"
                        label = "공식 경로까지의 직선거리로 확인한 주변 코스"
                        sources.append(geometry)
                courses.append(
                    WalkingCourse(
                        course_id=course_id,
                        route_id=route_id,
                        name_ko=name,
                        exact_match_review_sha256=reviewed.review_sha256
                        if link == "EXACT_CANONICAL_COURSE" and reviewed
                        else None,
                        link_kind=cast(
                            Literal[
                                "EXACT_CANONICAL_COURSE",
                                "MENTIONED_ON_COURSE",
                                "REGIONAL_COURSE",
                                "VERIFIED_NEARBY_COURSE",
                            ],
                            link,
                        ),
                        state="AVAILABLE" if course_reason == "NONE" else "UNKNOWN",
                        reason=course_reason,
                        distance_km=distance,
                        duration_minutes=duration,
                        difficulty_code=cast(Literal["1", "2", "3"] | None, difficulty),
                        difficulty_label_ko={"1": "낮음", "2": "보통", "3": "높음"}.get(
                            difficulty or ""
                        ),
                        source_modified_date=modified,
                        source_field_values={
                            field: str(row.get(field, ""))
                            for field in (
                                "crsDstnc",
                                "crsTotlRqrmHour",
                                "crsLevel",
                                "sigun",
                                "routeIdx",
                                "travelerinfo",
                            )
                        },
                        gpx_url=gpx,
                        geometry_sha256=geometry.geometry_sha256
                        if link == "VERIFIED_NEARBY_COURSE" and geometry is not None
                        else None,
                        distance_from_place_meters=meters
                        if link == "VERIFIED_NEARBY_COURSE"
                        else None,
                        scope_label_ko=label,
                    )
                )
        if not courses and reason == "NONE":
            reason = "EMPTY"
        draft = WalkingContext.model_construct(
            place_id=place_id,
            state="AVAILABLE"
            if courses and all(row.state == "AVAILABLE" for row in courses) and reason == "NONE"
            else "PARTIAL"
            if courses
            else "UNKNOWN",
            reason=reason,
            courses=tuple(sorted(courses, key=lambda row: row.course_id)),
            source_snapshot_sha256=tuple(
                sorted({canonical_sha256(source.model_dump(mode="json")) for source in sources})
            ),
            receipts=(*courses_source.receipts, *routes_source.receipts),
            retrieved_at=min(courses_source.retrieved_at, routes_source.retrieved_at),
            expires_at=min(courses_source.expires_at, routes_source.expires_at),
            context_sha256="0" * 64,
        )
        payload = draft.model_dump(mode="json", exclude={"context_sha256"})
        return WalkingContext.model_validate(
            {**payload, "context_sha256": canonical_sha256(payload)}
        ), tuple(sources)

    def get_context(self, place_id: str) -> WalkingContext:
        return self.get_context_with_sources(place_id)[0]
