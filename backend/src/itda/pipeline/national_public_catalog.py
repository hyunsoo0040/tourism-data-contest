"""Fresh nationwide TourAPI discovery and source-sufficiency sampling.

This pipeline selects evidence-rich places without model scores or popularity.
Every province's complete official listing is inspected before detail sampling;
immutable provider responses and per-place decisions make interruption resumable.
"""

from __future__ import annotations

import hashlib
import json
import math
import re
import threading
import time
import unicodedata
from collections import Counter, defaultdict, deque
from collections.abc import Iterator
from concurrent.futures import ThreadPoolExecutor, as_completed
from contextlib import ExitStack, contextmanager
from datetime import UTC, datetime, timedelta
from email.utils import parsedate_to_datetime
from pathlib import Path
from typing import Any

import httpx

from itda.collectors.base import OfficialApiClient, RequestPolicy, parse_provider_envelope
from itda.collectors.kto import KorService2Client
from itda.collectors.odii import OdiiClient
from itda.collectors.tourism_photo import TourismPhotoGalleryClient
from itda.contracts.mvp_public_catalog import (
    OfficialDatasetPermissionMetadata,
    PublicEvidence,
    PublicEvidenceInventory,
    PublicPlace,
    PublicPlaceCatalog,
    PublicPlaceRelations,
)
from itda.contracts.source_assessment import SourceService
from itda.domain.canonical import canonical_sha256
from itda.pipeline.destination_evidence import OfficialSourceCache, atomic_json, cache_lock
from itda.pipeline.mvp_public_catalog import verify_permission_snapshot
from itda.pipeline.source_authority import prepare_source_text
from itda.tourism.accessibility import provider_items

POLICY_VERSION = "national-source-sufficiency-v1"
SELECTION_POLICY_VERSION = "national-sightseeing-only-v1"
SIGHTSEEING_TYPES = frozenset({"12", "14", "28"})
CATEGORIES = {"12": "관광지", "14": "문화시설", "28": "레포츠", "32": "숙박", "39": "음식점"}
_USEFUL_INTRO_FIELDS = (
    "expguide",
    "expguideleports",
    "expagerange",
    "usetime",
    "usetimeculture",
    "usetimeleports",
    "parking",
    "parkingculture",
    "parkingleports",
    "restdate",
    "restdateculture",
    "restdateleports",
    "heritage1",
    "heritage2",
    "heritage3",
    "usefee",
    "usefeeleports",
    "accomcount",
    "infocenter",
    "infocenterculture",
    "infocenterleports",
    "scale",
    "spendtime",
    "firstmenu",
    "treatmenu",
    "opentimefood",
    "parkingfood",
    "reservationfood",
    "checkintime",
    "checkouttime",
    "roomcount",
    "roomtype",
    "reservationlodging",
    "parkinglodging",
    "subfacility",
)
Json = dict[str, Any]


class NationalProviderPaused(RuntimeError):
    """Provider-wide quota/rate failure; never an individual place decision."""

    def __init__(self, state: Json) -> None:
        self.state = state
        super().__init__("national provider collection is paused")


class NationalBatchControl:
    """Stop all providers in one batch when any provider reaches its quota."""

    def __init__(self) -> None:
        self.lock = threading.Lock()
        self.state: Json | None = None

    def check(self) -> None:
        with self.lock:
            if self.state is not None:
                raise NationalProviderPaused(self.state)

    def pause(self, state: Json) -> None:
        with self.lock:
            if self.state is None:
                self.state = state


class NationalAttemptTransport(httpx.BaseTransport):
    """Credential-free accounting for every actual national collection request."""

    def __init__(
        self,
        output: Path,
        transport: httpx.BaseTransport | None = None,
        *,
        resume_provider: bool = False,
        batch_control: NationalBatchControl | None = None,
    ) -> None:
        self.output = output
        self.transport = transport or httpx.HTTPTransport(retries=0)
        self.lock = threading.Lock()
        self.paused: Json | None = None
        self.resume_provider = resume_provider
        self.batch_control = batch_control
        self.output.parent.mkdir(parents=True, exist_ok=True)

    def _before_request(self) -> None:
        # File locking also bounds another collector process sharing this root.
        while True:
            if self.batch_control is not None:
                self.batch_control.check()
            with cache_lock(self.output.parent / "provider-control"):
                state_path = self.output.parent / "provider-state.json"
                if self.paused is not None:
                    raise NationalProviderPaused(self.paused)
                if state_path.is_file():
                    state = read_artifact(state_path)
                    if state.get("status") == "PAUSED":
                        until = (
                            datetime.fromisoformat(state["resume_not_before"])
                            if state.get("resume_not_before")
                            else None
                        )
                        if (state.get("manual_resume_required") and not self.resume_provider) or (
                            until is not None and datetime.now(UTC) < until
                        ):
                            self.paused = state
                            if self.batch_control is not None:
                                self.batch_control.pause(state)
                            raise NationalProviderPaused(state)
                        atomic_json(
                            state_path,
                            _stamped(
                                {
                                    "status": "RESUMING",
                                    "previous_pause_sha256": state["artifact_sha256"],
                                    "resumed_at": datetime.now(UTC).isoformat(),
                                }
                            ),
                        )
                pace_path = self.output.parent / "provider-request-start.json"
                previous = (
                    json.loads(pace_path.read_text())["started_at_epoch"]
                    if pace_path.is_file()
                    else 0
                )
                delay = previous + (1 / 3) - time.time()
                if delay <= 0:
                    atomic_json(
                        pace_path, {"started_at_epoch": time.time(), "requests_per_second": 3}
                    )
                    return
            time.sleep(delay)

    def _pause(self, response: httpx.Response, operation: str) -> None:
        now = datetime.now(UTC)
        authorization_rejected = response.status_code in {401, 403}
        reason = (
            "PROVIDER_AUTHORIZATION_REJECTED"
            if authorization_rejected
            else "PROVIDER_RATE_OR_QUOTA_LIMIT"
        )
        # Close the circuit at header receipt, before parsing a potentially slow body.
        self.paused = _stamped(
            {
                "status": "PAUSED",
                "reason": reason,
                "http_status": response.status_code,
                "operation": operation,
                "manual_resume_required": True,
                "resume_not_before": None,
                "observed_at": now.isoformat(),
            }
        )
        if self.batch_control is not None:
            self.batch_control.pause(self.paused)
        with cache_lock(self.output.parent / "provider-control"):
            atomic_json(self.output.parent / "provider-state.json", self.paused)
        raw_retry = response.headers.get("Retry-After", "").strip()
        retry_seconds: float | None = None
        if raw_retry.isdigit():
            retry_seconds = float(raw_retry)
        elif raw_retry:
            try:
                parsed = parsedate_to_datetime(raw_retry)
                retry_seconds = max(0, (parsed.astimezone(UTC) - now).total_seconds())
            except (ValueError, TypeError, OverflowError):
                pass
        # A missing header does not grant permission to immediately retry a quota.
        cooldown = max(1, retry_seconds if retry_seconds is not None else 300)
        code = None
        body = bytearray()
        truncated = False
        try:
            for chunk in response.iter_bytes():
                room = 65536 - len(body)
                body.extend(chunk[:room])
                if len(chunk) > room:
                    truncated = True
                    break
            try:
                _, observed_code, _ = parse_provider_envelope(
                    bytes(body),
                    content_type=response.headers.get("content-type", ""),
                )
                if observed_code is not None and re.fullmatch(
                    r"[A-Za-z0-9_-]{1,40}", observed_code
                ):
                    code = observed_code
            except ValueError:
                pass
        except httpx.HTTPError:
            truncated = True
        finally:
            response.close()
        limit_header = response.headers.get("x-ratelimit-limit", "")
        remaining_header = response.headers.get("x-ratelimit-remaining", "")
        daily_quota = code == "22"
        state = _stamped(
            {
                "status": "PAUSED",
                "reason": reason,
                "pause_kind": "AUTHORIZATION_REJECTED"
                if authorization_rejected
                else ("DAILY_REQUEST_QUOTA" if daily_quota else "RATE_LIMIT"),
                "operation": operation,
                "http_status": response.status_code,
                "provider_result_code": code,
                "observed_at": now.isoformat(),
                "retry_after_seconds": retry_seconds,
                "resume_not_before": None
                if authorization_rejected or (daily_quota and retry_seconds is None)
                else (now + timedelta(seconds=cooldown)).isoformat(),
                "manual_resume_required": True,
                "daily_limit": int(limit_header) if limit_header.isdigit() else None,
                "remaining": int(remaining_header) if remaining_header.isdigit() else None,
                "default_cooldown_used": not authorization_rejected and retry_seconds is None,
                "response_body_sha256": hashlib.sha256(body).hexdigest(),
                "response_body_truncated": truncated,
                "body_retained": False,
            }
        )
        self.paused = state
        with cache_lock(self.output.parent / "provider-control"):
            atomic_json(
                self.output.parent / "provider-pauses" / (state["artifact_sha256"] + ".json"), state
            )
            atomic_json(self.output.parent / "provider-state.json", state)
        raise NationalProviderPaused(state)

    def handle_request(self, request: httpx.Request) -> httpx.Response:
        self._before_request()
        started = time.monotonic()
        fields: Json = {
            "operation": request.url.path.rsplit("/", 1)[-1],
            "started_at": datetime.now(UTC).isoformat(),
            "request_scope": {
                k: v
                for k, v in request.url.params.items()
                if k.casefold().replace("_", "")
                not in {"servicekey", "apikey", "token", "authorization"}
            },
            "transport_retries": 0,
        }
        try:
            response = self.transport.handle_request(request)
            fields.update(http_status=response.status_code, exception_class=None)
            if response.status_code in {401, 403, 429}:
                self._pause(response, fields["operation"])
            return response
        except Exception as error:
            fields.setdefault("http_status", None)
            fields["exception_class"] = type(error).__name__
            raise
        finally:
            fields["elapsed_ms"] = round((time.monotonic() - started) * 1000)
            with self.lock, self.output.open("a") as stream:
                stream.write(json.dumps(fields, ensure_ascii=False, sort_keys=True) + "\n")

    def close(self) -> None:
        self.transport.close()


class NationalSourceUnavailable(RuntimeError):
    def __init__(self, operation: str, reason: str, http_status: int | None) -> None:
        self.operation = operation
        self.reason = reason
        self.http_status = http_status
        super().__init__(f"{operation} unavailable: {reason}")

    @property
    def terminal_authority_error(self) -> bool:
        return self.http_status in {401, 403} or any(
            word in self.reason.casefold()
            for word in (
                "authentication",
                "authorization",
                "credential",
                "service key",
                "servicekey",
                "access is denied",
                "unregistered ip",
                "parameters",
            )
        )


@contextmanager
def national_source_clients(
    key: str,
    odii_key: str | None,
    control_root: Path,
    *,
    resume_provider: bool = False,
) -> Iterator[dict[SourceService, OfficialApiClient]]:
    """Own all provider/HTTP resources and share pause/pacing across collection phases."""
    for directory in (
        control_root,
        control_root / "provider-controls/odii",
        control_root / "provider-controls/gallery",
    ):
        state_path = directory / "provider-state.json"
        if state_path.is_file():
            state = read_artifact(state_path)
            if state.get("status") == "PAUSED" and (
                not resume_provider
                or (
                    state.get("resume_not_before")
                    and datetime.now(UTC) < datetime.fromisoformat(state["resume_not_before"])
                )
            ):
                raise NationalProviderPaused(state)
    with ExitStack() as resources:
        clients: dict[SourceService, OfficialApiClient] = {}
        batch_control = NationalBatchControl()
        for service, client_type, credential, directory in (
            (SourceService.TOUR, KorService2Client, key, control_root),
            (
                SourceService.ODII,
                OdiiClient,
                odii_key or key,
                control_root / "provider-controls/odii",
            ),
            (
                SourceService.GALLERY,
                TourismPhotoGalleryClient,
                key,
                control_root / "provider-controls/gallery",
            ),
        ):
            http_client = resources.enter_context(
                httpx.Client(
                    transport=NationalAttemptTransport(
                        directory / "http-attempts.jsonl",
                        resume_provider=resume_provider,
                        batch_control=batch_control,
                    ),
                    follow_redirects=False,
                    trust_env=False,
                )
            )
            client = client_type(
                service_key=credential,
                http_client=http_client,
                policy=RequestPolicy(timeout_seconds=30, max_attempts=1, max_backoff_seconds=2),
            )
            resources.callback(client.close)
            clients[service] = client
        yield clients


def _stamped(fields: Json, key: str = "artifact_sha256") -> Json:
    return {**fields, key: canonical_sha256(fields)}


def read_artifact(path: Path) -> Json:
    payload: Json = json.loads(path.read_text())
    expected = canonical_sha256({k: v for k, v in payload.items() if k != "artifact_sha256"})
    if payload.get("artifact_sha256") != expected:
        raise ValueError("national artifact integrity mismatch")
    return payload


def _write_once(path: Path, payload: Json) -> None:
    if path.is_file():
        if read_artifact(path) != payload:
            raise ValueError("immutable national artifact changed")
    else:
        atomic_json(path, payload)


def quarantine_rate_limited_decisions(output: Path) -> Json:
    """Repair the superseded per-place 429 handling without losing normal sources."""
    archive = output / "old-partial-http-errors"
    manifest_path = archive / "repair.json"
    previous = read_artifact(manifest_path) if manifest_path.is_file() else None
    records = list(previous["pending_reconsideration"]) if previous else []
    known = {row["content_id"] for row in records}
    for path in sorted((output / "collection-failures").glob("*.json")):
        failures = read_artifact(path)
        if not any(attempt.get("http_status") == 429 for attempt in failures["attempts"]):
            continue
        cid = failures["content_id"]
        decision_path = output / "decisions" / (cid + ".json")
        decision = read_artifact(decision_path) if decision_path.is_file() else None
        if decision and decision["sufficiency"]["reason"] != "API_UNAVAILABLE":
            continue
        if cid in known:
            raise ValueError("rate-limit repair encountered duplicate live/archive content")
        record: Json = {
            "content_id": cid,
            "status": "PENDING_RECONSIDERATION",
            "reason": "PROVIDER_429_IS_NOT_SOURCE_INSUFFICIENCY",
            "http_attempts": len(failures["attempts"]),
            "files": [],
        }
        for source in (decision_path, path):
            if not source.is_file():
                continue
            destination = archive / source.parent.name / source.name
            destination.parent.mkdir(parents=True, exist_ok=True)
            if destination.exists():
                raise ValueError("rate-limit repair destination already exists")
            digest = hashlib.sha256(source.read_bytes()).hexdigest()
            source.rename(destination)
            record["files"].append({"path": str(destination.relative_to(output)), "sha256": digest})
        records.append(record)
    normal = [read_artifact(p) for p in sorted((output / "decisions").glob("*.json"))]
    manifest = _stamped(
        {
            "schema_version": "national-rate-limit-repair.v1",
            "status": "PENDING_PROVIDER_RESUME",
            "pending_reconsideration": sorted(records, key=lambda row: row["content_id"]),
            "quarantined_decision_count": len(records),
            "retained_normal_decisions": len(normal),
            "retained_normal_decisions_sha256": canonical_sha256(
                sorted(r["artifact_sha256"] for r in normal)
            ),
            "retained_selected_count": sum(r["sufficiency"]["accepted"] for r in normal),
            "recorded_at": previous["recorded_at"] if previous else datetime.now(UTC).isoformat(),
        }
    )
    atomic_json(manifest_path, manifest)
    progress_path = output / "progress.json"
    if progress_path.is_file():
        old_progress = archive / "progress-before-repair.json"
        if not old_progress.exists():
            old_progress.parent.mkdir(parents=True, exist_ok=True)
            old_progress.write_bytes(progress_path.read_bytes())
        atomic_json(
            progress_path,
            _stamped(
                {
                    "stage": "selection",
                    "status": "PAUSED",
                    "reason": "PROVIDER_DAILY_QUOTA",
                    "selected_count": manifest["retained_selected_count"],
                    "checked_count": len(normal),
                    "pending_reconsideration_count": len(records),
                    "repair_sha256": manifest["artifact_sha256"],
                }
            ),
        )
    return manifest


def _page(cache: OfficialSourceCache, operation: str, params: dict[str, str]) -> Json:
    receipt, raw = cache.fetch(SourceService.TOUR, operation, params)
    if raw is None or receipt.status == "UNAVAILABLE":
        raise NationalSourceUnavailable(operation, receipt.reason, receipt.http_status)
    body = raw["payload"].get("response", {}).get("body", {})
    total = str(body.get("totalCount", ""))
    page_no = str(body.get("pageNo", ""))
    if not total.isdigit() or page_no != params["pageNo"]:
        raise ValueError("official pagination count/page identity is missing")
    rows = provider_items(raw["payload"])
    return {
        "rows": list(rows),
        "total_count": int(total),
        "receipt": receipt.model_dump(mode="json"),
    }


def _all_pages(
    cache: OfficialSourceCache,
    operation: str,
    params: dict[str, str],
    *,
    page_size: int,
) -> Json:
    rows: list[Json] = []
    pages: list[Json] = []
    expected_total: int | None = None
    for page_no in range(1, 2001):
        page = _page(
            cache,
            operation,
            {
                **params,
                "numOfRows": str(page_size),
                "pageNo": str(page_no),
            },
        )
        if expected_total is None:
            expected_total = page["total_count"]
        elif expected_total != page["total_count"]:
            raise ValueError("official total changed within a region; use a fresh discovery root")
        batch = page.pop("rows")
        if len(batch) > page_size or (not batch and len(rows) < expected_total):
            raise ValueError("official pagination stopped before complete coverage")
        rows.extend(batch)
        pages.append(page)
        if len(rows) >= expected_total:
            if len(rows) != expected_total:
                raise ValueError("official row count exceeds total")
            return {"rows": rows, "total_count": expected_total, "pages": pages}
    raise ValueError("official national discovery exceeded explicit page ceiling")


def discover_nationwide(
    cache: OfficialSourceCache,
    output: Path,
    *,
    page_size: int = 300,
) -> Json:
    """Inspect every province and all content types, preserving paging evidence."""
    if not 1 <= page_size <= 500:
        raise ValueError("national page size must be 1..500")
    result_path = output / "discovery.json"
    if result_path.is_file():
        return read_artifact(result_path)
    region_listing = _all_pages(cache, "ldongCode2", {"lDongListYn": "N"}, page_size=100)
    provinces = sorted(
        (
            {"code": str(r.get("code", "")), "name": str(r.get("name", ""))}
            for r in region_listing["rows"]
        ),
        key=lambda r: r["code"],
    )
    if (
        not provinces
        or len({r["code"] for r in provinces}) != len(provinces)
        or any(
            not re.fullmatch(r"[0-9]{2}(?:[0-9]{3})?", r["code"]) or not r["name"]
            for r in provinces
        )
    ):
        raise ValueError("official complete province code list is invalid")

    def collect_region(province: Json) -> Json:
        path = output / "regions" / (province["code"] + ".json")
        if path.is_file():
            return read_artifact(path)
        districts = _all_pages(
            cache,
            "ldongCode2",
            {
                "lDongRegnCd": province["code"],
                "lDongListYn": "N",
            },
            page_size=100,
        )
        listing = _all_pages(
            cache,
            "areaBasedList2",
            {
                "lDongRegnCd": province["code"],
                "arrange": "A",
            },
            page_size=page_size,
        )
        ids = [str(r.get("contentid", "")) for r in listing["rows"]]
        if any(not cid.isdigit() for cid in ids) or len(ids) != len(set(ids)):
            raise ValueError("national listing contains missing/duplicate provider identity")
        if any(str(r.get("lDongRegnCd", "")) != province["code"] for r in listing["rows"]):
            raise ValueError("provider listing contains a different province")
        result = _stamped(
            {
                "schema_version": "national-discovery-region.v1",
                "province": province,
                "district_codes": districts,
                "listing": listing,
                "complete": True,
            }
        )
        _write_once(path, result)
        print(
            json.dumps(
                {
                    "stage": "discovery",
                    "region": province["name"],
                    "listing_count": len(ids),
                    "complete": True,
                },
                ensure_ascii=False,
            ),
            flush=True,
        )
        return result

    with ThreadPoolExecutor(max_workers=3) as executor:
        regions = list(executor.map(collect_region, provinces))
    all_ids = [str(r["contentid"]) for region in regions for r in region["listing"]["rows"]]
    if len(all_ids) != len(set(all_ids)):
        raise ValueError("the same provider entity appears in multiple provinces")
    result = _stamped(
        {
            "schema_version": "national-discovery.v1",
            "policy_version": POLICY_VERSION,
            "created_at": datetime.now(UTC).isoformat(),
            "region_codes": region_listing,
            "regions": regions,
            "complete": True,
            "total_listing_count": len(all_ids),
            "model_calls": 0,
            "popularity_used": False,
        }
    )
    _write_once(result_path, result)
    return result


def official_region_code(province_code: str, district_code: str) -> str | None:
    """Normalize only observed official shapes, including Sejong's complete code."""
    if re.fullmatch(r"[0-9]{2}", province_code) and re.fullmatch(r"[0-9]{3}", district_code):
        return province_code + district_code
    if re.fullmatch(r"[0-9]{5}", province_code) and district_code == province_code:
        return province_code
    return None


def identity_is_usable(row: Json, province_code: str) -> bool:
    try:
        lat, lon = float(row.get("mapy", "nan")), float(row.get("mapx", "nan"))
    except (TypeError, ValueError):
        return False
    return bool(
        str(row.get("contenttypeid", "")) in CATEGORIES
        and str(row.get("contentid", "")).isdigit()
        and str(row.get("title", "")).strip()
        and str(row.get("addr1", "")).strip()
        and str(row.get("lDongRegnCd", "")) == province_code
        and official_region_code(province_code, str(row.get("lDongSignguCd", "")))
        and 33.0 <= lat <= 38.7
        and 124.0 <= lon <= 132.0
    )


def balanced_candidates(rows: list[Json], province_code: str) -> list[Json]:
    """Round-robin districts/types; hash ordering avoids provider/popularity order."""
    groups: dict[tuple[str, str], list[Json]] = defaultdict(list)
    for row in rows:
        if str(row.get("contenttypeid", "")) in SIGHTSEEING_TYPES and identity_is_usable(
            row, province_code
        ):
            groups[(str(row["lDongSignguCd"]), str(row["contenttypeid"]))].append(row)
    queues = [
        deque(sorted(group, key=lambda r: canonical_sha256({"content_id": str(r["contentid"])})))
        for _, group in sorted(groups.items())
    ]
    result = []
    while queues:
        for queue in queues:
            if queue:
                result.append(queue.popleft())
        queues = [queue for queue in queues if queue]
    return result


def source_sufficiency(common: Json, intro: Json) -> Json:
    text = prepare_source_text(str(common.get("overview", "")), character_limit=8000).text
    characters = len(re.sub(r"\s", "", text))
    useful_fields = [
        field
        for field in _USEFUL_INTRO_FIELDS
        if intro.get(field) is not None
        and str(intro.get(field, "")).strip() not in {"", "정보없음", "미제공", "미확인", "문의"}
    ]
    # Content length, usable administrative identity and explicit source fields
    # measure documentation sufficiency, not whether a destination is good.
    accepted = characters >= 650 or (characters >= 400 and bool(useful_fields))
    return {
        "accepted": accepted,
        "overview_characters": characters,
        "structured_fields": useful_fields,
        "reason": "SUFFICIENT_OFFICIAL_TEXT" if accepted else "INSUFFICIENT_OFFICIAL_TEXT",
        "overview": text,
        "model_score_used": False,
    }


def _purpose(row: Json) -> str:
    return {"39": "FOOD", "32": "LODGING"}.get(str(row["contenttypeid"]), "SIGHTSEEING")


def _inspect_candidate(cache: OfficialSourceCache, output: Path, row: Json, province: Json) -> Json:
    cid = str(row["contentid"])
    path = output / "decisions" / (cid + ".json")
    if path.is_file():
        result = read_artifact(path)
        if result["listing_sha256"] != canonical_sha256(row):
            raise ValueError("candidate decision belongs to a different discovery")
        return result
    common = _page(cache, "detailCommon2", {"contentId": cid, "numOfRows": "100", "pageNo": "1"})
    matches = [r for r in common["rows"] if str(r.get("contentid", "")) == cid]
    details: Json = matches[0] if len(matches) == 1 and len(common["rows"]) == 1 else {}
    # Frozen listing and detail must identify the same official place/location.
    identity_valid = identity_is_usable(details, province["code"])
    if identity_valid:
        identity_valid = (
            str(details["contenttypeid"]) == str(row["contenttypeid"])
            and unicodedata.normalize("NFC", str(details["title"]))
            == unicodedata.normalize("NFC", str(row["title"]))
            and str(details["lDongSignguCd"]) == str(row["lDongSignguCd"])
            and abs(float(details["mapy"]) - float(row["mapy"])) < 0.001
            and abs(float(details["mapx"]) - float(row["mapx"])) < 0.001
        )
    intro: Json | None = None
    if (
        identity_valid
        and len(prepare_source_text(str(details.get("overview", "")), character_limit=8000).text)
        >= 400
    ):
        intro = _page(
            cache,
            "detailIntro2",
            {
                "contentId": cid,
                "contentTypeId": str(row["contenttypeid"]),
                "numOfRows": "100",
                "pageNo": "1",
            },
        )
    intro_rows = (
        [] if intro is None else [r for r in intro["rows"] if str(r.get("contentid", "")) == cid]
    )
    assessment = source_sufficiency(details, intro_rows[0] if len(intro_rows) == 1 else {})
    if not identity_valid:
        assessment.update(accepted=False, reason="OFFICIAL_IDENTITY_MISMATCH")
    result = _stamped(
        {
            "schema_version": "national-source-decision.v1",
            "policy_version": POLICY_VERSION,
            "content_id": cid,
            "province": province,
            "listing_sha256": canonical_sha256(row),
            "common": common,
            "intro": intro,
            "sufficiency": assessment,
        }
    )
    _write_once(path, result)
    return result


def _inspect_with_retries(
    cache: OfficialSourceCache,
    output: Path,
    row: Json,
    province: Json,
) -> Json:
    """Three bounded attempts; failed transport is distinct from insufficient text."""
    cid = str(row["contentid"])
    failures_path = output / "collection-failures" / (cid + ".json")
    failures = read_artifact(failures_path)["attempts"] if failures_path.is_file() else []
    if (output / "decisions" / (cid + ".json")).is_file():
        return _inspect_candidate(cache, output, row, province)
    for attempt in range(len(failures) + 1, 4):
        try:
            return _inspect_candidate(cache, output, row, province)
        except NationalSourceUnavailable as error:
            if error.http_status == 429:
                raise NationalProviderPaused(
                    {
                        "status": "PAUSED",
                        "http_status": 429,
                        "manual_resume_required": True,
                        "reason": "PROVIDER_RATE_OR_QUOTA_LIMIT",
                    }
                ) from error
            failure = {
                "attempt": attempt,
                "operation": error.operation,
                "reason": error.reason,
                "http_status": error.http_status,
                "observed_at": datetime.now(UTC).isoformat(),
                "terminal_authority_error": error.terminal_authority_error,
            }
            failures.append(failure)
            atomic_json(failures_path, _stamped({"content_id": cid, "attempts": failures}))
            if error.terminal_authority_error:
                raise
    result = _stamped(
        {
            "schema_version": "national-source-decision.v1",
            "policy_version": POLICY_VERSION,
            "content_id": cid,
            "province": province,
            "listing_sha256": canonical_sha256(row),
            "common": None,
            "intro": None,
            "sufficiency": {
                "accepted": False,
                "reason": "API_UNAVAILABLE",
                "model_score_used": False,
            },
            "collection_failures_sha256": read_artifact(failures_path)["artifact_sha256"],
        }
    )
    _write_once(output / "decisions" / (cid + ".json"), result)
    return result


def _place_identity(row: Json) -> tuple[str, float, float]:
    return (
        re.sub(r"\W", "", str(row["title"])),
        round(float(row["mapy"]), 5),
        round(float(row["mapx"]), 5),
    )


def prior_collection_exclusions(collections: list[Path]) -> Json:
    """Freeze already inspected IDs and exact name/location identities."""
    ids: set[str] = set()
    identities: set[tuple[str, float, float]] = set()
    sources = []
    for root in collections:
        paths = sorted((root / "decisions").glob("*.json"))
        if not paths:
            raise ValueError("excluded collection has no source decisions")
        hashes = []
        for path in paths:
            decision = read_artifact(path)
            cid = str(decision["content_id"])
            if not cid.isdigit() or path.stem != cid:
                raise ValueError("excluded decision identity mismatch")
            ids.add(cid)
            hashes.append(decision["artifact_sha256"])
            for row in decision["common"]["rows"]:
                if identity_is_usable(row, str(decision["province"]["code"])):
                    identities.add(_place_identity(row))
        sources.append(
            {
                "collection": str(root),
                "decision_count": len(paths),
                "decision_set_sha256": canonical_sha256(hashes),
            }
        )
    return _stamped(
        {
            "schema_version": "national-prior-collection-exclusions.v1",
            "policy": "EXCLUDE_ALL_PREVIOUSLY_INSPECTED_IDS_AND_NAME_LOCATION_IDENTITIES",
            "content_ids": sorted(ids),
            "place_identities": [list(k) for k in sorted(identities)],
            "sources": sources,
        }
    )


def select_nationwide(
    cache: OfficialSourceCache,
    output: Path,
    discovery: Json,
    *,
    target_count: int = 1000,
    exclusions: Json | None = None,
    evaluation_sample: bool = False,
) -> Json:
    if evaluation_sample and (not exclusions or not 1 <= target_count <= 120):
        raise ValueError("new-place evaluation requires prior exclusions and target 1..120")
    if not evaluation_sample and not 800 <= target_count <= 1000:
        raise ValueError("national sample target must be 800..1000")
    if discovery.get("complete") is not True:
        raise ValueError("national source selection requires complete nationwide discovery")
    excluded_ids = set(exclusions["content_ids"]) if exclusions else set()
    excluded_identities = (
        {tuple(k) for k in exclusions["place_identities"]} if exclusions else set()
    )
    exclusion_sha256 = exclusions["artifact_sha256"] if exclusions else None
    path = output / "selection.json"
    if path.is_file():
        existing = read_artifact(path)
        if (
            existing["discovery_sha256"] != discovery["artifact_sha256"]
            or existing["target_count"] != target_count
            or existing.get("selection_policy_version") != SELECTION_POLICY_VERSION
            or existing.get("exclusion_sha256") != exclusion_sha256
            or (existing.get("sampling_scope") == "NEW_PLACE_AUTOMATIC_EVALUATION")
            != evaluation_sample
        ):
            raise ValueError("national selection identity changed")
        return existing
    provinces = {r["province"]["code"]: r["province"] for r in discovery["regions"]}
    queues = {
        r["province"]["code"]: deque(
            row
            for row in balanced_candidates(r["listing"]["rows"], r["province"]["code"])
            if str(row["contentid"]) not in excluded_ids
            and _place_identity(row) not in excluded_identities
        )
        for r in discovery["regions"]
    }
    capacities = {code: len(queue) for code, queue in queues.items()}
    weights = {code: math.sqrt(n) for code, n in capacities.items()}
    weight_sum = sum(weights.values())
    if not weight_sum:
        raise ValueError("national discovery contains no eligible identities")
    province_cap = math.ceil(target_count * 0.125)
    quotas = {
        code: min(
            math.ceil(target_count * 0.125), max(20, round(target_count * weight / weight_sum))
        )
        for code, weight in weights.items()
    }
    selected: dict[str, list[Json]] = {code: [] for code in queues}
    purpose_targets = {"SIGHTSEEING": target_count}
    selected_purposes: Counter[str] = Counter()
    checked_purposes: Counter[str] = Counter()
    checked: Counter[str] = Counter()
    reasons: Counter[str] = Counter()
    seen_identity: set[tuple[str, float, float]] = set(excluded_identities)
    exhausted: set[str] = set()
    with ThreadPoolExecutor(max_workers=3) as executor:
        while sum(len(rows) for rows in selected.values()) < target_count:
            available = [
                code
                for code, queue in queues.items()
                if queue and len(selected[code]) < province_cap
            ]
            if not available:
                break
            # Each region advances in proportion to its documentation opportunity,
            # with an explicit cap preventing any one province dominating.
            available.sort(
                key=lambda code: (
                    checked[code] / quotas[code],
                    len(selected[code]) / quotas[code],
                    code,
                )
            )
            candidate_by_region: dict[str, Json] = {}
            for purpose in sorted(
                purpose_targets,
                key=lambda p: (
                    selected_purposes[p] >= purpose_targets[p],
                    checked_purposes[p] / purpose_targets[p],
                    p,
                ),
            ):
                candidate_by_region = {
                    code: row
                    for code in available
                    if (row := next((r for r in queues[code] if _purpose(r) == purpose), None))
                    is not None
                }
                if candidate_by_region:
                    break
            batch_codes = list(candidate_by_region)[
                : min(3, target_count - sum(map(len, selected.values())))
            ]
            for code in batch_codes:
                queues[code].remove(candidate_by_region[code])
            futures = {
                executor.submit(
                    _inspect_with_retries, cache, output, candidate_by_region[code], provinces[code]
                ): code
                for code in batch_codes
            }
            outcomes = sorted(
                ((futures[future], future.result()) for future in as_completed(futures)),
                key=lambda x: x[0],
            )
            for code, result in outcomes:
                checked[code] += 1
                checked_purposes[_purpose(candidate_by_region[code])] += 1
                decision = result["sufficiency"]
                reasons[decision["reason"]] += 1
                if decision["accepted"]:
                    row = result["common"]["rows"][0]
                    key = _place_identity(row)
                    if key not in seen_identity:
                        seen_identity.add(key)
                        selected[code].append(result)
                        selected_purposes[_purpose(row)] += 1
                if not queues[code]:
                    exhausted.add(code)
            count = sum(map(len, selected.values()))
            progress = _stamped(
                {
                    "stage": "selection",
                    "selection_policy_version": SELECTION_POLICY_VERSION,
                    "exclusion_sha256": exclusion_sha256,
                    "excluded_prior_content_ids": len(excluded_ids),
                    "selected_count": count,
                    "checked_count": sum(checked.values()),
                    "target_count": target_count,
                    "by_region": {code: len(rows) for code, rows in selected.items()},
                    "by_purpose": dict(selected_purposes),
                    "checked_by_purpose": dict(checked_purposes),
                    "rejections": dict(reasons),
                }
            )
            atomic_json(output / "progress.json", progress)
            print(
                json.dumps(
                    {
                        k: progress[k]
                        for k in ("stage", "selected_count", "checked_count", "target_count")
                    }
                ),
                flush=True,
            )
    count = sum(map(len, selected.values()))
    if count < target_count:
        raise RuntimeError(
            f"only {count}/{target_count} source-sufficient places; "
            "inspect progress before changing policy"
        )
    result = _stamped(
        {
            "schema_version": "national-selection.v1",
            **({"sampling_scope": "NEW_PLACE_AUTOMATIC_EVALUATION"} if evaluation_sample else {}),
            "policy_version": POLICY_VERSION,
            "selection_policy_version": SELECTION_POLICY_VERSION,
            "exclusion_sha256": exclusion_sha256,
            "excluded_prior_content_ids": len(excluded_ids),
            "included_content_types": sorted(SIGHTSEEING_TYPES),
            "excluded_purposes": ["FOOD", "LODGING"],
            "discovery_sha256": discovery["artifact_sha256"],
            "target_count": target_count,
            "created_at": datetime.now(UTC).isoformat(),
            "selected_count": count,
            "selected": sorted(
                (r for rows in selected.values() for r in rows), key=lambda r: r["content_id"]
            ),
            "distribution": [
                {
                    "province": provinces[code],
                    "listed_eligible": capacities[code],
                    "detail_inspected": checked[code],
                    "selected": len(selected[code]),
                    "sampling_quota_weight": quotas[code],
                    "exhausted": code in exhausted,
                }
                for code in sorted(provinces)
            ],
            "selection_uses": [
                "official_identity",
                "official_description_length",
                "structured_source_fields",
                "province_district_category_balance",
            ],
            "model_calls": 0,
            "popularity_used": False,
            "maximum_per_province": province_cap,
            "purpose_targets": purpose_targets,
            "purpose_selected": dict(selected_purposes),
            "purpose_inspected": dict(checked_purposes),
            "scheduling_policy": "sightseeing-region-district-type-balance-v1",
            "detail_collection_attempt_limit": 3,
            "purpose_shortfall_policy": "REDISTRIBUTE_ONLY_TO_SOURCE_SUFFICIENT_PLACES",
        }
    )
    _write_once(path, result)
    return result


def materialize_national_catalog(
    selection: Json,
    discovery: Json,
    *,
    permission: OfficialDatasetPermissionMetadata,
    permission_snapshot: bytes,
) -> tuple[PublicPlaceCatalog, PublicEvidenceInventory, PublicPlaceRelations]:
    if permission.official_dataset_id != "15101578" or not permission.permits_mvp_use:
        raise ValueError("verified TourAPI permission required")
    verify_permission_snapshot(permission, permission_snapshot)
    if selection["discovery_sha256"] != discovery["artifact_sha256"]:
        raise ValueError("national discovery/selection binding changed")
    districts = {
        official_region_code(region["province"]["code"], str(row["code"])): str(row["name"])
        for region in discovery["regions"]
        for row in region["district_codes"]["rows"]
    }
    places, evidence_rows = [], []
    for decision in selection["selected"]:
        row = decision["common"]["rows"][0]
        if str(row.get("contenttypeid", "")) not in SIGHTSEEING_TYPES:
            raise ValueError("national catalog includes only sightseeing destinations")
        cid = decision["content_id"]
        identity = {"provider": "TOUR_API", "source_id": cid}
        place_id = "public:korea:" + canonical_sha256(identity)
        receipt = decision["common"]["receipt"]
        evidence_fields = {
            "evidence_id": "evidence:"
            + canonical_sha256({"place_id": place_id, "response": receipt["response_sha256"]}),
            "provider": "TOUR_API",
            "official_dataset_id": "15101578",
            "provider_source_id": cid,
            "official_license_url": permission.official_url,
            "license_type": permission.license_type,
            "attribution_text": permission.attribution_for_release,
            "reference_date": receipt["reference_date"],
            "excerpt": decision["sufficiency"]["overview"][:4000],
            "source_response_sha256": receipt["response_sha256"],
            "permission_metadata": permission.model_dump(mode="json"),
            "commercial_use_allowed": True,
            "transform_allowed": True,
            "display_allowed": True,
            "model_input_allowed": True,
            "release_redistribution_allowed": True,
            "third_party_model_processing_allowed": True,
        }
        evidence = PublicEvidence.model_validate(
            {**evidence_fields, "evidence_sha256": canonical_sha256(evidence_fields)}
        )
        evidence_rows.append(evidence)
        region_code = official_region_code(str(row["lDongRegnCd"]), str(row["lDongSignguCd"]))
        if region_code is None:
            raise ValueError("selected place lost its official administrative identity")
        administrative_area = decision["province"]["name"]
        district = districts.get(region_code)
        if district and district != administrative_area:
            administrative_area += " " + district
        fields = {
            "place_id": place_id,
            "pool": "PUBLIC",
            "name_ko": row["title"],
            "normalized_name_ko": "".join(
                unicodedata.normalize("NFC", row["title"]).casefold().split()
            ),
            "category": CATEGORIES[str(row["contenttypeid"])],
            "administrative_area": administrative_area,
            "region_code": region_code,
            "address_ko": row["addr1"],
            "latitude": float(row["mapy"]),
            "longitude": float(row["mapx"]),
            "provider_crosswalk": [{"provider": "TOUR_API", "source_id": cid}],
            "evidence_ids": [evidence.evidence_id],
            "duplicate_group_id": "duplicate:" + canonical_sha256(identity),
        }
        places.append(
            PublicPlace.model_validate({**fields, "row_sha256": canonical_sha256(fields)})
        )
    evidence_fields = {
        "schema_version": "public-evidence-inventory.v1",
        "evidence": [
            r.model_dump(mode="json") for r in sorted(evidence_rows, key=lambda r: r.evidence_id)
        ],
    }
    inventory = PublicEvidenceInventory.model_validate(
        {**evidence_fields, "inventory_sha256": canonical_sha256(evidence_fields)}
    )
    catalog_fields = {
        "schema_version": "public-place-catalog.v1",
        "pool": "PUBLIC",
        "region": "전국",
        "places": [r.model_dump(mode="json") for r in sorted(places, key=lambda r: r.place_id)],
        "evidence_inventory_sha256": inventory.inventory_sha256,
        "blind_overlap_count": None,
    }
    catalog = PublicPlaceCatalog.model_validate(
        {**catalog_fields, "catalog_sha256": canonical_sha256(catalog_fields)}
    )
    relation_fields = {
        "schema_version": "public-place-relations.v1",
        "catalog_sha256": catalog.catalog_sha256,
        "catalog_place_ids": [r.place_id for r in catalog.places],
        "relations": [],
    }
    relations = PublicPlaceRelations.model_validate(
        {**relation_fields, "relations_sha256": canonical_sha256(relation_fields)}
    )
    return catalog, inventory, relations
