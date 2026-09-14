"""Budgeted Apify pilot with durable start/recovery state and minimal retained post data."""

from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime
from decimal import Decimal, InvalidOperation
from pathlib import Path
from typing import Any, Literal
from urllib.parse import quote

import httpx

from itda.collectors.base import credential_material_present
from itda.domain.canonical import canonical_sha256
from itda.pipeline.destination_evidence import atomic_json, cache_lock

ACTOR_ID = "apify~instagram-hashtag-analytics-scraper"
ACTOR_BUILD = "0.0.538"
API_ROOT = "https://api.apify.com/v2"
ACTORS = {
    "ANALYTICS": (ACTOR_ID, "cHedUknx10dsaavpI", ACTOR_BUILD),
    "POSTS": ("apify~instagram-hashtag-scraper", "reGe1ST3OBgYZSsZJ", "0.0.658"),
    "DETAILS": ("apify~instagram-scraper", "shu8hvrXbJbY3Eb9W", "0.0.781"),
}
TERMINAL = frozenset({"SUCCEEDED", "FAILED", "ABORTED", "TIMED-OUT"})


class SocialCollectionPaused(RuntimeError):
    pass


def _money(value: object) -> Decimal:
    try:
        amount = Decimal(str(value))
    except InvalidOperation as error:
        raise ValueError("INVALID_BUDGET_AMOUNT") from error
    if not amount.is_finite() or amount < 0:
        raise ValueError("INVALID_BUDGET_AMOUNT")
    return amount


class BudgetLedger:
    """One local budget across runs; uncertain starts keep their reservation."""

    def __init__(self, path: Path, *, total_usd: str) -> None:
        self.path = path
        self.total = _money(total_usd)
        if self.total <= 0:
            raise ValueError("POSITIVE_EXPLICIT_BUDGET_REQUIRED")
        with cache_lock(path):
            if path.exists():
                if _money(self._read()["total_usd"]) != self.total:
                    raise ValueError("BUDGET_CANNOT_CHANGE_DURING_RESUME")
            else:
                atomic_json(
                    path,
                    {
                        "schema_version": "apify-budget-ledger.v1",
                        "total_usd": str(self.total),
                        "runs": {},
                    },
                )

    def _read(self) -> dict[str, Any]:
        return json.loads(self.path.read_text())  # type: ignore[no-any-return]

    def get(self, key: str) -> dict[str, Any] | None:
        with cache_lock(self.path):
            row = self._read()["runs"].get(key)
            return dict(row) if row is not None else None

    def reserve(self, key: str, *, max_usd: str, input_sha: str) -> dict[str, Any]:
        cap = _money(max_usd)
        with cache_lock(self.path):
            data = self._read()
            if key in data["runs"]:
                prior = data["runs"][key]
                if prior["input_sha256"] != input_sha or _money(prior["reserved_usd"]) != cap:
                    raise ValueError("RESUMED_INPUT_OR_CAP_CHANGED")
                return dict(prior)
            committed = sum(
                (
                    _money(r["actual_usd"])
                    if r.get("actual_usd") is not None
                    else _money(r["reserved_usd"])
                )
                for r in data["runs"].values()
            )
            if cap <= 0 or committed + cap > self.total:
                raise SocialCollectionPaused("APIFY_PROJECT_BUDGET_EXHAUSTED")
            row = {
                "status": "RESERVED",
                "reserved_usd": str(cap),
                "actual_usd": None,
                "input_sha256": input_sha,
                "run_id": None,
                "created_at": datetime.now(UTC).isoformat(),
            }
            data["runs"][key] = row
            atomic_json(self.path, data)
            return dict(row)

    def update(self, key: str, **fields: Any) -> dict[str, Any]:
        with cache_lock(self.path):
            data = self._read()
            row = data["runs"][key]
            if "actual_usd" in fields and fields["actual_usd"] is not None:
                actual = _money(fields["actual_usd"])
                if actual > _money(row["reserved_usd"]):
                    raise SocialCollectionPaused("APIFY_REPORTED_CHARGE_EXCEEDS_RESERVATION")
                fields["actual_usd"] = str(actual)
            row.update(fields)
            row["updated_at"] = datetime.now(UTC).isoformat()
            atomic_json(self.path, data)
            return dict(row)


def pilot_input(tags: tuple[str, ...]) -> dict[str, Any]:
    if not 1 <= len(tags) <= 120 or len(set(tags)) != len(tags):
        raise ValueError("PILOT_REQUIRES_1_TO_120_UNIQUE_TAGS")
    if any(not tag or len(tag) > 100 or any(c.isspace() for c in tag) for tag in tags):
        raise ValueError("INVALID_HASHTAG")
    return {"hashtags": list(tags), "includeTopPosts": True, "includeLatestPosts": True}


def minimal_post(raw: object) -> dict[str, Any] | None:
    if not isinstance(raw, dict):
        return None
    identifier = raw.get("id") or raw.get("shortCode") or raw.get("url")
    if identifier is None:
        return None
    # Owner profiles, avatars, tagged people, comments and follower information
    # are not needed to analyze a place's represented meaning.
    return {
        "id": str(identifier),
        **{
            key: raw[key]
            for key in (
                "shortCode",
                "url",
                "caption",
                "hashtags",
                "timestamp",
                "type",
                "inputUrl",
                "locationName",
                "locationId",
            )
            if key in raw
        },
        "source_item_sha256": canonical_sha256(raw),
    }


def minimal_result(raw: object) -> dict[str, Any]:
    if not isinstance(raw, dict):
        raise ValueError("SOCIAL_DATASET_ITEM_IS_NOT_OBJECT")
    fields = {
        key: raw[key]
        for key in (
            "name",
            "id",
            "url",
            "postsCount",
            "posts",
            "postsPerDay",
            "error",
            "errorDescription",
        )
        if key in raw
    }
    for group in ("topPosts", "latestPosts"):
        posts = raw.get(group, [])
        if not isinstance(posts, list):
            fields[group] = []
            fields[group + "State"] = "INVALID_FORMAT"
            continue
        unique: dict[str, dict[str, Any]] = {}
        for item in posts:
            cleaned = minimal_post(item)
            if cleaned:
                unique[cleaned["id"]] = cleaned
        fields[group] = list(unique.values())
    fields["source_item_sha256"] = canonical_sha256(raw)
    return fields


class ApifyPilot:
    def __init__(
        self,
        *,
        token: str,
        directory: Path,
        total_budget_usd: str,
        transport: httpx.BaseTransport | None = None,
        mode: Literal["ANALYTICS", "POSTS", "DETAILS"] = "ANALYTICS",
        budget_ledger: Path | None = None,
    ) -> None:
        if not token:
            raise ValueError("APIFY_TOKEN_REQUIRED")
        self._token = token
        self.directory = directory
        self.mode = mode
        self.actor_id, self.actor_internal_id, self.actor_build = ACTORS[mode]
        self.ledger = BudgetLedger(
            budget_ledger or directory / "budget.json", total_usd=total_budget_usd
        )
        self.client = httpx.Client(
            base_url=API_ROOT,
            timeout=45,
            follow_redirects=False,
            trust_env=False,
            headers={"Authorization": "Bearer " + token},
            transport=transport,
        )

    def close(self) -> None:
        self.client.close()

    def _response(self, response: httpx.Response) -> dict[str, Any]:
        if len(response.content) > 32 * 1024 * 1024:
            raise ValueError("APIFY_RESPONSE_TOO_LARGE")
        if credential_material_present(response.content, self._token):
            raise ValueError("CREDENTIAL_REFLECTION_REJECTED")
        if response.status_code == 429:
            raise SocialCollectionPaused("APIFY_RATE_LIMIT_NO_AUTORETRY")
        if response.status_code != 200 and response.status_code != 201:
            raise SocialCollectionPaused(f"APIFY_HTTP_{response.status_code}")
        body = response.json()
        if not isinstance(body, dict) or not isinstance(body.get("data"), dict):
            raise ValueError("APIFY_RESPONSE_ENVELOPE_INVALID")
        return body["data"]  # type: ignore[no-any-return]

    def start(self, tags: tuple[str, ...], *, max_usd: str) -> dict[str, Any]:
        payload = pilot_input(tags)
        if self.mode == "POSTS":
            payload = {"hashtags": list(tags), "resultsType": "posts", "resultsLimit": 5}
        elif self.mode == "DETAILS":
            payload = {
                "directUrls": [
                    "https://www.instagram.com/explore/tags/" + quote(tag, safe="") + "/"
                    for tag in tags
                ],
                "resultsType": "details",
                "resultsLimit": 1,
            }
        request = {"actor_id": self.actor_id, "build": self.actor_build, "input": payload}
        key = canonical_sha256(request)
        with cache_lock(self.directory / "start.lock"):
            prior = self.ledger.get(key)
            if prior is not None:
                if prior.get("run_id"):
                    atomic_json(self.directory / "active-run.json", prior | {"request_sha256": key})
                    return prior
                # A previous process may have died after the POST was transmitted.
                # Never launch again merely because no response was observed.
                raise SocialCollectionPaused("APIFY_START_UNCERTAIN_RECONCILE_EXISTING_RUN")
            self.ledger.reserve(key, max_usd=max_usd, input_sha=canonical_sha256(payload))
            atomic_json(self.directory / "input.json", request | {"request_sha256": key})
            self.ledger.update(key, status="STARTING")
            try:
                response = self.client.post(
                    f"/acts/{self.actor_id}/runs",
                    params={
                        "build": self.actor_build,
                        "timeout": "1800",
                        "maxTotalChargeUsd": max_usd,
                    },
                    json=payload,
                )
                run = self._response(response)
                if not run.get("id"):
                    raise ValueError("APIFY_RUN_ID_MISSING")
            except (httpx.HTTPError, ValueError, SocialCollectionPaused):
                self.ledger.update(key, status="START_UNCERTAIN")
                raise
            result = self.ledger.update(
                key,
                status=run.get("status", "READY"),
                run_id=run["id"],
                actor_build_id=run.get("buildId"),
                dataset_id=run.get("defaultDatasetId"),
            )
            atomic_json(self.directory / "active-run.json", result | {"request_sha256": key})
            return result

    def poll(self) -> dict[str, Any]:
        active = json.loads((self.directory / "active-run.json").read_text())
        key, run_id = active["request_sha256"], active["run_id"]
        run = self._response(self.client.get(f"/actor-runs/{run_id}"))
        if run.get("id") != run_id:
            raise ValueError("APIFY_RUN_IDENTITY_MISMATCH")
        if run.get("actId") != self.actor_internal_id:
            raise ValueError("APIFY_ACTOR_IDENTITY_MISMATCH")
        status = run.get("status")
        if not isinstance(status, str):
            raise ValueError("APIFY_RUN_STATUS_MISSING")
        cap = run.get("options", {}).get("maxTotalChargeUsd")
        if cap is None or _money(cap) > _money(active["reserved_usd"]):
            self.client.post(f"/actor-runs/{run_id}/abort")
            self.ledger.update(key, status="ABORT_REQUESTED_COST_CAP_UNVERIFIED")
            raise SocialCollectionPaused("APIFY_APPLIED_COST_CAP_NOT_VERIFIED_ABORT_REQUESTED")
        actual = run.get("usageTotalUsd") if status in TERMINAL else None
        result = self.ledger.update(
            key,
            status=status,
            actual_usd=actual,
            actor_build_id=run.get("buildId"),
            dataset_id=run.get("defaultDatasetId"),
            finished_at=run.get("finishedAt"),
            run_record_sha256=canonical_sha256(run),
        )
        atomic_json(self.directory / "active-run.json", result | {"request_sha256": key})
        return result

    def results(self) -> list[dict[str, Any]]:
        active = json.loads((self.directory / "active-run.json").read_text())
        if active["status"] not in TERMINAL:
            raise SocialCollectionPaused("APIFY_RUN_NOT_TERMINAL")
        dataset = active.get("dataset_id")
        if not dataset:
            raise ValueError("APIFY_DATASET_MISSING")
        retained: list[dict[str, Any]] = []
        offset = 0
        response_hashes = []
        while True:
            response = self.client.get(
                f"/datasets/{dataset}/items",
                params={"offset": offset, "limit": 120, "clean": "true"},
            )
            if response.status_code != 200:
                raise SocialCollectionPaused(f"APIFY_DATASET_HTTP_{response.status_code}")
            if len(response.content) > 32 * 1024 * 1024:
                raise ValueError("APIFY_DATASET_PAGE_TOO_LARGE")
            if credential_material_present(response.content, self._token):
                raise ValueError("CREDENTIAL_REFLECTION_REJECTED")
            rows = response.json()
            if not isinstance(rows, list):
                raise ValueError("APIFY_DATASET_IS_NOT_LIST")
            response_hashes.append(hashlib.sha256(response.content).hexdigest())
            for row in rows:
                if self.mode == "POSTS":
                    cleaned = minimal_post(row)
                    if cleaned is None:
                        cleaned = {
                            k: row[k]
                            for k in ("inputUrl", "error", "errorDescription")
                            if isinstance(row, dict) and k in row
                        }
                    retained.append(cleaned)
                else:
                    retained.append(minimal_result(row))
            if len(rows) < 120:
                break
            offset += len(rows)
            if offset >= 480:
                raise ValueError("PILOT_DATASET_EXCEEDS_EXPECTED_BOUND")
        atomic_json(
            self.directory / "results.json",
            {
                "schema_version": "instagram-pilot-results.v1",
                "actor_id": self.actor_id,
                "mode": self.mode,
                "actor_build_id": active["actor_build_id"],
                "run_id": active["run_id"],
                "request_sha256": active["request_sha256"],
                "retrieved_at": datetime.now(UTC).isoformat(),
                "response_page_sha256": response_hashes,
                "run_status": active["status"],
                "actual_usd": active.get("actual_usd"),
                "items": retained,
                "human_validation": "NOT_CONDUCTED_BY_USER_INSTRUCTION",
            },
        )
        return retained
