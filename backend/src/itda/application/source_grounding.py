"""Prepare and replay source-bound facility requirements without changing raw profiles."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from typing import Literal, Protocol

from itda.contracts.grounded_recommendation import (
    GroundedInputAuthority,
    GroundedRunBinding,
    GroundedTripInput,
    TripContextPlace,
    TripContextResponse,
)
from itda.contracts.place_enrichment import confirmed_facility_exclusions
from itda.contracts.source_assessment import SupportState
from itda.domain.canonical import canonical_sha256
from itda.tourism.accessibility import AccessibilityService, AccessibilitySnapshot


class SourceStore(Protocol):
    def put_source(self, payload: dict[str, object]) -> str: ...
    def get_source(self, digest: str) -> dict[str, object] | None: ...
    def get_run_binding(self, run_id: str) -> GroundedRunBinding | None: ...
    def get_request_binding(self, request_id: str) -> GroundedRunBinding | None: ...


@dataclass(frozen=True)
class PreparedGrounding:
    trip_input: GroundedTripInput
    authority: GroundedInputAuthority
    excluded_place_ids: frozenset[str]


class SourceGroundingService:
    def __init__(self, *, accessibility: AccessibilityService, store: SourceStore) -> None:
        self.accessibility = accessibility
        self.store = store

    def prepare(
        self,
        *,
        trip_input: GroundedTripInput,
        raw_release_sha256: str,
        place_ids: tuple[str, ...],
    ) -> PreparedGrounding:
        snapshots = self.accessibility.get_many(place_ids) if trip_input.required_facilities else ()
        hashes = tuple(
            sorted({self.store.put_source(s.model_dump(mode="json")) for s in snapshots})
        )
        excluded = confirmed_facility_exclusions(snapshots, trip_input.required_facilities)
        source_release = canonical_sha256(
            {
                "policy_version": "facility-requirements-v1",
                "raw_release_sha256": raw_release_sha256,
                "source_snapshot_sha256": hashes,
            }
        )
        return PreparedGrounding(
            trip_input=trip_input,
            authority=GroundedInputAuthority(
                trip_input_sha256=trip_input.input_sha256,
                source_release_sha256=source_release,
                source_snapshot_sha256=hashes,
            ),
            excluded_place_ids=frozenset(excluded),
        )

    def context(
        self,
        *,
        run_id: str,
        place_names: dict[str, str],
        trip_input: GroundedTripInput,
        checked_at: datetime,
        binding: GroundedRunBinding | None,
    ) -> TripContextResponse:
        snapshots: dict[str, tuple[str, AccessibilitySnapshot]] = {}
        if binding is not None:
            for digest in binding.source_snapshot_sha256:
                payload = self.store.get_source(digest)
                if payload is None or canonical_sha256(payload) != digest:
                    raise ValueError("missing or altered source snapshot")
                snapshot = AccessibilitySnapshot.model_validate(payload)
                snapshots[snapshot.place_id] = (digest, snapshot)
        mode: Literal["PINNED", "REFRESHED"] = "PINNED" if snapshots else "REFRESHED"
        if not snapshots:
            for snapshot in self.accessibility.get_many(tuple(place_names)):
                digest = self.store.put_source(snapshot.model_dump(mode="json"))
                snapshots[snapshot.place_id] = (digest, snapshot)
        places = []
        for place_id, name in place_names.items():
            entry = snapshots.get(place_id)
            if entry is None:
                # A partial pinned bundle is never silently repaired with today's data.
                places.append(
                    TripContextPlace(
                        place_id=place_id,
                        place_name_ko=name,
                        facts=(),
                        source_snapshot_sha256=None,
                        state="UNAVAILABLE",
                        reason_ko="이 추천을 만들 때 연결된 시설 정보가 없습니다.",
                    )
                )
                continue
            digest, snapshot = entry
            known = sum(f.state != SupportState.UNKNOWN for f in snapshot.facts.values())
            places.append(
                TripContextPlace(
                    place_id=place_id,
                    place_name_ko=name,
                    facts=tuple(snapshot.facts[k] for k in sorted(snapshot.facts)),
                    source_snapshot_sha256=digest,
                    state="AVAILABLE"
                    if known == len(snapshot.facts)
                    else "PARTIAL"
                    if known
                    else "UNAVAILABLE",
                    reason_ko=(
                        "추천 생성 시 확인한 시설 정보입니다. 현재 상태와 달라질 수 있습니다."
                        if mode == "PINNED"
                        else "공식 등록 정보를 새로 확인했습니다. 현장 상태와 다를 수 있습니다."
                    ),
                )
            )
        return TripContextResponse(
            recommendation_run_id=run_id,
            trip_input=trip_input,
            checked_at=checked_at,
            mode=mode,
            places=tuple(places),
        )
