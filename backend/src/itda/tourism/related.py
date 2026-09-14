"""Navigation-related candidates after canonical eligibility and pair filters."""

from __future__ import annotations

import re
from collections.abc import Callable, Sequence
from datetime import UTC, datetime
from zoneinfo import ZoneInfo

from itda.collectors.kto_related import RelatedDestinationsClient
from itda.contracts.place_enrichment import RelatedCanonicalPlace, RelatedContext, RelatedSuggestion
from itda.contracts.source_assessment import SourceService
from itda.domain.canonical import canonical_sha256
from itda.tourism.temporal import TemporalContextService, TemporalPolicy
from itda.tourism.temporal_cache import TemporalSourceSnapshot


def _name(value: object) -> str:
    return re.sub(r"[\W_]+", "", str(value or "").casefold())


class RelatedDestinationsService:
    def __init__(
        self,
        *,
        places: Sequence[RelatedCanonicalPlace],
        client: RelatedDestinationsClient | None,
        loader: TemporalContextService | None = None,
        policy: TemporalPolicy | None = None,
        clock: Callable[[], datetime] = lambda: datetime.now(UTC),
    ) -> None:
        self.places = {row.place_id: row for row in places}
        self.client = client
        self.clock = clock
        if len(self.places) != len(places):
            raise ValueError("duplicate canonical related place")
        self.loader = loader or TemporalContextService(places=places, policy=policy, clock=clock)

    def get_context_with_sources(
        self,
        *,
        place_id: str,
        base_month: str,
        eligible_place_ids: tuple[str, ...],
        purpose: str = "SIGHTSEEING",
        condition_excluded_place_ids: tuple[str, ...] = (),
        selected_place_ids: tuple[str, ...] = (),
        cannot_coappear_pairs: tuple[tuple[str, str], ...] = (),
        limit: int = 3,
    ) -> tuple[RelatedContext, tuple[TemporalSourceSnapshot, ...]]:
        place = self.places[place_id]
        if re.fullmatch(
            r"\d{4}(0[1-9]|1[0-2])", base_month
        ) is None or base_month >= self.clock().astimezone(ZoneInfo("Asia/Seoul")).strftime("%Y%m"):
            raise ValueError("related source period must be a complete historical month")
        if not 1 <= limit <= 5 or purpose not in {"SIGHTSEEING", "FOOD", "LODGING", "MIXED"}:
            raise ValueError("invalid related purpose or limit")
        all_ids = (
            set(eligible_place_ids) | set(condition_excluded_place_ids) | set(selected_place_ids)
        )
        if any(
            left not in self.places or right not in self.places or left == right
            for left, right in cannot_coappear_pairs
        ) or not all_ids <= set(self.places):
            raise ValueError("related eligibility and constraints must use canonical IDs")
        eligibility = canonical_sha256(
            {
                "eligible": sorted(set(eligible_place_ids)),
                "excluded": sorted(set(condition_excluded_place_ids)),
                "selected": sorted(set(selected_place_ids)),
                "purpose": purpose,
                "cannot_coappear": sorted({tuple(sorted(pair)) for pair in cannot_coappear_pairs}),
                "limit": limit,
            }
        )
        snapshot = self.loader.collect_source_batch(
            SourceService.RELATED,
            "areaBasedList1",
            {"baseYm": base_month, "areaCd": place.region_code[:2], "signguCd": place.region_code},
            self.client,
        )
        reason: str = snapshot.reason
        suggestions: list[RelatedSuggestion] = []
        filtered = 0

        def resolve_name(name: object, region_code: object) -> RelatedCanonicalPlace | None:
            matches = [
                row
                for row in self.places.values()
                if row.region_code == str(region_code)
                and _name(name) in {_name(row.name_ko), *map(_name, row.aliases)}
            ]
            return matches[0] if len(matches) == 1 else None

        if snapshot.complete and snapshot.rows:
            rows = [
                row
                for row in snapshot.rows
                if row.get("areaCd") == place.region_code[:2]
                and row.get("signguCd") == place.region_code
                and row.get("baseYm") == base_month
                and resolve_name(row.get("tAtsNm"), place.region_code) == place
            ]
            source_ids = {str(row.get("tAtsCd", "")) for row in rows}
            if not rows:
                reason = "PLACE_NOT_MATCHED"
            elif len(source_ids) != 1 or not next(iter(source_ids)):
                reason = "AMBIGUOUS_MATCH"
            elif self.clock() >= snapshot.expires_at:
                reason = "STALE"
            else:
                allowed_categories = {
                    "SIGHTSEEING": {"관광지", "문화시설", "레포츠", "축제·공연·행사"},
                    "FOOD": {"음식점"},
                    "LODGING": {"숙박"},
                }
                forbidden = {frozenset(pair) for pair in cannot_coappear_pairs}
                selected = {place_id, *selected_place_ids}
                groups = {self.places[key].duplicate_group_id for key in selected}
                eligible = set(eligible_place_ids) - set(condition_excluded_place_ids)
                candidates = []
                for row in rows:
                    target = resolve_name(row.get("rlteTatsNm"), row.get("rlteSignguCd"))
                    identifier = str(row.get("rlteTatsCd", ""))
                    rank = str(row.get("rlteRank", ""))
                    matching_ids = {
                        str(other.get("rlteTatsCd", ""))
                        for other in rows
                        if _name(other.get("rlteTatsNm")) == _name(row.get("rlteTatsNm"))
                    }
                    if (
                        target is None
                        or target.place_id not in eligible
                        or row.get("rlteRegnCd") != target.region_code[:2]
                        or row.get("rlteSignguCd") != target.region_code
                        or not identifier
                        or len(matching_ids) != 1
                        or re.fullmatch(r"[1-9]\d{0,5}", rank) is None
                    ):
                        filtered += 1
                        continue
                    if purpose != "MIXED" and target.category not in allowed_categories[purpose]:
                        filtered += 1
                        continue
                    candidates.append((int(rank), target.place_id, identifier))
                for rank_value, target_id, identifier in sorted(set(candidates)):
                    target = self.places[target_id]
                    if (
                        target_id in selected
                        or target.duplicate_group_id in groups
                        or any(frozenset({target_id, other}) in forbidden for other in selected)
                    ):
                        filtered += 1
                        continue
                    if len(suggestions) >= limit:
                        filtered += 1
                        continue
                    suggestions.append(
                        RelatedSuggestion(
                            place_id=target_id,
                            place_name_ko=target.name_ko,
                            provider_entity_id=identifier,
                            source_provider_entity_id=next(iter(source_ids)),
                            provider_rank=rank_value,
                        )
                    )
                    selected.add(target_id)
                    groups.add(target.duplicate_group_id)
                reason = "NONE" if suggestions else "NO_ELIGIBLE_RELATED_PLACES"
        draft = RelatedContext.model_construct(
            place_id=place_id,
            base_month=base_month,
            state="AVAILABLE" if suggestions else "UNKNOWN",
            reason=reason,
            suggestions=tuple(suggestions),
            eligibility_sha256=eligibility,
            filtered_count=filtered,
            provider_result_code=snapshot.provider_result_code,
            source_snapshot_sha256=(canonical_sha256(snapshot.model_dump(mode="json")),),
            receipts=snapshot.receipts,
            retrieved_at=snapshot.retrieved_at,
            expires_at=snapshot.expires_at,
            context_sha256="0" * 64,
        )
        payload = draft.model_dump(mode="json", exclude={"context_sha256"})
        return RelatedContext.model_validate(
            {**payload, "context_sha256": canonical_sha256(payload)}
        ), (snapshot,)

    def get_context(
        self,
        *,
        place_id: str,
        base_month: str,
        eligible_place_ids: tuple[str, ...],
        purpose: str = "SIGHTSEEING",
        condition_excluded_place_ids: tuple[str, ...] = (),
        selected_place_ids: tuple[str, ...] = (),
        cannot_coappear_pairs: tuple[tuple[str, str], ...] = (),
        limit: int = 3,
    ) -> RelatedContext:
        return self.get_context_with_sources(
            place_id=place_id,
            base_month=base_month,
            eligible_place_ids=eligible_place_ids,
            purpose=purpose,
            condition_excluded_place_ids=condition_excluded_place_ids,
            selected_place_ids=selected_place_ids,
            cannot_coappear_pairs=cannot_coappear_pairs,
            limit=limit,
        )[0]
