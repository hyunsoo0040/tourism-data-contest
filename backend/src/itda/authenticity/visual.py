"""Visual preferences replace their owned facet comparison, never add a second bonus."""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from itda.authenticity.rubric import FacetKey
from itda.contracts.destination_mood import DestinationMoodBundle
from itda.contracts.visual_mood import VisualMoodDimension
from itda.domain.grounded_scoring import half_up
from itda.domain.visual_mood import aggregate_moods

VISUAL_FACETS: dict[VisualMoodDimension, FacetKey] = {
    VisualMoodDimension.GREENERY: "R.b",
    VisualMoodDimension.WATER: "R.b",
    VisualMoodDimension.OPEN_COMPOSITION: "R.b",
    VisualMoodDimension.TRADITIONAL_APPEARANCE: "E.c",
    VisualMoodDimension.CONTEMPORARY_DESIGN: "E.c",
    VisualMoodDimension.WARM_LIGHT: "E.c",
    VisualMoodDimension.VIVID_COLOR: "E.c",
    VisualMoodDimension.NIGHT_LIGHTING: "E.c",
}


def compare_visual(
    facet: FacetKey,
    targets: Mapping[VisualMoodDimension, int],
    reference: DestinationMoodBundle | None,
) -> tuple[int | None, list[dict[str, Any]]]:
    requested = {k: v for k, v in targets.items() if VISUAL_FACETS[k] == facet}
    if not requested:
        return None, []
    if reference is None:
        return None, [
            {"dimension": k.value, "target": v * 25, "actual": None, "fit": None}
            for k, v in requested.items()
        ]
    DestinationMoodBundle.model_validate_json(reference.model_dump_json())
    values = {
        m.dimension: m.value
        for m in aggregate_moods(tuple(i.candidate_set for i in reference.images))
    }
    parts: list[dict[str, Any]] = []
    for key, target in requested.items():
        value = values.get(key)
        parts.append(
            {
                "dimension": key.value,
                "target": target * 25,
                "actual": value,
                "fit": 100 - abs(value - target * 25) if value is not None else None,
            }
        )
    known = [p["fit"] for p in parts if p["fit"] is not None]
    # Do not silently drop a selected but unobserved visual requirement.
    return (half_up(sum(known), len(known)) if len(known) == len(requested) else None), parts
