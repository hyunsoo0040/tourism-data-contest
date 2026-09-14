"""Current national data authority; archived catalogs remain read-only history."""

from pathlib import Path

from itda.contracts.grounded_release import GroundedReleaseCandidate
from itda.contracts.grounded_source import GroundedSourceRelease
from itda.contracts.mvp_public_catalog import PublicPlaceCatalog

NATIONAL_CURRENT_DIRECTORY = Path("artifacts/national/current")
NATIONAL_CATALOG_PATH = NATIONAL_CURRENT_DIRECTORY / "catalog.json"
NATIONAL_EVIDENCE_PATH = NATIONAL_CURRENT_DIRECTORY / "evidence.json"
NATIONAL_RELATIONS_PATH = NATIONAL_CURRENT_DIRECTORY / "relations.json"
NATIONAL_SIGHTSEEING_CATEGORIES = frozenset({"관광지", "문화시설", "레포츠"})


def is_national_catalog(catalog: PublicPlaceCatalog) -> bool:
    return (
        catalog.region == "전국"
        and bool(catalog.places)
        and all(
            place.place_id.startswith("public:korea:")
            and place.region_code is not None
            and place.category in NATIONAL_SIGHTSEEING_CATEGORIES
            for place in catalog.places
        )
    )


def is_national_candidate(
    candidate: GroundedReleaseCandidate,
    catalog: PublicPlaceCatalog | None = None,
) -> bool:
    raw = candidate.raw_release
    if (
        not isinstance(raw, GroundedSourceRelease)
        or not raw.profiles
        or any(not profile.place_id.startswith("public:korea:") for profile in raw.profiles)
    ):
        return False
    if catalog is None:
        return True
    return (
        is_national_catalog(catalog)
        and raw.catalog_sha256 == catalog.catalog_sha256
        and raw.evidence_inventory_sha256 == catalog.evidence_inventory_sha256
        and tuple(profile.place_id for profile in raw.profiles)
        == tuple(place.place_id for place in catalog.places)
        and all(
            profile.catalog_row_sha256 == place.row_sha256
            for profile, place in zip(raw.profiles, catalog.places, strict=True)
        )
    )
