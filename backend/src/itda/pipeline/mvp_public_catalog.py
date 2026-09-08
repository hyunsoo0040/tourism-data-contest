"""Provider-free construction for the Gyeongju PUBLIC scoring catalog."""

from __future__ import annotations

import hashlib
import html
import json
import unicodedata
from collections.abc import Iterable, Iterator, Mapping
from datetime import date
from pathlib import Path

from itda.contracts.mvp_catalog_enrichment import (
    MvpCatalogEnrichmentOutcome,
    MvpCatalogEnrichmentResult,
)
from itda.contracts.mvp_public_catalog import (
    CatalogGapReport,
    OfficialDatasetPermissionMetadata,
    PublicEvidence,
    PublicEvidenceInventory,
    PublicPlace,
    PublicPlaceCatalog,
    PublicPlaceRelation,
    PublicPlaceRelations,
)
from itda.domain.canonical import canonical_sha256

_PERMISSION_SNAPSHOT_MAX_BYTES = 2 * 1024 * 1024
_V5_RESULT_SHA256 = "b38ff474f8e4baabc0d61dbd6c0019dbb32bc437fe73f6fa5bd4255e6d4946fe"
_V6_RESULT_SHA256 = "2f5d61f12b9790e69340217f209a9a93ab037ff0d505a346d66b8c173f9c4825"
_CONTENT_TYPE_CATEGORIES = {
    "12": "관광지",
    "14": "문화시설",
    "15": "축제·공연·행사",
    "28": "레포츠",
    "32": "숙박",
    "38": "쇼핑",
    "39": "음식점",
}


def normalize_permission_snapshot(raw: bytes) -> str:
    if not raw or len(raw) > _PERMISSION_SNAPSHOT_MAX_BYTES:
        raise ValueError("official permission snapshot size is invalid")
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as error:
        raise ValueError("official permission snapshot is not UTF-8") from error
    return " ".join(unicodedata.normalize("NFC", html.unescape(text)).split())


def verify_permission_snapshot(
    permission: OfficialDatasetPermissionMetadata,
    raw: bytes,
) -> str:
    raw_sha256 = hashlib.sha256(raw).hexdigest()
    if raw_sha256 != permission.raw_response_sha256:
        raise ValueError("official permission snapshot hash does not match")
    normalized = normalize_permission_snapshot(raw)
    quotes = (
        permission.dataset_title_ko,
        permission.provider_name_ko,
        permission.license_type,
        permission.attribution_text_ko
        if permission.attribution_required
        else permission.no_attribution_evidence_ko,
        permission.public_display.evidence_quote,
        permission.transformation_and_derived_scores.evidence_quote,
        permission.third_party_model_processing_and_retention.evidence_quote,
        permission.excerpt_and_release_redistribution.evidence_quote,
        permission.commercial_scope.evidence_quote,
        permission.restrictions_ko,
    )
    for quote in quotes:
        normalized_quote = (
            ""
            if quote is None
            else " ".join(unicodedata.normalize("NFC", html.unescape(quote)).split())
        )
        if not normalized_quote or normalized_quote not in normalized:
            raise ValueError("official permission evidence quote is absent from snapshot")
    return raw_sha256


def build_catalog_gap_report(
    source_path: Path,
    *,
    permissions: Iterable[OfficialDatasetPermissionMetadata] = (),
    permission_snapshots: Mapping[str, bytes] | None = None,
) -> CatalogGapReport:
    raw = source_path.read_bytes()
    payload = json.loads(raw)
    candidates = payload.get("candidates")
    if not isinstance(candidates, list):
        raise ValueError("catalog source candidates are missing")
    description_ready_ids: set[str] = set()
    enrichment_ids: set[str] = set()
    for row in candidates:
        if not isinstance(row, dict):
            continue
        gates = row.get("non_image_gates")
        place_id = row.get("place_entity_id")
        if not isinstance(gates, dict) or not isinstance(place_id, str):
            continue
        base = ("canonical_identity", "coordinates", "dataset_rights")
        if not all(gates.get(name) == "PASS" for name in base):
            continue
        if gates.get("description") == "PASS":
            description_ready_ids.add(place_id)
        elif gates.get("description") != "PASS":
            enrichment_ids.add(place_id)

    permission_rows = tuple(sorted(permissions, key=lambda row: row.official_dataset_id))
    snapshots = {} if permission_snapshots is None else dict(permission_snapshots)
    if permission_rows or snapshots:
        if tuple(row.official_dataset_id for row in permission_rows) != (
            "15101578",
            "15101971",
        ):
            raise ValueError("exact official dataset permission metadata is required")
        permission_by_hash = {row.metadata_sha256: row for row in permission_rows}
        if len(permission_by_hash) != 2 or set(snapshots) != set(permission_by_hash):
            raise ValueError("exact permission snapshots must cover official metadata")
        if any(not row.permits_mvp_use for row in permission_rows):
            raise ValueError("official permission metadata does not permit all MVP usage lanes")
        for metadata_sha256, permission in permission_by_hash.items():
            verify_permission_snapshot(permission, snapshots[metadata_sha256])
        strict_rights_state = "PERMISSION_METADATA_VERIFIED"
        permission_metadata_present = True
        permission_bindings = tuple(
            {
                "official_dataset_id": row.official_dataset_id,
                "metadata_sha256": row.metadata_sha256,
                "raw_response_sha256": row.raw_response_sha256,
            }
            for row in permission_rows
        )
    else:
        strict_rights_state = "BLOCKED_RIGHTS_METADATA"
        permission_metadata_present = False
        permission_bindings = ()

    description_ready = len(description_ready_ids)
    fields = {
        "schema_version": "public-place-catalog-gap.v3",
        "tracked_candidate_count": len(candidates),
        "description_ready_historical_count": description_ready,
        "description_enrichment_candidate_count": len(enrichment_ids),
        "required_count": 100,
        "preliminary_description_gap_count": max(0, 100 - description_ready),
        "strict_rights_qualified_count": None,
        "strict_rights_state": strict_rights_state,
        "catalog_ready": False,
        "permission_metadata_present": permission_metadata_present,
        "permission_bindings": permission_bindings,
        "provider_traffic": False,
        "secret_access": False,
        "source_file_sha256": hashlib.sha256(raw).hexdigest(),
    }
    return CatalogGapReport.model_validate({**fields, "report_sha256": canonical_sha256(fields)})


def materialize_public_catalog(
    v5_result_path: Path,
    v6_result_path: Path,
    *,
    permission: OfficialDatasetPermissionMetadata,
    permission_snapshots: Mapping[str, bytes],
    reference_date: date,
) -> tuple[PublicPlaceCatalog, PublicEvidenceInventory, PublicPlaceRelations]:
    if permission.official_dataset_id != "15101578":
        raise ValueError("TourAPI permission metadata is required")
    snapshot = permission_snapshots.get(permission.metadata_sha256)
    if (
        snapshot is None
        or verify_permission_snapshot(permission, snapshot) != permission.raw_response_sha256
    ):
        raise ValueError("TourAPI permission snapshot is not verified")
    v5_result = MvpCatalogEnrichmentResult.model_validate_json(v5_result_path.read_bytes())
    v6_result = MvpCatalogEnrichmentResult.model_validate_json(v6_result_path.read_bytes())
    if v5_result.result_sha256 != _V5_RESULT_SHA256:
        raise ValueError("v5 enrichment result is not the verified collection")
    if v6_result.result_sha256 != _V6_RESULT_SHA256:
        raise ValueError("v6 enrichment result is not the verified collection")

    v5_rows = tuple(_successful_response_rows(v5_result_path.parent, v5_result))
    v6_rows = tuple(_successful_response_rows(v6_result_path.parent, v6_result))
    if len(v5_rows) != 77 or len(v6_rows) != 39:
        raise ValueError("verified enrichment success counts changed")
    selected = tuple(sorted(v5_rows, key=_materialization_key)) + tuple(
        sorted(v6_rows, key=_materialization_key)[:23]
    )
    if len(selected) != 100:
        raise ValueError("materialization requires exactly 100 verified responses")

    evidence_rows: list[PublicEvidence] = []
    place_rows: list[PublicPlace] = []
    for outcome, item in selected:
        name = _required_text(item, "title", "name")
        address = _required_text(item, "addr1", "address")
        latitude = _required_coordinate(item, "mapy", 35.0, 36.5)
        longitude = _required_coordinate(item, "mapx", 128.0, 130.5)
        content_type = _required_text(item, "contenttypeid", "contentTypeId")
        category = _CONTENT_TYPE_CATEGORIES.get(content_type)
        if category is None:
            raise ValueError("TourAPI content type is unsupported")
        identity = {
            "provider": "TOUR_API",
            "source_id": outcome.provider_content_id,
            "name_ko": name,
            "latitude": latitude,
            "longitude": longitude,
        }
        place_digest = canonical_sha256(identity)
        evidence_digest = canonical_sha256(
            {"place": place_digest, "response": outcome.raw_response_sha256}
        )
        evidence_id = f"evidence:{evidence_digest}"
        evidence_fields = {
            "evidence_id": evidence_id,
            "provider": "TOUR_API",
            "official_dataset_id": "15101578",
            "provider_source_id": outcome.provider_content_id,
            "official_license_url": permission.official_url,
            "license_type": permission.license_type,
            "attribution_text": permission.attribution_for_release,
            "reference_date": reference_date,
            "excerpt": outcome.overview,
            "source_response_sha256": outcome.raw_response_sha256,
            "permission_metadata": permission,
            "commercial_use_allowed": True,
            "transform_allowed": True,
            "display_allowed": True,
            "model_input_allowed": True,
            "release_redistribution_allowed": True,
            "third_party_model_processing_allowed": True,
        }
        evidence_rows.append(
            PublicEvidence(
                **evidence_fields,
                evidence_sha256=canonical_sha256(
                    {
                        **evidence_fields,
                        "reference_date": reference_date.isoformat(),
                        "permission_metadata": permission.model_dump(mode="json"),
                    }
                ),
            )
        )
        normalized_name = "".join(unicodedata.normalize("NFC", name).casefold().split())
        place_fields = {
            "place_id": f"public:gyeongju:{place_digest}",
            "pool": "PUBLIC",
            "name_ko": name,
            "normalized_name_ko": normalized_name,
            "category": category,
            "administrative_area": "경주시",
            "address_ko": address,
            "latitude": latitude,
            "longitude": longitude,
            "provider_crosswalk": (
                {"provider": "TOUR_API", "source_id": outcome.provider_content_id},
            ),
            "evidence_ids": (evidence_id,),
            "duplicate_group_id": f"duplicate:{canonical_sha256({'identity': identity})}",
        }
        place_rows.append(PublicPlace(**place_fields, row_sha256=canonical_sha256(place_fields)))

    evidence = tuple(sorted(evidence_rows, key=lambda row: row.evidence_id))
    inventory_fields = {"schema_version": "public-evidence-inventory.v1", "evidence": evidence}
    inventory = PublicEvidenceInventory(
        **inventory_fields,
        inventory_sha256=canonical_sha256(
            {
                "schema_version": inventory_fields["schema_version"],
                "evidence": [row.model_dump(mode="json") for row in evidence],
            }
        ),
    )
    catalog, relations = build_public_catalog(
        place_rows,
        inventory,
        permission_snapshots={permission.metadata_sha256: snapshot},
        cannot_coappear=(),
    )
    return catalog, inventory, relations


def _successful_response_rows(
    root: Path,
    result: MvpCatalogEnrichmentResult,
) -> Iterator[tuple[MvpCatalogEnrichmentOutcome, Mapping[str, object]]]:
    for outcome in result.outcomes:
        if outcome.status != "SUCCESS":
            continue
        if outcome.raw_response_file is None or outcome.raw_response_sha256 is None:
            raise ValueError("successful enrichment response lineage is absent")
        path = root / outcome.raw_response_file
        raw = path.read_bytes()
        if hashlib.sha256(raw).hexdigest() != outcome.raw_response_sha256:
            raise ValueError("enrichment response hash does not match")
        payload = json.loads(raw)
        matching = tuple(
            item
            for item in _iter_mappings(payload)
            if _optional_text(item, "contentid", "contentId") == outcome.provider_content_id
        )
        if len(matching) != 1:
            raise ValueError("enrichment response content ID does not match")
        item = matching[0]
        if _required_text(item, "overview") != outcome.overview:
            raise ValueError("enrichment response overview does not match")
        yield outcome, item


def _iter_mappings(value: object) -> Iterator[Mapping[str, object]]:
    if isinstance(value, Mapping):
        if "contentid" in value or "contentId" in value:
            yield value
        for child in value.values():
            yield from _iter_mappings(child)
    elif isinstance(value, list):
        for child in value:
            yield from _iter_mappings(child)


def _optional_text(item: Mapping[str, object], *names: str) -> str | None:
    for name in names:
        value = item.get(name)
        if isinstance(value, str) and value.strip():
            return " ".join(value.strip().split())
        if isinstance(value, int):
            return str(value)
    return None


def _required_text(item: Mapping[str, object], *names: str) -> str:
    value = _optional_text(item, *names)
    if value is None:
        raise ValueError("materialized TourAPI text is absent")
    return value


def _required_coordinate(
    item: Mapping[str, object],
    name: str,
    minimum: float,
    maximum: float,
) -> float:
    raw = item.get(name)
    if not isinstance(raw, (str, int, float)) or isinstance(raw, bool):
        raise ValueError("materialized TourAPI coordinate is absent")
    value = float(raw)
    if not minimum <= value <= maximum:
        raise ValueError("materialized TourAPI coordinate is outside Gyeongju")
    return value


def _materialization_key(
    row: tuple[MvpCatalogEnrichmentOutcome, Mapping[str, object]],
) -> tuple[str, str]:
    return row[0].place_entity_id, row[0].provider_content_id


def build_public_catalog(
    candidates: Iterable[PublicPlace],
    evidence_inventory: PublicEvidenceInventory,
    *,
    permission_snapshots: Mapping[str, bytes],
    cannot_coappear: Iterable[tuple[str, str, str]],
    blind_overlap_count: int = 0,
) -> tuple[PublicPlaceCatalog, PublicPlaceRelations]:
    permission_by_hash = {
        row.permission_metadata.metadata_sha256: row.permission_metadata
        for row in evidence_inventory.evidence
    }
    if set(permission_snapshots) != set(permission_by_hash):
        raise ValueError("exact permission snapshots must cover public evidence metadata")
    for metadata_sha256, permission in permission_by_hash.items():
        verify_permission_snapshot(permission, permission_snapshots[metadata_sha256])
    places = tuple(sorted(candidates, key=lambda row: row.place_id))
    if len(places) != 100:
        raise ValueError("public catalog requires exactly 100 candidates")
    evidence_ids = {row.evidence_id for row in evidence_inventory.evidence}
    if any(not set(place.evidence_ids).issubset(evidence_ids) for place in places):
        raise ValueError("public place references evidence outside the inventory")
    if blind_overlap_count != 0:
        raise ValueError("BLIND overlap is non-zero")
    catalog_fields = {
        "schema_version": "public-place-catalog.v1",
        "pool": "PUBLIC",
        "region": "경주시",
        "places": places,
        "evidence_inventory_sha256": evidence_inventory.inventory_sha256,
        "blind_overlap_count": 0,
    }
    catalog = PublicPlaceCatalog.model_validate(
        {
            **catalog_fields,
            "catalog_sha256": canonical_sha256(
                {
                    **catalog_fields,
                    "places": [row.model_dump(mode="json") for row in places],
                }
            ),
        }
    )
    relation_rows = tuple(
        sorted(
            (
                PublicPlaceRelation(
                    relation_type="CANNOT_COAPPEAR",
                    left_place_id=min(left, right),
                    right_place_id=max(left, right),
                    reason=reason,
                )
                for left, right, reason in cannot_coappear
            ),
            key=lambda row: (row.left_place_id, row.right_place_id),
        )
    )
    relation_fields = {
        "schema_version": "public-place-relations.v1",
        "catalog_sha256": catalog.catalog_sha256,
        "catalog_place_ids": tuple(row.place_id for row in places),
        "relations": relation_rows,
    }
    relations = PublicPlaceRelations.model_validate(
        {
            **relation_fields,
            "relations_sha256": canonical_sha256(
                {
                    **relation_fields,
                    "catalog_place_ids": list(relation_fields["catalog_place_ids"]),
                    "relations": [row.model_dump(mode="json") for row in relation_rows],
                }
            ),
        }
    )
    return catalog, relations
