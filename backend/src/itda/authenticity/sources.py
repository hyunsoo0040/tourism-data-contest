"""Read immutable national source snapshots without reading their old scores."""

from __future__ import annotations

from pathlib import Path
from typing import Any, Literal

from itda.authenticity.contracts import Appearance, Evidence, Place, Receipt, SourceBundle
from itda.contracts.source_assessment import SourceService
from itda.domain.canonical import canonical_sha256
from itda.pipeline.destination_evidence import DestinationEvidenceSnapshot


def seal_evidence(fields: dict[str, Any]) -> Evidence:
    # Materialize defaults before hashing; do not accept caller-provided hash authority.
    normalized = dict(fields)
    normalized["receipt"] = Receipt.model_validate(fields["receipt"])
    normalized["match_basis"] = tuple(fields.get("match_basis", ()))
    if fields.get("appearance") is not None:
        normalized["appearance"] = Appearance.model_validate(fields["appearance"])
    draft = Evidence.model_construct(**normalized)
    payload = draft.model_dump(mode="json", exclude={"record_sha256"})
    return Evidence.model_validate(payload | {"record_sha256": canonical_sha256(payload)})


def seal_bundle(place: Place, evidence: tuple[Evidence, ...], parent_sha: str) -> SourceBundle:
    payload = {
        "schema_version": "authenticity-source.v1",
        "place": place.model_dump(mode="json"),
        "evidence": [
            e.model_dump(mode="json") for e in sorted(evidence, key=lambda e: e.evidence_id)
        ],
        "parent_source_sha256": parent_sha,
    }
    return SourceBundle.model_validate(payload | {"bundle_sha256": canonical_sha256(payload)})


def import_official_source(
    path: Path,
    *,
    duplicate_group_id: str,
    cohort: Literal["initial", "additional", "new-evaluation", "synthetic"],
) -> SourceBundle:
    original = DestinationEvidenceSnapshot.model_validate_json(path.read_bytes())
    records = []
    for item in original.evidence:
        if item.receipt.service not in {SourceService.TOUR, SourceService.ODII}:
            continue
        if item.scope != "PLACE" or item.place_match is None:
            continue
        if item.modality == "IMAGE_PIXELS":
            continue
        if item.receipt.response_sha256 is None:
            continue
        provider: Literal["Odii", "KorService2"] = (
            "Odii" if item.receipt.service == SourceService.ODII else "KorService2"
        )
        receipt = Receipt(
            provider=provider,
            operation=item.receipt.operation,
            provider_record_id=str(
                item.place_match.provider_entity_id or original.place.provider_content_id
            ),
            retrieved_at=item.receipt.retrieved_at,
            source_modified_at=item.receipt.source_modified_at,
            request_sha256=canonical_sha256(item.receipt.request_scope),
            response_sha256=item.receipt.response_sha256,
            source_record_sha256=canonical_sha256(item.model_dump(mode="json")),
        )
        records.append(
            seal_evidence(
                {
                    "evidence_id": item.evidence_id,
                    "place_id": original.place.place_id,
                    "modality": "TEXT",
                    "state": "AVAILABLE",
                    "receipt": receipt,
                    "place_match": "VERIFIED"
                    if item.place_match.state == "MATCHED"
                    else "AMBIGUOUS",
                    "match_basis": item.place_match.evidence,
                    "source_role": "OFFICIAL_NARRATIVE"
                    if provider == "Odii"
                    else "OFFICIAL_DESCRIPTION",
                    "field": item.source_field,
                    "text": item.excerpt,
                }
            )
        )
    place = Place.model_validate(
        {
            "place_id": original.place.place_id,
            "name_ko": original.place.name_ko,
            "address": original.place.address,
            "region_code": original.place.region_code,
            "region_name": original.place.region_name or "",
            "category": original.category,
            "duplicate_group_id": duplicate_group_id,
            "provider_content_id": original.place.provider_content_id,
            "cohort": cohort,
        }
    )
    return seal_bundle(place, tuple(records), original.snapshot_sha256)


def extend_source(source: SourceBundle, records: tuple[Evidence, ...]) -> SourceBundle:
    by_id = {record.evidence_id: record for record in source.evidence}
    for record in records:
        if record.evidence_id in by_id and by_id[record.evidence_id] != record:
            raise ValueError("SOURCE_EXTENSION_REWRITES_EVIDENCE")
        by_id[record.evidence_id] = record
    return seal_bundle(source.place, tuple(by_id.values()), source.parent_source_sha256)
