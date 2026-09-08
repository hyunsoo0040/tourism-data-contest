"""Provider-free verification for publishing an MVP scored release."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from datetime import datetime

from itda.contracts.mvp_place_scoring import (
    MVP_SCORING_PROMPT_SHA256,
    BoundScoringResult,
    ProviderWireScoringResponse,
)
from itda.contracts.mvp_public_catalog import (
    PublicEvidenceInventory,
    PublicPlaceCatalog,
    PublicPlaceRelations,
)
from itda.contracts.mvp_scored_release import (
    FailedPlace,
    MvpEvidenceExcerpt,
    MvpReleaseLineage,
    MvpScoredProfile,
    MvpScoredRelease,
    information_state_for,
)
from itda.contracts.recommendation import public_relation_sha256
from itda.domain.canonical import canonical_sha256
from itda.pipeline.mvp_public_catalog import verify_permission_snapshot


def materialize_scored_release(
    *,
    catalog: PublicPlaceCatalog,
    evidence_inventory: PublicEvidenceInventory,
    relations: PublicPlaceRelations,
    results: Sequence[BoundScoringResult],
    attempted_place_ids: Sequence[str],
    source_sha256: str,
    entitlement_snapshot_sha256: str,
    canary_plan_sha256: str,
    canary_outcome_sha256: str,
    run_plan_sha256: str,
    created_at: datetime,
) -> MvpScoredRelease:
    catalog_ids = tuple(row.place_id for row in catalog.places)
    if set(attempted_place_ids) != set(catalog_ids):
        raise ValueError("release requires all 100 catalog places to be attempted")
    results_by_id = {row.place_id: row for row in results}
    if len(results_by_id) != len(results) or not set(results_by_id).issubset(catalog_ids):
        raise ValueError("release results must be unique catalog members")
    if len(results_by_id) < 80:
        raise ValueError("release requires at least 80 valid profiles")
    if catalog.evidence_inventory_sha256 != evidence_inventory.inventory_sha256:
        raise ValueError("catalog evidence inventory binding does not match")

    places_by_id = {row.place_id: row for row in catalog.places}
    evidence_by_id = {row.evidence_id: row for row in evidence_inventory.evidence}
    profiles: list[MvpScoredProfile] = []
    for place_id in sorted(results_by_id):
        place = places_by_id[place_id]
        result = results_by_id[place_id]
        if (
            result.catalog_sha256 != catalog.catalog_sha256
            or result.evidence_inventory_sha256 != evidence_inventory.inventory_sha256
            or result.prompt_sha256 != MVP_SCORING_PROMPT_SHA256
        ):
            raise ValueError("scoring result lineage does not match release inputs")
        referenced = tuple(
            sorted(
                {
                    evidence_id
                    for justification in result.scores.justifications
                    for evidence_id in justification.evidence_ids
                }
            )
        )
        if not set(referenced).issubset(place.evidence_ids):
            raise ValueError("scoring result references unauthorized evidence")
        excerpts = tuple(
            MvpEvidenceExcerpt(
                evidence_id=evidence_id,
                excerpt_ko=evidence_by_id[evidence_id].excerpt,
                source_label_ko=evidence_by_id[
                    evidence_id
                ].permission_metadata.dataset_title_ko,
                attribution_ko=evidence_by_id[evidence_id].attribution_text,
                reference_date=evidence_by_id[evidence_id].reference_date,
                evidence=evidence_by_id[evidence_id],
            )
            for evidence_id in referenced
        )
        profile_fields = {
            "place_id": place_id,
            "place_name_ko": place.name_ko,
            "duplicate_group_id": place.duplicate_group_id,
            "source_evidence_ids": referenced,
            "evidence_excerpts": excerpts,
            "scores": result.scores,
            "condition_scores": result.condition_scores,
            "information_state": information_state_for(result.scores.confidence),
            "recommendation_eligible": True,
            "scoring_result": result,
        }
        profiles.append(
            MvpScoredProfile.model_validate(
                {
                    **profile_fields,
                    "profile_sha256": canonical_sha256(
                        {
                            **profile_fields,
                            "evidence_excerpts": [
                                row.model_dump(mode="json") for row in excerpts
                            ],
                            "scores": result.scores.model_dump(mode="json"),
                            "condition_scores": result.condition_scores.model_dump(mode="json"),
                            "information_state": str(
                                information_state_for(result.scores.confidence)
                            ),
                            "scoring_result": result.model_dump(mode="json"),
                        }
                    ),
                }
            )
        )

    profile_ids = tuple(row.place_id for row in profiles)
    failed_ids = tuple(sorted(set(catalog_ids) - set(profile_ids)))
    relation_pairs = tuple(
        (row.left_place_id, row.right_place_id)
        for row in relations.relations
        if row.left_place_id in set(profile_ids) and row.right_place_id in set(profile_ids)
    )
    failed = tuple(
        FailedPlace(place_id=place_id, reason="PROVIDER_ATTEMPT_FAILED")
        for place_id in failed_ids
    )
    lineage = MvpReleaseLineage(
        prompt_sha256=MVP_SCORING_PROMPT_SHA256,
        response_schema_sha256=canonical_sha256(
            ProviderWireScoringResponse.model_json_schema()
        ),
        source_sha256=source_sha256,
        entitlement_snapshot_sha256=entitlement_snapshot_sha256,
        canary_plan_sha256=canary_plan_sha256,
        canary_outcome_sha256=canary_outcome_sha256,
        run_plan_sha256=run_plan_sha256,
    )
    release_fields = {
        "schema_version": "mvp-scored-release.v1",
        "attempted_count": 100,
        "published_count": len(profiles),
        "catalog_sha256": catalog.catalog_sha256,
        "relation_sha256": public_relation_sha256(profile_ids, relation_pairs),
        "evidence_inventory_sha256": evidence_inventory.inventory_sha256,
        "membership_sha256": canonical_sha256(list(profile_ids)),
        "relation_pairs": relation_pairs,
        "profiles": tuple(profiles),
        "failed": failed,
        "lineage": lineage,
        "created_at": created_at,
    }
    serializable = {
        **release_fields,
        "profiles": [row.model_dump(mode="json") for row in profiles],
        "failed": [row.model_dump(mode="json") for row in failed],
        "lineage": lineage.model_dump(mode="json"),
        "created_at": created_at.isoformat().replace("+00:00", "Z"),
    }
    return MvpScoredRelease.model_validate(
        {**release_fields, "release_sha256": canonical_sha256(serializable)}
    )


def verify_release_inputs(
    release: MvpScoredRelease,
    catalog: PublicPlaceCatalog,
    evidence_inventory: PublicEvidenceInventory,
    relations: PublicPlaceRelations,
    permission_snapshots: Mapping[str, bytes],
) -> None:
    if release.catalog_sha256 != catalog.catalog_sha256:
        raise ValueError("release catalog hash does not match exact catalog")
    if catalog.evidence_inventory_sha256 != evidence_inventory.inventory_sha256:
        raise ValueError("catalog evidence inventory hash does not match exact inventory")
    if release.evidence_inventory_sha256 != evidence_inventory.inventory_sha256:
        raise ValueError("release evidence inventory hash does not match exact inventory")

    evidence_by_id = {row.evidence_id: row for row in evidence_inventory.evidence}
    places_by_id = {row.place_id: row for row in catalog.places}
    for profile in release.profiles:
        for excerpt in profile.evidence_excerpts:
            if evidence_by_id.get(excerpt.evidence_id) != excerpt.evidence:
                raise ValueError("release nested evidence does not match the exact inventory")
        place = places_by_id.get(profile.place_id)
        if place is None:
            raise ValueError("release profile is outside the exact catalog")
        if not set(profile.source_evidence_ids).issubset(place.evidence_ids):
            raise ValueError("release profile evidence is not authorized for its catalog place")

    if (
        relations.catalog_sha256 != catalog.catalog_sha256
        or relations.catalog_place_ids != tuple(row.place_id for row in catalog.places)
    ):
        raise ValueError("relation manifest does not bind the exact catalog")
    published_ids = {row.place_id for row in release.profiles}
    expected_pairs = tuple(
        (row.left_place_id, row.right_place_id)
        for row in relations.relations
        if row.left_place_id in published_ids and row.right_place_id in published_ids
    )
    expected_relation_sha256 = public_relation_sha256(
        tuple(row.place_id for row in release.profiles), expected_pairs
    )
    if (
        release.relation_pairs != expected_pairs
        or release.relation_sha256 != expected_relation_sha256
    ):
        raise ValueError("release relations do not match the exact relation manifest")

    permission_by_hash = {
        row.permission_metadata.metadata_sha256: row.permission_metadata
        for row in evidence_inventory.evidence
    }
    if set(permission_snapshots) != set(permission_by_hash):
        raise ValueError("permission snapshots must exactly cover release evidence")
    for metadata_sha256, permission in permission_by_hash.items():
        verify_permission_snapshot(permission, permission_snapshots[metadata_sha256])
