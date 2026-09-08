from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

import pytest

from itda.cli.manage_mvp_scored_release import _verify_completed_attempts, main
from itda.contracts.mvp_place_scoring import MVP_SCORING_PROMPT_SHA256, BoundScoringResult
from itda.contracts.mvp_public_catalog import PublicPlaceCatalog, PublicPlaceRelations
from itda.contracts.mvp_scored_release import MvpScoredRelease
from itda.domain.canonical import canonical_json_bytes, canonical_sha256
from itda.pipeline.mvp_public_catalog import build_public_catalog
from itda.pipeline.mvp_scored_release import materialize_scored_release, verify_release_inputs
from tests.contract.test_mvp_scored_release import release
from tests.pipeline.test_mvp_public_catalog import PERMISSION_RAW, _evidence, _inventory, _place


def _inputs(*, relation_pair: bool = False, start: int = 0):
    inventory = _inventory()
    places = tuple(
        _place(index, inventory.evidence[offset].evidence_id)
        for offset, index in enumerate(range(start, start + 100))
    )
    cannot_coappear = (
        ((places[0].place_id, places[1].place_id, "합성 관계"),) if relation_pair else ()
    )
    permissions = {
        row.permission_metadata.metadata_sha256: PERMISSION_RAW for row in inventory.evidence
    }
    catalog, relations = build_public_catalog(
        places,
        inventory,
        permission_snapshots=permissions,
        cannot_coappear=cannot_coappear,
    )
    snapshot = release(
        80,
        catalog_sha256=catalog.catalog_sha256,
        evidence_inventory_sha256=inventory.inventory_sha256,
        evidences=inventory.evidence[:80],
    )
    return snapshot, catalog, inventory, relations, permissions


def _write_inputs(
    tmp_path: Path, *, raw: bytes = PERMISSION_RAW
) -> tuple[list[str], MvpScoredRelease]:
    snapshot, catalog, inventory, relations, permissions = _inputs()
    release_path = tmp_path / "release.json"
    catalog_path = tmp_path / "catalog.json"
    inventory_path = tmp_path / "inventory.json"
    relations_path = tmp_path / "relations.json"
    raw_path = tmp_path / "permission.html"
    for path, value in (
        (release_path, snapshot),
        (catalog_path, catalog),
        (inventory_path, inventory),
        (relations_path, relations),
    ):
        path.write_bytes(canonical_json_bytes(value.model_dump(mode="json")))
    raw_path.write_bytes(raw)
    return [
        "--root",
        str(tmp_path / "store"),
        "publish",
        str(release_path),
        "--catalog",
        str(catalog_path),
        "--evidence-inventory",
        str(inventory_path),
        "--relations",
        str(relations_path),
        "--permission-snapshot",
        f"{next(iter(permissions))}={raw_path}",
    ], snapshot


def _materializer_results(snapshot, catalog, inventory) -> tuple[BoundScoringResult, ...]:
    rows = []
    for profile in snapshot.profiles:
        fields = {
            **profile.scoring_result.model_dump(
                exclude={"result_sha256"}, mode="json"
            ),
            "catalog_sha256": catalog.catalog_sha256,
            "evidence_inventory_sha256": inventory.inventory_sha256,
            "prompt_sha256": MVP_SCORING_PROMPT_SHA256,
        }
        rows.append(
            BoundScoringResult.model_validate(
                {**fields, "result_sha256": canonical_sha256(fields)}
            )
        )
    return tuple(rows)


def _completed_attempt(
    place_id: str,
    request_sha256: str,
    *,
    attempt_number: int = 1,
    status: str = "SUCCEEDED",
) -> dict[str, object]:
    return {
        "place_id": place_id,
        "request_sha256": request_sha256,
        "attempt_number": attempt_number,
        "status": status,
        "reason": None if status == "SUCCEEDED" else "GLM_TIMEOUT",
    }


def test_completed_attempts_require_exact_first_pass_and_bounded_retry() -> None:
    request_sha_by_id = {
        f"place-{index}": f"{index:064x}" for index in range(1, 101)
    }
    attempts = [
        _completed_attempt(place_id, request_sha256)
        for place_id, request_sha256 in request_sha_by_id.items()
    ]

    verified = _verify_completed_attempts(attempts, request_sha_by_id)
    assert set(verified) == set(request_sha_by_id)

    first = attempts[0]
    retried = [
        {**first, "status": "FAILED", "reason": "GLM_TIMEOUT"},
        *attempts[1:],
        _completed_attempt(
            str(first["place_id"]),
            str(first["request_sha256"]),
            attempt_number=2,
        ),
    ]
    assert len(_verify_completed_attempts(retried, request_sha_by_id)) == 100

    with pytest.raises(ValueError, match="exactly 100 first passes"):
        _verify_completed_attempts(attempts[:-1], request_sha_by_id)
    with pytest.raises(ValueError, match="retry order"):
        _verify_completed_attempts(
            [*attempts, {**first, "attempt_number": 2}], request_sha_by_id
        )
    with pytest.raises(ValueError, match="retry order"):
        _verify_completed_attempts(
            [
                {**first, "status": "FAILED", "reason": "GLM_TIMEOUT"},
                *attempts[1:],
                {**first, "attempt_number": 3},
            ],
            request_sha_by_id,
        )


def test_materialize_release_requires_80_results_and_all_100_attempted() -> None:
    snapshot, catalog, inventory, relations, _ = _inputs()
    results = _materializer_results(snapshot, catalog, inventory)
    attempted = tuple(row.place_id for row in catalog.places)
    kwargs = {
        "catalog": catalog,
        "evidence_inventory": inventory,
        "relations": relations,
        "results": results,
        "attempted_place_ids": attempted,
        "source_sha256": "1" * 64,
        "entitlement_snapshot_sha256": "2" * 64,
        "canary_plan_sha256": "3" * 64,
        "canary_outcome_sha256": "4" * 64,
        "run_plan_sha256": "5" * 64,
        "created_at": datetime(2026, 8, 27, tzinfo=UTC),
    }

    release = materialize_scored_release(**kwargs)
    assert release.attempted_count == 100
    assert release.published_count == 80
    assert len(release.failed) == 20
    assert release.lineage.run_plan_sha256 == "5" * 64

    with pytest.raises(ValueError, match="at least 80"):
        materialize_scored_release(**{**kwargs, "results": results[:79]})
    with pytest.raises(ValueError, match="all 100"):
        materialize_scored_release(**{**kwargs, "attempted_place_ids": attempted[:99]})


def test_materialize_release_is_deterministic_for_fixed_timestamp() -> None:
    snapshot, catalog, inventory, relations, _ = _inputs()
    results = _materializer_results(snapshot, catalog, inventory)
    kwargs = {
        "catalog": catalog,
        "evidence_inventory": inventory,
        "relations": relations,
        "results": results,
        "attempted_place_ids": tuple(row.place_id for row in catalog.places),
        "source_sha256": "1" * 64,
        "entitlement_snapshot_sha256": "2" * 64,
        "canary_plan_sha256": "3" * 64,
        "canary_outcome_sha256": "4" * 64,
        "run_plan_sha256": "5" * 64,
        "created_at": datetime(2026, 8, 27, tzinfo=UTC),
    }

    assert materialize_scored_release(**kwargs) == materialize_scored_release(**kwargs)


def test_partial_release_with_failed_place_only_evidence_publishes(tmp_path: Path) -> None:
    argv, snapshot = _write_inputs(tmp_path)
    _, _, inventory, _, _ = _inputs()
    nested_ids = {
        excerpt.evidence_id
        for profile in snapshot.profiles
        for excerpt in profile.evidence_excerpts
    }

    assert inventory.evidence[-1].evidence_id not in nested_ids
    assert len(nested_ids) == 80
    assert len(inventory.evidence) == 100
    assert main(argv) == 0
    assert (tmp_path / "store/releases" / snapshot.release_sha256 / "release.json").is_file()
    assert not (tmp_path / "store/active.json").exists()


def test_failed_cli_verification_does_not_mutate_store(tmp_path: Path) -> None:
    argv, _ = _write_inputs(tmp_path, raw=PERMISSION_RAW + b" drift")

    with pytest.raises(ValueError, match="hash does not match"):
        main(argv)

    assert not (tmp_path / "store").exists()


def test_publication_rejects_forged_inventory_hash() -> None:
    snapshot, catalog, inventory, relations, permissions = _inputs()
    payload = snapshot.model_dump(mode="json")
    payload["evidence_inventory_sha256"] = "f" * 64
    for row in payload["profiles"]:
        row["scoring_result"]["evidence_inventory_sha256"] = "f" * 64
        row["scoring_result"]["result_sha256"] = canonical_sha256(
            {
                key: value
                for key, value in row["scoring_result"].items()
                if key != "result_sha256"
            }
        )
        row["profile_sha256"] = canonical_sha256(
            {key: value for key, value in row.items() if key != "profile_sha256"}
        )
    payload["release_sha256"] = canonical_sha256(
        {key: value for key, value in payload.items() if key != "release_sha256"}
    )
    forged = MvpScoredRelease.model_validate(payload)

    with pytest.raises(ValueError, match="release evidence inventory hash"):
        verify_release_inputs(forged, catalog, inventory, relations, permissions)


def test_publication_rejects_unknown_or_mutated_nested_evidence() -> None:
    snapshot, catalog, inventory, relations, permissions = _inputs()
    unknown_evidence = _evidence(101)
    unknown = release(
        80,
        catalog_sha256=catalog.catalog_sha256,
        evidence_inventory_sha256=inventory.inventory_sha256,
        evidences=(unknown_evidence, *inventory.evidence[1:80]),
    )
    with pytest.raises(ValueError, match="nested evidence"):
        verify_release_inputs(unknown, catalog, inventory, relations, permissions)

    mutated_evidence = inventory.evidence[0].model_copy(update={"excerpt": "변조된 설명"})
    mutated_evidence = mutated_evidence.model_copy(
        update={
            "evidence_sha256": canonical_sha256(
                mutated_evidence.model_dump(exclude={"evidence_sha256"}, mode="json")
            )
        }
    )
    mutated = release(
        80,
        catalog_sha256=catalog.catalog_sha256,
        evidence_inventory_sha256=inventory.inventory_sha256,
        evidences=(mutated_evidence, *inventory.evidence[1:80]),
    )
    with pytest.raises(ValueError, match="nested evidence"):
        verify_release_inputs(mutated, catalog, inventory, relations, permissions)


def test_publication_rejects_missing_extra_or_wrong_permission_snapshot() -> None:
    snapshot, catalog, inventory, relations, permissions = _inputs()
    with pytest.raises(ValueError, match="exactly cover"):
        verify_release_inputs(snapshot, catalog, inventory, relations, {})
    with pytest.raises(ValueError, match="exactly cover"):
        verify_release_inputs(
            snapshot,
            catalog,
            inventory,
            relations,
            {**permissions, "f" * 64: b"extra"},
        )
    with pytest.raises(ValueError, match="hash does not match"):
        verify_release_inputs(
            snapshot,
            catalog,
            inventory,
            relations,
            {next(iter(permissions)): PERMISSION_RAW + b" drift"},
        )


def test_publication_rejects_catalog_evidence_authority_drift() -> None:
    snapshot, catalog, inventory, relations, permissions = _inputs()
    payload = catalog.model_dump(mode="json")
    payload["places"][0]["evidence_ids"] = [f"evidence:{'f' * 64}"]
    payload["places"][0]["row_sha256"] = canonical_sha256(
        {
            key: value
            for key, value in payload["places"][0].items()
            if key != "row_sha256"
        }
    )
    payload["catalog_sha256"] = canonical_sha256(
        {key: value for key, value in payload.items() if key != "catalog_sha256"}
    )
    wrong_catalog = PublicPlaceCatalog.model_validate(payload)
    wrong_snapshot = release(
        80,
        catalog_sha256=wrong_catalog.catalog_sha256,
        evidence_inventory_sha256=inventory.inventory_sha256,
        evidences=inventory.evidence[:80],
    )
    relation_fields = {
        "schema_version": relations.schema_version,
        "catalog_sha256": wrong_catalog.catalog_sha256,
        "catalog_place_ids": relations.catalog_place_ids,
        "relations": relations.relations,
    }
    wrong_relations = PublicPlaceRelations(
        **relation_fields,
        relations_sha256=canonical_sha256(
            {
                **relation_fields,
                "relations": [row.model_dump(mode="json") for row in relations.relations],
            }
        ),
    )

    with pytest.raises(ValueError, match="not authorized"):
        verify_release_inputs(
            wrong_snapshot,
            wrong_catalog,
            inventory,
            wrong_relations,
            permissions,
        )


def test_publication_rejects_catalog_membership_and_relation_drift() -> None:
    snapshot, _, _, _, _ = _inputs()
    _, wrong_catalog, inventory, relations, permissions = _inputs(start=1)
    with pytest.raises(ValueError, match="catalog hash"):
        verify_release_inputs(snapshot, wrong_catalog, inventory, relations, permissions)

    snapshot, catalog, inventory, relations, permissions = _inputs(relation_pair=True)
    with pytest.raises(ValueError, match="relations do not match"):
        verify_release_inputs(snapshot, catalog, inventory, relations, permissions)


def test_publish_requires_all_verification_inputs() -> None:
    with pytest.raises(SystemExit):
        from itda.cli.manage_mvp_scored_release import build_parser

        build_parser().parse_args(["--root", "store", "publish", "release.json"])
