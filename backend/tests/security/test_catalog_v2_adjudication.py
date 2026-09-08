from __future__ import annotations

import hashlib
import json
import shutil
import stat
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from itda.cli.build_catalog_v2_review import (
    ADJUDICATION_FILENAMES,
    PLAN55_HANDOFF_ROOT_FIELDS,
    REVIEW_FILENAMES,
    assert_predecessor_summaries_absent,
    build_catalog_v2_review_bundle,
    derive_adjudication_target,
    materialize_adjudication_bundle,
    prepare_contest_closure,
    publish_closure_result,
    verify_adjudication_bundle,
    verify_materialized_bundle,
    verify_plan54_success,
)
from itda.contracts.authority import ALLOWED_AUTHORITY_ACTIONS, freeze_issuance_context
from itda.domain.canonical import canonical_json_bytes, canonical_sha256

REPOSITORY_ROOT = Path(__file__).resolve().parents[3]
GENERATION_SHA256 = "fcaed68b724eedf4604c3510e9100f382d96819bad49f122e84529aa0e73f324"
GENERATION = (
    REPOSITORY_ROOT
    / "artifacts/restricted/catalog/contest-use-official-public-data-v1/generations"
    / GENERATION_SHA256
)
BRIDGE = (
    REPOSITORY_ROOT
    / "artifacts/restricted/catalog/v2/review/plan54-bridges"
    / "3be0d6255fd019ecec6bf01507a8bb5571223107de23445dacbcd28983d8dfbf"
)


def _closure() -> dict[str, object]:
    return prepare_contest_closure(GENERATION, repository_root=REPOSITORY_ROOT)


def _redigest(value: dict[str, object]) -> dict[str, object]:
    updated = dict(value)
    updated["closure_result_sha256"] = canonical_sha256(
        {key: item for key, item in updated.items() if key != "closure_result_sha256"}
    )
    return updated


def _draft() -> dict[str, object]:
    request = json.loads((BRIDGE / "catalog-review-request.json").read_bytes())
    return {
        "schema_version": "itda.catalog-adjudication-private-draft.v1",
        "decisions": [],
        "ordered_place_ids": request["noncanonical_preview_ids"],
    }


def _authority_descriptor(tmp_path: Path, draft: dict[str, object]) -> Path:
    request = json.loads((BRIDGE / "catalog-review-request.json").read_bytes())
    state = json.loads((BRIDGE / "catalog-state-attestation.json").read_bytes())
    target = derive_adjudication_target(BRIDGE, draft, repository_root=REPOSITORY_ROOT)
    binding = {
        "schema_version": "itda.catalog-adjudication-authority-binding.v1",
        "bridge_root_sha256": target["bridge_root_sha256"],
        "request_sha256": target["request_sha256"],
        "state_attestation_sha256": target["state_attestation_sha256"],
        "target_sha256": target["target_sha256"],
        "plan55_roots_sha256": target["plan55_roots_sha256"],
        "mode_security_roots_sha256": target["mode_security_roots_sha256"],
    }
    issued_at = datetime(2026, 8, 1, 3, 0, tzinfo=UTC)
    context = freeze_issuance_context(
        action="catalog-adjudicate-select",
        request={key: value for key, value in request.items() if key != "request_sha256"},
        state_attestation={
            key: value for key, value in state.items() if key != "state_attestation_sha256"
        },
        target={key: value for key, value in target.items() if key != "target_sha256"},
        reviewer_id="phase2-reviewer",
        binding=binding,
        nonce="9" * 64,
        issued_at=issued_at,
        expires_at=issued_at + timedelta(hours=1),
        reviewer_channel_risk="Local protected descriptor; identity is not cryptographic.",
    )
    descriptor = {
        "schema_version": "itda.catalog-adjudication-authority-descriptor.v1",
        "issuance_context": context.model_dump(mode="json"),
        "authority_token": context.expected_token().serialize(),
    }
    path = tmp_path / "authority-descriptor.json"
    path.write_bytes(canonical_json_bytes(descriptor))
    path.chmod(0o600)
    return path


def _readdress_tampered_bundle(bundle: Path) -> Path:
    manifest_path = bundle / "catalog-adjudication-bundle.json"
    manifest = json.loads(manifest_path.read_bytes())
    inventory = []
    for name in sorted(set(ADJUDICATION_FILENAMES) - {manifest_path.name}):
        raw = (bundle / name).read_bytes()
        inventory.append(
            {
                "filename": name,
                "mode": "0600",
                "size": len(raw),
                "sha256": hashlib.sha256(raw).hexdigest(),
            }
        )
    manifest["inventory"] = inventory
    manifest["inventory_sha256"] = canonical_sha256(inventory)
    manifest["bundle_root_sha256"] = canonical_sha256(
        {key: value for key, value in manifest.items() if key != "bundle_root_sha256"}
    )
    manifest_path.write_bytes(canonical_json_bytes(manifest))
    readdressed = bundle.with_name(str(manifest["bundle_root_sha256"]))
    bundle.rename(readdressed)
    return readdressed


def test_contest_closure_reconstructs_outer_and_carries_all_roots() -> None:
    closure = _closure()
    verified = verify_plan54_success(closure, repository_root=REPOSITORY_ROOT)

    handoff = json.loads((GENERATION / "plan54-handoff.json").read_bytes())
    assert "contest_generation_sha256" not in handoff
    assert set(verified["plan55_roots"]) == {
        *PLAN55_HANDOFF_ROOT_FIELDS,
        "contest_generation_sha256",
    }
    assert verified["plan55_roots"]["contest_generation_sha256"] == GENERATION_SHA256
    assert verified["plan55_roots_sha256"] == canonical_sha256(verified["plan55_roots"])
    assert verified["mode_security_roots"] == handoff["mode_security_roots"]
    assert verified["handoff_mode_security_roots_sha256"] == (handoff["mode_security_roots_sha256"])
    assert verified["mode_security_roots_sha256"] == (handoff["mode_security_roots_sha256"])
    for payload in verified["bridge_payloads"].values():
        assert payload["plan55_roots"] == verified["plan55_roots"]
        assert payload["plan55_roots_sha256"] == verified["plan55_roots_sha256"]
        assert payload["mode_security_roots"] == verified["mode_security_roots"]
        assert payload["mode_security_roots_sha256"] == (verified["mode_security_roots_sha256"])


@pytest.mark.parametrize(
    "schema_version",
    (
        "itda.catalog-optional-media-closure-finalization.v1",
        "itda.catalog-contest-use-closure-result.v2",
        "itda.catalog-contest-use-terminal.v1",
    ),
)
def test_active_adapter_rejects_historical_unknown_and_terminal_schemas(
    schema_version: str,
    tmp_path: Path,
) -> None:
    closure = _redigest({**_closure(), "schema_version": schema_version})
    destination = tmp_path / "plan54-bridges"

    with pytest.raises(ValueError, match="schema|contest|closure"):
        build_catalog_v2_review_bundle(
            closure,
            destination,
            repository_root=REPOSITORY_ROOT,
        )
    assert not destination.exists()


@pytest.mark.parametrize(
    ("root_field", "replacement"),
    (
        ("official_dataset_grants_root_sha256", "1" * 64),
        ("asset_exclusions_root_sha256", "2" * 64),
        ("eligible_pool_sha256", "3" * 64),
        ("missingness_state_root_sha256", "4" * 64),
        ("pre_handoff_content_sha256", "5" * 64),
        ("contest_generation_sha256", "6" * 64),
    ),
)
def test_adapter_rejects_tampered_plan55_root(
    root_field: str,
    replacement: str,
) -> None:
    closure = _closure()
    roots = dict(closure["plan55_roots"])
    roots[root_field] = replacement
    closure["plan55_roots"] = roots
    closure["plan55_roots_sha256"] = canonical_sha256(roots)
    closure = _redigest(closure)

    with pytest.raises(ValueError, match="root|generation|binding|Plan 55"):
        verify_plan54_success(closure, repository_root=REPOSITORY_ROOT)


def test_adapter_rejects_cross_mode_or_secret_bearing_mode_roots() -> None:
    closure = _closure()
    roots = dict(closure["mode_security_roots"])
    roots["credential_reference_sha256"] = "7" * 64
    closure["mode_security_roots"] = roots
    closure["mode_security_roots_sha256"] = canonical_sha256(roots)
    closure = _redigest(closure)

    with pytest.raises(ValueError, match="mode-security|captured|key"):
        verify_plan54_success(closure, repository_root=REPOSITORY_ROOT)


def test_bridge_publication_is_exact_atomic_and_read_only_recoverable(
    tmp_path: Path,
) -> None:
    closure = _closure()
    closure_path = tmp_path / "closure-result.json"
    disposition = publish_closure_result(closure, closure_path)
    assert disposition == "PUBLISHED"
    persisted_closure = json.loads(closure_path.read_bytes())
    assert (
        verify_plan54_success(
            persisted_closure,
            repository_root=REPOSITORY_ROOT,
        )["closure_result_sha256"]
        == closure["closure_result_sha256"]
    )

    destination_root = tmp_path / "plan54-bridges"
    first = build_catalog_v2_review_bundle(
        closure,
        destination_root,
        repository_root=REPOSITORY_ROOT,
    )
    bridge = destination_root / str(closure["bridge_root_sha256"])
    assert first["publication_disposition"] == "PUBLISHED"
    assert stat.S_IMODE(bridge.stat().st_mode) == 0o700
    assert {path.name for path in bridge.iterdir()} == set(REVIEW_FILENAMES)
    assert all(stat.S_IMODE(path.stat().st_mode) == 0o600 for path in bridge.iterdir())
    assert all(path.stat().st_nlink == 1 for path in bridge.iterdir())

    before = {path.name: (path.read_bytes(), path.stat().st_ino) for path in bridge.iterdir()}
    verified = verify_materialized_bundle(bridge, closure_result=closure)
    assert verified["bridge_root_sha256"] == closure["bridge_root_sha256"]
    recovered = build_catalog_v2_review_bundle(
        closure,
        destination_root,
        repository_root=REPOSITORY_ROOT,
    )
    assert recovered["publication_disposition"] == "ALREADY_PRESENT_VERIFIED"
    assert {
        path.name: (path.read_bytes(), path.stat().st_ino) for path in bridge.iterdir()
    } == before

    assert publish_closure_result(closure, closure_path) == "ALREADY_PRESENT_VERIFIED"
    assert closure_path.read_bytes() == canonical_json_bytes(closure)


def test_bundle_verifier_rejects_cross_file_mode_root(tmp_path: Path) -> None:
    closure = _closure()
    destination_root = tmp_path / "plan54-bridges"
    build_catalog_v2_review_bundle(
        closure,
        destination_root,
        repository_root=REPOSITORY_ROOT,
    )
    bridge = destination_root / str(closure["bridge_root_sha256"])
    request_path = bridge / "catalog-review-request.json"
    request = json.loads(request_path.read_bytes())
    request["mode_security_roots"] = {
        **request["mode_security_roots"],
        "target_sha256": "8" * 64,
    }
    request["request_sha256"] = canonical_sha256(
        {key: value for key, value in request.items() if key != "request_sha256"}
    )
    request_path.write_bytes(canonical_json_bytes(request))

    with pytest.raises(ValueError, match="mode-security|binding|root|digest"):
        verify_materialized_bundle(bridge, closure_result=closure)


@pytest.mark.parametrize("predecessor", (19, 49, 50))
def test_each_forbidden_predecessor_summary_blocks_success(
    predecessor: int,
    tmp_path: Path,
) -> None:
    phase = tmp_path / ".planning/phases/02-canonical-36-rights-and-evaluation-manifest"
    phase.mkdir(parents=True)
    (phase / f"02-{predecessor}-SUMMARY.md").write_text("forged", encoding="utf-8")

    with pytest.raises(ValueError, match=f"02-{predecessor}-SUMMARY"):
        assert_predecessor_summaries_absent(tmp_path)


def test_closure_authority_action_is_explicitly_allowlisted() -> None:
    assert "catalog-optional-media-close" in ALLOWED_AUTHORITY_ACTIONS


def test_adjudication_target_is_read_only_complete_and_order_sensitive(tmp_path: Path) -> None:
    draft = _draft()
    before = tuple(tmp_path.iterdir())
    target = derive_adjudication_target(BRIDGE, draft, repository_root=REPOSITORY_ROOT)

    assert tuple(tmp_path.iterdir()) == before
    assert target["schema_version"] == "itda.catalog-adjudication-selection-target.v1"
    assert target["request_sha256"] == (
        "3ac78abbd4036bd7073f85e43799991672cff4c715b8cca9556f5ebe8d788523"
    )
    assert target["state_attestation_sha256"] == (
        "5caee594835737ef293315a1b333bf0cec2118fef7cadfb9f443b27182bd3246"
    )
    assert target["ordered_place_ids"] == draft["ordered_place_ids"]
    assert target["exact_quotas"] == {
        "history_culture": 12,
        "history_scenery_boundary": 6,
        "image_modern_content": 7,
        "rest_walk_immersion": 11,
    }
    assert target["plan55_roots_sha256"] == (
        "b144662bab48c4397dafccd0f02bc2878ff0d1b42309506228adf00e5b433e9f"
    )
    assert target["mode_security_roots_sha256"] == (
        "c0a6e822f2fcea76c7b32d1a3aecae703347289d19747187ffdca0b8311cdd63"
    )
    assert target["target_sha256"] == canonical_sha256(
        {key: value for key, value in target.items() if key != "target_sha256"}
    )

    reordered = _draft()
    ordered = list(reordered["ordered_place_ids"])
    ordered[0], ordered[1] = ordered[1], ordered[0]
    reordered["ordered_place_ids"] = ordered
    changed = derive_adjudication_target(BRIDGE, reordered, repository_root=REPOSITORY_ROOT)
    assert changed["target_sha256"] != target["target_sha256"]


@pytest.mark.parametrize("mutation", ("short", "duplicate", "out_of_pool", "wrong_quota"))
def test_adjudication_target_rejects_invalid_selection(mutation: str) -> None:
    draft = _draft()
    ordered = list(draft["ordered_place_ids"])
    if mutation == "short":
        ordered.pop()
    elif mutation == "duplicate":
        ordered[-1] = ordered[0]
    elif mutation == "out_of_pool":
        ordered[-1] = "place:" + "f" * 64
    else:
        request = json.loads((BRIDGE / "catalog-review-request.json").read_bytes())
        selected = set(ordered)
        replacement = next(
            row["place_entity_id"]
            for row in request["eligible_pool"]
            if row["place_entity_id"] not in selected
            and row["representation_primary_group"] == "history_culture"
        )
        replace_index = next(
            index
            for index, place_id in enumerate(ordered)
            if next(
                row["representation_primary_group"]
                for row in request["eligible_pool"]
                if row["place_entity_id"] == place_id
            )
            == "image_modern_content"
        )
        ordered[replace_index] = replacement
    draft["ordered_place_ids"] = ordered

    with pytest.raises(ValueError, match="36|unique|eligible|quota|group"):
        derive_adjudication_target(BRIDGE, draft, repository_root=REPOSITORY_ROOT)


def test_five_file_contract_is_disjoint_from_plan54_bridge() -> None:
    assert set(ADJUDICATION_FILENAMES) == {
        "catalog-adjudication-selection-target.json",
        "catalog-adjudication.json",
        "catalog-selection.json",
        "authoritative-relationship-leaves.json",
        "catalog-adjudication-bundle.json",
    }
    assert set(ADJUDICATION_FILENAMES).isdisjoint(REVIEW_FILENAMES)
    assert verify_adjudication_bundle is not verify_materialized_bundle


def test_target_derivation_is_anchored_to_repository_root(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.chdir(REPOSITORY_ROOT / "backend")

    target = derive_adjudication_target(
        BRIDGE,
        _draft(),
        repository_root=REPOSITORY_ROOT,
    )

    assert target["bridge_root_sha256"] == BRIDGE.name


def test_authority_materializes_exact_five_files_and_recovers_read_only(
    tmp_path: Path,
) -> None:
    draft = _draft()
    authority = _authority_descriptor(tmp_path, draft)
    destination = tmp_path / "adjudication-bundles"
    now = datetime(2026, 8, 1, 3, 1, tzinfo=UTC)

    receipt = materialize_adjudication_bundle(
        BRIDGE,
        draft,
        authority,
        repository_root=REPOSITORY_ROOT,
        destination_base=destination,
        now=now,
    )
    assert receipt["publication_disposition"] == "PUBLISHED"
    assert set(receipt) == {
        "schema_version",
        "bundle_manifest_path",
        "bundle_root_sha256",
        "bridge_directory",
        "bridge_root_sha256",
        "publication_disposition",
    }
    assert not ({"authority_token", "nonce", "authority_descriptor"} & set(receipt))
    bundle = destination / receipt["bundle_root_sha256"]
    assert stat.S_IMODE(bundle.stat().st_mode) == 0o700
    assert {path.name for path in bundle.iterdir()} == set(ADJUDICATION_FILENAMES)
    assert all(stat.S_IMODE(path.stat().st_mode) == 0o600 for path in bundle.iterdir())
    manifest = bundle / "catalog-adjudication-bundle.json"
    verified = verify_adjudication_bundle(manifest, repository_root=REPOSITORY_ROOT)
    assert verified["bundle_root_sha256"] == receipt["bundle_root_sha256"]

    before = {path.name: (path.read_bytes(), path.stat().st_ino) for path in bundle.iterdir()}
    recovered = materialize_adjudication_bundle(
        BRIDGE,
        draft,
        authority,
        repository_root=REPOSITORY_ROOT,
        destination_base=destination,
        now=now,
    )
    assert recovered["publication_disposition"] == "ALREADY_PRESENT_VERIFIED"
    after = {path.name: (path.read_bytes(), path.stat().st_ino) for path in bundle.iterdir()}
    assert after == before


@pytest.mark.parametrize(
    ("attack", "expected_error"),
    (
        ("adjudication", "semantics"),
        ("selection", "semantics"),
        ("relationships", "semantics"),
        ("authority_binding", "binding"),
    ),
)
def test_dedicated_verifier_rejects_rehashed_semantic_substitution(
    tmp_path: Path,
    attack: str,
    expected_error: str,
) -> None:
    draft = _draft()
    authority = _authority_descriptor(tmp_path, draft)
    destination = tmp_path / "adjudication-bundles"
    receipt = materialize_adjudication_bundle(
        BRIDGE,
        draft,
        authority,
        repository_root=REPOSITORY_ROOT,
        destination_base=destination,
        now=datetime(2026, 8, 1, 3, 1, tzinfo=UTC),
    )
    bundle = destination / receipt["bundle_root_sha256"]

    if attack == "adjudication":
        path = bundle / "catalog-adjudication.json"
        value = json.loads(path.read_bytes())
        value["decisions"] = [{"forged": True}]
        value["decisions_sha256"] = canonical_sha256(value["decisions"])
        value["catalog_adjudication_sha256"] = canonical_sha256(
            {key: item for key, item in value.items() if key != "catalog_adjudication_sha256"}
        )
        path.write_bytes(canonical_json_bytes(value))
    elif attack == "selection":
        path = bundle / "catalog-selection.json"
        value = json.loads(path.read_bytes())
        ordered = list(value["ordered_place_ids"])
        ordered[0], ordered[1] = ordered[1], ordered[0]
        value["ordered_place_ids"] = ordered
        value["ordered_place_ids_sha256"] = canonical_sha256(ordered)
        value["catalog_selection_sha256"] = canonical_sha256(
            {key: item for key, item in value.items() if key != "catalog_selection_sha256"}
        )
        path.write_bytes(canonical_json_bytes(value))
    elif attack == "relationships":
        path = bundle / "authoritative-relationship-leaves.json"
        value = json.loads(path.read_bytes())
        value["relationship_leaf_count"] = 1
        value["relationship_leaves"] = [{"forged": True}]
        value["relationship_leaves_sha256"] = canonical_sha256(
            value["relationship_leaves"]
        )
        value["authoritative_relationship_leaves_sha256"] = canonical_sha256(
            {
                key: item
                for key, item in value.items()
                if key != "authoritative_relationship_leaves_sha256"
            }
        )
        path.write_bytes(canonical_json_bytes(value))
    else:
        manifest_path = bundle / "catalog-adjudication-bundle.json"
        manifest = json.loads(manifest_path.read_bytes())
        authority_receipt = dict(manifest["authority_consumption_receipt"])
        authority_receipt["binding_sha256"] = "f" * 64
        authority_receipt["receipt_sha256"] = canonical_sha256(
            {
                key: item
                for key, item in authority_receipt.items()
                if key != "receipt_sha256"
            }
        )
        manifest["authority_consumption_receipt"] = authority_receipt
        manifest_path.write_bytes(canonical_json_bytes(manifest))

    readdressed = _readdress_tampered_bundle(bundle)
    with pytest.raises(ValueError, match=expected_error):
        verify_adjudication_bundle(
            readdressed / "catalog-adjudication-bundle.json",
            repository_root=REPOSITORY_ROOT,
        )


def test_replayed_nonce_cannot_publish_after_output_loss(tmp_path: Path) -> None:
    draft = _draft()
    authority = _authority_descriptor(tmp_path, draft)
    destination = tmp_path / "adjudication-bundles"
    now = datetime(2026, 8, 1, 3, 1, tzinfo=UTC)
    first = materialize_adjudication_bundle(
        BRIDGE,
        draft,
        authority,
        repository_root=REPOSITORY_ROOT,
        destination_base=destination,
        now=now,
    )
    shutil.rmtree(destination / first["bundle_root_sha256"])

    with pytest.raises(RuntimeError, match="nonce already consumed"):
        materialize_adjudication_bundle(
            BRIDGE,
            draft,
            authority,
            repository_root=REPOSITORY_ROOT,
            destination_base=destination,
            now=now,
        )
    assert not (destination / first["bundle_root_sha256"]).exists()


def test_three_and_five_file_verifiers_do_not_confuse_directories(tmp_path: Path) -> None:
    draft = _draft()
    authority = _authority_descriptor(tmp_path, draft)
    destination = tmp_path / "adjudication-bundles"
    receipt = materialize_adjudication_bundle(
        BRIDGE,
        draft,
        authority,
        repository_root=REPOSITORY_ROOT,
        destination_base=destination,
        now=datetime(2026, 8, 1, 3, 1, tzinfo=UTC),
    )
    bundle = destination / receipt["bundle_root_sha256"]

    with pytest.raises(ValueError, match="exactly three"):
        verify_materialized_bundle(bundle)
    with pytest.raises(ValueError, match="five-file bundle manifest"):
        verify_adjudication_bundle(
            BRIDGE / "catalog-review-request.json",
            repository_root=REPOSITORY_ROOT,
        )


def test_authority_failure_publishes_no_bundle_or_receipt(tmp_path: Path) -> None:
    draft = _draft()
    authority = _authority_descriptor(tmp_path, draft)
    authority.chmod(0o644)
    destination = tmp_path / "adjudication-bundles"

    with pytest.raises(ValueError, match="protected 0600"):
        materialize_adjudication_bundle(
            BRIDGE,
            draft,
            authority,
            repository_root=REPOSITORY_ROOT,
            destination_base=destination,
            now=datetime(2026, 8, 1, 3, 1, tzinfo=UTC),
        )
    assert not destination.exists()
    assert not (tmp_path / "catalog-adjudication-materialization-receipt.json").exists()


@pytest.mark.parametrize("attack", ("extra", "symlink", "noncanonical", "mode"))
def test_dedicated_verifier_rejects_inventory_and_filesystem_attacks(
    tmp_path: Path,
    attack: str,
) -> None:
    draft = _draft()
    authority = _authority_descriptor(tmp_path, draft)
    destination = tmp_path / "adjudication-bundles"
    receipt = materialize_adjudication_bundle(
        BRIDGE,
        draft,
        authority,
        repository_root=REPOSITORY_ROOT,
        destination_base=destination,
        now=datetime(2026, 8, 1, 3, 1, tzinfo=UTC),
    )
    bundle = destination / receipt["bundle_root_sha256"]
    selection = bundle / "catalog-selection.json"
    if attack == "extra":
        (bundle / "unexpected.json").write_text("{}", encoding="utf-8")
    elif attack == "symlink":
        selection.unlink()
        selection.symlink_to("catalog-adjudication.json")
    elif attack == "noncanonical":
        value = json.loads(selection.read_bytes())
        selection.write_text(json.dumps(value, indent=2), encoding="utf-8")
    else:
        selection.chmod(0o644)

    with pytest.raises(ValueError, match="inventory|child|canonical|mode|links"):
        verify_adjudication_bundle(
            bundle / "catalog-adjudication-bundle.json",
            repository_root=REPOSITORY_ROOT,
        )
