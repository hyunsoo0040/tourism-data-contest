from __future__ import annotations

import json
from copy import deepcopy
from pathlib import Path

import pytest

from itda.contracts.phase5_recovery_policy import (
    CANONICAL_CONTRAST_PAIRS,
    CANONICAL_PHASE5_RECOVERY_POLICY,
    CANONICAL_SCENARIO_IDS,
    validate_activation_scenario_results,
    validate_contrast_results,
)


def test_recovery_activation_suite_requires_exact_scenarios_and_contrasts() -> None:
    policy = CANONICAL_PHASE5_RECOVERY_POLICY
    assert tuple(row.scenario_id for row in policy.activation_scenarios) == CANONICAL_SCENARIO_IDS
    assert tuple(row.pair for row in policy.contrast_bindings) == CANONICAL_CONTRAST_PAIRS
    assert policy.activation_source_file_sha256 == (
        "793f11140210c3ea9dda0ca801e86f37a848c144c81afd0f73f4124674617115"
    )
    assert policy.activation_dataset_sha256 == (
        "7e2a088fe60dae23fd565db71fd6b3a7edeeece629fc644d4ac746eb9df07f8d"
    )
    assert policy.activation_suite_sha256 == (
        "6e049343d62770b8437ce9e29220fcd31a0e7b30d9b888bc3d9a823421fc5659"
    )
    assert policy.contrast_suite_sha256 == (
        "1f9caa8dbb010ca64acffdf1c174c383e08b4fc04ede9b7aece10af35cb4c6c9"
    )


def test_recovery_suite_rejects_omission_reorder_copied_and_no_change_records() -> None:
    def result(scenario_id: str, digest: str, ids: tuple[str, ...]) -> dict[str, object]:
        return {
            "scenario_id": scenario_id,
            "status": "SUCCESS",
            "eligible_place_ids": ids,
            "result_sha256": digest,
            "replay_sha256": digest,
        }

    ids = tuple(f"place:{index:02d}" for index in range(1, 6))
    results = {
        scenario_id: result(scenario_id, f"{index + 1:064x}", ids)
        for index, scenario_id in enumerate(CANONICAL_SCENARIO_IDS)
    }
    parsed = validate_activation_scenario_results(results)
    assert len(parsed) == 8

    for mutation in (
        {key: value for key, value in results.items() if key != CANONICAL_SCENARIO_IDS[-1]},
        {key: results[key] for key in reversed(CANONICAL_SCENARIO_IDS)},
        {
            **results,
            CANONICAL_SCENARIO_IDS[0]: result(
                CANONICAL_SCENARIO_IDS[0],
                results[CANONICAL_SCENARIO_IDS[1]]["result_sha256"],
                ids,
            ),
        },
    ):
        with pytest.raises(ValueError):
            validate_activation_scenario_results(mutation)

    contrasts = {}
    for index, pair in enumerate(CANONICAL_CONTRAST_PAIRS):
        contrasts[pair] = {
            "left_scenario_id": pair[0],
            "right_scenario_id": pair[1],
            "left_result_sha256": results[pair[0]]["result_sha256"],
            "right_result_sha256": results[pair[1]]["result_sha256"],
            "left_contribution_sha256": f"{index + 10:064x}",
            "right_contribution_sha256": f"{index + 20:064x}",
            "left_place_ids": ids,
            "right_place_ids": ids,
        }
    with pytest.raises(ValueError):
        validate_contrast_results(contrasts, scenarios=parsed)


def test_historical_05_16_is_hash_bound_but_never_current_profile_authority() -> None:
    policy = CANONICAL_PHASE5_RECOVERY_POLICY
    assert policy.historical_05_16_terminal_sha256 == (
        "65adc81f59548debd0d964dced0ee6eb6f8ee14e3045c64b9605d4b589b298da"
    )
    assert policy.historical_05_16_plan_sha256 == (
        "4f13db73ad8d50eaa0bcb316faa693910f4e128c282dbdbcf51d94ffad9c8352"
    )
    assert policy.historical_05_16_summary_sha256 != policy.policy_sha256
    assert policy.hard_duplicate_adjudication_sha256 != policy.historical_05_16_terminal_sha256


def test_controlled_red_sentinel() -> None:
    from itda.db.phase5_demo_release import (
        Phase5DemoReleaseStore,
        resolve_active_public_scored_release,
        validate_demo_scored_release,
    )

    assert Phase5DemoReleaseStore
    assert validate_demo_scored_release
    assert resolve_active_public_scored_release


def test_source_only_replay_and_synthetic_roots_never_become_production_authority(
    tmp_path: Path,
) -> None:
    from itda.db.phase5_demo_release import (
        Phase5DemoReleaseError,
        Phase5DemoReleaseStore,
        resolve_active_public_scored_release,
    )
    from tests.integration.test_demo_scored_release import _nvidia_live_generation

    phase4_receipts = tuple(Path("artifacts/public/catalog/v2").glob("phase4-demo-*.json"))
    before = {path: path.read_bytes() for path in phase4_receipts}
    production_before = resolve_active_public_scored_release()

    root = tmp_path / "synthetic-only"
    generation, expected = _nvidia_live_generation(root)
    store = Phase5DemoReleaseStore(root=root, expected_place_ids=expected)
    candidate = store.build(generation.name)
    store.activate(candidate.release_sha256, expected_current_sha256=None)

    assert store.resolve_active() is not None
    assert resolve_active_public_scored_release() == production_before
    assert {path: path.read_bytes() for path in phase4_receipts} == before

    replay_root = tmp_path / "replay"
    replay_root.mkdir()
    with pytest.raises(Phase5DemoReleaseError):
        Phase5DemoReleaseStore(root=replay_root, expected_place_ids=expected).build("0" * 64)


@pytest.mark.parametrize(
    "mutation",
    (
        "partial",
        "extra",
        "duplicate",
        "blind",
        "source-only",
        "hand-filled",
        "response-drift",
        "pricing-drift",
    ),
)
def test_hostile_release_substitutions_fail_without_active_state_change(
    tmp_path: Path,
    mutation: str,
) -> None:
    from itda.contracts.demo_profile_materialization import (
        DemoModelDerivedProfile,
        DemoProfileMaterializationReceipt,
        DemoSourceBundle,
    )
    from itda.db.phase5_demo_release import Phase5DemoReleaseError, validate_demo_scored_release
    from tests.integration.test_demo_scored_release import _live_generation

    root = tmp_path / mutation
    generation, expected = _live_generation(root)
    profiles = json.loads((generation / "profiles.json").read_bytes())
    attempts = json.loads((generation / "attempts.json").read_bytes())
    receipt = json.loads((generation / "receipt.json").read_bytes())
    sources = json.loads((root / "source-bundles.json").read_bytes())
    raw = {
        path.name.removeprefix("raw-").removesuffix(".json"): path.read_bytes()
        for path in generation.glob("raw-*.json")
    }

    if mutation == "partial":
        profiles.pop()
    elif mutation == "extra":
        profiles.append(deepcopy(profiles[-1]))
        profiles[-1]["place_id"] = "canonical-dev-25"
    elif mutation == "duplicate":
        profiles[-1] = deepcopy(profiles[0])
    elif mutation == "blind":
        profiles[0]["place_id"] = "blind-place-01"
    elif mutation == "source-only":
        profiles[0]["analysis_origin"] = "SOURCE_EVIDENCE_ONLY"
    elif mutation == "hand-filled":
        profiles[0]["axis_scores"]["H"] = 100
    elif mutation == "response-drift":
        raw[next(iter(raw))] += b" "
    elif mutation == "pricing-drift":
        attempts[0]["committed_micro_usd"] += 1

    with pytest.raises((Phase5DemoReleaseError, ValueError)):
        validate_demo_scored_release(
            profiles=tuple(DemoModelDerivedProfile.model_validate(profile) for profile in profiles),
            attempts=attempts,
            receipt=DemoProfileMaterializationReceipt.model_validate(receipt),
            source_bundles=tuple(DemoSourceBundle.model_validate(row) for row in sources),
            raw_responses=raw,
            expected_place_ids=expected,
        )


def _recovery_maps(
    profile_ids: tuple[str, ...],
) -> tuple[dict[str, object], tuple[dict[str, object], ...]]:
    from itda.contracts.phase5_recovery_policy import (
        CANONICAL_CONTRAST_PAIRS,
        CANONICAL_SCENARIO_IDS,
    )

    scenario_results: dict[str, object] = {}
    for index, scenario_id in enumerate(CANONICAL_SCENARIO_IDS):
        selected = tuple(profile_ids[(index + offset) % len(profile_ids)] for offset in range(5))
        digest = f"{index + 1:064x}"
        scenario_results[scenario_id] = {
            "scenario_id": scenario_id,
            "status": "SUCCESS",
            "eligible_place_ids": selected,
            "result_sha256": digest,
            "replay_sha256": digest,
        }

    contrast_results: list[dict[str, object]] = []
    for index, pair in enumerate(CANONICAL_CONTRAST_PAIRS):
        left = scenario_results[pair[0]]
        right = scenario_results[pair[1]]
        assert isinstance(left, dict)
        assert isinstance(right, dict)
        contrast_results.append(
            {
                "left_scenario_id": pair[0],
                "right_scenario_id": pair[1],
                "left_result_sha256": left["result_sha256"],
                "right_result_sha256": right["result_sha256"],
                "left_contribution_sha256": f"{index + 101:064x}",
                "right_contribution_sha256": f"{index + 201:064x}",
                "left_place_ids": left["eligible_place_ids"],
                "right_place_ids": right["eligible_place_ids"],
            }
        )
    return scenario_results, tuple(contrast_results)


def test_recovery_candidate_starts_quarantined_and_public_resolver_denies_before_pointer(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from itda.db.phase5_demo_release import Phase5DemoReleaseStore
    from tests.integration.test_demo_scored_release import _nvidia_live_generation

    root = tmp_path / "recovery-draft"
    generation, expected = _nvidia_live_generation(root)
    scenario_results, contrast_results = _recovery_maps(expected)
    store = Phase5DemoReleaseStore(root=root, expected_place_ids=expected)
    candidate = store.build_recovery_candidate(
        generation.name,
        scenario_results=scenario_results,
        contrast_results=contrast_results,
    )

    assert candidate.state == "DRAFT_QUARANTINED"
    assert candidate.structural_profile_count == 24
    assert candidate.candidate_profile_count == 24
    assert candidate.effective_candidate_count >= 5
    assert store.resolve_candidate_private(candidate.release_sha256) == candidate

    (root / "active").mkdir(exist_ok=True)
    (root / "active" / "current.json").write_bytes(b"forged-pointer")
    monkeypatch.setattr(store, "_read_active", lambda: pytest.fail("pointer read before lifecycle"))
    assert store.resolve_active() is None


def test_recovery_candidate_rejects_active_state_and_map_drift(tmp_path: Path) -> None:
    from pydantic import ValidationError

    from itda.contracts.demo_profile_materialization import Phase5RecoveryReleaseCandidate
    from itda.db.phase5_demo_release import Phase5DemoReleaseStore
    from tests.integration.test_demo_scored_release import _nvidia_live_generation

    root = tmp_path / "recovery-contract"
    generation, expected = _nvidia_live_generation(root)
    scenario_results, contrast_results = _recovery_maps(expected)
    store = Phase5DemoReleaseStore(root=root, expected_place_ids=expected)
    candidate = store.build_recovery_candidate(
        generation.name,
        scenario_results=scenario_results,
        contrast_results=contrast_results,
    )
    payload = candidate.model_dump(mode="json")
    payload["state"] = "ACTIVE"
    with pytest.raises(ValidationError):
        Phase5RecoveryReleaseCandidate.model_validate(payload)

    drifted = candidate.model_dump(mode="json")
    drifted["scenario_results"]["critical-01-history-morning-solo"]["result_sha256"] = "f" * 64
    (root / "candidates" / candidate.release_sha256 / "candidate.json").write_bytes(
        json.dumps(drifted, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode()
    )
    with pytest.raises(ValueError, match="CANDIDATE"):
        store.resolve_candidate_private(candidate.release_sha256)
