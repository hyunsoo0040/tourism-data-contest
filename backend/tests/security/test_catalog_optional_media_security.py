from __future__ import annotations

import hashlib
import json
import socket
from copy import deepcopy
from pathlib import Path

import pytest
from pydantic import ValidationError

from itda.cli.replay_catalog_optional_media import (
    HISTORICAL_TERMINAL_ROOT,
    build_optional_media_projection,
    load_canonical_json_nofollow,
    project_sealed_universe,
    publish_optional_media_projection,
)
from itda.contracts.catalog_optional_media import (
    OptionalMediaPolicyV2,
    build_optional_media_policy,
    verify_historical_lineage,
)
from itda.domain.canonical import canonical_json_bytes, canonical_sha256

REPO_ROOT = Path(__file__).resolve().parents[3]
TERMINAL_FAILURE = (
    REPO_ROOT
    / "artifacts/restricted/catalog/v2/supplemental/kto-recovery/reentries"
    / HISTORICAL_TERMINAL_ROOT
    / "reentry-exhausted.json"
)
AGGREGATE = (
    REPO_ROOT
    / "artifacts/restricted/catalog/v2/enrichment/rounds"
    / "01072d20529d6114c0b1d7093f02b42f547e9f519fadc6b09e838c1c2a969b55"
    / "aggregate-readiness.json"
)
NORMALIZATION = (
    REPO_ROOT
    / "artifacts/restricted/catalog/v2/supplemental/kto-recovery/normalizations"
    / "540bdc90c709418fe690956e56e3b50b402d0ba7e16b4c4c417fdc27a5389b10"
    / "normalization.json"
)


def _load(path: Path) -> dict[str, object]:
    value = json.loads(path.read_bytes())
    assert isinstance(value, dict)
    return value


def test_terminal_lineage_rejects_root_parent_and_terminal_semantic_tampering() -> None:
    terminal = _load(TERMINAL_FAILURE)
    verify_historical_lineage(terminal, HISTORICAL_TERMINAL_ROOT)

    for mutation in ("root", "parent", "status"):
        hostile = deepcopy(terminal)
        payload = hostile["payload"]
        assert isinstance(payload, dict)
        if mutation == "root":
            hostile["terminal_root_sha256"] = "0" * 64
        elif mutation == "parent":
            parents = payload["parents"]
            assert isinstance(parents, dict)
            parents["aggregate_readiness_sha256"] = "0" * 64
            hostile["terminal_root_sha256"] = hashlib.sha256(
                canonical_json_bytes(payload)
            ).hexdigest()
        else:
            payload["status"] = "SUCCESS"
            hostile["terminal_root_sha256"] = hashlib.sha256(
                canonical_json_bytes(payload)
            ).hexdigest()
        with pytest.raises(ValueError, match="historical"):
            verify_historical_lineage(hostile, HISTORICAL_TERMINAL_ROOT)


def test_replay_cannot_open_network_or_use_model_or_credentials(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def denied_socket(*args: object, **kwargs: object) -> socket.socket:
        raise AssertionError("network access is forbidden during captured replay")

    monkeypatch.setattr(socket, "socket", denied_socket)
    generation = build_optional_media_projection(REPO_ROOT)

    assert generation.capabilities.provider_traffic_allowed is False
    assert generation.capabilities.credential_access_allowed is False
    assert generation.capabilities.vlm_inference_allowed is False
    assert generation.provider_attempts == ()


def test_nofollow_loader_rejects_symlink_noncanonical_and_oversized_json(
    tmp_path: Path,
) -> None:
    canonical = tmp_path / "canonical.json"
    canonical.write_bytes(canonical_json_bytes({"a": 1}))
    assert load_canonical_json_nofollow(canonical, max_bytes=32) == {"a": 1}

    alias = tmp_path / "alias.json"
    alias.symlink_to(canonical)
    with pytest.raises(ValueError, match="symlink|regular"):
        load_canonical_json_nofollow(alias, max_bytes=32)

    noncanonical = tmp_path / "noncanonical.json"
    noncanonical.write_text('{"a": 1}\n', encoding="utf-8")
    with pytest.raises(ValueError, match="canonical"):
        load_canonical_json_nofollow(noncanonical, max_bytes=32)

    oversized = tmp_path / "oversized.json"
    oversized.write_bytes(canonical_json_bytes({"a": "x" * 100}))
    with pytest.raises(ValueError, match="size"):
        load_canonical_json_nofollow(oversized, max_bytes=32)


def test_duplicate_place_ids_and_mixed_policy_versions_are_rejected() -> None:
    aggregate = _load(AGGREGATE)
    normalization_envelope = _load(NORMALIZATION)
    normalization = normalization_envelope["payload"]
    assert isinstance(normalization, dict)

    duplicate = deepcopy(aggregate)
    rows = duplicate["rows"]
    assert isinstance(rows, list)
    assert len(rows) == 718
    rows[1] = deepcopy(rows[0])
    unsigned = dict(duplicate)
    unsigned.pop("aggregate_sha256")
    duplicate["aggregate_sha256"] = canonical_sha256(unsigned)
    with pytest.raises(ValueError, match="duplicate|unique"):
        project_sealed_universe(
            aggregate=duplicate,
            normalization=normalization,
            policy=build_optional_media_policy(),
        )

    policy = build_optional_media_policy().model_dump(mode="json")
    policy["policy_version"] = "optional-media-v1"
    with pytest.raises(ValidationError):
        OptionalMediaPolicyV2.from_manifest(policy)


def test_publication_rejects_symlink_target_and_existing_byte_drift(
    tmp_path: Path,
) -> None:
    generation = build_optional_media_projection(REPO_ROOT)
    base = tmp_path / "policy"
    base.mkdir()
    outside = tmp_path / "outside"
    outside.mkdir()
    (base / generation.projection_sha256).symlink_to(
        outside,
        target_is_directory=True,
    )
    with pytest.raises(ValueError, match="symlink"):
        publish_optional_media_projection(
            generation,
            repository_root=REPO_ROOT,
            output_base=base,
        )

    (base / generation.projection_sha256).unlink()
    root = publish_optional_media_projection(
        generation,
        repository_root=REPO_ROOT,
        output_base=base,
    )
    (root / "policy.json").write_bytes(canonical_json_bytes({"tampered": True}))
    with pytest.raises(ValueError, match="differs"):
        publish_optional_media_projection(
            generation,
            repository_root=REPO_ROOT,
            output_base=base,
        )


def test_replay_does_not_mutate_plan49_or_create_forbidden_summaries(
    tmp_path: Path,
) -> None:
    history = (
        REPO_ROOT
        / ".planning/phases/02-canonical-36-rights-and-evaluation-manifest"
        / "02-49-TERMINAL-HISTORY.md"
    )
    history_before = history.read_bytes()
    terminal_before = TERMINAL_FAILURE.read_bytes()
    generation = build_optional_media_projection(REPO_ROOT)
    publish_optional_media_projection(
        generation,
        repository_root=REPO_ROOT,
        output_base=tmp_path / "policy",
    )

    assert history.read_bytes() == history_before
    assert TERMINAL_FAILURE.read_bytes() == terminal_before
    phase_dir = history.parent
    for plan in ("19", "49", "50"):
        assert not (phase_dir / f"02-{plan}-SUMMARY.md").exists()
