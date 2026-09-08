from __future__ import annotations

from dataclasses import replace
from pathlib import Path

import pytest

from itda.cli import audit_catalog_optional_media_frontier as frontier_audit_module
from itda.cli.audit_catalog_optional_media_frontier import (
    OptionalMediaFrontierAuditError,
    build_optional_media_frontier_audit,
    publish_optional_media_frontier_audit,
)
from itda.contracts.catalog_optional_media import OptionalMediaCandidate
from itda.contracts.catalog_optional_media_frontier import (
    evaluate_optional_media_frontier,
)
from itda.domain.canonical import canonical_sha256

REPO_ROOT = Path(__file__).resolve().parents[3]


def _patched_candidate(
    candidate: OptionalMediaCandidate,
    **updates: object,
) -> OptionalMediaCandidate:
    payload = candidate.model_dump(mode="json")
    payload.update(updates)
    payload["row_sha256"] = canonical_sha256(
        {key: value for key, value in payload.items() if key != "row_sha256"}
    )
    return OptionalMediaCandidate.model_validate(payload)


def test_unknown_group_duplicate_id_and_policy_drift_fail_closed() -> None:
    audit = build_optional_media_frontier_audit(REPO_ROOT)
    projection = audit.first_projection
    first = projection.candidates[0]

    patched_group = _patched_candidate(
        first,
        representation_primary_group="famous_photo_bonus",
    )
    with pytest.raises(ValueError, match="unknown representation group"):
        evaluate_optional_media_frontier(
            (patched_group,),
            projection.policy,
            projection.projection_sha256,
        )

    with pytest.raises(ValueError, match="unique canonical candidate order"):
        evaluate_optional_media_frontier(
            (first, first),
            projection.policy,
            projection.projection_sha256,
        )

    mixed_policy = _patched_candidate(first, policy_sha256="f" * 64)
    with pytest.raises(ValueError, match="mixed policy"):
        evaluate_optional_media_frontier(
            (mixed_policy,),
            projection.policy,
            projection.projection_sha256,
        )


def test_publisher_rederives_counts_and_rejects_caller_patch(tmp_path: Path) -> None:
    audit = build_optional_media_frontier_audit(REPO_ROOT)
    patched_frontier = audit.first_frontier.model_copy(
        update={"eligible_count": 36, "capped_capacity": 36}
    )
    patched = replace(audit, first_frontier=patched_frontier)

    with pytest.raises(OptionalMediaFrontierAuditError, match="patched|replay"):
        publish_optional_media_frontier_audit(
            patched,
            repository_root=REPO_ROOT,
            output_base=tmp_path / "readiness",
        )


def test_publication_rejects_symlink_and_existing_byte_substitution(
    tmp_path: Path,
) -> None:
    audit = build_optional_media_frontier_audit(REPO_ROOT)
    real_base = tmp_path / "real"
    real_base.mkdir()
    symlink_base = tmp_path / "readiness-link"
    symlink_base.symlink_to(real_base, target_is_directory=True)

    with pytest.raises(OptionalMediaFrontierAuditError, match="symlink"):
        publish_optional_media_frontier_audit(
            audit,
            repository_root=REPO_ROOT,
            output_base=symlink_base,
        )

    root = publish_optional_media_frontier_audit(
        audit,
        repository_root=REPO_ROOT,
        output_base=tmp_path / "readiness",
    )
    (root / "eligibility-replay.json").write_bytes(b"{}")
    with pytest.raises(OptionalMediaFrontierAuditError, match="differs"):
        publish_optional_media_frontier_audit(
            audit,
            repository_root=REPO_ROOT,
            output_base=tmp_path / "readiness",
        )


def test_existing_output_descendant_through_symlink_parent_is_rejected(
    tmp_path: Path,
) -> None:
    audit = build_optional_media_frontier_audit(REPO_ROOT)
    real_parent = tmp_path / "real"
    real_base = real_parent / "readiness"
    published = publish_optional_media_frontier_audit(
        audit,
        repository_root=REPO_ROOT,
        output_base=real_base,
    )
    original_bytes = {path.name: path.read_bytes() for path in published.iterdir()}
    linked_parent = tmp_path / "linked"
    linked_parent.symlink_to(real_parent, target_is_directory=True)
    aliased_existing_base = linked_parent / "readiness"

    assert aliased_existing_base.exists()
    assert not aliased_existing_base.is_symlink()
    with pytest.raises(OptionalMediaFrontierAuditError, match="symlink"):
        publish_optional_media_frontier_audit(
            audit,
            repository_root=REPO_ROOT,
            output_base=aliased_existing_base,
        )
    aliased_root = aliased_existing_base / published.name
    with pytest.raises(OptionalMediaFrontierAuditError, match="symlink"):
        frontier_audit_module._verify_existing_publication(
            aliased_root,
            original_bytes,
        )
    with pytest.raises(OptionalMediaFrontierAuditError, match="symlink"):
        frontier_audit_module._only_frontier_root(aliased_existing_base)
    assert {path.name: path.read_bytes() for path in published.iterdir()} == original_bytes


def test_audit_is_offline_and_preserves_plan49_history(monkeypatch: pytest.MonkeyPatch) -> None:
    history = (
        REPO_ROOT
        / ".planning/phases/02-canonical-36-rights-and-evaluation-manifest"
        / "02-49-TERMINAL-HISTORY.md"
    )
    before = history.read_bytes()

    def deny_network(*_args: object, **_kwargs: object) -> None:
        raise AssertionError("frontier audit attempted provider traffic")

    monkeypatch.setattr("socket.create_connection", deny_network)
    audit = build_optional_media_frontier_audit(REPO_ROOT)

    assert audit.first_frontier.status == "REPRESENTATION_INFEASIBLE"
    assert history.read_bytes() == before
