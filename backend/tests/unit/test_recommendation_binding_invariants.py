from __future__ import annotations

import pytest

from itda.db.models import RecommendationRequestBindingRow, RecommendationRunRow
from itda.db.recommendation_repositories import (
    RecommendationPinInvalid,
    _validate_request_binding_metadata,
)


def test_request_binding_metadata_must_match_the_persisted_run() -> None:
    binding = RecommendationRequestBindingRow(
        preference_profile_id="profile:bound",
        input_digest="a" * 64,
    )
    run = RecommendationRunRow(
        preference_profile_id="profile:other",
        input_digest="b" * 64,
    )

    with pytest.raises(RecommendationPinInvalid, match="metadata drifted"):
        _validate_request_binding_metadata(binding, run)


def test_request_binding_model_uses_composite_run_metadata_foreign_key() -> None:
    constraints = RecommendationRequestBindingRow.__table__.foreign_key_constraints
    assert {
        (foreign_key.parent.name, foreign_key.target_fullname)
        for constraint in constraints
        if constraint.name == "fk_request_binding_run_metadata"
        for foreign_key in constraint.elements
    } == {
        ("run_id", "app.recommendation_runs.run_id"),
        ("preference_profile_id", "app.recommendation_runs.preference_profile_id"),
        ("input_digest", "app.recommendation_runs.input_digest"),
    }
