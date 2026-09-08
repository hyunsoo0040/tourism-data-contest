"""Wave 0 contract for DATA-02 (02-W0-DATA02; T-02-05)."""

from __future__ import annotations

import importlib
import importlib.util
from datetime import UTC, datetime
from types import ModuleType

import pytest

CAPABILITY_MODULE = "itda.contracts.crosswalk"
REVIEWED_AT = datetime(2026, 7, 27, 5, 0, tzinfo=UTC)


def _capability_or_skip() -> ModuleType:
    if importlib.util.find_spec(CAPABILITY_MODULE) is None:
        pytest.skip("crosswalk production capability is implemented in Plan 02-06")
    return importlib.import_module(CAPABILITY_MODULE)


def _exact_evidence() -> list[dict[str, object]]:
    return [
        {
            "provider": "TOUR_API",
            "source_alias_id": "126166",
            "normalized_title": "불국사",
            "gyeongju_address": "경상북도 경주시 불국로 385",
            "latitude": 35.790000,
            "longitude": 129.331000,
            "hierarchy_path": ("경주시", "진현동", "불국사"),
            "evidence_sha256": "1" * 64,
        },
        {
            "provider": "ODII",
            "source_alias_id": "story-777",
            "normalized_title": "불국사",
            "gyeongju_address": "경상북도 경주시 불국로 385",
            "latitude": 35.790000,
            "longitude": 129.331000,
            "hierarchy_path": ("경주시", "진현동", "불국사"),
            "evidence_sha256": "2" * 64,
        },
    ]


def test_exact_unambiguous_evidence_can_auto_link_to_source_neutral_id() -> None:
    capability = _capability_or_skip()
    proposal = capability.propose_identity_link(_exact_evidence())
    assert proposal.status == "EXACT_AUTO_LINK"
    assert proposal.canonical_place_id.startswith("place:")
    assert "126166" not in proposal.canonical_place_id
    assert "story-777" not in proposal.canonical_place_id
    assert "불국사" not in proposal.canonical_place_id
    assert proposal.evidence_sha256 == capability.canonical_evidence_sha256(_exact_evidence())


@pytest.mark.parametrize("case", ["approximate-title", "coordinate-conflict", "duplicate-exact"])
def test_ambiguous_or_conflicting_evidence_never_auto_activates(case: str) -> None:
    capability = _capability_or_skip()
    evidence = _exact_evidence()
    if case == "approximate-title":
        evidence[1]["normalized_title"] = "불국사 관광지"
    elif case == "coordinate-conflict":
        evidence[1]["latitude"] = 35.900000
    else:
        evidence.append(dict(evidence[1]))
    proposal = capability.propose_identity_link(evidence)
    assert proposal.status == "REVIEW_REQUIRED"
    assert proposal.activation_event is None


def test_reviewed_revisions_append_chain_and_explicit_rollback() -> None:
    capability = _capability_or_skip()
    initial = capability.append_crosswalk_revision(
        previous_revision=None,
        canonical_place_id="place:01hv6w0x1p6hx5jgq4v72g2g07",
        aliases=(("TOUR_API", "126166"),),
        decision="LINK",
        reviewer_id="reviewer-1",
        reviewed_at=REVIEWED_AT,
        evidence_sha256="3" * 64,
    )
    corrected = capability.append_crosswalk_revision(
        previous_revision=initial,
        canonical_place_id="place:01hv6w0x1p6hx5jgq4v72g2g08",
        aliases=(("TOUR_API", "126166"),),
        decision="CORRECT",
        reviewer_id="reviewer-2",
        reviewed_at=REVIEWED_AT,
        evidence_sha256="4" * 64,
    )
    activated = capability.activate_crosswalk_revision(corrected, actor_id="reviewer-2")
    rolled_back = capability.rollback_crosswalk_revision(
        activated,
        restore_revision_sha256=initial.revision_sha256,
        actor_id="reviewer-2",
    )

    assert corrected.parent_revision_sha256 == initial.revision_sha256
    assert initial.revision_sha256 != corrected.revision_sha256
    assert activated.activation_event.action == "ACTIVATE"
    assert rolled_back.activation_event.action == "ROLLBACK"
    assert rolled_back.activation_event.target_revision_sha256 == initial.revision_sha256
    assert capability.verify_activation_history(
        (initial, corrected),
        (activated.activation_event, rolled_back.activation_event),
    ) == {("TOUR_API", "126166"): initial.canonical_place_id}
    assert initial.model_dump() == capability.verify_revision(initial).model_dump()


def test_missing_crosswalk_revisions_is_controlled_red() -> None:
    if importlib.util.find_spec(CAPABILITY_MODULE) is None:
        pytest.fail("PHASE2-MISSING:crosswalk-revisions", pytrace=False)
    importlib.import_module(CAPABILITY_MODULE)
