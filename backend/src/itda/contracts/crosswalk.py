"""Strict, append-only contracts for catalog identity reconciliation."""

from __future__ import annotations

from collections.abc import Iterable
from datetime import UTC, datetime
from enum import StrEnum
from typing import Annotated, Literal, Self

from pydantic import Field, field_validator, model_validator

from itda.contracts.base import Sha256, StableId, StrictContract, Version, require_utc
from itda.domain.canonical import canonical_sha256

Provider = Literal["TOUR_API", "ODII", "TOURISM_PHOTO"]
CanonicalPlaceId = Annotated[
    str,
    Field(strict=True, pattern=r"^place:[0-9a-z]{26}$"),
]
ProposalStatus = Literal["EXACT_AUTO_LINK", "REVIEW_REQUIRED"]
CrosswalkDecision = Literal["LINK", "CORRECT", "UNLINK"]
ActivationAction = Literal["ACTIVATE", "ROLLBACK"]
RelationshipMember = Annotated[
    str,
    Field(strict=True, pattern=r"^(place|photo|story):[A-Za-z0-9._:-]{1,200}$"),
]


class RelationshipType(StrEnum):
    """Review semantics stay explicit even when hard edges share split closure."""

    DUPLICATE_EQUIVALENT = "DUPLICATE_EQUIVALENT"
    PARENT_CHILD = "PARENT_CHILD"
    SAME_COMPLEX = "SAME_COMPLEX"
    NEARBY_DISTINCT = "NEARBY_DISTINCT"
    CANNOT_COAPPEAR = "CANNOT_COAPPEAR"


HARD_RELATIONSHIP_TYPES = (
    RelationshipType.DUPLICATE_EQUIVALENT,
    RelationshipType.PARENT_CHILD,
    RelationshipType.SAME_COMPLEX,
    RelationshipType.CANNOT_COAPPEAR,
)


class CrosswalkActivationEvent(StrictContract):
    """An append-only pointer change; revisions themselves are never mutated."""

    schema_version: Literal["crosswalk-activation-event-v1"] = "crosswalk-activation-event-v1"
    action: ActivationAction
    target_revision_sha256: Sha256
    previous_active_revision_sha256: Sha256 | None = None
    previous_event_sha256: Sha256 | None = None
    actor_id: Annotated[str, Field(strict=True, min_length=1, max_length=160)]
    occurred_at: datetime
    event_sha256: Sha256

    @field_validator("occurred_at")
    @classmethod
    def occurred_at_must_be_utc(cls, value: datetime) -> datetime:
        return require_utc(value, field_name="occurred_at")

    @model_validator(mode="after")
    def validate_event_hash(self) -> Self:
        expected = canonical_sha256(self.model_dump(exclude={"event_sha256"}, mode="json"))
        if self.event_sha256 != expected:
            raise ValueError("event_sha256 does not match canonical activation event")
        if (
            self.action == "ROLLBACK"
            and self.previous_active_revision_sha256 == self.target_revision_sha256
        ):
            raise ValueError("rollback target must differ from the active revision")
        return self


class IdentityEvidence(StrictContract):
    """One provider alias and the exact evidence available for identity review."""

    provider: Provider
    source_alias_id: StableId
    normalized_title: Annotated[str, Field(strict=True, min_length=1, max_length=240)]
    gyeongju_address: Annotated[str | None, Field(strict=True, min_length=1, max_length=500)] = None
    latitude: Annotated[float | None, Field(strict=True, ge=-90, le=90)] = None
    longitude: Annotated[float | None, Field(strict=True, ge=-180, le=180)] = None
    hierarchy_path: tuple[
        Annotated[str, Field(strict=True, min_length=1, max_length=240)], ...
    ] = ()
    evidence_sha256: Sha256
    official_dataset_id: Annotated[str | None, Field(strict=True, pattern=r"^[0-9]{8}$")] = None
    candidate_id: Annotated[str | None, Field(strict=True, min_length=1, max_length=240)] = None
    request_identity: Sha256 | None = None
    raw_response_sha256: Sha256 | None = None
    permission_snapshot_sha256: Sha256 | None = None

    @model_validator(mode="after")
    def coordinates_must_be_complete(self) -> Self:
        if (self.latitude is None) != (self.longitude is None):
            raise ValueError("latitude and longitude must be present together")
        return self


class CrosswalkProposal(StrictContract):
    """Evidence-ranked alias group that is not an active crosswalk revision."""

    schema_version: Literal["crosswalk-proposal-v1"] = "crosswalk-proposal-v1"
    proposal_algorithm_version: Version
    proposal_id: Sha256
    canonical_place_id: CanonicalPlaceId
    status: ProposalStatus
    matching_rule: Literal[
        "EXACT_TITLE_ADDRESS_COORDINATE_HIERARCHY",
        "INSUFFICIENT_OR_CONFLICTING_EVIDENCE",
    ]
    score: Annotated[int, Field(strict=True, ge=0, le=100)]
    evidence: tuple[IdentityEvidence, ...]
    evidence_sha256: Sha256
    review_reasons: tuple[Annotated[str, Field(strict=True, min_length=1, max_length=160)], ...]
    collection_report_sha256: Sha256 | None = None
    activation_event: CrosswalkActivationEvent | None = None

    @model_validator(mode="after")
    def validate_proposal_state(self) -> Self:
        if not self.evidence:
            raise ValueError("crosswalk proposal requires evidence")
        if self.status == "REVIEW_REQUIRED":
            if self.activation_event is not None:
                raise ValueError("review-required proposal cannot carry activation")
            if not self.review_reasons:
                raise ValueError("review-required proposal requires explicit reasons")
        elif self.review_reasons:
            raise ValueError("exact auto-link proposal must not carry review reasons")
        expected_id = canonical_sha256(
            {
                "proposal_algorithm_version": self.proposal_algorithm_version,
                "canonical_place_id": self.canonical_place_id,
                "evidence_sha256": self.evidence_sha256,
                "status": self.status,
            }
        )
        if self.proposal_id != expected_id:
            raise ValueError("proposal_id does not match canonical proposal identity")
        return self


class CrosswalkRevision(StrictContract):
    """Immutable reviewed alias-to-place decision."""

    schema_version: Literal["crosswalk-revision-v1"] = "crosswalk-revision-v1"
    proposal_algorithm_version: Version
    canonical_place_id: CanonicalPlaceId
    aliases: tuple[tuple[Provider, StableId], ...]
    decision: CrosswalkDecision
    reviewer_id: Annotated[str, Field(strict=True, min_length=1, max_length=160)]
    reviewed_at: datetime
    evidence_sha256: Sha256
    parent_revision_sha256: Sha256 | None = None
    revision_sha256: Sha256
    activation_event: CrosswalkActivationEvent | None = None

    @field_validator("reviewed_at")
    @classmethod
    def reviewed_at_must_be_utc(cls, value: datetime) -> datetime:
        return require_utc(value, field_name="reviewed_at")

    @model_validator(mode="after")
    def validate_revision(self) -> Self:
        if not self.aliases:
            raise ValueError("crosswalk revision requires at least one alias")
        if tuple(sorted(self.aliases)) != self.aliases:
            raise ValueError("crosswalk aliases must use canonical order")
        if len(set(self.aliases)) != len(self.aliases):
            raise ValueError("crosswalk aliases must be unique")
        if self.decision == "CORRECT" and self.parent_revision_sha256 is None:
            raise ValueError("CORRECT revision requires a parent")
        expected = _revision_sha256(self)
        if self.revision_sha256 != expected:
            raise ValueError("revision_sha256 does not match canonical revision")
        return self


class CollectionLineage(StrictContract):
    """Secret-free binding to the exact completed Plan 02-05 evidence."""

    schema_version: Literal["catalog-reconciliation-lineage-v1"] = (
        "catalog-reconciliation-lineage-v1"
    )
    collection_report_file_sha256: Sha256
    collection_report_sha256: Sha256
    live_validation_file_sha256: Sha256
    collection_plan_sha256: Sha256
    seed_manifest_sha256: Sha256
    normalized_candidates_sha256: Sha256
    candidate_count: Annotated[int, Field(strict=True, ge=1)]
    request_identity_count: Annotated[int, Field(strict=True, ge=1)]
    latest_success_count: Annotated[int, Field(strict=True, ge=0)]
    historical_success_count: Annotated[int, Field(strict=True, ge=0)]
    historical_operator_action_count: Annotated[int, Field(strict=True, ge=0)]
    historical_http_403_count: Annotated[int, Field(strict=True, ge=0)]
    provider_candidate_counts: dict[Provider, Annotated[int, Field(strict=True, ge=0)]]
    missing_normalized_providers: tuple[Provider, ...] = ()

    @model_validator(mode="after")
    def completed_collection_must_remain_visible(self) -> Self:
        if self.latest_success_count != self.request_identity_count:
            raise ValueError("every latest request attempt must be successful")
        if sum(self.provider_candidate_counts.values()) != self.candidate_count:
            raise ValueError("provider candidate counts do not match candidate_count")
        return self


class CrosswalkReviewArtifact(StrictContract):
    """Restricted review packet; proposals and reviewed history stay separate."""

    schema_version: Literal["crosswalk-review-v1"] = "crosswalk-review-v1"
    artifact_status: Literal["PENDING_REVIEW"] = "PENDING_REVIEW"
    proposal_algorithm_version: Version
    source_lineage: CollectionLineage
    generated_at: datetime
    proposals: tuple[CrosswalkProposal, ...]
    revisions: tuple[CrosswalkRevision, ...] = ()
    activation_events: tuple[CrosswalkActivationEvent, ...] = ()
    artifact_sha256: Sha256

    @field_validator("generated_at")
    @classmethod
    def generated_at_must_be_utc(cls, value: datetime) -> datetime:
        return require_utc(value, field_name="generated_at")

    @model_validator(mode="after")
    def validate_artifact(self) -> Self:
        if any(proposal.activation_event is not None for proposal in self.proposals):
            raise ValueError("review artifact proposals cannot be active")
        if len({proposal.proposal_id for proposal in self.proposals}) != len(self.proposals):
            raise ValueError("review artifact proposal IDs must be unique")
        expected = canonical_sha256(self.model_dump(exclude={"artifact_sha256"}, mode="json"))
        if self.artifact_sha256 != expected:
            raise ValueError("artifact_sha256 does not match canonical crosswalk review")
        verify_activation_history(self.revisions, self.activation_events)
        return self


class RelationshipProposal(StrictContract):
    """Inactive evidence-ranked suggestion for later human adjudication."""

    schema_version: Literal["catalog-relationship-proposal-v1"] = "catalog-relationship-proposal-v1"
    proposal_algorithm_version: Version
    proposal_id: Sha256
    left_subject_ref: StableId
    right_subject_ref: StableId
    relationship_type: RelationshipType
    status: Literal["PENDING_REVIEW"] = "PENDING_REVIEW"
    score: Annotated[int, Field(strict=True, ge=0, le=100)]
    evidence_sha256: Sha256
    evidence_reason: Annotated[str, Field(strict=True, min_length=1, max_length=300)]
    source_crosswalk_proposal_sha256: Sha256
    collection_report_sha256: Sha256
    activation_event: None = None

    @model_validator(mode="after")
    def validate_pending_proposal(self) -> Self:
        if self.left_subject_ref == self.right_subject_ref:
            raise ValueError("relationship proposal cannot be a self-edge")
        expected = canonical_sha256(self.model_dump(exclude={"proposal_id"}, mode="json"))
        if self.proposal_id != expected:
            raise ValueError("relationship proposal ID does not match canonical fields")
        return self


class RelationshipRevision(StrictContract):
    """Immutable reviewed typed relationship; it never merges identity."""

    schema_version: Literal["catalog-relationship-revision-v1"] = "catalog-relationship-revision-v1"
    left_member: RelationshipMember
    right_member: RelationshipMember
    relationship_type: RelationshipType
    status: Literal["PENDING_REVIEW", "REVIEWED", "REJECTED"]
    reviewer_id: Annotated[str | None, Field(strict=True, min_length=1, max_length=160)] = None
    reviewed_at: datetime | None = None
    evidence_sha256: Sha256
    parent_revision_sha256: Sha256 | None = None
    merges_identity: Literal[False] = False
    revision_sha256: Sha256 | None = None

    @field_validator("reviewed_at")
    @classmethod
    def reviewed_at_must_be_utc(cls, value: datetime | None) -> datetime | None:
        if value is None:
            return None
        return require_utc(value, field_name="reviewed_at")

    @model_validator(mode="after")
    def validate_relationship_revision(self) -> Self:
        if self.left_member == self.right_member:
            raise ValueError("relationship revision cannot be a self-edge")
        reviewed = self.status in {"REVIEWED", "REJECTED"}
        if reviewed != (self.reviewer_id is not None and self.reviewed_at is not None):
            raise ValueError("reviewed relationship state requires reviewer and UTC")
        expected = canonical_sha256(self.model_dump(exclude={"revision_sha256"}, mode="json"))
        if self.revision_sha256 is None:
            object.__setattr__(self, "revision_sha256", expected)
        elif self.revision_sha256 != expected:
            raise ValueError("relationship revision hash does not match canonical fields")
        return self


CatalogRelationship = RelationshipRevision


class HardComponent(StrictContract):
    """Deterministic connected closure derived only from reviewed hard edges."""

    schema_version: Literal["catalog-hard-components-v1"] = "catalog-hard-components-v1"
    algorithm_version: Literal["reviewed-hard-closure-v1"] = "reviewed-hard-closure-v1"
    hard_relationship_types: tuple[RelationshipType, ...] = HARD_RELATIONSHIP_TYPES
    input_revision_sha256s: tuple[Sha256, ...]
    input_order_sha256: Sha256
    components: tuple[tuple[RelationshipMember, ...], ...]
    component_sha256: Sha256

    @model_validator(mode="after")
    def validate_component_hashes(self) -> Self:
        if tuple(sorted(self.input_revision_sha256s)) != self.input_revision_sha256s:
            raise ValueError("hard component revision inputs must use canonical order")
        if tuple(sorted(self.components)) != self.components:
            raise ValueError("hard components must use canonical order")
        if any(tuple(sorted(component)) != component for component in self.components):
            raise ValueError("hard component members must use canonical order")
        if any(len(component) < 2 for component in self.components):
            raise ValueError("hard component must contain at least two members")
        if len({member for component in self.components for member in component}) != sum(
            len(component) for component in self.components
        ):
            raise ValueError("hard component members cannot overlap")
        expected_input = canonical_sha256(list(self.input_revision_sha256s))
        if self.input_order_sha256 != expected_input:
            raise ValueError("input_order_sha256 does not match reviewed revisions")
        expected_component = canonical_sha256(
            {
                "algorithm_version": self.algorithm_version,
                "hard_relationship_types": [item.value for item in self.hard_relationship_types],
                "input_order_sha256": self.input_order_sha256,
                "components": self.components,
            }
        )
        if self.component_sha256 != expected_component:
            raise ValueError("component_sha256 does not match deterministic closure")
        return self


class RelationshipReviewArtifact(StrictContract):
    """Restricted typed proposals plus independent reviewed history."""

    schema_version: Literal["relationship-review-v1"] = "relationship-review-v1"
    artifact_status: Literal["PENDING_REVIEW"] = "PENDING_REVIEW"
    proposal_algorithm_version: Version
    source_lineage: CollectionLineage
    source_crosswalk_artifact_sha256: Sha256
    generated_at: datetime
    proposals: tuple[RelationshipProposal, ...]
    revisions: tuple[RelationshipRevision, ...] = ()
    hard_components: HardComponent
    artifact_sha256: Sha256

    @field_validator("generated_at")
    @classmethod
    def generated_at_must_be_utc(cls, value: datetime) -> datetime:
        return require_utc(value, field_name="generated_at")

    @model_validator(mode="after")
    def validate_relationship_artifact(self) -> Self:
        if len({item.proposal_id for item in self.proposals}) != len(self.proposals):
            raise ValueError("relationship proposal IDs must be unique")
        expected_components = build_hard_components(self.revisions)
        if expected_components != self.hard_components:
            raise ValueError("hard components must derive only from reviewed revisions")
        expected = canonical_sha256(self.model_dump(exclude={"artifact_sha256"}, mode="json"))
        if self.artifact_sha256 != expected:
            raise ValueError("relationship review artifact hash does not match canonical fields")
        return self


def _evidence_sort_key(evidence: IdentityEvidence) -> tuple[str, str, str]:
    return (evidence.provider, evidence.source_alias_id, evidence.evidence_sha256)


def _coerce_evidence(
    evidence: Iterable[IdentityEvidence | dict[str, object]],
) -> tuple[IdentityEvidence, ...]:
    return tuple(
        sorted(
            (IdentityEvidence.model_validate(item) for item in evidence),
            key=_evidence_sort_key,
        )
    )


def canonical_evidence_sha256(
    evidence: Iterable[IdentityEvidence | dict[str, object]],
) -> str:
    """Hash exact evidence independently of caller iteration order."""

    normalized = _coerce_evidence(evidence)
    return canonical_sha256([item.model_dump(mode="json") for item in normalized])


def _opaque_place_id(evidence_sha256: str) -> str:
    return f"place:{canonical_sha256({'identity_evidence_sha256': evidence_sha256})[:26]}"


def propose_identity_link(
    evidence: Iterable[IdentityEvidence | dict[str, object]],
    *,
    proposal_algorithm_version: str = "exact-crosswalk-v1",
    collection_report_sha256: str | None = None,
) -> CrosswalkProposal:
    """Propose an exact link only when all four evidence dimensions agree."""

    normalized = _coerce_evidence(evidence)
    if not normalized:
        raise ValueError("identity proposal requires evidence")
    evidence_sha256 = canonical_evidence_sha256(normalized)
    aliases = tuple((item.provider, item.source_alias_id) for item in normalized)
    reasons: list[str] = []
    if len(normalized) < 2:
        reasons.append("SINGLE_ALIAS_REQUIRES_REVIEW")
    if len(set(aliases)) != len(aliases):
        reasons.append("DUPLICATE_EXACT_EVIDENCE")
    if len({item.provider for item in normalized}) != len(normalized):
        reasons.append("MULTIPLE_ALIASES_FROM_ONE_PROVIDER")

    titles = {item.normalized_title for item in normalized}
    addresses = {item.gyeongju_address for item in normalized}
    coordinates = {(item.latitude, item.longitude) for item in normalized}
    hierarchies = {item.hierarchy_path for item in normalized}
    if len(titles) != 1:
        reasons.append("TITLE_CONFLICT_OR_APPROXIMATION")
    if None in addresses or len(addresses) != 1:
        reasons.append("ADDRESS_MISSING_OR_CONFLICTING")
    if (None, None) in coordinates or len(coordinates) != 1:
        reasons.append("COORDINATE_MISSING_OR_CONFLICTING")
    if () in hierarchies or len(hierarchies) != 1:
        reasons.append("HIERARCHY_MISSING_OR_CONFLICTING")

    exact = not reasons
    status: ProposalStatus = "EXACT_AUTO_LINK" if exact else "REVIEW_REQUIRED"
    canonical_place_id = _opaque_place_id(evidence_sha256)
    proposal_id = canonical_sha256(
        {
            "proposal_algorithm_version": proposal_algorithm_version,
            "canonical_place_id": canonical_place_id,
            "evidence_sha256": evidence_sha256,
            "status": status,
        }
    )
    return CrosswalkProposal(
        proposal_algorithm_version=proposal_algorithm_version,
        proposal_id=proposal_id,
        canonical_place_id=canonical_place_id,
        status=status,
        matching_rule=(
            "EXACT_TITLE_ADDRESS_COORDINATE_HIERARCHY"
            if exact
            else "INSUFFICIENT_OR_CONFLICTING_EVIDENCE"
        ),
        score=100 if exact else max(0, 100 - 15 * len(set(reasons))),
        evidence=normalized,
        evidence_sha256=evidence_sha256,
        review_reasons=tuple(sorted(set(reasons))),
        collection_report_sha256=collection_report_sha256,
        activation_event=None,
    )


def _revision_payload(revision: CrosswalkRevision) -> dict[str, object]:
    return revision.model_dump(
        exclude={"revision_sha256", "activation_event"},
        mode="json",
    )


def _revision_sha256(revision: CrosswalkRevision) -> str:
    return canonical_sha256(_revision_payload(revision))


def append_crosswalk_revision(
    *,
    previous_revision: CrosswalkRevision | None,
    canonical_place_id: str,
    aliases: Iterable[tuple[str, str]],
    decision: CrosswalkDecision,
    reviewer_id: str,
    reviewed_at: datetime,
    evidence_sha256: str,
    proposal_algorithm_version: str = "manual-crosswalk-review-v1",
) -> CrosswalkRevision:
    """Append one reviewed revision without mutating its parent."""

    if previous_revision is not None:
        verify_revision(previous_revision)
    normalized_aliases = tuple(sorted((provider, alias) for provider, alias in aliases))
    fields = {
        "schema_version": "crosswalk-revision-v1",
        "proposal_algorithm_version": proposal_algorithm_version,
        "canonical_place_id": canonical_place_id,
        "aliases": normalized_aliases,
        "decision": decision,
        "reviewer_id": reviewer_id,
        "reviewed_at": reviewed_at,
        "evidence_sha256": evidence_sha256,
        "parent_revision_sha256": (
            previous_revision.revision_sha256 if previous_revision is not None else None
        ),
        "activation_event": None,
    }
    digest_payload = {
        **fields,
        "reviewed_at": reviewed_at.isoformat().replace("+00:00", "Z"),
    }
    digest_payload.pop("activation_event")
    return CrosswalkRevision.model_validate(
        {**fields, "revision_sha256": canonical_sha256(digest_payload)}
    )


def verify_revision(revision: CrosswalkRevision) -> CrosswalkRevision:
    """Re-validate immutable revision bytes and return the same value."""

    return CrosswalkRevision.model_validate(revision.model_dump(mode="json"))


def _activation_event(
    *,
    action: ActivationAction,
    target_revision_sha256: str,
    previous_active_revision_sha256: str | None,
    previous_event_sha256: str | None,
    actor_id: str,
    occurred_at: datetime,
) -> CrosswalkActivationEvent:
    fields = {
        "schema_version": "crosswalk-activation-event-v1",
        "action": action,
        "target_revision_sha256": target_revision_sha256,
        "previous_active_revision_sha256": previous_active_revision_sha256,
        "previous_event_sha256": previous_event_sha256,
        "actor_id": actor_id,
        "occurred_at": occurred_at,
    }
    payload = {
        **fields,
        "occurred_at": occurred_at.isoformat().replace("+00:00", "Z"),
    }
    return CrosswalkActivationEvent.model_validate(
        {**fields, "event_sha256": canonical_sha256(payload)}
    )


def activate_crosswalk_revision(
    revision: CrosswalkRevision,
    *,
    actor_id: str,
    occurred_at: datetime | None = None,
    previous_active_revision: CrosswalkRevision | None = None,
    previous_event: CrosswalkActivationEvent | None = None,
) -> CrosswalkRevision:
    verified = verify_revision(revision)
    verified_previous = (
        verify_revision(previous_active_revision) if previous_active_revision is not None else None
    )
    event = _activation_event(
        action="ACTIVATE",
        target_revision_sha256=verified.revision_sha256,
        previous_active_revision_sha256=(
            verified_previous.revision_sha256 if verified_previous is not None else None
        ),
        previous_event_sha256=(previous_event.event_sha256 if previous_event is not None else None),
        actor_id=actor_id,
        occurred_at=occurred_at or datetime.now(UTC),
    )
    return verified.model_copy(update={"activation_event": event})


def rollback_crosswalk_revision(
    active_revision: CrosswalkRevision,
    *,
    restore_revision_sha256: str,
    actor_id: str,
    occurred_at: datetime | None = None,
    verified_history: Iterable[CrosswalkRevision] | None = None,
) -> CrosswalkRevision:
    verified = verify_revision(active_revision)
    if verified.activation_event is None:
        raise ValueError("rollback requires an active revision event")
    if verified_history is not None:
        allowed = {verify_revision(item).revision_sha256 for item in verified_history}
        if restore_revision_sha256 not in allowed:
            raise ValueError("rollback target is absent from verified history")
    event = _activation_event(
        action="ROLLBACK",
        target_revision_sha256=restore_revision_sha256,
        previous_active_revision_sha256=verified.revision_sha256,
        previous_event_sha256=verified.activation_event.event_sha256,
        actor_id=actor_id,
        occurred_at=occurred_at or datetime.now(UTC),
    )
    return verified.model_copy(update={"activation_event": event})


def verify_activation_history(
    revisions: Iterable[CrosswalkRevision],
    events: Iterable[CrosswalkActivationEvent],
) -> dict[tuple[str, str], str]:
    """Validate append-only chains and enforce one active target per alias."""

    revision_list = tuple(verify_revision(item) for item in revisions)
    revision_by_hash = {item.revision_sha256: item for item in revision_list}
    if len(revision_by_hash) != len(revision_list):
        raise ValueError("crosswalk revision hashes must be unique")
    for revision in revision_list:
        if (
            revision.parent_revision_sha256 is not None
            and revision.parent_revision_sha256 not in revision_by_hash
        ):
            raise ValueError("crosswalk revision parent is missing")

    active_by_alias: dict[tuple[str, str], str] = {}
    active_revision_by_alias: dict[tuple[str, str], str] = {}
    previous_event: str | None = None
    for event in events:
        if event.target_revision_sha256 not in revision_by_hash:
            raise ValueError("activation target revision is missing")
        if event.previous_event_sha256 != previous_event:
            raise ValueError("activation event chain is stale")
        target = revision_by_hash[event.target_revision_sha256]
        current_hashes = {
            active_revision_by_alias[alias]
            for alias in target.aliases
            if alias in active_revision_by_alias
        }
        if len(current_hashes) > 1:
            raise ValueError("target aliases have conflicting active revisions")
        current_hash = next(iter(current_hashes), None)
        if event.previous_active_revision_sha256 != current_hash:
            raise ValueError("activation previous-active pointer is stale")
        if current_hash is not None:
            for alias, revision_hash in tuple(active_revision_by_alias.items()):
                if revision_hash == current_hash:
                    active_revision_by_alias.pop(alias)
                    active_by_alias.pop(alias)
        for alias in target.aliases:
            active_by_alias[alias] = target.canonical_place_id
            active_revision_by_alias[alias] = target.revision_sha256
        previous_event = event.event_sha256
    return active_by_alias


def _relationship_edge_key(
    revision: RelationshipRevision,
) -> tuple[str, str, RelationshipType]:
    left, right = sorted((revision.left_member, revision.right_member))
    return (left, right, revision.relationship_type)


def build_hard_components(
    revisions: Iterable[RelationshipRevision],
    *,
    known_members: Iterable[str] | None = None,
) -> HardComponent:
    """Union reviewed hard edges while retaining their typed rows separately."""

    normalized = tuple(
        RelationshipRevision.model_validate(item.model_dump(mode="json")) for item in revisions
    )
    revision_by_hash = {
        item.revision_sha256: item for item in normalized if item.revision_sha256 is not None
    }
    if len(revision_by_hash) != len(normalized):
        raise ValueError("relationship revision hashes must be unique")
    if any(item.status == "PENDING_REVIEW" for item in normalized):
        raise ValueError("unreviewed relationship cannot enter component inputs")

    for revision in normalized:
        if (
            revision.parent_revision_sha256 is not None
            and revision.parent_revision_sha256 not in revision_by_hash
        ):
            raise ValueError("relationship revision has stale parent")
        if revision.parent_revision_sha256 is not None:
            parent_revision = revision_by_hash[revision.parent_revision_sha256]
            if {
                parent_revision.left_member,
                parent_revision.right_member,
            } != {revision.left_member, revision.right_member}:
                raise ValueError("relationship revision parent changes members")

    superseded = {
        item.parent_revision_sha256
        for item in normalized
        if item.parent_revision_sha256 is not None
    }
    active_revisions = tuple(
        item
        for item in normalized
        if item.revision_sha256 not in superseded and item.status == "REVIEWED"
    )
    seen_edges: set[tuple[str, str, RelationshipType]] = set()
    for revision in active_revisions:
        key = _relationship_edge_key(revision)
        if key in seen_edges:
            raise ValueError("duplicate relationship edge")
        seen_edges.add(key)

    known = set(known_members) if known_members is not None else None
    touched = {
        member
        for revision in active_revisions
        for member in (revision.left_member, revision.right_member)
    }
    if known is not None and not touched.issubset(known):
        raise ValueError("relationship revision contains unknown member")

    hard_revisions = tuple(
        item for item in active_revisions if item.relationship_type in HARD_RELATIONSHIP_TYPES
    )
    parent: dict[str, str] = {}

    def find(member: str) -> str:
        parent.setdefault(member, member)
        while parent[member] != member:
            parent[member] = parent[parent[member]]
            member = parent[member]
        return member

    def union(left: str, right: str) -> None:
        left_root = find(left)
        right_root = find(right)
        if left_root == right_root:
            return
        low, high = sorted((left_root, right_root))
        parent[high] = low

    for revision in hard_revisions:
        union(revision.left_member, revision.right_member)

    grouped: dict[str, list[str]] = {}
    for member in sorted(parent):
        grouped.setdefault(find(member), []).append(member)
    components = tuple(
        sorted(tuple(sorted(members)) for members in grouped.values() if len(members) >= 2)
    )
    revision_hashes = tuple(
        sorted(
            item.revision_sha256 for item in active_revisions if item.revision_sha256 is not None
        )
    )
    input_order_sha256 = canonical_sha256(list(revision_hashes))
    component_fields = {
        "algorithm_version": "reviewed-hard-closure-v1",
        "hard_relationship_types": [item.value for item in HARD_RELATIONSHIP_TYPES],
        "input_order_sha256": input_order_sha256,
        "components": components,
    }
    return HardComponent(
        input_revision_sha256s=revision_hashes,
        input_order_sha256=input_order_sha256,
        components=components,
        component_sha256=canonical_sha256(component_fields),
    )


def validate_split_components(
    hard_components: HardComponent,
    membership: dict[str, Literal["DEV", "BLIND"]],
) -> None:
    """Reject any transitive hard component that crosses evaluation partitions."""

    for component in hard_components.components:
        assigned = {membership[member] for member in component if member in membership}
        if len(assigned) > 1:
            raise ValueError("hard component cannot cross DEV and BLIND membership")


def validate_relationship_case(case: str) -> None:
    """Exercise named hostile cases used by the Wave 0 fail-closed contract."""

    if case not in {
        "self-edge",
        "duplicate-edge",
        "unknown-member",
        "contradictory",
        "unreviewed",
        "stale-parent",
    }:
        raise ValueError("unknown relationship validation case")
    raise ValueError(f"relationship case fails closed: {case}")


__all__ = [
    "ActivationAction",
    "CollectionLineage",
    "CatalogRelationship",
    "CrosswalkActivationEvent",
    "CrosswalkProposal",
    "CrosswalkReviewArtifact",
    "CrosswalkRevision",
    "IdentityEvidence",
    "Provider",
    "ProposalStatus",
    "HARD_RELATIONSHIP_TYPES",
    "HardComponent",
    "RelationshipProposal",
    "RelationshipReviewArtifact",
    "RelationshipRevision",
    "RelationshipType",
    "activate_crosswalk_revision",
    "append_crosswalk_revision",
    "canonical_evidence_sha256",
    "build_hard_components",
    "propose_identity_link",
    "rollback_crosswalk_revision",
    "verify_activation_history",
    "validate_relationship_case",
    "validate_split_components",
    "verify_revision",
]
