"""Transactional, actor-bound access to immutable Phase 3 label revisions."""

from __future__ import annotations

import hashlib
import json
import re
from collections import defaultdict
from collections.abc import Mapping, Sequence
from datetime import UTC, datetime, timedelta
from typing import Annotated, Any, Literal, Self, cast

from pydantic import Field, StrictBool, model_validator
from sqlalchemy import text
from sqlalchemy.engine import CursorResult, Row
from sqlalchemy.exc import DBAPIError, IntegrityError
from sqlalchemy.orm import Session, sessionmaker

from itda.analysis.text.candidate_pipeline import validate_candidate_manifest
from itda.contracts.base import Sha256, StableId, StrictContract, require_utc
from itda.contracts.labeling import (
    AcceptedRevisionSelection,
    AdjudicatedAttributeValue,
    AdjudicatedLabelExport,
    AdjudicationProjection,
    AdjudicationSourceManifest,
    AdjudicatorAcceptedHead,
    AdjudicatorRawRevision,
    AdjudicatorRevisionChain,
    LabelExportBlocked,
    RawLabelRevision,
    ReviewTrigger,
    ReviewTriggerResolution,
    aggregate_accepted_revisions,
    derive_review_triggers,
)
from itda.contracts.profile_release import (
    ProfileReleaseActivePointerProjection,
    ProfileReleaseApproval,
    ProfileReleaseBuildDraftReference,
    ProfileReleaseBuildOutcome,
    ProfileReleaseBuildReceipt,
    ProfileReleaseBuildUnavailableError,
    ProfileReleaseCandidate,
    ProfileReleaseCompletion,
    ProfileReleaseDraftCleanupUnknownError,
    ProfileReleaseDraftPurgeResult,
    ProfileReleasePin,
    ProfileReleaseReplayError,
    ProfileReleaseRetryableAbortError,
    ProfileReleaseSessionPinProjection,
    ProfileReleaseState,
    ProfileReleaseStateProjection,
    ProfileReleaseTransitionMutationResult,
    ProfileReleaseTransitionOutcome,
    ProfileReleaseTransitionReceipt,
    ProfileReleaseUnknownOutcomeError,
    authorize_profile_release_action,
    profile_release_activate_binding_sha256_v1,
    profile_release_build_binding_sha256_v1,
    profile_release_rollback_binding_sha256_v1,
    validate_profile_release_action_identity,
    validate_rollback_authority,
)
from itda.contracts.profile_release_authority import (
    ProfileReleaseBuildAuthorityResolution,
)
from itda.contracts.profile_release_v2 import (
    ProfileReleaseCandidateAny,
    ProfileReleaseCandidateV2,
    ProfileReleaseTransitionProofV2,
    build_exact_predecessor_transition_proof,
    require_exact_predecessor_transition,
)
from itda.contracts.text_evidence import (
    AcceptedEvidenceReviewHead,
    EvidenceCandidate,
    EvidenceCandidateLane,
    EvidenceRelevanceDecision,
    EvidenceReviewChain,
    EvidenceReviewProvenance,
    EvidenceReviewQueue,
    EvidenceReviewReceipt,
    EvidenceReviewRevision,
    LaneEvidenceStatus,
    ReviewedEvidenceItem,
    ReviewedEvidenceLane,
    ReviewedEvidenceManifest,
)
from itda.contracts.text_evidence import (
    EvidenceLane as TextEvidenceLane,
)
from itda.domain.canonical import canonical_sha256


def _resolved_profile_release_candidate(
    resolution: object,
) -> ProfileReleaseCandidateAny:
    if not isinstance(resolution, ProfileReleaseBuildAuthorityResolution):
        raise TypeError("profile release build requires server authority resolution")
    return resolution.candidate


def _profile_release_candidate_from_payload(
    payload: Mapping[str, Any],
) -> ProfileReleaseCandidateAny:
    schema_version = payload.get("schema_version")
    if schema_version == "itda.profile-release-candidate.v1":
        return ProfileReleaseCandidate.model_validate(payload)
    if schema_version == "itda.profile-release-candidate.v2":
        return ProfileReleaseCandidateV2.model_validate(payload)
    raise ValueError("profile release schema is unsupported")


def _profile_release_lineage_columns(
    candidate: ProfileReleaseCandidateAny,
) -> tuple[str, str, str]:
    if isinstance(candidate, ProfileReleaseCandidateV2):
        return (
            candidate.lineage.canonical_lineage_sha256,
            candidate.lineage.dev_lineage_sha256,
            candidate.lineage.profile_schema_sha256,
        )
    return (
        candidate.canonical_lineage_sha256,
        candidate.dev_lineage_sha256,
        candidate.profile_schema_sha256,
    )


class StoredLabelRevision(StrictContract):
    revision_sha256: Sha256
    receipt_sha256: Sha256
    evaluator_principal: StableId
    revision: RawLabelRevision
    created_at: datetime

    @model_validator(mode="after")
    def created_at_is_utc(self) -> Self:
        require_utc(self.created_at, field_name="created_at")
        return self


class AcceptedHeadReceipt(StrictContract):
    event_sha256: Sha256
    revision_sha256: Sha256


class LabelSubmissionStatus(StrictContract):
    evaluator_pseudonym: StableId
    submission_status: Literal["SUBMITTED"]
    latest_server_event_at: datetime
    all_required_submissions_exist: StrictBool

    @model_validator(mode="after")
    def latest_event_is_utc(self) -> Self:
        require_utc(self.latest_server_event_at, field_name="latest_server_event_at")
        return self


class AcceptedLabelHead(StrictContract):
    revision_sha256: Sha256
    revision: RawLabelRevision
    selection: AcceptedRevisionSelection


class EvaluationRepository:
    """Use only a Phase 3 capability DSN; database functions derive the actor."""

    def __init__(
        self,
        factory: sessionmaker[Session],
        *,
        authority_connection_factory: sessionmaker[Session] | None = None,
    ) -> None:
        self._factory = factory
        self._authority_connection_factory = authority_connection_factory

    def profile_release_builder_database_principal(self) -> str:
        """Return the exact builder role that fixed-root authority must bind."""

        with self._factory() as session:
            return str(session.execute(text("SELECT session_user")).scalar_one())

    @staticmethod
    def _payload(revision: RawLabelRevision) -> str:
        payload = revision.model_dump(exclude={"evaluator_pseudonym"}, mode="json")
        return json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":"))

    @staticmethod
    def _stored_from_row(
        row: Row[Any],
        *,
        evaluator_pseudonym: str,
    ) -> StoredLabelRevision:
        mapping = row._mapping
        payload = dict(mapping["payload"])
        payload["evaluator_pseudonym"] = evaluator_pseudonym
        return StoredLabelRevision(
            revision_sha256=mapping["revision_sha256"],
            receipt_sha256=mapping["receipt_sha256"],
            evaluator_principal=mapping["evaluator_principal"],
            revision=RawLabelRevision.model_validate(payload),
            created_at=mapping["created_at"],
        )

    def append_revision(self, revision: RawLabelRevision) -> StoredLabelRevision:
        if revision.parent_revision_sha256 is not None:
            raise ValueError("initial revision cannot name a correction parent")
        return self._append(revision)

    def append_correction(self, revision: RawLabelRevision) -> StoredLabelRevision:
        if revision.parent_revision_sha256 is None or revision.correction_reason is None:
            raise ValueError("correction requires an immutable parent and reason")
        return self._append(revision)

    def _append(self, revision: RawLabelRevision) -> StoredLabelRevision:
        with self._factory.begin() as session:
            result = session.execute(
                text(
                    "SELECT revision_sha256, evaluator_principal "
                    "FROM dev_eval.submit_label_revision_v1(CAST(:payload AS jsonb))"
                ),
                {"payload": self._payload(revision)},
            ).one()
            stored = session.execute(
                text(
                    "SELECT revision_sha256, receipt_sha256, assignment_id, "
                    "evaluator_principal, parent_revision_sha256, correction_reason, "
                    "payload, submitted_at, created_at "
                    "FROM dev_eval.own_label_revisions_v1 "
                    "WHERE revision_sha256 = :revision_sha256"
                ),
                {"revision_sha256": result.revision_sha256},
            ).one()
        return self._stored_from_row(
            stored,
            evaluator_pseudonym=revision.evaluator_pseudonym,
        )

    def select_accepted_head(
        self,
        revision_sha256: Annotated[str, Field(pattern=r"^[0-9a-f]{64}$")],
        *,
        reason: str,
        selected_at: datetime | None = None,
        expected_chain_sha256: Annotated[str, Field(pattern=r"^[0-9a-f]{64}$")],
    ) -> AcceptedHeadReceipt:
        event_at = selected_at or datetime.now(UTC)
        require_utc(event_at, field_name="selected_at")
        try:
            with self._factory() as session:
                session.connection(execution_options={"isolation_level": "SERIALIZABLE"})
                identity = session.execute(
                    text(
                        "SELECT assignment_id, evaluator_pseudonym "
                        "FROM dev_eval.adjudicator_label_revisions_v1 "
                        "WHERE revision_sha256 = :revision_sha256"
                    ),
                    {"revision_sha256": revision_sha256},
                ).one_or_none()
                if identity is None:
                    raise LabelExportBlocked("phase 3 label state is incomplete or stale")
                rows = self._adjudicator_rows(
                    session,
                    assignment_id=identity.assignment_id,
                    evaluator_pseudonym=identity.evaluator_pseudonym,
                )
                chain, _ = self._adjudicator_chain(rows)
                if (
                    chain.tip_revision_sha256 != revision_sha256
                    or chain.chain_sha256 != expected_chain_sha256
                ):
                    raise LabelExportBlocked("phase 3 label state is incomplete or stale")
                row = session.execute(
                    text(
                        "SELECT event_sha256, revision_sha256 "
                        "FROM dev_eval.select_accepted_label_revision_v1("
                        ":revision_sha256, :reason, :selected_at)"
                    ),
                    {
                        "revision_sha256": revision_sha256,
                        "reason": reason,
                        "selected_at": event_at,
                    },
                ).one()
                session.commit()
        except DBAPIError as error:
            if getattr(error.orig, "sqlstate", None) == "40001":
                raise LabelExportBlocked("phase 3 label state is incomplete or stale") from error
            raise
        return AcceptedHeadReceipt(
            event_sha256=row.event_sha256,
            revision_sha256=row.revision_sha256,
        )

    @staticmethod
    def _adjudicator_rows(
        session: Session,
        *,
        assignment_id: str,
        evaluator_pseudonym: str | None = None,
    ) -> tuple[Row[Any], ...]:
        evaluator_clause = (
            " AND evaluator_pseudonym = :evaluator_pseudonym"
            if evaluator_pseudonym is not None
            else ""
        )
        parameters: dict[str, object] = {"assignment_id": assignment_id}
        if evaluator_pseudonym is not None:
            parameters["evaluator_pseudonym"] = evaluator_pseudonym
        return tuple(
            session.execute(
                text(
                    "SELECT assignment_id, evaluator_pseudonym, revision_sha256, "
                    "receipt_sha256, parent_revision_sha256, correction_reason, "
                    "payload, submitted_at, created_at, accepted_event_sha256, "
                    "accepted_revision_sha256, operator_pseudonym, selection_reason, "
                    "selected_at FROM dev_eval.adjudicator_label_revisions_v1 "
                    "WHERE assignment_id = :assignment_id"
                    f"{evaluator_clause} "
                    "ORDER BY evaluator_pseudonym, created_at, revision_sha256"
                ),
                parameters,
            ).all()
        )

    @staticmethod
    def _adjudicator_chain(
        rows: Sequence[Row[Any]],
    ) -> tuple[AdjudicatorRevisionChain, tuple[RawLabelRevision, ...]]:
        if not rows:
            raise LabelExportBlocked("phase 3 label state is incomplete or stale")
        mappings = tuple(row._mapping for row in rows)
        evaluator_pseudonyms = {str(mapping["evaluator_pseudonym"]) for mapping in mappings}
        if len(evaluator_pseudonyms) != 1:
            raise LabelExportBlocked("phase 3 label state is incomplete or stale")
        by_revision = {str(mapping["revision_sha256"]): mapping for mapping in mappings}
        if len(by_revision) != len(mappings):
            raise LabelExportBlocked("phase 3 label state is incomplete or stale")
        children: dict[str, list[str]] = defaultdict(list)
        roots: list[str] = []
        for revision_sha256, mapping in by_revision.items():
            parent = mapping["parent_revision_sha256"]
            if parent is None:
                roots.append(revision_sha256)
            elif str(parent) not in by_revision:
                raise LabelExportBlocked("phase 3 label state is incomplete or stale")
            else:
                children[str(parent)].append(revision_sha256)
        if len(roots) != 1 or any(len(successors) != 1 for successors in children.values()):
            raise LabelExportBlocked("phase 3 label state is incomplete or stale")
        ordered_ids: list[str] = []
        current = roots[0]
        while True:
            ordered_ids.append(current)
            successors = children.get(current, [])
            if not successors:
                break
            current = successors[0]
        if len(ordered_ids) != len(by_revision):
            raise LabelExportBlocked("phase 3 label state is incomplete or stale")

        pseudonym = next(iter(evaluator_pseudonyms))
        raw_revisions: list[RawLabelRevision] = []
        projected_revisions: list[AdjudicatorRawRevision] = []
        for revision_sha256 in ordered_ids:
            mapping = by_revision[revision_sha256]
            payload = dict(mapping["payload"])
            payload["evaluator_pseudonym"] = pseudonym
            raw = RawLabelRevision.model_validate(payload)
            raw_revisions.append(raw)
            projected_revisions.append(
                AdjudicatorRawRevision(
                    revision_sha256=revision_sha256,
                    receipt_sha256=mapping["receipt_sha256"],
                    parent_revision_sha256=mapping["parent_revision_sha256"],
                    correction_reason=mapping["correction_reason"],
                    primary_axis=raw.primary_axis,
                    judgments=raw.judgments,
                    submitted_at=raw.submitted_at,
                    created_at=mapping["created_at"],
                )
            )

        accepted_values = {
            (
                mapping["accepted_event_sha256"],
                mapping["accepted_revision_sha256"],
                mapping["operator_pseudonym"],
                mapping["selection_reason"],
                mapping["selected_at"],
            )
            for mapping in mappings
        }
        if len(accepted_values) != 1:
            raise LabelExportBlocked("phase 3 label state is incomplete or stale")
        accepted_event, accepted_revision, operator, selection_reason, selected_at = next(
            iter(accepted_values)
        )
        accepted_head: AdjudicatorAcceptedHead | None = None
        if accepted_event is not None:
            if (
                accepted_revision != ordered_ids[-1]
                or operator is None
                or selection_reason is None
                or selected_at is None
            ):
                raise LabelExportBlocked("phase 3 label state is incomplete or stale")
            accepted_head = AdjudicatorAcceptedHead(
                event_sha256=accepted_event,
                selection=AcceptedRevisionSelection(
                    assignment_id=mappings[0]["assignment_id"],
                    evaluator_pseudonym=pseudonym,
                    accepted_revision_sha256=accepted_revision,
                    operator_pseudonym=operator,
                    selected_at=selected_at,
                ),
                reason=selection_reason,
            )
        chain = AdjudicatorRevisionChain(
            evaluator_pseudonym=pseudonym,
            revisions=tuple(projected_revisions),
            tip_revision_sha256=ordered_ids[-1],
            accepted_head=accepted_head,
        )
        return chain, tuple(raw_revisions)

    @staticmethod
    def _validate_official_source_evidence(
        revisions: Sequence[RawLabelRevision],
        official_source: AdjudicationSourceManifest,
    ) -> None:
        evidence_lookup = {
            evidence_id: source
            for source in official_source.sources
            for evidence_id in source.evidence_ids
        }
        for revision in revisions:
            for judgment in revision.judgments:
                for evidence in judgment.evidence:
                    source = evidence_lookup.get(evidence.evidence_id)
                    if (
                        source is None
                        or source.source_id != evidence.source_id
                        or source.lane.value != evidence.lane.value
                    ):
                        raise LabelExportBlocked("official source evidence is incomplete or stale")

    def get_adjudicator_projection(
        self,
        assignment_id: str,
        official_source: AdjudicationSourceManifest,
    ) -> AdjudicationProjection:
        if official_source.assignment_id != assignment_id:
            raise LabelExportBlocked("official source assignment is incomplete or stale")
        with self._factory() as session:
            rows = self._adjudicator_rows(session, assignment_id=assignment_id)
        if not rows:
            raise LabelExportBlocked("phase 3 label state is incomplete or stale")
        grouped: dict[str, list[Row[Any]]] = defaultdict(list)
        for row in rows:
            grouped[str(row._mapping["evaluator_pseudonym"])].append(row)
        chains: list[AdjudicatorRevisionChain] = []
        raw_by_pseudonym: dict[str, tuple[RawLabelRevision, ...]] = {}
        for pseudonym in sorted(grouped):
            chain, raw_revisions = self._adjudicator_chain(grouped[pseudonym])
            chains.append(chain)
            raw_by_pseudonym[pseudonym] = raw_revisions
        all_raw = tuple(
            revision
            for pseudonym in sorted(raw_by_pseudonym)
            for revision in raw_by_pseudonym[pseudonym]
        )
        assignment_ids = {revision.assignment_id for revision in all_raw}
        rubric_versions = {revision.rubric_version for revision in all_raw}
        source_versions = {revision.source_snapshot_version for revision in all_raw}
        if (
            assignment_ids != {assignment_id}
            or len(rubric_versions) != 1
            or source_versions != {official_source.source_snapshot_version}
        ):
            raise LabelExportBlocked("phase 3 label state is incomplete or stale")
        self._validate_official_source_evidence(all_raw, official_source)

        complete = len(chains) == 3 and all(chain.accepted_head is not None for chain in chains)
        accepted_set: str | None = None
        review_triggers: tuple[ReviewTrigger, ...] = ()
        if complete:
            selections = tuple(
                cast(AdjudicatorAcceptedHead, chain.accepted_head).selection for chain in chains
            )
            accepted_set = canonical_sha256(
                [selection.model_dump(mode="json") for selection in selections]
            )
            accepted_revisions = tuple(
                raw_by_pseudonym[chain.evaluator_pseudonym][-1] for chain in chains
            )
            review_triggers = derive_review_triggers(accepted_revisions)
        return AdjudicationProjection(
            assignment_id=assignment_id,
            rubric_version=next(iter(rubric_versions)),
            source_snapshot_version=official_source.source_snapshot_version,
            official_sources=official_source.sources,
            official_source_sha256=cast(str, official_source.official_source_sha256),
            chains=tuple(chains),
            accepted_revision_set_sha256=accepted_set,
            review_triggers=review_triggers,
            release_blocked=not complete,
        )

    def get_own_revision(
        self,
        revision_sha256: str,
        *,
        evaluator_pseudonym: str,
    ) -> StoredLabelRevision | None:
        with self._factory() as session:
            row = session.execute(
                text(
                    "SELECT revision_sha256, receipt_sha256, assignment_id, "
                    "evaluator_principal, parent_revision_sha256, correction_reason, "
                    "payload, submitted_at, created_at "
                    "FROM dev_eval.own_label_revisions_v1 "
                    "WHERE revision_sha256 = :revision_sha256"
                ),
                {"revision_sha256": revision_sha256},
            ).one_or_none()
        if row is None:
            return None
        return self._stored_from_row(row, evaluator_pseudonym=evaluator_pseudonym)

    def get_own_chain(self, *, evaluator_pseudonym: str) -> tuple[StoredLabelRevision, ...]:
        with self._factory() as session:
            rows = session.execute(
                text(
                    "SELECT revision_sha256, receipt_sha256, assignment_id, "
                    "evaluator_principal, parent_revision_sha256, correction_reason, "
                    "payload, submitted_at, created_at "
                    "FROM dev_eval.own_label_revisions_v1 "
                    "ORDER BY created_at, revision_sha256"
                )
            ).all()
        return tuple(
            self._stored_from_row(row, evaluator_pseudonym=evaluator_pseudonym) for row in rows
        )

    def get_submission_status(self) -> tuple[LabelSubmissionStatus, ...]:
        with self._factory() as session:
            rows = session.execute(
                text(
                    "SELECT evaluator_pseudonym, submission_status, "
                    "latest_server_event_at, all_required_submissions_exist "
                    "FROM dev_eval.label_submission_status_v1 "
                    "ORDER BY evaluator_pseudonym"
                )
            ).all()
        return tuple(LabelSubmissionStatus.model_validate(dict(row._mapping)) for row in rows)

    @staticmethod
    def _accepted_heads(
        session: Session,
        *,
        assignment_id: str,
    ) -> tuple[AcceptedLabelHead, ...]:
        rows = session.execute(
            text(
                "SELECT assignment_id, evaluator_pseudonym, revision_sha256, "
                "operator_pseudonym, selected_at, payload "
                "FROM dev_eval.accepted_label_heads_v1 "
                "WHERE assignment_id = :assignment_id "
                "ORDER BY evaluator_pseudonym"
            ),
            {"assignment_id": assignment_id},
        ).all()
        if len(rows) != 3:
            raise LabelExportBlocked("all three evaluator roles must have accepted submissions")
        heads: list[AcceptedLabelHead] = []
        for row in rows:
            mapping = row._mapping
            payload = dict(mapping["payload"])
            payload["evaluator_pseudonym"] = mapping["evaluator_pseudonym"]
            revision = RawLabelRevision.model_validate(payload)
            heads.append(
                AcceptedLabelHead(
                    revision_sha256=mapping["revision_sha256"],
                    revision=revision,
                    selection=AcceptedRevisionSelection(
                        assignment_id=mapping["assignment_id"],
                        evaluator_pseudonym=mapping["evaluator_pseudonym"],
                        accepted_revision_sha256=mapping["revision_sha256"],
                        operator_pseudonym=mapping["operator_pseudonym"],
                        selected_at=mapping["selected_at"],
                    ),
                )
            )
        return tuple(heads)

    def get_accepted_heads(self, assignment_id: str) -> tuple[AcceptedLabelHead, ...]:
        with self._factory() as session:
            return self._accepted_heads(session, assignment_id=assignment_id)

    @staticmethod
    def _accepted_set_sha256(heads: tuple[AcceptedLabelHead, ...]) -> str:
        return canonical_sha256([head.selection.model_dump(mode="json") for head in heads])

    @staticmethod
    def _store_review_triggers(
        session: Session,
        *,
        assignment_id: str,
        accepted_revision_set_sha256: str,
        triggers: tuple[ReviewTrigger, ...],
    ) -> None:
        for trigger in triggers:
            payload = trigger.model_dump(mode="json")
            session.execute(
                text(
                    "INSERT INTO dev_eval.label_review_triggers ("
                    "trigger_sha256, assignment_id, accepted_revision_set_sha256, "
                    "trigger_kind, attribute_id, payload, created_by) "
                    "VALUES (:trigger_sha256, :assignment_id, :accepted_set, :kind, "
                    ":attribute_id, CAST(:payload AS jsonb), session_user) "
                    "ON CONFLICT ON CONSTRAINT pk_phase3_review_triggers DO NOTHING"
                ),
                {
                    "trigger_sha256": trigger.review_trigger_sha256,
                    "assignment_id": assignment_id,
                    "accepted_set": accepted_revision_set_sha256,
                    "kind": trigger.kind.value,
                    "attribute_id": trigger.attribute_id.value if trigger.attribute_id else None,
                    "payload": json.dumps(payload, ensure_ascii=False, sort_keys=True),
                },
            )

    def derive_and_store_review_triggers(
        self,
        assignment_id: str,
    ) -> tuple[ReviewTrigger, ...]:
        with self._factory.begin() as session:
            heads = self._accepted_heads(session, assignment_id=assignment_id)
            triggers = derive_review_triggers(tuple(head.revision for head in heads))
            self._store_review_triggers(
                session,
                assignment_id=assignment_id,
                accepted_revision_set_sha256=self._accepted_set_sha256(heads),
                triggers=triggers,
            )
        return triggers

    def resolve_review_trigger(
        self,
        assignment_id: str,
        resolution: ReviewTriggerResolution,
    ) -> ReviewTriggerResolution:
        with self._factory.begin() as session:
            heads = self._accepted_heads(session, assignment_id=assignment_id)
            accepted_set = self._accepted_set_sha256(heads)
            stored = session.execute(
                text(
                    "SELECT payload FROM dev_eval.label_review_triggers "
                    "WHERE accepted_revision_set_sha256 = :accepted_set "
                    "AND trigger_sha256 = :trigger_sha256"
                ),
                {
                    "accepted_set": accepted_set,
                    "trigger_sha256": resolution.review_trigger_sha256,
                },
            ).one_or_none()
            if stored is None:
                raise LabelExportBlocked("review trigger is absent from the current accepted set")
            session.execute(
                text(
                    "INSERT INTO dev_eval.label_trigger_resolutions ("
                    "resolution_sha256, accepted_revision_set_sha256, trigger_sha256, "
                    "payload, adjudicated_by) VALUES ("
                    ":resolution_sha256, :accepted_set, :trigger_sha256, "
                    "CAST(:payload AS jsonb), session_user) "
                    "ON CONFLICT ON CONSTRAINT uq_phase3_trigger_resolution DO NOTHING"
                ),
                {
                    "resolution_sha256": resolution.resolution_sha256,
                    "accepted_set": accepted_set,
                    "trigger_sha256": resolution.review_trigger_sha256,
                    "payload": resolution.model_dump_json(),
                },
            )
            existing = session.execute(
                text(
                    "SELECT payload FROM dev_eval.label_trigger_resolutions "
                    "WHERE accepted_revision_set_sha256 = :accepted_set "
                    "AND trigger_sha256 = :trigger_sha256"
                ),
                {
                    "accepted_set": accepted_set,
                    "trigger_sha256": resolution.review_trigger_sha256,
                },
            ).scalar_one()
            if ReviewTriggerResolution.model_validate(existing) != resolution:
                raise LabelExportBlocked("review trigger already has a different resolution")
        return resolution

    def aggregate_and_store(
        self,
        assignment_id: str,
        *,
        adjudications: tuple[AdjudicatedAttributeValue, ...] = (),
    ) -> AdjudicatedLabelExport:
        with self._factory.begin() as session:
            session.execute(text("SET TRANSACTION ISOLATION LEVEL SERIALIZABLE"))
            heads = self._accepted_heads(session, assignment_id=assignment_id)
            accepted_set = self._accepted_set_sha256(heads)
            revisions = tuple(head.revision for head in heads)
            triggers = derive_review_triggers(revisions)
            self._store_review_triggers(
                session,
                assignment_id=assignment_id,
                accepted_revision_set_sha256=accepted_set,
                triggers=triggers,
            )
            resolved = tuple(
                row.trigger_sha256
                for row in session.execute(
                    text(
                        "SELECT trigger_sha256 FROM dev_eval.label_trigger_resolutions "
                        "WHERE accepted_revision_set_sha256 = :accepted_set "
                        "ORDER BY trigger_sha256"
                    ),
                    {"accepted_set": accepted_set},
                ).all()
            )
            required = {cast(str, trigger.review_trigger_sha256) for trigger in triggers}
            if set(resolved) != required:
                raise LabelExportBlocked("all review triggers must be resolved before export")
            persisted_digests = {
                head.revision.evaluator_pseudonym: head.revision_sha256 for head in heads
            }
            export = aggregate_accepted_revisions(
                revisions,
                tuple(head.selection for head in heads),
                adjudications=adjudications,
                resolved_review_trigger_sha256s=resolved,
                persisted_revision_sha256s=persisted_digests,
            )
            for aggregate in export.aggregates:
                session.execute(
                    text(
                        "INSERT INTO dev_eval.label_aggregates ("
                        "aggregate_sha256, assignment_id, accepted_revision_set_sha256, "
                        "payload, created_by) VALUES ("
                        ":aggregate_sha256, :assignment_id, :accepted_set, "
                        "CAST(:payload AS jsonb), session_user) "
                        "ON CONFLICT ON CONSTRAINT pk_phase3_label_aggregates DO NOTHING"
                    ),
                    {
                        "aggregate_sha256": aggregate.aggregate_sha256,
                        "assignment_id": assignment_id,
                        "accepted_set": accepted_set,
                        "payload": aggregate.model_dump_json(),
                    },
                )
            session.execute(
                text(
                    "INSERT INTO dev_eval.adjudicated_label_exports ("
                    "export_sha256, created_at, assignment_id, "
                    "accepted_revision_set_sha256, payload, created_by) VALUES ("
                    ":export_sha256, CURRENT_TIMESTAMP, :assignment_id, :accepted_set, "
                    "CAST(:payload AS jsonb), session_user) "
                    "ON CONFLICT ON CONSTRAINT pk_phase3_adjudicated_exports DO NOTHING"
                ),
                {
                    "export_sha256": export.export_sha256,
                    "assignment_id": assignment_id,
                    "accepted_set": accepted_set,
                    "payload": export.model_dump_json(),
                },
            )
            existing = session.execute(
                text(
                    "SELECT payload FROM dev_eval.adjudicated_label_exports "
                    "WHERE export_sha256 = :export_sha256"
                ),
                {"export_sha256": export.export_sha256},
            ).scalar_one()
            if AdjudicatedLabelExport.model_validate(existing) != export:
                raise LabelExportBlocked("export digest collision has different canonical bytes")
        return export

    def get_label_export(self, export_sha256: str) -> AdjudicatedLabelExport | None:
        with self._factory() as session:
            payload = session.execute(
                text(
                    "SELECT payload FROM dev_eval.label_freeze_exports_v1 "
                    "WHERE export_sha256 = :export_sha256"
                ),
                {"export_sha256": export_sha256},
            ).scalar_one_or_none()
        if payload is None:
            return None
        return AdjudicatedLabelExport.model_validate(payload)

    @staticmethod
    def _candidate_queue(manifest: Mapping[str, Any]) -> EvidenceReviewQueue:
        validate_candidate_manifest(manifest)
        manifest_payload = dict(manifest)
        manifest_sha256 = canonical_sha256(manifest_payload)
        raw_provenance = dict(cast(Mapping[str, Any], manifest_payload["provenance"]))
        raw_provenance["candidate_output_sha256"] = raw_provenance.pop("output_sha256")
        provenance = EvidenceReviewProvenance.model_validate(raw_provenance)
        raw_lanes = cast(Mapping[str, Any], manifest_payload["lanes"])
        lanes: list[EvidenceCandidateLane] = []
        for lane in (TextEvidenceLane.DESCRIPTION, TextEvidenceLane.ODII):
            raw_lane = cast(Mapping[str, Any], raw_lanes[lane.value])
            candidates: list[EvidenceCandidate] = []
            for raw_candidate in cast(list[Mapping[str, Any]], raw_lane["candidates"]):
                candidate = dict(raw_candidate)
                candidate["candidate_sha256"] = canonical_sha256(candidate)
                candidates.append(EvidenceCandidate.model_validate(candidate))
            lanes.append(
                EvidenceCandidateLane(
                    lane=lane,
                    status=LaneEvidenceStatus(str(raw_lane["status"])),
                    candidates=tuple(candidates),
                )
            )
        return EvidenceReviewQueue(
            candidate_manifest_sha256=manifest_sha256,
            provenance=provenance,
            lanes=cast(tuple[EvidenceCandidateLane, EvidenceCandidateLane], tuple(lanes)),
        )

    def register_candidate_manifest(self, manifest: Mapping[str, Any]) -> EvidenceReviewQueue:
        """Copy a verified server-held candidate manifest into immutable DB references."""

        queue = self._candidate_queue(manifest)
        manifest_json = json.dumps(
            manifest, ensure_ascii=False, sort_keys=True, separators=(",", ":")
        )
        with self._factory.begin() as session:
            session.execute(
                text(
                    "INSERT INTO dev_eval.evidence_candidate_manifests ("
                    "candidate_manifest_sha256, payload, registered_by) VALUES ("
                    ":manifest_sha256, CAST(:payload AS jsonb), session_user) "
                    "ON CONFLICT ON CONSTRAINT pk_phase3_candidate_manifests DO NOTHING"
                ),
                {
                    "manifest_sha256": queue.candidate_manifest_sha256,
                    "payload": manifest_json,
                },
            )
            stored_manifest = session.execute(
                text(
                    "SELECT payload FROM dev_eval.evidence_candidate_manifests "
                    "WHERE candidate_manifest_sha256 = :manifest_sha256"
                ),
                {"manifest_sha256": queue.candidate_manifest_sha256},
            ).scalar_one()
            if canonical_sha256(stored_manifest) != queue.candidate_manifest_sha256:
                raise LabelExportBlocked("candidate manifest digest collision")
            for lane in queue.lanes:
                for candidate in lane.candidates:
                    session.execute(
                        text(
                            "INSERT INTO dev_eval.evidence_candidate_references ("
                            "candidate_manifest_sha256, candidate_id, candidate_sha256, "
                            "lane, source_id, payload) VALUES ("
                            ":manifest_sha256, :candidate_id, :candidate_sha256, :lane, "
                            ":source_id, CAST(:payload AS jsonb)) "
                            "ON CONFLICT ON CONSTRAINT "
                            "pk_phase3_evidence_candidate_references DO NOTHING"
                        ),
                        {
                            "manifest_sha256": queue.candidate_manifest_sha256,
                            "candidate_id": candidate.candidate_id,
                            "candidate_sha256": candidate.candidate_sha256,
                            "lane": candidate.lane.value,
                            "source_id": candidate.source_id,
                            "payload": candidate.model_dump_json(),
                        },
                    )
                    stored = session.execute(
                        text(
                            "SELECT payload FROM dev_eval.evidence_candidate_references "
                            "WHERE candidate_manifest_sha256 = :manifest_sha256 "
                            "AND candidate_id = :candidate_id"
                        ),
                        {
                            "manifest_sha256": queue.candidate_manifest_sha256,
                            "candidate_id": candidate.candidate_id,
                        },
                    ).scalar_one()
                    if EvidenceCandidate.model_validate(stored) != candidate:
                        raise LabelExportBlocked("candidate reference collision")
        return queue

    @staticmethod
    def _review_from_row(row: Row[Any]) -> EvidenceReviewReceipt:
        mapping = row._mapping
        return EvidenceReviewReceipt(
            receipt_sha256=mapping["receipt_sha256"],
            revision=EvidenceReviewRevision.model_validate(mapping["payload"]),
            created_at=mapping["created_at"],
        )

    def append_evidence_review(self, revision: EvidenceReviewRevision) -> EvidenceReviewReceipt:
        if revision.parent_review_sha256 is not None:
            raise ValueError("initial evidence review cannot name a correction parent")
        return self._append_evidence_review(revision)

    def append_evidence_review_correction(
        self, revision: EvidenceReviewRevision
    ) -> EvidenceReviewReceipt:
        if revision.parent_review_sha256 is None or revision.correction_reason is None:
            raise ValueError("evidence review correction requires a parent and reason")
        return self._append_evidence_review(revision)

    def _append_evidence_review(self, revision: EvidenceReviewRevision) -> EvidenceReviewReceipt:
        review_sha256 = cast(str, revision.review_sha256)
        receipt_sha256 = canonical_sha256(
            {
                "schema_version": "phase3-evidence-review-receipt-v1",
                "review_sha256": review_sha256,
                "candidate_manifest_sha256": revision.candidate_manifest_sha256,
                "candidate_sha256": revision.candidate_sha256,
                "reviewer_pseudonym": revision.reviewer_pseudonym,
            }
        )
        with self._factory.begin() as session:
            candidate = session.execute(
                text(
                    "SELECT payload FROM dev_eval.evidence_candidate_references "
                    "WHERE candidate_manifest_sha256 = :manifest_sha256 "
                    "AND candidate_id = :candidate_id AND candidate_sha256 = :candidate_sha256 "
                    "AND lane = :lane"
                ),
                {
                    "manifest_sha256": revision.candidate_manifest_sha256,
                    "candidate_id": revision.candidate_id,
                    "candidate_sha256": revision.candidate_sha256,
                    "lane": revision.lane.value,
                },
            ).one_or_none()
            if candidate is None:
                raise LabelExportBlocked("evidence candidate is incomplete or stale")
            if revision.parent_review_sha256 is not None:
                parent = session.execute(
                    text(
                        "SELECT review_sha256 FROM dev_eval.evidence_review_revisions "
                        "WHERE review_sha256 = :parent AND candidate_manifest_sha256 = :manifest "
                        "AND candidate_id = :candidate_id AND reviewed_by = session_user "
                        "AND NOT EXISTS (SELECT 1 FROM "
                        "dev_eval.evidence_review_revisions successor "
                        "WHERE successor.parent_review_sha256 = :parent)"
                    ),
                    {
                        "parent": revision.parent_review_sha256,
                        "manifest": revision.candidate_manifest_sha256,
                        "candidate_id": revision.candidate_id,
                    },
                ).one_or_none()
                if parent is None:
                    raise LabelExportBlocked("evidence review parent is incomplete or stale")
            session.execute(
                text(
                    "INSERT INTO dev_eval.evidence_review_revisions ("
                    "review_sha256, receipt_sha256, candidate_manifest_sha256, candidate_id, "
                    "candidate_sha256, lane, parent_review_sha256, correction_reason, "
                    "decision, payload, reviewed_by, reviewed_at) VALUES ("
                    ":review_sha256, :receipt_sha256, :manifest_sha256, :candidate_id, "
                    ":candidate_sha256, :lane, :parent_review_sha256, :correction_reason, "
                    ":decision, CAST(:payload AS jsonb), session_user, :reviewed_at) "
                    "ON CONFLICT ON CONSTRAINT pk_phase3_evidence_reviews DO NOTHING"
                ),
                {
                    "review_sha256": review_sha256,
                    "receipt_sha256": receipt_sha256,
                    "manifest_sha256": revision.candidate_manifest_sha256,
                    "candidate_id": revision.candidate_id,
                    "candidate_sha256": revision.candidate_sha256,
                    "lane": revision.lane.value,
                    "parent_review_sha256": revision.parent_review_sha256,
                    "correction_reason": revision.correction_reason,
                    "decision": revision.decision.value,
                    "payload": revision.model_dump_json(),
                    "reviewed_at": revision.reviewed_at,
                },
            )
            row = session.execute(
                text(
                    "SELECT receipt_sha256, payload, created_at "
                    "FROM dev_eval.evidence_review_revisions "
                    "WHERE review_sha256 = :review_sha256 AND reviewed_by = session_user"
                ),
                {"review_sha256": review_sha256},
            ).one_or_none()
            if row is None:
                raise LabelExportBlocked("evidence review append was not observable")
            receipt = self._review_from_row(row)
            if receipt.receipt_sha256 != receipt_sha256 or receipt.revision != revision:
                raise LabelExportBlocked("evidence review digest collision")
        return receipt

    @staticmethod
    def _review_chain_from_rows(rows: Sequence[Row[Any]]) -> EvidenceReviewChain:
        if not rows:
            raise LabelExportBlocked("evidence review chain is incomplete or stale")
        mappings = tuple(row._mapping for row in rows)
        revisions = tuple(
            EvidenceReviewRevision.model_validate(mapping["payload"]) for mapping in mappings
        )
        by_sha = {cast(str, revision.review_sha256): revision for revision in revisions}
        if len(by_sha) != len(revisions):
            raise LabelExportBlocked("evidence review chain is incomplete or stale")
        children: dict[str, list[str]] = defaultdict(list)
        roots: list[str] = []
        for review_sha256, revision in by_sha.items():
            if revision.parent_review_sha256 is None:
                roots.append(review_sha256)
            elif revision.parent_review_sha256 not in by_sha:
                raise LabelExportBlocked("evidence review chain is incomplete or stale")
            else:
                children[revision.parent_review_sha256].append(review_sha256)
        if len(roots) != 1 or any(len(successors) != 1 for successors in children.values()):
            raise LabelExportBlocked("evidence review chain is incomplete or stale")
        ordered: list[EvidenceReviewRevision] = []
        current = roots[0]
        while True:
            ordered.append(by_sha[current])
            successors = children.get(current, [])
            if not successors:
                break
            current = successors[0]
        if len(ordered) != len(revisions):
            raise LabelExportBlocked("evidence review chain is incomplete or stale")
        first = ordered[0]
        accepted_payloads = {
            json.dumps(mapping["accepted_payload"], sort_keys=True, default=str)
            if mapping["accepted_payload"] is not None
            else None
            for mapping in mappings
        }
        if len(accepted_payloads) != 1:
            raise LabelExportBlocked("evidence review accepted head is inconsistent")
        accepted_payload = mappings[0]["accepted_payload"]
        return EvidenceReviewChain(
            candidate_manifest_sha256=first.candidate_manifest_sha256,
            candidate_id=first.candidate_id,
            candidate_sha256=first.candidate_sha256,
            lane=first.lane,
            revisions=tuple(ordered),
            tip_review_sha256=cast(str, ordered[-1].review_sha256),
            chain_sha256=canonical_sha256(
                [cast(str, revision.review_sha256) for revision in ordered]
            ),
            accepted_head=(
                AcceptedEvidenceReviewHead.model_validate(accepted_payload)
                if accepted_payload is not None
                else None
            ),
        )

    @staticmethod
    def _review_chain_rows(
        session: Session, *, candidate_manifest_sha256: str, candidate_id: str
    ) -> tuple[Row[Any], ...]:
        return tuple(
            session.execute(
                text(
                    "SELECT reviews.payload, accepted.payload AS accepted_payload "
                    "FROM dev_eval.evidence_review_revisions reviews "
                    "LEFT JOIN LATERAL (SELECT payload FROM "
                    "dev_eval.accepted_evidence_review_heads heads "
                    "WHERE heads.candidate_manifest_sha256 = reviews.candidate_manifest_sha256 "
                    "AND heads.candidate_id = reviews.candidate_id "
                    "ORDER BY heads.selected_at DESC, heads.event_sha256 DESC LIMIT 1) accepted "
                    "ON true WHERE reviews.candidate_manifest_sha256 = :manifest_sha256 "
                    "AND reviews.candidate_id = :candidate_id "
                    "AND reviews.reviewed_by = session_user "
                    "ORDER BY reviews.created_at, reviews.review_sha256"
                ),
                {
                    "manifest_sha256": candidate_manifest_sha256,
                    "candidate_id": candidate_id,
                },
            ).all()
        )

    def get_evidence_review_chain(
        self, *, candidate_manifest_sha256: str, candidate_id: str
    ) -> EvidenceReviewChain:
        with self._factory() as session:
            rows = self._review_chain_rows(
                session,
                candidate_manifest_sha256=candidate_manifest_sha256,
                candidate_id=candidate_id,
            )
        return self._review_chain_from_rows(rows)

    def select_evidence_review_head(
        self,
        review_sha256: str,
        *,
        expected_chain_sha256: str,
        selected_by: str,
        selection_reason: str,
        selected_at: datetime,
    ) -> AcceptedEvidenceReviewHead:
        require_utc(selected_at, field_name="selected_at")
        with self._factory() as session:
            session.connection(execution_options={"isolation_level": "SERIALIZABLE"})
            identity = session.execute(
                text(
                    "SELECT candidate_manifest_sha256, candidate_id FROM "
                    "dev_eval.evidence_review_revisions WHERE review_sha256 = :review_sha256 "
                    "AND reviewed_by = session_user"
                ),
                {"review_sha256": review_sha256},
            ).one_or_none()
            if identity is None:
                raise LabelExportBlocked("evidence review state is incomplete or stale")
            chain = self._review_chain_from_rows(
                self._review_chain_rows(
                    session,
                    candidate_manifest_sha256=identity.candidate_manifest_sha256,
                    candidate_id=identity.candidate_id,
                )
            )
            if (
                chain.tip_review_sha256 != review_sha256
                or chain.chain_sha256 != expected_chain_sha256
            ):
                raise LabelExportBlocked("evidence review state is incomplete or stale")
            revision = chain.revisions[-1]
            head = AcceptedEvidenceReviewHead(
                candidate_manifest_sha256=revision.candidate_manifest_sha256,
                candidate_id=revision.candidate_id,
                candidate_sha256=revision.candidate_sha256,
                lane=revision.lane,
                accepted_review_sha256=review_sha256,
                expected_chain_sha256=expected_chain_sha256,
                selected_by=selected_by,
                selection_reason=selection_reason,
                selected_at=selected_at,
                provenance=revision.provenance,
            )
            session.execute(
                text(
                    "INSERT INTO dev_eval.accepted_evidence_review_heads ("
                    "event_sha256, candidate_manifest_sha256, candidate_id, candidate_sha256, "
                    "lane, review_sha256, expected_chain_sha256, payload, "
                    "selected_by, selected_at) "
                    "VALUES (:event_sha256, :manifest_sha256, :candidate_id, "
                    ":candidate_sha256, :lane, :review_sha256, :chain_sha256, "
                    "CAST(:payload AS jsonb), session_user, :selected_at) "
                    "ON CONFLICT ON CONSTRAINT pk_phase3_accepted_evidence_heads DO NOTHING"
                ),
                {
                    "event_sha256": head.event_sha256,
                    "manifest_sha256": head.candidate_manifest_sha256,
                    "candidate_id": head.candidate_id,
                    "candidate_sha256": head.candidate_sha256,
                    "lane": head.lane.value,
                    "review_sha256": head.accepted_review_sha256,
                    "chain_sha256": head.expected_chain_sha256,
                    "payload": head.model_dump_json(),
                    "selected_at": head.selected_at,
                },
            )
            session.commit()
        return head

    def finalize_reviewed_evidence_manifest(
        self,
        candidate_manifest_sha256: str,
        *,
        finalized_by: str,
        finalized_at: datetime,
    ) -> ReviewedEvidenceManifest:
        require_utc(finalized_at, field_name="finalized_at")
        with self._factory.begin() as session:
            session.execute(text("SET TRANSACTION ISOLATION LEVEL SERIALIZABLE"))
            raw_manifest = session.execute(
                text(
                    "SELECT payload FROM dev_eval.evidence_candidate_manifests "
                    "WHERE candidate_manifest_sha256 = :manifest_sha256"
                ),
                {"manifest_sha256": candidate_manifest_sha256},
            ).scalar_one_or_none()
            if raw_manifest is None:
                raise LabelExportBlocked("candidate manifest is incomplete or stale")
            queue = self._candidate_queue(cast(Mapping[str, Any], raw_manifest))
            if queue.candidate_manifest_sha256 != candidate_manifest_sha256:
                raise LabelExportBlocked("candidate manifest is incomplete or stale")

            accepted_items: dict[
                TextEvidenceLane,
                list[tuple[EvidenceCandidate, AcceptedEvidenceReviewHead]],
            ] = defaultdict(list)
            all_event_sha256s: list[str] = []
            for lane in queue.lanes:
                if lane.status is LaneEvidenceStatus.MISSING:
                    continue
                for candidate in lane.candidates:
                    chain = self._review_chain_from_rows(
                        self._review_chain_rows(
                            session,
                            candidate_manifest_sha256=candidate_manifest_sha256,
                            candidate_id=candidate.candidate_id,
                        )
                    )
                    if chain.accepted_head is None:
                        raise LabelExportBlocked("all candidate reviews require accepted heads")
                    if chain.accepted_head.accepted_review_sha256 != chain.tip_review_sha256:
                        raise LabelExportBlocked("accepted evidence review head is stale")
                    all_event_sha256s.append(cast(str, chain.accepted_head.event_sha256))
                    if chain.revisions[-1].decision is EvidenceRelevanceDecision.ACCEPT:
                        accepted_items[lane.lane].append((candidate, chain.accepted_head))

            reviewed_lanes: list[ReviewedEvidenceLane] = []
            for lane in queue.lanes:
                if lane.status is LaneEvidenceStatus.MISSING:
                    reviewed_lanes.append(
                        ReviewedEvidenceLane(
                            lane=lane.lane,
                            status=LaneEvidenceStatus.MISSING,
                            evidence=(),
                            missing_reason="UPSTREAM_CANDIDATE_LANE_MISSING",
                        )
                    )
                    continue
                accepted = accepted_items[lane.lane]
                if not accepted:
                    raise LabelExportBlocked("available lane lacks accepted evidence")
                diverse: list[tuple[EvidenceCandidate, AcceptedEvidenceReviewHead]] = []
                seen_sources: set[str] = set()
                for item in accepted:
                    if item[0].source_id not in seen_sources:
                        diverse.append(item)
                        seen_sources.add(item[0].source_id)
                    if len(diverse) == 3:
                        break
                if len(diverse) < 3:
                    for item in accepted:
                        if item in diverse:
                            continue
                        diverse.append(item)
                        if len(diverse) == 3:
                            break
                reviewed_lanes.append(
                    ReviewedEvidenceLane(
                        lane=lane.lane,
                        status=LaneEvidenceStatus.AVAILABLE,
                        evidence=tuple(
                            ReviewedEvidenceItem(
                                candidate=candidate,
                                accepted_review_sha256=head.accepted_review_sha256,
                                accepted_head_sha256=cast(str, head.event_sha256),
                            )
                            for candidate, head in diverse
                        ),
                    )
                )
            accepted_set_sha256 = canonical_sha256(sorted(all_event_sha256s))
            manifest = ReviewedEvidenceManifest(
                candidate_manifest_sha256=candidate_manifest_sha256,
                accepted_review_set_sha256=accepted_set_sha256,
                provenance=queue.provenance,
                lanes=cast(
                    tuple[ReviewedEvidenceLane, ReviewedEvidenceLane],
                    tuple(reviewed_lanes),
                ),
                finalized_by=finalized_by,
                finalized_at=finalized_at,
            )
            session.execute(
                text(
                    "INSERT INTO dev_eval.reviewed_evidence_manifests ("
                    "manifest_sha256, candidate_manifest_sha256, accepted_review_set_sha256, "
                    "payload, created_by, created_at) VALUES ("
                    ":manifest_sha256, :candidate_manifest_sha256, :accepted_set, "
                    "CAST(:payload AS jsonb), session_user, :created_at) "
                    "ON CONFLICT ON CONSTRAINT pk_phase3_reviewed_manifests DO NOTHING"
                ),
                {
                    "manifest_sha256": manifest.manifest_sha256,
                    "candidate_manifest_sha256": candidate_manifest_sha256,
                    "accepted_set": accepted_set_sha256,
                    "payload": manifest.model_dump_json(),
                    "created_at": finalized_at,
                },
            )
            stored = session.execute(
                text(
                    "SELECT payload FROM dev_eval.reviewed_evidence_manifests "
                    "WHERE manifest_sha256 = :manifest_sha256"
                ),
                {"manifest_sha256": manifest.manifest_sha256},
            ).scalar_one()
            if ReviewedEvidenceManifest.model_validate(stored) != manifest:
                raise LabelExportBlocked("reviewed evidence manifest digest collision")
        return manifest

    def get_reviewed_evidence_manifest(
        self, manifest_sha256: str
    ) -> ReviewedEvidenceManifest | None:
        with self._factory() as session:
            payload = session.execute(
                text(
                    "SELECT payload FROM dev_eval.reviewed_evidence_manifests "
                    "WHERE manifest_sha256 = :manifest_sha256"
                ),
                {"manifest_sha256": manifest_sha256},
            ).scalar_one_or_none()
        return ReviewedEvidenceManifest.model_validate(payload) if payload is not None else None

    def create_profile_release_build_draft(
        self,
        candidate: ProfileReleaseCandidate,
        *,
        authenticated_principal: str,
        reconciliation_nonce: str,
        draft_ref: str,
    ) -> ProfileReleaseBuildDraftReference:
        """Persist one exact protected candidate under a client-retained opaque reference."""

        principal = authorize_profile_release_action(
            action="BUILD",
            authenticated_principal=authenticated_principal,
            builder_principal=candidate.builder_principal,
            client_actor_id=None,
        )
        if re.fullmatch(r"[A-Za-z0-9_-]{43}", draft_ref) is None:
            raise ValueError("profile release build draft reference is invalid")
        nonce_sha256 = self._profile_nonce(reconciliation_nonce)
        candidate_sha256 = cast(str, candidate.release_sha256)
        draft_ref_sha256 = hashlib.sha256(draft_ref.encode("ascii")).hexdigest()
        expires_at = datetime.now(UTC) + timedelta(minutes=10)
        try:
            with self._factory() as session:
                session.connection(execution_options={"isolation_level": "SERIALIZABLE"})
                existing = self._validated_profile_release_build_draft(
                    session,
                    draft_ref=draft_ref,
                    draft_ref_sha256=draft_ref_sha256,
                    authenticated_principal=principal,
                    nonce_sha256=nonce_sha256,
                    candidate=candidate,
                )
                if existing is None:
                    session.execute(
                        text(
                            "SELECT dev_eval.reserve_profile_release_build_nonce_v1("
                            ":builder, :nonce, :candidate, :draft_ref)"
                        ),
                        {
                            "builder": principal,
                            "nonce": nonce_sha256,
                            "candidate": candidate_sha256,
                            "draft_ref": draft_ref_sha256,
                        },
                    )
                    session.execute(
                        text(
                            "INSERT INTO dev_eval.profile_release_build_drafts ("
                            "draft_ref_sha256, builder_principal, candidate_payload, "
                            "candidate_sha256, nonce_sha256, expires_at) VALUES ("
                            ":draft_ref, :builder, CAST(:payload AS jsonb), "
                            ":candidate, :nonce, :expires_at)"
                        ),
                        {
                            "draft_ref": draft_ref_sha256,
                            "builder": principal,
                            "payload": candidate.model_dump_json(),
                            "candidate": candidate_sha256,
                            "nonce": nonce_sha256,
                            "expires_at": expires_at,
                        },
                    )
                    existing = ProfileReleaseBuildDraftReference(
                        draft_ref=draft_ref,
                        expires_at=expires_at,
                        nonce_sha256=nonce_sha256,
                    )
                session.commit()
                return existing
        except IntegrityError as error:
            existing = self._reconcile_profile_release_build_draft_creation(
                draft_ref=draft_ref,
                draft_ref_sha256=draft_ref_sha256,
                authenticated_principal=principal,
                nonce_sha256=nonce_sha256,
                candidate=candidate,
            )
            if existing is None:
                raise ProfileReleaseReplayError(
                    "profile release draft nonce is bound to another candidate"
                ) from error
            return existing
        except DBAPIError as error:
            existing = self._reconcile_profile_release_build_draft_creation(
                draft_ref=draft_ref,
                draft_ref_sha256=draft_ref_sha256,
                authenticated_principal=principal,
                nonce_sha256=nonce_sha256,
                candidate=candidate,
            )
            if existing is not None:
                return ProfileReleaseBuildDraftReference(
                    draft_ref=existing.draft_ref,
                    expires_at=existing.expires_at,
                    nonce_sha256=existing.nonce_sha256,
                )
            raise error

    def _validated_profile_release_build_draft(
        self,
        session: Session,
        *,
        draft_ref: str,
        draft_ref_sha256: str,
        authenticated_principal: str,
        nonce_sha256: str,
        candidate: ProfileReleaseCandidate,
    ) -> ProfileReleaseBuildDraftReference | None:
        rows = session.execute(
            text(
                "SELECT draft_ref_sha256, builder_principal, candidate_payload, "
                "candidate_sha256, nonce_sha256, expires_at FROM "
                "dev_eval.profile_release_build_drafts WHERE "
                "builder_principal = :builder AND nonce_sha256 = :nonce"
            ),
            {"builder": authenticated_principal, "nonce": nonce_sha256},
        ).all()
        if not rows:
            outcome = self._build_outcome_from_session(
                session,
                nonce_sha256=nonce_sha256,
                authenticated_principal=authenticated_principal,
            )
            if outcome is not None:
                if outcome.release_sha256 != candidate.release_sha256:
                    raise ProfileReleaseReplayError(
                        "profile release draft nonce is bound to another candidate"
                    )
                reservation = session.execute(
                    text(
                        "SELECT candidate_sha256, draft_ref_sha256 FROM "
                        "dev_eval.profile_release_build_nonce_reservations WHERE "
                        "builder_principal = :builder AND nonce_sha256 = :nonce"
                    ),
                    {
                        "builder": authenticated_principal,
                        "nonce": nonce_sha256,
                    },
                ).one_or_none()
                if (
                    reservation is None
                    or reservation.candidate_sha256 != candidate.release_sha256
                    or (
                        reservation.draft_ref_sha256 is not None
                        and reservation.draft_ref_sha256 != draft_ref_sha256
                    )
                ):
                    raise ProfileReleaseReplayError(
                        "profile release draft nonce reservation is corrupt or conflicting"
                    )
                return ProfileReleaseBuildDraftReference(
                    draft_ref=draft_ref,
                    expires_at=datetime.now(UTC),
                    nonce_sha256=nonce_sha256,
                )
            consumed = session.execute(
                text(
                    "SELECT draft_ref_sha256, builder_principal, nonce_sha256, "
                    "candidate_sha256, receipt_sha256, consumed_at FROM "
                    "dev_eval.profile_release_build_draft_consumptions WHERE "
                    "builder_principal = :builder AND nonce_sha256 = :nonce"
                ),
                {"builder": authenticated_principal, "nonce": nonce_sha256},
            ).all()
            if not consumed:
                return None
            if len(consumed) != 1:
                raise ProfileReleaseReplayError(
                    "profile release consumed draft binding is ambiguous"
                )
            row = consumed[0]
            if (
                row.draft_ref_sha256 != draft_ref_sha256
                or row.builder_principal != authenticated_principal
                or row.nonce_sha256 != nonce_sha256
                or row.candidate_sha256 != candidate.release_sha256
            ):
                raise ProfileReleaseReplayError(
                    "profile release draft nonce is bound to another candidate"
                )
            return ProfileReleaseBuildDraftReference(
                draft_ref=draft_ref,
                expires_at=row.consumed_at,
                nonce_sha256=nonce_sha256,
            )
        if len(rows) != 1:
            raise ProfileReleaseReplayError("profile release build draft is ambiguous")
        row = rows[0]
        if (
            row.draft_ref_sha256 != draft_ref_sha256
            or row.builder_principal != authenticated_principal
            or row.candidate_sha256 != candidate.release_sha256
            or row.nonce_sha256 != nonce_sha256
            or ProfileReleaseCandidate.model_validate(row.candidate_payload) != candidate
        ):
            raise ProfileReleaseReplayError(
                "profile release draft nonce is bound to another candidate"
            )
        return ProfileReleaseBuildDraftReference(
            draft_ref=draft_ref,
            expires_at=row.expires_at,
            nonce_sha256=nonce_sha256,
        )

    def _reconcile_profile_release_build_draft_creation(
        self,
        *,
        draft_ref: str,
        draft_ref_sha256: str,
        authenticated_principal: str,
        nonce_sha256: str,
        candidate: ProfileReleaseCandidate,
    ) -> ProfileReleaseBuildDraftReference | None:
        with self._factory() as session:
            return self._validated_profile_release_build_draft(
                session,
                draft_ref=draft_ref,
                draft_ref_sha256=draft_ref_sha256,
                authenticated_principal=authenticated_principal,
                nonce_sha256=nonce_sha256,
                candidate=candidate,
            )

    def get_profile_release_build_draft_candidate(
        self,
        draft_ref: str,
        *,
        authenticated_principal: str,
        nonce_sha256: str,
    ) -> ProfileReleaseCandidate | None:
        """Read one live principal-bound draft without consuming or mutating it."""

        if re.fullmatch(r"[A-Za-z0-9_-]{43}", draft_ref) is None:
            raise ValueError("profile release build draft reference is invalid")
        if re.fullmatch(r"[0-9a-f]{64}", nonce_sha256) is None:
            raise ValueError("profile release build draft nonce digest is invalid")
        draft_ref_sha256 = hashlib.sha256(draft_ref.encode("ascii")).hexdigest()
        try:
            with self._factory() as session:
                row = session.execute(
                    text(
                        "SELECT builder_principal, candidate_payload, candidate_sha256, "
                        "nonce_sha256 FROM dev_eval.profile_release_build_drafts "
                        "WHERE draft_ref_sha256 = :draft_ref "
                        "AND builder_principal = :builder AND nonce_sha256 = :nonce "
                        "AND expires_at > CURRENT_TIMESTAMP"
                    ),
                    {
                        "draft_ref": draft_ref_sha256,
                        "builder": authenticated_principal,
                        "nonce": nonce_sha256,
                    },
                ).one_or_none()
        except DBAPIError as error:
            raise ProfileReleaseBuildUnavailableError(
                retry_path="/internal/evaluation/profile-releases/build-drafts/build"
            ) from error
        if row is None:
            return None
        candidate = ProfileReleaseCandidate.model_validate(row.candidate_payload)
        authorize_profile_release_action(
            action="BUILD",
            authenticated_principal=authenticated_principal,
            builder_principal=candidate.builder_principal,
            client_actor_id=None,
        )
        if (
            row.builder_principal != authenticated_principal
            or row.candidate_sha256 != candidate.release_sha256
            or row.nonce_sha256 != nonce_sha256
        ):
            raise ValueError("profile release build draft binding is corrupt")
        return candidate

    def build_profile_release_from_draft(
        self,
        draft_ref: str,
        *,
        authenticated_principal: str,
        nonce_sha256: str,
        authority_resolution: ProfileReleaseBuildAuthorityResolution | None = None,
        reconciliation_only: bool = False,
    ) -> ProfileReleaseBuildOutcome:
        """Build only the exact server-side candidate bound to an unexpired opaque ref."""

        if re.fullmatch(r"[A-Za-z0-9_-]{43}", draft_ref) is None:
            raise ValueError("profile release build draft reference is invalid")
        if re.fullmatch(r"[0-9a-f]{64}", nonce_sha256) is None:
            raise ValueError("profile release build draft nonce digest is invalid")
        draft_ref_sha256 = hashlib.sha256(draft_ref.encode("ascii")).hexdigest()
        try:
            with self._factory() as session:
                session.connection(execution_options={"isolation_level": "REPEATABLE READ"})
                row = session.execute(
                    text(
                        "SELECT builder_principal, candidate_payload, candidate_sha256, "
                        "nonce_sha256 "
                        "FROM dev_eval.profile_release_build_drafts "
                        "WHERE draft_ref_sha256 = :draft_ref "
                        "AND builder_principal = :builder AND nonce_sha256 = :nonce "
                        "AND expires_at > CURRENT_TIMESTAMP"
                    ),
                    {
                        "draft_ref": draft_ref_sha256,
                        "builder": authenticated_principal,
                        "nonce": nonce_sha256,
                    },
                ).one_or_none()
                if row is None:
                    outcome = self._build_outcome_from_session(
                        session,
                        nonce_sha256=nonce_sha256,
                        authenticated_principal=authenticated_principal,
                    )
                    if outcome is not None and self._draft_cleanup_is_authoritative(
                        session,
                        draft_ref_sha256=draft_ref_sha256,
                        authenticated_principal=authenticated_principal,
                        outcome=outcome,
                    ):
                        return outcome
                    if outcome is not None and self._direct_build_replay_is_authoritative(
                        session,
                        authenticated_principal=authenticated_principal,
                        outcome=outcome,
                    ):
                        return outcome
                    raise ValueError("profile release build draft is missing or expired")
                candidate = ProfileReleaseCandidate.model_validate(row.candidate_payload)
                if reconciliation_only:
                    raise ProfileReleaseBuildUnavailableError(
                        retry_path="/internal/evaluation/profile-releases/build-drafts/build"
                    )
                if authority_resolution is None:
                    raise TypeError("profile release build requires server authority resolution")
                authoritative_candidate = _resolved_profile_release_candidate(authority_resolution)
                if candidate != authoritative_candidate:
                    raise ValueError("profile release build draft authority drifted")
                principal = authorize_profile_release_action(
                    action="BUILD",
                    authenticated_principal=authenticated_principal,
                    builder_principal=candidate.builder_principal,
                    client_actor_id=None,
                )
                if row.candidate_sha256 != candidate.release_sha256:
                    raise ValueError("profile release build draft candidate digest drifted")
                if row.nonce_sha256 != nonce_sha256:
                    raise ValueError("profile release build draft nonce binding drifted")
        except DBAPIError as error:
            raise ProfileReleaseBuildUnavailableError(
                retry_path="/internal/evaluation/profile-releases/build-drafts/build"
            ) from error
        return self._build_profile_release_with_nonce_sha256(
            authoritative_candidate,
            authority_resolution=authority_resolution,
            authenticated_principal=principal,
            nonce_sha256=nonce_sha256,
            draft_ref_sha256=draft_ref_sha256,
        )

    def purge_expired_profile_release_build_drafts(
        self,
        *,
        authenticated_principal: str,
    ) -> ProfileReleaseDraftPurgeResult:
        """Delete only this builder's expired protected drafts for scheduled retention."""

        with self._factory.begin() as session:
            result = cast(
                CursorResult[Any],
                session.execute(
                    text(
                        "DELETE FROM dev_eval.profile_release_build_drafts "
                        "WHERE builder_principal = :builder "
                        "AND expires_at <= CURRENT_TIMESTAMP"
                    ),
                    {"builder": authenticated_principal},
                ),
            )
            remaining = session.execute(
                text(
                    "SELECT count(*) FROM dev_eval.profile_release_build_drafts "
                    "WHERE builder_principal = :builder "
                    "AND expires_at <= CURRENT_TIMESTAMP"
                ),
                {"builder": authenticated_principal},
            ).scalar_one()
            if remaining:
                raise RuntimeError("expired profile release drafts remain after purge")
        return ProfileReleaseDraftPurgeResult(
            deleted_count=int(result.rowcount or 0),
            remaining_expired_count=int(remaining),
        )

    def build_profile_release(
        self,
        authority_resolution: ProfileReleaseBuildAuthorityResolution,
        *,
        authenticated_principal: str,
        reconciliation_nonce: str,
        client_actor_id: str | None = None,
    ) -> ProfileReleaseBuildOutcome:
        """Atomically persist one exact release, BUILT head, and response receipt."""

        candidate = _resolved_profile_release_candidate(authority_resolution)
        principal = authorize_profile_release_action(
            action="BUILD",
            authenticated_principal=authenticated_principal,
            builder_principal=candidate.builder_principal,
            client_actor_id=client_actor_id,
        )
        nonce_sha256 = self._profile_nonce(reconciliation_nonce)
        return self._build_profile_release_with_nonce_sha256(
            candidate,
            authority_resolution=authority_resolution,
            authenticated_principal=principal,
            nonce_sha256=nonce_sha256,
        )

    def _build_profile_release_with_nonce_sha256(
        self,
        candidate: ProfileReleaseCandidateAny,
        *,
        authority_resolution: ProfileReleaseBuildAuthorityResolution,
        authenticated_principal: str,
        nonce_sha256: str,
        draft_ref_sha256: str | None = None,
        serialization_attempts_remaining: int = 3,
        capability_id: str | None = None,
    ) -> ProfileReleaseBuildOutcome:
        principal = authenticated_principal
        coordination_key = f"{principal}:{nonce_sha256}"
        release_sha256 = cast(str, candidate.release_sha256)
        if draft_ref_sha256 is not None and not isinstance(candidate, ProfileReleaseCandidate):
            raise ValueError("successor releases do not support v1 build drafts")
        draft_candidate = cast(ProfileReleaseCandidate, candidate)
        binding_sha256 = profile_release_build_binding_sha256_v1(
            builder_principal=principal,
            release_sha256=release_sha256,
        )
        receipt = ProfileReleaseBuildReceipt(
            release_sha256=release_sha256,
            builder_principal=principal,
            nonce_sha256=nonce_sha256,
            binding_sha256=binding_sha256,
        )
        if capability_id is None:
            with self._factory() as preflight_session:
                preflight_existing = self._build_outcome_from_session(
                    preflight_session,
                    nonce_sha256=nonce_sha256,
                    authenticated_principal=principal,
                )
                builder_database_principal = str(
                    preflight_session.execute(text("SELECT session_user")).scalar_one()
                )
            if builder_database_principal != authority_resolution.builder_database_principal:
                raise ValueError("profile release builder database authority drifted")
            if preflight_existing is not None:
                if (
                    preflight_existing.release_sha256 != release_sha256
                    or preflight_existing.binding_sha256 != binding_sha256
                ):
                    raise ProfileReleaseReplayError(
                        "profile release build nonce is bound to another candidate"
                    )
                if draft_ref_sha256 is None:
                    return preflight_existing
            else:
                try:
                    capability_id = self._issue_profile_release_build_capability(
                        authority_resolution,
                        coordination_key=coordination_key,
                    )
                except IntegrityError as error:
                    try:
                        outcome = self._reconcile_profile_build_after_collision(
                            nonce_sha256=nonce_sha256,
                            authenticated_principal=principal,
                            release_sha256=release_sha256,
                            binding_sha256=binding_sha256,
                        )
                    except ProfileReleaseReplayError as replay:
                        raise replay from error
                    if draft_ref_sha256 is not None:
                        self._consume_profile_release_build_draft_after_relookup(
                            draft_ref_sha256=draft_ref_sha256,
                            authenticated_principal=principal,
                            candidate=draft_candidate,
                            nonce_sha256=nonce_sha256,
                            outcome=outcome,
                        )
                    return outcome
                except DBAPIError as error:
                    if self._is_build_transaction_retryable(error):
                        if serialization_attempts_remaining > 1:
                            return self._build_profile_release_with_nonce_sha256(
                                candidate,
                                authority_resolution=authority_resolution,
                                authenticated_principal=principal,
                                nonce_sha256=nonce_sha256,
                                draft_ref_sha256=draft_ref_sha256,
                                serialization_attempts_remaining=(
                                    serialization_attempts_remaining - 1
                                ),
                            )
                        raise ProfileReleaseRetryableAbortError(action="BUILD") from error
                    raise ProfileReleaseBuildUnavailableError(
                        retry_path=(
                            "/internal/evaluation/profile-releases/build-drafts/build"
                            if draft_ref_sha256 is not None
                            else "/internal/evaluation/profile-releases/build"
                        )
                    ) from error
        mutation_started = False
        try:
            with self._factory() as session:
                session.connection(execution_options={"isolation_level": "SERIALIZABLE"})
                self._acquire_profile_release_build_coordination_lock(
                    session,
                    coordination_key=coordination_key,
                )
                existing = self._build_outcome_from_session(
                    session,
                    nonce_sha256=nonce_sha256,
                    authenticated_principal=principal,
                )
                if existing is not None:
                    if (
                        existing.release_sha256 != release_sha256
                        or existing.binding_sha256 != binding_sha256
                    ):
                        raise ProfileReleaseReplayError(
                            "profile release build nonce is bound to another candidate"
                        )
                    if draft_ref_sha256 is not None:
                        if self._draft_cleanup_is_authoritative(
                            session,
                            draft_ref_sha256=draft_ref_sha256,
                            authenticated_principal=principal,
                            outcome=existing,
                        ):
                            return existing
                        self._consume_profile_release_build_draft(
                            session,
                            draft_ref_sha256=draft_ref_sha256,
                            authenticated_principal=principal,
                            candidate=draft_candidate,
                            nonce_sha256=nonce_sha256,
                        )
                        self._record_profile_release_build_draft_consumption(
                            session,
                            draft_ref_sha256=draft_ref_sha256,
                            authenticated_principal=principal,
                            outcome=existing,
                        )
                        session.commit()
                    return existing
                if capability_id is None:
                    raise ProfileReleaseBuildUnavailableError(
                        retry_path="/internal/evaluation/profile-releases/build-drafts/build"
                    )
                if draft_ref_sha256 is not None:
                    mutation_started = True
                    self._consume_profile_release_build_draft(
                        session,
                        draft_ref_sha256=draft_ref_sha256,
                        authenticated_principal=principal,
                        candidate=draft_candidate,
                        nonce_sha256=nonce_sha256,
                    )
                else:
                    mutation_started = True
                transition_proof = None
                if isinstance(candidate, ProfileReleaseCandidateV2):
                    predecessor_row = session.execute(
                        text(
                            "SELECT releases.payload, pointer.receipt_sha256 FROM "
                            "dev_eval.profile_release_active_pointer pointer "
                            "JOIN dev_eval.profile_releases releases USING (release_sha256) "
                            "JOIN dev_eval.profile_release_lifecycle_heads heads "
                            "USING (release_sha256) WHERE pointer.slot = 'DEV' "
                            "AND pointer.release_sha256 = :predecessor "
                            "AND heads.state = 'ACTIVE'"
                        ),
                        {"predecessor": (candidate.lineage.predecessor_release_sha256)},
                    ).one_or_none()
                    if predecessor_row is None:
                        raise ValueError("successor build requires the exact active predecessor")
                    if (
                        predecessor_row.receipt_sha256
                        != candidate.lineage.predecessor_lifecycle_receipt_sha256
                    ):
                        raise ValueError("successor build predecessor lifecycle epoch is stale")
                    predecessor = ProfileReleaseCandidate.model_validate(predecessor_row.payload)
                    transition_proof = build_exact_predecessor_transition_proof(
                        successor=candidate,
                        predecessor=predecessor,
                    )
                consumed_sha256 = session.execute(
                    text(
                        "SELECT dev_eval.consume_profile_release_build_capability_v1("
                        "CAST(:capability_id AS uuid))"
                    ),
                    {"capability_id": capability_id},
                ).scalar_one()
                if consumed_sha256 != release_sha256:
                    raise ValueError("database-consumed candidate digest differs")
                stored = session.execute(
                    text(
                        "SELECT payload FROM dev_eval.profile_releases "
                        "WHERE release_sha256 = :release_sha256"
                    ),
                    {"release_sha256": release_sha256},
                ).scalar_one()
                if _profile_release_candidate_from_payload(stored) != candidate:
                    raise ValueError("profile release collision or hash drift")
                if transition_proof is not None:
                    stored_proof_sha256 = session.execute(
                        text(
                            "SELECT "
                            "dev_eval.insert_profile_release_v2_transition_proof_v1("
                            ":successor)"
                        ),
                        {
                            "successor": transition_proof.successor_release_sha256,
                        },
                    ).scalar_one()
                    if stored_proof_sha256 != transition_proof.proof_sha256:
                        raise ValueError("database-derived transition proof differs")
                lifecycle_head = session.execute(
                    text(
                        "SELECT state, head_receipt_sha256 FROM "
                        "dev_eval.profile_release_lifecycle_heads "
                        "WHERE release_sha256 = :release_sha256"
                    ),
                    {"release_sha256": release_sha256},
                ).one()
                if (
                    lifecycle_head.state != ProfileReleaseState.BUILT_UNAPPROVED.value
                    or lifecycle_head.head_receipt_sha256 is not None
                ):
                    raise ValueError("profile release is not an exact BUILT_UNAPPROVED head")
                session.execute(
                    text(
                        "SELECT dev_eval.insert_profile_release_build_receipt_v1("
                        ":builder, :nonce, :binding, :release, :receipt)"
                    ),
                    {
                        "builder": principal,
                        "nonce": nonce_sha256,
                        "binding": binding_sha256,
                        "release": release_sha256,
                        "receipt": receipt.receipt_sha256,
                    },
                )
                if draft_ref_sha256 is not None:
                    self._record_profile_release_build_draft_consumption(
                        session,
                        draft_ref_sha256=draft_ref_sha256,
                        authenticated_principal=principal,
                        outcome=ProfileReleaseBuildOutcome(
                            release_sha256=release_sha256,
                            receipt_sha256=cast(str, receipt.receipt_sha256),
                            nonce_sha256=nonce_sha256,
                            binding_sha256=binding_sha256,
                            completion=ProfileReleaseCompletion.MUTATION_COMMITTED,
                        ),
                    )
                session.commit()
        except IntegrityError as error:
            if not self._is_profile_build_unique_violation(error):
                raise
            outcome = self._reconcile_profile_build_after_collision(
                nonce_sha256=nonce_sha256,
                authenticated_principal=principal,
                release_sha256=release_sha256,
                binding_sha256=binding_sha256,
            )
            if draft_ref_sha256 is not None:
                self._consume_profile_release_build_draft_after_relookup(
                    draft_ref_sha256=draft_ref_sha256,
                    authenticated_principal=principal,
                    candidate=draft_candidate,
                    nonce_sha256=nonce_sha256,
                    outcome=outcome,
                )
            return outcome
        except DBAPIError as error:
            if self._is_build_transaction_retryable(error):
                if serialization_attempts_remaining > 1:
                    return self._build_profile_release_with_nonce_sha256(
                        candidate,
                        authority_resolution=authority_resolution,
                        authenticated_principal=principal,
                        nonce_sha256=nonce_sha256,
                        draft_ref_sha256=draft_ref_sha256,
                        serialization_attempts_remaining=(serialization_attempts_remaining - 1),
                        capability_id=capability_id,
                    )
                raise ProfileReleaseRetryableAbortError(action="BUILD") from error
            if not mutation_started:
                raise ProfileReleaseBuildUnavailableError(
                    retry_path=(
                        "/internal/evaluation/profile-releases/build-drafts/build"
                        if draft_ref_sha256 is not None
                        else "/internal/evaluation/profile-releases/build"
                    )
                ) from error
            try:
                outcome = self._reconcile_profile_build_after_possible_commit(
                    nonce_sha256=nonce_sha256,
                    authenticated_principal=principal,
                    release_sha256=release_sha256,
                    binding_sha256=binding_sha256,
                )
                if draft_ref_sha256 is not None:
                    self._consume_profile_release_build_draft_after_relookup(
                        draft_ref_sha256=draft_ref_sha256,
                        authenticated_principal=principal,
                        candidate=draft_candidate,
                        nonce_sha256=nonce_sha256,
                        outcome=outcome,
                    )
                return outcome
            except ProfileReleaseUnknownOutcomeError as unknown:
                raise unknown from error
        return ProfileReleaseBuildOutcome(
            release_sha256=release_sha256,
            receipt_sha256=cast(str, receipt.receipt_sha256),
            nonce_sha256=nonce_sha256,
            binding_sha256=binding_sha256,
            completion=ProfileReleaseCompletion.MUTATION_COMMITTED,
        )

    def _issue_profile_release_build_capability(
        self,
        resolution: ProfileReleaseBuildAuthorityResolution,
        *,
        coordination_key: str,
    ) -> str:
        factory = self._authority_connection_factory
        if factory is None:
            raise ProfileReleaseBuildUnavailableError(
                retry_path="/internal/evaluation/profile-releases/build"
            )
        candidate = resolution.candidate
        with factory.begin() as authority_session:
            authority_session.connection(execution_options={"isolation_level": "SERIALIZABLE"})
            self._acquire_profile_release_build_coordination_lock(
                authority_session,
                coordination_key=coordination_key,
            )
            session_user = str(authority_session.execute(text("SELECT session_user")).scalar_one())
            if session_user != "itda_profile_release_authority_service":
                raise ProfileReleaseBuildUnavailableError(
                    retry_path="/internal/evaluation/profile-releases/build"
                )
            recorded = authority_session.execute(
                text(
                    "SELECT authorization_id::text, candidate_sha256 FROM "
                    "dev_eval.record_profile_release_build_authorization_v1("
                    "CAST(:resolution AS jsonb))"
                ),
                {
                    "resolution": resolution.model_dump_json(),
                },
            ).one()
            if recorded.candidate_sha256 != candidate.release_sha256:
                raise ValueError("database-recorded candidate digest differs")
            issued = authority_session.execute(
                text(
                    "SELECT capability_id::text, candidate_sha256 FROM "
                    "dev_eval.issue_profile_release_build_capability_v2("
                    "CAST(:authorization_id AS uuid))"
                ),
                {"authorization_id": recorded.authorization_id},
            ).one()
            if issued.candidate_sha256 != candidate.release_sha256:
                raise ValueError("database-issued candidate digest differs")
            return str(issued.capability_id)

    @staticmethod
    def _acquire_profile_release_build_coordination_lock(
        session: Session,
        *,
        coordination_key: str,
    ) -> None:
        session.execute(
            text("SELECT pg_advisory_xact_lock(hashtextextended(:coordination_key, 0))"),
            {"coordination_key": coordination_key},
        )

    @staticmethod
    def _consume_profile_release_build_draft(
        session: Session,
        *,
        draft_ref_sha256: str,
        authenticated_principal: str,
        candidate: ProfileReleaseCandidate,
        nonce_sha256: str,
    ) -> None:
        deleted = session.execute(
            text(
                "DELETE FROM dev_eval.profile_release_build_drafts "
                "WHERE draft_ref_sha256 = :draft_ref "
                "AND builder_principal = :builder AND nonce_sha256 = :nonce "
                "AND expires_at > CURRENT_TIMESTAMP "
                "RETURNING candidate_payload, nonce_sha256"
            ),
            {
                "draft_ref": draft_ref_sha256,
                "builder": authenticated_principal,
                "nonce": nonce_sha256,
            },
        )
        row = deleted.one_or_none()
        if row is None:
            raise ValueError("profile release build draft consumption was not exact")
        if (
            row.nonce_sha256 != nonce_sha256
            or ProfileReleaseCandidate.model_validate(row.candidate_payload) != candidate
        ):
            raise ValueError("profile release build draft binding is corrupt")

    def _consume_profile_release_build_draft_after_relookup(
        self,
        *,
        draft_ref_sha256: str,
        authenticated_principal: str,
        candidate: ProfileReleaseCandidate,
        nonce_sha256: str,
        outcome: ProfileReleaseBuildOutcome,
    ) -> None:
        for attempt in range(3):
            try:
                with self._factory() as session:
                    session.connection(execution_options={"isolation_level": "SERIALIZABLE"})
                    if self._draft_cleanup_is_authoritative(
                        session,
                        draft_ref_sha256=draft_ref_sha256,
                        authenticated_principal=authenticated_principal,
                        outcome=outcome,
                    ):
                        return
                    self._consume_profile_release_build_draft(
                        session,
                        draft_ref_sha256=draft_ref_sha256,
                        authenticated_principal=authenticated_principal,
                        candidate=candidate,
                        nonce_sha256=nonce_sha256,
                    )
                    self._record_profile_release_build_draft_consumption(
                        session,
                        draft_ref_sha256=draft_ref_sha256,
                        authenticated_principal=authenticated_principal,
                        outcome=outcome,
                    )
                    session.commit()
                return
            except DBAPIError as error:
                with self._factory() as session:
                    if self._draft_cleanup_is_authoritative(
                        session,
                        draft_ref_sha256=draft_ref_sha256,
                        authenticated_principal=authenticated_principal,
                        outcome=outcome,
                    ):
                        return
                if self._is_serialization_failure(error) or attempt < 2:
                    continue
                raise self._draft_cleanup_unknown(nonce_sha256) from error
        raise self._draft_cleanup_unknown(nonce_sha256)

    @staticmethod
    def _direct_build_replay_is_authoritative(
        session: Session,
        *,
        authenticated_principal: str,
        outcome: ProfileReleaseBuildOutcome,
    ) -> bool:
        reservation = session.execute(
            text(
                "SELECT candidate_sha256, draft_ref_sha256 FROM "
                "dev_eval.profile_release_build_nonce_reservations WHERE "
                "builder_principal = :builder AND nonce_sha256 = :nonce"
            ),
            {
                "builder": authenticated_principal,
                "nonce": outcome.nonce_sha256,
            },
        ).one_or_none()
        if reservation is None:
            raise ProfileReleaseReplayError("profile release build nonce reservation is missing")
        if reservation.candidate_sha256 != outcome.release_sha256:
            raise ProfileReleaseReplayError("profile release build nonce reservation is corrupt")
        if reservation.draft_ref_sha256 is not None:
            return False
        protected_count = int(
            session.execute(
                text(
                    "SELECT count(*) FROM dev_eval.profile_release_build_drafts "
                    "WHERE builder_principal = :builder AND nonce_sha256 = :nonce"
                ),
                {
                    "builder": authenticated_principal,
                    "nonce": outcome.nonce_sha256,
                },
            ).scalar_one()
        )
        return protected_count == 0

    @staticmethod
    def _record_profile_release_build_draft_consumption(
        session: Session,
        *,
        draft_ref_sha256: str,
        authenticated_principal: str,
        outcome: ProfileReleaseBuildOutcome,
    ) -> None:
        session.execute(
            text(
                "INSERT INTO dev_eval.profile_release_build_draft_consumptions ("
                "draft_ref_sha256, builder_principal, nonce_sha256, "
                "candidate_sha256, receipt_sha256) VALUES ("
                ":draft_ref, :builder, :nonce, :candidate, :receipt) "
                "ON CONFLICT ON CONSTRAINT "
                "pk_phase3_profile_release_build_draft_consumptions DO NOTHING"
            ),
            {
                "draft_ref": draft_ref_sha256,
                "builder": authenticated_principal,
                "nonce": outcome.nonce_sha256,
                "candidate": outcome.release_sha256,
                "receipt": outcome.receipt_sha256,
            },
        )
        row = session.execute(
            text(
                "SELECT builder_principal, nonce_sha256, candidate_sha256, "
                "receipt_sha256 FROM "
                "dev_eval.profile_release_build_draft_consumptions "
                "WHERE draft_ref_sha256 = :draft_ref"
            ),
            {"draft_ref": draft_ref_sha256},
        ).one()
        if (
            row.builder_principal != authenticated_principal
            or row.nonce_sha256 != outcome.nonce_sha256
            or row.candidate_sha256 != outcome.release_sha256
            or row.receipt_sha256 != outcome.receipt_sha256
        ):
            raise ProfileReleaseReplayError("profile release draft consumption binding is corrupt")

    @staticmethod
    def _draft_cleanup_is_authoritative(
        session: Session,
        *,
        draft_ref_sha256: str,
        authenticated_principal: str,
        outcome: ProfileReleaseBuildOutcome,
    ) -> bool:
        protected_count = session.execute(
            text(
                "SELECT count(*) FROM dev_eval.profile_release_build_drafts "
                "WHERE draft_ref_sha256 = :draft_ref"
            ),
            {"draft_ref": draft_ref_sha256},
        ).scalar_one()
        rows = session.execute(
            text(
                "SELECT builder_principal, nonce_sha256, candidate_sha256, "
                "receipt_sha256 FROM "
                "dev_eval.profile_release_build_draft_consumptions "
                "WHERE draft_ref_sha256 = :draft_ref"
            ),
            {"draft_ref": draft_ref_sha256},
        ).all()
        if protected_count:
            return False
        if not rows:
            return False
        if len(rows) != 1:
            raise ProfileReleaseReplayError("profile release draft consumption is ambiguous")
        row = rows[0]
        if (
            row.builder_principal != authenticated_principal
            or row.nonce_sha256 != outcome.nonce_sha256
            or row.candidate_sha256 != outcome.release_sha256
            or row.receipt_sha256 != outcome.receipt_sha256
        ):
            raise ProfileReleaseReplayError("profile release draft consumption binding is corrupt")
        return True

    @staticmethod
    def _draft_cleanup_unknown(
        nonce_sha256: str,
    ) -> ProfileReleaseDraftCleanupUnknownError:
        return ProfileReleaseDraftCleanupUnknownError(
            lookup_path=(
                f"/internal/evaluation/profile-releases/build-receipts/by-nonce/{nonce_sha256}"
            ),
            retry_path="/internal/evaluation/profile-releases/build-drafts/build",
        )

    @staticmethod
    def _is_profile_build_unique_violation(error: IntegrityError) -> bool:
        if getattr(error.orig, "sqlstate", None) != "23505":
            return False
        constraint = getattr(getattr(error.orig, "diag", None), "constraint_name", None)
        return constraint in {
            "pk_phase3_profile_releases",
            "pk_phase3_profile_release_build_receipts",
            "uq_phase3_profile_release_build_receipt_release",
            "uq_phase3_profile_release_build_receipt_receipt",
        }

    def _reconcile_profile_build_after_collision(
        self,
        *,
        nonce_sha256: str,
        authenticated_principal: str,
        release_sha256: str,
        binding_sha256: str,
    ) -> ProfileReleaseBuildOutcome:
        with self._factory() as session:
            outcome = self._build_outcome_from_session(
                session,
                nonce_sha256=nonce_sha256,
                authenticated_principal=authenticated_principal,
            )
        if (
            outcome is None
            or outcome.release_sha256 != release_sha256
            or outcome.binding_sha256 != binding_sha256
        ):
            raise ProfileReleaseReplayError(
                "profile release build collision has no identical committed winner"
            )
        return outcome

    def _reconcile_profile_build_after_possible_commit(
        self,
        *,
        nonce_sha256: str,
        authenticated_principal: str,
        release_sha256: str,
        binding_sha256: str,
    ) -> ProfileReleaseBuildOutcome:
        with self._factory() as session:
            outcome = self._build_outcome_from_session(
                session,
                nonce_sha256=nonce_sha256,
                authenticated_principal=authenticated_principal,
            )
        if outcome is None:
            raise ProfileReleaseUnknownOutcomeError(
                action="BUILD",
                lookup_path=(
                    f"/internal/evaluation/profile-releases/build-receipts/by-nonce/{nonce_sha256}"
                ),
            )
        if outcome.release_sha256 != release_sha256 or outcome.binding_sha256 != binding_sha256:
            raise ProfileReleaseReplayError(
                "profile release build nonce is bound to another candidate"
            )
        return outcome

    @staticmethod
    def _build_outcome_from_session(
        session: Session,
        *,
        nonce_sha256: str,
        authenticated_principal: str,
    ) -> ProfileReleaseBuildOutcome | None:
        rows = session.execute(
            text(
                "SELECT builder_principal, nonce_sha256, binding_sha256, "
                "release_sha256, receipt_sha256 FROM "
                "dev_eval.profile_release_build_receipts "
                "WHERE builder_principal = :builder AND nonce_sha256 = :nonce"
            ),
            {"builder": authenticated_principal, "nonce": nonce_sha256},
        ).all()
        if not rows:
            return None
        if len(rows) != 1:
            raise ValueError("profile release build receipt is ambiguous")
        row = rows[0]
        receipt = ProfileReleaseBuildReceipt(
            release_sha256=row.release_sha256,
            builder_principal=row.builder_principal,
            nonce_sha256=row.nonce_sha256,
            binding_sha256=row.binding_sha256,
            receipt_sha256=row.receipt_sha256,
        )
        expected_binding = profile_release_build_binding_sha256_v1(
            builder_principal=authenticated_principal,
            release_sha256=row.release_sha256,
        )
        if row.binding_sha256 != expected_binding:
            raise ValueError("profile release build binding is corrupt")
        release = session.execute(
            text(
                "SELECT releases.release_sha256, releases.release_id, "
                "releases.builder_principal, releases.canonical_lineage_sha256, "
                "releases.dev_lineage_sha256, releases.profile_schema_sha256, "
                "releases.payload FROM dev_eval.profile_releases releases "
                "WHERE releases.release_sha256 = :release"
            ),
            {"release": row.release_sha256},
        ).one_or_none()
        if release is None or release.builder_principal != authenticated_principal:
            raise ValueError("profile release build target is missing or actor-mismatched")
        candidate = _profile_release_candidate_from_payload(release.payload)
        canonical_lineage, dev_lineage, profile_schema = _profile_release_lineage_columns(candidate)
        if (
            candidate.release_sha256 != row.release_sha256
            or candidate.release_id != release.release_id
            or candidate.builder_principal != release.builder_principal
            or canonical_lineage != release.canonical_lineage_sha256
            or dev_lineage != release.dev_lineage_sha256
            or profile_schema != release.profile_schema_sha256
        ):
            raise ValueError("profile release build target payload is corrupt")
        return ProfileReleaseBuildOutcome(
            release_sha256=row.release_sha256,
            receipt_sha256=cast(str, receipt.receipt_sha256),
            nonce_sha256=row.nonce_sha256,
            binding_sha256=row.binding_sha256,
            completion=ProfileReleaseCompletion.RELOOKUP_CONFIRMED,
        )

    def get_profile_release_build_outcome_by_nonce(
        self,
        nonce_sha256: str,
        authenticated_principal: str,
    ) -> ProfileReleaseBuildOutcome | None:
        with self._factory() as session:
            return self._build_outcome_from_session(
                session,
                nonce_sha256=nonce_sha256,
                authenticated_principal=authenticated_principal,
            )

    def approve_profile_release(
        self,
        release_sha256: str,
        *,
        authenticated_principal: str,
        client_approver_id: str | None = None,
        serialization_attempts_remaining: int = 3,
    ) -> ProfileReleaseApproval:
        try:
            return self._approve_profile_release_once(
                release_sha256,
                authenticated_principal=authenticated_principal,
                client_approver_id=client_approver_id,
            )
        except IntegrityError as error:
            try:
                return self._reconcile_approval_after_possible_commit(
                    release_sha256=release_sha256,
                    authenticated_principal=authenticated_principal,
                )
            except ProfileReleaseUnknownOutcomeError:
                raise ProfileReleaseReplayError(
                    "profile release approval was rejected before commit"
                ) from error
        except DBAPIError as error:
            if self._is_serialization_failure(error):
                if serialization_attempts_remaining > 1:
                    return self.approve_profile_release(
                        release_sha256,
                        authenticated_principal=authenticated_principal,
                        client_approver_id=client_approver_id,
                        serialization_attempts_remaining=(serialization_attempts_remaining - 1),
                    )
                raise ProfileReleaseRetryableAbortError(action="APPROVE") from error
            try:
                return self._reconcile_approval_after_possible_commit(
                    release_sha256=release_sha256,
                    authenticated_principal=authenticated_principal,
                )
            except ProfileReleaseUnknownOutcomeError as unknown:
                raise unknown from error

    def _approve_profile_release_once(
        self,
        release_sha256: str,
        *,
        authenticated_principal: str,
        client_approver_id: str | None = None,
    ) -> ProfileReleaseApproval:
        """Append exact-hash approval without changing the active pointer."""

        with self._factory() as session:
            session.connection(execution_options={"isolation_level": "SERIALIZABLE"})
            row = session.execute(
                text(
                    "SELECT releases.payload, heads.state FROM dev_eval.profile_releases releases "
                    "JOIN dev_eval.profile_release_lifecycle_heads heads USING (release_sha256) "
                    "WHERE releases.release_sha256 = :release_sha256 FOR UPDATE OF heads"
                ),
                {"release_sha256": release_sha256},
            ).one_or_none()
            if row is None:
                raise ValueError("profile release target does not exist")
            candidate = _profile_release_candidate_from_payload(row.payload)
            principal = authorize_profile_release_action(
                action="APPROVE",
                authenticated_principal=authenticated_principal,
                builder_principal=candidate.builder_principal,
                client_actor_id=client_approver_id,
            )
            if row.state != ProfileReleaseState.BUILT_UNAPPROVED.value:
                raise ValueError("only BUILT_UNAPPROVED release can be approved")
            approval = ProfileReleaseApproval(
                release_sha256=release_sha256,
                builder_principal=candidate.builder_principal,
                approver_principal=principal,
            )
            session.execute(
                text(
                    "INSERT INTO dev_eval.profile_release_approvals ("
                    "approval_sha256, release_sha256, builder_principal, "
                    "approver_principal, payload) VALUES ("
                    ":approval_sha256, :release_sha256, :builder, :approver, "
                    "CAST(:payload AS jsonb))"
                ),
                {
                    "approval_sha256": approval.approval_sha256,
                    "release_sha256": release_sha256,
                    "builder": candidate.builder_principal,
                    "approver": principal,
                    "payload": approval.model_dump_json(),
                },
            )
            session.execute(
                text(
                    "UPDATE dev_eval.profile_release_lifecycle_heads SET "
                    "state = 'APPROVED_INACTIVE', head_receipt_sha256 = :approval_sha256 "
                    "WHERE release_sha256 = :release_sha256 AND state = 'BUILT_UNAPPROVED'"
                ),
                {
                    "approval_sha256": approval.approval_sha256,
                    "release_sha256": release_sha256,
                },
            )
            changed = session.execute(
                text(
                    "SELECT state, head_receipt_sha256 FROM "
                    "dev_eval.profile_release_lifecycle_heads "
                    "WHERE release_sha256 = :release_sha256"
                ),
                {"release_sha256": release_sha256},
            ).one()
            if (
                changed.state != ProfileReleaseState.APPROVED_INACTIVE.value
                or changed.head_receipt_sha256 != approval.approval_sha256
            ):
                raise ProfileReleaseReplayError("profile release approval state changed")
            session.commit()
        return approval

    @staticmethod
    def _require_successor_exact_predecessor(
        session: Session,
        *,
        successor: ProfileReleaseCandidateV2,
        predecessor_release_sha256: str,
    ) -> ProfileReleaseCandidate:
        row = session.execute(
            text(
                "SELECT proof.predecessor_release_sha256, proof.proof_sha256, "
                "proof.payload AS proof_payload, predecessor.payload AS "
                "predecessor_payload FROM "
                "dev_eval.profile_release_v2_transition_proofs proof JOIN "
                "dev_eval.profile_releases predecessor ON "
                "predecessor.release_sha256 = proof.predecessor_release_sha256 "
                "WHERE proof.successor_release_sha256 = :successor AND "
                "proof.predecessor_release_sha256 = :predecessor"
            ),
            {
                "successor": successor.release_sha256,
                "predecessor": predecessor_release_sha256,
            },
        ).one_or_none()
        if row is None:
            raise ValueError("successor exact predecessor proof is missing")
        predecessor = ProfileReleaseCandidate.model_validate(row.predecessor_payload)
        proof = ProfileReleaseTransitionProofV2.model_validate(row.proof_payload)
        if (
            proof.proof_sha256 != row.proof_sha256
            or proof.predecessor_release_sha256 != row.predecessor_release_sha256
            or not require_exact_predecessor_transition(
                successor=successor,
                predecessor=predecessor,
                proof=proof,
            )
        ):
            raise ValueError("successor exact predecessor proof is invalid")
        return predecessor

    def _reconcile_approval_after_possible_commit(
        self,
        *,
        release_sha256: str,
        authenticated_principal: str,
    ) -> ProfileReleaseApproval:
        with self._factory() as session:
            session.connection(execution_options={"isolation_level": "REPEATABLE READ"})
            release = session.execute(
                text(
                    "SELECT payload FROM dev_eval.profile_releases WHERE release_sha256 = :release"
                ),
                {"release": release_sha256},
            ).one_or_none()
            approval = self._validated_approval_for_release(session, release_sha256)
            if release is None or approval is None:
                raise ProfileReleaseUnknownOutcomeError(
                    action="APPROVE",
                    lookup_path=(f"/internal/evaluation/profile-releases/{release_sha256}/state"),
                )
            candidate = _profile_release_candidate_from_payload(release.payload)
            expected_principal = authorize_profile_release_action(
                action="APPROVE",
                authenticated_principal=authenticated_principal,
                builder_principal=candidate.builder_principal,
                client_actor_id=None,
            )
            if (
                approval.release_sha256 != release_sha256
                or approval.builder_principal != candidate.builder_principal
                or approval.approver_principal != expected_principal
            ):
                raise ProfileReleaseReplayError(
                    "profile release approval is bound to another principal"
                )
            return approval

    @staticmethod
    def _profile_nonce(nonce: str) -> str:
        if re.fullmatch(r"[0-9a-f]{64}", nonce) is None:
            raise ValueError("profile release nonce must be 64 lowercase hex characters")
        return hashlib.sha256(nonce.encode("ascii")).hexdigest()

    @staticmethod
    def _transition_outcome_from_session(
        session: Session,
        *,
        nonce_sha256: str,
        authenticated_principal: str,
    ) -> ProfileReleaseTransitionOutcome | None:
        rows = session.execute(
            text(
                "SELECT ledger.binding_sha256, ledger.nonce_sha256 AS ledger_nonce, "
                "ledger.receipt_sha256 AS ledger_receipt, ledger.payload AS ledger_payload, "
                "events.receipt_sha256, events.action, events.release_sha256, "
                "events.previous_release_sha256, events.expected_current_sha256, "
                "events.approver_principal, events.nonce_sha256, events.payload "
                "FROM dev_eval.profile_release_nonce_ledger ledger "
                "JOIN dev_eval.profile_release_transition_events events "
                "ON events.receipt_sha256 = ledger.receipt_sha256 "
                "WHERE ledger.nonce_sha256 = :nonce"
            ),
            {"nonce": nonce_sha256},
        ).all()
        if not rows:
            return None
        if len(rows) != 1:
            raise ValueError("profile release transition nonce is ambiguous")
        row = rows[0]
        if row.approver_principal != authenticated_principal:
            return None
        event_receipt = ProfileReleaseTransitionReceipt.model_validate(row.payload)
        ledger_receipt = ProfileReleaseTransitionReceipt.model_validate(row.ledger_payload)
        if event_receipt != ledger_receipt:
            raise ValueError("profile release transition ledger payload drifted")
        if (
            row.ledger_nonce != row.nonce_sha256
            or row.ledger_receipt != row.receipt_sha256
            or event_receipt.receipt_sha256 != row.receipt_sha256
            or event_receipt.action != row.action
            or event_receipt.release_sha256 != row.release_sha256
            or event_receipt.previous_release_sha256 != row.previous_release_sha256
            or event_receipt.expected_current_sha256 != row.expected_current_sha256
            or event_receipt.approver_principal != row.approver_principal
            or event_receipt.nonce_sha256 != row.nonce_sha256
        ):
            raise ValueError("profile release transition columns drifted from payload")
        if row.previous_release_sha256 != row.expected_current_sha256:
            raise ValueError("profile release transition CAS provenance is impossible")
        if row.action == "ROLLBACK" and row.previous_release_sha256 is None:
            raise ValueError("profile release rollback lacks a displaced current release")
        if row.action == "ACTIVATE":
            rollback_rows = session.execute(
                text(
                    "SELECT 1 FROM dev_eval.profile_release_rollback_receipts "
                    "WHERE transition_receipt_sha256 = :receipt"
                ),
                {"receipt": row.receipt_sha256},
            ).all()
            if rollback_rows:
                raise ValueError("ACTIVATE transition has rollback-only provenance")
            binding_sha256 = profile_release_activate_binding_sha256_v1(
                target_sha256=row.release_sha256,
                expected_current_sha256=row.expected_current_sha256,
            )
        elif row.action == "ROLLBACK":
            rollback_rows = session.execute(
                text(
                    "SELECT receipt_sha256, transition_receipt_sha256, release_sha256, "
                    "approver_principal, reason, reason_sha256, payload FROM "
                    "dev_eval.profile_release_rollback_receipts "
                    "WHERE transition_receipt_sha256 = :receipt"
                ),
                {"receipt": row.receipt_sha256},
            ).all()
            if len(rollback_rows) != 1:
                raise ValueError("ROLLBACK transition lacks exact rollback provenance")
            rollback = rollback_rows[0]
            rollback_payload = ProfileReleaseTransitionReceipt.model_validate(rollback.payload)
            actual_reason_sha256 = hashlib.sha256(rollback.reason.encode("utf-8")).hexdigest()
            if (
                rollback.receipt_sha256 != row.receipt_sha256
                or rollback.transition_receipt_sha256 != row.receipt_sha256
                or rollback.release_sha256 != row.release_sha256
                or rollback.approver_principal != row.approver_principal
                or rollback.reason_sha256 != actual_reason_sha256
                or rollback_payload != event_receipt
            ):
                raise ValueError("ROLLBACK receipt provenance is corrupt")
            binding_sha256 = profile_release_rollback_binding_sha256_v1(
                target_sha256=row.release_sha256,
                expected_current_sha256=cast(str, row.expected_current_sha256),
                reason_sha256=rollback.reason_sha256,
                approver_principal=row.approver_principal,
            )
        else:
            raise ValueError("profile release transition action is invalid")
        if row.binding_sha256 != binding_sha256:
            raise ValueError("profile release transition binding is corrupt")
        return ProfileReleaseTransitionOutcome(
            action=row.action,
            release_sha256=row.release_sha256,
            previous_release_sha256=row.previous_release_sha256,
            expected_current_sha256=row.expected_current_sha256,
            receipt_sha256=row.receipt_sha256,
            nonce_sha256=row.nonce_sha256,
            binding_sha256=binding_sha256,
            completion=ProfileReleaseCompletion.RELOOKUP_CONFIRMED,
        )

    def get_profile_release_transition_outcome_by_nonce(
        self,
        nonce_sha256: str,
        authenticated_principal: str,
    ) -> ProfileReleaseTransitionOutcome | None:
        with self._factory() as session:
            return self._transition_outcome_from_session(
                session,
                nonce_sha256=nonce_sha256,
                authenticated_principal=authenticated_principal,
            )

    @staticmethod
    def _validated_build_receipt_for_release(
        session: Session,
        release_sha256: str,
        *,
        expected_builder_principal: str,
    ) -> ProfileReleaseBuildReceipt:
        rows = session.execute(
            text(
                "SELECT builder_principal, nonce_sha256, binding_sha256, "
                "release_sha256, receipt_sha256 FROM "
                "dev_eval.profile_release_build_receipts WHERE release_sha256 = :release"
            ),
            {"release": release_sha256},
        ).all()
        if len(rows) != 1:
            raise ValueError("profile release requires exactly one build provenance receipt")
        row = rows[0]
        receipt = ProfileReleaseBuildReceipt(
            release_sha256=row.release_sha256,
            builder_principal=row.builder_principal,
            nonce_sha256=row.nonce_sha256,
            binding_sha256=row.binding_sha256,
            receipt_sha256=row.receipt_sha256,
        )
        if (
            row.builder_principal != expected_builder_principal
            or row.binding_sha256
            != profile_release_build_binding_sha256_v1(
                builder_principal=expected_builder_principal,
                release_sha256=release_sha256,
            )
        ):
            raise ValueError("profile release build provenance binding is corrupt")
        return receipt

    @staticmethod
    def _validated_approval_for_release(
        session: Session,
        release_sha256: str,
    ) -> ProfileReleaseApproval | None:
        rows = session.execute(
            text(
                "SELECT approval_sha256, release_sha256, builder_principal, "
                "approver_principal, payload FROM dev_eval.profile_release_approvals "
                "WHERE release_sha256 = :release"
            ),
            {"release": release_sha256},
        ).all()
        if not rows:
            return None
        if len(rows) != 1:
            raise ValueError("profile release approval provenance is ambiguous")
        row = rows[0]
        approval = ProfileReleaseApproval.model_validate(row.payload)
        if (
            approval.approval_sha256 != row.approval_sha256
            or approval.release_sha256 != row.release_sha256
            or approval.builder_principal != row.builder_principal
            or approval.approver_principal != row.approver_principal
        ):
            raise ValueError("profile release approval columns drifted from payload")
        return approval

    def get_profile_release_state(
        self,
        release_sha256: str,
    ) -> ProfileReleaseStateProjection | None:
        with self._factory() as session:
            session.connection(execution_options={"isolation_level": "REPEATABLE READ"})
            return self._get_profile_release_state_from_session(session, release_sha256)

    def _get_profile_release_state_from_session(
        self,
        session: Session,
        release_sha256: str,
    ) -> ProfileReleaseStateProjection | None:
        head = session.execute(
            text(
                "SELECT releases.payload, releases.builder_principal, heads.state, "
                "heads.head_receipt_sha256 FROM dev_eval.profile_releases releases JOIN "
                "dev_eval.profile_release_lifecycle_heads heads USING (release_sha256) "
                "WHERE releases.release_sha256 = :release"
            ),
            {"release": release_sha256},
        ).one_or_none()
        if head is None:
            return None
        candidate = _profile_release_candidate_from_payload(head.payload)
        if (
            candidate.release_sha256 != release_sha256
            or candidate.builder_principal != head.builder_principal
        ):
            raise ValueError("profile release candidate payload is corrupt")
        build_receipt = self._validated_build_receipt_for_release(
            session,
            release_sha256,
            expected_builder_principal=candidate.builder_principal,
        )
        approval = self._validated_approval_for_release(session, release_sha256)
        state = ProfileReleaseState(head.state)
        if state == ProfileReleaseState.BUILT_UNAPPROVED:
            if head.head_receipt_sha256 is not None or approval is not None:
                raise ValueError("BUILT lifecycle has extra approval or head provenance")
            transition_count = session.execute(
                text(
                    "SELECT count(*) FROM dev_eval.profile_release_transition_events "
                    "WHERE release_sha256 = :release OR previous_release_sha256 = :release"
                ),
                {"release": release_sha256},
            ).scalar_one()
            if transition_count:
                raise ValueError("BUILT lifecycle has transition provenance")
            return ProfileReleaseStateProjection(
                release_sha256=release_sha256,
                state=state,
                lifecycle_head_receipt_sha256=None,
                provenance_kind="BUILD",
                provenance_receipt_sha256=cast(str, build_receipt.receipt_sha256),
            )
        if approval is None or head.head_receipt_sha256 is None:
            raise ValueError("approved lifecycle lacks exact approval/head provenance")
        if approval.builder_principal != candidate.builder_principal:
            raise ValueError("approval builder differs from canonical release builder")
        if head.head_receipt_sha256 == approval.approval_sha256:
            if state != ProfileReleaseState.APPROVED_INACTIVE:
                raise ValueError("ACTIVE lifecycle cannot retain approval-only head")
            return ProfileReleaseStateProjection(
                release_sha256=release_sha256,
                state=state,
                lifecycle_head_receipt_sha256=head.head_receipt_sha256,
                provenance_kind="APPROVAL",
                provenance_receipt_sha256=cast(str, approval.approval_sha256),
            )
        event = session.execute(
            text(
                "SELECT nonce_sha256, approver_principal, release_sha256, "
                "previous_release_sha256 FROM dev_eval.profile_release_transition_events "
                "WHERE receipt_sha256 = :receipt"
            ),
            {"receipt": head.head_receipt_sha256},
        ).one_or_none()
        if event is None:
            raise ValueError("lifecycle transition head is orphaned")
        outcome = self._transition_outcome_from_session(
            session,
            nonce_sha256=event.nonce_sha256,
            authenticated_principal=event.approver_principal,
        )
        if outcome is None or outcome.receipt_sha256 != head.head_receipt_sha256:
            raise ValueError("lifecycle transition provenance is invalid")
        pointer = session.execute(
            text(
                "SELECT release_sha256, receipt_sha256 FROM "
                "dev_eval.profile_release_active_pointer WHERE slot = 'DEV'"
            )
        ).one_or_none()
        if state == ProfileReleaseState.ACTIVE:
            if (
                pointer is None
                or pointer.release_sha256 != release_sha256
                or pointer.receipt_sha256 != head.head_receipt_sha256
                or event.release_sha256 != release_sha256
            ):
                raise ValueError("ACTIVE lifecycle disagrees with pointer provenance")
        elif (
            state != ProfileReleaseState.APPROVED_INACTIVE
            or event.previous_release_sha256 != release_sha256
            or (pointer is not None and pointer.release_sha256 == release_sha256)
        ):
            raise ValueError("inactive lifecycle has wrong transition provenance")
        return ProfileReleaseStateProjection(
            release_sha256=release_sha256,
            state=state,
            lifecycle_head_receipt_sha256=head.head_receipt_sha256,
            provenance_kind="TRANSITION",
            provenance_receipt_sha256=outcome.receipt_sha256,
        )

    def get_profile_release_active_pointer(self) -> ProfileReleaseActivePointerProjection:
        with self._factory() as session:
            session.connection(execution_options={"isolation_level": "REPEATABLE READ"})
            pointer = session.execute(
                text(
                    "SELECT release_sha256, receipt_sha256 FROM "
                    "dev_eval.profile_release_active_pointer WHERE slot = 'DEV'"
                )
            ).one_or_none()
            if pointer is None:
                return ProfileReleaseActivePointerProjection(
                    active_release_sha256=None,
                    state=None,
                    receipt_sha256=None,
                )
            state = self._get_profile_release_state_from_session(
                session,
                pointer.release_sha256,
            )
            if (
                state is None
                or state.state != ProfileReleaseState.ACTIVE
                or state.lifecycle_head_receipt_sha256 != pointer.receipt_sha256
            ):
                raise ValueError("profile release active pointer is corrupt")
            return ProfileReleaseActivePointerProjection(
                active_release_sha256=pointer.release_sha256,
                state=ProfileReleaseState.ACTIVE,
                receipt_sha256=pointer.receipt_sha256,
            )

    @staticmethod
    def _receipt_from_outcome(
        outcome: ProfileReleaseTransitionOutcome,
        *,
        authenticated_principal: str,
        reason: str | None,
    ) -> ProfileReleaseTransitionReceipt:
        persisted = ProfileReleaseTransitionReceipt(
            action=outcome.action,
            release_sha256=outcome.release_sha256,
            previous_release_sha256=outcome.previous_release_sha256,
            expected_current_sha256=outcome.expected_current_sha256,
            approver_principal=authenticated_principal,
            nonce_sha256=outcome.nonce_sha256,
            reason=reason,
            completion=ProfileReleaseCompletion.MUTATION_COMMITTED,
            receipt_sha256=outcome.receipt_sha256,
        )
        return persisted

    def _reconcile_existing_transition(
        self,
        session: Session,
        *,
        nonce_sha256: str,
        authenticated_principal: str,
        action: Literal["ACTIVATE", "ROLLBACK"],
        binding_sha256: str,
        reason: str | None,
    ) -> ProfileReleaseTransitionMutationResult | None:
        outcome = self._transition_outcome_from_session(
            session,
            nonce_sha256=nonce_sha256,
            authenticated_principal=authenticated_principal,
        )
        if outcome is None:
            return None
        if outcome.action != action or outcome.binding_sha256 != binding_sha256:
            raise ProfileReleaseReplayError("profile release nonce is bound to another transition")
        return ProfileReleaseTransitionMutationResult(
            receipt=self._receipt_from_outcome(
                outcome,
                authenticated_principal=authenticated_principal,
                reason=reason,
            ),
            completion=ProfileReleaseCompletion.RELOOKUP_CONFIRMED,
        )

    def _reconcile_transition_after_collision(
        self,
        *,
        nonce_sha256: str,
        authenticated_principal: str,
        action: Literal["ACTIVATE", "ROLLBACK"],
        binding_sha256: str,
        reason: str | None,
    ) -> ProfileReleaseTransitionMutationResult:
        with self._factory() as session:
            receipt = self._reconcile_existing_transition(
                session,
                nonce_sha256=nonce_sha256,
                authenticated_principal=authenticated_principal,
                action=action,
                binding_sha256=binding_sha256,
                reason=reason,
            )
        if receipt is None:
            raise ProfileReleaseReplayError(
                "profile release transition collision has no validated winner"
            )
        return receipt

    def _reconcile_transition_after_possible_commit(
        self,
        *,
        nonce_sha256: str,
        authenticated_principal: str,
        action: Literal["ACTIVATE", "ROLLBACK"],
        binding_sha256: str,
        reason: str | None,
    ) -> ProfileReleaseTransitionMutationResult:
        with self._factory() as session:
            receipt = self._reconcile_existing_transition(
                session,
                nonce_sha256=nonce_sha256,
                authenticated_principal=authenticated_principal,
                action=action,
                binding_sha256=binding_sha256,
                reason=reason,
            )
        if receipt is None:
            raise ProfileReleaseUnknownOutcomeError(
                action=action,
                lookup_path=(
                    "/internal/evaluation/profile-releases/"
                    f"transition-receipts/by-nonce/{nonce_sha256}"
                ),
            )
        return receipt

    @staticmethod
    def _is_serialization_failure(error: DBAPIError) -> bool:
        return getattr(error.orig, "sqlstate", None) == "40001"

    @staticmethod
    def _is_build_transaction_retryable(error: DBAPIError) -> bool:
        return getattr(error.orig, "sqlstate", None) in {"40001", "40P01"}

    def activate_profile_release(
        self,
        release_sha256: str,
        *,
        expected_current: str | None,
        authenticated_principal: str,
        nonce: str,
        client_actor_id: str | None = None,
        serialization_attempts_remaining: int = 3,
    ) -> ProfileReleaseTransitionMutationResult:
        """Compare-and-swap one approved release into the DEV active slot."""

        validate_profile_release_action_identity(
            authenticated_principal=authenticated_principal,
            client_actor_id=client_actor_id,
        )
        nonce_sha256 = self._profile_nonce(nonce)
        binding_sha256 = profile_release_activate_binding_sha256_v1(
            target_sha256=release_sha256,
            expected_current_sha256=expected_current,
        )
        try:
            with self._factory() as session:
                session.connection(execution_options={"isolation_level": "SERIALIZABLE"})
                replay = self._reconcile_existing_transition(
                    session,
                    nonce_sha256=nonce_sha256,
                    authenticated_principal=authenticated_principal,
                    action="ACTIVATE",
                    binding_sha256=binding_sha256,
                    reason=None,
                )
                if replay is not None:
                    return replay
                target_row = session.execute(
                    text(
                        "SELECT releases.payload, heads.state, approvals.payload AS approval "
                        "FROM dev_eval.profile_releases releases "
                        "JOIN dev_eval.profile_release_lifecycle_heads heads "
                        "USING (release_sha256) "
                        "JOIN dev_eval.profile_release_approvals approvals USING (release_sha256) "
                        "WHERE releases.release_sha256 = :release_sha256 FOR UPDATE OF heads"
                    ),
                    {"release_sha256": release_sha256},
                ).one_or_none()
                if target_row is None:
                    raise ValueError("profile release activation target is not approved")
                candidate = _profile_release_candidate_from_payload(target_row.payload)
                approval = ProfileReleaseApproval.model_validate(target_row.approval)
                principal = authorize_profile_release_action(
                    action="ACTIVATE",
                    authenticated_principal=authenticated_principal,
                    builder_principal=candidate.builder_principal,
                    client_actor_id=client_actor_id,
                )
                if approval.approver_principal != principal:
                    raise ValueError("activation principal differs from exact approval")
                if target_row.state != ProfileReleaseState.APPROVED_INACTIVE.value:
                    raise ValueError("activation target is not APPROVED_INACTIVE")
                current_pointer = session.execute(
                    text(
                        "SELECT release_sha256, receipt_sha256 FROM "
                        "dev_eval.profile_release_active_pointer "
                        "WHERE slot = 'DEV' FOR UPDATE"
                    )
                ).one_or_none()
                current = None if current_pointer is None else current_pointer.release_sha256
                if current != expected_current:
                    raise ProfileReleaseReplayError("stale expected-current activation CAS")
                if isinstance(candidate, ProfileReleaseCandidateV2):
                    if current != candidate.lineage.predecessor_release_sha256:
                        raise ValueError("successor activation requires its exact predecessor")
                    if (
                        current_pointer is None
                        or current_pointer.receipt_sha256
                        != candidate.lineage.predecessor_lifecycle_receipt_sha256
                    ):
                        raise ValueError(
                            "successor activation predecessor lifecycle epoch is stale"
                        )
                    self._require_successor_exact_predecessor(
                        session,
                        successor=candidate,
                        predecessor_release_sha256=current,
                    )
                receipt = ProfileReleaseTransitionReceipt(
                    action="ACTIVATE",
                    release_sha256=release_sha256,
                    previous_release_sha256=current,
                    expected_current_sha256=expected_current,
                    approver_principal=principal,
                    nonce_sha256=nonce_sha256,
                    completion=ProfileReleaseCompletion.MUTATION_COMMITTED,
                )
                with session.begin_nested():
                    if current is not None:
                        session.execute(
                            text(
                                "UPDATE dev_eval.profile_release_lifecycle_heads SET "
                                "state = 'APPROVED_INACTIVE', head_receipt_sha256 = :receipt "
                                "WHERE release_sha256 = :current AND state = 'ACTIVE'"
                            ),
                            {"receipt": receipt.receipt_sha256, "current": current},
                        )
                    session.execute(
                        text(
                            "UPDATE dev_eval.profile_release_lifecycle_heads SET state = 'ACTIVE', "
                            "head_receipt_sha256 = :receipt WHERE release_sha256 = :target "
                            "AND state = 'APPROVED_INACTIVE'"
                        ),
                        {"receipt": receipt.receipt_sha256, "target": release_sha256},
                    )
                    session.execute(
                        text(
                            "INSERT INTO dev_eval.profile_release_active_pointer "
                            "(slot, release_sha256, receipt_sha256) VALUES "
                            "('DEV', :target, :receipt) ON CONFLICT (slot) DO UPDATE SET "
                            "release_sha256 = EXCLUDED.release_sha256, "
                            "receipt_sha256 = EXCLUDED.receipt_sha256"
                        ),
                        {"target": release_sha256, "receipt": receipt.receipt_sha256},
                    )
                    self._insert_profile_transition(session, receipt, binding_sha256)
                session.commit()
            return ProfileReleaseTransitionMutationResult(
                receipt=receipt,
                completion=ProfileReleaseCompletion.MUTATION_COMMITTED,
            )
        except IntegrityError as error:
            try:
                return self._reconcile_transition_after_possible_commit(
                    nonce_sha256=nonce_sha256,
                    authenticated_principal=authenticated_principal,
                    action="ACTIVATE",
                    binding_sha256=binding_sha256,
                    reason=None,
                )
            except ProfileReleaseUnknownOutcomeError:
                raise ProfileReleaseReplayError(
                    "profile release activation was rejected before commit"
                ) from error
        except DBAPIError as error:
            if self._is_serialization_failure(error):
                if serialization_attempts_remaining > 1:
                    return self.activate_profile_release(
                        release_sha256,
                        expected_current=expected_current,
                        authenticated_principal=authenticated_principal,
                        nonce=nonce,
                        client_actor_id=client_actor_id,
                        serialization_attempts_remaining=(serialization_attempts_remaining - 1),
                    )
                raise ProfileReleaseRetryableAbortError(action="ACTIVATE") from error
            try:
                return self._reconcile_transition_after_possible_commit(
                    nonce_sha256=nonce_sha256,
                    authenticated_principal=authenticated_principal,
                    action="ACTIVATE",
                    binding_sha256=binding_sha256,
                    reason=None,
                )
            except ProfileReleaseUnknownOutcomeError as unknown:
                raise unknown from error

    def rollback_profile_release(
        self,
        release_sha256: str,
        *,
        expected_current: str,
        authenticated_principal: str,
        reason: str,
        nonce: str,
        client_approver_id: str | None = None,
        serialization_attempts_remaining: int = 3,
    ) -> ProfileReleaseTransitionMutationResult:
        """CAS only to a compatible prior-active release and bind reason/approver."""

        validate_profile_release_action_identity(
            authenticated_principal=authenticated_principal,
            client_actor_id=client_approver_id,
        )
        nonce_sha256 = self._profile_nonce(nonce)
        normalized_reason = reason.strip()
        if not 1 <= len(normalized_reason) <= 300:
            raise ValueError("rollback reason must contain 1..300 trimmed characters")
        reason_sha256 = hashlib.sha256(normalized_reason.encode("utf-8")).hexdigest()
        binding_sha256 = profile_release_rollback_binding_sha256_v1(
            target_sha256=release_sha256,
            expected_current_sha256=expected_current,
            reason_sha256=reason_sha256,
            approver_principal=authenticated_principal,
        )
        try:
            with self._factory() as session:
                session.connection(execution_options={"isolation_level": "SERIALIZABLE"})
                replay = self._reconcile_existing_transition(
                    session,
                    nonce_sha256=nonce_sha256,
                    authenticated_principal=authenticated_principal,
                    action="ROLLBACK",
                    binding_sha256=binding_sha256,
                    reason=normalized_reason,
                )
                if replay is not None:
                    return replay
                current_sha256 = session.execute(
                    text(
                        "SELECT release_sha256 FROM dev_eval.profile_release_active_pointer "
                        "WHERE slot = 'DEV' FOR UPDATE"
                    )
                ).scalar_one_or_none()
                if current_sha256 != expected_current:
                    raise ProfileReleaseReplayError("stale expected-current rollback CAS")
                rows = session.execute(
                    text(
                        "SELECT releases.release_sha256, releases.payload, heads.state "
                        "FROM dev_eval.profile_releases releases "
                        "JOIN dev_eval.profile_release_lifecycle_heads heads "
                        "USING (release_sha256) "
                        "WHERE releases.release_sha256 IN (:current, :target) "
                        "FOR UPDATE OF heads"
                    ),
                    {"current": expected_current, "target": release_sha256},
                ).all()
                by_sha = {row.release_sha256: row for row in rows}
                if set(by_sha) != {expected_current, release_sha256}:
                    raise ValueError("rollback target or current release does not exist")
                current = _profile_release_candidate_from_payload(by_sha[expected_current].payload)
                target = _profile_release_candidate_from_payload(by_sha[release_sha256].payload)
                principal, validated_reason = validate_rollback_authority(
                    authenticated_principal=authenticated_principal,
                    builder_principal=current.builder_principal,
                    client_approver_id=client_approver_id,
                    reason=reason,
                )
                if validated_reason != normalized_reason or principal != authenticated_principal:
                    raise ValueError("rollback authority normalization drifted")
                if by_sha[release_sha256].state != ProfileReleaseState.APPROVED_INACTIVE.value:
                    raise ValueError("rollback target is not inactive")
                prior_active = session.execute(
                    text(
                        "SELECT 1 FROM dev_eval.profile_release_transition_events "
                        "WHERE release_sha256 = :target LIMIT 1"
                    ),
                    {"target": release_sha256},
                ).one_or_none()
                if prior_active is None:
                    raise ValueError("rollback target is not a recorded prior-active release")
                if isinstance(current, ProfileReleaseCandidateV2):
                    if not isinstance(target, ProfileReleaseCandidate):
                        raise ValueError("successor rollback requires its exact predecessor")
                    if release_sha256 != current.lineage.predecessor_release_sha256:
                        raise ValueError("successor rollback requires its exact predecessor")
                    exact_predecessor = self._require_successor_exact_predecessor(
                        session,
                        successor=current,
                        predecessor_release_sha256=release_sha256,
                    )
                    if exact_predecessor != target:
                        raise ValueError("successor exact predecessor payload drifted")
                else:
                    current_lineage = _profile_release_lineage_columns(current)
                    target_lineage = _profile_release_lineage_columns(target)
                    if current_lineage != target_lineage:
                        raise ValueError("rollback target has incompatible immutable lineage")
                receipt = ProfileReleaseTransitionReceipt(
                    action="ROLLBACK",
                    release_sha256=release_sha256,
                    previous_release_sha256=expected_current,
                    expected_current_sha256=expected_current,
                    approver_principal=principal,
                    nonce_sha256=nonce_sha256,
                    reason=normalized_reason,
                    completion=ProfileReleaseCompletion.MUTATION_COMMITTED,
                )
                with session.begin_nested():
                    session.execute(
                        text(
                            "UPDATE dev_eval.profile_release_lifecycle_heads SET "
                            "state = 'APPROVED_INACTIVE', head_receipt_sha256 = :receipt "
                            "WHERE release_sha256 = :current AND state = 'ACTIVE'"
                        ),
                        {"receipt": receipt.receipt_sha256, "current": expected_current},
                    )
                    session.execute(
                        text(
                            "UPDATE dev_eval.profile_release_lifecycle_heads SET state = 'ACTIVE', "
                            "head_receipt_sha256 = :receipt WHERE release_sha256 = :target "
                            "AND state = 'APPROVED_INACTIVE'"
                        ),
                        {"receipt": receipt.receipt_sha256, "target": release_sha256},
                    )
                    session.execute(
                        text(
                            "UPDATE dev_eval.profile_release_active_pointer SET "
                            "release_sha256 = :target, receipt_sha256 = :receipt "
                            "WHERE slot = 'DEV' AND release_sha256 = :current"
                        ),
                        {
                            "target": release_sha256,
                            "receipt": receipt.receipt_sha256,
                            "current": expected_current,
                        },
                    )
                    self._insert_profile_transition(session, receipt, binding_sha256)
                    session.execute(
                        text(
                            "INSERT INTO dev_eval.profile_release_rollback_receipts ("
                            "receipt_sha256, transition_receipt_sha256, release_sha256, "
                            "approver_principal, reason, reason_sha256, payload) VALUES ("
                            ":receipt, :transition, :release, :approver, :reason, "
                            ":reason_sha256, CAST(:payload AS jsonb))"
                        ),
                        {
                            "receipt": receipt.receipt_sha256,
                            "transition": receipt.receipt_sha256,
                            "release": release_sha256,
                            "approver": principal,
                            "reason": normalized_reason,
                            "reason_sha256": reason_sha256,
                            "payload": receipt.model_dump_json(),
                        },
                    )
                session.commit()
            return ProfileReleaseTransitionMutationResult(
                receipt=receipt,
                completion=ProfileReleaseCompletion.MUTATION_COMMITTED,
            )
        except IntegrityError as error:
            try:
                return self._reconcile_transition_after_possible_commit(
                    nonce_sha256=nonce_sha256,
                    authenticated_principal=authenticated_principal,
                    action="ROLLBACK",
                    binding_sha256=binding_sha256,
                    reason=normalized_reason,
                )
            except ProfileReleaseUnknownOutcomeError:
                raise ProfileReleaseReplayError(
                    "profile release rollback was rejected before commit"
                ) from error
        except DBAPIError as error:
            if self._is_serialization_failure(error):
                if serialization_attempts_remaining > 1:
                    return self.rollback_profile_release(
                        release_sha256,
                        expected_current=expected_current,
                        authenticated_principal=authenticated_principal,
                        reason=reason,
                        nonce=nonce,
                        client_approver_id=client_approver_id,
                        serialization_attempts_remaining=(serialization_attempts_remaining - 1),
                    )
                raise ProfileReleaseRetryableAbortError(action="ROLLBACK") from error
            try:
                return self._reconcile_transition_after_possible_commit(
                    nonce_sha256=nonce_sha256,
                    authenticated_principal=authenticated_principal,
                    action="ROLLBACK",
                    binding_sha256=binding_sha256,
                    reason=normalized_reason,
                )
            except ProfileReleaseUnknownOutcomeError as unknown:
                raise unknown from error

    @staticmethod
    def _insert_profile_transition(
        session: Session,
        receipt: ProfileReleaseTransitionReceipt,
        binding_sha256: str,
    ) -> None:
        session.execute(
            text(
                "INSERT INTO dev_eval.profile_release_transition_events ("
                "receipt_sha256, action, release_sha256, previous_release_sha256, "
                "expected_current_sha256, approver_principal, nonce_sha256, payload) "
                "VALUES (:receipt, :action, :release, :previous, :expected, :approver, "
                ":nonce, CAST(:payload AS jsonb))"
            ),
            {
                "receipt": receipt.receipt_sha256,
                "action": receipt.action,
                "release": receipt.release_sha256,
                "previous": receipt.previous_release_sha256,
                "expected": receipt.expected_current_sha256,
                "approver": receipt.approver_principal,
                "nonce": receipt.nonce_sha256,
                "payload": receipt.model_dump_json(),
            },
        )
        session.execute(
            text(
                "INSERT INTO dev_eval.profile_release_nonce_ledger "
                "(binding_sha256, nonce_sha256, receipt_sha256, payload) VALUES "
                "(:binding, :nonce, :receipt, CAST(:payload AS jsonb))"
            ),
            {
                "binding": binding_sha256,
                "nonce": receipt.nonce_sha256,
                "receipt": receipt.receipt_sha256,
                "payload": receipt.model_dump_json(),
            },
        )

    def _pin_profile_release(
        self,
        *,
        relation: Literal["profile_release_session_pins", "profile_release_result_pins"],
        owner_column: Literal["session_ref", "result_ref"],
        owner_ref: str,
        kind: Literal["SESSION", "RESULT"],
    ) -> ProfileReleasePin:
        action = f"PIN_{kind}"
        for attempt in range(3):
            try:
                with self._factory() as session:
                    session.connection(execution_options={"isolation_level": "REPEATABLE READ"})
                    stored = session.execute(
                        text(
                            f"SELECT release_sha256, pin_sha256 FROM dev_eval.{relation} "
                            f"WHERE {owner_column} = :owner_ref"
                        ),
                        {"owner_ref": owner_ref},
                    ).one_or_none()
                    if stored is not None:
                        return ProfileReleasePin(
                            pin_kind=kind,
                            owner_ref=owner_ref,
                            release_sha256=stored.release_sha256,
                            pin_sha256=stored.pin_sha256,
                        )
                    active = session.execute(
                        text(
                            "SELECT release_sha256, receipt_sha256 FROM "
                            "dev_eval.profile_release_active_pointer "
                            "WHERE slot = 'DEV'"
                        )
                    ).one_or_none()
                    if active is None:
                        raise ValueError("cannot pin without an active profile release")
                    provenance_is_valid = session.execute(
                        text(
                            "SELECT "
                            "dev_eval.validate_active_profile_release_for_pin_dispatch_v1("
                            ":release, :receipt)"
                        ),
                        {
                            "release": active.release_sha256,
                            "receipt": active.receipt_sha256,
                        },
                    ).scalar_one()
                    if not provenance_is_valid:
                        raise ValueError("active profile release provenance is invalid")
                    pin = ProfileReleasePin(
                        pin_kind=kind,
                        owner_ref=owner_ref,
                        release_sha256=active.release_sha256,
                    )
                    session.execute(
                        text(
                            f"INSERT INTO dev_eval.{relation} "
                            f"({owner_column}, release_sha256, pin_sha256) "
                            f"VALUES (:owner_ref, :release, :pin) "
                            f"ON CONFLICT ({owner_column}) DO NOTHING"
                        ),
                        {
                            "owner_ref": owner_ref,
                            "release": active.release_sha256,
                            "pin": pin.pin_sha256,
                        },
                    )
                    stored = session.execute(
                        text(
                            f"SELECT release_sha256, pin_sha256 FROM dev_eval.{relation} "
                            f"WHERE {owner_column} = :owner_ref"
                        ),
                        {"owner_ref": owner_ref},
                    ).one_or_none()
                    if stored is None:
                        continue
                    session.commit()
                    return ProfileReleasePin(
                        pin_kind=kind,
                        owner_ref=owner_ref,
                        release_sha256=stored.release_sha256,
                        pin_sha256=stored.pin_sha256,
                    )
            except DBAPIError as error:
                if not self._is_serialization_failure(error):
                    raise
                if attempt == 2:
                    raise ProfileReleaseRetryableAbortError(action=action) from error
        raise ProfileReleaseRetryableAbortError(action=action)

    def pin_profile_release_session(self, session_ref: str) -> ProfileReleasePin:
        return self._pin_profile_release(
            relation="profile_release_session_pins",
            owner_column="session_ref",
            owner_ref=session_ref,
            kind="SESSION",
        )

    def get_profile_release_session_pin(
        self,
        session_ref: str,
    ) -> ProfileReleaseSessionPinProjection | None:
        with self._factory() as session:
            stored = session.execute(
                text(
                    "SELECT session_ref, release_sha256, pin_sha256, pinned_at FROM "
                    "dev_eval.profile_release_session_pins WHERE session_ref = :session_ref"
                ),
                {"session_ref": session_ref},
            ).one_or_none()
            if stored is None:
                return None
            return ProfileReleaseSessionPinProjection(
                session_ref=stored.session_ref,
                release_sha256=stored.release_sha256,
                pin_sha256=stored.pin_sha256,
                pinned_at=stored.pinned_at,
            )

    def pin_profile_release_result(self, result_ref: str) -> ProfileReleasePin:
        return self._pin_profile_release(
            relation="profile_release_result_pins",
            owner_column="result_ref",
            owner_ref=result_ref,
            kind="RESULT",
        )


__all__ = [
    "AcceptedHeadReceipt",
    "AcceptedEvidenceReviewHead",
    "AcceptedLabelHead",
    "EvaluationRepository",
    "LabelSubmissionStatus",
    "StoredLabelRevision",
    "EvidenceReviewChain",
    "EvidenceReviewQueue",
    "EvidenceReviewReceipt",
    "ReviewedEvidenceManifest",
]
