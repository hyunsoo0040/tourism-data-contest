"""Deterministic, fail-closed reconciliation over a validated collection report."""

from __future__ import annotations

import hashlib
import json
import os
import unicodedata
from collections import Counter, defaultdict
from pathlib import Path

from pydantic import ValidationError

from itda.contracts.catalog_collection import (
    CollectionAttempt,
    CollectionReport,
    LiveReportValidation,
    NormalizedCandidate,
)
from itda.contracts.crosswalk import (
    CollectionLineage,
    CrosswalkActivationEvent,
    CrosswalkReviewArtifact,
    CrosswalkRevision,
    IdentityEvidence,
    Provider,
    RelationshipProposal,
    RelationshipReviewArtifact,
    RelationshipRevision,
    build_hard_components,
    propose_identity_link,
)
from itda.domain.canonical import canonical_json_bytes, canonical_sha256


def _sha256_bytes(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def _normalize_title(value: str) -> str:
    normalized = unicodedata.normalize("NFKC", value)
    return " ".join(normalized.split()).casefold()


def _load_validated_collection(
    collection_report_path: Path,
) -> tuple[CollectionReport, LiveReportValidation, CollectionLineage]:
    """Validate semantic hashes, exact bytes, completion, and recovery history."""

    try:
        report_bytes = collection_report_path.read_bytes()
        report = CollectionReport.model_validate_json(report_bytes)
    except (OSError, ValidationError) as exc:
        raise ValueError("collection report is unavailable or invalid") from exc

    validation_path = collection_report_path.with_name("live-report-validation.json")
    try:
        validation_bytes = validation_path.read_bytes()
        validation = LiveReportValidation.model_validate_json(validation_bytes)
    except (OSError, ValidationError) as exc:
        raise ValueError("live collection validation is unavailable or invalid") from exc
    if not validation.valid:
        raise ValueError("live collection validation did not pass")
    if validation.report_sha256 != report.report_sha256:
        raise ValueError("live validation is not bound to the collection report")
    if validation.collection_plan_sha256 != report.collection_plan_sha256:
        raise ValueError("live validation is not bound to the collection plan")
    if validation.actual_unique_candidate_count != len(report.candidates):
        raise ValueError("live validation candidate count does not match report")

    identities = {item.request_identity for item in report.request_identities}
    latest: dict[str, CollectionAttempt] = {}
    for attempt in report.attempts:
        if attempt.request_identity not in identities:
            raise ValueError("collection attempt is outside the reviewed request plan")
        previous = latest.get(attempt.request_identity)
        if previous is None or attempt.attempt_number >= previous.attempt_number:
            latest[attempt.request_identity] = attempt
    if set(latest) != identities:
        raise ValueError("not every request identity has a terminal attempt")
    latest_success_count = sum(attempt.terminal_state == "SUCCESS" for attempt in latest.values())
    if latest_success_count != len(identities):
        raise ValueError("reconciliation requires 33/33 latest request successes")

    provider_counts: Counter[Provider] = Counter(item.provider for item in report.candidates)
    expected_providers: tuple[Provider, ...] = (
        "TOUR_API",
        "ODII",
        "TOURISM_PHOTO",
    )
    missing_providers = tuple(
        provider for provider in expected_providers if provider_counts[provider] == 0
    )
    candidate_projection = [item.model_dump(mode="json") for item in report.candidates]
    lineage = CollectionLineage(
        collection_report_file_sha256=_sha256_bytes(report_bytes),
        collection_report_sha256=report.report_sha256,
        live_validation_file_sha256=_sha256_bytes(validation_bytes),
        collection_plan_sha256=report.collection_plan_sha256,
        seed_manifest_sha256=report.seed_manifest_sha256,
        normalized_candidates_sha256=canonical_sha256(candidate_projection),
        candidate_count=len(report.candidates),
        request_identity_count=len(identities),
        latest_success_count=latest_success_count,
        historical_success_count=sum(
            attempt.terminal_state == "SUCCESS" for attempt in report.attempts
        ),
        historical_operator_action_count=sum(
            attempt.terminal_state == "TERMINAL_OPERATOR_ACTION" for attempt in report.attempts
        ),
        historical_http_403_count=sum(attempt.http_status == 403 for attempt in report.attempts),
        provider_candidate_counts={
            provider: provider_counts[provider] for provider in expected_providers
        },
        missing_normalized_providers=missing_providers,
    )
    return report, validation, lineage


def _candidate_evidence(candidate: NormalizedCandidate) -> IdentityEvidence:
    evidence_payload = {
        "candidate_id": candidate.candidate_id,
        "provider": candidate.provider,
        "official_dataset_id": candidate.official_dataset_id,
        "provider_content_id": candidate.provider_content_id,
        "name_ko": candidate.name_ko,
        "gyeongju_evidence": candidate.gyeongju_evidence,
        "request_identity": candidate.request_identity,
        "raw_response_sha256": candidate.raw_response_sha256,
        "permission_snapshot_sha256": candidate.permission_snapshot_sha256,
    }
    return IdentityEvidence(
        provider=candidate.provider,
        source_alias_id=candidate.provider_content_id,
        normalized_title=_normalize_title(candidate.name_ko),
        gyeongju_address=None,
        latitude=None,
        longitude=None,
        hierarchy_path=(),
        evidence_sha256=canonical_sha256(evidence_payload),
        official_dataset_id=candidate.official_dataset_id,
        candidate_id=candidate.candidate_id,
        request_identity=candidate.request_identity,
        raw_response_sha256=candidate.raw_response_sha256,
        permission_snapshot_sha256=candidate.permission_snapshot_sha256,
    )


def reconcile_crosswalk(
    *,
    collection_report_path: Path,
    previous_revision_path: Path | None,
    proposal_algorithm_version: str,
) -> CrosswalkReviewArtifact:
    """Create inactive exact-only proposals from every actual report candidate."""

    report, _validation, lineage = _load_validated_collection(collection_report_path)
    grouped: dict[str, list[IdentityEvidence]] = defaultdict(list)
    for candidate in report.candidates:
        evidence = _candidate_evidence(candidate)
        grouped[evidence.normalized_title].append(evidence)

    proposals = tuple(
        sorted(
            (
                propose_identity_link(
                    evidence,
                    proposal_algorithm_version=proposal_algorithm_version,
                    collection_report_sha256=report.report_sha256,
                )
                for _, evidence in sorted(grouped.items())
            ),
            key=lambda item: item.proposal_id,
        )
    )
    revisions: tuple[CrosswalkRevision, ...] = ()
    activation_events: tuple[CrosswalkActivationEvent, ...] = ()
    if previous_revision_path is not None:
        try:
            previous = CrosswalkReviewArtifact.model_validate_json(
                previous_revision_path.read_bytes()
            )
        except (OSError, ValidationError) as exc:
            raise ValueError("previous crosswalk review is unavailable or invalid") from exc
        revisions = previous.revisions
        activation_events = previous.activation_events

    proposal_payloads = [proposal.model_dump(mode="json") for proposal in proposals]
    revision_payloads = [revision.model_dump(mode="json") for revision in revisions]
    event_payloads = [event.model_dump(mode="json") for event in activation_events]
    fields = {
        "schema_version": "crosswalk-review-v1",
        "artifact_status": "PENDING_REVIEW",
        "proposal_algorithm_version": proposal_algorithm_version,
        "source_lineage": lineage.model_dump(mode="json"),
        "generated_at": report.generated_at.isoformat().replace("+00:00", "Z"),
        "proposals": proposal_payloads,
        "revisions": revision_payloads,
        "activation_events": event_payloads,
    }
    return CrosswalkReviewArtifact.model_validate(
        {**fields, "artifact_sha256": canonical_sha256(fields)}
    )


def _relationship_proposal(
    *,
    left: IdentityEvidence,
    right: IdentityEvidence,
    crosswalk_proposal_sha256: str,
    collection_report_sha256: str,
    proposal_algorithm_version: str,
    score: int,
) -> RelationshipProposal:
    if left.candidate_id is None or right.candidate_id is None:
        raise ValueError("relationship proposal requires candidate subject references")
    left_ref, right_ref = sorted((left.candidate_id, right.candidate_id))
    evidence_sha256 = canonical_sha256(
        {
            "left_evidence_sha256": left.evidence_sha256,
            "right_evidence_sha256": right.evidence_sha256,
            "source_crosswalk_proposal_sha256": crosswalk_proposal_sha256,
        }
    )
    fields = {
        "schema_version": "catalog-relationship-proposal-v1",
        "proposal_algorithm_version": proposal_algorithm_version,
        "left_subject_ref": left_ref,
        "right_subject_ref": right_ref,
        "relationship_type": "DUPLICATE_EQUIVALENT",
        "status": "PENDING_REVIEW",
        "score": score,
        "evidence_sha256": evidence_sha256,
        "evidence_reason": "EXACT_TITLE_ONLY_REQUIRES_HUMAN_SEMANTIC_REVIEW",
        "source_crosswalk_proposal_sha256": crosswalk_proposal_sha256,
        "collection_report_sha256": collection_report_sha256,
        "activation_event": None,
    }
    return RelationshipProposal.model_validate({**fields, "proposal_id": canonical_sha256(fields)})


def reconcile_relationships(
    *,
    crosswalk_review: CrosswalkReviewArtifact,
    previous_relationship_path: Path | None,
    proposal_algorithm_version: str,
) -> RelationshipReviewArtifact:
    """Create inactive typed suggestions; only reviewed history forms components."""

    relationship_proposals: list[RelationshipProposal] = []
    for crosswalk_proposal in crosswalk_review.proposals:
        evidence = tuple(
            sorted(
                crosswalk_proposal.evidence,
                key=lambda item: (
                    item.candidate_id or "",
                    item.provider,
                    item.source_alias_id,
                ),
            )
        )
        if len(evidence) < 2:
            continue
        anchor = evidence[0]
        for other in evidence[1:]:
            relationship_proposals.append(
                _relationship_proposal(
                    left=anchor,
                    right=other,
                    crosswalk_proposal_sha256=crosswalk_proposal.proposal_id,
                    collection_report_sha256=(
                        crosswalk_review.source_lineage.collection_report_sha256
                    ),
                    proposal_algorithm_version=proposal_algorithm_version,
                    score=crosswalk_proposal.score,
                )
            )
    proposals = tuple(sorted(relationship_proposals, key=lambda item: item.proposal_id))

    revisions: tuple[RelationshipRevision, ...] = ()
    if previous_relationship_path is not None and previous_relationship_path.exists():
        try:
            previous = RelationshipReviewArtifact.model_validate_json(
                previous_relationship_path.read_bytes()
            )
        except (OSError, ValidationError) as exc:
            raise ValueError("previous relationship review is unavailable or invalid") from exc
        revisions = previous.revisions
    hard_components = build_hard_components(revisions)
    fields = {
        "schema_version": "relationship-review-v1",
        "artifact_status": "PENDING_REVIEW",
        "proposal_algorithm_version": proposal_algorithm_version,
        "source_lineage": crosswalk_review.source_lineage.model_dump(mode="json"),
        "source_crosswalk_artifact_sha256": crosswalk_review.artifact_sha256,
        "generated_at": crosswalk_review.generated_at.isoformat().replace("+00:00", "Z"),
        "proposals": [item.model_dump(mode="json") for item in proposals],
        "revisions": [item.model_dump(mode="json") for item in revisions],
        "hard_components": hard_components.model_dump(mode="json"),
    }
    return RelationshipReviewArtifact.model_validate(
        {**fields, "artifact_sha256": canonical_sha256(fields)}
    )


def write_restricted_artifact(path: Path, payload: object) -> None:
    """Publish deterministic review bytes once with private permissions."""

    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    os.chmod(path.parent, 0o700)
    artifact_bytes = canonical_json_bytes(payload)
    try:
        with path.open("xb") as handle:
            os.chmod(path, 0o600)
            handle.write(artifact_bytes)
            handle.flush()
            os.fsync(handle.fileno())
    except FileExistsError as exc:
        raise ValueError("restricted review artifact already exists") from exc


def load_json_object(path: Path) -> dict[str, object]:
    try:
        payload = json.loads(path.read_bytes())
    except (OSError, json.JSONDecodeError) as exc:
        raise ValueError("JSON artifact is unavailable or invalid") from exc
    if not isinstance(payload, dict):
        raise ValueError("JSON artifact must be an object")
    return payload


__all__ = [
    "reconcile_crosswalk",
    "reconcile_relationships",
    "write_restricted_artifact",
]
