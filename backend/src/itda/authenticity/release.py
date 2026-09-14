"""Portable immutable assessment releases and honest automated validation receipts."""

from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime
from pathlib import Path, PurePosixPath
from typing import Any, Literal, Self

from pydantic import Field, model_validator

from itda.authenticity.auxiliary import Auxiliary
from itda.authenticity.batch import write_once
from itda.authenticity.contracts import Assessment
from itda.authenticity.publication_scope import PublicationSelection
from itda.authenticity.rubric import CONSTRUCT_VERSION, RUBRIC_SHA256
from itda.authenticity.scoring import verify_assessment
from itda.contracts.base import Sha256, StableId, StrictContract, require_utc
from itda.domain.canonical import canonical_sha256


class ReleaseMember(StrictContract):
    place_id: StableId
    assessment_sha256: Sha256
    file: str
    file_sha256: Sha256

    @model_validator(mode="after")
    def path(self) -> Self:
        path = PurePosixPath(self.file)
        if path.is_absolute() or ".." in path.parts or self.file != path.as_posix():
            raise ValueError("RELEASE_MEMBER_PATH_UNSAFE")
        if self.file != f"assessments/{self.assessment_sha256}.json":
            raise ValueError("RELEASE_MEMBER_PATH_NOT_CONTENT_ADDRESSED")
        return self


class Release(StrictContract):
    schema_version: Literal["authenticity-release.v1"] = "authenticity-release.v1"
    construct_version: Literal["authenticity-construct-v1"] = CONSTRUCT_VERSION
    rubric_sha256: Sha256 = RUBRIC_SHA256
    policy_sha256: Sha256
    scope: Literal["DEVELOPMENT", "PUBLIC"]
    expected_place_count: int = Field(strict=True, ge=1, le=10000)
    members: tuple[ReleaseMember, ...] = Field(min_length=1, max_length=10000)
    membership_sha256: Sha256
    forbidden_pairs: tuple[tuple[StableId, StableId], ...] = ()
    parent_manifest_sha256: Sha256
    auxiliary_sha256: Sha256
    validation_report_sha256: Sha256
    created_at: datetime
    release_sha256: Sha256

    @model_validator(mode="after")
    def identity(self) -> Self:
        require_utc(self.created_at, field_name="created_at")
        if self.rubric_sha256 != RUBRIC_SHA256:
            raise ValueError("RELEASE_RUBRIC_MISMATCH")
        ids = tuple(m.place_id for m in self.members)
        if ids != tuple(sorted(set(ids))) or len(ids) != self.expected_place_count:
            raise ValueError("RELEASE_MEMBERSHIP_INCOMPLETE_OR_DUPLICATED")
        if self.membership_sha256 != canonical_sha256(list(ids)):
            raise ValueError("RELEASE_MEMBERSHIP_DIGEST_MISMATCH")
        if self.forbidden_pairs != tuple(sorted(set(self.forbidden_pairs))) or any(
            a >= b or a not in ids or b not in ids for a, b in self.forbidden_pairs
        ):
            raise ValueError("RELEASE_RELATIONS_INVALID")
        if self.release_sha256 != canonical_sha256(
            self.model_dump(mode="json", exclude={"release_sha256"})
        ):
            raise ValueError("RELEASE_DIGEST_MISMATCH")
        return self


def build_release(
    *,
    assessments: tuple[Assessment, ...],
    directory: Path,
    expected_ids: tuple[str, ...],
    parent_manifest_sha256: str,
    scope: Literal["DEVELOPMENT", "PUBLIC"],
    forbidden_pairs: tuple[tuple[str, str], ...] = (),
    created_at: datetime | None = None,
    auxiliary: Auxiliary | None = None,
    publication_selection: PublicationSelection | None = None,
) -> Release:
    ids = tuple(sorted(a.source.place.place_id for a in assessments))
    if ids != tuple(sorted(set(expected_ids))) or len(ids) != len(set(ids)):
        raise ValueError("RELEASE_DOES_NOT_COVER_DECLARED_INPUT_MEMBERSHIP")
    if publication_selection is not None:
        publication_selection.verify_release(ids, parent_manifest_sha256)
    policies = {a.policy.policy_sha256 for a in assessments}
    if len(policies) != 1:
        raise ValueError("RELEASE_REQUIRES_ONE_SCORING_POLICY")
    auxiliary = auxiliary or Auxiliary()
    if not (set(auxiliary.moods) | set(auxiliary.facilities) | set(auxiliary.photos)) <= set(ids):
        raise ValueError("AUXILIARY_OUTSIDE_RELEASE")
    write_once(directory / "auxiliary.json", auxiliary.model_dump(mode="json"))
    members = []
    counts = {"H": 0, "E": 0, "R": 0}
    for assessment in sorted(assessments, key=lambda a: a.source.place.place_id):
        verify_assessment(assessment)
        if scope == "PUBLIC" and assessment.source.place.cohort == "synthetic":
            raise ValueError("SYNTHETIC_ASSESSMENT_CANNOT_BE_PUBLIC")
        file = f"assessments/{assessment.assessment_sha256}.json"
        write_once(directory / file, assessment.model_dump(mode="json"))
        members.append(
            {
                "place_id": assessment.source.place.place_id,
                "assessment_sha256": assessment.assessment_sha256,
                "file": file,
                "file_sha256": hashlib.sha256((directory / file).read_bytes()).hexdigest(),
            }
        )
        for axis in assessment.axes:
            counts[axis.axis] += axis.value is not None
    report = {
        "schema_version": "authenticity-release-validation.v1",
        "parent_manifest_sha256": parent_manifest_sha256,
        "membership_sha256": canonical_sha256(list(ids)),
        "policy_sha256": next(iter(policies)),
        "rubric_sha256": RUBRIC_SHA256,
        "checked_assessments": len(assessments),
        "axis_coverage": counts,
        "rule_violations": 0,
        "scope": "STRUCTURAL_BINDING_AUTHORITY_AND_ARITHMETIC",
        "human_evaluation": "EXCLUDED_BY_USER",
        "semantic_accuracy": "NOT_ESTABLISHED",
        "assessment_hashes": sorted(a.assessment_sha256 for a in assessments),
    }
    if publication_selection is not None:
        report["publication_selection"] = publication_selection.model_dump(mode="json")
    report_sha = canonical_sha256(report)
    write_once(directory / "validation.json", report | {"report_sha256": report_sha})
    payload = {
        "schema_version": "authenticity-release.v1",
        "construct_version": CONSTRUCT_VERSION,
        "rubric_sha256": RUBRIC_SHA256,
        "policy_sha256": next(iter(policies)),
        "scope": scope,
        "expected_place_count": len(ids),
        "members": members,
        "membership_sha256": canonical_sha256(list(ids)),
        "forbidden_pairs": [list(p) for p in sorted(set(forbidden_pairs))],
        "parent_manifest_sha256": parent_manifest_sha256,
        "auxiliary_sha256": auxiliary.digest,
        "validation_report_sha256": report_sha,
        "created_at": (created_at or datetime.now(UTC)).isoformat().replace("+00:00", "Z"),
    }
    release = Release.model_validate(payload | {"release_sha256": canonical_sha256(payload)})
    write_once(directory / "release.json", release.model_dump(mode="json"))
    return release


def load_release(directory: Path) -> tuple[Release, tuple[Assessment, ...]]:
    release = Release.model_validate_json((directory / "release.json").read_bytes())
    auxiliary = Auxiliary.model_validate_json((directory / "auxiliary.json").read_bytes())
    if auxiliary.digest != release.auxiliary_sha256:
        raise ValueError("AUXILIARY_DIGEST_MISMATCH")
    report = json.loads((directory / "validation.json").read_text())
    if (
        report.get("report_sha256") != release.validation_report_sha256
        or canonical_sha256({k: v for k, v in report.items() if k != "report_sha256"})
        != release.validation_report_sha256
    ):
        raise ValueError("RELEASE_VALIDATION_REPORT_MISMATCH")
    assessments = []
    for member in release.members:
        file = directory / member.file
        if not file.resolve().is_relative_to(directory.resolve()):
            raise ValueError("RELEASE_MEMBER_ESCAPES_DIRECTORY")
        raw = file.read_bytes()
        if hashlib.sha256(raw).hexdigest() != member.file_sha256:
            raise ValueError("RELEASE_MEMBER_FILE_DIGEST_MISMATCH")
        assessment = Assessment.model_validate_json(raw)
        verify_assessment(assessment)
        if (
            assessment.assessment_sha256 != member.assessment_sha256
            or assessment.source.place.place_id != member.place_id
            or assessment.policy.policy_sha256 != release.policy_sha256
        ):
            raise ValueError("RELEASE_ASSESSMENT_IDENTITY_MISMATCH")
        assessments.append(assessment)
    if report["checked_assessments"] != len(assessments) or report["assessment_hashes"] != sorted(
        a.assessment_sha256 for a in assessments
    ):
        raise ValueError("RELEASE_VALIDATION_MEMBERSHIP_MISMATCH")
    if "publication_selection" in report:
        PublicationSelection.model_validate(report["publication_selection"]).verify_release(
            tuple(m.place_id for m in release.members), release.parent_manifest_sha256
        )
    return release, tuple(assessments)


def release_summary(release: Release, assessments: tuple[Assessment, ...]) -> dict[str, Any]:
    return {
        "release_sha256": release.release_sha256,
        "scope": release.scope,
        "places": len(assessments),
        "construct_version": release.construct_version,
        "regions": sorted({a.source.place.region_name for a in assessments}),
        "human_evaluation": "EXCLUDED_BY_USER",
    }
