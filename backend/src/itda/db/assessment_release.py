"""Immutable staged grounded pairs and measured, atomic publication authority."""

from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path

from sqlalchemy import text
from sqlalchemy.orm import Session, sessionmaker

from itda.contracts.grounded_promotion import (
    GroundedPromotionGate,
    GroundedPromotionReport,
    validate_promotion_reports,
)
from itda.contracts.grounded_release import GroundedReleaseCandidate
from itda.contracts.grounded_run import GROUNDED_POLICY


class GroundedReleaseInvalid(ValueError):
    """Staged or active authority could not be independently validated."""


@dataclass(frozen=True)
class ActiveGroundedRelease:
    candidate: GroundedReleaseCandidate
    gate: GroundedPromotionGate
    generation: int
    activated_at: datetime


class AssessmentReleaseRepository:
    """Runtime can read; only administrator/closed daily-service SQL may mutate."""

    def __init__(self, factory: sessionmaker[Session]) -> None:
        self._factory = factory

    def stage(self, candidate: GroundedReleaseCandidate) -> str:
        validated = GroundedReleaseCandidate.model_validate_json(candidate.model_dump_json())
        with self._factory.begin() as session:
            digest = session.execute(
                text("SELECT app.stage_grounded_release_candidate_v1(CAST(:payload AS jsonb))"),
                {"payload": validated.model_dump_json()},
            ).scalar_one()
            if digest != validated.candidate_sha256:
                raise GroundedReleaseInvalid("staged candidate digest differs")
        return str(digest)

    stage_candidate = stage

    @staticmethod
    def _candidate(session: Session, digest: str) -> GroundedReleaseCandidate | None:
        row = (
            session.execute(
                text(
                    "SELECT candidate_sha256,raw_release_sha256,source_release_sha256,payload "
                    "FROM app.grounded_release_candidates WHERE candidate_sha256=:digest"
                ),
                {"digest": digest},
            )
            .mappings()
            .one_or_none()
        )
        if row is None:
            return None
        candidate = GroundedReleaseCandidate.model_validate(row["payload"])
        if (
            candidate.candidate_sha256 != digest
            or row["candidate_sha256"] != digest
            or candidate.raw_release.release_sha256 != row["raw_release_sha256"]
            or candidate.manifest.source_release_sha256 != row["source_release_sha256"]
        ):
            raise GroundedReleaseInvalid("candidate row metadata differs from immutable payload")
        return candidate

    def load_candidate(self, candidate_sha256: str) -> GroundedReleaseCandidate | None:
        with self._factory() as session:
            return self._candidate(session, candidate_sha256)

    get_candidate = load_candidate

    def store_report(self, report: GroundedPromotionReport) -> str:
        validated = GroundedPromotionReport.model_validate_json(report.model_dump_json())
        with self._factory.begin() as session:
            digest = session.execute(
                text("SELECT app.store_grounded_promotion_report_v1(CAST(:payload AS jsonb))"),
                {"payload": validated.model_dump_json()},
            ).scalar_one()
            if digest != validated.report_sha256:
                raise GroundedReleaseInvalid("report digest differs")
        return str(digest)

    @staticmethod
    def _report(session: Session, digest: str) -> GroundedPromotionReport:
        row = (
            session.execute(
                text(
                    "SELECT report_sha256,candidate_sha256,kind,config_sha256,payload "
                    "FROM app.grounded_promotion_reports WHERE report_sha256=:digest"
                ),
                {"digest": digest},
            )
            .mappings()
            .one_or_none()
        )
        if row is None:
            raise GroundedReleaseInvalid("actual promotion report is missing")
        report = GroundedPromotionReport.model_validate(row["payload"])
        if report.report_sha256 != digest or any(
            row[key] != getattr(report, key)
            for key in ("report_sha256", "candidate_sha256", "kind", "config_sha256")
        ):
            raise GroundedReleaseInvalid("report metadata differs from actual payload")
        return report

    def load_report(self, report_sha256: str) -> GroundedPromotionReport:
        with self._factory() as session:
            return self._report(session, report_sha256)

    @classmethod
    def _reports(
        cls, session: Session, gate: GroundedPromotionGate
    ) -> tuple[GroundedPromotionReport, ...]:
        return tuple(
            cls._report(session, digest)
            for digest in (
                gate.source_ablation_sha256,
                gate.axis_comparison_sha256,
                gate.api_ui_verification_sha256,
            )
        )

    def promote(
        self,
        gate: GroundedPromotionGate,
        *,
        expected_active_sha256: str | None = None,
        expected_config_sha256: str = GROUNDED_POLICY.sha256,
    ) -> int:
        """Compare-and-swap only after loading/revalidating actual three report bodies."""
        validated = GroundedPromotionGate.model_validate_json(gate.model_dump_json())
        if validated.config_sha256 != expected_config_sha256:
            raise GroundedReleaseInvalid("promotion config differs from selected server policy")
        with self._factory.begin() as session:
            candidate = self._candidate(session, validated.candidate_sha256)
            if candidate is None:
                raise GroundedReleaseInvalid("promotion candidate is not staged")
            reports = self._reports(session, validated)
            validate_promotion_reports(
                validated, reports, candidate_created_at=candidate.created_at
            )
            generation = session.execute(
                text(
                    "SELECT app.promote_grounded_release_pair_v1(CAST(:payload AS jsonb),:expected)"
                ),
                {"payload": validated.model_dump_json(), "expected": expected_active_sha256},
            ).scalar_one()
        return int(generation)

    def load_active_record(self) -> ActiveGroundedRelease | None:
        with self._factory() as session:
            # One joined read observes a complete pointer+gate pair even while a
            # concurrent promotion replaces it. Referenced artifacts are immutable.
            row = (
                session.execute(
                    text(
                        "SELECT a.candidate_sha256,a.gate_sha256,a.generation,a.activated_at,"
                        "g.payload,g.candidate_sha256 AS gate_candidate,g.config_sha256 "
                        "FROM app.grounded_release_active a "
                        "JOIN app.grounded_promotion_gates g USING(gate_sha256) "
                        "WHERE a.singleton"
                    )
                )
                .mappings()
                .one_or_none()
            )
            if row is None:
                return None
            candidate = self._candidate(session, row["candidate_sha256"])
            if candidate is None:
                raise GroundedReleaseInvalid("active candidate is missing")
            gate = GroundedPromotionGate.model_validate(row["payload"])
            if (
                gate.gate_sha256 != row["gate_sha256"]
                or gate.candidate_sha256 != candidate.candidate_sha256
                or row["gate_candidate"] != candidate.candidate_sha256
                or gate.config_sha256 != row["config_sha256"]
            ):
                raise GroundedReleaseInvalid("active pointer and gate authority differ")
            validate_promotion_reports(
                gate, self._reports(session, gate), candidate_created_at=candidate.created_at
            )
            return ActiveGroundedRelease(
                candidate, gate, int(row["generation"]), row["activated_at"]
            )

    def load_active(self) -> GroundedReleaseCandidate | None:
        active = self.load_active_record()
        return active.candidate if active else None

    def load_promotion(self, generation: int) -> ActiveGroundedRelease | None:
        """Read immutable activation history without assuming a candidate is still active."""
        with self._factory() as session:
            row = (
                session.execute(
                    text(
                        "SELECT h.candidate_sha256,h.gate_sha256,h.generation,h.activated_at,"
                        "g.payload FROM app.grounded_release_promotions h "
                        "JOIN app.grounded_promotion_gates g USING(gate_sha256) "
                        "WHERE h.generation=:generation"
                    ),
                    {"generation": generation},
                )
                .mappings()
                .one_or_none()
            )
            if row is None:
                return None
            candidate = self._candidate(session, row["candidate_sha256"])
            if candidate is None:
                raise GroundedReleaseInvalid("promoted candidate is missing")
            gate = GroundedPromotionGate.model_validate(row["payload"])
            if (
                gate.gate_sha256 != row["gate_sha256"]
                or gate.candidate_sha256 != candidate.candidate_sha256
            ):
                raise GroundedReleaseInvalid("promotion history and gate authority differ")
            validate_promotion_reports(
                gate, self._reports(session, gate), candidate_created_at=candidate.created_at
            )
            return ActiveGroundedRelease(
                candidate, gate, int(row["generation"]), row["activated_at"]
            )


GroundedReleaseRepository = AssessmentReleaseRepository


def load_candidate_from_directory(directory: Path, raw_release: object) -> GroundedReleaseCandidate:
    """Rebuild complete authority from every immutable batch output, never status alone."""
    from itda.contracts.destination_mood import DestinationMoodBundle
    from itda.contracts.source_assessment import AssessmentBundle, AssessmentReleaseManifest

    root = Path(directory)
    manifest = AssessmentReleaseManifest.model_validate_json((root / "manifest.json").read_bytes())
    report = json.loads((root / "run.json").read_text(encoding="utf-8"))
    context = json.loads((root / "context.json").read_text(encoding="utf-8"))
    if context.get("source_release_sha256") != manifest.source_release_sha256:
        raise GroundedReleaseInvalid("batch context and manifest authority differ")
    ids = tuple(member.place_id for member in manifest.members)
    stems = tuple(pid.rsplit(":", 1)[-1] for pid in ids)
    if any(
        len(stem) != 64 or any(char not in "0123456789abcdef" for char in stem) for stem in stems
    ):
        raise GroundedReleaseInvalid("batch place path is not canonical")
    assessments = tuple(
        AssessmentBundle.model_validate_json((root / "assessments" / (stem + ".json")).read_bytes())
        for stem in stems
    )
    moods = tuple(
        DestinationMoodBundle.model_validate_json((root / "moods" / (stem + ".json")).read_bytes())
        for stem in stems
    )
    sources = tuple(
        json.loads((root / "sources" / (stem + ".json")).read_text(encoding="utf-8"))
        for stem in stems
    )
    created = datetime.fromisoformat(context["created_at"].replace("Z", "+00:00"))
    draft = GroundedReleaseCandidate.model_construct(
        raw_release=raw_release,
        manifest=manifest,
        assessments=assessments,
        moods=moods,
        source_snapshots=sources,
        analysis_run=report,
        created_at=created,
        candidate_sha256="0" * 64,
    )
    from itda.domain.canonical import canonical_sha256

    payload = draft.model_dump(mode="json", exclude={"candidate_sha256"})
    candidate = GroundedReleaseCandidate.model_validate(
        payload | {"candidate_sha256": canonical_sha256(payload)}
    )
    if (root / "candidate.json").is_file():
        previous = GroundedReleaseCandidate.model_validate_json(
            (root / "candidate.json").read_bytes()
        )
        if previous != candidate:
            raise GroundedReleaseInvalid("candidate differs from its batch outputs")
    return candidate
