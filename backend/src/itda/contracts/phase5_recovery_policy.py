"""Self-authenticating provider-free recovery policy for Phase 5.

This module is the narrow authority shared by recovery generation, candidate
construction, recommendation, smoke, and activation.  It deliberately binds
only public source identities and typed relation/suite projections; it never
loads provider responses, profile bodies, or protected Plan 05-16 evidence.
"""

from __future__ import annotations

import hashlib
import hmac
import json
from collections.abc import Mapping, Sequence
from enum import StrEnum
from pathlib import Path
from typing import Annotated, Literal, Self

from pydantic import Field, model_validator

from itda.contracts.base import Sha256, StrictContract
from itda.contracts.hard_duplicate_adjudication import (
    AUTHORITATIVE_RELATIONSHIP_LEAVES_SHA256,
    CATALOG_ACTIVATION_EVENT_SHA256,
    CATALOG_APPROVAL_SHA256,
    CATALOG_REVISION_SHA256,
    DEV_INPUT_AUTHORITY_SHA256,
    DEV_MEMBERSHIP_SHA256,
    HARD_DUPLICATE_ADJUDICATION_SHA256,
    RELATIONSHIP_AUTOMATIC_ROOT_SHA256,
    RELATIONSHIP_UNRESOLVED_ROOT_SHA256,
    REVIEWED_RELATIONSHIP_LEAVES_ROOT_SHA256,
    load_hard_duplicate_adjudication,
)
from itda.domain.canonical import canonical_sha256

REPOSITORY_ROOT = Path(__file__).resolve().parents[4]
SCENARIO_SOURCE_PATH = REPOSITORY_ROOT / "backend/tests/evals/phase5/recommendation_scenarios.json"
HISTORICAL_05_16_PLAN_PATH = (
    REPOSITORY_ROOT
    / ".planning/milestones/v1.0-phases/05-complete-no-photo-recommendation-journey/05-16-PLAN.md"
)
HISTORICAL_05_16_SUMMARY_PATH = (
    REPOSITORY_ROOT
    / ".planning/milestones/v1.0-phases"
    / "05-complete-no-photo-recommendation-journey"
    / "05-16-SUMMARY.md"
)
HISTORICAL_05_16_TERMINAL_PATH = (
    REPOSITORY_ROOT / "artifacts/reports/phase5/fresh-provider-terminal.json"
)

SCENARIO_SOURCE_FILE_SHA256 = (
    "793f11140210c3ea9dda0ca801e86f37a848c144c81afd0f73f4124674617115"
)
SCENARIO_DATASET_SHA256 = "7e2a088fe60dae23fd565db71fd6b3a7edeeece629fc644d4ac746eb9df07f8d"
ACTIVATION_SUITE_SHA256 = "6e049343d62770b8437ce9e29220fcd31a0e7b30d9b888bc3d9a823421fc5659"
CONTRAST_SUITE_SHA256 = "1f9caa8dbb010ca64acffdf1c174c383e08b4fc04ede9b7aece10af35cb4c6c9"
CANNOT_COAPPEAR_AUTHORITY_SHA256 = (
    "eefb20e6d27ba2bb1b743f72c0ad9961ed09125f94d73546858ddb9692a6bb70"
)

# These are public file/self-digests only.  No profile, response, or protected
# body from the failed 05-16 run is imported into the current policy.
HISTORICAL_05_16_PLAN_SHA256 = "4f13db73ad8d50eaa0bcb316faa693910f4e128c282dbdbcf51d94ffad9c8352"
HISTORICAL_05_16_SUMMARY_SHA256 = "0a4339b28f445a68dfb1d311569835f202540e68f1057a196db9619a1a4ff68f"
HISTORICAL_05_16_TERMINAL_FILE_SHA256 = (
    "14d16266cedee68d132e3992b82367643de3658b7f489172e2153f1b85019675"
)
HISTORICAL_05_16_TERMINAL_SHA256 = (
    "65adc81f59548debd0d964dced0ee6eb6f8ee14e3045c64b9605d4b589b298da"
)

CANONICAL_SCENARIO_IDS = (
    "critical-01-history-morning-solo",
    "critical-02-image-sunset-partner",
    "critical-03-rest-daytime-seniors",
    "critical-04-balanced-family-car",
    "critical-05-history-evening-walk",
    "critical-06-image-group-transit",
    "critical-07-rest-outdoor-low-crowd",
    "critical-08-balanced-undecided",
)
CANONICAL_CONTRAST_PAIRS = (
    (CANONICAL_SCENARIO_IDS[0], CANONICAL_SCENARIO_IDS[1]),
    (CANONICAL_SCENARIO_IDS[0], CANONICAL_SCENARIO_IDS[2]),
    (CANONICAL_SCENARIO_IDS[1], CANONICAL_SCENARIO_IDS[2]),
    (CANONICAL_SCENARIO_IDS[0], CANONICAL_SCENARIO_IDS[4]),
    (CANONICAL_SCENARIO_IDS[1], CANONICAL_SCENARIO_IDS[5]),
    (CANONICAL_SCENARIO_IDS[2], CANONICAL_SCENARIO_IDS[6]),
    (CANONICAL_SCENARIO_IDS[3], CANONICAL_SCENARIO_IDS[7]),
)

ScenarioId = Annotated[str, Field(strict=True, pattern=r"^critical-[0-9]{2}-[a-z0-9-]+$")]
PlaceId = Annotated[str, Field(strict=True, min_length=1, max_length=160)]


class ConfidenceBand(StrEnum):
    AUDIT_ONLY = "EVIDENCE_AUDIT_ONLY"
    LIMITED_MISMATCH_SUPPRESSED = "EVIDENCE_LIMITED_MISMATCH_SUPPRESSED"
    LIMITED_MISMATCH_AVAILABLE = "EVIDENCE_LIMITED_MISMATCH_AVAILABLE"
    SUPPORTED = "EVIDENCE_SUPPORTED"


def _read_bounded(path: Path, *, maximum: int = 512 * 1024) -> bytes:
    """Read a tracked public artifact without accepting an oversized source."""

    if path.is_symlink() or not path.is_file():
        raise ValueError(f"recovery policy source is not a regular file: {path.name}")
    payload = path.read_bytes()
    if not 0 < len(payload) <= maximum:
        raise ValueError("recovery policy source is outside its bounded size")
    return payload


def _historical_file_sha256(path: Path, expected: str) -> str:
    actual = hashlib.sha256(_read_bounded(path, maximum=2 * 1024 * 1024)).hexdigest()
    if not hmac.compare_digest(actual, expected):
        raise ValueError(f"historical public artifact drifted: {path.name}")
    return actual


def _validate_canonical_scenario_source() -> None:
    payload = _read_bounded(SCENARIO_SOURCE_PATH)
    if hashlib.sha256(payload).hexdigest() != SCENARIO_SOURCE_FILE_SHA256:
        raise ValueError("Phase 5 scenario source file digest drifted")
    decoded = json.loads(payload)
    if not isinstance(decoded, dict) or not isinstance(decoded.get("scenarios"), list):
        raise ValueError("Phase 5 scenario source shape drifted")
    if canonical_sha256(decoded["scenarios"]) != SCENARIO_DATASET_SHA256:
        raise ValueError("Phase 5 scenario dataset digest drifted")
    critical = tuple(
        row.get("scenario_id")
        for row in decoded["scenarios"]
        if isinstance(row, dict) and str(row.get("scenario_id", "")).startswith("critical-")
    )
    if critical != CANONICAL_SCENARIO_IDS:
        raise ValueError("Phase 5 critical scenario IDs drifted")


class CannotCoappearAuthority(StrictContract):
    """Typed, independent projection of the human relationship authority.

    ``pairs`` is explicit even when empty.  It is not the hard-duplicate
    partition: singleton duplicate groups and co-appearance edges have
    separate identities and are applied in separate stages.
    """

    schema_version: Literal["itda.phase5-cannot-coappear-authority.v1"]
    scope: Literal["CANONICAL_DEV_24"]
    source_dev_authority_sha256: Sha256
    dev_membership_sha256: Sha256
    catalog_revision_sha256: Sha256
    catalog_approval_sha256: Sha256
    catalog_activation_event_sha256: Sha256
    relationship_automatic_leaves_root_sha256: Sha256
    relationship_unresolved_leaves_root_sha256: Sha256
    reviewed_relationship_leaves_root_sha256: Sha256
    authoritative_relationship_leaves_sha256: Sha256
    hard_duplicate_adjudication_sha256: Sha256
    dev_place_ids: Annotated[tuple[PlaceId, ...], Field(min_length=24, max_length=24)]
    pairs: tuple[tuple[PlaceId, PlaceId], ...]
    authority_sha256: Sha256 | None = None

    @model_validator(mode="before")
    @classmethod
    def require_explicit_projection(cls, value: object) -> object:
        if not isinstance(value, Mapping) or "pairs" not in value:
            raise ValueError("cannot-coappear pair set must be explicit, including when empty")
        return value

    @model_validator(mode="after")
    def validate_authority(self) -> Self:
        if self.scope != "CANONICAL_DEV_24":
            raise ValueError("cannot-coappear scope drifted")
        if self.source_dev_authority_sha256 != DEV_INPUT_AUTHORITY_SHA256:
            raise ValueError("cannot-coappear source authority drifted")
        if self.dev_membership_sha256 != DEV_MEMBERSHIP_SHA256:
            raise ValueError("cannot-coappear DEV membership drifted")
        if self.catalog_revision_sha256 != CATALOG_REVISION_SHA256:
            raise ValueError("cannot-coappear catalog revision drifted")
        if self.catalog_approval_sha256 != CATALOG_APPROVAL_SHA256:
            raise ValueError("cannot-coappear catalog approval drifted")
        if self.catalog_activation_event_sha256 != CATALOG_ACTIVATION_EVENT_SHA256:
            raise ValueError("cannot-coappear activation event drifted")
        if self.relationship_automatic_leaves_root_sha256 != RELATIONSHIP_AUTOMATIC_ROOT_SHA256:
            raise ValueError("cannot-coappear automatic relationship root drifted")
        if self.relationship_unresolved_leaves_root_sha256 != RELATIONSHIP_UNRESOLVED_ROOT_SHA256:
            raise ValueError("cannot-coappear unresolved relationship root drifted")
        if (
            self.reviewed_relationship_leaves_root_sha256
            != REVIEWED_RELATIONSHIP_LEAVES_ROOT_SHA256
        ):
            raise ValueError("cannot-coappear reviewed relationship root drifted")
        if (
            self.authoritative_relationship_leaves_sha256
            != AUTHORITATIVE_RELATIONSHIP_LEAVES_SHA256
        ):
            raise ValueError("cannot-coappear authoritative relationship root drifted")
        if self.hard_duplicate_adjudication_sha256 != HARD_DUPLICATE_ADJUDICATION_SHA256:
            raise ValueError("cannot-coappear hard-duplicate authority drifted")
        if tuple(self.dev_place_ids) != tuple(sorted(self.dev_place_ids)):
            raise ValueError("cannot-coappear membership must be canonical and sorted")
        if len(set(self.dev_place_ids)) != 24:
            raise ValueError("cannot-coappear membership must contain 24 unique places")
        if canonical_sha256(list(self.dev_place_ids)) != self.dev_membership_sha256:
            raise ValueError("cannot-coappear membership digest drifted")
        known = set(self.dev_place_ids)
        normalized: list[tuple[str, str]] = []
        for pair in self.pairs:
            if len(pair) != 2:
                raise ValueError("cannot-coappear edges require two endpoints")
            left, right = pair
            if left == right or left not in known or right not in known:
                raise ValueError("cannot-coappear edge endpoint is not a distinct DEV place")
            if left >= right:
                raise ValueError("cannot-coappear edges must use canonical endpoint order")
            normalized.append((left, right))
        if len(normalized) != len(set(normalized)):
            raise ValueError("cannot-coappear edges must be unique and symmetric-free")
        if self.pairs != tuple(normalized):
            raise ValueError("cannot-coappear edges must use canonical tuple order")
        if self.pairs:
            expected = canonical_sha256(
                self.model_dump(mode="json", exclude={"authority_sha256"})
            )
            if self.authority_sha256 is None:
                object.__setattr__(self, "authority_sha256", expected)
            elif self.authority_sha256 != expected:
                raise ValueError("cannot-coappear authority self-digest drifted")
        elif self.authority_sha256 != CANNOT_COAPPEAR_AUTHORITY_SHA256:
            raise ValueError("explicit empty cannot-coappear authority digest drifted")
        return self

    @property
    def cannot_coappear_pairs(self) -> tuple[tuple[str, str], ...]:
        return self.pairs

    def forbids(self, left: str, right: str) -> bool:
        edge = tuple(sorted((left, right)))
        return edge in self.pairs


class ActivationScenarioBinding(StrictContract):
    """One immutable scenario identity; result bytes are downstream evidence."""

    scenario_id: ScenarioId
    status: Literal["SUCCESS"] = "SUCCESS"
    top_k: Literal[5] = 5
    binding_sha256: Sha256 | None = None

    @model_validator(mode="after")
    def validate_binding(self) -> Self:
        if self.scenario_id not in CANONICAL_SCENARIO_IDS:
            raise ValueError("scenario is not in the canonical activation suite")
        expected = canonical_sha256(self.model_dump(mode="json", exclude={"binding_sha256"}))
        if self.binding_sha256 is None:
            object.__setattr__(self, "binding_sha256", expected)
        elif self.binding_sha256 != expected:
            raise ValueError("scenario binding digest drifted")
        return self


class ActivationScenarioResult(StrictContract):
    """A complete exact-five result and its independently replayed bytes."""

    scenario_id: ScenarioId
    status: Literal["SUCCESS"]
    eligible_place_ids: Annotated[tuple[PlaceId, ...], Field(min_length=5, max_length=5)]
    result_sha256: Sha256
    replay_sha256: Sha256
    contribution_sha256: Sha256 | None = None
    result_record_sha256: Sha256 | None = None

    @model_validator(mode="after")
    def validate_result(self) -> Self:
        if self.contribution_sha256 is None:
            object.__setattr__(
                self,
                "contribution_sha256",
                canonical_sha256(
                    {"result_sha256": self.result_sha256, "scenario_id": self.scenario_id}
                ),
            )
        if self.contribution_sha256 == self.result_sha256:
            raise ValueError("scenario contribution digest must be distinct")
        if self.scenario_id not in CANONICAL_SCENARIO_IDS:
            raise ValueError("scenario result is not canonical")
        if len(set(self.eligible_place_ids)) != 5:
            raise ValueError("scenario result must contain five unique places")
        if self.result_sha256 != self.replay_sha256:
            raise ValueError(
                "scenario replay digest must equal independently replayed result bytes"
            )
        expected = canonical_sha256(self.model_dump(mode="json", exclude={"result_record_sha256"}))
        if self.result_record_sha256 is None:
            object.__setattr__(self, "result_record_sha256", expected)
        elif self.result_record_sha256 != expected:
            raise ValueError("scenario result record digest drifted")
        return self


class FrozenScenarioBinding(ActivationScenarioBinding):
    """Compatibility name for downstream recovery receipts."""


class ContrastBinding(StrictContract):
    """One of the seven predetermined personalization contrasts."""

    left_scenario_id: ScenarioId
    right_scenario_id: ScenarioId
    binding_sha256: Sha256 | None = None

    @model_validator(mode="after")
    def validate_binding(self) -> Self:
        pair = (self.left_scenario_id, self.right_scenario_id)
        if pair not in CANONICAL_CONTRAST_PAIRS:
            raise ValueError("contrast pair is not in the canonical D-32 suite")
        expected = canonical_sha256(self.model_dump(mode="json", exclude={"binding_sha256"}))
        if self.binding_sha256 is None:
            object.__setattr__(self, "binding_sha256", expected)
        elif self.binding_sha256 != expected:
            raise ValueError("contrast binding digest drifted")
        return self

    @property
    def pair(self) -> tuple[str, str]:
        return self.left_scenario_id, self.right_scenario_id


class ContrastSensitivityBinding(ContrastBinding):
    """Compatibility name for downstream contrast receipts."""


class ContrastResult(StrictContract):
    """Stored pair result proving membership/order and contribution sensitivity."""

    left_scenario_id: ScenarioId
    right_scenario_id: ScenarioId
    left_result_sha256: Sha256
    right_result_sha256: Sha256
    left_contribution_sha256: Sha256
    right_contribution_sha256: Sha256
    left_place_ids: Annotated[tuple[PlaceId, ...], Field(min_length=5, max_length=5)]
    right_place_ids: Annotated[tuple[PlaceId, ...], Field(min_length=5, max_length=5)]
    membership_or_order_changed: Literal[True] = True
    result_record_sha256: Sha256 | None = None

    @model_validator(mode="after")
    def validate_contrast(self) -> Self:
        if (self.left_scenario_id, self.right_scenario_id) not in CANONICAL_CONTRAST_PAIRS:
            raise ValueError("contrast result pair is not canonical")
        if len(set(self.left_place_ids)) != 5 or len(set(self.right_place_ids)) != 5:
            raise ValueError("contrast results must contain exact-five unique places")
        if self.left_place_ids == self.right_place_ids:
            raise ValueError("contrast pair did not change membership or order")
        if self.left_result_sha256 == self.right_result_sha256:
            raise ValueError("contrast pair reused one result digest")
        if self.left_contribution_sha256 == self.right_contribution_sha256:
            raise ValueError("contrast pair reused one contribution digest")
        expected = canonical_sha256(self.model_dump(mode="json", exclude={"result_record_sha256"}))
        if self.result_record_sha256 is None:
            object.__setattr__(self, "result_record_sha256", expected)
        elif self.result_record_sha256 != expected:
            raise ValueError("contrast result record digest drifted")
        return self

    @property
    def pair(self) -> tuple[str, str]:
        return self.left_scenario_id, self.right_scenario_id


class ActivationSuiteEvaluation(StrictContract):
    """Complete keyed D-31/D-32 evidence produced from actual kernel runs."""

    scenario_results: tuple[ActivationScenarioResult, ...]
    contrast_results: tuple[ContrastResult, ...]
    activation_suite_sha256: Sha256
    contrast_suite_sha256: Sha256
    evaluation_sha256: Sha256 | None = None

    @model_validator(mode="after")
    def validate_complete_evaluation(self) -> Self:
        scenario_map = {row.scenario_id: row for row in self.scenario_results}
        if tuple(scenario_map) != CANONICAL_SCENARIO_IDS:
            raise ValueError("activation evaluation requires exact scenario order")
        validate_activation_scenario_results(scenario_map)
        contrast_map = {row.pair: row for row in self.contrast_results}
        validate_contrast_results(contrast_map, scenarios=self.scenario_results)
        if self.activation_suite_sha256 != ACTIVATION_SUITE_SHA256:
            raise ValueError("activation evaluation suite identity drifted")
        if self.contrast_suite_sha256 != CONTRAST_SUITE_SHA256:
            raise ValueError("contrast evaluation suite identity drifted")
        expected = canonical_sha256(
            self.model_dump(mode="json", exclude={"evaluation_sha256"})
        )
        if self.evaluation_sha256 is None:
            object.__setattr__(self, "evaluation_sha256", expected)
        elif self.evaluation_sha256 != expected:
            raise ValueError("activation evaluation digest drifted")
        return self


def validate_activation_scenario_results(
    results: Mapping[str, ActivationScenarioResult | Mapping[str, object]],
) -> tuple[ActivationScenarioResult, ...]:
    """Require every canonical scenario exactly once and reject copied results."""

    if tuple(results) != CANONICAL_SCENARIO_IDS:
        raise ValueError("activation scenario result map must use exact canonical order")
    parsed = tuple(
        value
        if isinstance(value, ActivationScenarioResult)
        else ActivationScenarioResult.model_validate(value)
        for value in results.values()
    )
    if tuple(row.scenario_id for row in parsed) != CANONICAL_SCENARIO_IDS:
        raise ValueError("activation scenario result IDs do not match map keys")
    if len({row.result_sha256 for row in parsed}) != 8:
        raise ValueError("activation scenario result digest was copied or omitted")
    if any(row.status != "SUCCESS" or len(row.eligible_place_ids) != 5 for row in parsed):
        raise ValueError("activation scenario result is not exact-five success")
    return parsed


def validate_contrast_results(
    results: Mapping[tuple[str, str], ContrastResult | Mapping[str, object]],
    *,
    scenarios: Sequence[ActivationScenarioResult],
) -> tuple[ContrastResult, ...]:
    """Require all seven ordered contrasts and bind them to scenario evidence."""

    if tuple(results) != CANONICAL_CONTRAST_PAIRS:
        raise ValueError("contrast result map must use exact canonical order")
    if tuple(row.scenario_id for row in scenarios) != CANONICAL_SCENARIO_IDS:
        raise ValueError("contrast results require the complete canonical scenario map")
    scenario_by_id = {row.scenario_id: row for row in scenarios}
    parsed = tuple(
        value if isinstance(value, ContrastResult) else ContrastResult.model_validate(value)
        for value in results.values()
    )
    if tuple(row.pair for row in parsed) != CANONICAL_CONTRAST_PAIRS:
        raise ValueError("contrast result IDs do not match map keys")
    for row in parsed:
        left = scenario_by_id[row.left_scenario_id]
        right = scenario_by_id[row.right_scenario_id]
        if (
            row.left_result_sha256 != left.result_sha256
            or row.right_result_sha256 != right.result_sha256
        ):
            raise ValueError("contrast result is detached from its scenario result")
    return parsed


class Phase5RecoveryPolicy(StrictContract):
    """Complete D-28 through D-33 policy identity."""

    schema_version: Literal["itda.phase5-recovery-policy.v1"]
    structural_profile_count: Literal[24]
    candidate_confidence_min: Literal[55]
    mismatch_guidance_confidence_min: Literal[65]
    ordinary_information_confidence_min: Literal[70]
    minimum_effective_candidate_count: Literal[5]
    confidence_is_ranking_input: Literal[False]
    hard_duplicate_suppression_precedes_effective_count: Literal[True] = True
    hard_duplicate_adjudication_sha256: Sha256
    cannot_coappear_authority: CannotCoappearAuthority
    activation_source_file_sha256: Sha256
    activation_dataset_sha256: Sha256
    activation_suite_sha256: Sha256
    activation_scenarios: Annotated[
        tuple[ActivationScenarioBinding, ...], Field(min_length=8, max_length=8)
    ]
    contrast_suite_sha256: Sha256
    contrast_bindings: Annotated[tuple[ContrastBinding, ...], Field(min_length=7, max_length=7)]
    historical_05_16_plan_sha256: Sha256
    historical_05_16_summary_sha256: Sha256
    historical_05_16_terminal_file_sha256: Sha256
    historical_05_16_terminal_sha256: Sha256
    policy_sha256: Sha256 | None = None

    @model_validator(mode="after")
    def validate_policy(self) -> Self:
        _validate_canonical_scenario_source()
        _historical_file_sha256(HISTORICAL_05_16_PLAN_PATH, HISTORICAL_05_16_PLAN_SHA256)
        _historical_file_sha256(HISTORICAL_05_16_SUMMARY_PATH, HISTORICAL_05_16_SUMMARY_SHA256)
        _historical_file_sha256(
            HISTORICAL_05_16_TERMINAL_PATH, HISTORICAL_05_16_TERMINAL_FILE_SHA256
        )
        if self.structural_profile_count != 24:
            raise ValueError("recovery policy requires exact DEV-24 structure")
        if self.hard_duplicate_adjudication_sha256 != HARD_DUPLICATE_ADJUDICATION_SHA256:
            raise ValueError("recovery policy hard-duplicate authority drifted")
        if self.cannot_coappear_authority.authority_sha256 != CANNOT_COAPPEAR_AUTHORITY_SHA256:
            raise ValueError("recovery policy cannot-coappear authority drifted")
        if self.activation_source_file_sha256 != SCENARIO_SOURCE_FILE_SHA256:
            raise ValueError("recovery policy scenario source drifted")
        if self.activation_dataset_sha256 != SCENARIO_DATASET_SHA256:
            raise ValueError("recovery policy scenario dataset drifted")
        if self.activation_suite_sha256 != ACTIVATION_SUITE_SHA256:
            raise ValueError("recovery policy activation suite drifted")
        if tuple(row.scenario_id for row in self.activation_scenarios) != CANONICAL_SCENARIO_IDS:
            raise ValueError("recovery policy scenario IDs must be exact and ordered")
        if self.contrast_suite_sha256 != CONTRAST_SUITE_SHA256:
            raise ValueError("recovery policy contrast suite drifted")
        if tuple(row.pair for row in self.contrast_bindings) != CANONICAL_CONTRAST_PAIRS:
            raise ValueError("recovery policy contrast pairs must be exact and ordered")
        if self.historical_05_16_summary_sha256 != HISTORICAL_05_16_SUMMARY_SHA256:
            raise ValueError("historical 05-16 summary identity drifted")
        if self.historical_05_16_terminal_file_sha256 != HISTORICAL_05_16_TERMINAL_FILE_SHA256:
            raise ValueError("historical 05-16 terminal file identity drifted")
        if self.historical_05_16_terminal_sha256 != HISTORICAL_05_16_TERMINAL_SHA256:
            raise ValueError("historical 05-16 terminal identity drifted")
        expected = canonical_sha256(self.model_dump(mode="json", exclude={"policy_sha256"}))
        if self.policy_sha256 is None:
            object.__setattr__(self, "policy_sha256", expected)
        elif not hmac.compare_digest(self.policy_sha256, expected):
            raise ValueError("recovery policy self-digest drifted")
        return self

    @property
    def activation_scenario_ids(self) -> tuple[str, ...]:
        return tuple(row.scenario_id for row in self.activation_scenarios)

    @property
    def contrast_pairs(self) -> tuple[tuple[str, str], ...]:
        return tuple(row.pair for row in self.contrast_bindings)


_HARD_DUPLICATE = load_hard_duplicate_adjudication()
_CANONICAL_CANNOT_COAPPEAR = CannotCoappearAuthority(
    schema_version="itda.phase5-cannot-coappear-authority.v1",
    scope="CANONICAL_DEV_24",
    source_dev_authority_sha256=_HARD_DUPLICATE.source_dev_authority_sha256,
    dev_membership_sha256=_HARD_DUPLICATE.dev_membership_sha256,
    catalog_revision_sha256=_HARD_DUPLICATE.catalog_revision_sha256,
    catalog_approval_sha256=_HARD_DUPLICATE.catalog_approval_sha256,
    catalog_activation_event_sha256=_HARD_DUPLICATE.catalog_activation_event_sha256,
    relationship_automatic_leaves_root_sha256=(
        _HARD_DUPLICATE.relationship_resolution.relationship_automatic_leaves_root_sha256
    ),
    relationship_unresolved_leaves_root_sha256=(
        _HARD_DUPLICATE.relationship_resolution.relationship_unresolved_leaves_root_sha256
    ),
    reviewed_relationship_leaves_root_sha256=(
        _HARD_DUPLICATE.relationship_resolution.reviewed_relationship_leaves_root_sha256
    ),
    authoritative_relationship_leaves_sha256=(
        _HARD_DUPLICATE.relationship_resolution.authoritative_relationship_leaves_sha256
    ),
    hard_duplicate_adjudication_sha256=_HARD_DUPLICATE.adjudication_sha256,
    dev_place_ids=tuple(row.member_place_ids[0] for row in _HARD_DUPLICATE.equivalence_classes),
    pairs=(),
    authority_sha256=CANNOT_COAPPEAR_AUTHORITY_SHA256,
)

CANONICAL_PHASE5_RECOVERY_POLICY = Phase5RecoveryPolicy(
    schema_version="itda.phase5-recovery-policy.v1",
    structural_profile_count=24,
    candidate_confidence_min=55,
    mismatch_guidance_confidence_min=65,
    ordinary_information_confidence_min=70,
    minimum_effective_candidate_count=5,
    confidence_is_ranking_input=False,
    hard_duplicate_suppression_precedes_effective_count=True,
    hard_duplicate_adjudication_sha256=HARD_DUPLICATE_ADJUDICATION_SHA256,
    cannot_coappear_authority=_CANONICAL_CANNOT_COAPPEAR,
    activation_source_file_sha256=SCENARIO_SOURCE_FILE_SHA256,
    activation_dataset_sha256=SCENARIO_DATASET_SHA256,
    activation_suite_sha256=ACTIVATION_SUITE_SHA256,
    activation_scenarios=tuple(
        ActivationScenarioBinding(scenario_id=scenario_id) for scenario_id in CANONICAL_SCENARIO_IDS
    ),
    contrast_suite_sha256=CONTRAST_SUITE_SHA256,
    contrast_bindings=tuple(
        ContrastBinding(left_scenario_id=left, right_scenario_id=right)
        for left, right in CANONICAL_CONTRAST_PAIRS
    ),
    historical_05_16_plan_sha256=HISTORICAL_05_16_PLAN_SHA256,
    historical_05_16_summary_sha256=HISTORICAL_05_16_SUMMARY_SHA256,
    historical_05_16_terminal_file_sha256=HISTORICAL_05_16_TERMINAL_FILE_SHA256,
    historical_05_16_terminal_sha256=HISTORICAL_05_16_TERMINAL_SHA256,
)

# Short aliases make downstream receipt code descriptive without creating a
# second contract or a second source of scenario IDs.
ScenarioResult = ActivationScenarioResult


__all__ = [
    "ACTIVATION_SUITE_SHA256",
    "CANONICAL_CONTRAST_PAIRS",
    "CANONICAL_PHASE5_RECOVERY_POLICY",
    "CANONICAL_SCENARIO_IDS",
    "CANNOT_COAPPEAR_AUTHORITY_SHA256",
    "CONTRAST_SUITE_SHA256",
    "ConfidenceBand",
    "ContrastBinding",
    "ContrastResult",
    "ContrastSensitivityBinding",
    "FrozenScenarioBinding",
    "CannotCoappearAuthority",
    "ContrastSensitivityBinding",
    "ActivationScenarioBinding",
    "ActivationScenarioResult",
    "ActivationSuiteEvaluation",
    "Phase5RecoveryPolicy",
    "ScenarioResult",
    "validate_activation_scenario_results",
    "validate_contrast_results",
]
