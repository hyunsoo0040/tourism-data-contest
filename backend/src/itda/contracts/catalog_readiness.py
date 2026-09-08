"""Selection-independent catalog readiness and REINF-12 contracts."""

from __future__ import annotations

import unicodedata
from collections import Counter
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Annotated, Any, Literal, Self

from pydantic import Field, model_validator

from itda.contracts.base import Sha256, StrictContract
from itda.contracts.catalog_enrichment import APPROVED_OPERATIONS
from itda.contracts.catalog_enrichment_evidence import EnrichmentEvidenceSidecar
from itda.contracts.catalog_entity_policy import EntityPolicyReport
from itda.contracts.catalog_rights_v2 import (
    CandidateObjectiveEvidence,
    CandidateObjectiveRow,
    GateState,
)
from itda.domain.canonical import canonical_sha256

RepresentationGroup = Literal[
    "history_culture",
    "history_scenery_boundary",
    "image_modern_content",
    "rest_walk_immersion",
]
AssignmentStatus = Literal["PRIMARY", "UNCLASSIFIED", "AMBIGUOUS"]
GROUP_ORDER: tuple[RepresentationGroup, ...] = (
    "history_culture",
    "history_scenery_boundary",
    "image_modern_content",
    "rest_walk_immersion",
)
REPRESENTATION_POLICY_VERSION = "reinforcement-12-evidence-only-v1"
ALLOWED_CLASSIFICATION_FIELDS = (
    "entity_projection.dataset_records.name_ko",
    "entity_projection.dataset_records.evidence.provider",
    "entity_projection.dataset_records.evidence.official_dataset_id",
    "entity_projection.dataset_records.evidence.source_row_sha256",
    "candidate_objective_evidence.rows.place_entity_id",
    "candidate_objective_evidence.rows.row_sha256",
    "candidate_objective_evidence.rows.source_candidate_ids",
    "candidate_objective_evidence.rows.source_dataset_entity_ids",
)
FORBIDDEN_CLASSIFICATION_FRAGMENTS = (
    "allocation",
    "blind",
    "dev_membership",
    "embedding",
    "evaluation",
    "human_override",
    "label",
    "model",
    "outcome",
    "quota",
    "score",
    "selection",
    "split",
)


@dataclass(frozen=True)
class KtoRecoveryReadiness:
    target_count: int
    universe_count: int
    unresolved_count: int
    objective_eligible_count: int
    group_counts: dict[str, int]
    capped_capacity: int
    representation_feasible: bool
    human_identity_relationship_decisions: int
    maximum_human_decisions: int
    attempted_provider_count: int
    frontier_rows: tuple[dict[str, Any], ...]
    substitute_rows: tuple[dict[str, Any], ...]
    reentry_disposition: dict[str, Any]
    reentry_ordinal: int
    target_replay_sha256: str
    universe_replay_sha256: str
    decision_accounting_sha256: str
    representation_quota_attestation_sha256: str
    substitution_root_sha256: str
    reentry_root_sha256: str
    preflight_root_sha256: str
    outcome: str
    outcome_reason: str
    plan50_reachable: bool
    substitution_payload: dict[str, Any]
    reentry_payload: dict[str, Any]
    preflight_payload: dict[str, Any]


_EXACT_NAMES: dict[RepresentationGroup, tuple[str, ...]] = {
    "history_culture": (
        "불국사",
        "석굴암",
        "대릉원·천마총",
        "첨성대",
        "동궁과 월지",
        "국립경주박물관",
        "분황사",
        "황룡사지",
        "월정교",
        "교촌마을",
        "양동마을",
        "옥산서원",
    ),
    "history_scenery_boundary": (
        "포석정",
        "감은사지",
        "문무대왕릉",
        "김유신묘",
        "무열왕릉",
        "오릉",
        "계림",
        "월성·반월성",
    ),
    "image_modern_content": (
        "황리단길",
        "보문정",
        "경주엑스포대공원",
        "솔거미술관",
        "경주동궁원",
        "한국대중음악박물관",
        "구황동 원지 유적",
        "경주월드",
    ),
    "rest_walk_immersion": (
        "보문호반길",
        "경주 남산",
        "삼릉숲",
        "토함산 자연휴양림",
        "주상절리 파도소리길",
        "오류고아라해변",
        "나정고운모래해변",
        "화랑마을",
    ),
}
_SUFFIX_LEXEMES: dict[RepresentationGroup, tuple[str, ...]] = {
    "history_culture": (
        "서원",
        "향교",
        "박물관",
        "문화관",
        "기념관",
        "사지",
        "사찰",
    ),
    "history_scenery_boundary": (
        "왕릉",
        "여왕릉",
        "묘",
        "고분군",
        "월성",
        "읍성",
        "포석정지",
    ),
    "image_modern_content": (
        "미술관",
        "뮤지엄",
        "엑스포대공원",
        "월드",
        "동궁원",
        "대중음악박물관",
        "황리단길",
        "테마파크",
        "아트센터",
        "전시관",
    ),
    "rest_walk_immersion": (
        "해변",
        "해수욕장",
        "휴양림",
        "숲",
        "남산",
        "호반길",
        "산책로",
        "둘레길",
        "파도소리길",
        "계곡",
        "폭포",
        "생태공원",
        "수목원",
        "정원",
        "국립공원",
        "수변공원",
    ),
}


def normalize_provider_name(value: str) -> str:
    """Normalize provider names without semantic or model-derived processing."""

    normalized = unicodedata.normalize("NFKC", value).casefold()
    return "".join(
        character for character in normalized if unicodedata.category(character)[0] in {"L", "N"}
    )


class ProviderCandidateEvidence(StrictContract):
    """Allowlisted immutable provider fields accepted by classification."""

    source_candidate_id: Annotated[
        str,
        Field(
            strict=True,
            pattern=r"^candidate:(tour-api|tourism-photo|odii):[A-Za-z0-9._:-]+$",
        ),
    ]
    source_dataset_entity_id: Annotated[str, Field(strict=True, pattern=r"^dataset:[0-9a-f]{64}$")]
    source_row_sha256: Sha256
    provider: Literal["TOUR_API", "TOURISM_PHOTO", "ODII"]
    official_dataset_id: Literal["15101578", "15101971", "15101914"]
    name_ko: Annotated[str, Field(strict=True, min_length=1, max_length=500)]

    @model_validator(mode="after")
    def validate_provider_dataset(self) -> Self:
        expected = {
            "TOUR_API": "15101578",
            "ODII": "15101971",
            "TOURISM_PHOTO": "15101914",
        }[self.provider]
        if self.official_dataset_id != expected:
            raise ValueError("provider evidence uses the wrong exact dataset identity")
        return self


class RepresentationGroupRule(StrictContract):
    """One deterministic name-evidence predicate."""

    group_id: RepresentationGroup
    rule_id: Annotated[str, Field(strict=True, pattern=r"^GROUP_[A-Z_]+_V1$")]
    rationale_code: Annotated[str, Field(strict=True, min_length=1, max_length=160)]
    exact_names: tuple[Annotated[str, Field(strict=True, min_length=1, max_length=500)], ...]
    suffix_lexemes: tuple[Annotated[str, Field(strict=True, min_length=1, max_length=120)], ...]

    @model_validator(mode="after")
    def validate_rule(self) -> Self:
        for values in (self.exact_names, self.suffix_lexemes):
            if values != tuple(sorted(set(values), key=lambda item: item.encode("utf-8"))):
                raise ValueError("representation lexemes must be unique canonical order")
        if not self.exact_names or not self.suffix_lexemes:
            raise ValueError("representation rule requires exact names and suffix lexemes")
        return self


class RepresentationGroupRules(StrictContract):
    """Frozen evidence-only REINF-12 classification rule table."""

    schema_version: Literal["representation-group-rules-v1"]
    data_version: Literal["catalog-v2-representation-rules-data-v1"]
    policy_version: Literal["reinforcement-12-evidence-only-v1"]
    group_order: tuple[RepresentationGroup, ...]
    normalization_version: Literal["provider-name-nfkc-alnum-v1"]
    allowed_evidence_fields: tuple[str, ...]
    forbidden_input_fragments: tuple[str, ...]
    proposal_seed_manifest_sha256: Sha256
    source_attachment_sha256: Sha256
    groups: tuple[RepresentationGroupRule, ...]
    rule_table_sha256: Sha256

    @model_validator(mode="after")
    def validate_rules(self) -> Self:
        if self.group_order != GROUP_ORDER:
            raise ValueError("representation rules must use the fixed group order")
        if tuple(rule.group_id for rule in self.groups) != GROUP_ORDER:
            raise ValueError("representation rules must contain each fixed group once")
        if self.allowed_evidence_fields != ALLOWED_CLASSIFICATION_FIELDS:
            raise ValueError("representation evidence allowlist drifted")
        if self.forbidden_input_fragments != FORBIDDEN_CLASSIFICATION_FRAGMENTS:
            raise ValueError("representation forbidden-input policy drifted")
        expected = canonical_sha256(self.model_dump(exclude={"rule_table_sha256"}, mode="json"))
        if self.rule_table_sha256 != expected:
            raise ValueError("representation rule table sha256 does not match")
        return self


def build_default_representation_rules(
    *,
    seed_manifest_sha256: str,
    source_attachment_sha256: str,
) -> RepresentationGroupRules:
    """Build the frozen proposal-rationale rule table byte-identically."""

    groups = tuple(
        RepresentationGroupRule(
            group_id=group,
            rule_id=f"GROUP_{group.upper()}_V1",
            rationale_code="PROPOSAL_HYPOTHESIS_PROVIDER_NAME_EVIDENCE",
            exact_names=tuple(
                sorted(
                    {normalize_provider_name(value) for value in _EXACT_NAMES[group]},
                    key=lambda item: item.encode("utf-8"),
                )
            ),
            suffix_lexemes=tuple(
                sorted(
                    {normalize_provider_name(value) for value in _SUFFIX_LEXEMES[group]},
                    key=lambda item: item.encode("utf-8"),
                )
            ),
        )
        for group in GROUP_ORDER
    )
    fields = {
        "schema_version": "representation-group-rules-v1",
        "data_version": "catalog-v2-representation-rules-data-v1",
        "policy_version": REPRESENTATION_POLICY_VERSION,
        "group_order": GROUP_ORDER,
        "normalization_version": "provider-name-nfkc-alnum-v1",
        "allowed_evidence_fields": ALLOWED_CLASSIFICATION_FIELDS,
        "forbidden_input_fragments": FORBIDDEN_CLASSIFICATION_FRAGMENTS,
        "proposal_seed_manifest_sha256": seed_manifest_sha256,
        "source_attachment_sha256": source_attachment_sha256,
        "groups": [group.model_dump(mode="json") for group in groups],
    }
    return RepresentationGroupRules(
        **fields,
        rule_table_sha256=canonical_sha256(fields),
    )


class ClassificationEvidenceRef(StrictContract):
    """One exact provider-evidence value used by classification."""

    field_path: Literal["entity_projection.dataset_records.name_ko"]
    source_candidate_id: Annotated[
        str,
        Field(
            strict=True,
            pattern=r"^candidate:(tour-api|tourism-photo|odii):[A-Za-z0-9._:-]+$",
        ),
    ]
    source_dataset_entity_id: Annotated[str, Field(strict=True, pattern=r"^dataset:[0-9a-f]{64}$")]
    source_row_sha256: Sha256
    value_sha256: Sha256


class CandidateRepresentationAssignment(StrictContract):
    """One fail-closed four-group classification result."""

    place_entity_id: Annotated[str, Field(strict=True, pattern=r"^place:[0-9a-f]{64}$")]
    status: AssignmentStatus
    primary_group: RepresentationGroup | None
    matched_groups: tuple[RepresentationGroup, ...]
    matched_rule_ids: tuple[Annotated[str, Field(strict=True, min_length=1, max_length=120)], ...]
    evidence_field_refs: tuple[ClassificationEvidenceRef, ...]
    objective_evidence_row_sha256: Sha256
    rule_table_sha256: Sha256
    assignment_row_sha256: Sha256

    @model_validator(mode="after")
    def validate_assignment(self) -> Self:
        ordered_matches = tuple(group for group in GROUP_ORDER if group in set(self.matched_groups))
        if self.matched_groups != ordered_matches:
            raise ValueError("matched groups must follow the fixed group order")
        if len(set(self.matched_groups)) != len(self.matched_groups):
            raise ValueError("matched groups must be unique")
        if len(self.matched_rule_ids) != len(self.matched_groups):
            raise ValueError("matched groups and rule IDs differ")
        if not self.evidence_field_refs:
            raise ValueError("classification requires exact provider evidence")
        if self.status == "PRIMARY":
            if len(self.matched_groups) != 1 or self.primary_group != self.matched_groups[0]:
                raise ValueError("primary assignment requires exactly one matching group")
        elif self.status == "UNCLASSIFIED":
            if self.matched_groups or self.primary_group is not None:
                raise ValueError("unclassified assignment cannot carry a primary group")
        elif len(self.matched_groups) < 2 or self.primary_group is not None:
            raise ValueError("ambiguous assignment requires multiple groups and no primary")
        expected = canonical_sha256(self.model_dump(exclude={"assignment_row_sha256"}, mode="json"))
        if self.assignment_row_sha256 != expected:
            raise ValueError("assignment row sha256 does not match")
        return self


def classify_representation_candidate(
    *,
    place_entity_id: str,
    objective_evidence_row_sha256: str,
    provider_evidence: tuple[ProviderCandidateEvidence, ...],
    rules: RepresentationGroupRules,
) -> CandidateRepresentationAssignment:
    """Evaluate all four rules without using fixed order as a tie-breaker."""

    if not provider_evidence:
        raise ValueError("classification requires at least one provider evidence row")
    ordered_evidence = tuple(
        sorted(
            provider_evidence,
            key=lambda row: (
                row.source_candidate_id.encode("utf-8"),
                row.source_dataset_entity_id.encode("utf-8"),
            ),
        )
    )
    normalized_tourapi_names = tuple(
        normalize_provider_name(row.name_ko)
        for row in ordered_evidence
        if row.provider == "TOUR_API"
    )
    matched_groups: list[RepresentationGroup] = []
    matched_rule_ids: list[str] = []
    for rule in rules.groups:
        matches = any(
            normalized in set(rule.exact_names)
            or any(normalized.endswith(lexeme) for lexeme in rule.suffix_lexemes)
            for normalized in normalized_tourapi_names
        )
        if matches:
            matched_groups.append(rule.group_id)
            matched_rule_ids.append(rule.rule_id)
    if len(matched_groups) == 1:
        status: AssignmentStatus = "PRIMARY"
        primary_group: RepresentationGroup | None = matched_groups[0]
    elif not matched_groups:
        status = "UNCLASSIFIED"
        primary_group = None
    else:
        status = "AMBIGUOUS"
        primary_group = None
    evidence_refs = tuple(
        ClassificationEvidenceRef(
            field_path="entity_projection.dataset_records.name_ko",
            source_candidate_id=row.source_candidate_id,
            source_dataset_entity_id=row.source_dataset_entity_id,
            source_row_sha256=row.source_row_sha256,
            value_sha256=canonical_sha256(
                {
                    "field_path": "entity_projection.dataset_records.name_ko",
                    "normalized_value": normalize_provider_name(row.name_ko),
                }
            ),
        )
        for row in ordered_evidence
    )
    fields = {
        "place_entity_id": place_entity_id,
        "status": status,
        "primary_group": primary_group,
        "matched_groups": tuple(matched_groups),
        "matched_rule_ids": tuple(matched_rule_ids),
        "evidence_field_refs": [row.model_dump(mode="json") for row in evidence_refs],
        "objective_evidence_row_sha256": objective_evidence_row_sha256,
        "rule_table_sha256": rules.rule_table_sha256,
    }
    return CandidateRepresentationAssignment(
        **fields,
        assignment_row_sha256=canonical_sha256(fields),
    )


class RepresentationAssignmentsParents(StrictContract):
    entity_policy_file_sha256: Sha256
    entity_policy_report_sha256: Sha256
    formal_policy_sha256: Sha256
    catalog_v1_tree_sha256: Sha256
    protected_inputs_sha256: Sha256
    complete_dispositions_root: Sha256
    media_attachments_root: Sha256
    entity_projection_file_sha256: Sha256
    entity_projection_sha256: Sha256
    rights_projection_file_sha256: Sha256
    rights_projection_sha256: Sha256
    objective_evidence_file_sha256: Sha256
    objective_evidence_report_sha256: Sha256
    objective_evidence_rows_root: Sha256
    proposal_seed_manifest_sha256: Sha256
    source_attachment_sha256: Sha256
    representation_rules_file_sha256: Sha256
    representation_rule_table_sha256: Sha256


class CandidateRepresentationAssignments(StrictContract):
    """Complete immutable exact-one/fail-closed assignment inventory."""

    schema_version: Literal["candidate-representation-groups-v1"]
    data_version: Literal["catalog-v2-representation-assignments-data-v1"]
    policy_version: Literal["reinforcement-12-evidence-only-v1"]
    group_order: tuple[RepresentationGroup, ...]
    parents: RepresentationAssignmentsParents
    rows: tuple[CandidateRepresentationAssignment, ...]
    candidate_count: Annotated[int, Field(strict=True, ge=0)]
    status_counts: dict[
        AssignmentStatus,
        Annotated[int, Field(strict=True, ge=0)],
    ]
    primary_group_counts: dict[
        RepresentationGroup,
        Annotated[int, Field(strict=True, ge=0)],
    ]
    rows_root: Sha256
    complete_assignment_sha256: Sha256

    @model_validator(mode="after")
    def validate_assignments(self) -> Self:
        if self.group_order != GROUP_ORDER:
            raise ValueError("assignment artifact must use the fixed group order")
        ids = tuple(row.place_entity_id for row in self.rows)
        if ids != tuple(sorted(ids)) or len(set(ids)) != len(ids):
            raise ValueError("assignment rows must use unique canonical place order")
        if self.candidate_count != len(self.rows):
            raise ValueError("assignment candidate count is not row-derived")
        expected_status = {
            status: sum(row.status == status for row in self.rows)
            for status in ("PRIMARY", "UNCLASSIFIED", "AMBIGUOUS")
        }
        if self.status_counts != expected_status:
            raise ValueError("assignment status counts are not row-derived")
        expected_groups = {
            group: sum(row.primary_group == group for row in self.rows) for group in GROUP_ORDER
        }
        if self.primary_group_counts != expected_groups:
            raise ValueError("primary group counts are not row-derived")
        if any(
            row.rule_table_sha256 != self.parents.representation_rule_table_sha256
            for row in self.rows
        ):
            raise ValueError("assignment row uses a different rule table")
        expected_root = canonical_sha256([row.model_dump(mode="json") for row in self.rows])
        if self.rows_root != expected_root:
            raise ValueError("assignment rows root does not match")
        expected = canonical_sha256(
            self.model_dump(exclude={"complete_assignment_sha256"}, mode="json")
        )
        if self.complete_assignment_sha256 != expected:
            raise ValueError("complete assignment sha256 does not match")
        return self


def build_assignment_artifact(
    *,
    rows: tuple[CandidateRepresentationAssignment, ...],
    parents: RepresentationAssignmentsParents,
) -> CandidateRepresentationAssignments:
    ordered = tuple(sorted(rows, key=lambda row: row.place_entity_id))
    fields = {
        "schema_version": "candidate-representation-groups-v1",
        "data_version": "catalog-v2-representation-assignments-data-v1",
        "policy_version": REPRESENTATION_POLICY_VERSION,
        "group_order": GROUP_ORDER,
        "parents": parents.model_dump(mode="json"),
        "rows": [row.model_dump(mode="json") for row in ordered],
        "candidate_count": len(ordered),
        "status_counts": {
            status: sum(row.status == status for row in ordered)
            for status in ("PRIMARY", "UNCLASSIFIED", "AMBIGUOUS")
        },
        "primary_group_counts": {
            group: sum(row.primary_group == group for row in ordered) for group in GROUP_ORDER
        },
        "rows_root": canonical_sha256([row.model_dump(mode="json") for row in ordered]),
    }
    return CandidateRepresentationAssignments(
        **fields,
        complete_assignment_sha256=canonical_sha256(fields),
    )


class CandidateReadinessRow(StrictContract):
    """Complete named-gate inventory for one potential candidate."""

    place_entity_id: Annotated[str, Field(strict=True, pattern=r"^place:[0-9a-f]{64}$")]
    source_crosswalk_row_id: Annotated[str, Field(strict=True, pattern=r"^crosswalk:[0-9a-f]{64}$")]
    source_candidate_ids: tuple[
        Annotated[str, Field(strict=True, min_length=1, max_length=200)], ...
    ]
    source_dataset_entity_ids: tuple[
        Annotated[str, Field(strict=True, pattern=r"^dataset:[0-9a-f]{64}$")], ...
    ]
    provider_place_candidate_id: Annotated[
        str | None, Field(strict=True, pattern=r"^candidate:tour-api:[0-9]+$")
    ] = None
    objective_evidence_row_sha256: Sha256
    objective_gate_states: dict[
        Literal[
            "coordinates",
            "description",
            "operating_info",
            "dataset_rights",
            "direct_media",
        ],
        GateState,
    ]
    representation_assignment_status: AssignmentStatus | Literal["MISSING", "HASH_INVALID"]
    representation_primary_group: RepresentationGroup | None
    representation_assignment_row_sha256: Sha256 | None
    already_passing_objective_gate_count: Annotated[int, Field(strict=True, ge=0, le=5)]
    named_deficits: tuple[Annotated[str, Field(strict=True, min_length=1, max_length=160)], ...]
    objective_eligible: Annotated[bool, Field(strict=True)]
    confidence_is_qualification_filter_only: Literal[True]
    confidence_adds_score: Literal[False]
    row_sha256: Sha256

    @model_validator(mode="after")
    def validate_row(self) -> Self:
        expected_gate_names = {
            "coordinates",
            "description",
            "operating_info",
            "dataset_rights",
            "direct_media",
        }
        if set(self.objective_gate_states) != expected_gate_names:
            raise ValueError("readiness row requires all five objective evidence gates")
        passing = sum(state is GateState.PASS for state in self.objective_gate_states.values())
        if self.already_passing_objective_gate_count != passing:
            raise ValueError("passing objective gate count is not evidence-derived")
        if self.objective_eligible != (not self.named_deficits):
            raise ValueError("objective eligibility must equal the complete named-gate truth")
        expected = canonical_sha256(self.model_dump(exclude={"row_sha256"}, mode="json"))
        if self.row_sha256 != expected:
            raise ValueError("readiness row sha256 does not match")
        return self


class ReadinessParents(StrictContract):
    """All immutable parents required before readiness may be derived."""

    entity_policy_file_sha256: Sha256
    entity_policy_report_sha256: Sha256
    formal_policy_sha256: Sha256
    catalog_v1_tree_sha256: Sha256
    protected_inputs_sha256: Sha256
    complete_dispositions_root: Sha256
    media_attachments_root: Sha256
    entity_projection_file_sha256: Sha256
    entity_projection_sha256: Sha256
    rights_projection_file_sha256: Sha256
    rights_projection_sha256: Sha256
    objective_evidence_file_sha256: Sha256
    objective_evidence_report_sha256: Sha256
    objective_evidence_rows_root: Sha256
    representation_rules_file_sha256: Sha256
    representation_rule_table_sha256: Sha256
    representation_assignments_file_sha256: Sha256
    complete_assignment_sha256: Sha256


class CatalogReadinessReport(StrictContract):
    """Selection-independent readiness over the full potential inventory."""

    schema_version: Literal["catalog-readiness-before-enrichment-v1"]
    data_version: Literal["catalog-v2-readiness-data-v1"]
    parents: ReadinessParents
    rows: tuple[CandidateReadinessRow, ...]
    potential_candidate_count: Annotated[int, Field(strict=True, ge=0)]
    objective_eligible_count: Annotated[int, Field(strict=True, ge=0)]
    named_deficit_counts: dict[
        Annotated[str, Field(strict=True, min_length=1, max_length=160)],
        Annotated[int, Field(strict=True, ge=1)],
    ]
    rows_root: Sha256
    report_sha256: Sha256

    @model_validator(mode="after")
    def validate_report(self) -> Self:
        ids = tuple(row.place_entity_id for row in self.rows)
        if ids != tuple(sorted(ids)) or len(set(ids)) != len(ids):
            raise ValueError("readiness rows must use unique canonical place order")
        if self.potential_candidate_count != len(self.rows):
            raise ValueError("potential candidate count is not row-derived")
        if self.objective_eligible_count != sum(row.objective_eligible for row in self.rows):
            raise ValueError("objective eligible count is not full-inventory derived")
        expected_deficits = dict(
            sorted(Counter(deficit for row in self.rows for deficit in row.named_deficits).items())
        )
        if self.named_deficit_counts != expected_deficits:
            raise ValueError("named deficit counts are not row-derived")
        expected_root = canonical_sha256([row.model_dump(mode="json") for row in self.rows])
        if self.rows_root != expected_root:
            raise ValueError("readiness rows root does not match")
        expected = canonical_sha256(self.model_dump(exclude={"report_sha256"}, mode="json"))
        if self.report_sha256 != expected:
            raise ValueError("readiness report sha256 does not match")
        return self


class EnrichmentPoolParents(StrictContract):
    readiness_file_sha256: Sha256
    readiness_report_sha256: Sha256
    readiness_rows_root: Sha256
    entity_policy_report_sha256: Sha256
    formal_policy_sha256: Sha256
    catalog_v1_tree_sha256: Sha256
    protected_inputs_sha256: Sha256
    complete_dispositions_root: Sha256
    media_attachments_root: Sha256
    entity_projection_file_sha256: Sha256
    entity_projection_sha256: Sha256
    rights_projection_file_sha256: Sha256
    rights_projection_sha256: Sha256
    objective_evidence_file_sha256: Sha256
    objective_evidence_report_sha256: Sha256
    representation_rules_file_sha256: Sha256
    representation_rule_table_sha256: Sha256
    representation_assignments_file_sha256: Sha256
    complete_assignment_sha256: Sha256


class EnrichmentPoolRow(StrictContract):
    place_entity_id: Annotated[str, Field(strict=True, pattern=r"^place:[0-9a-f]{64}$")]
    provider_candidate_id: Annotated[
        str, Field(strict=True, pattern=r"^candidate:tour-api:[0-9]+$")
    ]
    primary_group: RepresentationGroup
    group_ordinal: Annotated[int, Field(strict=True, ge=0, le=3)]
    linked_seed_ids: tuple[
        Annotated[
            str,
            Field(strict=True, pattern=r"^proposal:gyeongju:[0-9]{3}$"),
        ],
        ...,
    ]
    linked_seed_priority: Annotated[bool, Field(strict=True)]
    already_passing_objective_gate_count: Annotated[int, Field(strict=True, ge=0, le=5)]
    readiness_row_sha256: Sha256
    assignment_row_sha256: Sha256
    row_sha256: Sha256

    @model_validator(mode="after")
    def validate_pool_row(self) -> Self:
        if self.group_ordinal != GROUP_ORDER.index(self.primary_group):
            raise ValueError("pool row group ordinal does not match fixed order")
        if self.linked_seed_priority != bool(self.linked_seed_ids):
            raise ValueError("linked-seed priority is not evidence-derived")
        if self.linked_seed_ids != tuple(sorted(set(self.linked_seed_ids))):
            raise ValueError("linked seed IDs must use unique canonical order")
        expected = canonical_sha256(self.model_dump(exclude={"row_sha256"}, mode="json"))
        if self.row_sha256 != expected:
            raise ValueError("enrichment pool row sha256 does not match")
        return self


class EnrichmentCandidatePool(StrictContract):
    schema_version: Literal["enrichment-candidate-pool-v1"]
    data_version: Literal["catalog-v2-enrichment-pool-data-v1"]
    algorithm_version: Literal["linked-seed-gates-group-provider-id-v1"]
    group_order: tuple[RepresentationGroup, ...]
    maximum_pool_size: Literal[60]
    eligible_candidate_count: Annotated[int, Field(strict=True, ge=36)]
    parents: EnrichmentPoolParents
    rows: tuple[EnrichmentPoolRow, ...]
    ordered_pool_ids: tuple[
        Annotated[str, Field(strict=True, pattern=r"^candidate:tour-api:[0-9]+$")],
        ...,
    ]
    pool_count: Annotated[int, Field(strict=True, ge=36, le=60)]
    rows_root: Sha256
    pool_sha256: Sha256

    @model_validator(mode="after")
    def validate_pool(self) -> Self:
        if self.group_order != GROUP_ORDER:
            raise ValueError("enrichment pool must use the fixed group order")
        if self.pool_count != len(self.rows) or self.pool_count != len(self.ordered_pool_ids):
            raise ValueError("pool count does not match rows and IDs")
        if self.pool_count != min(60, self.eligible_candidate_count):
            raise ValueError("pool must take exactly min(60, candidate_count)")
        row_ids = tuple(row.provider_candidate_id for row in self.rows)
        if row_ids != self.ordered_pool_ids or len(set(row_ids)) != len(row_ids):
            raise ValueError("pool IDs must be unique and match ordered rows")
        expected_order = tuple(
            sorted(
                self.rows,
                key=lambda row: (
                    not row.linked_seed_priority,
                    -row.already_passing_objective_gate_count,
                    row.group_ordinal,
                    row.provider_candidate_id.encode("utf-8"),
                ),
            )
        )
        if self.rows != expected_order:
            raise ValueError("pool rows violate the fixed deterministic order")
        expected_root = canonical_sha256([row.model_dump(mode="json") for row in self.rows])
        if self.rows_root != expected_root:
            raise ValueError("pool rows root does not match")
        expected = canonical_sha256(self.model_dump(exclude={"pool_sha256"}, mode="json"))
        if self.pool_sha256 != expected:
            raise ValueError("pool sha256 does not match")
        return self


def build_enrichment_pool(
    *,
    readiness: CatalogReadinessReport,
    linked_seed_ids_by_place: Mapping[str, tuple[str, ...]],
    parents: EnrichmentPoolParents,
) -> EnrichmentCandidatePool:
    """Select the bounded request pool from objective evidence, never quotas."""

    eligible = tuple(
        row
        for row in readiness.rows
        if row.provider_place_candidate_id is not None
        and row.objective_gate_states["dataset_rights"] is GateState.PASS
        and row.representation_assignment_status == "PRIMARY"
        and row.representation_primary_group is not None
        and row.representation_assignment_row_sha256 is not None
    )
    if len(eligible) < 36:
        raise ValueError("enrichment candidate pool requires at least 36 candidates")
    pool_rows: list[EnrichmentPoolRow] = []
    for readiness_row in eligible:
        assert readiness_row.provider_place_candidate_id is not None
        assert readiness_row.representation_primary_group is not None
        assert readiness_row.representation_assignment_row_sha256 is not None
        linked_seed_ids = tuple(
            sorted(set(linked_seed_ids_by_place.get(readiness_row.place_entity_id, ())))
        )
        fields = {
            "place_entity_id": readiness_row.place_entity_id,
            "provider_candidate_id": readiness_row.provider_place_candidate_id,
            "primary_group": readiness_row.representation_primary_group,
            "group_ordinal": GROUP_ORDER.index(readiness_row.representation_primary_group),
            "linked_seed_ids": linked_seed_ids,
            "linked_seed_priority": bool(linked_seed_ids),
            "already_passing_objective_gate_count": (
                readiness_row.already_passing_objective_gate_count
            ),
            "readiness_row_sha256": readiness_row.row_sha256,
            "assignment_row_sha256": (readiness_row.representation_assignment_row_sha256),
        }
        pool_rows.append(EnrichmentPoolRow(**fields, row_sha256=canonical_sha256(fields)))
    ordered = tuple(
        sorted(
            pool_rows,
            key=lambda row: (
                not row.linked_seed_priority,
                -row.already_passing_objective_gate_count,
                row.group_ordinal,
                row.provider_candidate_id.encode("utf-8"),
            ),
        )[:60]
    )
    fields = {
        "schema_version": "enrichment-candidate-pool-v1",
        "data_version": "catalog-v2-enrichment-pool-data-v1",
        "algorithm_version": "linked-seed-gates-group-provider-id-v1",
        "group_order": GROUP_ORDER,
        "maximum_pool_size": 60,
        "eligible_candidate_count": len(eligible),
        "parents": parents.model_dump(mode="json"),
        "rows": [row.model_dump(mode="json") for row in ordered],
        "ordered_pool_ids": tuple(row.provider_candidate_id for row in ordered),
        "pool_count": len(ordered),
        "rows_root": canonical_sha256([row.model_dump(mode="json") for row in ordered]),
    }
    return EnrichmentCandidatePool(**fields, pool_sha256=canonical_sha256(fields))


def evaluate_readiness_candidate(
    *,
    objective_row: CandidateObjectiveRow,
    assignment: CandidateRepresentationAssignment | None,
    assignment_hash_valid: bool,
    expected_rule_table_sha256: str,
    t0_provider_candidate_ids: frozenset[str],
) -> CandidateReadinessRow:
    """Evaluate every named gate without accepting a selected catalog."""

    gate_states = {
        "coordinates": objective_row.coordinates.state,
        "description": objective_row.description.state,
        "operating_info": objective_row.operating_info.state,
        "dataset_rights": objective_row.dataset_rights.state,
        "direct_media": objective_row.direct_media.state,
    }
    deficits: list[str] = []
    provider_candidate_id: str | None = None
    if (
        len(objective_row.source_candidate_ids) == 1
        and objective_row.source_candidate_ids[0] in t0_provider_candidate_ids
    ):
        provider_candidate_id = objective_row.source_candidate_ids[0]
    else:
        deficits.append("NOT_SINGLE_T0_TOURAPI_PLACE")

    for gate_name, state in gate_states.items():
        if state is not GateState.PASS:
            deficits.append(f"{gate_name.upper()}_{state.value}")

    assignment_status: AssignmentStatus | Literal["MISSING", "HASH_INVALID"]
    primary_group: RepresentationGroup | None = None
    assignment_sha256: str | None = None
    if assignment is None:
        assignment_status = "MISSING"
        deficits.append("REPRESENTATION_ASSIGNMENT_MISSING")
    elif not assignment_hash_valid:
        assignment_status = "HASH_INVALID"
        assignment_sha256 = assignment.assignment_row_sha256
        deficits.append("REPRESENTATION_ASSIGNMENT_HASH_INVALID")
    elif assignment.place_entity_id != objective_row.place_entity_id:
        assignment_status = "HASH_INVALID"
        assignment_sha256 = assignment.assignment_row_sha256
        deficits.append("REPRESENTATION_ASSIGNMENT_PLACE_MISMATCH")
    elif assignment.objective_evidence_row_sha256 != objective_row.row_sha256:
        assignment_status = "HASH_INVALID"
        assignment_sha256 = assignment.assignment_row_sha256
        deficits.append("REPRESENTATION_ASSIGNMENT_EVIDENCE_MISMATCH")
    elif assignment.rule_table_sha256 != expected_rule_table_sha256:
        assignment_status = "HASH_INVALID"
        assignment_sha256 = assignment.assignment_row_sha256
        deficits.append("REPRESENTATION_RULE_TABLE_HASH_MISMATCH")
    else:
        assignment_status = assignment.status
        assignment_sha256 = assignment.assignment_row_sha256
        primary_group = assignment.primary_group
        if assignment.status == "UNCLASSIFIED":
            deficits.append("REPRESENTATION_ASSIGNMENT_UNCLASSIFIED")
        elif assignment.status == "AMBIGUOUS":
            deficits.append("REPRESENTATION_ASSIGNMENT_AMBIGUOUS")

    fields = {
        "place_entity_id": objective_row.place_entity_id,
        "source_crosswalk_row_id": objective_row.source_crosswalk_row_id,
        "source_candidate_ids": objective_row.source_candidate_ids,
        "source_dataset_entity_ids": objective_row.source_dataset_entity_ids,
        "provider_place_candidate_id": provider_candidate_id,
        "objective_evidence_row_sha256": objective_row.row_sha256,
        "objective_gate_states": gate_states,
        "representation_assignment_status": assignment_status,
        "representation_primary_group": primary_group,
        "representation_assignment_row_sha256": assignment_sha256,
        "already_passing_objective_gate_count": sum(
            state is GateState.PASS for state in gate_states.values()
        ),
        "named_deficits": tuple(deficits),
        "objective_eligible": not deficits,
        "confidence_is_qualification_filter_only": True,
        "confidence_adds_score": False,
    }
    return CandidateReadinessRow(**fields, row_sha256=canonical_sha256(fields))


def build_readiness_report(
    *,
    objective_evidence: CandidateObjectiveEvidence,
    assignments: Mapping[str, CandidateRepresentationAssignment],
    assignment_hash_validity: Mapping[str, bool],
    expected_rule_table_sha256: str,
    t0_provider_candidate_ids: frozenset[str],
    parents: ReadinessParents,
) -> CatalogReadinessReport:
    """Aggregate selection-independent readiness over every potential candidate."""

    rows = tuple(
        evaluate_readiness_candidate(
            objective_row=objective_row,
            assignment=assignments.get(objective_row.place_entity_id),
            assignment_hash_valid=assignment_hash_validity.get(
                objective_row.place_entity_id, False
            ),
            expected_rule_table_sha256=expected_rule_table_sha256,
            t0_provider_candidate_ids=t0_provider_candidate_ids,
        )
        for objective_row in objective_evidence.rows
    )
    deficit_counts = dict(
        sorted(Counter(deficit for row in rows for deficit in row.named_deficits).items())
    )
    fields = {
        "schema_version": "catalog-readiness-before-enrichment-v1",
        "data_version": "catalog-v2-readiness-data-v1",
        "parents": parents.model_dump(mode="json"),
        "rows": [row.model_dump(mode="json") for row in rows],
        "potential_candidate_count": len(rows),
        "objective_eligible_count": sum(row.objective_eligible for row in rows),
        "named_deficit_counts": deficit_counts,
        "rows_root": canonical_sha256([row.model_dump(mode="json") for row in rows]),
    }
    return CatalogReadinessReport.model_validate(
        {**fields, "report_sha256": canonical_sha256(fields)}
    )


OutcomeReason = Literal[
    "READY",
    "REMEDIATION_ROUND_ISSUED",
    "EVIDENCE_FRONTIER_EXHAUSTED",
    "NON_ADDRESSABLE_IDENTITY_REVIEW_OVERFLOW",
    "REPRESENTATION_INFEASIBLE",
]

FIELD_TO_GATE = {
    "coordinates": "coordinates",
    "korean_description": "description",
    "provider_specific_operating_information": "operating_info",
    "exact_provider_direct_media": "direct_media",
}
DEFICIT_TO_OPERATION = {
    "COORDINATES_MISSING": "detailCommon2",
    "DESCRIPTION_MISSING": "detailCommon2",
    "OPERATING_INFO_MISSING": "detailIntro2",
    "DIRECT_MEDIA_MISSING": "detailImage2",
}


class RoundManifestFile(StrictContract):
    relpath: Annotated[
        str,
        Field(strict=True, pattern=r"^[A-Za-z0-9._/-]+$", min_length=1),
    ]
    size: Annotated[int, Field(strict=True, ge=0)]
    mode: Annotated[str, Field(strict=True, pattern=r"^0[0-7]{3}$")]
    file_sha256: Sha256

    @model_validator(mode="after")
    def validate_relpath(self) -> Self:
        if self.relpath.startswith("/") or ".." in self.relpath.split("/"):
            raise ValueError("round manifest file escapes its round root")
        return self


class CatalogRoundManifest(StrictContract):
    schema_version: Literal["itda.catalog-enrichment-round-manifest.v1"]
    round_id: Sha256
    round_root: Annotated[str, Field(strict=True, min_length=1, max_length=1_000)]
    ancestry_depth: Annotated[int, Field(strict=True, ge=1)]
    previous_round_manifest_sha256: Sha256 | None
    immutable_files: tuple[RoundManifestFile, ...]
    immutable_files_root: Sha256
    sidecar_file_sha256: Sha256
    sidecar_sha256: Sha256
    manifest_sha256: Sha256

    @model_validator(mode="after")
    def validate_manifest(self) -> Self:
        paths = tuple(row.relpath for row in self.immutable_files)
        if paths != tuple(sorted(paths)) or len(paths) != len(set(paths)):
            raise ValueError("round manifest files must use unique canonical order")
        if self.ancestry_depth == 1 and self.previous_round_manifest_sha256 is not None:
            raise ValueError("initial round manifest cannot claim a previous parent")
        if self.ancestry_depth > 1 and self.previous_round_manifest_sha256 is None:
            raise ValueError("remediation round manifest requires previous ancestry")
        expected_root = canonical_sha256(
            [row.model_dump(mode="json") for row in self.immutable_files]
        )
        if self.immutable_files_root != expected_root:
            raise ValueError("round immutable-file root drifted")
        expected = canonical_sha256(self.model_dump(exclude={"manifest_sha256"}, mode="json"))
        if self.manifest_sha256 != expected:
            raise ValueError("round manifest sha256 drifted")
        return self


class RoundOrderEntry(StrictContract):
    ordinal: Annotated[int, Field(strict=True, ge=0)]
    round_id: Sha256
    round_root: Annotated[str, Field(strict=True, min_length=1, max_length=1_000)]
    ancestry_depth: Annotated[int, Field(strict=True, ge=1)]
    round_manifest_sha256: Sha256
    parent_round_manifest_sha256: Sha256 | None
    sidecar_file_sha256: Sha256
    sidecar_sha256: Sha256
    entry_sha256: Sha256

    @model_validator(mode="after")
    def validate_entry(self) -> Self:
        expected = canonical_sha256(self.model_dump(exclude={"entry_sha256"}, mode="json"))
        if self.entry_sha256 != expected:
            raise ValueError("round-order entry sha256 drifted")
        return self


class RoundOrderManifest(StrictContract):
    schema_version: Literal["itda.catalog-enrichment-round-order.v1"]
    entries: tuple[RoundOrderEntry, ...]
    round_count: Annotated[int, Field(strict=True, ge=1)]
    newest_round_id: Sha256
    newest_round_root: Annotated[
        str,
        Field(strict=True, min_length=1, max_length=1_000),
    ]
    newest_round_manifest_sha256: Sha256
    entries_root: Sha256
    manifest_sha256: Sha256

    @model_validator(mode="after")
    def validate_order(self) -> Self:
        if self.round_count != len(self.entries) or not self.entries:
            raise ValueError("round-order count is not entry-derived")
        if len({row.round_id for row in self.entries}) != len(self.entries):
            raise ValueError("round-order manifest contains duplicate rounds")
        previous: RoundOrderEntry | None = None
        for ordinal, row in enumerate(self.entries):
            if row.ordinal != ordinal or row.ancestry_depth != ordinal + 1:
                raise ValueError("round-order ancestry depth or order is invalid")
            expected_parent = None if previous is None else previous.round_manifest_sha256
            if row.parent_round_manifest_sha256 != expected_parent:
                raise ValueError("round-order ancestry chain is broken")
            previous = row
        newest = self.entries[-1]
        if (
            self.newest_round_id != newest.round_id
            or self.newest_round_root != newest.round_root
            or self.newest_round_manifest_sha256 != newest.round_manifest_sha256
        ):
            raise ValueError("round-order newest round mismatch")
        expected_root = canonical_sha256([row.model_dump(mode="json") for row in self.entries])
        if self.entries_root != expected_root:
            raise ValueError("round-order entries root drifted")
        expected = canonical_sha256(self.model_dump(exclude={"manifest_sha256"}, mode="json"))
        if self.manifest_sha256 != expected:
            raise ValueError("round-order manifest sha256 drifted")
        return self


def build_round_order_manifest(
    manifests: tuple[CatalogRoundManifest, ...],
) -> RoundOrderManifest:
    if not manifests:
        raise ValueError("round-order manifest requires explicit rounds")
    entries: list[RoundOrderEntry] = []
    for ordinal, manifest in enumerate(manifests):
        expected_parent = None if ordinal == 0 else manifests[ordinal - 1].manifest_sha256
        if (
            manifest.ancestry_depth != ordinal + 1
            or manifest.previous_round_manifest_sha256 != expected_parent
        ):
            raise ValueError("round manifest ancestry does not match explicit order")
        fields = {
            "ordinal": ordinal,
            "round_id": manifest.round_id,
            "round_root": manifest.round_root,
            "ancestry_depth": manifest.ancestry_depth,
            "round_manifest_sha256": manifest.manifest_sha256,
            "parent_round_manifest_sha256": expected_parent,
            "sidecar_file_sha256": manifest.sidecar_file_sha256,
            "sidecar_sha256": manifest.sidecar_sha256,
        }
        entries.append(RoundOrderEntry(**fields, entry_sha256=canonical_sha256(fields)))
    newest = entries[-1]
    fields = {
        "schema_version": "itda.catalog-enrichment-round-order.v1",
        "entries": [row.model_dump(mode="json") for row in entries],
        "round_count": len(entries),
        "newest_round_id": newest.round_id,
        "newest_round_root": newest.round_root,
        "newest_round_manifest_sha256": newest.round_manifest_sha256,
        "entries_root": canonical_sha256([row.model_dump(mode="json") for row in entries]),
    }
    return RoundOrderManifest(**fields, manifest_sha256=canonical_sha256(fields))


class AggregateReadinessRow(StrictContract):
    place_entity_id: Annotated[
        str,
        Field(strict=True, pattern=r"^place:[0-9a-f]{64}$"),
    ]
    provider_place_candidate_id: Annotated[
        str | None,
        Field(strict=True, pattern=r"^candidate:tour-api:[0-9]+$"),
    ] = None
    representation_assignment_status: AssignmentStatus | Literal["MISSING", "HASH_INVALID"]
    representation_primary_group: RepresentationGroup | None
    objective_gate_states: dict[str, GateState]
    evidence_round_ids: tuple[Sha256, ...]
    named_deficits: tuple[str, ...]
    objective_eligible: Annotated[bool, Field(strict=True)]
    row_sha256: Sha256

    @model_validator(mode="after")
    def validate_aggregate_row(self) -> Self:
        if set(self.objective_gate_states) != {
            "coordinates",
            "description",
            "operating_info",
            "dataset_rights",
            "direct_media",
        }:
            raise ValueError("aggregate row requires every objective gate")
        if self.objective_eligible != (not self.named_deficits):
            raise ValueError("aggregate row eligibility is not deficit-derived")
        expected = canonical_sha256(self.model_dump(exclude={"row_sha256"}, mode="json"))
        if self.row_sha256 != expected:
            raise ValueError("aggregate readiness row sha256 drifted")
        return self


class RemediationFrontierRow(StrictContract):
    source_neutral_id: Annotated[
        str,
        Field(strict=True, pattern=r"^place:[0-9a-f]{64}$"),
    ]
    provider_candidate_id: Annotated[
        str,
        Field(strict=True, pattern=r"^candidate:tour-api:[0-9]+$"),
    ]
    primary_group: RepresentationGroup
    mandatory_deficits: tuple[str, ...]
    mandatory_deficit_count: Annotated[int, Field(strict=True, ge=1, le=4)]
    under_target_group_need: Annotated[int, Field(strict=True, ge=0, le=6)]
    missing_operations: tuple[
        Literal["detailCommon2", "detailIntro2", "detailImage2"],
        ...,
    ]
    row_sha256: Sha256

    @model_validator(mode="after")
    def validate_frontier(self) -> Self:
        if self.mandatory_deficit_count != len(self.mandatory_deficits):
            raise ValueError("frontier deficit count is not row-derived")
        expected_operations = tuple(
            operation
            for operation in APPROVED_OPERATIONS
            if operation in {DEFICIT_TO_OPERATION[deficit] for deficit in self.mandatory_deficits}
        )
        if self.missing_operations != expected_operations:
            raise ValueError("frontier operation mapping drifted")
        expected = canonical_sha256(self.model_dump(exclude={"row_sha256"}, mode="json"))
        if self.row_sha256 != expected:
            raise ValueError("frontier row sha256 drifted")
        return self


class RemediationPoolRow(StrictContract):
    place_entity_id: Annotated[
        str,
        Field(strict=True, pattern=r"^place:[0-9a-f]{64}$"),
    ]
    provider_candidate_id: Annotated[
        str,
        Field(strict=True, pattern=r"^candidate:tour-api:[0-9]+$"),
    ]
    primary_group: RepresentationGroup
    source_neutral_id: Annotated[
        str,
        Field(strict=True, pattern=r"^place:[0-9a-f]{64}$"),
    ]
    mandatory_deficits: tuple[str, ...]
    mandatory_deficit_count: Annotated[int, Field(strict=True, ge=1, le=4)]
    under_target_group_need: Annotated[int, Field(strict=True, ge=0, le=6)]
    missing_operations: tuple[
        Literal["detailCommon2", "detailIntro2", "detailImage2"],
        ...,
    ]
    frontier_row_sha256: Sha256
    row_sha256: Sha256

    @model_validator(mode="after")
    def validate_pool_row(self) -> Self:
        if self.source_neutral_id != self.place_entity_id:
            raise ValueError("remediation pool rank key must be source-neutral")
        expected = canonical_sha256(self.model_dump(exclude={"row_sha256"}, mode="json"))
        if self.row_sha256 != expected:
            raise ValueError("remediation pool row sha256 drifted")
        return self


class RemediationCandidatePool(StrictContract):
    schema_version: Literal["enrichment-remediation-candidate-pool-v1"]
    data_version: Literal["catalog-v2-remediation-pool-data-v1"]
    algorithm_version: Literal["deficits-group-lower-bound-source-neutral-v1"]
    group_order: tuple[RepresentationGroup, ...]
    maximum_pool_size: Literal[60]
    parents: dict[str, object]
    rows: tuple[RemediationPoolRow, ...]
    ordered_pool_ids: tuple[str, ...]
    pool_count: Annotated[int, Field(strict=True, ge=1, le=60)]
    rows_root: Sha256
    pool_sha256: Sha256

    @model_validator(mode="after")
    def validate_pool(self) -> Self:
        if self.group_order != GROUP_ORDER:
            raise ValueError("remediation pool group order drifted")
        if self.pool_count != len(self.rows) or self.pool_count != len(self.ordered_pool_ids):
            raise ValueError("remediation pool count is not row-derived")
        if tuple(row.provider_candidate_id for row in self.rows) != (self.ordered_pool_ids):
            raise ValueError("remediation pool ordered identities drifted")
        expected_order = tuple(
            sorted(
                self.rows,
                key=lambda row: (
                    row.mandatory_deficit_count,
                    -row.under_target_group_need,
                    row.source_neutral_id.encode("utf-8"),
                    row.provider_candidate_id.encode("utf-8"),
                ),
            )
        )
        if self.rows != expected_order:
            raise ValueError("remediation pool violates deterministic frontier order")
        if self.rows_root != canonical_sha256([row.model_dump(mode="json") for row in self.rows]):
            raise ValueError("remediation pool rows root drifted")
        expected = canonical_sha256(self.model_dump(exclude={"pool_sha256"}, mode="json"))
        if self.pool_sha256 != expected:
            raise ValueError("remediation pool sha256 drifted")
        return self


class RepresentationQuotaConfig(StrictContract):
    schema_version: Literal["itda.catalog-representation-quota-config.v1"]
    policy_version: Literal["reinforcement-12-full-pool-quota-v1"]
    representation_rule_sha256: Sha256
    fixed_group_order: tuple[RepresentationGroup, ...]
    seat_count: Literal[36]
    lower_bound: Literal[6]
    upper_bound: Literal[12]
    algorithm: Literal["bounded-largest-remainder-v1"]
    tie_break: Literal["fixed-group-order-v1"]
    config_sha256: Sha256

    @model_validator(mode="after")
    def validate_config(self) -> Self:
        if self.fixed_group_order != GROUP_ORDER:
            raise ValueError("representation quota config changed the fixed group order")
        expected = canonical_sha256(self.model_dump(exclude={"config_sha256"}, mode="json"))
        if self.config_sha256 != expected:
            raise ValueError("representation quota config sha256 drifted")
        return self


class RepresentationQuotaAttestation(StrictContract):
    schema_version: Literal["itda.catalog-representation-quota-attestation.v1"]
    config_sha256: Sha256
    eligible_pool_sha256: Sha256
    eligible_pool_count: Annotated[int, Field(strict=True, ge=0)]
    raw_eligible_group_counts: dict[
        RepresentationGroup,
        Annotated[int, Field(strict=True, ge=0)],
    ]
    missing_assignment_count: Annotated[int, Field(strict=True, ge=0)]
    ambiguous_assignment_count: Annotated[int, Field(strict=True, ge=0)]
    ideal_share_numerators: dict[
        RepresentationGroup,
        Annotated[int, Field(strict=True, ge=0)],
    ]
    ideal_share_denominator: Annotated[int, Field(strict=True, ge=1)]
    floor_quotas: dict[RepresentationGroup, Annotated[int, Field(strict=True, ge=0)]]
    fractional_remainders: dict[
        RepresentationGroup,
        Annotated[int, Field(strict=True, ge=0)],
    ]
    availability_upper_bounds: dict[
        RepresentationGroup,
        Annotated[int, Field(strict=True, ge=0)],
    ]
    final_quotas: dict[RepresentationGroup, Annotated[int, Field(strict=True, ge=0)]]
    quota_sum: Annotated[int, Field(strict=True, ge=0)]
    feasible: bool
    outcome_code: Literal[0, 23]
    failure_reason: Literal["REPRESENTATION_INFEASIBLE"] | None
    attestation_sha256: Sha256

    @model_validator(mode="after")
    def validate_attestation(self) -> Self:
        required_keys = set(GROUP_ORDER)
        for field_name in (
            "raw_eligible_group_counts",
            "ideal_share_numerators",
            "floor_quotas",
            "fractional_remainders",
            "availability_upper_bounds",
        ):
            if set(getattr(self, field_name)) != required_keys:
                raise ValueError(f"representation quota attestation {field_name} keys drifted")
        assigned_count = sum(self.raw_eligible_group_counts.values())
        if self.eligible_pool_count != (
            assigned_count + self.missing_assignment_count + self.ambiguous_assignment_count
        ):
            raise ValueError("representation quota eligible pool count drifted")
        if self.ideal_share_denominator != max(1, self.eligible_pool_count):
            raise ValueError("representation quota ideal denominator drifted")
        expected_numerators = {
            group: 36 * self.raw_eligible_group_counts[group] for group in GROUP_ORDER
        }
        if self.ideal_share_numerators != expected_numerators:
            raise ValueError("representation quota ideal numerators drifted")
        expected_floors = {
            group: expected_numerators[group] // self.ideal_share_denominator
            for group in GROUP_ORDER
        }
        expected_remainders = {
            group: expected_numerators[group] % self.ideal_share_denominator
            for group in GROUP_ORDER
        }
        if self.floor_quotas != expected_floors:
            raise ValueError("representation quota floors drifted")
        if self.fractional_remainders != expected_remainders:
            raise ValueError("representation quota remainders drifted")
        expected_availability = {
            group: min(12, self.raw_eligible_group_counts[group]) for group in GROUP_ORDER
        }
        if self.availability_upper_bounds != expected_availability:
            raise ValueError("representation quota availability bounds drifted")
        if self.quota_sum != sum(self.final_quotas.values()):
            raise ValueError("representation quota sum drifted")
        if self.feasible:
            if self.outcome_code != 0 or self.failure_reason is not None:
                raise ValueError("feasible representation quota outcome drifted")
            if set(self.final_quotas) != required_keys or self.quota_sum != 36:
                raise ValueError("feasible representation quota does not allocate 36 seats")
            if any(
                not 6 <= self.final_quotas[group] <= min(12, self.raw_eligible_group_counts[group])
                for group in GROUP_ORDER
            ):
                raise ValueError("feasible representation quota violates bounds")
        elif (
            self.outcome_code != 23
            or self.failure_reason != "REPRESENTATION_INFEASIBLE"
            or self.final_quotas
            or self.quota_sum
        ):
            raise ValueError("infeasible representation quota is not fail closed")
        expected = canonical_sha256(self.model_dump(exclude={"attestation_sha256"}, mode="json"))
        if self.attestation_sha256 != expected:
            raise ValueError("representation quota attestation sha256 drifted")
        return self


def _default_representation_quota_config(
    *,
    representation_rule_sha256: Sha256,
) -> RepresentationQuotaConfig:
    fields = {
        "schema_version": "itda.catalog-representation-quota-config.v1",
        "policy_version": "reinforcement-12-full-pool-quota-v1",
        "representation_rule_sha256": representation_rule_sha256,
        "fixed_group_order": GROUP_ORDER,
        "seat_count": 36,
        "lower_bound": 6,
        "upper_bound": 12,
        "algorithm": "bounded-largest-remainder-v1",
        "tie_break": "fixed-group-order-v1",
    }
    return RepresentationQuotaConfig(
        **fields,
        config_sha256=canonical_sha256(fields),
    )


def _adjust_quota_seats(
    quotas: dict[RepresentationGroup, int],
    *,
    target: int,
    remainders: Mapping[RepresentationGroup, int],
    availability: Mapping[RepresentationGroup, int],
) -> bool:
    while sum(quotas.values()) != target:
        adding = sum(quotas.values()) < target
        ordered = sorted(
            GROUP_ORDER,
            key=lambda group: (
                -remainders[group] if adding else remainders[group],
                GROUP_ORDER.index(group),
            ),
        )
        changed = False
        for group in ordered:
            if adding and quotas[group] < availability[group]:
                quotas[group] += 1
                changed = True
            elif not adding and quotas[group] > 6:
                quotas[group] -= 1
                changed = True
            if sum(quotas.values()) == target:
                return True
        if not changed:
            return False
    return True


def build_representation_quota_artifacts(
    *,
    eligible_pool_sha256: Sha256,
    representation_rule_sha256: Sha256,
    raw_eligible_group_counts: Mapping[RepresentationGroup, int],
    missing_assignment_count: int = 0,
    ambiguous_assignment_count: int = 0,
) -> tuple[RepresentationQuotaConfig, RepresentationQuotaAttestation]:
    if set(raw_eligible_group_counts) != set(GROUP_ORDER):
        raise ValueError("representation quota requires every fixed group")
    if (
        any(
            isinstance(count, bool) or not isinstance(count, int) or count < 0
            for count in raw_eligible_group_counts.values()
        )
        or isinstance(missing_assignment_count, bool)
        or not isinstance(missing_assignment_count, int)
        or missing_assignment_count < 0
        or isinstance(ambiguous_assignment_count, bool)
        or not isinstance(ambiguous_assignment_count, int)
        or ambiguous_assignment_count < 0
    ):
        raise ValueError("representation quota counts must be nonnegative integers")
    counts = {group: raw_eligible_group_counts[group] for group in GROUP_ORDER}
    eligible_pool_count = (
        sum(counts.values()) + missing_assignment_count + ambiguous_assignment_count
    )
    denominator = max(1, eligible_pool_count)
    numerators = {group: 36 * counts[group] for group in GROUP_ORDER}
    floors = {group: numerators[group] // denominator for group in GROUP_ORDER}
    remainders = {group: numerators[group] % denominator for group in GROUP_ORDER}
    availability = {group: min(12, counts[group]) for group in GROUP_ORDER}
    config = _default_representation_quota_config(
        representation_rule_sha256=representation_rule_sha256,
    )
    impossible = (
        missing_assignment_count > 0
        or ambiguous_assignment_count > 0
        or eligible_pool_count < 36
        or any(counts[group] < 6 for group in GROUP_ORDER)
        or sum(availability.values()) < 36
    )
    quotas: dict[RepresentationGroup, int] = {}
    if not impossible:
        quotas = {group: min(max(floors[group], 6), availability[group]) for group in GROUP_ORDER}
        impossible = not _adjust_quota_seats(
            quotas,
            target=36,
            remainders=remainders,
            availability=availability,
        )
    fields = {
        "schema_version": "itda.catalog-representation-quota-attestation.v1",
        "config_sha256": config.config_sha256,
        "eligible_pool_sha256": eligible_pool_sha256,
        "eligible_pool_count": eligible_pool_count,
        "raw_eligible_group_counts": counts,
        "missing_assignment_count": missing_assignment_count,
        "ambiguous_assignment_count": ambiguous_assignment_count,
        "ideal_share_numerators": numerators,
        "ideal_share_denominator": denominator,
        "floor_quotas": floors,
        "fractional_remainders": remainders,
        "availability_upper_bounds": availability,
        "final_quotas": {} if impossible else quotas,
        "quota_sum": 0 if impossible else sum(quotas.values()),
        "feasible": not impossible,
        "outcome_code": 23 if impossible else 0,
        "failure_reason": "REPRESENTATION_INFEASIBLE" if impossible else None,
    }
    return config, RepresentationQuotaAttestation(
        **fields,
        attestation_sha256=canonical_sha256(fields),
    )


class AggregateReadiness(StrictContract):
    schema_version: Literal["itda.catalog-aggregate-readiness.v1"]
    base_readiness_report_sha256: Sha256
    entity_policy_file_sha256: Sha256
    entity_policy_report_sha256: Sha256
    formal_policy_sha256: Sha256
    protected_inputs_sha256: Sha256
    complete_dispositions_root: Sha256
    media_attachments_root: Sha256
    ordered_round_manifest_sha256: Sha256
    ordered_round_ids: tuple[Sha256, ...]
    rows: tuple[AggregateReadinessRow, ...]
    potential_candidate_count: Annotated[int, Field(strict=True, ge=0)]
    objective_eligible_count: Annotated[int, Field(strict=True, ge=0)]
    eligible_group_counts: dict[RepresentationGroup, Annotated[int, Field(strict=True, ge=0)]]
    named_deficit_counts: dict[str, Annotated[int, Field(strict=True, ge=1)]]
    human_identity_relationship_decisions: Annotated[int, Field(strict=True, ge=0)]
    required_objective_eligible: Annotated[int, Field(strict=True, ge=1)]
    maximum_human_decisions: Annotated[int, Field(strict=True, ge=0)]
    attempted_provider_ids: tuple[str, ...]
    attempted_provider_ids_root: Sha256
    addressable_frontier_count: Annotated[int, Field(strict=True, ge=0)]
    outcome_code: Literal[0, 20, 21, 22, 23]
    outcome_reason: OutcomeReason
    rows_root: Sha256
    aggregate_sha256: Sha256

    @model_validator(mode="after")
    def validate_aggregate(self) -> Self:
        if self.potential_candidate_count != len(self.rows):
            raise ValueError("aggregate candidate count is not row-derived")
        if self.objective_eligible_count != sum(row.objective_eligible for row in self.rows):
            raise ValueError("aggregate eligible count is not row-derived")
        expected_groups = {
            group: sum(
                row.objective_eligible and row.representation_primary_group == group
                for row in self.rows
            )
            for group in GROUP_ORDER
        }
        if self.eligible_group_counts != expected_groups:
            raise ValueError("aggregate eligible group counts drifted")
        expected_deficits = dict(
            sorted(Counter(deficit for row in self.rows for deficit in row.named_deficits).items())
        )
        if self.named_deficit_counts != expected_deficits:
            raise ValueError("aggregate named deficit counts drifted")
        if self.attempted_provider_ids != tuple(sorted(set(self.attempted_provider_ids))):
            raise ValueError("attempted provider identities are not canonical")
        if self.attempted_provider_ids_root != canonical_sha256(list(self.attempted_provider_ids)):
            raise ValueError("attempted provider identity root drifted")
        expected_rows_root = canonical_sha256([row.model_dump(mode="json") for row in self.rows])
        if self.rows_root != expected_rows_root:
            raise ValueError("aggregate rows root drifted")
        expected = canonical_sha256(self.model_dump(exclude={"aggregate_sha256"}, mode="json"))
        if self.aggregate_sha256 != expected:
            raise ValueError("aggregate readiness sha256 drifted")
        return self


def _aggregate_named_deficits(
    *,
    provider_candidate_id: str | None,
    gates: Mapping[str, GateState],
    assignment_status: str,
) -> tuple[str, ...]:
    deficits: list[str] = []
    if provider_candidate_id is None:
        deficits.append("NOT_SINGLE_T0_TOURAPI_PLACE")
    for gate_name, state in gates.items():
        if state is not GateState.PASS:
            deficits.append(f"{gate_name.upper()}_{state.value}")
    if assignment_status in {"MISSING", "HASH_INVALID"} or assignment_status != "PRIMARY":
        deficits.append(f"REPRESENTATION_ASSIGNMENT_{assignment_status}")
    return tuple(deficits)


def _frontier_rows(
    rows: tuple[AggregateReadinessRow, ...],
    *,
    attempted: frozenset[str],
    maximum_candidates: int,
) -> tuple[RemediationFrontierRow, ...]:
    eligible_counts = {
        group: sum(
            row.objective_eligible and row.representation_primary_group == group for row in rows
        )
        for group in GROUP_ORDER
    }
    candidates: list[RemediationFrontierRow] = []
    for row in rows:
        provider_id = row.provider_place_candidate_id
        group = row.representation_primary_group
        if (
            provider_id is None
            or provider_id in attempted
            or row.representation_assignment_status != "PRIMARY"
            or group is None
            or row.objective_gate_states["dataset_rights"] is not GateState.PASS
        ):
            continue
        mandatory = tuple(
            deficit for deficit in row.named_deficits if deficit in DEFICIT_TO_OPERATION
        )
        if not mandatory:
            continue
        operations = tuple(
            operation
            for operation in APPROVED_OPERATIONS
            if operation in {DEFICIT_TO_OPERATION[item] for item in mandatory}
        )
        fields = {
            "source_neutral_id": row.place_entity_id,
            "provider_candidate_id": provider_id,
            "primary_group": group,
            "mandatory_deficits": mandatory,
            "mandatory_deficit_count": len(mandatory),
            "under_target_group_need": max(0, 6 - eligible_counts[group]),
            "missing_operations": operations,
        }
        candidates.append(
            RemediationFrontierRow(
                **fields,
                row_sha256=canonical_sha256(fields),
            )
        )
    return tuple(
        sorted(
            candidates,
            key=lambda row: (
                row.mandatory_deficit_count,
                -row.under_target_group_need,
                row.source_neutral_id.encode("utf-8"),
                row.provider_candidate_id.encode("utf-8"),
            ),
        )[:maximum_candidates]
    )


def rank_remediation_frontier(
    aggregate: AggregateReadiness,
    *,
    maximum_candidates: int = 60,
) -> tuple[RemediationFrontierRow, ...]:
    if not 1 <= maximum_candidates <= 60:
        raise ValueError("remediation frontier maximum must be between 1 and 60")
    return _frontier_rows(
        aggregate.rows,
        attempted=frozenset(aggregate.attempted_provider_ids),
        maximum_candidates=maximum_candidates,
    )


def build_remediation_candidate_pool(
    aggregate: AggregateReadiness,
    *,
    parents: Mapping[str, object],
    maximum_candidates: int = 60,
) -> RemediationCandidatePool:
    frontier = rank_remediation_frontier(
        aggregate,
        maximum_candidates=maximum_candidates,
    )
    if not frontier:
        raise ValueError("remediation candidate pool requires a nonempty frontier")
    rows: list[RemediationPoolRow] = []
    for frontier_row in frontier:
        fields = {
            "place_entity_id": frontier_row.source_neutral_id,
            "provider_candidate_id": frontier_row.provider_candidate_id,
            "primary_group": frontier_row.primary_group,
            "source_neutral_id": frontier_row.source_neutral_id,
            "mandatory_deficits": frontier_row.mandatory_deficits,
            "mandatory_deficit_count": frontier_row.mandatory_deficit_count,
            "under_target_group_need": frontier_row.under_target_group_need,
            "missing_operations": frontier_row.missing_operations,
            "frontier_row_sha256": frontier_row.row_sha256,
        }
        rows.append(
            RemediationPoolRow(
                **fields,
                row_sha256=canonical_sha256(fields),
            )
        )
    ordered = tuple(rows)
    fields = {
        "schema_version": "enrichment-remediation-candidate-pool-v1",
        "data_version": "catalog-v2-remediation-pool-data-v1",
        "algorithm_version": "deficits-group-lower-bound-source-neutral-v1",
        "group_order": GROUP_ORDER,
        "maximum_pool_size": 60,
        "parents": dict(parents),
        "rows": [row.model_dump(mode="json") for row in ordered],
        "ordered_pool_ids": tuple(row.provider_candidate_id for row in ordered),
        "pool_count": len(ordered),
        "rows_root": canonical_sha256([row.model_dump(mode="json") for row in ordered]),
    }
    return RemediationCandidatePool(
        **fields,
        pool_sha256=canonical_sha256(fields),
    )


def build_aggregate_readiness(
    *,
    base_readiness: CatalogReadinessReport,
    entity_policy: EntityPolicyReport,
    ordered_manifest: RoundOrderManifest,
    sidecars: tuple[EnrichmentEvidenceSidecar, ...],
    require_objective_eligible: int,
    max_human_decisions: int,
    attempted_provider_ids: frozenset[str] | None = None,
) -> AggregateReadiness:
    if len(sidecars) != ordered_manifest.round_count:
        raise ValueError("ordered round manifest and sidecar inventory differ")
    by_provider = {
        row.provider_place_candidate_id: row
        for row in base_readiness.rows
        if row.provider_place_candidate_id is not None
    }
    gates_by_place = {
        row.place_entity_id: dict(row.objective_gate_states) for row in base_readiness.rows
    }
    rounds_by_place: dict[str, list[str]] = {row.place_entity_id: [] for row in base_readiness.rows}
    observed_attempted: set[str] = set()
    for entry, sidecar in zip(
        ordered_manifest.entries,
        sidecars,
        strict=True,
    ):
        if (
            sidecar.round_id != entry.round_id
            or sidecar.round_root != entry.round_root
            or sidecar.sidecar_sha256 != entry.sidecar_sha256
        ):
            raise ValueError("ordered sidecar does not match its round manifest")
        for response in sidecar.responses:
            observed_attempted.add(response.provider_candidate_id)
            base_row = by_provider.get(response.provider_candidate_id)
            if base_row is None or base_row.place_entity_id != response.place_entity_id:
                raise ValueError("sidecar response is outside the full potential inventory")
            if entry.round_id not in rounds_by_place[base_row.place_entity_id]:
                rounds_by_place[base_row.place_entity_id].append(entry.round_id)
            for field in response.fields:
                gate_name = FIELD_TO_GATE[field.field_name]
                current = gates_by_place[base_row.place_entity_id][gate_name]
                if field.state == "POPULATED":
                    if (
                        field.rights.rights_state != "ALLOWED"
                        or not field.rights.analysis_eligible
                        or not field.rights.ui_eligible
                        or not field.rights.demo_eligible
                    ):
                        raise ValueError("populated evidence lacks exact passing rights")
                    gates_by_place[base_row.place_entity_id][gate_name] = GateState.PASS
                elif current is not GateState.PASS:
                    gates_by_place[base_row.place_entity_id][gate_name] = GateState(
                        "BLOCKED" if field.state in {"BLOCKED", "REVIEW_REQUIRED"} else "MISSING"
                    )
    attempted = (
        frozenset(observed_attempted)
        if attempted_provider_ids is None
        else frozenset(attempted_provider_ids)
    )
    rows: list[AggregateReadinessRow] = []
    for base_row in base_readiness.rows:
        gates = gates_by_place[base_row.place_entity_id]
        deficits = _aggregate_named_deficits(
            provider_candidate_id=base_row.provider_place_candidate_id,
            gates=gates,
            assignment_status=base_row.representation_assignment_status,
        )
        fields = {
            "place_entity_id": base_row.place_entity_id,
            "provider_place_candidate_id": base_row.provider_place_candidate_id,
            "representation_assignment_status": (base_row.representation_assignment_status),
            "representation_primary_group": base_row.representation_primary_group,
            "objective_gate_states": gates,
            "evidence_round_ids": tuple(rounds_by_place[base_row.place_entity_id]),
            "named_deficits": deficits,
            "objective_eligible": not deficits,
        }
        rows.append(
            AggregateReadinessRow(
                **fields,
                row_sha256=canonical_sha256(fields),
            )
        )
    ordered_rows = tuple(rows)
    human_decisions = (
        entity_policy.counts.crosswalk_unresolved + entity_policy.counts.relationship_unresolved
    )
    provisional_frontier = _frontier_rows(
        ordered_rows,
        attempted=attempted,
        maximum_candidates=60,
    )
    eligible_count = sum(row.objective_eligible for row in ordered_rows)
    if human_decisions > max_human_decisions:
        outcome_code = 22
        outcome_reason: OutcomeReason = "NON_ADDRESSABLE_IDENTITY_REVIEW_OVERFLOW"
    elif eligible_count < require_objective_eligible:
        if provisional_frontier:
            outcome_code = 20
            outcome_reason = "REMEDIATION_ROUND_ISSUED"
        else:
            outcome_code = 21
            outcome_reason = "EVIDENCE_FRONTIER_EXHAUSTED"
    else:
        outcome_code = 0
        outcome_reason = "READY"
    deficit_counts = dict(
        sorted(Counter(deficit for row in ordered_rows for deficit in row.named_deficits).items())
    )
    policy_file_sha256 = base_readiness.parents.entity_policy_file_sha256
    fields = {
        "schema_version": "itda.catalog-aggregate-readiness.v1",
        "base_readiness_report_sha256": base_readiness.report_sha256,
        "entity_policy_file_sha256": policy_file_sha256,
        "entity_policy_report_sha256": entity_policy.report_sha256,
        "formal_policy_sha256": entity_policy.formal_policy_sha256,
        "protected_inputs_sha256": entity_policy.parents.protected_inputs_sha256,
        "complete_dispositions_root": base_readiness.parents.complete_dispositions_root,
        "media_attachments_root": entity_policy.roots["media_attachments"],
        "ordered_round_manifest_sha256": ordered_manifest.manifest_sha256,
        "ordered_round_ids": tuple(row.round_id for row in ordered_manifest.entries),
        "rows": [row.model_dump(mode="json") for row in ordered_rows],
        "potential_candidate_count": len(ordered_rows),
        "objective_eligible_count": eligible_count,
        "eligible_group_counts": {
            group: sum(
                row.objective_eligible and row.representation_primary_group == group
                for row in ordered_rows
            )
            for group in GROUP_ORDER
        },
        "named_deficit_counts": deficit_counts,
        "human_identity_relationship_decisions": human_decisions,
        "required_objective_eligible": require_objective_eligible,
        "maximum_human_decisions": max_human_decisions,
        "attempted_provider_ids": tuple(sorted(attempted)),
        "attempted_provider_ids_root": canonical_sha256(sorted(attempted)),
        "addressable_frontier_count": len(provisional_frontier),
        "outcome_code": outcome_code,
        "outcome_reason": outcome_reason,
        "rows_root": canonical_sha256([row.model_dump(mode="json") for row in ordered_rows]),
    }
    return AggregateReadiness(
        **fields,
        aggregate_sha256=canonical_sha256(fields),
    )


def derive_kto_recovery_readiness(
    *,
    normalization: Mapping[str, object],
    aggregate: Mapping[str, object],
    request_manifest: Mapping[str, object],
    candidate_names: Mapping[str, str],
) -> KtoRecoveryReadiness:
    """Replay exact Plan 49 readiness from immutable leaves only."""

    ancestry = {
        "kto_normalization_root": normalization.get("kto_normalization_root"),
        "kto_rights_attestation_sha256": normalization.get("kto_rights_attestation_sha256"),
        "kto_collection_base": normalization.get("kto_collection_base"),
        "kto_collection_success_root": normalization.get("kto_collection_success_root"),
        "kto_eligibility_root": normalization.get("kto_eligibility_root"),
        "kto_request_manifest_sha256": normalization.get("kto_request_manifest_sha256"),
        "aggregate_readiness_file_sha256": aggregate.get("aggregate_readiness_file_sha256"),
        "aggregate_readiness_sha256": aggregate.get("aggregate_sha256"),
        "entity_projection_file_sha256": aggregate.get("entity_projection_file_sha256"),
    }
    if any(not isinstance(value, str) or len(value) != 64 for value in ancestry.values()):
        raise ValueError("KTO readiness ancestry is incomplete")
    ancestry_sha256 = canonical_sha256(ancestry)
    responses_value = normalization.get("responses")
    requests_value = request_manifest.get("requests")
    aggregate_rows_value = aggregate.get("rows")
    if (
        not isinstance(responses_value, list)
        or len(responses_value) != 48
        or not isinstance(requests_value, list)
        or len(requests_value) != 48
        or not isinstance(aggregate_rows_value, list)
        or len(aggregate_rows_value) != 718
    ):
        raise ValueError("KTO readiness leaf inventories drifted")
    responses = [row for row in responses_value if isinstance(row, Mapping)]
    requests = [row for row in requests_value if isinstance(row, Mapping)]
    aggregate_rows = [row for row in aggregate_rows_value if isinstance(row, Mapping)]
    if len(responses) != 48 or len(requests) != 48 or len(aggregate_rows) != 718:
        raise ValueError("KTO readiness contains a non-object leaf")
    response_ids = {str(row.get("request_identity", "")) for row in responses}
    request_ids = {str(row.get("request_identity", "")) for row in requests}
    if response_ids != request_ids or len(request_ids) != 48:
        raise ValueError("KTO normalization and request identities differ")
    response_by_request = {str(row["request_identity"]): row for row in responses}
    target_requests: dict[str, dict[str, Mapping[str, object]]] = {}
    for request in requests:
        candidate_id = str(request.get("provider_candidate_id", ""))
        operation = str(request.get("operation", ""))
        if (
            not candidate_id.startswith("candidate:tour-api:")
            or operation not in {"detailCommon2", "detailImage2"}
            or operation in target_requests.setdefault(candidate_id, {})
        ):
            raise ValueError("KTO target request pairs are invalid")
        target_requests[candidate_id][operation] = request
    if len(target_requests) != 24 or any(
        set(operations) != {"detailCommon2", "detailImage2"}
        for operations in target_requests.values()
    ):
        raise ValueError("KTO target scope is not exactly 24 Common/Image pairs")
    aggregate_by_candidate: dict[str, Mapping[str, object]] = {}
    for aggregate_row in aggregate_rows:
        aggregate_candidate_id = aggregate_row.get("provider_place_candidate_id")
        if isinstance(aggregate_candidate_id, str):
            aggregate_by_candidate[aggregate_candidate_id] = aggregate_row
    place_ids = [str(row.get("place_entity_id", "")) for row in aggregate_rows]
    provider_row_count = sum(
        isinstance(row.get("provider_place_candidate_id"), str) for row in aggregate_rows
    )
    if len(set(place_ids)) != 718 or len(aggregate_by_candidate) != provider_row_count:
        raise ValueError("full source-neutral candidate universe is not unique")

    target_replay_rows: list[dict[str, Any]] = []
    target_eligibility: dict[str, bool] = {}
    for candidate_id, operations in target_requests.items():
        base_row = aggregate_by_candidate.get(candidate_id)
        if base_row is None:
            raise ValueError("KTO target is outside the complete candidate universe")
        common = response_by_request[str(operations["detailCommon2"]["request_identity"])]
        image = response_by_request[str(operations["detailImage2"]["request_identity"])]
        if (
            common.get("provider_candidate_id") != candidate_id
            or image.get("provider_candidate_id") != candidate_id
            or common.get("place_entity_id") != base_row.get("place_entity_id")
            or image.get("place_entity_id") != base_row.get("place_entity_id")
        ):
            raise ValueError("KTO target response is detached from source-neutral identity")
        base_gates = base_row.get("objective_gate_states")
        if not isinstance(base_gates, Mapping):
            raise ValueError("KTO target lacks base readiness gate leaves")
        deficits: list[str] = []
        if common.get("coordinates_state") != "PASS":
            deficits.append("COORDINATES_MISSING")
        if common.get("description_state") != "PASS":
            deficits.append("DESCRIPTION_MISSING")
        common_dataset_rights = common.get("dataset_rights")
        image_dataset_rights = image.get("dataset_rights")
        asset_rights = image.get("asset_rights")
        if (
            not isinstance(common_dataset_rights, Mapping)
            or not isinstance(image_dataset_rights, Mapping)
            or not isinstance(asset_rights, Mapping)
        ):
            raise ValueError("KTO response lacks separate rights attestations")
        if common_dataset_rights.get("state") != "PASS":
            deficits.append("DATASET_RIGHTS_BLOCKED")
        direct_media_state = image.get("direct_media_state")
        if direct_media_state == "MISSING":
            deficits.append("SUCCESS_EMPTY_DIRECT_MEDIA")
        elif direct_media_state != "PASS":
            reason = asset_rights.get("reason", "ASSET_RIGHTS_BLOCKED")
            deficits.append(str(reason))
        if image_dataset_rights.get("state") != "PASS":
            deficits.append("DATASET_RIGHTS_BLOCKED")
        if base_row.get("representation_assignment_status") != "PRIMARY":
            deficits.append("REPRESENTATION_ASSIGNMENT_NOT_PRIMARY")
        eligible = not deficits
        target_eligibility[candidate_id] = eligible
        target_replay_rows.append(
            {
                "provider_candidate_id": candidate_id,
                "provider_content_id": candidate_id.removeprefix("candidate:tour-api:"),
                "place_entity_id": base_row["place_entity_id"],
                "name_ko": candidate_names.get(candidate_id, ""),
                "primary_coverage_group": base_row["representation_primary_group"],
                "common_request_identity": operations["detailCommon2"]["request_identity"],
                "image_request_identity": operations["detailImage2"]["request_identity"],
                "common_response_evidence_sha256": common["response_evidence_sha256"],
                "image_response_evidence_sha256": image["response_evidence_sha256"],
                "dataset_rights_attestation_sha256": common_dataset_rights["attestation_sha256"],
                "asset_rights_attestation_sha256": asset_rights["attestation_sha256"],
                "objective_eligible": eligible,
                "named_deficits": deficits,
                "base_operating_info_state": base_gates.get("operating_info"),
                "base_aggregate_row_sha256": base_row["row_sha256"],
            }
        )
    target_replay_rows.sort(key=lambda row: str(row["place_entity_id"]))
    target_replay_sha256 = canonical_sha256(target_replay_rows)

    universe_rows: list[dict[str, Any]] = []
    for base_row in aggregate_rows:
        candidate_id = str(base_row.get("provider_place_candidate_id", ""))
        eligible = target_eligibility.get(
            candidate_id,
            bool(base_row.get("objective_eligible")),
        )
        universe_rows.append(
            {
                "place_entity_id": base_row["place_entity_id"],
                "provider_candidate_id": candidate_id,
                "objective_eligible": eligible,
                "representation_assignment_status": base_row["representation_assignment_status"],
                "representation_primary_group": base_row["representation_primary_group"],
                "base_row_sha256": base_row["row_sha256"],
                "target_replay_sha256": (
                    next(
                        (
                            row["image_response_evidence_sha256"]
                            for row in target_replay_rows
                            if row["provider_candidate_id"] == candidate_id
                        ),
                        None,
                    )
                ),
            }
        )
    universe_rows.sort(key=lambda row: str(row["place_entity_id"]))
    universe_replay_sha256 = canonical_sha256(universe_rows)
    eligible_rows = [
        row
        for row in universe_rows
        if row["objective_eligible"]
        and row["representation_assignment_status"] == "PRIMARY"
        and row["representation_primary_group"] in GROUP_ORDER
    ]
    group_counts: dict[str, int] = {
        group: sum(row["representation_primary_group"] == group for row in eligible_rows)
        for group in GROUP_ORDER
    }
    objective_eligible_count = len(eligible_rows)
    capped_capacity = sum(min(value, 12) for value in group_counts.values())
    representation_feasible = (
        objective_eligible_count >= 36
        and all(value >= 6 for value in group_counts.values())
        and capped_capacity >= 36
    )
    representation_attestation = {
        "policy_version": REPRESENTATION_POLICY_VERSION,
        "group_order": GROUP_ORDER,
        "eligible_pool_sha256": canonical_sha256(eligible_rows),
        "raw_group_counts": group_counts,
        "minimum_per_group": 6,
        "maximum_per_group": 12,
        "required_total": 36,
        "capped_capacity": capped_capacity,
        "feasible": representation_feasible,
        "failure_reason": (None if representation_feasible else "REPRESENTATION_INFEASIBLE"),
    }
    representation_sha256 = canonical_sha256(representation_attestation)
    human_decisions_value = aggregate.get("human_identity_relationship_decisions")
    maximum_human_decisions_value = aggregate.get("maximum_human_decisions")
    if not isinstance(human_decisions_value, int) or not isinstance(
        maximum_human_decisions_value,
        int,
    ):
        raise ValueError("D-03/D-09/D-10 decision accounting is not integral")
    human_decisions = human_decisions_value
    maximum_human_decisions = maximum_human_decisions_value
    decision_accounting = {
        "human_identity_relationship_decisions": human_decisions,
        "maximum_human_decisions": maximum_human_decisions,
        "complete_dispositions_root": aggregate.get("complete_dispositions_root"),
        "entity_policy_report_sha256": aggregate.get("entity_policy_report_sha256"),
        "formal_policy_sha256": aggregate.get("formal_policy_sha256"),
    }
    decision_accounting_sha256 = canonical_sha256(decision_accounting)
    if not 0 <= human_decisions <= maximum_human_decisions <= 6:
        raise ValueError("D-03/D-09/D-10 decision accounting exceeds six")

    attempted_value = aggregate.get("attempted_provider_ids")
    if not isinstance(attempted_value, list):
        raise ValueError("aggregate attempted-provider leaves are missing")
    prior_attempted = [str(value) for value in attempted_value]
    attempted = set(prior_attempted)
    attempted.update(target_requests)
    attempted_provider_count = len(prior_attempted) + len(target_requests)
    attempted_provider_ids_root = canonical_sha256(
        {
            "prior_attempted_provider_ids": sorted(prior_attempted),
            "plan48_target_provider_ids": sorted(target_requests),
        }
    )
    candidate_pool: list[Mapping[str, object]] = []
    for aggregate_row in aggregate_rows:
        candidate_gates = aggregate_row.get("objective_gate_states")
        if (
            aggregate_row.get("provider_place_candidate_id") not in attempted
            and aggregate_row.get("representation_assignment_status") == "PRIMARY"
            and aggregate_row.get("named_deficits")
            == ["DESCRIPTION_MISSING", "DIRECT_MEDIA_MISSING"]
            and isinstance(candidate_gates, Mapping)
            and candidate_gates.get("operating_info") == "PASS"
            and candidate_gates.get("dataset_rights") == "PASS"
        ):
            candidate_pool.append(aggregate_row)
    candidate_pool.sort(
        key=lambda row: (
            -max(
                0,
                6
                - group_counts.get(
                    str(row.get("representation_primary_group")),
                    0,
                ),
            ),
            str(row["place_entity_id"]),
        )
    )
    unresolved_targets = [row for row in target_replay_rows if not row["objective_eligible"]]
    substitute_rows: list[dict[str, Any]] = []
    frontier_rows: list[dict[str, Any]] = []
    for index, target in enumerate(unresolved_targets):
        substitute = candidate_pool[index] if index < len(candidate_pool) else None
        deficits = target["named_deficits"]
        assert isinstance(deficits, list)
        deficit_reason = str(deficits[0])
        if "SUCCESS_EMPTY_DIRECT_MEDIA" in deficits:
            deficit_reason = "SUCCESS_EMPTY_DIRECT_MEDIA"
        elif "NARROWER_TYPE3_ASSET_RESTRICTION" in deficits:
            deficit_reason = "NARROWER_TYPE3_ASSET_RESTRICTION"
        substitute_id: str | None = None
        if substitute is not None:
            substitute_id_value = substitute.get("provider_place_candidate_id")
            if not isinstance(substitute_id_value, str):
                raise ValueError("KTO substitute lacks a provider identity")
            substitute_id = substitute_id_value
            substitute_row = {
                "provider_candidate_id": substitute_id,
                "provider_content_id": substitute_id.removeprefix("candidate:tour-api:"),
                "place_entity_id": substitute["place_entity_id"],
                "name_ko": candidate_names.get(substitute_id, ""),
                "primary_coverage_group": substitute["representation_primary_group"],
                "operations": ["detailCommon2", "detailImage2"],
                "base_aggregate_row_sha256": substitute["row_sha256"],
                "required_next_action": "FRESH_COLLECTION_REQUIRED",
            }
            substitute_rows.append(substitute_row)
        frontier_rows.append(
            {
                **target,
                "deficit_reason": deficit_reason,
                "complete_immutable_kto_evidence_exists": (
                    deficit_reason != "SUCCESS_EMPTY_DIRECT_MEDIA"
                ),
                "human_rights_or_identity_review_needed": False,
                "fresh_collection_required": substitute is not None,
                "substitute_provider_candidate_id": substitute_id,
                "substitute_name_ko": (
                    candidate_names.get(substitute_id, "") if substitute_id is not None else None
                ),
                "substitute_operations": (
                    ["detailCommon2", "detailImage2"] if substitute is not None else []
                ),
                "required_next_action": (
                    "FRESH_COLLECTION_REQUIRED"
                    if substitute is not None
                    else "STOP_EVIDENCE_FRONTIER_EXHAUSTED"
                ),
            }
        )
    substitution_payload: dict[str, Any] = {
        "schema_version": "itda.kto-recovery-substitution-frontier.v1",
        "status": "BLOCKED" if frontier_rows else "SUCCESS",
        "ancestry": ancestry,
        "ancestry_sha256": ancestry_sha256,
        "target_replay_sha256": target_replay_sha256,
        "attempted_provider_ids_root": attempted_provider_ids_root,
        "attempted_provider_count": attempted_provider_count,
        "frontier_rows": frontier_rows,
        "frontier_count": len(frontier_rows),
        "substitute_rows": substitute_rows,
        "substitute_count": len(substitute_rows),
        "capabilities": {
            "authority": False,
            "canonical_membership": False,
            "rights_waiver": False,
            "schema_mutation": False,
            "split_membership": False,
        },
    }
    substitution_root = canonical_sha256(substitution_payload)
    if substitute_rows:
        request_rows = [
            {
                "provider_candidate_id": row["provider_candidate_id"],
                "provider_content_id": row["provider_content_id"],
                "place_entity_id": row["place_entity_id"],
                "operations": row["operations"],
            }
            for row in substitute_rows
        ]
        reentry_disposition: dict[str, Any] = {
            "required": True,
            "reentry_ordinal": 1,
            "request_packet": {
                "substitution_root_sha256": substitution_root,
                "requests": request_rows,
                "request_count": len(request_rows) * 2,
            },
            "reason": "FRESH_KTO_SUBSTITUTE_EVIDENCE_REQUIRED",
        }
    else:
        reentry_disposition = {
            "required": False,
            "reentry_ordinal": 0,
            "request_packet": None,
            "reason": ("EVIDENCE_FRONTIER_EXHAUSTED" if frontier_rows else "ZERO_UNRESOLVED"),
        }
    reentry_payload: dict[str, Any] = {
        "schema_version": "itda.kto-recovery-reentry-disposition.v1",
        "ancestry_sha256": ancestry_sha256,
        "substitution_root_sha256": substitution_root,
        **reentry_disposition,
        "authority_issued": False,
        "nonce_created": False,
        "collection_performed": False,
    }
    reentry_root = canonical_sha256(reentry_payload)
    outcome = "SUCCESS" if not frontier_rows and representation_feasible else "BLOCKED"
    outcome_reason = (
        "ZERO_UNRESOLVED"
        if outcome == "SUCCESS"
        else "EVIDENCE_FRONTIER_EXHAUSTED"
        if not substitute_rows
        else "KTO_SUBSTITUTION_REENTRY_REQUIRED"
    )
    preflight_payload: dict[str, Any] = {
        "schema_version": "itda.kto-recovery-preflight-readiness.v1",
        "status": outcome,
        "outcome_reason": outcome_reason,
        "ancestry": ancestry,
        "ancestry_sha256": ancestry_sha256,
        "target_count": len(target_requests),
        "target_replay_sha256": target_replay_sha256,
        "target_rows": target_replay_rows,
        "unresolved_count": len(unresolved_targets),
        "universe_count": len(universe_rows),
        "universe_replay_sha256": universe_replay_sha256,
        "objective_eligible_count": objective_eligible_count,
        "group_counts": group_counts,
        "representation_quota_attestation": representation_attestation,
        "representation_quota_attestation_sha256": representation_sha256,
        "decision_accounting": decision_accounting,
        "decision_accounting_sha256": decision_accounting_sha256,
        "substitution_root_sha256": substitution_root,
        "reentry_root_sha256": reentry_root,
        "reentry_disposition": reentry_disposition,
        "plan50_reachable": outcome == "SUCCESS",
    }
    preflight_root = canonical_sha256(preflight_payload)
    return KtoRecoveryReadiness(
        target_count=len(target_requests),
        universe_count=len(universe_rows),
        unresolved_count=len(unresolved_targets),
        objective_eligible_count=objective_eligible_count,
        group_counts=group_counts,
        capped_capacity=capped_capacity,
        representation_feasible=representation_feasible,
        human_identity_relationship_decisions=human_decisions,
        maximum_human_decisions=maximum_human_decisions,
        attempted_provider_count=attempted_provider_count,
        frontier_rows=tuple(frontier_rows),
        substitute_rows=tuple(substitute_rows),
        reentry_disposition=reentry_disposition,
        reentry_ordinal=int(reentry_disposition["reentry_ordinal"]),
        target_replay_sha256=target_replay_sha256,
        universe_replay_sha256=universe_replay_sha256,
        decision_accounting_sha256=decision_accounting_sha256,
        representation_quota_attestation_sha256=representation_sha256,
        substitution_root_sha256=substitution_root,
        reentry_root_sha256=reentry_root,
        preflight_root_sha256=preflight_root,
        outcome=outcome,
        outcome_reason=outcome_reason,
        plan50_reachable=outcome == "SUCCESS",
        substitution_payload=substitution_payload,
        reentry_payload=reentry_payload,
        preflight_payload=preflight_payload,
    )


__all__ = [
    "AssignmentStatus",
    "CandidateReadinessRow",
    "CandidateRepresentationAssignment",
    "CatalogReadinessReport",
    "CatalogRoundManifest",
    "ClassificationEvidenceRef",
    "AggregateReadiness",
    "AggregateReadinessRow",
    "GROUP_ORDER",
    "KtoRecoveryReadiness",
    "RemediationFrontierRow",
    "RemediationCandidatePool",
    "RemediationPoolRow",
    "ReadinessParents",
    "RepresentationGroup",
    "RepresentationQuotaAttestation",
    "RepresentationQuotaConfig",
    "RoundManifestFile",
    "RoundOrderEntry",
    "RoundOrderManifest",
    "build_aggregate_readiness",
    "build_remediation_candidate_pool",
    "build_representation_quota_artifacts",
    "build_readiness_report",
    "build_round_order_manifest",
    "evaluate_readiness_candidate",
    "derive_kto_recovery_readiness",
    "rank_remediation_frontier",
]
