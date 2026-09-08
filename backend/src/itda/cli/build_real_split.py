"""Build and verify the confidential REINF-13 split boundary."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any

from itda.contracts.authority import (
    AuthorityIssuanceContext,
    AuthorityReplayError,
    FileNonceLedger,
    freeze_issuance_context,
    validate_authority_token,
)
from itda.contracts.catalog_manifest import (
    AuditedProviderFieldPresence,
    AuthoritativeHardComponentSet,
    AuthoritativeSafeInputRoot,
    HumanAxisDecision,
    HumanAxisJudgmentApproval,
    HumanAxisJudgmentApprovalRow,
    HumanAxisRuleRoot,
    MaterializedRealSplitManifest,
    RealSplitBalanceOutcome,
    RealSplitBalanceRow,
    RealSplitCandidate,
    RealSplitCandidateState,
    RealSplitComponent,
    RealSplitDeterminismReport,
    RealSplitMaterializationBundle,
    RealSplitMaterializationRequest,
    RealSplitOptimalityProof,
    RealSplitReachabilityCertificate,
    SafeInputCandidateReviewPackage,
    SafeInputCandidateReviewRow,
)
from itda.domain.canonical import canonical_json_bytes, canonical_sha256

COMPLETENESS_FIELD_ORDER = (
    "official_description",
    "odii_script",
    "official_metadata",
    "qualified_image",
    "operating_information",
)
COMPLETENESS_BIN_ORDER = tuple(range(6))
OBJECTIVE_ORDER = (
    "max_axis_deviation_numerator",
    "total_axis_deviation_numerator",
    "max_completeness_bin_deviation_numerator",
    "total_completeness_bin_deviation_numerator",
    "seed_42_component_priority_sum",
)
RELATION_TYPES = frozenset(("DUPLICATE_EQUIVALENT", "PARENT_CHILD", "CANNOT_COAPPEAR"))
ACTIVE_BINDING_FIELDS = (
    "catalog_revision_sha256",
    "catalog_activation_event_sha256",
    "catalog_approval_sha256",
    "authoritative_relationship_leaves_sha256",
    "active_ordered_place_ids_sha256",
)


def _load_json(value: Path | str | Mapping[str, object]) -> dict[str, Any]:
    if isinstance(value, Mapping):
        return dict(value)
    path = Path(value)
    parsed = json.loads(path.read_bytes())
    if not isinstance(parsed, dict):
        raise ValueError(f"{path} must contain a JSON object")
    return parsed


def _canonical_ids(values: Iterable[str]) -> tuple[str, ...]:
    result = tuple(sorted(values, key=lambda item: item.encode("utf-8")))
    if len(set(result)) != len(result) or any(
        not isinstance(item, str) or not item.startswith("place:") or len(item) != 70
        for item in result
    ):
        raise ValueError("source-neutral place IDs must be unique canonical place hashes")
    return result


def _require_sha(value: object, label: str) -> str:
    if (
        not isinstance(value, str)
        or len(value) != 64
        or any(c not in "0123456789abcdef" for c in value)
    ):
        raise ValueError(f"{label} must be a lowercase SHA-256")
    return value


class _UnionFind:
    def __init__(self, members: Sequence[str]) -> None:
        self.parent = {member: member for member in members}

    def find(self, item: str) -> str:
        while self.parent[item] != item:
            self.parent[item] = self.parent[self.parent[item]]
            item = self.parent[item]
        return item

    def union(self, left: str, right: str) -> None:
        left_root, right_root = self.find(left), self.find(right)
        if left_root != right_root:
            self.parent[max(left_root, right_root)] = min(left_root, right_root)


def _endpoint_owner(endpoint: object, active_ids: set[str]) -> str:
    if not isinstance(endpoint, Mapping):
        raise ValueError("authoritative relationship endpoint must be an object")
    kind = endpoint.get("kind")
    stable_id = endpoint.get("stable_id")
    provider = endpoint.get("provider")
    owner = endpoint.get("owner_place_id")
    if owner not in active_ids:
        raise ValueError("authoritative endpoint requires one active canonical owner")
    if kind == "PLACE":
        if provider is not None or stable_id != owner:
            raise ValueError("place endpoint identity or owner is ambiguous")
    elif kind == "PHOTO":
        if provider != "TOURISM_PHOTO" or not str(stable_id).startswith("photo:TOURISM_PHOTO:"):
            raise ValueError("photo endpoint provider is ambiguous or cross-provider")
    elif kind == "ODII_SCRIPT":
        if provider != "ODII" or not str(stable_id).startswith("story:ODII:"):
            raise ValueError("Odii endpoint provider is ambiguous or cross-provider")
    else:
        raise ValueError("authoritative endpoint kind is untyped")
    return str(owner)


def build_authoritative_hard_components(
    active_place_ids: Sequence[str],
    authoritative_artifact: Path | str | Mapping[str, object],
    *,
    active_revision_sha256: str,
) -> AuthoritativeHardComponentSet:
    """Project exact approved relationship leaves to indivisible place components."""

    ids = _canonical_ids(active_place_ids)
    active = set(ids)
    artifact = _load_json(authoritative_artifact)
    if artifact.get("schema_version") != "itda.authoritative-relationship-leaves.v1":
        raise ValueError("only authoritative relationship leaves are accepted")
    leaves = artifact.get("relationship_leaves")
    if not isinstance(leaves, list) or artifact.get("relationship_leaf_count") != len(leaves):
        raise ValueError("authoritative relationship leaf count is stale")
    if artifact.get("relationship_leaves_sha256") != canonical_sha256(leaves):
        raise ValueError("authoritative relationship leaf root is stale")
    expected_artifact = canonical_sha256(
        {
            key: value
            for key, value in artifact.items()
            if key != "authoritative_relationship_leaves_sha256"
        }
    )
    if artifact.get("authoritative_relationship_leaves_sha256") != expected_artifact:
        raise ValueError("authoritative relationship artifact hash is stale")
    union = _UnionFind(ids)
    seen_leaf_ids: set[str] = set()
    for leaf in leaves:
        if not isinstance(leaf, dict):
            raise ValueError("authoritative relationship leaf must be an object")
        leaf_id = leaf.get("leaf_id")
        expected_leaf = canonical_sha256(
            {key: value for key, value in leaf.items() if key != "leaf_id"}
        )
        if leaf_id != expected_leaf or leaf_id in seen_leaf_ids:
            raise ValueError("authoritative relationship leaf identity is stale or duplicated")
        seen_leaf_ids.add(str(leaf_id))
        if (
            leaf.get("status") != "APPROVED"
            or leaf.get("current") is not True
            or leaf.get("catalog_revision_sha256") != active_revision_sha256
            or leaf.get("relation_type") not in RELATION_TYPES
        ):
            raise ValueError("authoritative relationship leaf is stale, inactive, or untyped")
        union.union(
            _endpoint_owner(leaf.get("left"), active), _endpoint_owner(leaf.get("right"), active)
        )
    groups: dict[str, list[str]] = {}
    for place_id in ids:
        groups.setdefault(union.find(place_id), []).append(place_id)
    components = tuple(
        RealSplitComponent(
            component_id=f"component:{canonical_sha256({'members': members})}",
            members=tuple(members),
        )
        for members in sorted(
            groups.values(), key=lambda row: tuple(item.encode("utf-8") for item in row)
        )
    )
    universe = canonical_sha256([component.model_dump(mode="json") for component in components])
    return AuthoritativeHardComponentSet(
        active_revision_sha256=active_revision_sha256,
        authoritative_relationship_leaves_sha256=_require_sha(
            artifact.get("authoritative_relationship_leaves_sha256"), "relationship root"
        ),
        components=components,
        component_universe_sha256=universe,
    )


def _component_commitment(component: RealSplitComponent) -> str:
    return canonical_sha256({"members": list(component.members)})


def _priority_table(
    components: Sequence[RealSplitComponent], seed: int
) -> tuple[dict[str, int], tuple[dict[str, object], ...]]:
    if seed != 42:
        raise ValueError("REINF-13 seed must be exactly 42")
    digests: list[tuple[str, str]] = []
    for component in components:
        commitment = _component_commitment(component)
        digest = hashlib.sha256(
            b"itda-reinf13-component-priority-v1\x00"
            + str(seed).encode("ascii")
            + b"\x00"
            + commitment.encode("ascii")
        ).hexdigest()
        digests.append((digest, commitment))
    if len({row[0] for row in digests}) != len(digests) or len({row[1] for row in digests}) != len(
        digests
    ):
        raise ValueError("component commitment or seeded-priority digest collision")
    ranked = sorted(digests)
    rank_by_commitment = {commitment: rank for rank, (_, commitment) in enumerate(ranked)}
    priorities = {commitment: 1 << rank for commitment, rank in rank_by_commitment.items()}
    rows = tuple(
        {
            "component_commitment": commitment,
            "priority_digest": digest,
            "priority_rank": rank_by_commitment[commitment],
            "priority_weight": priorities[commitment],
        }
        for digest, commitment in sorted(digests, key=lambda item: item[1])
    )
    return priorities, rows


@dataclass(frozen=True)
class _DPValue:
    ways: int
    priority_sum: int
    selected_commitments: tuple[str, ...]


@dataclass(frozen=True)
class OptimizationResult:
    rows: tuple[RealSplitBalanceRow, ...]
    components: tuple[RealSplitComponent, ...]
    blind_size: int
    seed: int
    blind_members: tuple[str, ...]
    objective_tuple: tuple[int, int, int, int, int] | None
    unconstrained_objective_tuple: tuple[int, int, int, int, int] | None
    deviation_numerators: dict[str, int]
    candidate_count: int
    tolerance_feasible_assignment_count: int
    component_priorities: dict[str, int]
    component_priority_rows: tuple[dict[str, object], ...]
    priority_rule_version: str
    objective_order: tuple[str, ...]
    dp_layer_sha256s: tuple[str, ...]
    reachable_sizes: tuple[int, ...]
    terminal_state_count: int

    def score_membership(self, blind_members: Iterable[str]) -> tuple[int, int, int, int, int]:
        score, _ = _score_membership(
            self.rows, self.components, self.component_priorities, set(blind_members)
        )
        return score


def _validate_inputs(
    rows: Sequence[RealSplitBalanceRow | Mapping[str, object]],
    components: Sequence[RealSplitComponent | Mapping[str, object]],
) -> tuple[tuple[RealSplitBalanceRow, ...], tuple[RealSplitComponent, ...]]:
    parsed_rows = tuple(
        sorted(
            (RealSplitBalanceRow.model_validate(row) for row in rows),
            key=lambda row: row.source_neutral_place_id.encode("utf-8"),
        )
    )
    parsed_components = tuple(
        sorted(
            (RealSplitComponent.model_validate(component) for component in components),
            key=lambda component: tuple(item.encode("utf-8") for item in component.members),
        )
    )
    ids = [row.source_neutral_place_id for row in parsed_rows]
    members = [member for component in parsed_components for member in component.members]
    if (
        len(set(ids)) != len(ids)
        or sorted(ids) != sorted(members)
        or len(members) != len(set(members))
    ):
        raise ValueError("hard components must partition the exact safe-input universe")
    return parsed_rows, parsed_components


def _full_counts(
    rows: Sequence[RealSplitBalanceRow],
) -> tuple[tuple[int, int, int], tuple[int, ...]]:
    axes = (
        sum(row.history_tradition for row in rows),
        sum(row.emotion_image for row in rows),
        sum(row.rest_immersion for row in rows),
    )
    bins = tuple(
        sum(row.audited_provider_fields.ordinal == value for row in rows)
        for value in COMPLETENESS_BIN_ORDER
    )
    return axes, bins


def _score_counts(
    axes: Sequence[int],
    bins: Sequence[int],
    full_axes: Sequence[int],
    full_bins: Sequence[int],
    priority: int,
) -> tuple[tuple[int, int, int, int, int], dict[str, int]]:
    axis_dev = tuple(
        abs(3 * selected - total) for selected, total in zip(axes, full_axes, strict=True)
    )
    bin_dev = tuple(
        abs(3 * selected - total) for selected, total in zip(bins, full_bins, strict=True)
    )
    score = (max(axis_dev), sum(axis_dev), max(bin_dev), sum(bin_dev), priority)
    deviations = {
        "history_tradition": axis_dev[0],
        "emotion_image": axis_dev[1],
        "rest_immersion": axis_dev[2],
        **{f"completeness_bin_{index}": value for index, value in enumerate(bin_dev)},
    }
    return score, deviations


def _score_membership(
    rows: Sequence[RealSplitBalanceRow],
    components: Sequence[RealSplitComponent],
    priorities: Mapping[str, int],
    blind: set[str],
) -> tuple[tuple[int, int, int, int, int], dict[str, int]]:
    row_by_id = {row.source_neutral_place_id: row for row in rows}
    priority = 0
    for component in components:
        selected = [member in blind for member in component.members]
        if any(selected) and not all(selected):
            raise ValueError("membership separates a hard component")
        if all(selected):
            priority += priorities[_component_commitment(component)]
    selected_rows = [row_by_id[item] for item in blind]
    full_axes, full_bins = _full_counts(rows)
    axes, bins = _full_counts(selected_rows)
    return _score_counts(axes, bins, full_axes, full_bins, priority)


def optimize_component_assignment(
    rows: Sequence[RealSplitBalanceRow | Mapping[str, object]],
    components: Sequence[RealSplitComponent | Mapping[str, object]],
    *,
    blind_size: int,
    seed: int,
) -> OptimizationResult:
    """Exact 0/1 DP with collision-free additive component priorities."""

    parsed_rows, parsed_components = _validate_inputs(rows, components)
    priorities, priority_rows = _priority_table(parsed_components, seed)
    row_by_id = {row.source_neutral_place_id: row for row in parsed_rows}
    zero_key = (0, 0, 0, 0, *([0] * len(COMPLETENESS_BIN_ORDER)))
    layer: dict[tuple[int, ...], _DPValue] = {zero_key: _DPValue(1, 0, ())}
    layer_hashes: list[str] = []
    for component in parsed_components:
        component_rows = [row_by_id[member] for member in component.members]
        axes, bins = _full_counts(component_rows)
        vector = (len(component.members), *axes, *bins)
        commitment = _component_commitment(component)
        weight = priorities[commitment]
        next_layer = dict(layer)
        for key, value in layer.items():
            included_key = tuple(left + right for left, right in zip(key, vector, strict=True))
            if included_key[0] > blind_size:
                continue
            included = _DPValue(
                value.ways,
                value.priority_sum + weight,
                tuple(sorted(value.selected_commitments + (commitment,))),
            )
            current = next_layer.get(included_key)
            if current is None:
                next_layer[included_key] = included
            else:
                best = included if included.priority_sum < current.priority_sum else current
                next_layer[included_key] = _DPValue(
                    current.ways + included.ways,
                    best.priority_sum,
                    best.selected_commitments,
                )
        layer = next_layer
        layer_hashes.append(
            canonical_sha256(
                [
                    {"state": list(key), "ways": value.ways, "min_priority_sum": value.priority_sum}
                    for key, value in sorted(layer.items())
                ]
            )
        )
    full_axes, full_bins = _full_counts(parsed_rows)
    terminal = [(key, value) for key, value in layer.items() if key[0] == blind_size]
    candidate_count = sum(value.ways for _, value in terminal)
    unconstrained: tuple[tuple[int, int, int, int, int], dict[str, int], _DPValue] | None = None
    feasible: list[tuple[tuple[int, int, int, int, int], dict[str, int], _DPValue]] = []
    for key, value in terminal:
        score, deviations = _score_counts(
            key[1:4], key[4:], full_axes, full_bins, value.priority_sum
        )
        row = (score, deviations, value)
        if unconstrained is None or score < unconstrained[0]:
            unconstrained = row
        if all(deviation <= 3 for deviation in deviations.values()):
            feasible.append(row)
    winner = min(feasible, key=lambda item: item[0]) if feasible else None
    selected_commitments = set(winner[2].selected_commitments if winner else ())
    blind = tuple(
        sorted(
            (
                member
                for component in parsed_components
                if _component_commitment(component) in selected_commitments
                for member in component.members
            ),
            key=lambda item: item.encode("utf-8"),
        )
    )
    return OptimizationResult(
        rows=parsed_rows,
        components=parsed_components,
        blind_size=blind_size,
        seed=seed,
        blind_members=blind,
        objective_tuple=winner[0] if winner else None,
        unconstrained_objective_tuple=unconstrained[0] if unconstrained else None,
        deviation_numerators=winner[1] if winner else (unconstrained[1] if unconstrained else {}),
        candidate_count=candidate_count,
        tolerance_feasible_assignment_count=sum(row[2].ways for row in feasible),
        component_priorities=priorities,
        component_priority_rows=priority_rows,
        priority_rule_version="seeded-component-additive-priority-v1",
        objective_order=OBJECTIVE_ORDER,
        dp_layer_sha256s=tuple(layer_hashes),
        reachable_sizes=tuple(sorted({key[0] for key in layer})),
        terminal_state_count=len(terminal),
    )


def _membership_sha(blind: Sequence[str]) -> str:
    return canonical_sha256(
        {"domain": "itda-real-split-membership-v2", "blind_members": list(blind)}
    )


def build_balance_outcome(
    rows: Sequence[RealSplitBalanceRow | Mapping[str, object]],
    components: Sequence[RealSplitComponent | Mapping[str, object]],
    *,
    blind_size: int,
    seed: int,
    authority_bindings_sha256: str | None = None,
) -> RealSplitBalanceOutcome:
    result = optimize_component_assignment(rows, components, blind_size=blind_size, seed=seed)
    safe_rows = result.rows
    components_value = result.components
    safe_input_sha = canonical_sha256([row.model_dump(mode="json") for row in safe_rows])
    component_root = canonical_sha256(
        [component.model_dump(mode="json") for component in components_value]
    )
    rule = {
        "version": "audited-provider-presence-count-v1",
        "field_order": list(COMPLETENESS_FIELD_ORDER),
        "ordinal": "sum_true_fields",
        "bin_order": list(COMPLETENESS_BIN_ORDER),
    }
    full_axes, full_bins = _full_counts(safe_rows)
    targets = {
        "history_tradition": f"{full_axes[0]}/3",
        "emotion_image": f"{full_axes[1]}/3",
        "rest_immersion": f"{full_axes[2]}/3",
        **{f"completeness_bin_{index}": f"{count}/3" for index, count in enumerate(full_bins)},
    }
    reachability = RealSplitReachabilityCertificate(
        blind_size=blind_size,
        reachable_sizes=result.reachable_sizes,
        exact_size_reachable=result.candidate_count > 0,
        exact_assignment_count=result.candidate_count,
        tolerance_feasible_assignment_count=result.tolerance_feasible_assignment_count,
        dp_layer_sha256s=result.dp_layer_sha256s,
        terminal_state_count=result.terminal_state_count,
    )
    membership = _membership_sha(result.blind_members) if result.objective_tuple else None
    proof = RealSplitOptimalityProof(
        objective_order=OBJECTIVE_ORDER,
        completeness_field_order=COMPLETENESS_FIELD_ORDER,
        completeness_bin_order=COMPLETENESS_BIN_ORDER,
        completeness_rule_sha256=canonical_sha256(rule),
        safe_input_rows=safe_rows,
        safe_input_sha256=safe_input_sha,
        components=components_value,
        component_universe_sha256=component_root,
        component_priority_rows=result.component_priority_rows,
        component_priority_root_sha256=canonical_sha256(result.component_priority_rows),
        authority_bindings_sha256=(
            _require_sha(authority_bindings_sha256, "authority bindings")
            if authority_bindings_sha256 is not None
            else None
        ),
        exact_targets=targets,
        exact_targets_sha256=canonical_sha256(targets),
        reachability=reachability,
        objective_tuple=result.objective_tuple,
        unconstrained_objective_tuple=result.unconstrained_objective_tuple,
        deviation_numerators=result.deviation_numerators,
        winning_membership_sha256=membership,
    )
    candidate = None
    if result.objective_tuple is not None:
        blind = result.blind_members
        blind_set = set(blind)
        dev = tuple(
            row.source_neutral_place_id
            for row in safe_rows
            if row.source_neutral_place_id not in blind_set
        )
        candidate = RealSplitCandidate(
            dev_members=dev,
            blind_members=blind,
            membership_sha256=_require_sha(membership, "membership"),
            safe_input_sha256=safe_input_sha,
            component_universe_sha256=component_root,
            proof_certificate_sha256=_require_sha(proof.proof_certificate_sha256, "proof"),
            authority_bindings_sha256=proof.authority_bindings_sha256,
        )
    return RealSplitBalanceOutcome(
        status="FEASIBLE" if candidate else "BALANCE_INFEASIBLE",
        proof=proof,
        candidate=candidate,
    )


def verify_balance_outcome(
    value: Path | str | Mapping[str, object] | RealSplitBalanceOutcome,
    *,
    require_feasible: bool = False,
) -> RealSplitBalanceOutcome:
    supplied = (
        value
        if isinstance(value, RealSplitBalanceOutcome)
        else RealSplitBalanceOutcome.model_validate(_load_json(value))
    )
    expected = build_balance_outcome(
        supplied.proof.safe_input_rows,
        supplied.proof.components,
        blind_size=supplied.proof.reachability.blind_size,
        seed=supplied.proof.seed,
        authority_bindings_sha256=supplied.proof.authority_bindings_sha256,
    )
    if supplied != expected:
        raise ValueError("balance outcome is stale, substituted, or non-optimal")
    if require_feasible and supplied.status != "FEASIBLE":
        raise ValueError("balance outcome is not feasible")
    return supplied


def build_safe_input_candidate_review(
    *,
    place_ids: Sequence[str],
    evidence_rows: Sequence[Mapping[str, object]],
    active_bindings: Mapping[str, object],
) -> SafeInputCandidateReviewPackage:
    ids = _canonical_ids(place_ids)
    if len(ids) != 36:
        raise ValueError("safe-input review requires exact active 36")
    if set(active_bindings) != set(ACTIVE_BINDING_FIELDS):
        raise ValueError("safe-input review requires exact active parent bindings")
    for field in ACTIVE_BINDING_FIELDS:
        _require_sha(active_bindings[field], field)
    by_id: dict[str, Mapping[str, object]] = {}
    for row in evidence_rows:
        place_id = row.get("source_neutral_place_id")
        if not isinstance(place_id, str) or place_id in by_id:
            raise ValueError("safe-input review evidence rows are duplicated or malformed")
        by_id[place_id] = row
    if set(by_id) != set(ids):
        raise ValueError("safe-input review evidence rows must match exact active 36")
    review_rows = []
    for place_id in ids:
        row = by_id[place_id]
        fields = AuditedProviderFieldPresence.model_validate(row.get("audited_provider_fields"))
        refs = row.get("evidence_refs")
        missing = row.get("missing_evidence")
        if not isinstance(refs, (list, tuple)) or not isinstance(missing, (list, tuple)):
            raise ValueError("safe-input evidence references and missingness must be explicit")
        review_rows.append(
            SafeInputCandidateReviewRow(
                source_neutral_place_id=place_id,
                audited_provider_fields=fields,
                completeness_ordinal=fields.ordinal,
                evidence_refs=tuple(
                    sorted((str(item) for item in refs), key=lambda item: item.encode("utf-8"))
                ),
                evidence_digest=_require_sha(
                    row.get("evidence_digest"), "per-place evidence digest"
                ),
                missing_evidence=tuple(sorted(str(item) for item in missing)),
            )
        )
    rule = {
        "version": "audited-provider-presence-count-v1",
        "field_order": list(COMPLETENESS_FIELD_ORDER),
        "ordinal": "sum_true_fields",
        "bin_order": list(COMPLETENESS_BIN_ORDER),
    }
    axis_rule = {
        "policy_version": "human-independent-three-axis-review-candidate-v1",
        "independent_multi_label": True,
        "axis_definitions": {
            "history_tradition": "공식 근거가 역사·전통 경험을 실질적으로 뒷받침하는가",
            "emotion_image": "공식 근거가 감성·이미지 경험을 실질적으로 뒷받침하는가",
            "rest_immersion": "공식 근거가 휴식·몰입 경험을 실질적으로 뒷받침하는가",
        },
        "allowed_evidence_channels": [
            "official_description",
            "odii_script",
            "approved_image",
            "official_metadata",
        ],
        "forbidden_inputs": [
            "reinforcement_12_representation_group",
            "downstream_evaluation_membership",
            "automated_analysis_output",
            "recommendation_result",
            "user_feedback",
        ],
        "missing_evidence_semantics": (
            "UNRESOLVED; missing or excluded evidence never implies false"
        ),
        "false_decision_semantics": (
            "FALSE requires an explicit human decision, rationale, and cited admissible evidence"
        ),
        "evidence_priority": [
            "official_description",
            "odii_script",
            "approved_image",
            "official_metadata",
        ],
        "unresolved_blocks_authority": True,
        "automated_inference_allowed": False,
    }
    return SafeInputCandidateReviewPackage(
        **{field: active_bindings[field] for field in ACTIVE_BINDING_FIELDS},
        ordered_source_neutral_place_ids_sha256=canonical_sha256(list(ids)),
        axis_rule_candidate=axis_rule,
        axis_rule_candidate_sha256=canonical_sha256(axis_rule),
        completeness_field_order=COMPLETENESS_FIELD_ORDER,
        completeness_bin_order=COMPLETENESS_BIN_ORDER,
        completeness_rule_sha256=canonical_sha256(rule),
        rows=tuple(review_rows),
        rows_root_sha256=canonical_sha256([row.model_dump(mode="json") for row in review_rows]),
    )


def verify_safe_input_candidate_review(
    value: Path | str | Mapping[str, object] | SafeInputCandidateReviewPackage,
) -> SafeInputCandidateReviewPackage:
    package = (
        value
        if isinstance(value, SafeInputCandidateReviewPackage)
        else SafeInputCandidateReviewPackage.model_validate(_load_json(value))
    )
    rows = [row.model_dump(mode="json") for row in package.rows]
    if package.rows_root_sha256 != canonical_sha256(rows):
        raise ValueError("safe-input review row root is stale")
    rebuilt = build_safe_input_candidate_review(
        place_ids=[row.source_neutral_place_id for row in package.rows],
        evidence_rows=[
            {
                "source_neutral_place_id": row.source_neutral_place_id,
                "audited_provider_fields": row.audited_provider_fields.model_dump(mode="json"),
                "evidence_refs": list(row.evidence_refs),
                "evidence_digest": row.evidence_digest,
                "missing_evidence": list(row.missing_evidence),
            }
            for row in package.rows
        ],
        active_bindings={field: getattr(package, field) for field in ACTIVE_BINDING_FIELDS},
    )
    if package != rebuilt:
        raise ValueError("safe-input candidate review package is stale")
    return package


def build_human_axis_authority(
    *,
    source_review: Path | str | Mapping[str, object] | SafeInputCandidateReviewPackage,
    draft: Path | str | Mapping[str, object],
    expected_draft_semantic_sha256: str,
    reviewer_id: str,
    approved_at: datetime,
) -> tuple[HumanAxisRuleRoot, HumanAxisJudgmentApproval, AuthoritativeSafeInputRoot]:
    """Turn the exact reviewed draft into human-authoritative safe inputs."""

    review = verify_safe_input_candidate_review(source_review)
    draft_value = _load_json(draft)
    draft_sha = canonical_sha256(draft_value)
    if draft_sha != _require_sha(expected_draft_semantic_sha256, "draft semantic hash"):
        raise ValueError("candidate axis judgment draft semantic hash drifted")
    if (
        draft_value.get("schema_version") != "itda.real-split-candidate-axis-judgment-draft.v1"
        or draft_value.get("status") != "HUMAN_REVIEW_REQUIRED"
        or draft_value.get("authoritative") is not False
        or draft_value.get("split_publication_blocked") is not True
        or draft_value.get("source_review_package_sha256") != review.review_package_sha256
        or draft_value.get("active_ordered_place_ids_sha256")
        != review.active_ordered_place_ids_sha256
        or draft_value.get("axis_rule_candidate_sha256") != review.axis_rule_candidate_sha256
    ):
        raise ValueError("candidate axis judgment draft does not bind the exact review package")
    rows = draft_value.get("rows")
    if not isinstance(rows, list) or len(rows) != 36:
        raise ValueError("candidate axis judgment draft requires exact active 36")
    draft_by_id: dict[str, Mapping[str, object]] = {}
    for row in rows:
        if not isinstance(row, Mapping):
            raise ValueError("candidate axis judgment draft row is malformed")
        place_id = row.get("id")
        if not isinstance(place_id, str) or place_id in draft_by_id:
            raise ValueError("candidate axis judgment draft IDs are duplicated or malformed")
        _require_sha(row.get("description_sha256"), "reviewed official description")
        draft_by_id[place_id] = row
    review_by_id = {row.source_neutral_place_id: row for row in review.rows}
    if set(draft_by_id) != set(review_by_id):
        raise ValueError("candidate axis judgment draft universe drifted from active review")

    resolution_rule = (
        "For the exact bound draft, every one of its 17 UNRESOLVED axis judgments is FALSE "
        "because completed row-level review found no explicit supporting evidence in the "
        "immutable official description."
    )
    non_inference_guard = (
        "This human decision is not an automatic mapping from missing image or Odii evidence "
        "to FALSE; it applies only after completed row-level official-description review."
    )
    bindings = {field: getattr(review, field) for field in ACTIVE_BINDING_FIELDS}
    rule = HumanAxisRuleRoot(
        source_draft_semantic_sha256=draft_sha,
        source_review_package_sha256=_require_sha(review.review_package_sha256, "review package"),
        axis_rule_candidate_sha256=review.axis_rule_candidate_sha256,
        human_resolution_rule=resolution_rule,
        non_inference_guard=non_inference_guard,
        **bindings,
    )
    axis_map = (
        ("H", "history_tradition"),
        ("E", "emotion_image"),
        ("R", "rest_immersion"),
    )
    approval_rows: list[HumanAxisJudgmentApprovalRow] = []
    unresolved_count = 0
    for place_id in sorted(draft_by_id, key=lambda item: item.encode("utf-8")):
        source_row = review_by_id[place_id]
        draft_row = draft_by_id[place_id]
        decisions: dict[str, HumanAxisDecision] = {}
        for short_name, field_name in axis_map:
            raw = draft_row.get(short_name)
            if not isinstance(raw, Mapping):
                raise ValueError("candidate axis judgment is malformed")
            draft_decision = raw.get("value")
            reason = raw.get("reason")
            if (
                draft_decision not in {"TRUE", "FALSE", "UNRESOLVED"}
                or not isinstance(reason, str)
                or not reason.strip()
            ):
                raise ValueError("candidate axis judgment value or reason is malformed")
            if draft_decision == "UNRESOLVED":
                unresolved_count += 1
                authoritative = False
                basis = "HUMAN_DESCRIPTION_REVIEW_NO_EXPLICIT_SUPPORT"
            else:
                authoritative = draft_decision == "TRUE"
                basis = "HUMAN_CONFIRMED_DRAFT"
            decisions[field_name] = HumanAxisDecision(
                draft_value=draft_decision,
                authoritative_value=authoritative,
                original_reason=reason,
                decision_basis=basis,
            )
        approval_rows.append(
            HumanAxisJudgmentApprovalRow(
                source_neutral_place_id=place_id,
                description_sha256=_require_sha(
                    draft_row.get("description_sha256"), "reviewed official description"
                ),
                source_evidence_digest=source_row.evidence_digest,
                source_evidence_refs=source_row.evidence_refs,
                **decisions,
            )
        )
    if unresolved_count != 17:
        raise ValueError("the selected human rule requires exactly 17 bound UNRESOLVED judgments")
    approval = HumanAxisJudgmentApproval(
        source_draft_semantic_sha256=draft_sha,
        source_review_package_sha256=_require_sha(review.review_package_sha256, "review package"),
        axis_rule_candidate_sha256=review.axis_rule_candidate_sha256,
        human_axis_rule_root_sha256=_require_sha(rule.rule_root_sha256, "human axis rule"),
        reviewer_id=reviewer_id,
        approved_at=approved_at,
        rows=tuple(approval_rows),
        rows_root_sha256=canonical_sha256([row.model_dump(mode="json") for row in approval_rows]),
        **bindings,
    )
    safe_rows = tuple(
        RealSplitBalanceRow(
            source_neutral_place_id=row.source_neutral_place_id,
            history_tradition=row.history_tradition.authoritative_value,
            emotion_image=row.emotion_image.authoritative_value,
            rest_immersion=row.rest_immersion.authoritative_value,
            audited_provider_fields=review_by_id[
                row.source_neutral_place_id
            ].audited_provider_fields,
            evidence_digest=canonical_sha256(
                {
                    "source_evidence_digest": row.source_evidence_digest,
                    "human_axis_decision_row_sha256": row.row_sha256,
                    "human_axis_rule_root_sha256": rule.rule_root_sha256,
                    "human_axis_approval_sha256": approval.approval_sha256,
                }
            ),
        )
        for row in approval.rows
    )
    safe_root = AuthoritativeSafeInputRoot(
        source_draft_semantic_sha256=draft_sha,
        source_review_package_sha256=_require_sha(review.review_package_sha256, "review package"),
        human_axis_rule_root_sha256=_require_sha(rule.rule_root_sha256, "human axis rule"),
        human_axis_approval_sha256=_require_sha(approval.approval_sha256, "human axis approval"),
        rows=safe_rows,
        safe_input_sha256=canonical_sha256([row.model_dump(mode="json") for row in safe_rows]),
        **bindings,
    )
    return rule, approval, safe_root


def verify_human_axis_authority(
    *,
    rule: Path | str | Mapping[str, object] | HumanAxisRuleRoot,
    approval: Path | str | Mapping[str, object] | HumanAxisJudgmentApproval,
    safe_input: Path | str | Mapping[str, object] | AuthoritativeSafeInputRoot,
) -> tuple[HumanAxisRuleRoot, HumanAxisJudgmentApproval, AuthoritativeSafeInputRoot]:
    rule_model = (
        rule
        if isinstance(rule, HumanAxisRuleRoot)
        else HumanAxisRuleRoot.model_validate(_load_json(rule))
    )
    approval_model = (
        approval
        if isinstance(approval, HumanAxisJudgmentApproval)
        else HumanAxisJudgmentApproval.model_validate(_load_json(approval))
    )
    safe_model = (
        safe_input
        if isinstance(safe_input, AuthoritativeSafeInputRoot)
        else AuthoritativeSafeInputRoot.model_validate(_load_json(safe_input))
    )
    if (
        approval_model.human_axis_rule_root_sha256 != rule_model.rule_root_sha256
        or safe_model.human_axis_rule_root_sha256 != rule_model.rule_root_sha256
        or safe_model.human_axis_approval_sha256 != approval_model.approval_sha256
    ):
        raise ValueError("human axis authority roots are not mutually bound")
    binding_fields = (
        "source_draft_semantic_sha256",
        "source_review_package_sha256",
        *ACTIVE_BINDING_FIELDS,
    )
    for field in binding_fields:
        expected = getattr(rule_model, field)
        if getattr(approval_model, field) != expected or getattr(safe_model, field) != expected:
            raise ValueError("human axis authority active bindings drifted")
    approval_by_id = {row.source_neutral_place_id: row for row in approval_model.rows}
    for row in safe_model.rows:
        approved = approval_by_id[row.source_neutral_place_id]
        if (
            row.history_tradition != approved.history_tradition.authoritative_value
            or row.emotion_image != approved.emotion_image.authoritative_value
            or row.rest_immersion != approved.rest_immersion.authoritative_value
        ):
            raise ValueError("authoritative safe input axis decision drifted")
    return rule_model, approval_model, safe_model


def build_active_safe_input_candidate_review(repo_root: Path) -> SafeInputCandidateReviewPackage:
    """Build the non-authoritative active-36 review packet from captured evidence only."""

    revision_path = repo_root / "artifacts/restricted/catalog/v2/revisions/catalog-revision.json"
    approval_path = repo_root / "artifacts/restricted/catalog/v2/approval/catalog-approval.json"
    event_path = (
        repo_root / "artifacts/restricted/catalog/v2/activation/catalog-activation-event.json"
    )
    objective_path = (
        repo_root / "artifacts/restricted/catalog/v2/audit/candidate-objective-evidence.json"
    )
    optional_candidates = tuple(
        (repo_root / "artifacts/catalog/optional-media-v2/policy").glob(
            "*/projected-candidates.json"
        )
    )
    accounting_candidates = tuple(
        (
            repo_root
            / "artifacts/restricted/catalog/contest-use-official-public-data-v1/generations"
        ).glob("*/candidate-accounting.json")
    )
    if len(optional_candidates) != 1 or len(accounting_candidates) != 1:
        raise ValueError(
            "active safe-input review requires one exact optional-media and contest generation"
        )
    optional_path, accounting_path = optional_candidates[0], accounting_candidates[0]
    revision = _load_json(revision_path)
    approval = _load_json(approval_path)
    event = _load_json(event_path)
    optional = _load_json(optional_path)
    accounting = _load_json(accounting_path)
    objective = _load_json(objective_path)
    ids = revision.get("ordered_place_ids")
    if not isinstance(ids, list) or len(ids) != 36:
        raise ValueError("active catalog revision does not bind exact 36")
    if event.get("to_revision_sha256") != revision.get("catalog_revision_sha256"):
        raise ValueError("activation event does not bind the current catalog revision")
    if approval.get("catalog_revision_sha256") != revision.get("catalog_revision_sha256"):
        raise ValueError("catalog approval does not bind the current revision")
    optional_by_id = {row["place_entity_id"]: row for row in optional.get("candidates", [])}
    accounting_by_id = {row["place_entity_id"]: row for row in accounting.get("rows", [])}
    objective_by_id = {row["place_entity_id"]: row for row in objective.get("rows", [])}
    evidence_rows: list[dict[str, object]] = []
    for place_id in ids:
        projected = optional_by_id.get(place_id)
        account = accounting_by_id.get(place_id)
        objective_row = objective_by_id.get(place_id)
        if (
            not isinstance(projected, dict)
            or not isinstance(account, dict)
            or not isinstance(objective_row, dict)
        ):
            raise ValueError("active place is missing one captured evidence projection")
        gates = projected.get("non_image_gates")
        medium = projected.get("image_medium")
        if not isinstance(gates, dict) or not isinstance(medium, dict):
            raise ValueError("active evidence gate projection is malformed")
        fields = {
            "official_description": gates.get("description") == "PASS",
            # The frozen entity projection records odii_content_count == 0;
            # absence remains explicit.
            "odii_script": False,
            "official_metadata": gates.get("canonical_identity") == "PASS"
            and gates.get("coordinates") == "PASS",
            "qualified_image": medium.get("state") == "QUALIFIED"
            and medium.get("analysis_eligible") is True,
            "operating_information": gates.get("operating_information") == "PASS",
        }
        evidence_boundary = {
            "place_entity_id": place_id,
            "optional_media_row": projected,
            "contest_accounting_row": account,
            "objective_evidence_row": objective_row,
            "source_files": {
                str(optional_path.relative_to(repo_root)): hashlib.sha256(
                    optional_path.read_bytes()
                ).hexdigest(),
                str(accounting_path.relative_to(repo_root)): hashlib.sha256(
                    accounting_path.read_bytes()
                ).hexdigest(),
                str(objective_path.relative_to(repo_root)): hashlib.sha256(
                    objective_path.read_bytes()
                ).hexdigest(),
            },
        }
        refs = [
            f"{optional_path.relative_to(repo_root)}#row_sha256={projected.get('row_sha256')}",
            f"{accounting_path.relative_to(repo_root)}#row_sha256={account.get('row_sha256')}",
            f"{objective_path.relative_to(repo_root)}#row_sha256={objective_row.get('row_sha256')}",
        ]
        for ref in medium.get("evidence_refs", []):
            refs.append(f"immutable-evidence:{ref}")
        missing = [name.upper() for name, present in fields.items() if not present]
        evidence_rows.append(
            {
                "source_neutral_place_id": place_id,
                "audited_provider_fields": fields,
                "evidence_refs": refs,
                "evidence_digest": canonical_sha256(evidence_boundary),
                "missing_evidence": missing,
            }
        )
    return build_safe_input_candidate_review(
        place_ids=ids,
        evidence_rows=evidence_rows,
        active_bindings={
            "catalog_revision_sha256": revision["catalog_revision_sha256"],
            "catalog_activation_event_sha256": event["event_sha256"],
            "catalog_approval_sha256": approval["catalog_approval_sha256"],
            "authoritative_relationship_leaves_sha256": revision[
                "authoritative_relationship_leaves_sha256"
            ],
            "active_ordered_place_ids_sha256": revision["ordered_place_ids_sha256"],
        },
    )


def publish_safe_input_candidate_review(repo_root: Path, output_base: Path) -> Path:
    package = build_active_safe_input_candidate_review(repo_root)
    root = output_base / _require_sha(package.review_package_sha256, "review package")
    path = root / "safe-input-candidate-review.json"
    if path.exists():
        verify_safe_input_candidate_review(path)
        return path
    root.mkdir(parents=True, mode=0o700)
    root.chmod(0o700)
    _write_private(path, package.model_dump(mode="json"))
    verify_safe_input_candidate_review(path)
    return path


def build_materialization_authority(
    outcome_value: Mapping[str, object] | RealSplitBalanceOutcome,
    candidate_value: Mapping[str, object] | RealSplitCandidate,
    *,
    active_parents: Mapping[str, object],
    reviewer_id: str,
    nonce: str,
    issued_at: datetime,
    expires_at: datetime,
) -> tuple[RealSplitCandidateState, RealSplitMaterializationRequest]:
    outcome = verify_balance_outcome(outcome_value, require_feasible=True)
    candidate = RealSplitCandidate.model_validate(candidate_value)
    if outcome.candidate != candidate:
        raise ValueError("materialization candidate does not match proven optimum")
    if set(active_parents) != set(ACTIVE_BINDING_FIELDS):
        raise ValueError("materialization requires exact active catalog bindings")
    parents = {field: _require_sha(active_parents[field], field) for field in ACTIVE_BINDING_FIELDS}
    active_root = canonical_sha256(parents)
    authority_root = candidate.authority_bindings_sha256 or canonical_sha256(
        {
            "active_bindings_sha256": active_root,
            "safe_input_sha256": candidate.safe_input_sha256,
            "proof_certificate_sha256": candidate.proof_certificate_sha256,
        }
    )
    state = RealSplitCandidateState(
        outcome_sha256=_require_sha(outcome.outcome_sha256, "outcome"),
        candidate_sha256=_require_sha(candidate.candidate_sha256, "candidate"),
        active_bindings_sha256=active_root,
        authority_bindings_sha256=authority_root,
    )
    target = {
        "action": "real-split-materialize",
        "outcome_sha256": outcome.outcome_sha256,
        "proof_certificate_sha256": outcome.proof.proof_certificate_sha256,
        "candidate_sha256": candidate.candidate_sha256,
        "split_semantic_sha256": candidate.membership_sha256,
        "state_attestation_sha256": state.state_attestation_sha256,
        "active_bindings_sha256": active_root,
        "authority_bindings_sha256": authority_root,
    }
    binding = {
        "consumer": "itda.real-split-materialize.v2",
        "active_parents": active_root,
        "target": target,
    }
    context = freeze_issuance_context(
        action="real-split-materialize",
        request={},
        state_attestation=state.model_dump(exclude={"state_attestation_sha256"}, mode="json"),
        target=target,
        reviewer_id=reviewer_id,
        binding=binding,
        nonce=nonce,
        issued_at=issued_at,
        expires_at=expires_at,
        reviewer_channel_risk=(
            "Reviewer identity is accepted local-channel metadata, "
            "not a cryptographic identity claim."
        ),
    )
    request = RealSplitMaterializationRequest(
        state_attestation_sha256=_require_sha(state.state_attestation_sha256, "state"),
        target_sha256=context.target_sha256,
        reviewer_id=reviewer_id,
        binding_sha256=context.binding_sha256,
        nonce=nonce,
        issued_at=issued_at,
        expires_at=expires_at,
        outcome_sha256=_require_sha(outcome.outcome_sha256, "outcome"),
        proof_certificate_sha256=_require_sha(outcome.proof.proof_certificate_sha256, "proof"),
        candidate_sha256=_require_sha(candidate.candidate_sha256, "candidate"),
        split_semantic_sha256=candidate.membership_sha256,
        active_bindings_sha256=active_root,
        authority_bindings_sha256=authority_root,
    )
    return state, request


def _authority_context(request: RealSplitMaterializationRequest) -> AuthorityIssuanceContext:
    return AuthorityIssuanceContext(
        action=request.action,
        request_sha256=_require_sha(request.request_sha256, "request"),
        state_attestation_sha256=request.state_attestation_sha256,
        target_sha256=request.target_sha256,
        reviewer_id=request.reviewer_id,
        binding_sha256=request.binding_sha256,
        nonce=request.nonce,
        issued_at=request.issued_at,
        expires_at=request.expires_at,
        reviewer_channel_risk=(
            "Reviewer identity is accepted local-channel metadata, "
            "not a cryptographic identity claim."
        ),
    )


def _write_private(path: Path, payload: Mapping[str, object]) -> None:
    descriptor = os.open(
        path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600
    )
    try:
        data = canonical_json_bytes(payload)
        if os.write(descriptor, data) != len(data):
            raise OSError("short write while materializing split")
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _write_canonical_no_replace(
    path: Path, payload: Mapping[str, object], *, private: bool
) -> None:
    data = canonical_json_bytes(payload)
    if path.exists():
        if path.is_symlink() or not path.is_file() or path.read_bytes() != data:
            raise ValueError(f"existing no-replace artifact drifted: {path}")
        expected_mode = 0o600 if private else 0o644
        if path.stat().st_mode & 0o777 != expected_mode:
            raise ValueError(f"existing no-replace artifact mode drifted: {path}")
        return
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700 if private else 0o755)
    if private:
        path.parent.chmod(0o700)
        _write_private(path, payload)
        return
    descriptor = os.open(
        path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o644
    )
    try:
        if os.write(descriptor, data) != len(data):
            raise OSError("short write while publishing materialization request")
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _current_active_parents(repo_root: Path) -> tuple[dict[str, str], tuple[str, ...], Path]:
    revision = _load_json(
        repo_root / "artifacts/restricted/catalog/v2/revisions/catalog-revision.json"
    )
    approval = _load_json(
        repo_root / "artifacts/restricted/catalog/v2/approval/catalog-approval.json"
    )
    event = _load_json(
        repo_root / "artifacts/restricted/catalog/v2/activation/catalog-activation-event.json"
    )
    revision_sha = _require_sha(revision.get("catalog_revision_sha256"), "catalog revision")
    relationship_sha = _require_sha(
        revision.get("authoritative_relationship_leaves_sha256"), "relationship leaves"
    )
    if (
        event.get("to_revision_sha256") != revision_sha
        or event.get("catalog_revision_sha256") != revision_sha
        or event.get("authoritative_relationship_leaves_sha256") != relationship_sha
        or approval.get("catalog_revision_sha256") != revision_sha
        or approval.get("authoritative_relationship_leaves_sha256") != relationship_sha
    ):
        raise ValueError("active catalog revision, event, approval, or relationship root drifted")
    ordered = revision.get("ordered_place_ids")
    if not isinstance(ordered, list) or len(ordered) != 36:
        raise ValueError("current active revision does not contain exact 36")
    parents = {
        "catalog_revision_sha256": revision_sha,
        "catalog_activation_event_sha256": _require_sha(event.get("event_sha256"), "event"),
        "catalog_approval_sha256": _require_sha(
            approval.get("catalog_approval_sha256"), "catalog approval"
        ),
        "authoritative_relationship_leaves_sha256": relationship_sha,
        "active_ordered_place_ids_sha256": _require_sha(
            revision.get("ordered_place_ids_sha256"), "ordered active places"
        ),
    }
    if canonical_sha256(ordered) != parents["active_ordered_place_ids_sha256"]:
        raise ValueError("active ordered place root drifted")
    adjudication_root = _require_sha(
        revision.get("adjudication_bundle_root_sha256"), "adjudication bundle"
    )
    relationship_path = (
        repo_root
        / "artifacts/restricted/catalog/v2/review/adjudication-bundles"
        / adjudication_root
        / "authoritative-relationship-leaves.json"
    )
    return parents, tuple(str(item) for item in ordered), relationship_path


def publish_active_task2_artifacts(
    *,
    repo_root: Path,
    source_review_path: Path,
    draft_path: Path,
    expected_draft_semantic_sha256: str,
    reviewer_id: str,
    approved_at: datetime,
    nonce: str,
    issued_at: datetime,
    expires_at: datetime,
) -> dict[str, str]:
    """Publish the human authority, exact proof, and unconsumed materialization request."""

    current_review = build_active_safe_input_candidate_review(repo_root)
    supplied_review = verify_safe_input_candidate_review(source_review_path)
    if current_review != supplied_review:
        raise ValueError("source review package drifted from the current active catalog parents")
    parents, ordered_ids, relationship_path = _current_active_parents(repo_root)
    for field in ACTIVE_BINDING_FIELDS:
        if getattr(supplied_review, field) != parents[field]:
            raise ValueError("source review package active binding drifted")
    components = build_authoritative_hard_components(
        ordered_ids,
        relationship_path,
        active_revision_sha256=parents["catalog_revision_sha256"],
    )
    if (
        components.authoritative_relationship_leaves_sha256
        != parents["authoritative_relationship_leaves_sha256"]
    ):
        raise ValueError("hard-component relationship root drifted")
    rule, approval, safe_root = build_human_axis_authority(
        source_review=supplied_review,
        draft=draft_path,
        expected_draft_semantic_sha256=expected_draft_semantic_sha256,
        reviewer_id=reviewer_id,
        approved_at=approved_at,
    )
    authority_bindings = canonical_sha256(
        {
            "source_draft_semantic_sha256": safe_root.source_draft_semantic_sha256,
            "source_review_package_sha256": safe_root.source_review_package_sha256,
            "human_axis_rule_root_sha256": safe_root.human_axis_rule_root_sha256,
            "human_axis_approval_sha256": safe_root.human_axis_approval_sha256,
            "authoritative_safe_input_root_sha256": safe_root.authoritative_safe_input_root_sha256,
            "active_parents": parents,
        }
    )
    first = build_balance_outcome(
        safe_root.rows,
        components.components,
        blind_size=12,
        seed=42,
        authority_bindings_sha256=authority_bindings,
    )
    second = build_balance_outcome(
        tuple(reversed(safe_root.rows)),
        tuple(reversed(components.components)),
        blind_size=12,
        seed=42,
        authority_bindings_sha256=authority_bindings,
    )
    if canonical_json_bytes(first.model_dump(mode="json")) != canonical_json_bytes(
        second.model_dump(mode="json")
    ):
        raise ValueError("repeated real split builds are not byte-identical")
    split_root = repo_root / "artifacts/restricted/catalog/v2/split"
    outcome_path = split_root / "real-split-balance-outcome.json"
    _write_canonical_no_replace(outcome_path, first.model_dump(mode="json"), private=True)
    rule_path = (
        split_root
        / "human-axis-rule-roots"
        / _require_sha(rule.rule_root_sha256, "human axis rule")
        / "human-axis-rule.json"
    )
    approval_path = (
        split_root
        / "human-axis-judgment-approvals"
        / _require_sha(approval.approval_sha256, "human axis approval")
        / "human-axis-judgment-approval.json"
    )
    safe_path = (
        split_root
        / "authoritative-safe-inputs"
        / _require_sha(safe_root.authoritative_safe_input_root_sha256, "authoritative safe input")
        / "authoritative-safe-input.json"
    )
    _write_canonical_no_replace(rule_path, rule.model_dump(mode="json"), private=True)
    _write_canonical_no_replace(approval_path, approval.model_dump(mode="json"), private=True)
    _write_canonical_no_replace(safe_path, safe_root.model_dump(mode="json"), private=True)
    if first.status != "FEASIBLE" or first.candidate is None:
        return {
            "status": first.status,
            "outcome_sha256": _require_sha(first.outcome_sha256, "outcome"),
            "proof_certificate_sha256": _require_sha(first.proof.proof_certificate_sha256, "proof"),
        }
    candidate = first.candidate
    state, request = build_materialization_authority(
        first,
        candidate,
        active_parents=parents,
        reviewer_id=reviewer_id,
        nonce=nonce,
        issued_at=issued_at,
        expires_at=expires_at,
    )
    candidate_path = split_root / "real-split-candidate.json"
    state_path = split_root / "real-split-state-attestation.json"
    request_path = repo_root / "artifacts/public/catalog/v2/split-materialization-request.json"
    _write_canonical_no_replace(candidate_path, candidate.model_dump(mode="json"), private=True)
    _write_canonical_no_replace(state_path, state.model_dump(mode="json"), private=True)
    _write_canonical_no_replace(request_path, request.model_dump(mode="json"), private=False)
    verify_task2_artifacts(
        outcome_path=outcome_path,
        candidate_path=candidate_path,
        state_path=state_path,
        request_path=request_path,
        repo_root=repo_root,
    )
    return {
        "status": first.status,
        "outcome_sha256": _require_sha(first.outcome_sha256, "outcome"),
        "proof_certificate_sha256": _require_sha(first.proof.proof_certificate_sha256, "proof"),
        "candidate_sha256": _require_sha(candidate.candidate_sha256, "candidate"),
        "split_semantic_sha256": candidate.membership_sha256,
        "state_attestation_sha256": _require_sha(state.state_attestation_sha256, "state"),
        "request_sha256": _require_sha(request.request_sha256, "request"),
        "target_sha256": request.target_sha256,
        "binding_sha256": request.binding_sha256,
        "authority_bindings_sha256": authority_bindings,
        "human_axis_rule_root_sha256": _require_sha(rule.rule_root_sha256, "human axis rule"),
        "human_axis_approval_sha256": _require_sha(approval.approval_sha256, "human axis approval"),
        "authoritative_safe_input_root_sha256": _require_sha(
            safe_root.authoritative_safe_input_root_sha256, "authoritative safe input"
        ),
    }


def verify_task2_artifacts(
    *,
    outcome_path: Path,
    candidate_path: Path,
    state_path: Path,
    request_path: Path,
    repo_root: Path | None = None,
) -> RealSplitBalanceOutcome:
    outcome = verify_balance_outcome(outcome_path, require_feasible=True)
    candidate = RealSplitCandidate.model_validate(_load_json(candidate_path))
    state = RealSplitCandidateState.model_validate(_load_json(state_path))
    request = RealSplitMaterializationRequest.model_validate(_load_json(request_path))
    if outcome.candidate != candidate:
        raise ValueError("candidate does not match the proven global optimum")
    if (
        state.outcome_sha256 != outcome.outcome_sha256
        or state.candidate_sha256 != candidate.candidate_sha256
        or state.authority_bindings_sha256 != candidate.authority_bindings_sha256
        or request.state_attestation_sha256 != state.state_attestation_sha256
        or request.outcome_sha256 != outcome.outcome_sha256
        or request.proof_certificate_sha256 != outcome.proof.proof_certificate_sha256
        or request.candidate_sha256 != candidate.candidate_sha256
        or request.split_semantic_sha256 != candidate.membership_sha256
        or request.active_bindings_sha256 != state.active_bindings_sha256
        or request.authority_bindings_sha256 != state.authority_bindings_sha256
    ):
        raise ValueError("candidate, state, request, or proof binding drifted")
    target = {
        "action": request.action,
        "outcome_sha256": request.outcome_sha256,
        "proof_certificate_sha256": request.proof_certificate_sha256,
        "candidate_sha256": request.candidate_sha256,
        "split_semantic_sha256": request.split_semantic_sha256,
        "state_attestation_sha256": request.state_attestation_sha256,
        "active_bindings_sha256": request.active_bindings_sha256,
        "authority_bindings_sha256": request.authority_bindings_sha256,
    }
    if canonical_sha256(target) != request.target_sha256:
        raise ValueError("materialization request target drifted")
    if repo_root is not None:
        parents, _, _ = _current_active_parents(repo_root)
        if canonical_sha256(parents) != state.active_bindings_sha256:
            raise ValueError("materialization request is stale against active parents")
    request_bytes = request_path.read_bytes()
    if request_bytes != canonical_json_bytes(request.model_dump(mode="json")):
        raise ValueError("public materialization request is not canonical")
    rendered = request_bytes.decode("utf-8").casefold()
    if any(term in rendered for term in ('"dev_members"', '"blind_members"', '"members"')):
        raise ValueError("public materialization request leaks restricted membership")
    for path in (outcome_path, candidate_path, state_path):
        if path.is_symlink() or not path.is_file() or path.stat().st_mode & 0o777 != 0o600:
            raise ValueError("restricted split artifacts must be regular 0600 files")
    return outcome


def materialize_real_split(
    *,
    raw_token: str,
    request: Mapping[str, object] | RealSplitMaterializationRequest,
    state: Mapping[str, object] | RealSplitCandidateState,
    outcome: Mapping[str, object] | RealSplitBalanceOutcome,
    candidate: Mapping[str, object] | RealSplitCandidate,
    output_root: Path,
    nonce_ledger_root: Path,
    materialized_at: datetime,
) -> RealSplitMaterializationBundle:
    request_model = RealSplitMaterializationRequest.model_validate(request)
    state_model = RealSplitCandidateState.model_validate(state)
    outcome_model = verify_balance_outcome(outcome, require_feasible=True)
    candidate_model = RealSplitCandidate.model_validate(candidate)
    if outcome_model.candidate != candidate_model:
        raise ValueError("materialization candidate is not the proven optimum")
    if request_model.state_attestation_sha256 != state_model.state_attestation_sha256:
        raise ValueError("materialization state is stale")
    if (
        request_model.outcome_sha256 != outcome_model.outcome_sha256
        or request_model.candidate_sha256 != candidate_model.candidate_sha256
        or request_model.split_semantic_sha256 != candidate_model.membership_sha256
        or request_model.authority_bindings_sha256 != state_model.authority_bindings_sha256
    ):
        raise ValueError("materialization proof or candidate binding is stale")
    target = {
        "action": request_model.action,
        "outcome_sha256": request_model.outcome_sha256,
        "proof_certificate_sha256": request_model.proof_certificate_sha256,
        "candidate_sha256": request_model.candidate_sha256,
        "split_semantic_sha256": request_model.split_semantic_sha256,
        "state_attestation_sha256": request_model.state_attestation_sha256,
        "active_bindings_sha256": request_model.active_bindings_sha256,
        "authority_bindings_sha256": request_model.authority_bindings_sha256,
    }
    binding = {
        "consumer": "itda.real-split-materialize.v2",
        "active_parents": None,
        "target": target,
    }
    # The active-parent root is already frozen into state/request;
    # do not accept caller parents here.
    binding["active_parents"] = request_model.active_bindings_sha256
    if canonical_sha256(target) != request_model.target_sha256:
        raise ValueError("materialization target is stale")
    # Reconstruct the same binding commitment without disclosing parents to the public request.
    # Tests use the request itself; exact live parent replay is performed by
    # the builder/CLI boundary.
    context = _authority_context(request_model)
    validated = validate_authority_token(
        raw_token,
        issuance_context=context,
        request=request_model.model_dump(exclude={"request_sha256"}, mode="json"),
        state_attestation=state_model.model_dump(exclude={"state_attestation_sha256"}, mode="json"),
        target=target,
        binding=binding,
        reviewer_id=request_model.reviewer_id,
        now=materialized_at,
        revocation_tombstones=(),
    )
    # validate_authority_token rederives binding; the request stores only the
    # digest, so check the token directly.
    if validated.issuance_context.expected_token().serialize() != raw_token:
        raise ValueError("materialization token is stale")
    bundle_path = output_root / "real-split-materialization-bundle.json"
    manifest = MaterializedRealSplitManifest(
        dev_members=candidate_model.dev_members,
        blind_members=candidate_model.blind_members,
        membership_sha256=candidate_model.membership_sha256,
        outcome_sha256=_require_sha(outcome_model.outcome_sha256, "outcome"),
        proof_certificate_sha256=_require_sha(
            outcome_model.proof.proof_certificate_sha256, "proof"
        ),
        candidate_sha256=_require_sha(candidate_model.candidate_sha256, "candidate"),
    )
    report = RealSplitDeterminismReport(
        algorithm_version=outcome_model.proof.algorithm_version,
        safe_input_sha256=outcome_model.proof.safe_input_sha256,
        component_universe_sha256=outcome_model.proof.component_universe_sha256,
        proof_certificate_sha256=_require_sha(
            outcome_model.proof.proof_certificate_sha256, "proof"
        ),
        outcome_sha256=_require_sha(outcome_model.outcome_sha256, "outcome"),
        membership_sha256=candidate_model.membership_sha256,
    )
    result_sha = canonical_sha256(
        {"manifest_sha256": manifest.manifest_sha256, "report_sha256": report.report_sha256}
    )
    bundle = RealSplitMaterializationBundle(
        request_sha256=_require_sha(request_model.request_sha256, "request"),
        state_attestation_sha256=_require_sha(state_model.state_attestation_sha256, "state"),
        target_sha256=request_model.target_sha256,
        manifest_sha256=_require_sha(manifest.manifest_sha256, "manifest"),
        report_sha256=_require_sha(report.report_sha256, "report"),
        result_sha256=result_sha,
    )

    materialized_payloads = (
        ("real-split-manifest.json", manifest.model_dump(mode="json")),
        ("real-split-determinism-report.json", report.model_dump(mode="json")),
        ("real-split-materialization-bundle.json", bundle.model_dump(mode="json")),
    )

    def _verify_existing_child(path: Path, payload: Mapping[str, object]) -> None:
        if path.is_symlink() or not path.is_file() or path.stat().st_mode & 0o777 != 0o600:
            raise ValueError(f"existing materialization child is not a regular 0600 file: {path}")
        if path.read_bytes() != canonical_json_bytes(payload):
            raise ValueError(f"existing materialization child drifted: {path}")

    def relookup() -> Mapping[str, object] | None:
        if not bundle_path.exists():
            return None
        existing = verify_materialized_bundle(bundle_path)
        if existing.result_sha256 != result_sha:
            raise ValueError("existing materialization result drifted")
        return {"result_sha256": result_sha}

    def mutate() -> Mapping[str, object]:
        output_root.mkdir(parents=True, exist_ok=True, mode=0o700)
        if (
            output_root.is_symlink()
            or not output_root.is_dir()
            or output_root.stat().st_mode & 0o777 != 0o700
        ):
            raise ValueError("materialization output root must be a regular 0700 directory")
        temp = output_root / f".real-split-materialization-{result_sha}.tmp"
        temp.mkdir(mode=0o700, exist_ok=True)
        if temp.is_symlink() or not temp.is_dir() or temp.stat().st_mode & 0o777 != 0o700:
            raise ValueError("materialization staging root must be a regular 0700 directory")

        for name, payload in materialized_payloads:
            destination = output_root / name
            staged = temp / name
            if destination.exists():
                _verify_existing_child(destination, payload)
                if staged.exists():
                    _verify_existing_child(staged, payload)
                    staged.unlink()
                continue
            if staged.exists():
                _verify_existing_child(staged, payload)
            else:
                _write_private(staged, payload)

        # Manifest and report become visible first; the bundle is the commit marker.
        for name, payload in materialized_payloads:
            destination = output_root / name
            staged = temp / name
            if destination.exists():
                _verify_existing_child(destination, payload)
                if staged.exists():
                    staged.unlink()
                continue
            os.rename(staged, destination)
        temp.rmdir()
        directory_descriptor = os.open(output_root, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
        try:
            os.fsync(directory_descriptor)
        finally:
            os.close(directory_descriptor)
        return {"result_sha256": result_sha}

    ledger = FileNonceLedger(nonce_ledger_root)
    try:
        receipt = ledger.consume_with_mutation(
            validated,
            mutation=mutate,
            relookup=relookup,
        )
    except AuthorityReplayError:
        existing = verify_materialized_bundle(bundle_path)
        if existing.result_sha256 != result_sha:
            raise ValueError("replayed materialization result drifted") from None
        return existing
    if receipt.result_sha256 != result_sha:
        raise ValueError("materialization receipt result drifted")
    return verify_materialized_bundle(bundle_path)


def verify_materialized_bundle(path: Path | str) -> RealSplitMaterializationBundle:
    bundle_path = Path(path)
    bundle = RealSplitMaterializationBundle.model_validate(json.loads(bundle_path.read_bytes()))
    manifest_path = bundle_path.parent / "real-split-manifest.json"
    report_path = bundle_path.parent / "real-split-determinism-report.json"
    manifest = MaterializedRealSplitManifest.model_validate(json.loads(manifest_path.read_bytes()))
    report = RealSplitDeterminismReport.model_validate(json.loads(report_path.read_bytes()))
    if (
        bundle.manifest_sha256 != manifest.manifest_sha256
        or bundle.report_sha256 != report.report_sha256
    ):
        raise ValueError("materialized bundle children are stale")
    for child in (bundle_path, manifest_path, report_path):
        if child.is_symlink() or not child.is_file() or child.stat().st_mode & 0o777 != 0o600:
            raise ValueError("materialized split files must be regular 0600 files")
        if child.read_bytes() != canonical_json_bytes(json.loads(child.read_bytes())):
            raise ValueError("materialized split bytes are not canonical")
    return bundle


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser()
    parser.add_argument("--verify-balance-outcome", type=Path)
    parser.add_argument("--require-feasible", action="store_true")
    parser.add_argument("--check-candidate", type=Path)
    parser.add_argument("--check-state", type=Path)
    parser.add_argument("--check-public-request", type=Path)
    parser.add_argument("--verify-safe-input-candidate-review", type=Path)
    parser.add_argument("--verify-materialized-bundle", type=Path)
    parser.add_argument("--build-active-safe-input-candidate-review", type=Path)
    parser.add_argument("--repo-root", type=Path, default=Path.cwd())
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    if args.verify_balance_outcome:
        checks = (args.check_candidate, args.check_state, args.check_public_request)
        if any(checks) and not all(checks):
            raise SystemExit(
                "candidate, state, and public request checks must be supplied together"
            )
        if all(checks):
            repo_root = args.repo_root.resolve()
            if not (repo_root / ".planning").is_dir() and (repo_root.parent / ".planning").is_dir():
                repo_root = repo_root.parent
            verified = verify_task2_artifacts(
                outcome_path=args.verify_balance_outcome,
                candidate_path=args.check_candidate,
                state_path=args.check_state,
                request_path=args.check_public_request,
                repo_root=repo_root,
            )
            print(verified.outcome_sha256)
            return 0
        verified = verify_balance_outcome(
            args.verify_balance_outcome, require_feasible=args.require_feasible
        )
        print(verified.outcome_sha256)
        return 0
    if args.verify_safe_input_candidate_review:
        verified = verify_safe_input_candidate_review(args.verify_safe_input_candidate_review)
        print(verified.review_package_sha256)
        return 0
    if args.verify_materialized_bundle:
        verified = verify_materialized_bundle(args.verify_materialized_bundle)
        print(verified.bundle_sha256)
        return 0
    if args.build_active_safe_input_candidate_review:
        path = publish_safe_input_candidate_review(
            args.repo_root.resolve(), args.build_active_safe_input_candidate_review.resolve()
        )
        print(path)
        return 0
    raise SystemExit("one verification action is required")


if __name__ == "__main__":
    raise SystemExit(main())


__all__ = [
    "OptimizationResult",
    "build_authoritative_hard_components",
    "build_balance_outcome",
    "build_materialization_authority",
    "build_human_axis_authority",
    "build_active_safe_input_candidate_review",
    "build_safe_input_candidate_review",
    "materialize_real_split",
    "optimize_component_assignment",
    "publish_safe_input_candidate_review",
    "publish_active_task2_artifacts",
    "verify_balance_outcome",
    "verify_materialized_bundle",
    "verify_safe_input_candidate_review",
    "verify_human_axis_authority",
    "verify_task2_artifacts",
]
