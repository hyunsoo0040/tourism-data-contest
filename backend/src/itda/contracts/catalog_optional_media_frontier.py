"""Complete-universe optional-media eligibility and representation frontier."""

from __future__ import annotations

from collections import Counter
from typing import Annotated, Any, Literal, Self

from pydantic import Field, model_validator

from itda.contracts.base import Sha256, StrictContract
from itda.contracts.catalog_optional_media import (
    NON_IMAGE_GATE_NAMES,
    ImageMediumState,
    OptionalMediaCandidate,
    OptionalMediaPolicyV2,
)
from itda.contracts.catalog_readiness import (
    GROUP_ORDER,
    RepresentationGroup,
    RepresentationQuotaAttestation,
    RepresentationQuotaConfig,
    build_representation_quota_artifacts,
)
from itda.domain.canonical import canonical_json_bytes, canonical_sha256

FRONTIER_SCHEMA_VERSION = "itda.catalog-optional-media-frontier.v2"
ACCOUNTING_SCHEMA_VERSION = "itda.catalog-optional-media-accounting-row.v2"
REPLAY_SCHEMA_VERSION = "itda.catalog-optional-media-frontier-replay.v2"
FrontierStatus = Literal["REPRESENTATION_FEASIBLE", "REPRESENTATION_INFEASIBLE"]
FRONTIER_REPRESENTATION_RULE_SHA256 = canonical_sha256(
    {
        "policy_version": "optional-media-v2-projected-representation-v1",
        "fixed_group_order": GROUP_ORDER,
        "assignment_source": "plan-51-policy-v2-projection",
        "caller_group_override_allowed": False,
    }
)


class OptionalMediaAccountingRow(StrictContract):
    schema_version: Literal["itda.catalog-optional-media-accounting-row.v2"]
    place_entity_id: Annotated[str, Field(strict=True, pattern=r"^place:[0-9a-f]{64}$")]
    candidate_row_sha256: Sha256
    eligible: Annotated[bool, Field(strict=True)]
    representation_primary_group: RepresentationGroup | None
    non_image_deficits: tuple[str, ...]
    image_medium_state: ImageMediumState
    accounting_row_sha256: Sha256

    @model_validator(mode="after")
    def validate_accounting_row(self) -> Self:
        if len(set(self.non_image_deficits)) != len(self.non_image_deficits):
            raise ValueError("optional-media frontier deficits must be unique")
        expected_order = tuple(
            name for name in NON_IMAGE_GATE_NAMES if name in self.non_image_deficits
        )
        if self.non_image_deficits != expected_order:
            raise ValueError("optional-media frontier deficits changed the frozen gate order")
        if self.eligible:
            if self.non_image_deficits:
                raise ValueError("eligible frontier row cannot carry a place deficit")
            if self.representation_primary_group is None:
                raise ValueError("eligible frontier row requires one frozen representation group")
        elif not self.non_image_deficits:
            raise ValueError("ineligible frontier row requires a named non-image deficit")
        expected = canonical_sha256(self.model_dump(exclude={"accounting_row_sha256"}, mode="json"))
        if self.accounting_row_sha256 != expected:
            raise ValueError("optional-media accounting row sha256 drifted")
        return self


class OptionalMediaClosureDeficit(StrictContract):
    place_entity_id: Annotated[str, Field(strict=True, pattern=r"^place:[0-9a-f]{64}$")]
    candidate_row_sha256: Sha256
    non_image_deficits: tuple[str, ...]
    deficit_sha256: Sha256

    @model_validator(mode="after")
    def validate_deficit(self) -> Self:
        expected_order = tuple(
            name for name in NON_IMAGE_GATE_NAMES if name in self.non_image_deficits
        )
        if not self.non_image_deficits or self.non_image_deficits != expected_order:
            raise ValueError("closure deficit must contain frozen non-image gate names")
        expected = canonical_sha256(self.model_dump(exclude={"deficit_sha256"}, mode="json"))
        if self.deficit_sha256 != expected:
            raise ValueError("closure deficit sha256 drifted")
        return self


class OptionalMediaFrontier(StrictContract):
    schema_version: Literal["itda.catalog-optional-media-frontier.v2"]
    policy_version: Literal["optional-media-v2"]
    policy_sha256: Sha256
    universe_root_sha256: Sha256
    universe_candidates_root_sha256: Sha256
    universe_count: Annotated[int, Field(strict=True, ge=1, le=1_000)]
    accounting_rows: Annotated[
        tuple[OptionalMediaAccountingRow, ...],
        Field(min_length=1, max_length=1_000),
    ]
    accounting_rows_root_sha256: Sha256
    eligible_count: Annotated[int, Field(strict=True, ge=0, le=1_000)]
    eligible_pool_sha256: Sha256
    group_counts: dict[RepresentationGroup, Annotated[int, Field(strict=True, ge=0)]]
    group_shortfalls: dict[RepresentationGroup, Annotated[int, Field(strict=True, ge=0)]]
    capped_capacity: Annotated[int, Field(strict=True, ge=0, le=48)]
    closure_frontier: Annotated[
        tuple[OptionalMediaClosureDeficit, ...],
        Field(max_length=1_000),
    ]
    representation_quota_config: RepresentationQuotaConfig
    representation_quota: RepresentationQuotaAttestation
    status: FrontierStatus
    catalog_ready: Literal[False]
    plan20_reachable: Literal[False]
    frontier_sha256: Sha256

    @model_validator(mode="after")
    def validate_frontier(self) -> Self:
        ids = tuple(row.place_entity_id for row in self.accounting_rows)
        if ids != tuple(sorted(ids)) or len(set(ids)) != len(ids):
            raise ValueError("frontier accounting requires unique canonical ID order")
        if self.universe_count != len(self.accounting_rows):
            raise ValueError("frontier universe count is not accounting-derived")
        expected_accounting_root = canonical_sha256(
            [row.model_dump(mode="json") for row in self.accounting_rows]
        )
        if self.accounting_rows_root_sha256 != expected_accounting_root:
            raise ValueError("frontier accounting root drifted")
        eligible = tuple(row for row in self.accounting_rows if row.eligible)
        if self.eligible_count != len(eligible):
            raise ValueError("frontier eligible count is not row-derived")
        expected_eligible_root = canonical_sha256([row.model_dump(mode="json") for row in eligible])
        if self.eligible_pool_sha256 != expected_eligible_root:
            raise ValueError("frontier eligible pool root drifted")
        expected_counts = Counter(row.representation_primary_group for row in eligible)
        counts = {group: expected_counts[group] for group in GROUP_ORDER}
        if self.group_counts != counts:
            raise ValueError("frontier group counts are not eligible-row-derived")
        expected_shortfalls = {group: max(0, 6 - counts[group]) for group in GROUP_ORDER}
        if self.group_shortfalls != expected_shortfalls:
            raise ValueError("frontier group shortfalls drifted")
        expected_capacity = sum(min(12, counts[group]) for group in GROUP_ORDER)
        if self.capped_capacity != expected_capacity:
            raise ValueError("frontier capped capacity drifted")
        expected_closure = tuple(
            _closure_deficit(row) for row in self.accounting_rows if not row.eligible
        )
        if self.closure_frontier != expected_closure:
            raise ValueError("frontier closure inventory is not accounting-derived")
        if self.representation_quota.eligible_pool_sha256 != self.eligible_pool_sha256:
            raise ValueError("frontier quota is bound to a different eligible pool")
        if self.representation_quota.raw_eligible_group_counts != self.group_counts:
            raise ValueError("frontier quota group counts drifted")
        if self.representation_quota.config_sha256 != (
            self.representation_quota_config.config_sha256
        ):
            raise ValueError("frontier quota config binding drifted")
        expected_status = (
            "REPRESENTATION_FEASIBLE"
            if self.representation_quota.feasible
            else "REPRESENTATION_INFEASIBLE"
        )
        if self.status != expected_status:
            raise ValueError("frontier status does not match the quota proof")
        expected = canonical_sha256(self.model_dump(exclude={"frontier_sha256"}, mode="json"))
        if self.frontier_sha256 != expected:
            raise ValueError("optional-media frontier sha256 drifted")
        return self


class FrontierReplayAttestation(StrictContract):
    schema_version: Literal["itda.catalog-optional-media-frontier-replay.v2"]
    universe_root_sha256: Sha256
    policy_sha256: Sha256
    first_frontier_sha256: Sha256
    second_frontier_sha256: Sha256
    byte_identical: Literal[True]
    replay_attestation_sha256: Sha256

    @model_validator(mode="after")
    def validate_replay_attestation(self) -> Self:
        if self.first_frontier_sha256 != self.second_frontier_sha256:
            raise ValueError("frontier replay roots differ")
        expected = canonical_sha256(
            self.model_dump(exclude={"replay_attestation_sha256"}, mode="json")
        )
        if self.replay_attestation_sha256 != expected:
            raise ValueError("frontier replay attestation sha256 drifted")
        return self


def _accounting_row(candidate: OptionalMediaCandidate) -> OptionalMediaAccountingRow:
    fields: dict[str, Any] = {
        "schema_version": ACCOUNTING_SCHEMA_VERSION,
        "place_entity_id": candidate.place_entity_id,
        "candidate_row_sha256": candidate.row_sha256,
        "eligible": candidate.catalog_eligible,
        "representation_primary_group": candidate.representation_primary_group,
        "non_image_deficits": candidate.non_image_failure_reasons,
        "image_medium_state": candidate.image_medium.state,
    }
    return OptionalMediaAccountingRow(
        **fields,
        accounting_row_sha256=canonical_sha256(
            {
                **fields,
                "image_medium_state": candidate.image_medium.state.value,
            }
        ),
    )


def _closure_deficit(row: OptionalMediaAccountingRow) -> OptionalMediaClosureDeficit:
    fields: dict[str, Any] = {
        "place_entity_id": row.place_entity_id,
        "candidate_row_sha256": row.candidate_row_sha256,
        "non_image_deficits": row.non_image_deficits,
    }
    return OptionalMediaClosureDeficit(
        **fields,
        deficit_sha256=canonical_sha256(fields),
    )


def evaluate_optional_media_frontier(
    candidates: tuple[OptionalMediaCandidate, ...],
    policy: OptionalMediaPolicyV2,
    universe_root: Sha256,
) -> OptionalMediaFrontier:
    """Derive exhaustive eligibility and representation facts without authority."""

    policy = OptionalMediaPolicyV2.from_manifest(policy.model_dump(mode="json"))
    if not candidates or len(candidates) > 1_000:
        raise ValueError("optional-media frontier requires 1..1000 candidates")
    canonical_candidates = tuple(
        OptionalMediaCandidate.model_validate(candidate.model_dump(mode="json"))
        for candidate in candidates
    )
    ids = tuple(candidate.place_entity_id for candidate in canonical_candidates)
    if ids != tuple(sorted(ids)) or len(set(ids)) != len(ids):
        raise ValueError("optional-media frontier requires unique canonical candidate order")
    if any(
        candidate.policy_version != policy.policy_version
        or candidate.policy_sha256 != policy.policy_sha256
        for candidate in canonical_candidates
    ):
        raise ValueError("optional-media frontier contains mixed policy rows")
    for candidate in canonical_candidates:
        group = candidate.representation_primary_group
        if group is not None and group not in GROUP_ORDER:
            raise ValueError("optional-media frontier contains an unknown representation group")
        if candidate.catalog_eligible and group is None:
            raise ValueError("eligible candidate lacks one frozen representation group")

    accounting = tuple(_accounting_row(candidate) for candidate in canonical_candidates)
    eligible = tuple(row for row in accounting if row.eligible)
    counts = {
        group: sum(row.representation_primary_group == group for row in eligible)
        for group in GROUP_ORDER
    }
    eligible_pool_sha256 = canonical_sha256([row.model_dump(mode="json") for row in eligible])
    quota_config, quota = build_representation_quota_artifacts(
        eligible_pool_sha256=eligible_pool_sha256,
        representation_rule_sha256=FRONTIER_REPRESENTATION_RULE_SHA256,
        raw_eligible_group_counts=counts,
    )
    status: FrontierStatus = (
        "REPRESENTATION_FEASIBLE" if quota.feasible else "REPRESENTATION_INFEASIBLE"
    )
    fields: dict[str, Any] = {
        "schema_version": FRONTIER_SCHEMA_VERSION,
        "policy_version": policy.policy_version,
        "policy_sha256": policy.policy_sha256,
        "universe_root_sha256": universe_root,
        "universe_candidates_root_sha256": canonical_sha256(
            [candidate.model_dump(mode="json") for candidate in canonical_candidates]
        ),
        "universe_count": len(accounting),
        "accounting_rows": accounting,
        "accounting_rows_root_sha256": canonical_sha256(
            [row.model_dump(mode="json") for row in accounting]
        ),
        "eligible_count": len(eligible),
        "eligible_pool_sha256": eligible_pool_sha256,
        "group_counts": counts,
        "group_shortfalls": {group: max(0, 6 - counts[group]) for group in GROUP_ORDER},
        "capped_capacity": sum(min(12, counts[group]) for group in GROUP_ORDER),
        "closure_frontier": tuple(_closure_deficit(row) for row in accounting if not row.eligible),
        "representation_quota_config": quota_config,
        "representation_quota": quota,
        "status": status,
        "catalog_ready": False,
        "plan20_reachable": False,
    }
    digest_fields = {
        **fields,
        "accounting_rows": [row.model_dump(mode="json") for row in accounting],
        "closure_frontier": [row.model_dump(mode="json") for row in fields["closure_frontier"]],
        "representation_quota_config": quota_config.model_dump(mode="json"),
        "representation_quota": quota.model_dump(mode="json"),
    }
    return OptionalMediaFrontier(
        **fields,
        frontier_sha256=canonical_sha256(digest_fields),
    )


def compare_frontier_replays(
    first: OptionalMediaFrontier,
    second: OptionalMediaFrontier,
) -> FrontierReplayAttestation:
    """Require independently derived frontier bytes to match exactly."""

    first = OptionalMediaFrontier.model_validate(first.model_dump(mode="json"))
    second = OptionalMediaFrontier.model_validate(second.model_dump(mode="json"))
    if canonical_json_bytes(first.model_dump(mode="json")) != canonical_json_bytes(
        second.model_dump(mode="json")
    ):
        raise ValueError("FRONTIER_REPLAY_MISMATCH")
    fields: dict[str, Any] = {
        "schema_version": REPLAY_SCHEMA_VERSION,
        "universe_root_sha256": first.universe_root_sha256,
        "policy_sha256": first.policy_sha256,
        "first_frontier_sha256": first.frontier_sha256,
        "second_frontier_sha256": second.frontier_sha256,
        "byte_identical": True,
    }
    return FrontierReplayAttestation(
        **fields,
        replay_attestation_sha256=canonical_sha256(fields),
    )


__all__ = [
    "ACCOUNTING_SCHEMA_VERSION",
    "FRONTIER_SCHEMA_VERSION",
    "FRONTIER_REPRESENTATION_RULE_SHA256",
    "REPLAY_SCHEMA_VERSION",
    "FrontierReplayAttestation",
    "OptionalMediaAccountingRow",
    "OptionalMediaClosureDeficit",
    "OptionalMediaFrontier",
    "compare_frontier_replays",
    "evaluate_optional_media_frontier",
]
