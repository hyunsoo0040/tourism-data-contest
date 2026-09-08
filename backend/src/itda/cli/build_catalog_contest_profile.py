"""Build and verify the captured, network-denied contest-use catalog profile."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import stat
import sys
import tempfile
from collections import Counter
from collections.abc import Mapping, Sequence
from copy import deepcopy
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Literal, cast

from pydantic import ValidationError

from itda.cli.freeze_preview import (
    PublicationStateUncertainError,
    prepared_directory_snapshot,
    publish_immutable_directory,
)
from itda.contracts.catalog_contest_profile import (
    CONTEST_SCOPE,
    AxisEvidenceBasis,
    ContestCandidateAccounting,
    ContestGenerationChild,
    ContestGenerationManifest,
    ContestPlan54Handoff,
    ContestProfileConfidence,
    ContestProfileTerminal,
    ContestProfileTerminalCode,
    ContestReplayAttestation,
    ContestSelectionFrontier,
    ContestTerminalReason,
    ContestUsePolicy,
    DatasetPermissionDisposition,
    EvidenceAvailability,
)
from itda.contracts.catalog_optional_media_frontier import (
    FRONTIER_REPRESENTATION_RULE_SHA256,
)
from itda.contracts.catalog_readiness import (
    GROUP_ORDER,
    RepresentationGroup,
    build_representation_quota_artifacts,
)
from itda.domain.canonical import canonical_json_bytes, canonical_sha256

NETWORK_DENIAL_POLICY = "(version 1)(allow default)(deny network*)"
NETWORK_DENIAL_POLICY_SHA256 = hashlib.sha256(NETWORK_DENIAL_POLICY.encode()).hexdigest()
OUTPUT_ROOT_REL = Path("artifacts/restricted/catalog/contest-use-official-public-data-v1")
GENERATION_REL_PREFIX = OUTPUT_ROOT_REL / "generations"
SUMMARY_REL = Path(
    ".planning/phases/02-canonical-36-rights-and-evaluation-manifest/02-55-SUMMARY.md"
)
PHASE_REL = Path(".planning/phases/02-canonical-36-rights-and-evaluation-manifest")

PLAN49_HISTORY_SHA256 = "20490fa01d86f3653dc29fe9832fdd1da5e0d47af6861c595b2492b64054a058"
PLAN49_FAILURE_SHA256 = "aa8ee6835bc4fa311186bd7d079b6c31c68fbb8996b6cddaa9db4fa31507020c"
PLAN49_TERMINAL_FILE_SHA256 = "882dfa9bb31e0f3c9eeafbc5cfede28e37659c222e5b531d647cce2307d39cab"
PLAN49_TERMINAL_ROOT = "fab840841288cc0b0e1b31454cf65de5679e5cda0326a57ce42f22d0bdf377ac"
PLAN53_PLAN_SHA256 = "17ed9757ce348b376183c43e53ca9f047892cfce1e56009d407e76e3a91dd060"
PLAN53_SUMMARY_SHA256 = "4a254bb5804465338967976ff47919b7790d08838d4eccfd8f441ae66134498f"
PLAN53_TERMINAL_FILE_SHA256 = "67bfd8507a690af3840d821f2920c521fdccd12fa771277ef74097fda2e827c9"
PLAN53_TERMINAL_ROOT = "03aacc319c8f1c592cabc8794eb973d956232330a5afbf7d2439da592f81944c"
COMPLETE_UNIVERSE_ROOT = "573e21213f7c0d157e33c7a510b9bcdb612dd517dfc70ba506ef7281ca0e9243"

PROJECTED_CANDIDATES_REL = (
    Path("artifacts/catalog/optional-media-v2/policy")
    / COMPLETE_UNIVERSE_ROOT
    / "projected-candidates.json"
)
RIGHTS_PROJECTION_REL = Path("artifacts/restricted/catalog/v2/rights/rights-projection.json")
ENTITY_PROJECTION_REL = Path("artifacts/restricted/catalog/v2/projection/entity-projection.json")
ENTITY_POLICY_REL = Path("artifacts/restricted/catalog/v2/projection/entity-policy-report.json")
PLAN49_TERMINAL_REL = (
    Path("artifacts/restricted/catalog/v2/supplemental/kto-recovery/reentries")
    / PLAN49_TERMINAL_ROOT
    / "reentry-exhausted.json"
)
PLAN53_TERMINAL_REL = Path("artifacts/catalog/optional-media-v2/closure-plan/closure-terminal.json")

SUCCESS_PAYLOAD_NAMES = (
    "candidate-accounting.json",
    "first-replay.json",
    "plan54-handoff.json",
    "policy.json",
    "second-replay.json",
    "selection-frontier.json",
    "source-grants.json",
)
TERMINAL_PAYLOAD_NAMES = ("terminal.json",)

TERMINAL_PREDICATE_ORDER: dict[str, str] = {
    "FORBIDDEN_CAPABILITY_REQUESTED": "forbidden_capability_requested",
    "HISTORICAL_LINEAGE_DRIFT": "historical_lineage_drift",
    "NONCANONICAL_HELD_INPUT": "noncanonical_held_input",
    "INCOMPLETE_UNIVERSE": "incomplete_universe",
    "RIGHTS_OR_SOURCE_AMBIGUITY": "rights_or_source_ambiguity",
    "HUMAN_DECISION_LIMIT_EXCEEDED": "human_decision_limit_exceeded",
    "REPRESENTATION_QUOTA_INFEASIBLE": "representation_quota_infeasible",
    "SELECTABLE_COUNT_SHORTFALL": "selectable_count_shortfall",
}


class ContestProfileError(ValueError):
    """Base fail-closed contest-profile error."""


class ContestProfileCollisionError(ContestProfileError):
    """An immutable generation path exists but differs from the intended bytes."""


class ContestProfileUncertainError(ContestProfileError):
    """Input/publication/verification state cannot be proven exactly."""


@dataclass(frozen=True)
class ContestGenerationResult:
    publication_state: Literal["SUCCESS", "TERMINAL"]
    terminal_code: ContestProfileTerminalCode | None
    exit_code: Literal[0, 27]
    payloads: dict[str, dict[str, Any]]
    manifest: ContestGenerationManifest
    generation_sha256: str
    immutable_parents: tuple[dict[str, Any], ...]
    immutable_parents_root_sha256: str
    plan49_summary_absence_sha256: str
    mode_security_roots: dict[str, str]
    mode_security_roots_sha256: str


@dataclass(frozen=True)
class _Projection:
    policy: ContestUsePolicy
    source_grants: dict[str, Any]
    accounting: dict[str, Any]
    frontier: ContestSelectionFrontier
    lineage: dict[str, dict[str, Any]]
    ordered_parents: tuple[dict[str, Any], ...]
    immutable_parents_root_sha256: str
    plan49_summary_absence_sha256: str
    mode_roots: dict[str, str]
    mode_roots_sha256: str
    replay_content: dict[str, Any]


_PUBLISHED_LOCATIONS: dict[str, Path] = {}


def _sha256_bytes(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def _canonical_line_sha256(payload: object) -> str:
    return _sha256_bytes(canonical_json_bytes(payload) + b"\n")


def _mode(metadata: os.stat_result) -> str:
    return f"{stat.S_IMODE(metadata.st_mode):04o}"


def _identity(metadata: os.stat_result) -> tuple[int, int, int, int, int, int]:
    return (
        metadata.st_dev,
        metadata.st_ino,
        metadata.st_mode,
        metadata.st_nlink,
        metadata.st_size,
        metadata.st_mtime_ns,
    )


def _assert_inside_repo(path: Path, repository_root: Path) -> None:
    try:
        path.resolve(strict=False).relative_to(repository_root.resolve(strict=True))
    except ValueError as exc:
        raise ContestProfileUncertainError("held input escapes the repository root") from exc


def _assert_nofollow_ancestors(path: Path, stop: Path) -> None:
    stop = stop.resolve(strict=True)
    current = path
    while current != stop:
        if current.exists() and current.is_symlink():
            raise ContestProfileUncertainError("held path has a symlink ancestor")
        parent = current.parent
        if parent == current:
            raise ContestProfileUncertainError("held path is outside the pinned root")
        current = parent


def _read_regular_bytes_nofollow(
    path: Path,
    *,
    repository_root: Path,
    max_bytes: int = 100_000_000,
    require_single_link: bool = True,
) -> bytes:
    _assert_inside_repo(path, repository_root)
    _assert_nofollow_ancestors(path.parent, repository_root)
    try:
        visible_before = path.lstat()
        if not stat.S_ISREG(visible_before.st_mode):
            raise ContestProfileUncertainError("held input must be a regular no-follow file")
        descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    except OSError as exc:
        raise ContestProfileUncertainError("held input could not be opened no-follow") from exc
    try:
        opened_before = os.fstat(descriptor)
        if _identity(visible_before) != _identity(opened_before):
            raise ContestProfileUncertainError("held input identity changed before read")
        if require_single_link and opened_before.st_nlink != 1:
            raise ContestProfileUncertainError("held input link count must be one")
        if opened_before.st_size > max_bytes:
            raise ContestProfileUncertainError("held input size exceeds its fixed bound")
        chunks: list[bytes] = []
        remaining = opened_before.st_size
        while remaining:
            chunk = os.read(descriptor, min(1_048_576, remaining))
            if not chunk:
                raise ContestProfileUncertainError("held input ended before its stated size")
            chunks.append(chunk)
            remaining -= len(chunk)
        if os.read(descriptor, 1):
            raise ContestProfileUncertainError("held input grew while it was read")
        opened_after = os.fstat(descriptor)
        visible_after = path.lstat()
        if not (_identity(opened_before) == _identity(opened_after) == _identity(visible_after)):
            raise ContestProfileUncertainError("held input changed during stable read")
        return b"".join(chunks)
    finally:
        os.close(descriptor)


def load_canonical_json_nofollow(
    path: Path,
    *,
    max_bytes: int,
    repository_root: Path | None = None,
) -> dict[str, Any]:
    root = repository_root or path.parent.resolve(strict=True)
    payload = _read_regular_bytes_nofollow(
        path,
        repository_root=root,
        max_bytes=max_bytes,
    )
    try:
        value = json.loads(payload)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ContestProfileUncertainError("held input is not canonical JSON") from exc
    if not isinstance(value, dict) or canonical_json_bytes(value) != payload:
        raise ContestProfileUncertainError("held input is not a canonical JSON object")
    return cast(dict[str, Any], value)


def _file_leaf(
    repository_root: Path,
    relative: Path,
    *,
    expected_sha256: str,
    inner_key: str | None = None,
    expected_inner: str | None = None,
) -> dict[str, Any]:
    payload = _read_regular_bytes_nofollow(
        repository_root / relative,
        repository_root=repository_root,
    )
    digest = _sha256_bytes(payload)
    if digest != expected_sha256:
        raise ContestProfileUncertainError(f"historical lineage drift: {relative}")
    leaf: dict[str, Any] = {
        "path": relative.as_posix(),
        "entry_type": "regular_file",
        "file_sha256": digest,
    }
    if inner_key is not None:
        try:
            parsed = json.loads(payload)
        except json.JSONDecodeError as exc:
            raise ContestProfileUncertainError("historical terminal is malformed") from exc
        inner = parsed.get(inner_key) if isinstance(parsed, dict) else None
        if inner != expected_inner:
            raise ContestProfileUncertainError("historical terminal inner root drifted")
        leaf[inner_key] = inner
    return leaf


def verify_historical_lineage(repository_root: Path | str) -> dict[str, dict[str, Any]]:
    root = Path(repository_root).resolve(strict=True)
    phase = PHASE_REL
    leaves = {
        "02-49-TERMINAL-HISTORY.md": _file_leaf(
            root,
            phase / "02-49-TERMINAL-HISTORY.md",
            expected_sha256=PLAN49_HISTORY_SHA256,
        ),
        "02-49-FAILURE-RECORD.md": _file_leaf(
            root,
            phase / "02-49-FAILURE-RECORD.md",
            expected_sha256=PLAN49_FAILURE_SHA256,
        ),
        "reentry-exhausted.json": _file_leaf(
            root,
            PLAN49_TERMINAL_REL,
            expected_sha256=PLAN49_TERMINAL_FILE_SHA256,
            inner_key="terminal_root_sha256",
            expected_inner=PLAN49_TERMINAL_ROOT,
        ),
        "02-53-PLAN.md": _file_leaf(
            root,
            phase / "02-53-PLAN.md",
            expected_sha256=PLAN53_PLAN_SHA256,
        ),
        "02-53-SUMMARY.md": _file_leaf(
            root,
            phase / "02-53-SUMMARY.md",
            expected_sha256=PLAN53_SUMMARY_SHA256,
        ),
        "closure-terminal.json": _file_leaf(
            root,
            PLAN53_TERMINAL_REL,
            expected_sha256=PLAN53_TERMINAL_FILE_SHA256,
            inner_key="terminal_sha256",
            expected_inner=PLAN53_TERMINAL_ROOT,
        ),
    }
    absent = phase / "02-49-SUMMARY.md"
    if os.path.lexists(root / absent):
        raise ContestProfileUncertainError("historical lineage drift: forbidden Plan 49 Summary")
    leaves["02-49-SUMMARY.md"] = {
        "path": absent.as_posix(),
        "disposition": "ABSENT_REQUIRED",
        "absence_sha256": canonical_sha256(
            {"path": absent.as_posix(), "disposition": "ABSENT_REQUIRED"}
        ),
    }
    return leaves


def _ordered_lineage(lineage: Mapping[str, dict[str, Any]]) -> tuple[dict[str, Any], ...]:
    order = (
        "02-49-TERMINAL-HISTORY.md",
        "02-49-FAILURE-RECORD.md",
        "reentry-exhausted.json",
        "02-49-SUMMARY.md",
        "02-53-PLAN.md",
        "02-53-SUMMARY.md",
        "closure-terminal.json",
    )
    return tuple({"leaf_id": name, **lineage[name]} for name in order)


def mode_security_roots(network_denial_policy_sha256: str) -> dict[str, str]:
    if network_denial_policy_sha256 != NETWORK_DENIAL_POLICY_SHA256:
        raise ContestProfileUncertainError("external network-denial policy hash drifted")
    return {
        "execution_mode": "captured_replay",
        "network_denial_policy_sha256": network_denial_policy_sha256,
        "null_authority_state_sha256": canonical_sha256(
            {"authority": None, "nonce": None, "token": None}
        ),
        "null_credential_state_sha256": canonical_sha256(
            {"credential": None, "credential_file_opened": False}
        ),
        "provider_attempt_inventory_sha256": canonical_sha256([]),
    }


def require_external_network_denial(value: str | None) -> str:
    if value != NETWORK_DENIAL_POLICY_SHA256:
        raise ContestProfileUncertainError("exact external network-denial harness is required")
    if not Path("/usr/bin/sandbox-exec").is_file() or not os.access(
        "/usr/bin/sandbox-exec", os.X_OK
    ):
        raise ContestProfileUncertainError("external network-denial executable is unavailable")
    return value


def derive_dataset_permission(
    *,
    dataset_bound: bool,
    portal_terms: str,
    explicit_restriction: str | None,
    third_party_identified: bool,
) -> DatasetPermissionDisposition:
    if explicit_restriction:
        return DatasetPermissionDisposition.EXPLICIT_NARROWER_EXCLUDED
    if not third_party_identified:
        return DatasetPermissionDisposition.UNIDENTIFIED_THIRD_PARTY_EXCLUDED
    if dataset_bound and (
        "이용허락범위 제한 없음" in portal_terms or "unrestricted use" in portal_terms.casefold()
    ):
        return DatasetPermissionDisposition.DATASET_UNRESTRICTED_QUALIFIED
    return DatasetPermissionDisposition.DATASET_GRANT_UNRESOLVED


def derive_axis_evidence_basis(
    *,
    image_availability: EvidenceAvailability | str,
    operating_information_availability: EvidenceAvailability | str,
    known_operating_facts: Mapping[str, str],
) -> tuple[AxisEvidenceBasis, ContestProfileConfidence]:
    image = EvidenceAvailability(image_availability)
    operating = EvidenceAvailability(operating_information_availability)
    warnings = tuple(
        warning
        for warning, active in (
            ("IMAGE_EVIDENCE_UNAVAILABLE", image is not EvidenceAvailability.QUALIFIED),
            ("OPERATING_INFORMATION_UNAVAILABLE", operating is not EvidenceAvailability.QUALIFIED),
        )
        if active
    )
    basis = AxisEvidenceBasis(
        image_availability=image,
        operating_information_availability=operating,
        qualified_channels=("official_description", "odii", "metadata")
        + (("image",) if image is EvidenceAvailability.QUALIFIED else ()),
        availability_warnings=warnings,
        known_operating_facts=dict(sorted(known_operating_facts.items())),
    )
    confidence = ContestProfileConfidence(
        band="QUALIFIED" if not warnings else "REDUCED",
        qualification_eligible=True,
        warning_codes=warnings,
    )
    return basis, confidence


def evaluate_terminal_code(
    predicates: Mapping[str, bool],
) -> ContestProfileTerminalCode | None:
    unknown = set(predicates) - set(TERMINAL_PREDICATE_ORDER)
    if unknown:
        raise ContestProfileUncertainError("terminal predicate map contains an unknown code")
    for code in TERMINAL_PREDICATE_ORDER:
        if predicates.get(code, False):
            return ContestProfileTerminalCode(code)
    return None


def resolve_replay_terminal(
    first: Mapping[str, Any],
    second: Mapping[str, Any],
) -> ContestProfileTerminalCode:
    if canonical_json_bytes(first) != canonical_json_bytes(second):
        return ContestProfileTerminalCode.REPLAY_MISMATCH
    code = first.get("terminal_code")
    if not isinstance(code, str):
        raise ContestProfileUncertainError("equal replay failures lack a closed terminal code")
    return ContestProfileTerminalCode(code)


def _load_projection_inputs(root: Path) -> tuple[dict[str, Any], ...]:
    return (
        load_canonical_json_nofollow(
            root / PROJECTED_CANDIDATES_REL,
            max_bytes=20_000_000,
            repository_root=root,
        ),
        load_canonical_json_nofollow(
            root / RIGHTS_PROJECTION_REL,
            max_bytes=50_000_000,
            repository_root=root,
        ),
        load_canonical_json_nofollow(
            root / ENTITY_PROJECTION_REL,
            max_bytes=50_000_000,
            repository_root=root,
        ),
        load_canonical_json_nofollow(
            root / ENTITY_POLICY_REL,
            max_bytes=50_000_000,
            repository_root=root,
        ),
    )


def _image_availability(value: object) -> EvidenceAvailability:
    if value == "QUALIFIED":
        return EvidenceAvailability.QUALIFIED
    if value in {"MISSING", "EMPTY", "PROVENANCE_INCOMPLETE"}:
        return EvidenceAvailability.MISSING
    return EvidenceAvailability.EXCLUDED


def _candidate_source_grant(
    rights: Mapping[str, Any],
) -> tuple[dict[str, Any], str]:
    grants = rights.get("dataset_grants")
    if not isinstance(grants, list) or len(grants) != 3:
        raise ContestProfileUncertainError("official dataset grant inventory is incomplete")
    ordered = sorted(grants, key=lambda item: str(item.get("official_dataset_id")))
    for raw in ordered:
        if not isinstance(raw, dict):
            raise ContestProfileUncertainError("official dataset grant row is malformed")
        restriction_text = " ".join(str(item) for item in raw.get("explicit_restrictions", []))
        if (
            "이용허락범위 제한 없음" not in restriction_text
            and raw.get("official_dataset_id") != "15101914"
        ):
            raise ContestProfileUncertainError("official dataset unrestricted terms are absent")
    root = canonical_sha256(ordered)
    projected = {
        "schema_version": "itda.catalog-contest-use-source-grants.v1",
        "scope": CONTEST_SCOPE,
        "commercial_production_rights_review_required": True,
        "dataset_grants": ordered,
        "official_dataset_grants_root_sha256": root,
        "dataset_permission_rule": (
            "dataset-unrestricted-unless-explicit-narrower-or-third-party-v1"
        ),
    }
    projected["source_grants_sha256"] = canonical_sha256(projected)
    tour_grant = next(item for item in ordered if item.get("official_dataset_id") == "15101578")
    return projected, str(tour_grant["dataset_grant_sha256"])


def _asset_exclusion_root(rights: Mapping[str, Any]) -> str:
    raw_assets = rights.get("asset_rights")
    if not isinstance(raw_assets, list):
        raise ContestProfileUncertainError("asset rights inventory is malformed")
    leaves = sorted(
        str(item["leaf_sha256"])
        for item in raw_assets
        if isinstance(item, dict)
        and (
            item.get("explicit_asset_restriction") is not None
            or str(item.get("rights_state", "")).startswith("BLOCKED")
        )
    )
    if not leaves:
        raise ContestProfileUncertainError("asset exclusion inventory is empty")
    return canonical_sha256(leaves)


def _relationship_root(entity: Mapping[str, Any], policy: Mapping[str, Any]) -> str:
    payload = {
        "entity_relationships": entity.get("roots", {}).get("relationships"),
        "policy_relationships": policy.get("roots", {}).get("relationship_dispositions"),
        "typed_relationships": entity.get("relationships", []),
    }
    return canonical_sha256(payload)


def select_noncanonical_preview(
    rows: Sequence[Mapping[str, Any]],
    quotas: Mapping[RepresentationGroup, int],
) -> tuple[str, ...]:
    selected: list[str] = []
    for group in GROUP_ORDER:
        candidates = sorted(
            (
                str(row["place_entity_id"])
                for row in rows
                if row.get("representation_primary_group") == group
            ),
            key=lambda value: value.encode("utf-8"),
        )
        selected.extend(candidates[: quotas[group]])
    return tuple(selected)


def _build_accounting(
    candidates: Sequence[Mapping[str, Any]],
    *,
    dataset_grant_sha256: str,
    asset_exclusion_root_sha256: str,
) -> tuple[tuple[ContestCandidateAccounting, ...], dict[str, int]]:
    rows: list[ContestCandidateAccounting] = []
    for candidate in candidates:
        gates = candidate.get("non_image_gates")
        medium = candidate.get("image_medium")
        if not isinstance(gates, dict) or not isinstance(medium, dict):
            raise ContestProfileUncertainError("candidate gate or image evidence is malformed")
        blocking = tuple(
            sorted(
                name
                for name in (
                    "canonical_identity",
                    "coordinates",
                    "description",
                    "representation_assignment",
                )
                if gates.get(name) != "PASS"
            )
        )
        group = candidate.get("representation_primary_group")
        if group not in GROUP_ORDER:
            group = None
        eligible = not blocking and group is not None
        image = _image_availability(medium.get("state"))
        operating = (
            EvidenceAvailability.QUALIFIED
            if gates.get("operating_information") == "PASS"
            else EvidenceAvailability.MISSING
        )
        basis, confidence = derive_axis_evidence_basis(
            image_availability=image,
            operating_information_availability=operating,
            known_operating_facts={},
        )
        permission = derive_dataset_permission(
            dataset_bound=True,
            portal_terms="이용허락범위 제한 없음",
            explicit_restriction=None,
            third_party_identified=True,
        )
        fields: dict[str, Any] = {
            "place_entity_id": candidate.get("place_entity_id"),
            "source_candidate_id": candidate.get("provider_place_candidate_id"),
            "source_row_sha256": candidate.get("row_sha256"),
            "representation_primary_group": group,
            "objective_eligible": eligible,
            "blocking_deficits": blocking,
            "image_availability": image,
            "operating_information_availability": operating,
            "axis_evidence_basis": basis,
            "confidence": confidence,
            "dataset_permission": permission,
            "dataset_grant_sha256": dataset_grant_sha256,
            "asset_exclusion_root_sha256": canonical_sha256(
                {
                    "global_asset_exclusions_root_sha256": asset_exclusion_root_sha256,
                    "place_entity_id": candidate.get("place_entity_id"),
                    "image_state": medium.get("state"),
                    "image_evidence_refs": medium.get("evidence_refs", []),
                }
            ),
        }
        digest_fields = {
            "schema_version": "itda.catalog-contest-use-candidate-accounting.v1",
            **fields,
            "image_availability": image.value,
            "operating_information_availability": operating.value,
            "axis_evidence_basis": basis.model_dump(mode="json"),
            "confidence": confidence.model_dump(mode="json"),
            "dataset_permission": permission.value,
        }
        rows.append(
            ContestCandidateAccounting(
                **fields,
                row_sha256=canonical_sha256(digest_fields),
            )
        )
    ordered = tuple(sorted(rows, key=lambda row: row.place_entity_id.encode("utf-8")))
    if len(ordered) != 718 or len({row.place_entity_id for row in ordered}) != 718:
        raise ContestProfileError("complete contest universe must contain 718 unique places")
    counts = Counter(row.representation_primary_group for row in ordered if row.objective_eligible)
    return ordered, {group: counts[group] for group in GROUP_ORDER}


def _derive_projection(root: Path, network_hash: str) -> _Projection:
    before_a = verify_historical_lineage(root)
    projected, rights, entity, entity_policy = _load_projection_inputs(root)
    after_a = verify_historical_lineage(root)
    before_b = verify_historical_lineage(root)
    if not (before_a == after_a == before_b):
        raise ContestProfileUncertainError("historical lineage drifted at a replay boundary")
    candidates = projected.get("candidates")
    if projected.get("universe_count") != 718 or not isinstance(candidates, list):
        raise ContestProfileError("complete contest universe is not exactly 718 rows")
    source_grants, tour_grant_sha256 = _candidate_source_grant(rights)
    asset_exclusions_root = _asset_exclusion_root(rights)
    rows, group_counts = _build_accounting(
        candidates,
        dataset_grant_sha256=tour_grant_sha256,
        asset_exclusion_root_sha256=asset_exclusions_root,
    )
    after_b = verify_historical_lineage(root)
    if before_b != after_b:
        raise ContestProfileUncertainError("historical lineage drifted after replay")
    lineage = after_b
    ordered_parents = _ordered_lineage(lineage)
    immutable_root = canonical_sha256(list(ordered_parents))
    absence_root = str(lineage["02-49-SUMMARY.md"]["absence_sha256"])
    accounting_rows = [row.model_dump(mode="json") for row in rows]
    accounting_root = canonical_sha256(accounting_rows)
    eligible = tuple(row for row in rows if row.objective_eligible)
    eligible_rows = [
        {
            "place_entity_id": row.place_entity_id,
            "representation_primary_group": row.representation_primary_group,
            "candidate_row_sha256": row.row_sha256,
            "image_availability": row.image_availability.value,
            "operating_information_availability": row.operating_information_availability.value,
            "confidence_band": row.confidence.band,
            "availability_warnings": list(row.axis_evidence_basis.availability_warnings),
        }
        for row in sorted(
            eligible,
            key=lambda row: (
                GROUP_ORDER.index(cast(RepresentationGroup, row.representation_primary_group)),
                row.place_entity_id.encode("utf-8"),
            ),
        )
    ]
    eligible_root = canonical_sha256(eligible_rows)
    quota_config, quota = build_representation_quota_artifacts(
        eligible_pool_sha256=eligible_root,
        representation_rule_sha256=FRONTIER_REPRESENTATION_RULE_SHA256,
        raw_eligible_group_counts=cast(dict[RepresentationGroup, int], group_counts),
    )
    if not quota.feasible:
        raise ContestProfileError("contest representation quota is infeasible")
    preview = select_noncanonical_preview(eligible_rows, quota.final_quotas)
    warning_root = canonical_sha256(
        [
            {"place_entity_id": row.place_entity_id, "warnings": row.confidence.warning_codes}
            for row in rows
        ]
    )
    missingness_root = canonical_sha256(
        [
            {
                "place_entity_id": row.place_entity_id,
                "image": row.image_availability.value,
                "operating_information": row.operating_information_availability.value,
            }
            for row in rows
        ]
    )
    confidence_root = canonical_sha256(
        [
            {"place_entity_id": row.place_entity_id, **row.confidence.model_dump(mode="json")}
            for row in rows
        ]
    )
    commercial_root = canonical_sha256(
        {
            "scope": CONTEST_SCOPE,
            "commercial_production_rights_review_required": True,
            "production_clearance": False,
        }
    )
    source_entities_root = canonical_sha256([row.place_entity_id for row in rows])
    relationships_root = _relationship_root(entity, entity_policy)
    contest_rights_root = canonical_sha256(
        {
            "scope": CONTEST_SCOPE,
            "official_dataset_grants_root_sha256": source_grants[
                "official_dataset_grants_root_sha256"
            ],
            "asset_exclusions_root_sha256": asset_exclusions_root,
            "commercial_review_requirement_sha256": commercial_root,
        }
    )
    policy_fields: dict[str, Any] = {
        "official_dataset_grants_root_sha256": source_grants["official_dataset_grants_root_sha256"],
        "asset_exclusions_root_sha256": asset_exclusions_root,
        "contest_rights_root_sha256": contest_rights_root,
        "source_neutral_entities_root_sha256": source_entities_root,
        "relationship_leaves_root_sha256": relationships_root,
        "representation_rule_sha256": FRONTIER_REPRESENTATION_RULE_SHA256,
        "missingness_state_root_sha256": missingness_root,
        "warning_state_root_sha256": warning_root,
        "confidence_state_root_sha256": confidence_root,
        "commercial_review_requirement_sha256": commercial_root,
        "immutable_parents_root_sha256": immutable_root,
        "complete_universe_root_sha256": COMPLETE_UNIVERSE_ROOT,
    }
    policy_digest_fields = {
        "schema_version": "itda.catalog-contest-use-official-public-data-profile.v1",
        "policy_version": "contest-use-official-public-data-v1",
        "scope": CONTEST_SCOPE,
        "commercial_production_rights_review_required": True,
        **policy_fields,
        "confidence_is_qualification_filter_only": True,
        "confidence_adds_score": False,
        "image_presence_adds_score": False,
        "popularity_adds_score": False,
    }
    policy_model = ContestUsePolicy(
        **policy_fields,
        policy_sha256=canonical_sha256(policy_digest_fields),
    )
    frontier_fields: dict[str, Any] = {
        "universe_count": 718,
        "candidate_accounting_root_sha256": accounting_root,
        "eligible_pool": tuple(eligible_rows),
        "eligible_pool_sha256": eligible_root,
        "eligible_candidate_count": len(eligible_rows),
        "eligible_group_counts": group_counts,
        "capped_capacity": sum(min(12, group_counts[group]) for group in GROUP_ORDER),
        "quota_config_sha256": quota_config.config_sha256,
        "quota_proof_sha256": quota.attestation_sha256,
        "final_quotas": quota.final_quotas,
        "noncanonical_preview_ids": preview,
        "exact_36_sha256": canonical_sha256(list(preview)),
        "selectable_candidate_count": len(preview),
        "human_decision_count": 0,
    }
    frontier_digest_fields = {
        "schema_version": "itda.catalog-contest-use-selection-frontier.v1",
        "scope": CONTEST_SCOPE,
        **frontier_fields,
        "eligible_pool": eligible_rows,
        "noncanonical_preview_ids": list(preview),
        "preview_is_canonical_catalog": False,
        "human_choice_and_order_required": True,
        "confidence_used_for_selection": False,
        "popularity_used_for_selection": False,
        "ordering_rule": "group-ordinal-then-canonical-utf8-source-neutral-id",
    }
    frontier_model = ContestSelectionFrontier(
        **frontier_fields,
        frontier_sha256=canonical_sha256(frontier_digest_fields),
    )
    accounting = {
        "schema_version": "itda.catalog-contest-use-candidate-accounting.v1",
        "scope": CONTEST_SCOPE,
        "universe_count": 718,
        "rows": accounting_rows,
        "rows_root_sha256": accounting_root,
        "missingness_state_root_sha256": missingness_root,
        "warning_state_root_sha256": warning_root,
        "confidence_state_root_sha256": confidence_root,
        "confidence_is_qualification_filter_only": True,
        "confidence_adds_score": False,
    }
    accounting["accounting_sha256"] = canonical_sha256(accounting)
    mode_roots = mode_security_roots(network_hash)
    replay_content = {
        "schema_version": "itda.catalog-contest-use-replay-attestation.v1",
        "boundary_hashes": lineage,
        "immutable_parents_root_sha256": immutable_root,
        "policy_sha256": policy_model.policy_sha256,
        "candidate_accounting_root_sha256": accounting_root,
        "frontier_sha256": frontier_model.frontier_sha256,
        "eligible_pool_sha256": eligible_root,
        "exact_36_sha256": frontier_model.exact_36_sha256,
        "quota_proof_sha256": quota.attestation_sha256,
        "publication_state": "SUCCESS",
        "terminal_code": None,
    }
    replay_content["replay_content_sha256"] = canonical_sha256(replay_content)
    return _Projection(
        policy=policy_model,
        source_grants=source_grants,
        accounting=accounting,
        frontier=frontier_model,
        lineage=lineage,
        ordered_parents=ordered_parents,
        immutable_parents_root_sha256=immutable_root,
        plan49_summary_absence_sha256=absence_root,
        mode_roots=mode_roots,
        mode_roots_sha256=_canonical_line_sha256(mode_roots),
        replay_content=replay_content,
    )


def project_contest_profile(
    repository_root: Path | str,
    *,
    network_denial_policy_sha256: str = NETWORK_DENIAL_POLICY_SHA256,
) -> _Projection:
    return _derive_projection(
        Path(repository_root).resolve(strict=True), network_denial_policy_sha256
    )


def _replay_attestation(
    projection: _Projection, ordinal: Literal[1, 2]
) -> ContestReplayAttestation:
    content = projection.replay_content
    fields = {
        "replay_ordinal": ordinal,
        **{key: value for key, value in content.items() if key != "replay_content_sha256"},
        "replay_content_sha256": content["replay_content_sha256"],
    }
    return ContestReplayAttestation(
        **fields,
        replay_sha256=content["replay_content_sha256"],
    )


def _manifest_for(
    publication_state: Literal["SUCCESS", "TERMINAL"],
    payloads: Mapping[str, dict[str, Any]],
    ordered_parents: tuple[dict[str, Any], ...],
) -> ContestGenerationManifest:
    inventory = tuple(
        ContestGenerationChild(
            relpath=name,
            size_bytes=len(canonical_json_bytes(payloads[name])),
            file_sha256=_sha256_bytes(canonical_json_bytes(payloads[name])),
        )
        for name in sorted(payloads)
    )
    digest_fields = {
        "schema_version": "itda.catalog-contest-use-generation-manifest.v1",
        "publication_state": publication_state,
        "ordered_parents": list(ordered_parents),
        "payload_inventory": [child.model_dump(mode="json") for child in inventory],
    }
    return ContestGenerationManifest(
        publication_state=publication_state,
        ordered_parents=ordered_parents,
        payload_inventory=inventory,
        generation_sha256=canonical_sha256(digest_fields),
    )


def finalize_plan54_handoff(
    projection: _Projection,
    first: ContestReplayAttestation,
    second: ContestReplayAttestation,
    *,
    pre_handoff_content_sha256: str,
) -> ContestPlan54Handoff:
    frontier = projection.frontier
    fields: dict[str, Any] = {
        "mode_security_roots": projection.mode_roots,
        "mode_security_roots_sha256": projection.mode_roots_sha256,
        "contest_policy_sha256": projection.policy.policy_sha256,
        "contest_rights_root_sha256": projection.policy.contest_rights_root_sha256,
        "official_dataset_grants_root_sha256": (
            projection.policy.official_dataset_grants_root_sha256
        ),
        "asset_exclusions_root_sha256": projection.policy.asset_exclusions_root_sha256,
        "complete_universe_root_sha256": COMPLETE_UNIVERSE_ROOT,
        "pre_handoff_content_sha256": pre_handoff_content_sha256,
        "first_replay_sha256": first.replay_sha256,
        "second_replay_sha256": second.replay_sha256,
        "eligible_pool_sha256": frontier.eligible_pool_sha256,
        "exact_36_sha256": frontier.exact_36_sha256,
        "quota_proof_sha256": frontier.quota_proof_sha256,
        "missingness_state_root_sha256": projection.policy.missingness_state_root_sha256,
        "warning_state_root_sha256": projection.policy.warning_state_root_sha256,
        "confidence_state_root_sha256": projection.policy.confidence_state_root_sha256,
        "commercial_review_requirement_sha256": (
            projection.policy.commercial_review_requirement_sha256
        ),
        "immutable_parents_root_sha256": projection.immutable_parents_root_sha256,
        "eligible_candidate_count": 40,
        "eligible_group_counts": frontier.eligible_group_counts,
        "capped_capacity": 38,
        "final_quotas": frontier.final_quotas,
        "selectable_candidate_count": 36,
    }
    digest_fields = {
        "schema_version": "itda.catalog-contest-use-plan54-handoff.v1",
        "scope": CONTEST_SCOPE,
        "commercial_production_rights_review_required": True,
        "execution_mode": "captured_replay",
        "authority_required": False,
        "credential_required": False,
        "provider_traffic_allowed": False,
        "provider_attempt_inventory": [],
        **fields,
        "preview_is_canonical_catalog": False,
        "human_choice_and_order_required": True,
        "plan54_reachable": True,
    }
    return ContestPlan54Handoff(
        **fields,
        handoff_sha256=canonical_sha256(digest_fields),
    )


def replay_contest_profile(
    repository_root: Path | str,
    *,
    network_denial_policy_sha256: str = NETWORK_DENIAL_POLICY_SHA256,
) -> ContestGenerationResult:
    root = Path(repository_root).resolve(strict=True)
    first_projection = project_contest_profile(
        root,
        network_denial_policy_sha256=network_denial_policy_sha256,
    )
    second_projection = project_contest_profile(
        root,
        network_denial_policy_sha256=network_denial_policy_sha256,
    )
    if canonical_json_bytes(first_projection.replay_content) != canonical_json_bytes(
        second_projection.replay_content
    ):
        return build_terminal_generation(
            code=ContestProfileTerminalCode.REPLAY_MISMATCH,
            reasons=(
                {
                    "reason_code": "ISOLATED_REPLAY_CONTENT_MISMATCH",
                    "evidence_root_sha256": canonical_sha256(
                        [first_projection.replay_content, second_projection.replay_content]
                    ),
                },
            ),
            repository_root=root,
            network_denial_policy_sha256=network_denial_policy_sha256,
        )
    first = _replay_attestation(first_projection, 1)
    second = _replay_attestation(second_projection, 2)
    payloads: dict[str, dict[str, Any]] = {
        "policy.json": first_projection.policy.model_dump(mode="json"),
        "source-grants.json": first_projection.source_grants,
        "candidate-accounting.json": first_projection.accounting,
        "selection-frontier.json": first_projection.frontier.model_dump(mode="json"),
        "first-replay.json": first.model_dump(mode="json"),
        "second-replay.json": second.model_dump(mode="json"),
    }
    pre_handoff = canonical_sha256(
        {
            name: _sha256_bytes(canonical_json_bytes(payload))
            for name, payload in sorted(payloads.items())
        }
    )
    handoff = finalize_plan54_handoff(
        first_projection,
        first,
        second,
        pre_handoff_content_sha256=pre_handoff,
    )
    payloads["plan54-handoff.json"] = handoff.model_dump(mode="json")
    manifest = _manifest_for("SUCCESS", payloads, first_projection.ordered_parents)
    return ContestGenerationResult(
        publication_state="SUCCESS",
        terminal_code=None,
        exit_code=0,
        payloads=payloads,
        manifest=manifest,
        generation_sha256=manifest.generation_sha256,
        immutable_parents=first_projection.ordered_parents,
        immutable_parents_root_sha256=first_projection.immutable_parents_root_sha256,
        plan49_summary_absence_sha256=first_projection.plan49_summary_absence_sha256,
        mode_security_roots=first_projection.mode_roots,
        mode_security_roots_sha256=first_projection.mode_roots_sha256,
    )


def build_terminal_generation(
    *,
    code: ContestProfileTerminalCode | str,
    reasons: Sequence[Mapping[str, Any]],
    repository_root: Path | str,
    network_denial_policy_sha256: str = NETWORK_DENIAL_POLICY_SHA256,
) -> ContestGenerationResult:
    root = Path(repository_root).resolve(strict=True)
    lineage = verify_historical_lineage(root)
    ordered = _ordered_lineage(lineage)
    immutable_root = canonical_sha256(list(ordered))
    reason_models = tuple(
        sorted(
            (ContestTerminalReason.model_validate(dict(reason)) for reason in reasons),
            key=lambda reason: canonical_sha256(reason.model_dump(mode="json")),
        )
    )
    mode_roots = mode_security_roots(network_denial_policy_sha256)
    fields: dict[str, Any] = {
        "terminal_code": ContestProfileTerminalCode(code),
        "ordered_immutable_parents": ordered,
        "reasons": reason_models,
        "available_replay_roots": (),
        "mode_security_roots": mode_roots,
        "mode_security_roots_sha256": _canonical_line_sha256(mode_roots),
    }
    digest_fields = {
        "schema_version": "itda.catalog-contest-use-terminal.v1",
        "publication_state": "TERMINAL",
        "terminal_code": ContestProfileTerminalCode(code).value,
        "exit_code": 27,
        "predicate_version": "contest-profile-terminal-precedence-v1",
        "scope": CONTEST_SCOPE,
        "commercial_production_rights_review_required": True,
        "ordered_immutable_parents": list(ordered),
        "reasons": [reason.model_dump(mode="json") for reason in reason_models],
        "available_replay_roots": [],
        "mode_security_roots": mode_roots,
        "mode_security_roots_sha256": _canonical_line_sha256(mode_roots),
        "plan54_reachable": False,
        "handoff_created": False,
        "summary_created": False,
        "review_created": False,
        "provider_traffic_observed": False,
        "credential_accessed": False,
        "authority_accessed": False,
        "split_created": False,
        "schema_mutated": False,
        "catalog_activated": False,
        "seal_created": False,
    }
    terminal = ContestProfileTerminal(
        **fields,
        terminal_payload_sha256=canonical_sha256(digest_fields),
    )
    payloads = {"terminal.json": terminal.model_dump(mode="json")}
    manifest = _manifest_for("TERMINAL", payloads, ordered)
    return ContestGenerationResult(
        publication_state="TERMINAL",
        terminal_code=ContestProfileTerminalCode(code),
        exit_code=27,
        payloads=payloads,
        manifest=manifest,
        generation_sha256=manifest.generation_sha256,
        immutable_parents=ordered,
        immutable_parents_root_sha256=immutable_root,
        plan49_summary_absence_sha256=str(lineage["02-49-SUMMARY.md"]["absence_sha256"]),
        mode_security_roots=mode_roots,
        mode_security_roots_sha256=_canonical_line_sha256(mode_roots),
    )


def _write_all(descriptor: int, payload: bytes) -> None:
    offset = 0
    while offset < len(payload):
        written = os.write(descriptor, payload[offset:])
        if written <= 0:
            raise OSError("short write while preparing contest generation")
        offset += written


def _create_private_file(path: Path, payload: bytes) -> None:
    descriptor = os.open(
        path,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0),
        0o600,
    )
    try:
        os.fchmod(descriptor, 0o600)
        _write_all(descriptor, payload)
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _fsync_dir(path: Path) -> None:
    descriptor = os.open(
        path,
        os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0),
    )
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _expected_files(result: ContestGenerationResult) -> dict[str, bytes]:
    files = {name: canonical_json_bytes(payload) for name, payload in result.payloads.items()}
    files["generation-manifest.json"] = canonical_json_bytes(
        result.manifest.model_dump(mode="json")
    )
    return files


def _stable_generation_snapshot(path: Path) -> dict[str, bytes]:
    try:
        before = path.lstat()
    except OSError as exc:
        raise ContestProfileCollisionError("generation directory is not readable") from exc
    if not stat.S_ISDIR(before.st_mode) or _mode(before) != "0700":
        raise ContestProfileCollisionError("generation directory mode or type differs")
    try:
        root_descriptor = os.open(
            path,
            os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0),
        )
    except OSError as exc:
        raise ContestProfileCollisionError(
            "generation directory cannot be opened no-follow"
        ) from exc
    try:
        opened = os.fstat(root_descriptor)
        if _identity(before) != _identity(opened):
            raise ContestProfileCollisionError("generation directory identity changed")
        names = tuple(sorted(os.listdir(root_descriptor)))
        files: dict[str, bytes] = {}
        for name in names:
            visible = os.stat(name, dir_fd=root_descriptor, follow_symlinks=False)
            if (
                not stat.S_ISREG(visible.st_mode)
                or visible.st_nlink != 1
                or _mode(visible) != "0600"
            ):
                raise ContestProfileCollisionError("generation child type, links, or mode differs")
            descriptor = os.open(
                name,
                os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0),
                dir_fd=root_descriptor,
            )
            try:
                child_before = os.fstat(descriptor)
                if _identity(visible) != _identity(child_before):
                    raise ContestProfileCollisionError("generation child identity changed")
                chunks: list[bytes] = []
                remaining = child_before.st_size
                while remaining:
                    chunk = os.read(descriptor, min(1_048_576, remaining))
                    if not chunk:
                        raise ContestProfileCollisionError("generation child read was short")
                    chunks.append(chunk)
                    remaining -= len(chunk)
                if os.read(descriptor, 1):
                    raise ContestProfileCollisionError("generation child grew during read")
                child_after = os.fstat(descriptor)
                visible_after = os.stat(name, dir_fd=root_descriptor, follow_symlinks=False)
                if not (
                    _identity(child_before) == _identity(child_after) == _identity(visible_after)
                ):
                    raise ContestProfileCollisionError("generation child changed during read")
                files[name] = b"".join(chunks)
            finally:
                os.close(descriptor)
        after = os.fstat(root_descriptor)
        visible_after = path.lstat()
        if not (_identity(opened) == _identity(after) == _identity(visible_after)):
            raise ContestProfileCollisionError("generation directory changed during verification")
        return files
    finally:
        os.close(root_descriptor)


def _parse_existing_result(
    path: Path,
    *,
    repository_root: Path,
) -> ContestGenerationResult:
    files = _stable_generation_snapshot(path)
    manifest_bytes = files.get("generation-manifest.json")
    if manifest_bytes is None:
        raise ContestProfileCollisionError("generation manifest is missing")
    try:
        manifest_payload = json.loads(manifest_bytes)
        manifest = ContestGenerationManifest.model_validate(manifest_payload)
    except (json.JSONDecodeError, ValidationError) as exc:
        raise ContestProfileCollisionError("generation manifest is invalid") from exc
    if canonical_json_bytes(manifest_payload) != manifest_bytes:
        raise ContestProfileCollisionError("generation manifest is not canonical")
    if path.name != manifest.generation_sha256:
        raise ContestProfileCollisionError("generation path basename differs from descriptor root")
    expected_names = {child.relpath for child in manifest.payload_inventory} | {
        "generation-manifest.json"
    }
    if set(files) != expected_names:
        raise ContestProfileCollisionError("generation inventory differs")
    payloads: dict[str, dict[str, Any]] = {}
    for child in manifest.payload_inventory:
        payload = files[child.relpath]
        if len(payload) != child.size_bytes or _sha256_bytes(payload) != child.file_sha256:
            raise ContestProfileCollisionError("generation child size or digest differs")
        try:
            parsed = json.loads(payload)
        except json.JSONDecodeError as exc:
            raise ContestProfileCollisionError("generation child is invalid JSON") from exc
        if not isinstance(parsed, dict) or canonical_json_bytes(parsed) != payload:
            raise ContestProfileCollisionError("generation child is not canonical JSON")
        payloads[child.relpath] = parsed
    if manifest.publication_state == "SUCCESS":
        if set(payloads) != set(SUCCESS_PAYLOAD_NAMES):
            raise ContestProfileCollisionError("success generation inventory is not exact")
        try:
            policy = ContestUsePolicy.model_validate(payloads["policy.json"])
            frontier = ContestSelectionFrontier.model_validate(payloads["selection-frontier.json"])
            handoff = ContestPlan54Handoff.model_validate(payloads["plan54-handoff.json"])
        except ValidationError as exc:
            raise ContestProfileCollisionError("success generation contract is invalid") from exc
        if handoff.eligible_pool_sha256 != frontier.eligible_pool_sha256:
            raise ContestProfileCollisionError("success handoff/frontier binding differs")
        terminal_code = None
        exit_code: Literal[0, 27] = 0
        mode_roots = handoff.mode_security_roots
        mode_root_sha = handoff.mode_security_roots_sha256
        immutable_root = policy.immutable_parents_root_sha256
    else:
        if set(payloads) != {"terminal.json"}:
            raise ContestProfileCollisionError("terminal generation inventory is not exact")
        try:
            terminal = ContestProfileTerminal.model_validate(payloads["terminal.json"])
        except ValidationError as exc:
            raise ContestProfileCollisionError("terminal generation contract is invalid") from exc
        terminal_code = terminal.terminal_code
        exit_code = 27
        mode_roots = terminal.mode_security_roots
        mode_root_sha = terminal.mode_security_roots_sha256
        immutable_root = canonical_sha256(list(manifest.ordered_parents))
    absence = next(
        (
            item.get("absence_sha256")
            for item in manifest.ordered_parents
            if item.get("leaf_id") == "02-49-SUMMARY.md"
        ),
        None,
    )
    if not isinstance(absence, str):
        raise ContestProfileCollisionError("Plan 49 Summary absence leaf is missing")
    return ContestGenerationResult(
        publication_state=manifest.publication_state,
        terminal_code=terminal_code,
        exit_code=exit_code,
        payloads=payloads,
        manifest=manifest,
        generation_sha256=manifest.generation_sha256,
        immutable_parents=manifest.ordered_parents,
        immutable_parents_root_sha256=immutable_root,
        plan49_summary_absence_sha256=absence,
        mode_security_roots=mode_roots,
        mode_security_roots_sha256=mode_root_sha,
    )


def _assert_result_matches_intended(
    actual: ContestGenerationResult,
    intended: ContestGenerationResult,
) -> None:
    if (
        actual.generation_sha256 != intended.generation_sha256
        or canonical_json_bytes(actual.manifest.model_dump(mode="json"))
        != canonical_json_bytes(intended.manifest.model_dump(mode="json"))
        or canonical_json_bytes(actual.payloads) != canonical_json_bytes(intended.payloads)
    ):
        raise ContestProfileCollisionError("existing generation differs from intended bytes")


def publish_contest_generation(
    result: ContestGenerationResult,
    *,
    output_base: Path,
    repository_root: Path | str,
) -> dict[str, Any]:
    root = Path(repository_root).resolve(strict=True)
    output_base.mkdir(parents=True, exist_ok=True)
    if output_base.is_symlink() or not output_base.is_dir():
        raise ContestProfileCollisionError("generation parent must be a regular directory")
    destination = output_base / result.generation_sha256
    if os.path.lexists(destination):
        if destination.is_symlink() or not destination.is_dir():
            raise ContestProfileCollisionError("generation destination is not a directory")
        actual = _parse_existing_result(destination, repository_root=root)
        _assert_result_matches_intended(actual, result)
        _PUBLISHED_LOCATIONS[result.generation_sha256] = destination
        return receipt_for_result(
            actual,
            repository_root=root,
            disposition="ALREADY_PRESENT_VERIFIED",
        )
    staging = Path(tempfile.mkdtemp(prefix=".contest-generation-", dir=output_base))
    preserve_uncertain = False
    try:
        os.chmod(staging, 0o700)
        for name, payload in sorted(_expected_files(result).items()):
            _create_private_file(staging / name, payload)
        _fsync_dir(staging)
        try:
            with prepared_directory_snapshot(staging) as snapshot:
                publish_immutable_directory(
                    prepared=staging,
                    output=destination,
                    snapshot=snapshot,
                )
        except FileExistsError:
            actual = _parse_existing_result(destination, repository_root=root)
            _assert_result_matches_intended(actual, result)
            _PUBLISHED_LOCATIONS[result.generation_sha256] = destination
            return receipt_for_result(
                actual,
                repository_root=root,
                disposition="ALREADY_PRESENT_VERIFIED",
            )
        except PublicationStateUncertainError as exc:
            preserve_uncertain = True
            raise ContestProfileUncertainError("generation publication state is uncertain") from exc
        actual = _parse_existing_result(destination, repository_root=root)
        _assert_result_matches_intended(actual, result)
        _PUBLISHED_LOCATIONS[result.generation_sha256] = destination
        return receipt_for_result(actual, repository_root=root, disposition="PUBLISHED")
    finally:
        if not preserve_uncertain and staging.exists():
            shutil.rmtree(staging)


def verify_contest_generation(
    generation_path: Path | str,
    *,
    repository_root: Path | str | None = None,
) -> dict[str, Any]:
    path = Path(generation_path).resolve(strict=True)
    root = (
        Path(repository_root).resolve(strict=True)
        if repository_root is not None
        else Path(__file__).resolve().parents[4]
    )
    result = _parse_existing_result(path, repository_root=root)
    _PUBLISHED_LOCATIONS[result.generation_sha256] = path
    return receipt_for_result(result, repository_root=root, disposition="VERIFIED_EXISTING")


def _generation_rel(result: ContestGenerationResult) -> str:
    return (GENERATION_REL_PREFIX / result.generation_sha256).as_posix()


def _success_invariants(
    result: ContestGenerationResult,
    *,
    repository_root: Path,
) -> dict[str, Any]:
    manifest_bytes = canonical_json_bytes(result.manifest.model_dump(mode="json"))
    handoff = result.payloads["plan54-handoff.json"]
    frontier = result.payloads["selection-frontier.json"]
    generation_rel = _generation_rel(result)
    return {
        "manifest_path": f"{generation_rel}/generation-manifest.json",
        "manifest_file_sha256": _sha256_bytes(manifest_bytes),
        "manifest_descriptor_sha256": result.generation_sha256,
        "payload_inventory_sha256": canonical_sha256(
            [child.model_dump(mode="json") for child in result.manifest.payload_inventory]
        ),
        "payload_inventory_count": 7,
        "directory_mode": "0700",
        "entry_mode": "0600",
        "immutable_parents_root_sha256": result.immutable_parents_root_sha256,
        "plan49_summary_absence_sha256": result.plan49_summary_absence_sha256,
        "first_replay_sha256": handoff["first_replay_sha256"],
        "second_replay_sha256": handoff["second_replay_sha256"],
        "eligible_pool_sha256": handoff["eligible_pool_sha256"],
        "eligible_candidate_count": 40,
        "eligible_group_counts": frontier["eligible_group_counts"],
        "capped_capacity": 38,
        "exact_36_sha256": handoff["exact_36_sha256"],
        "quota_proof_sha256": handoff["quota_proof_sha256"],
        "exact_quotas": frontier["final_quotas"],
        "warning_state_root_sha256": handoff["warning_state_root_sha256"],
        "confidence_state_root_sha256": handoff["confidence_state_root_sha256"],
        "commercial_review_requirement_sha256": handoff["commercial_review_requirement_sha256"],
        "mode_security_roots": result.mode_security_roots,
        "mode_security_roots_sha256": result.mode_security_roots_sha256,
        "handoff_path": f"{generation_rel}/plan54-handoff.json",
        "handoff_file_sha256": _sha256_bytes(
            canonical_json_bytes(result.payloads["plan54-handoff.json"])
        ),
        "pre_handoff_content_sha256": handoff["pre_handoff_content_sha256"],
        "selectable_candidate_count": 36,
        "human_decision_count": frontier["human_decision_count"],
        "plan54_reachable": True,
        "authority_required": False,
        "credential_required": False,
        "provider_traffic_allowed": False,
        "provider_attempt_inventory_sha256": canonical_sha256([]),
        "summary_path": SUMMARY_REL.as_posix(),
        "summary_disposition": "CLOSEOUT_PENDING",
        "canonical_bytes_verified": True,
        "permissions_verified": True,
        "mutual_exclusion_verified": True,
    }


def _terminal_invariants(result: ContestGenerationResult) -> dict[str, Any]:
    manifest_bytes = canonical_json_bytes(result.manifest.model_dump(mode="json"))
    terminal = result.payloads["terminal.json"]
    generation_rel = _generation_rel(result)
    return {
        "manifest_path": f"{generation_rel}/generation-manifest.json",
        "manifest_file_sha256": _sha256_bytes(manifest_bytes),
        "manifest_descriptor_sha256": result.generation_sha256,
        "payload_inventory_sha256": canonical_sha256(
            [child.model_dump(mode="json") for child in result.manifest.payload_inventory]
        ),
        "payload_inventory_count": 1,
        "directory_mode": "0700",
        "entry_mode": "0600",
        "immutable_parents_root_sha256": result.immutable_parents_root_sha256,
        "plan49_summary_absence_sha256": result.plan49_summary_absence_sha256,
        "terminal_path": f"{generation_rel}/terminal.json",
        "terminal_file_sha256": _sha256_bytes(canonical_json_bytes(terminal)),
        "terminal_payload_sha256": terminal["terminal_payload_sha256"],
        "mode_security_roots": result.mode_security_roots,
        "mode_security_roots_sha256": result.mode_security_roots_sha256,
        "provider_attempt_inventory_sha256": canonical_sha256([]),
        "plan54_reachable": False,
        "handoff_created": False,
        "summary_path": SUMMARY_REL.as_posix(),
        "summary_disposition": "FORBIDDEN",
        "review_created": False,
        "provider_traffic_observed": False,
        "credential_accessed": False,
        "authority_accessed": False,
        "split_created": False,
        "schema_mutated": False,
        "catalog_activated": False,
        "seal_created": False,
        "canonical_bytes_verified": True,
        "permissions_verified": True,
        "mutual_exclusion_verified": True,
    }


def receipt_for_result(
    result: ContestGenerationResult,
    *,
    repository_root: Path | str,
    disposition: Literal[
        "CHECK_ONLY", "PUBLISHED", "ALREADY_PRESENT_VERIFIED", "VERIFIED_EXISTING"
    ],
) -> dict[str, Any]:
    root = Path(repository_root).resolve(strict=True)
    summary_exists = os.path.lexists(root / SUMMARY_REL)
    if result.publication_state == "SUCCESS" and summary_exists:
        raise ContestProfileUncertainError(
            "Plan 55 Summary must be pending during generation proof"
        )
    if result.publication_state == "TERMINAL" and summary_exists:
        raise ContestProfileUncertainError("terminal branch forbids a Plan 55 Summary")
    invariants = (
        _success_invariants(result, repository_root=root)
        if result.publication_state == "SUCCESS"
        else _terminal_invariants(result)
    )
    return {
        "schema_version": "itda.catalog-contest-use-generation-receipt.v1",
        "generation_path": _generation_rel(result),
        "generation_sha256": result.generation_sha256,
        "publication_state": result.publication_state,
        "publication_disposition": disposition,
        "terminal_code": result.terminal_code.value if result.terminal_code else None,
        "exit_code": result.exit_code,
        "invariants": invariants,
    }


def _validate_receipt_shape(receipt: Mapping[str, Any]) -> None:
    expected = {
        "schema_version",
        "generation_path",
        "generation_sha256",
        "publication_state",
        "publication_disposition",
        "terminal_code",
        "exit_code",
        "invariants",
    }
    if set(receipt) != expected:
        raise ContestProfileUncertainError("receipt has missing, extra, alias, or secret fields")
    if receipt.get("schema_version") != "itda.catalog-contest-use-generation-receipt.v1":
        raise ContestProfileUncertainError("receipt schema version drifted")


def verify_receipt_triplet(
    check: Mapping[str, Any],
    publish: Mapping[str, Any],
    verify: Mapping[str, Any],
    *,
    repository_root: Path | str,
) -> int:
    root = Path(repository_root).resolve(strict=True)
    for receipt in (check, publish, verify):
        _validate_receipt_shape(receipt)
    if check.get("publication_disposition") != "CHECK_ONLY":
        raise ContestProfileUncertainError("receipt check disposition drifted")
    if publish.get("publication_disposition") not in {
        "PUBLISHED",
        "ALREADY_PRESENT_VERIFIED",
    }:
        raise ContestProfileUncertainError("receipt publish disposition drifted")
    if verify.get("publication_disposition") != "VERIFIED_EXISTING":
        raise ContestProfileUncertainError("receipt verify disposition drifted")
    common: list[bytes] = []
    for receipt in (check, publish, verify):
        payload = deepcopy(dict(receipt))
        payload.pop("publication_disposition")
        common.append(canonical_json_bytes(payload))
    if common[0] != common[1] or common[1] != common[2]:
        raise ContestProfileUncertainError("receipt triplet common fields differ")
    generation_sha = check.get("generation_sha256")
    if not isinstance(generation_sha, str):
        raise ContestProfileUncertainError("receipt generation root is malformed")
    canonical_path = root / GENERATION_REL_PREFIX / generation_sha
    actual_path = (
        canonical_path if canonical_path.exists() else _PUBLISHED_LOCATIONS.get(generation_sha)
    )
    if actual_path is None:
        raise ContestProfileUncertainError(
            "receipt generation does not exist for live verification"
        )
    actual = _parse_existing_result(actual_path, repository_root=root)
    expected = receipt_for_result(
        actual,
        repository_root=root,
        disposition="VERIFIED_EXISTING",
    )
    normalized_expected = deepcopy(expected)
    normalized_verify = deepcopy(dict(verify))
    normalized_expected.pop("publication_disposition")
    normalized_verify.pop("publication_disposition")
    if canonical_json_bytes(normalized_expected) != canonical_json_bytes(normalized_verify):
        raise ContestProfileUncertainError("receipt triplet differs from current generation bytes")
    current_lineage = _ordered_lineage(verify_historical_lineage(root))
    if canonical_json_bytes(list(current_lineage)) != canonical_json_bytes(
        list(actual.immutable_parents)
    ):
        raise ContestProfileUncertainError("receipt triplet immutable parents drifted")
    return actual.exit_code


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    current = commands.add_parser("project-current")
    current.add_argument("--repo-root", type=Path, required=True)
    mode = current.add_mutually_exclusive_group(required=True)
    mode.add_argument("--check", action="store_true")
    mode.add_argument("--publish", action="store_true")
    verify = commands.add_parser("verify-generation")
    verify.add_argument("generation_path", type=Path)
    final = commands.add_parser("finalize-plan54-handoff")
    final.add_argument("generation_path", type=Path)
    triplet = commands.add_parser("verify-receipt-triplet")
    triplet.add_argument("--check-receipt", type=Path, required=True)
    triplet.add_argument("--publish-receipt", type=Path, required=True)
    triplet.add_argument("--verify-receipt", type=Path, required=True)
    triplet.add_argument("--repo-root", type=Path, required=True)
    return parser


def _print_receipt(receipt: Mapping[str, Any]) -> None:
    sys.stdout.buffer.write(canonical_json_bytes(dict(receipt)))


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        network_hash = require_external_network_denial(
            os.environ.get("ITDA_EXTERNAL_NETWORK_DENIAL_POLICY_SHA256")
        )
        default_root = Path(__file__).resolve().parents[4]
        if args.command == "project-current":
            root = args.repo_root.resolve(strict=True)
            result = replay_contest_profile(
                root,
                network_denial_policy_sha256=network_hash,
            )
            if args.check:
                receipt = receipt_for_result(
                    result,
                    repository_root=root,
                    disposition="CHECK_ONLY",
                )
            else:
                receipt = publish_contest_generation(
                    result,
                    output_base=root / GENERATION_REL_PREFIX,
                    repository_root=root,
                )
            _print_receipt(receipt)
            return result.exit_code
        if args.command == "verify-generation":
            receipt = verify_contest_generation(
                args.generation_path,
                repository_root=default_root,
            )
            _print_receipt(receipt)
            return int(receipt["exit_code"])
        if args.command == "finalize-plan54-handoff":
            receipt = verify_contest_generation(
                args.generation_path,
                repository_root=default_root,
            )
            if receipt["publication_state"] != "SUCCESS":
                return 27
            result = _parse_existing_result(
                args.generation_path.resolve(strict=True),
                repository_root=default_root,
            )
            sys.stdout.buffer.write(canonical_json_bytes(result.payloads["plan54-handoff.json"]))
            return 0
        check_path = args.check_receipt.resolve(strict=True)
        publish_path = args.publish_receipt.resolve(strict=True)
        verify_path = args.verify_receipt.resolve(strict=True)
        check = load_canonical_json_nofollow(
            check_path,
            max_bytes=2_000_000,
            repository_root=check_path.parent,
        )
        publish = load_canonical_json_nofollow(
            publish_path,
            max_bytes=2_000_000,
            repository_root=publish_path.parent,
        )
        verify = load_canonical_json_nofollow(
            verify_path,
            max_bytes=2_000_000,
            repository_root=verify_path.parent,
        )
        return verify_receipt_triplet(
            check,
            publish,
            verify,
            repository_root=args.repo_root,
        )
    except (ContestProfileError, ValidationError, OSError, KeyError, TypeError) as exc:
        print(f"ITDA_CONTEST_PROFILE_UNCERTAIN: {exc}", file=sys.stderr)
        return 28


if __name__ == "__main__":
    raise SystemExit(main())


__all__ = [
    "NETWORK_DENIAL_POLICY",
    "NETWORK_DENIAL_POLICY_SHA256",
    "OUTPUT_ROOT_REL",
    "PLAN49_HISTORY_SHA256",
    "SUCCESS_PAYLOAD_NAMES",
    "TERMINAL_PREDICATE_ORDER",
    "ContestProfileCollisionError",
    "ContestProfileError",
    "ContestProfileUncertainError",
    "build_terminal_generation",
    "derive_axis_evidence_basis",
    "derive_dataset_permission",
    "evaluate_terminal_code",
    "finalize_plan54_handoff",
    "load_canonical_json_nofollow",
    "mode_security_roots",
    "project_contest_profile",
    "publish_contest_generation",
    "receipt_for_result",
    "replay_contest_profile",
    "require_external_network_denial",
    "resolve_replay_terminal",
    "select_noncanonical_preview",
    "verify_contest_generation",
    "verify_historical_lineage",
    "verify_receipt_triplet",
]
