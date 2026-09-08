"""Derive and publish one strictly offline catalog-remediation preflight."""

from __future__ import annotations

import argparse
import hashlib
import os
import re
import stat
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from itda.cli.build_catalog_supplemental_evidence import (
    _load_canonical,
    _read_regular,
    verify_round_envelope,
)
from itda.cli.freeze_preview import publish_immutable_directory
from itda.contracts.catalog_remediation_preflight import (
    SOURCE_PRIORITY,
    ConfirmedCoverageBound,
    OfficialSourceCapability,
    PredeclaredLocalCapture,
    RecordAvailabilityState,
    SourceCapabilityState,
    SupplementalSourcePlan,
    TargetMatrix,
    TargetRow,
    build_confirmed_coverage_bound,
    build_packet_manifest,
    build_source_plan,
    build_target_matrix,
)
from itda.domain.canonical import canonical_json_bytes, canonical_sha256

INSUFFICIENT_CONFIRMED_COVERAGE = 24
EVIDENCE_FRONTIER_EXHAUSTED = 21
NON_ADDRESSABLE_IDENTITY_REVIEW_OVERFLOW = 22

PHASE_DIR = Path(".planning/phases/02-canonical-36-rights-and-evaluation-manifest")
SUMMARY_RELPATH = PHASE_DIR / "02-37-SUMMARY.md"
RESEARCH_RELPATH = PHASE_DIR / "02-REMEDIATION-RESEARCH.md"
EXPECTED_SALVAGE_BASE = Path("artifacts/restricted/catalog/v2/supplemental/salvage")
TERMINAL_AGGREGATE_RELPATH = Path(
    "artifacts/restricted/catalog/v2/enrichment/rounds/"
    "01072d20529d6114c0b1d7093f02b42f547e9f519fadc6b09e838c1c2a969b55/"
    "aggregate-readiness.json"
)
PREDECLARED_CAPTURES_RELPATH = Path(
    "artifacts/restricted/catalog/v2/supplemental/preflight-inputs/"
    "predeclared-local-captures.json"
)
PREFLIGHT_RELPATH = Path("artifacts/restricted/catalog/v2/supplemental/preflight")
HEX_64 = re.compile(r"^[0-9a-f]{64}$")
SUMMARY_FIELDS = (
    "status",
    "supplemental_status",
    "supplemental_salvage_base",
    "supplemental_round_root",
    "supplemental_round_id",
    "supplemental_success_root",
    "supplemental_evidence_manifest_sha256",
    "supplemental_round_manifest_sha256",
)
IDENTITY_KEYS = (
    "request_sha256",
    "state_attestation_sha256",
    "target_sha256",
    "binding_sha256",
    "nonce_sha256",
)
CHILD_ORDER = (
    "official-source-metadata-manifest.json",
    "supplemental-target-matrix.json",
    "coverage-upper-bound.json",
    "preflight-state-attestation.json",
    "supplemental-round-manifest.json",
)


class PreflightError(ValueError):
    """Raised when offline preflight facts cannot be replayed exactly."""


@dataclass(frozen=True)
class PreflightGeneration:
    """A byte-stable prepublication generation."""

    round_id: str
    packet_root: str
    children: dict[str, bytes]
    round_manifest: dict[str, object]
    target_matrix: TargetMatrix
    coverage: ConfirmedCoverageBound
    source_plan: SupplementalSourcePlan | None
    state: dict[str, object]
    exit_code: int


def _sha256(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def _parse_summary_frontmatter(path: Path) -> dict[str, str]:
    raw = _read_regular(path)
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as error:
        raise PreflightError("Plan 37 Summary is not UTF-8") from error
    if not text.startswith("---\n") or "\n---\n" not in text[4:]:
        raise PreflightError("Plan 37 Summary frontmatter is missing")
    header = text[4 : text.index("\n---\n", 4)]
    values: dict[str, str] = {}
    for line in header.splitlines():
        if not line or line[0].isspace() or ":" not in line:
            continue
        key, value = line.split(":", 1)
        if key in SUMMARY_FIELDS:
            values[key] = value.strip().strip("\"'")
    if set(values) != set(SUMMARY_FIELDS):
        raise PreflightError("Plan 37 Summary predecessor fields drifted")
    # GSD summaries use status: complete; the plan-specific success field is
    # the authoritative predecessor success assertion.
    if values["status"] != "complete" or values["supplemental_status"] != "success":
        raise PreflightError("Plan 37 predecessor is not a completed success")
    return values


def _resolve_predecessor(repo_root: Path) -> tuple[Path, dict[str, object], dict[str, str]]:
    summary = _parse_summary_frontmatter(repo_root / SUMMARY_RELPATH)
    if summary["supplemental_salvage_base"] != EXPECTED_SALVAGE_BASE.as_posix():
        raise PreflightError("Plan 37 salvage base drifted")
    root_rel = Path(summary["supplemental_round_root"])
    expected_rel = EXPECTED_SALVAGE_BASE / summary["supplemental_success_root"]
    if root_rel != expected_rel:
        raise PreflightError("Plan 37 success root is outside the fixed salvage base")
    root = repo_root / root_rel
    base = (repo_root / EXPECTED_SALVAGE_BASE).resolve(strict=True)
    resolved = root.resolve(strict=True)
    if resolved.parent != base:
        raise PreflightError("Plan 37 success root containment failed")
    if not (
        summary["supplemental_round_id"] == summary["supplemental_success_root"] == resolved.name
    ):
        raise PreflightError("Plan 37 root, ID, and digest basename differ")
    try:
        envelope = verify_round_envelope(resolved)
    except (OSError, ValueError) as error:
        raise PreflightError("Plan 37 round envelope verification failed") from error
    if envelope["root_sha256"] != resolved.name:
        raise PreflightError("Plan 37 round root digest drifted")
    evidence_raw = _read_regular(resolved / "supplemental-evidence-manifest.json")
    round_raw = _read_regular(resolved / "supplemental-round-manifest.json")
    if _sha256(evidence_raw) != summary["supplemental_evidence_manifest_sha256"]:
        raise PreflightError("Plan 37 evidence manifest file hash drifted")
    if _sha256(round_raw) != summary["supplemental_round_manifest_sha256"]:
        raise PreflightError("Plan 37 round manifest file hash drifted")
    return resolved, envelope, summary


def _source_capabilities(research_sha256: str) -> tuple[OfficialSourceCapability, ...]:
    common: dict[str, object] = {
        "research_file_sha256": research_sha256,
        "research_date": "2026-07-30",
        "refreshed_during_preflight": False,
        "proves_record_availability": False,
        "proves_rights": False,
    }
    return (
        OfficialSourceCapability(
            source_priority=0,
            official_source_id="15114464",
            official_source_url="https://www.data.go.kr/data/15114464/openapi.do",
            capability_state=SourceCapabilityState.SCHEMA_CAPABLE,
            documented_fields=(
                "address",
                "coordinates",
                "facilities",
                "introduction",
                "name",
                "representative_image",
            ),
            **common,
        ),
        OfficialSourceCapability(
            source_priority=1,
            official_source_id="15109381",
            official_source_url="https://www.data.go.kr/data/15109381/openapi.do",
            capability_state=SourceCapabilityState.SCHEMA_CAPABLE,
            documented_fields=(
                "address",
                "contact",
                "coordinates",
                "facilities",
                "fee",
                "name",
                "operating_hours",
            ),
            **common,
        ),
        OfficialSourceCapability(
            source_priority=2,
            official_source_id="3070426",
            official_source_url="https://www.data.go.kr/data/3070426/openapi.do",
            capability_state=SourceCapabilityState.SCHEMA_CAPABLE,
            documented_fields=("description", "location", "metadata", "photos"),
            **common,
        ),
    )


def _predeclared_captures(repo_root: Path) -> dict[str, PredeclaredLocalCapture]:
    path = repo_root / PREDECLARED_CAPTURES_RELPATH
    if not path.exists():
        return {}
    manifest, _ = _load_canonical(path)
    if (
        set(manifest) != {"schema_version", "captures"}
        or manifest["schema_version"] != "itda.predeclared-local-captures.v1"
        or not isinstance(manifest["captures"], list)
    ):
        raise PreflightError("predeclared local capture manifest shape drifted")
    captures = tuple(
        PredeclaredLocalCapture.model_validate(value)
        for value in manifest["captures"]
    )
    by_place = {capture.place_entity_id: capture for capture in captures}
    if len(by_place) != len(captures):
        raise PreflightError("predeclared capture manifest repeats a place identity")
    return by_place


def _target_frontier(
    aggregate: dict[str, Any],
    *,
    captures: dict[str, PredeclaredLocalCapture],
) -> list[TargetRow]:
    need = {
        "history_culture": 12,
        "history_scenery_boundary": 6,
        "image_modern_content": 6,
    }
    frontier: list[TargetRow] = []
    for value in aggregate["rows"]:
        if (
            value["objective_eligible"]
            or value["representation_assignment_status"] != "PRIMARY"
            or value["representation_primary_group"] == "rest_walk_immersion"
        ):
            continue
        deficits = tuple(value["named_deficits"])
        group = value["representation_primary_group"]
        if deficits == ("OPERATING_INFO_MISSING",) and group == "image_modern_content":
            selected_deficits = ("OPERATING_INFO_MISSING",)
            required_fields = ("operating_information",)
        elif (
            "DESCRIPTION_MISSING" in deficits
            and "DIRECT_MEDIA_MISSING" in deficits
            and "NOT_SINGLE_T0_TOURAPI_PLACE" not in deficits
        ):
            selected_deficits = ("DESCRIPTION_MISSING", "DIRECT_MEDIA_MISSING")
            required_fields = (
                "korean_description",
                "media_url",
                "media_creator",
                "media_license",
            )
        else:
            continue
        capture = captures.get(value["place_entity_id"])
        frontier.append(
            TargetRow(
                place_entity_id=value["place_entity_id"],
                existing_provider_candidate_id=value["provider_place_candidate_id"],
                primary_coverage_group=group,
                mandatory_deficits=selected_deficits,
                mandatory_deficit_count=len(selected_deficits),
                under_target_group_need=need[group],
                proposed_source_ids=SOURCE_PRIORITY,
                required_fields=required_fields,
                record_availability=(
                    RecordAvailabilityState.EXACT_LOCAL_ID_MATCH
                    if capture is not None
                    else RecordAvailabilityState.RECORD_AVAILABILITY_UNVERIFIED
                ),
                predeclared_capture=capture,
                confidence_adds_score=False,
                canonical_membership_created=False,
                split_membership_created=False,
            )
        )
    return frontier


def _round_identities(
    *,
    seed: str,
    ordered_parents: tuple[str, ...],
) -> dict[str, str]:
    identities = {
        name: canonical_sha256(
            {
                "schema_version": "itda.catalog-remediation-identity.v1",
                "generation_seed": seed,
                "identity_name": name,
                "ordinal": index,
                "ordered_parents": list(ordered_parents),
            }
        )
        for index, name in enumerate(IDENTITY_KEYS)
    }
    if len(set(identities.values())) != len(IDENTITY_KEYS):
        raise PreflightError("fresh round-envelope identities collided")
    return identities


def _canonical(value: object) -> bytes:
    return canonical_json_bytes(value)


def derive_preflight_generation(repo_root: Path) -> PreflightGeneration:
    """Build one generation using only verified local predecessor facts."""

    repo = repo_root.resolve(strict=True)
    salvage_root, envelope, summary = _resolve_predecessor(repo)
    research_raw = _read_regular(repo / RESEARCH_RELPATH)
    research_sha256 = _sha256(research_raw)
    aggregate, _ = _load_canonical(repo / TERMINAL_AGGREGATE_RELPATH)
    ancestry = envelope["payload"]["ancestry"]
    if not isinstance(ancestry, list) or len(ancestry) != 3:
        raise PreflightError("legacy terminal ancestry prefix drifted")
    ordered_parents = tuple([str(row["round_id"]) for row in ancestry] + [salvage_root.name])
    captures = _predeclared_captures(repo)
    frontier = _target_frontier(aggregate, captures=captures)
    # The proposed official-source identities have not been attempted. Legacy
    # TourAPI aliases remain audit facts, not attempt IDs for these new sources.
    matrix = build_target_matrix(
        frontier=frontier,
        ordered_ancestry=ordered_parents,
        attempted_provider_ids=(),
        terminal_eligible_group_counts=aggregate["eligible_group_counts"],
        terminal_objective_eligible_count=aggregate["objective_eligible_count"],
    )
    coverage = build_confirmed_coverage_bound(matrix=matrix, repo_root=repo)
    source_plan = (
        build_source_plan(targets=matrix.rows, coverage=coverage)
        if coverage.representation_feasible
        else None
    )
    capabilities = _source_capabilities(research_sha256)
    source_metadata = {
        "schema_version": "itda.official-source-metadata-manifest.v1",
        "source_priority": list(SOURCE_PRIORITY),
        "research_relpath": RESEARCH_RELPATH.as_posix(),
        "research_file_sha256": research_sha256,
        "research_date": "2026-07-30",
        "network_refreshed": False,
        "record_availability_proven": False,
        "rights_proven": False,
        "sources": [item.model_dump(mode="json") for item in capabilities],
    }
    seed = canonical_sha256(
        {
            "ordered_parents": list(ordered_parents),
            "research_file_sha256": research_sha256,
            "matrix_sha256": matrix.matrix_sha256,
            "coverage_bound_sha256": coverage.bound_sha256,
        }
    )
    identities = _round_identities(seed=seed, ordered_parents=ordered_parents)
    round_id = canonical_sha256(
        {
            "schema_version": "itda.catalog-remediation-round-id.v1",
            "non_authorizing_identities": identities,
            "ordered_parents": list(ordered_parents),
        }
    )
    state: dict[str, object] = {
        "schema_version": "itda.catalog-remediation-preflight-state.v1",
        "outcome": coverage.outcome,
        "network_state": "NETWORK_DISABLED",
        "external_data_bytes_obtained": 0,
        "ordered_parents": list(ordered_parents),
        "research_date": "2026-07-30",
        "research_file_sha256": research_sha256,
        "source_capability_status": "SCHEMA_CAPABLE",
        "record_availability_status": (
            "EXACT_LOCAL_ID_MATCH"
            if coverage.confirmed_target_count
            else "RECORD_AVAILABILITY_UNVERIFIED"
        ),
        "confirmed_total": coverage.confirmed_projected_total,
        "confirmed_group_counts": coverage.confirmed_group_counts,
        "confirmed_capped_sum": coverage.confirmed_capped_sum,
        "target_deficit_serviceability": list(coverage.target_serviceability),
        "rights_status": coverage.rights_status,
        "authority_issued_or_consumed": False,
        "authority_inherited": False,
        "authorizes_provider_execution": False,
        "authorizes_import": False,
        "plan39_reachable": coverage.representation_feasible,
        "canonical_membership_created": False,
        "split_membership_created": False,
        "schema_artifact_created": False,
        "seal_artifact_created": False,
        "source_plan_published": source_plan is not None,
        "successor_disposition": (
            "PLAN39_APPROVAL_MAY_BE_REQUESTED"
            if source_plan is not None
            else "HUMAN_SUPPLY_EXACT_OFFICIAL_LOCAL_CAPTURES_OR_REPLAN"
        ),
        "successor_target_matrix_sha256": matrix.matrix_sha256,
    }
    child_values: dict[str, object] = {
        "official-source-metadata-manifest.json": source_metadata,
        "supplemental-target-matrix.json": matrix.model_dump(mode="json"),
        "coverage-upper-bound.json": coverage.model_dump(mode="json"),
        "preflight-state-attestation.json": state,
    }
    if source_plan is not None:
        child_values["supplemental-source-plan.json"] = source_plan.model_dump(mode="json")
    pre_round_children = [
        {
            "relpath": name,
            "file_sha256": _sha256(_canonical(child_values[name])),
        }
        for name in child_values
    ]
    round_payload = {
        "schema_version": "itda.catalog-remediation-round-manifest.v1",
        "round_id": round_id,
        "ordered_parents": list(ordered_parents),
        "predecessor_success_root": summary["supplemental_success_root"],
        "round_envelope_identities": identities,
        "attempted_provider_ids_root": aggregate["attempted_provider_ids_root"],
        "new_official_source_attempted_provider_ids": [],
        "research_file_sha256": research_sha256,
        "target_matrix_sha256": matrix.matrix_sha256,
        "coverage_bound_sha256": coverage.bound_sha256,
        "children": pre_round_children,
        "outcome": (
            "SUCCESS" if coverage.representation_feasible else "INSUFFICIENT_CONFIRMED_COVERAGE"
        ),
        "authorizes_provider_execution": False,
        "authorizes_import": False,
        "authority_inherited": False,
    }
    round_manifest: dict[str, object] = {
        "payload": round_payload,
        "root_sha256": canonical_sha256(round_payload),
    }
    child_values["supplemental-round-manifest.json"] = round_manifest
    ordered_names = list(CHILD_ORDER)
    if source_plan is not None:
        ordered_names.insert(3, "supplemental-source-plan.json")
    ordered_digests = [(name, _sha256(_canonical(child_values[name]))) for name in ordered_names]
    packet = build_packet_manifest(
        ordered_child_digests=ordered_digests,
        ordered_parents=ordered_parents,
        policy_identities=(
            research_sha256,
            summary["supplemental_evidence_manifest_sha256"],
            summary["supplemental_round_manifest_sha256"],
        ),
        confirmed_facts_sha256=coverage.bound_sha256,
        round_id=round_id,
        publication_state=("SUCCESS" if coverage.representation_feasible else "FAILURE"),
    )
    child_values["packet-manifest.json"] = packet.model_dump(mode="json")
    children = {name: _canonical(value) for name, value in child_values.items()}
    return PreflightGeneration(
        round_id=round_id,
        packet_root=packet.root_sha256,
        children=children,
        round_manifest=round_manifest,
        target_matrix=matrix,
        coverage=coverage,
        source_plan=source_plan,
        state=state,
        exit_code=0 if source_plan is not None else INSUFFICIENT_CONFIRMED_COVERAGE,
    )


def _write_exclusive(path: Path, payload: bytes) -> None:
    descriptor = os.open(
        path,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0),
        0o600,
    )
    try:
        offset = 0
        while offset < len(payload):
            written = os.write(descriptor, payload[offset:])
            if written <= 0:
                raise OSError("short write while publishing preflight")
            offset += written
        os.fchmod(descriptor, 0o600)
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def publish_preflight_generation(
    generation: PreflightGeneration,
    *,
    output_base: Path,
) -> Path:
    """Atomically publish one immutable success or failure generation."""

    base = output_base.resolve()
    destination = (
        base / generation.packet_root
        if generation.exit_code == 0
        else base / "rounds" / generation.packet_root
    )
    destination.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    os.chmod(destination.parent, 0o700)
    prepared = Path(tempfile.mkdtemp(prefix=".catalog-preflight-", dir=destination.parent))
    os.chmod(prepared, 0o700)
    try:
        for name, payload in generation.children.items():
            _write_exclusive(prepared / name, payload)
        directory_descriptor = os.open(
            prepared,
            os.O_RDONLY | getattr(os, "O_DIRECTORY", 0),
        )
        try:
            os.fsync(directory_descriptor)
        finally:
            os.close(directory_descriptor)
        publish_immutable_directory(prepared=prepared, output=destination)
    finally:
        if prepared.exists():
            for path in prepared.iterdir():
                path.unlink()
            prepared.rmdir()
    _verify_published_generation(destination, generation=generation)
    return destination


def _verify_published_generation(
    root: Path,
    *,
    generation: PreflightGeneration,
) -> None:
    before = os.lstat(root)
    if (
        not stat.S_ISDIR(before.st_mode)
        or stat.S_IMODE(before.st_mode) != 0o700
        or root.is_symlink()
        or root.name != generation.packet_root
    ):
        raise PreflightError("published generation root identity or mode drifted")
    if sorted(path.name for path in root.iterdir()) != sorted(generation.children):
        raise PreflightError("published generation child inventory drifted")
    for name, expected in generation.children.items():
        path = root / name
        actual = _read_regular(path)
        if (
            actual != expected
            or stat.S_IMODE(os.lstat(path).st_mode) != 0o600
        ):
            raise PreflightError("published generation child bytes or mode drifted")
    packet = _load_packet(root)
    if packet["root_sha256"] != generation.packet_root:
        raise PreflightError("published packet root drifted")
    if os.lstat(root) != before:
        raise PreflightError("published generation changed during verification")


def _load_packet(root: Path) -> dict[str, Any]:
    before = os.lstat(root)
    if (
        not stat.S_ISDIR(before.st_mode)
        or stat.S_IMODE(before.st_mode) != 0o700
        or root.is_symlink()
    ):
        raise PreflightError("success root must be a non-symlink 0700 directory")
    packet, raw = _load_canonical(root / "packet-manifest.json")
    if tuple(packet) != ("payload", "root_sha256"):
        raise PreflightError("success packet outer shape drifted")
    if packet["root_sha256"] != root.name:
        raise PreflightError("success packet root does not match directory basename")
    if canonical_sha256(packet["payload"]) != root.name:
        raise PreflightError("success packet payload digest drifted")
    if raw != canonical_json_bytes(packet):
        raise PreflightError("success packet is not canonical")
    return packet


def verify_exact_success_under(
    base: Path,
    *,
    require_confirmed_coverage: bool,
    repo_root: Path | None = None,
) -> Path:
    """Discover and replay exactly one digest-named confirmed success root."""

    if not require_confirmed_coverage:
        raise PreflightError("--require-confirmed-coverage is mandatory for a success claim")
    if not base.exists():
        raise PreflightError("expected exactly one success root, found none")
    candidates = sorted(
        path for path in base.iterdir() if path.is_dir() and HEX_64.fullmatch(path.name)
    )
    if len(candidates) != 1:
        raise PreflightError(f"expected exactly one success root, found {len(candidates)}")
    root = candidates[0]
    packet = _load_packet(root)
    if packet["payload"].get("publication_state") != "SUCCESS":
        raise PreflightError("discovered root is not a success packet")
    children = packet["payload"].get("children")
    if not isinstance(children, list):
        raise PreflightError("success packet child inventory is invalid")
    expected_names: list[str] = []
    for row in children:
        name = row["relpath"]
        raw = _read_regular(root / name)
        if stat.S_IMODE(os.lstat(root / name).st_mode) != 0o600:
            raise PreflightError("success child mode drifted")
        if _sha256(raw) != row["file_sha256"]:
            raise PreflightError("success child digest drifted")
        expected_names.append(name)
    actual_names = sorted(path.name for path in root.iterdir())
    if actual_names != sorted([*expected_names, "packet-manifest.json"]):
        raise PreflightError("success root has an untracked child")
    if "supplemental-source-plan.json" not in expected_names:
        raise PreflightError("success packet has no source plan")
    matrix_value, _ = _load_canonical(root / "supplemental-target-matrix.json")
    coverage_value, _ = _load_canonical(root / "coverage-upper-bound.json")
    state, _ = _load_canonical(root / "preflight-state-attestation.json")
    matrix = TargetMatrix.model_validate(matrix_value)
    coverage = ConfirmedCoverageBound.model_validate(coverage_value)
    if repo_root is None:
        raise PreflightError("success confirmed-coverage replay requires the repository root")
    replayed = build_confirmed_coverage_bound(
        matrix=matrix,
        repo_root=repo_root.resolve(strict=True),
    )
    if (
        replayed != coverage
        or not coverage.representation_feasible
        or coverage.outcome != "FEASIBLE"
        or not coverage.all_target_deficits_serviceable
        or coverage.confirmed_target_count != matrix.target_count
        or state.get("rights_status") != "PENDING_PLAN39_VERIFICATION"
        or state.get("plan39_reachable") is not True
        or state.get("authorizes_provider_execution") is not False
        or state.get("authority_inherited") is not False
    ):
        raise PreflightError("success confirmed-coverage replay failed")
    return root


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo-root", type=Path, required=True)
    modes = parser.add_mutually_exclusive_group(required=True)
    modes.add_argument("--derive", action="store_true")
    modes.add_argument("--build", action="store_true")
    modes.add_argument("--check", action="store_true")
    parser.add_argument("--round-root", type=Path)
    parser.add_argument("--round-id")
    parser.add_argument("--discover-exact-success-under", type=Path)
    parser.add_argument("--require-confirmed-coverage", action="store_true")
    return parser


def _safe_result(generation: PreflightGeneration) -> dict[str, object]:
    return {
        "round_id": generation.round_id,
        "packet_root": generation.packet_root,
        "outcome": generation.coverage.outcome,
        "exit_code": generation.exit_code,
        "target_count": generation.target_matrix.target_count,
        "confirmed_total": generation.coverage.confirmed_projected_total,
        "confirmed_group_counts": generation.coverage.confirmed_group_counts,
        "confirmed_capped_sum": generation.coverage.confirmed_capped_sum,
        "source_plan_published": generation.source_plan is not None,
        "network_state": generation.state["network_state"],
        "external_data_bytes_obtained": 0,
    }


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    repo_root = args.repo_root.resolve(strict=True)
    if args.check:
        if args.discover_exact_success_under is None:
            raise PreflightError("--check requires --discover-exact-success-under")
        fixed_base = (repo_root / PREFLIGHT_RELPATH).resolve()
        if args.discover_exact_success_under.resolve() != fixed_base:
            raise PreflightError("success discovery is outside the fixed preflight base")
        verified = verify_exact_success_under(
            args.discover_exact_success_under,
            require_confirmed_coverage=args.require_confirmed_coverage,
            repo_root=repo_root,
        )
        print(canonical_json_bytes({"verified_success_root": str(verified)}).decode())
        return 0
    generation = derive_preflight_generation(repo_root)
    if args.derive:
        print(canonical_json_bytes(_safe_result(generation)).decode())
        return 0
    if args.round_root is None or args.round_id is None:
        raise PreflightError("--build requires explicit --round-root and --round-id")
    expected = Path(args.round_root).resolve()
    base = (repo_root / PREFLIGHT_RELPATH).resolve()
    expected_from_generation = (
        base / generation.packet_root
        if generation.exit_code == 0
        else base / "rounds" / generation.packet_root
    )
    if args.round_id != generation.round_id:
        raise PreflightError("explicit round ID does not match the frozen generation")
    if expected != expected_from_generation:
        raise PreflightError("explicit round root does not match the packet digest")
    published = publish_preflight_generation(generation, output_base=base)
    print(
        canonical_json_bytes(
            {**_safe_result(generation), "published_root": str(published)}
        ).decode()
    )
    return generation.exit_code


if __name__ == "__main__":
    raise SystemExit(main())
