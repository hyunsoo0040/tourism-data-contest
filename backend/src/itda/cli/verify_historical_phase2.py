"""Prove and replay Phase 2 historical verification equivalence."""

from __future__ import annotations

import argparse
import hashlib
import html
import re
import subprocess
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Any

from itda.cli.fingerprint_catalog_v1 import (
    PHASE_ROOT,
    FingerprintError,
    _load_manifest,
    _repo_root,
    _write_no_replace,
    verify_manifest,
    verify_successor_manifest,
)
from itda.domain.canonical import canonical_json_bytes, canonical_sha256

PLAN_CARDINALITY = (1, 2, 2, 3, 3, 2, 3, 3)
MAPPING_SCHEMA = "historical-verification-equivalence-v1"
EVIDENCE_SCHEMA = "historical-verification-evidence-v1"
IMMUTABILITY_PATH = (
    "artifacts/restricted/catalog/v2/lineage/v1-immutability-manifest.json"
)
SUCCESSOR_PATH = (
    "artifacts/restricted/catalog/v2/lineage/v1-immutability-manifest-v2.json"
)
_TASK_RE = re.compile(
    r"<task\b[^>]*>(?P<body>.*?)</task>",
    flags=re.DOTALL,
)
_NAME_RE = re.compile(r"<name>(?P<value>.*?)</name>", flags=re.DOTALL)
_VERIFY_RE = re.compile(
    r"<verify>\s*<automated>(?P<value>.*?)</automated>\s*</verify>",
    flags=re.DOTALL,
)
_PYTEST_RE = re.compile(
    r"(?<![A-Za-z0-9_./-])(?:backend/)?tests/[A-Za-z0-9_./-]+\.py"
    r"(?:::[A-Za-z0-9_]+)?"
)
_ARTIFACT_RE = re.compile(
    r"(?<![A-Za-z0-9_./-])(?:artifacts/restricted|(?:backend/)?fixtures|\.planning)/"
    r"[A-Za-z0-9_./*${}-]+"
)
_MODULE_RE = re.compile(r"\bitda\.cli\.[A-Za-z0-9_.-]+")
_NODE_RE = re.compile(r"\btest_[A-Za-z0-9_]+\b")


class HistoricalVerificationError(FingerprintError):
    """Raised when historical verification lineage fails closed."""


def _verify_historical_parent(
    repo_root: Path,
    *,
    successor_path: Path | None = None,
) -> None:
    predecessor = repo_root / IMMUTABILITY_PATH
    successor = repo_root / SUCCESSOR_PATH if successor_path is None else successor_path
    if successor.is_file():
        verify_successor_manifest(repo_root, predecessor, _load_manifest(successor))
        return
    verify_manifest(repo_root, predecessor)


def _sha(payload: str | bytes) -> str:
    raw = payload.encode("utf-8") if isinstance(payload, str) else payload
    return hashlib.sha256(raw).hexdigest()


def extract_sources(repo_root: Path) -> list[dict[str, object]]:
    rows: list[dict[str, object]] = []
    for plan_offset, expected_count in enumerate(PLAN_CARDINALITY, start=1):
        plan_id = f"02-{plan_offset:02d}"
        plan_path = repo_root / PHASE_ROOT / f"{plan_id}-PLAN.md"
        text = plan_path.read_text(encoding="utf-8")
        plan_rows: list[dict[str, object]] = []
        for task_ordinal, match in enumerate(_TASK_RE.finditer(text), start=1):
            body = match.group("body")
            name_match = _NAME_RE.search(body)
            verify_match = _VERIFY_RE.search(body)
            if name_match is None or verify_match is None:
                raise HistoricalVerificationError(
                    f"task {plan_id}.{task_ordinal} lacks name or automated verify"
                )
            task_name = html.unescape(name_match.group("value")).strip()
            command = html.unescape(verify_match.group("value"))
            plan_rows.append(
                {
                    "plan_id": plan_id,
                    "task_ordinal": task_ordinal,
                    "task_name": task_name,
                    "original_command": command,
                    "original_command_sha256": _sha(command),
                }
            )
        if len(plan_rows) != expected_count:
            raise HistoricalVerificationError(
                f"{plan_id} verify cardinality is {len(plan_rows)}, expected {expected_count}"
            )
        rows.extend(plan_rows)
    if len(rows) != 19:
        raise HistoricalVerificationError("historical verify cardinality must be exactly 19")
    return rows


def _normalize_obligation(value: str) -> str:
    return value.removeprefix("backend/")


def obligations(command: str) -> dict[str, list[str]]:
    gates: list[str] = []
    gate_patterns = {
        "uv-lock-check": r"\buv lock --check\b",
        "uv-sync-frozen": r"\buv sync --frozen\b",
        "git-check-ignore": r"\bgit check-ignore\b",
        "git-diff-check": r"\bgit diff --check\b",
        "pytest-collect-only": r"\b--collect-only\b",
        "pyarrow-version-25": r"pyarrow\.__version__ == '25\.0\.0'",
        "collect-catalog-preflight": r"collect_catalog --preflight-credential-ref",
        "collect-catalog-validate": r"collect_catalog --validate-report",
    }
    for name, pattern in gate_patterns.items():
        gates.extend([name] * len(re.findall(pattern, command)))
    return {
        "pytest_targets": sorted(
            _normalize_obligation(value).split("::", 1)[0]
            for value in _PYTEST_RE.findall(command)
        ),
        "controlled_nodes": sorted(_NODE_RE.findall(command)),
        "cli_modules": sorted(_MODULE_RE.findall(command)),
        "artifact_paths": sorted(
            _normalize_obligation(value.rstrip(";&"))
            for value in _ARTIFACT_RE.findall(command)
        ),
        "gates": sorted(gates),
    }


def _green_replacement(plan_id: str, task_ordinal: int) -> str | None:
    common = (
        "rtk mise exec -- uv run --offline --no-sync --frozen "
        "--no-python-downloads --project backend pytest "
    )
    commands: dict[tuple[str, int], tuple[list[str], list[str]]] = {
        ("02-02", 1): (
            [
                "tests/pipeline/test_catalog_collection.py",
                "tests/pipeline/test_crosswalk_revisions.py",
                "tests/pipeline/test_candidate_audit_exports.py",
                "tests/pipeline/test_catalog_relationships.py",
            ],
            [
                "tests/pipeline/test_catalog_collection.py::test_missing_catalog_collection_is_controlled_red",
                "tests/pipeline/test_crosswalk_revisions.py::test_missing_crosswalk_revisions_is_controlled_red",
                "tests/pipeline/test_candidate_audit_exports.py::test_missing_candidate_audit_exports_is_controlled_red",
                "tests/pipeline/test_catalog_relationships.py::test_missing_catalog_relationships_is_controlled_red",
            ],
        ),
        ("02-03", 1): (
            [
                "tests/pipeline/test_catalog_rights.py",
                "tests/pipeline/test_catalog_approval.py",
            ],
            [
                "tests/pipeline/test_catalog_rights.py::test_missing_catalog_rights_is_controlled_red",
                "tests/pipeline/test_catalog_approval.py::test_missing_catalog_approval_is_controlled_red",
            ],
        ),
        ("02-03", 2): (
            [
                "tests/pipeline/test_phase2_operator_journey.py",
                "tests/unit/test_real_manifest.py",
                "tests/integration/test_real_manifest_seal.py",
                "tests/security/test_phase2_artifact_leakage.py",
            ],
            [
                "tests/pipeline/test_phase2_operator_journey.py::test_phase2_operator_journey_reports_missing_entrypoints",
                "tests/unit/test_real_manifest.py::test_missing_real_manifest_is_controlled_red",
                "tests/integration/test_real_manifest_seal.py::test_missing_restricted_seal_is_controlled_red",
                "tests/security/test_phase2_artifact_leakage.py::test_missing_artifact_boundary_is_controlled_red",
            ],
        ),
    }
    selected = commands.get((plan_id, task_ordinal))
    if selected is None:
        return None
    files, nodes = selected
    collect = common + " ".join(f"backend/{value}" for value in files) + " -q --collect-only"
    if (plan_id, task_ordinal) == ("02-03", 2):
        red_nodes = nodes[::2]
        green_nodes = nodes[1::2]
        red_checks = " && ".join(
            (
                f"run_red backend/{node} "
                + (
                    "PHASE2-MISSING:operator-journey-entrypoints"
                    if "operator_journey" in node
                    else "PHASE2-MISSING:restricted-seal"
                )
            )
            for node in red_nodes
        )
        green = common + " ".join(f"backend/{node}" for node in green_nodes) + " -q"
        return (
            f"{collect} && {{ red_dir=$(rtk mktemp -d); "
            "trap 'rtk rm -rf \"$red_dir\"' EXIT; "
            "run_red() { target=\"$1\"; sentinel=\"$2\"; out=\"$red_dir/out.txt\"; "
            "set +e; "
            f"{common}\"$target\" -q >\"$out\" 2>&1; "
            "rc=$?; set -e; [ \"$rc\" -eq 1 ] && rtk rg -F \"$sentinel\" \"$out\"; }; "
            f"{red_checks}; }} && {green}"
        )
    execute = common + " ".join(f"backend/{value}" for value in nodes) + " -q"
    return f"{collect} && {execute}"


def _replacement_body(source: dict[str, object]) -> str:
    plan_id = str(source["plan_id"])
    task_ordinal = int(source["task_ordinal"])
    green = _green_replacement(plan_id, task_ordinal)
    if green is not None:
        return green
    original = str(source["original_command"])
    if (plan_id, task_ordinal) == ("02-04", 1):
        return (
            "rtk rg -n -F '/artifacts/restricted/catalog/**' .gitignore && "
            "rtk git check-ignore -v --no-index "
            "artifacts/restricted/catalog/v1/probe.json && "
            "! rtk git check-ignore -q --no-index "
            "backend/fixtures/catalog/v1/public/probe.json && "
            "rtk mise exec -- uv run --offline --no-sync --frozen "
            "--no-python-downloads --project backend pytest "
            "backend/tests/security/test_phase2_artifact_leakage.py -q"
        )
    if (plan_id, task_ordinal) == ("02-05", 3):
        report = (
            "artifacts/restricted/catalog/v1/collection/collection-report.json"
        )
        validation = (
            "artifacts/restricted/catalog/v1/collection/live-report-validation.json"
        )
        return (
            "validation_dir=$(rtk mktemp -d); "
            "trap 'rtk rm -rf \"$validation_dir\"' EXIT; "
            f"[ -f {report} ] && [ -f {validation} ] && "
            "[ -f fixtures/catalog/v1/public/proposal-36-coverage-seed.json ] && "
            "(cd backend && "
            "rtk mise exec -- uv run --offline --no-sync --frozen "
            "--no-python-downloads --project . python -m itda.cli.collect_catalog "
            "--validate-report "
            "--report-json ../artifacts/restricted/catalog/v1/collection/"
            "collection-report.json "
            "--seed-manifest ../fixtures/catalog/v1/public/"
            "proposal-36-coverage-seed.json "
            "--require-dataset 15101578 --require-dataset 15101971 "
            "--require-dataset 15101914 --min-candidates 60 "
            "--require-terminal-plan-completeness --require-resume-proof "
            '--validation-output "$validation_dir/live-report-validation.json" && '
            "rtk mise exec -- uv run --offline --no-sync --frozen "
            "--no-python-downloads --project . pytest "
            "tests/pipeline/test_catalog_collection.py "
            "tests/security/test_phase2_artifact_leakage.py -q) && "
            f"rtk git check-ignore -v --no-index {report}"
        )
    transformed = re.sub(r"(?<!backend/)tests/", "backend/tests/", original)
    transformed = re.sub(r"(?<!backend/)fixtures/", "backend/fixtures/", transformed)
    transformed = transformed.replace("$(mktemp -d)", "$(rtk mktemp -d)")
    transformed = transformed.replace("trap 'rm -rf ", "trap 'rtk rm -rf ")
    transformed = transformed.replace("rtk rg -i -E ", "rtk rg -i -e ")
    return transformed


def build_mapping(repo_root: Path) -> dict[str, object]:
    rows: list[dict[str, object]] = []
    replacement_ids: set[str] = set()
    source_keys: set[tuple[object, ...]] = set()
    for source in extract_sources(repo_root):
        replacement_id = (
            f"{source['plan_id']}-task-{int(source['task_ordinal']):02d}"
        )
        replacement = (
            "set -eu; repo_root=$(rtk git rev-parse --show-toplevel) && "
            'cd "$repo_root" && '
            + _replacement_body(source)
        )
        source_obligations = obligations(str(source["original_command"]))
        replacement_obligations = obligations(replacement)
        if source_obligations != replacement_obligations:
            raise HistoricalVerificationError(
                f"non-weaker obligation mismatch for {replacement_id}"
            )
        source_key = (
            source["plan_id"],
            source["task_ordinal"],
            source["task_name"],
            source["original_command_sha256"],
        )
        if source_key in source_keys or replacement_id in replacement_ids:
            raise HistoricalVerificationError("duplicate source key or replacement ID")
        source_keys.add(source_key)
        replacement_ids.add(replacement_id)
        rows.append(
            {
                "source": {
                    key: source[key]
                    for key in (
                        "plan_id",
                        "task_ordinal",
                        "task_name",
                        "original_command_sha256",
                    )
                },
                "replacement_id": replacement_id,
                "replacement_command": replacement,
                "replacement_command_sha256": _sha(replacement),
                "cwd_kind": "repository_root",
                "obligations": source_obligations,
            }
        )
    fields: dict[str, Any] = {
        "schema_version": MAPPING_SCHEMA,
        "source_count": 19,
        "rows": rows,
    }
    return {**fields, "mapping_sha256": canonical_sha256(fields)}


def _load_canonical(path: Path) -> dict[str, object]:
    return _load_manifest(path)


def _resolve(repo_root: Path, path: Path) -> Path:
    resolved = (path if path.is_absolute() else Path.cwd() / path).resolve()
    try:
        resolved.relative_to(repo_root.resolve())
    except ValueError as exc:
        raise HistoricalVerificationError(
            "lineage artifact path escapes the repository"
        ) from exc
    return resolved


def _verify_mapping(repo_root: Path, path: Path) -> dict[str, object]:
    expected = build_mapping(repo_root)
    if path.exists():
        if _load_canonical(path) != expected:
            raise HistoricalVerificationError("equivalence mapping is stale or tampered")
    else:
        _write_no_replace(path, canonical_json_bytes(expected))
    return expected


def _stable_output(payload: bytes, repo_root: Path) -> bytes:
    text = payload.decode("utf-8", errors="replace")
    text = text.replace(str(repo_root), "$REPO_ROOT")
    text = re.sub(r"\bin \d+(?:\.\d+)?s\b", "in <elapsed>s", text)
    text = re.sub(r"/(?:private/)?var/folders/\S+", "$TEMP", text)
    return text.encode("utf-8")


def _evidence_row(
    repo_root: Path,
    mapping_row: dict[str, object],
) -> dict[str, object]:
    command = str(mapping_row["replacement_command"])
    try:
        completed = subprocess.run(
            ["/bin/sh", "-c", command],
            cwd=repo_root,
            capture_output=True,
            check=False,
            timeout=55,
        )
        exit_code = completed.returncode
        stdout = completed.stdout
        stderr = completed.stderr
    except subprocess.TimeoutExpired as exc:
        exit_code = 124
        stdout = exc.stdout or b""
        stderr = (exc.stderr or b"") + b"\nPHASE2-REPLAY:timeout"
    named_hashes = {
        name: canonical_sha256(values)
        for name, values in dict(mapping_row["obligations"]).items()
    }
    fields: dict[str, object] = {
        "source": mapping_row["source"],
        "replacement_id": mapping_row["replacement_id"],
        "replacement_command_sha256": mapping_row["replacement_command_sha256"],
        "cwd": ".",
        "exit_code": exit_code,
        "status": "PASS" if exit_code == 0 else "FAIL",
        "stdout_sha256": _sha(_stable_output(stdout, repo_root)),
        "stderr_sha256": _sha(_stable_output(stderr, repo_root)),
        "named_evidence_sha256": named_hashes,
    }
    return {**fields, "row_sha256": canonical_sha256(fields)}


def build_evidence(
    repo_root: Path,
    mapping: dict[str, object],
) -> dict[str, object]:
    mapping_rows = mapping["rows"]
    assert isinstance(mapping_rows, list)
    with ThreadPoolExecutor(max_workers=4, thread_name_prefix="phase2-replay") as executor:
        futures = [
            executor.submit(_evidence_row, repo_root, row) for row in mapping_rows
        ]
        rows = [future.result() for future in futures]
    failures = [
        str(row["replacement_id"]) for row in rows if row["status"] != "PASS"
    ]
    if failures:
        raise HistoricalVerificationError(
            "historical replacements failed: " + ", ".join(failures)
        )
    fields: dict[str, object] = {
        "schema_version": EVIDENCE_SCHEMA,
        "mapping_sha256": mapping["mapping_sha256"],
        "evidence_count": 19,
        "rows": rows,
    }
    return {**fields, "evidence_sha256": canonical_sha256(fields)}


def _assert_replay_equivalent(
    recorded: dict[str, object],
    fresh: dict[str, object],
) -> None:
    volatile_row_fields = {"stdout_sha256", "stderr_sha256", "row_sha256"}

    def semantic_projection(evidence: dict[str, object]) -> dict[str, object]:
        rows = evidence.get("rows")
        if not isinstance(rows, list) or any(not isinstance(row, dict) for row in rows):
            raise HistoricalVerificationError("replay evidence rows are malformed")
        return {
            key: value
            for key, value in evidence.items()
            if key not in {"rows", "evidence_sha256"}
        } | {
            "rows": [
                {
                    key: value
                    for key, value in row.items()
                    if key not in volatile_row_fields
                }
                for row in rows
            ]
        }

    if semantic_projection(recorded) != semantic_projection(fresh):
        raise HistoricalVerificationError("fresh replay semantic evidence differs")


def _verify_evidence(
    mapping: dict[str, object],
    evidence: dict[str, object],
) -> None:
    fields = {key: value for key, value in evidence.items() if key != "evidence_sha256"}
    if evidence.get("evidence_sha256") != canonical_sha256(fields):
        raise HistoricalVerificationError("evidence root hash mismatch")
    rows = evidence.get("rows")
    if not isinstance(rows, list) or len(rows) != 19:
        raise HistoricalVerificationError("evidence must contain exactly 19 rows")
    mapping_rows = mapping["rows"]
    assert isinstance(mapping_rows, list)
    for expected, row in zip(mapping_rows, rows, strict=True):
        if not isinstance(row, dict):
            raise HistoricalVerificationError("evidence row must be an object")
        row_fields = {key: value for key, value in row.items() if key != "row_sha256"}
        if row.get("row_sha256") != canonical_sha256(row_fields):
            raise HistoricalVerificationError("evidence row hash mismatch")
        if (
            row.get("replacement_id") != expected["replacement_id"]
            or row.get("replacement_command_sha256")
            != expected["replacement_command_sha256"]
            or row.get("exit_code") != 0
            or row.get("status") != "PASS"
        ):
            raise HistoricalVerificationError("evidence mapping/status mismatch")
        expected_named = {
            name: canonical_sha256(values)
            for name, values in dict(expected["obligations"]).items()
        }
        if row.get("named_evidence_sha256") != expected_named:
            raise HistoricalVerificationError("named evidence hash mismatch")


def verify_equivalence(
    repo_root: Path,
    mapping_path: Path,
    evidence_path: Path | None,
) -> dict[str, object]:
    mapping = _verify_mapping(repo_root, mapping_path)
    if evidence_path is not None and evidence_path.exists():
        _verify_evidence(mapping, _load_canonical(evidence_path))
    _verify_historical_parent(repo_root)
    return mapping


def replay_equivalence(
    repo_root: Path,
    mapping_path: Path,
    evidence_path: Path,
) -> dict[str, object]:
    mapping = _verify_mapping(repo_root, mapping_path)
    fresh = build_evidence(repo_root, mapping)
    if evidence_path.exists():
        recorded = _load_canonical(evidence_path)
        _verify_evidence(mapping, recorded)
        _assert_replay_equivalent(recorded, fresh)
    else:
        _write_no_replace(evidence_path, canonical_json_bytes(fresh))
    _verify_historical_parent(repo_root)
    return fresh


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    modes = parser.add_mutually_exclusive_group(required=True)
    modes.add_argument("--verify-equivalence", type=Path, metavar="MAPPING")
    modes.add_argument("--replay-equivalence", type=Path, metavar="MAPPING")
    parser.add_argument("--evidence", type=Path)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    repo_root = _repo_root()
    evidence = _resolve(repo_root, args.evidence) if args.evidence is not None else None
    if args.verify_equivalence is not None:
        mapping = _resolve(repo_root, args.verify_equivalence)
        result = verify_equivalence(repo_root, mapping, evidence)
        print(result["mapping_sha256"])
    else:
        if evidence is None:
            raise HistoricalVerificationError("--evidence is required for replay")
        mapping = _resolve(repo_root, args.replay_equivalence)
        result = replay_equivalence(repo_root, mapping, evidence)
        print(result["evidence_sha256"])
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
