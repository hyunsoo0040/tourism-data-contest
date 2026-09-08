"""Verify and accept the complete membership-free Phase 2 evidence chain."""

# Exact Korean planning commitments are intentionally retained byte-for-byte.
# ruff: noqa: E501

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import stat
import subprocess
import sys
import time
from collections.abc import Callable, Mapping, Sequence
from datetime import UTC, date, datetime
from pathlib import Path
from typing import Any, cast

from itda.cli import fingerprint_catalog_v1 as lineage_capability
from itda.cli.build_catalog_v2_review import verify_adjudication_bundle
from itda.cli.fingerprint_catalog_v1 import FingerprintError
from itda.cli.verify_historical_phase2 import IMMUTABILITY_PATH, verify_equivalence
from itda.contracts.sqlite_manifest_authority import (
    INITIALIZATION_RESTRICTED_ROOT,
    verify_empty_projection,
    verify_seal_receipt,
)
from itda.pipeline.export_catalog_v2_audit import verify_catalog_v2_audit


class Phase2EvidenceError(ValueError):
    """Raised when any Phase 2 acceptance owner fails closed."""


SCHEMA_VERSION = "itda.phase-02-evidence-index.v1"
SOURCE_AUDIT_SCHEMA_VERSION = "itda.phase-02-source-audit.v1"
SOURCE_AUDIT_SUCCESSOR_SCHEMA_VERSION = "itda.phase-02-source-audit-successor.v2"
SOURCE_AUDIT_CLOSEOUT_SCHEMA_VERSION = "itda.phase-02-source-audit-closeout-successor.v3"
FINAL_VERIFICATION_MATRIX_V2_SCHEMA_VERSION = "itda.phase-02-verification-matrix.v2"
CLOSEOUT_EVIDENCE_SCHEMA_VERSION = "itda.phase-02-closeout-evidence-index.v3"
PLAN63_PROTECTED_SCHEMA_VERSION = "itda.phase-02-protected-manifest.v3"
PLAN64_PROTECTED_SCHEMA_VERSION = "itda.phase-02-protected-manifest.v4"
GRAMMAR_MIGRATION_COMMIT = "81d750e4df7a97207c7f70f948ae02a34f229e56"
PLAN62_CLOSEOUT_COMMIT = "bd1360af681fcff3939473d1e137bf3f72f9eab7"
PLAN62_ROADMAP_PARENT_SHA256 = "e6229b3a6a6032ef7793f03acccc9d724ceac9429ea6ddc4e8d2c6ab76ff6853"
PLAN62_ROADMAP_POST_SHA256 = "feb4d710afe4b19d21dda39999f15b9d3537432fb7228623862fa9f9bf47ac6f"
PREDECESSOR_SOURCE_AUDIT_FILE_SHA256 = (
    "2e20738995d0b4a29320fe880422667fde7fc8a6f1ba4e50e8ecb2330dfe1f8f"
)
PREDECESSOR_EVIDENCE_INDEX_FILE_SHA256 = (
    "ebecfde974980a26f3e3e6c9eb08ab75a4830e4c472f6f63746687f258d74361"
)
SOURCE_AUDIT_SUCCESSOR_RELATIVE = Path(
    "artifacts/restricted/catalog/v2/release/phase-02-source-audit-v2.json"
)
SOURCE_AUDIT_CLOSEOUT_RELATIVE = Path(
    "artifacts/restricted/catalog/v2/release/phase-02-source-audit-v3.json"
)
PREDECESSOR_SOURCE_AUDIT_RELATIVE = Path(
    "artifacts/restricted/catalog/v2/release/phase-02-source-audit.json"
)
PREDECESSOR_EVIDENCE_INDEX_RELATIVE = Path(
    "artifacts/restricted/catalog/v2/release/phase-02-evidence-index.json"
)
QUICK_GRAMMAR_SUMMARY_RELATIVE = Path(
    ".planning/quick/260803-241-repair-phase-2-mvp-user-story-grammar-on/260803-241-SUMMARY.md"
)
CURRENT_EVIDENCE_SCHEMA_VERSION = "itda.phase-02-current-evidence-index.v2"
VERIFICATION_MATRIX_SCHEMA_VERSION = "itda.phase-02-verification-matrix.v1"
CURRENT_EVIDENCE_RELATIVE = Path(
    "artifacts/restricted/catalog/v2/release/phase-02-evidence-index-v2.json"
)
VERIFICATION_MATRIX_RELATIVE = Path(
    "artifacts/restricted/catalog/v2/release/phase-02-verification-matrix-v1.json"
)
FINAL_VERIFICATION_MATRIX_V2_RELATIVE = Path(
    "artifacts/restricted/catalog/v2/release/phase-02-verification-matrix-v2.json"
)
CLOSEOUT_EVIDENCE_RELATIVE = Path(
    "artifacts/restricted/catalog/v2/release/phase-02-evidence-index-v3.json"
)
LINEAGE_SUCCESSOR_RELATIVE = Path(
    "artifacts/restricted/catalog/v2/lineage/v1-immutability-manifest-v2.json"
)
RIGHTS_CURRENT_PARENT_RELATIVE = Path(
    "artifacts/restricted/catalog/v2/rights/rights-current-parent-attestation-v1.json"
)
ACTIVATION_CURRENT_PARENT_RELATIVE = Path(
    "artifacts/restricted/catalog/v2/activation/"
    "catalog-activation-current-parent-attestation-v1.json"
)
ACTIVATION_EVENT_RELATIVE = Path(
    "artifacts/restricted/catalog/v2/activation/catalog-activation-event.json"
)
NETWORK_DENIAL_POLICY = "(version 1)(allow default)(deny network*)"
ROADMAP_PRE_CLOSEOUT_SHA256 = "7d61fab17422bee880be9a1e39ca417039772a96d9a546b96f5a729088446e6e"
ACCEPTANCE_NOTE = "after explicit Phase 2 SQLite evidence acceptance"
PHASE_RELATIVE = Path(".planning/phases/02-canonical-36-rights-and-evaluation-manifest")
REQUIREMENTS_RELATIVE = Path(".planning/REQUIREMENTS.md")
SQLITE_SCHEMA_RELATIVE = Path("backend/schema/evaluation_manifest_v1")
SQLITE_ROOT_RELATIVE = Path(INITIALIZATION_RESTRICTED_ROOT)
SQLITE_SEAL_RECEIPT_NAME = "real-manifest-seal-receipt.json"
FINAL_AUDIT_RELATIVE = Path("artifacts/restricted/catalog/v2/release/final-audit")
LINEAGE_RELATIVE = Path("artifacts/restricted/catalog/v2/lineage")
GSD_TOOLS = Path("/Users/penggin/.codex/gsd-core/bin/gsd-tools.cjs")

PREDECESSOR_SOURCE_AUDIT_SUCCESSOR_FILE_SHA256 = (
    "56c292b414a452b72861ab38ed935ab1a8052ed9753b7e909556ce622e4263f1"
)
PREDECESSOR_CURRENT_EVIDENCE_FILE_SHA256 = (
    "56533f53c8445efbb0a8a819515f3149df17a9403328b30aa7179caec98e65c9"
)
PREDECESSOR_VERIFICATION_MATRIX_FILE_SHA256 = (
    "7471d0d212ba65b8e727ce46ee88a78ea55866266528c505568b9c86eb2a85c6"
)

TERMINAL_SEMANTIC_OWNER_IDS = (
    *(f"02-{ordinal:02d}" for ordinal in range(1, 19)),
    *(f"02-{ordinal:02d}" for ordinal in range(20, 29)),
    *(f"02-{ordinal:02d}" for ordinal in range(33, 38)),
    "02-41",
    "02-47",
    "02-48",
    *(f"02-{ordinal:02d}" for ordinal in range(51, 63)),
)
CLOSEOUT_MIGRATION_IDS = (
    *(f"D-{ordinal:02d}" for ordinal in range(1, 30)),
    *(f"REINF-{ordinal:02d}" for ordinal in range(1, 19)),
    *(f"DATA-{ordinal:02d}" for ordinal in range(1, 5)),
)

EXPECTED_PHASE2_GOAL = (
    "As a dataset operator, I want to collect and review three official provider sources "
    "into an approved canonical 36 and independently seal a real 24/12 evaluation split, "
    "so that the contest dataset is traceable, legally usable, and leakage-resistant."
)
EXPECTED_PHASE2_SUCCESS_CRITERIA = (
    "운영자는 세 원천 응답을 수집 시각·요청 조건·hash와 함께 재실행 가능한 snapshot으로 저장하고 좌표·설명·사진·운영·Odii 충실도 및 결측 사유가 담긴 감사표를 생성할 수 있다.",
    "운영자는 source ID를 근거가 있는 stable place ID로 연결하고, 연결을 재검수·rollback하며 장소·사진·대본 중복과 부모/자식·동시 노출 금지 그룹을 검증할 수 있다.",
    "비상업 공모전 데모·평가용 versioned profile은 공식 포털의 `이용허락범위 제한 없음` dataset-level 근거를 해당 공식 레코드에 적용하되, 더 좁은 제공자 제한이나 식별되지 않은 제3자 자산은 분석·UI·데모에서 제외하고 상업 운영 전에는 권리를 새로 검토한다.",
    "권리·중복·대표성 검수를 통과한 canonical 36이 먼저 확정된 뒤에만 실제 DEV-24/BLIND-12 manifest가 한 번 봉인되며, 운영 정보나 사진 결측은 `MISSING`·불확실성·경고·confidence 감소로 표시하되 사실을 만들거나 장소 전체를 직접 탈락시키지 않고, 저장된 hash로 변경 여부를 검증할 수 있다.",
    "canonical 36은 정확한 네 coverage-group quota와 feasibility attestation을 만족하고, DEV-24/BLIND-12는 frozen pre-model 세 축·completeness 허용오차와 lexicographic optimum proof를 만족하며, 최종 v2 JSON/Parquet/CSV/Markdown 감사와 역사 검증 동등성까지 재현된다.",
)
EXPECTED_DATA_REQUIREMENT_TEXT = (
    "운영자는 TourAPI·Odii·관광사진 원본 응답을 수집 시각, 요청 조건, 응답 해시와 함께 버전된 스냅샷으로 저장할 수 있다.",
    "운영자는 서로 다른 원천 ID를 stable canonical place ID에 근거와 함께 연결하고, 연결 결과를 되돌리거나 재검수할 수 있다.",
    "운영자는 좌표·설명·사진·운영 여부·Odii 보유 여부와 결측 사유를 포함한 경주 후보 데이터 감사표를 생성할 수 있다.",
    "운영자는 장소 중복, 부모·자식 관계, 동일 추천 목록 동시 노출 금지 그룹을 정의하고 검증할 수 있다.",
    "시스템은 각 텍스트·대본·사진 자산의 출처, 원문 URL, 저작자·촬영자, 라이선스 유형, 허용 가공·표시 규칙을 보존한다.",
    "시스템은 권리가 불명확하거나 표시·모델 분석에 사용할 수 없는 자산을 분석, 사용자 UI, 데모 내보내기에서 차단한다.",
    "운영자는 권리·충실도·중복·대표성 검수를 통과한 canonical 관광지 36개를 확정할 수 있다. 사진 결측이나 사진 자산의 권리 제한만으로 장소 전체를 탈락시키지 않으며, 해당 사진만 파생 경로에서 차단하고 매체 상태를 보존한다.",
    "운영자는 장소·사진·대본 중복 그룹을 고려해 24개 DEV와 12개 BLIND manifest를 한 번 봉인하고 해시로 무결성을 검증할 수 있다.",
)

FORBIDDEN_OUTPUT_FRAGMENTS = (
    ".sqlite3",
    "database_path",
    "database_uri",
    "file:",
    "dev_members",
    "blind_members",
    "ordered_place_ids",
    "member_rows",
    "per_member",
    "complement",
    "raw_token",
    "raw_nonce",
    "-journal",
    "-wal",
    "-shm",
)

ACTIVE_OWNER_NAMES = (
    "historical-verification-equivalence",
    "catalog-v1-completed-history",
    "catalog-adjudication-bundle",
    "approved-catalog-and-split",
    "sqlite-logical-schema-and-empty-proof",
    "sqlite-initialization-receipt",
    "sqlite-one-time-seal-receipt",
    "postgresql-supersession-history-only",
    "canonical-v2-final-audit",
)

SUMMARY_SHA256 = {
    "09": "6627d028095c228779132547ba7adf18fb752311213cd046f605f6b982614a42",
    "56": "b2158a97a9502cb47d664bd5c0d6607d19a18e7ae8efd992d4870209d88cf648",
    "57": "244969dcaaff3d40b9824b56eac379b8121611e66dd359db91888b169b061909",
    "58": "e8c0b5a00e1c6e8b097ee4c3b4bd8082d590e4ab00e1889b9dbe70c7d746837f",
    "59": "e797a456242746b2e39c8a46954e5b8c1a017b4f625cbe983de8b8f1670e9c48",
    "33": "8536f75aa6a267cfcc1fb1add022a5296d60d78023097ec2d7cea173b620dada",
}
PLAN09_ARTIFACT_SHA256 = {
    "historical-verification-equivalence.json": (
        "d612c5b46a4558b4abde037cd2ff0daa9553daa14b0f07721dd60481eab68bec"
    ),
    "historical-verification-evidence.json": (
        "930005f261b43c5fc60a758aaa38906f0efecfdf88f5ddc2cccc1365a096fea6"
    ),
    "v1-immutability-manifest.json": (
        "a03f8ff2ab29bb3789d5b01cf9f9ce0b114424d468fbe6af9f35de6190242c50"
    ),
}

POSTGRESQL_HISTORY: dict[str, dict[str, str]] = {
    "29": {
        "sha256": "1dc5d4c970c23dd49d9b52a867b7fb798f8fb89336209fb822007c54b028d29b",
        "blob": "2ec904cc0ae14a9a7da81a6aa2859a8330980b23",
        "successor": "56",
    },
    "30": {
        "sha256": "c0e4d7fd8fe91d4bacd2d1fec71a23e0d2c44b0fc4786649fa632220f327edb6",
        "blob": "b2480b410b485e2063a198162b7f9a2fe08a14be",
        "successor": "57",
    },
    "31": {
        "sha256": "263eb1d0fa992b58779524dcaa51c156b95556cb566710189550f4f9de8706af",
        "blob": "e2102f1b2e9271f4298466e0f23e14782495e5fe",
        "successor": "58",
    },
    "32": {
        "sha256": "174abf5087fb75e276d669a87cc466f2f7094f256bb3719631c9c3e0a48f9a1d",
        "blob": "40a595c1032dfac38d5c39a923aba2bcfdbf3837",
        "successor": "59",
    },
}
PARTIAL_PLAN_29_COMMITS = (
    "faa1f75115c37544475f29e77efbb743d9a0b097",
    "607bb0ea14e0c7b939da407e6813338c5fd62f5d",
    "cf8a63d774de9bd9e03749e4c1ddfe97bc81926a",
)


def canonical_json_bytes(payload: object) -> bytes:
    return canonical_json_payload(payload) + b"\n"


def canonical_json_payload(payload: object) -> bytes:
    return json.dumps(
        payload,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    ).encode("utf-8")


def _sha256_bytes(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def _sha256_path(path: Path) -> str:
    return _sha256_bytes(path.read_bytes())


def _git_blob(payload: bytes) -> str:
    return hashlib.sha1(  # noqa: S324 - Git blob identity, not security crypto.
        f"blob {len(payload)}\0".encode("ascii") + payload
    ).hexdigest()


def _without(payload: Mapping[str, object], field: str) -> dict[str, object]:
    return {key: value for key, value in payload.items() if key != field}


def _self_hash(payload: Mapping[str, object], field: str) -> str:
    return _sha256_bytes(canonical_json_bytes(_without(payload, field)))


def _load_canonical_mapping(
    path: Path,
    *,
    max_bytes: int = 16_000_000,
    trailing_newline: bool = True,
) -> dict[str, Any]:
    try:
        metadata = path.lstat()
    except FileNotFoundError as exc:
        raise Phase2EvidenceError("required evidence is missing") from exc
    if path.is_symlink() or not stat.S_ISREG(metadata.st_mode):
        raise Phase2EvidenceError("required evidence is not a regular file")
    if metadata.st_size > max_bytes:
        raise Phase2EvidenceError("required evidence exceeds its size bound")
    raw = path.read_bytes()
    try:
        value = json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise Phase2EvidenceError("required evidence is not canonical JSON") from exc
    expected = canonical_json_bytes(value) if trailing_newline else canonical_json_payload(value)
    if not isinstance(value, dict) or expected != raw:
        raise Phase2EvidenceError("required evidence is not canonical JSON")
    return cast(dict[str, Any], value)


def _assert_sanitized(payload: object) -> None:
    rendered = canonical_json_bytes(payload).decode("utf-8").casefold()
    for fragment in FORBIDDEN_OUTPUT_FRAGMENTS:
        if fragment in rendered:
            raise Phase2EvidenceError("sanitized evidence contains a forbidden capability")


def _artifact_self_hash(payload: Mapping[str, object], field: str) -> str:
    return _sha256_bytes(canonical_json_payload(_without(payload, field)))


def verify_summary_owner(path: Path, plan_id: str) -> dict[str, str]:
    """Verify one exact completed successor Summary."""

    try:
        raw = path.read_bytes()
    except FileNotFoundError as exc:
        raise Phase2EvidenceError("required successor Summary is missing") from exc
    expected_sha = SUMMARY_SHA256.get(plan_id)
    if expected_sha is None or _sha256_bytes(raw) != expected_sha:
        raise Phase2EvidenceError("successor Summary bytes drifted")
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise Phase2EvidenceError("successor Summary is not UTF-8") from exc
    frontmatter = text.split("---", 2)
    if len(frontmatter) < 3:
        raise Phase2EvidenceError("successor Summary frontmatter is missing")
    if not re.search(rf'^plan:\s*["\']?{re.escape(plan_id)}["\']?\s*$', frontmatter[1], re.M):
        raise Phase2EvidenceError("successor Summary plan binding drifted")
    if not re.search(r"^status:\s*complete\s*$", frontmatter[1], re.M):
        raise Phase2EvidenceError("successor Summary is not complete")
    return {"plan": plan_id, "sha256": expected_sha, "status": "PASS"}


def _run_rtk_json(repo_root: Path, *arguments: str) -> dict[str, Any]:
    completed = subprocess.run(
        ["rtk", "proxy", "node", str(GSD_TOOLS), "query", *arguments],
        cwd=repo_root,
        check=True,
        capture_output=True,
        text=True,
    )
    try:
        value = json.loads(completed.stdout)
    except json.JSONDecodeError as exc:
        raise Phase2EvidenceError("GSD discovery output is invalid") from exc
    if not isinstance(value, dict):
        raise Phase2EvidenceError("GSD discovery output is invalid")
    return cast(dict[str, Any], value)


def _verify_history_discovery(repo_root: Path) -> None:
    init = _run_rtk_json(repo_root, "init.execute-phase", "02")
    index = _run_rtk_json(repo_root, "phase-plan-index", "02")
    plans = init.get("plans")
    waves = index.get("waves")
    if not isinstance(plans, list) or not isinstance(waves, dict):
        raise Phase2EvidenceError("GSD discovery shape drifted")
    forbidden = {f"02-{plan_id}-PLAN.md" for plan_id in POSTGRESQL_HISTORY}
    if forbidden.intersection(cast(list[str], plans)):
        raise Phase2EvidenceError("superseded PostgreSQL plan became executable")
    if waves.get("38") != ["02-56"]:
        raise Phase2EvidenceError("SQLite successor discovery boundary drifted")


def verify_sqlite_supersession_history(
    repo_root: Path,
    *,
    phase_dir: Path | None = None,
    verify_discovery: bool = True,
    verify_commits: bool = True,
) -> dict[str, object]:
    """Verify exact PostgreSQL history without claiming SQLite equivalence."""

    root = repo_root.resolve(strict=True)
    phase = phase_dir or (root / PHASE_RELATIVE)
    rows: list[dict[str, object]] = []
    for plan_id, expected in POSTGRESQL_HISTORY.items():
        executable = phase / f"02-{plan_id}-PLAN.md"
        summary = phase / f"02-{plan_id}-SUMMARY.md"
        history = phase / f"02-{plan_id}-POSTGRESQL-HISTORY.md"
        pointer = phase / f"02-{plan_id}-SUPERSEDED.md"
        if executable.exists() or executable.is_symlink():
            raise Phase2EvidenceError("superseded PostgreSQL plan became executable")
        if summary.exists() or summary.is_symlink():
            raise Phase2EvidenceError("superseded PostgreSQL Summary was fabricated")
        try:
            history_bytes = history.read_bytes()
            pointer_text = pointer.read_text(encoding="utf-8")
        except (FileNotFoundError, UnicodeDecodeError) as exc:
            raise Phase2EvidenceError("supersession history is missing or invalid") from exc
        if _sha256_bytes(history_bytes) != expected["sha256"]:
            raise Phase2EvidenceError("supersession history bytes drifted")
        if _git_blob(history_bytes) != expected["blob"]:
            raise Phase2EvidenceError("supersession history Git blob drifted")
        required_pointer_values = (
            f"02-{plan_id}-PLAN.md",
            f"02-{plan_id}-POSTGRESQL-HISTORY.md",
            expected["sha256"],
            expected["blob"],
            f"02-{expected['successor']}-PLAN.md",
            "Summary exists",
            "`false`",
            "Reason:",
        )
        if not all(value in pointer_text for value in required_pointer_values):
            raise Phase2EvidenceError("supersession pointer binding drifted")
        rows.append(
            {
                "plan": plan_id,
                "sha256": expected["sha256"],
                "git_blob": expected["blob"],
                "successor": expected["successor"],
                "executable_absent": True,
                "summary_absent": True,
                "status": "SUPERSEDED",
            }
        )
    if verify_commits:
        for commit in PARTIAL_PLAN_29_COMMITS:
            subprocess.run(
                ["rtk", "git", "cat-file", "-e", f"{commit}^{{commit}}"],
                cwd=root,
                check=True,
                capture_output=True,
            )
    if verify_discovery:
        _verify_history_discovery(root)
    result: dict[str, object] = {
        "status": "PASS",
        "history_records": rows,
        "reachable_partial_commits": list(PARTIAL_PLAN_29_COMMITS),
        "postgresql_equivalence_claimed": False,
    }
    _assert_sanitized(result)
    return result


def _sqlite_paths(root: Path, authority_root: Path) -> dict[str, Path]:
    return {
        "schema_dir": root / SQLITE_SCHEMA_RELATIVE,
        "initialization_receipt": authority_root / "initialization-receipt.json",
        "initialization_state": authority_root / "initialization-state-attestation.json",
        "initialization_issuance": authority_root / "initialization-issuance-context.json",
        "initialization_request": root
        / "artifacts/public/catalog/v2/sqlite-initialization-request.json",
        "split_approval": root / "artifacts/restricted/catalog/v2/split/real-split-approval.json",
        "materialized_bundle": root
        / "artifacts/restricted/catalog/v2/split/real-split-materialization-bundle.json",
        "seal_state": authority_root / "seal-state-attestation.json",
        "seal_issuance": authority_root / "seal-issuance-context.json",
        "seal_request": root / "artifacts/public/catalog/v2/sqlite-real-manifest-seal-request.json",
    }


def verify_sqlite_successor(
    repo_root: Path,
    *,
    receipt_path: Path,
    authority_root: Path,
) -> dict[str, object]:
    """Verify live SQLite authority and return only hashes, counts, and statuses."""

    root = repo_root.resolve(strict=True)
    expected_root = (root / SQLITE_ROOT_RELATIVE).resolve(strict=True)
    if authority_root.resolve(strict=True) != expected_root:
        raise Phase2EvidenceError("SQLite authority root is not exact")
    expected_receipt = expected_root / SQLITE_SEAL_RECEIPT_NAME
    if receipt_path.resolve(strict=True) != expected_receipt:
        raise Phase2EvidenceError("SQLite seal receipt is not exact")
    paths = _sqlite_paths(root, expected_root)
    proof = verify_empty_projection(paths["schema_dir"], as_of=date.today())
    initialization = _load_canonical_mapping(
        paths["initialization_receipt"], trailing_newline=False
    )
    initialization_metadata = paths["initialization_receipt"].lstat()
    if (
        stat.S_IMODE(initialization_metadata.st_mode) != 0o600
        or initialization_metadata.st_nlink != 1
        or initialization.get("receipt_sha256")
        != _artifact_self_hash(initialization, "receipt_sha256")
        or initialization.get("empty_counts")
        != {"authority_consumptions": 0, "manifest_members": 0, "manifest_seals": 0}
        or initialization.get("integrity_check") != "ok"
        or initialization.get("foreign_key_check_count") != 0
        or set(cast(dict[str, object], initialization.get("sidecars", {})).values())
        not in ({False}, {"ABSENT"})
    ):
        raise Phase2EvidenceError("SQLite initialization receipt drifted")
    seal = verify_seal_receipt(
        repo_root=root,
        schema_dir=paths["schema_dir"],
        receipt_path=paths["initialization_receipt"],
        materialized_bundle_path=paths["materialized_bundle"],
        split_approval_path=paths["split_approval"],
        state_path=paths["seal_state"],
        issuance_context_path=paths["seal_issuance"],
        request_path=paths["seal_request"],
        seal_receipt_path=receipt_path,
    )
    if seal.counts != {"blind": 12, "dev": 24, "total": 36}:
        raise Phase2EvidenceError("SQLite aggregate counts are not exact")
    if set(seal.sidecars.values()) != {False}:
        raise Phase2EvidenceError("SQLite sidecar state is not clean")
    if seal.integrity_check != "ok" or seal.foreign_key_check_count != 0:
        raise Phase2EvidenceError("SQLite integrity checks failed")
    if seal.database_mode != "0600" or seal.database_link_count != 1:
        raise Phase2EvidenceError("SQLite protected file mode or link count drifted")
    if seal.no_follow_result != "LSTAT_OPEN_FSTAT_MATCH":
        raise Phase2EvidenceError("SQLite no-follow identity proof drifted")
    initialization_file_sha256 = _sha256_path(paths["initialization_receipt"])
    if seal.initialization_receipt_sha256 != initialization_file_sha256:
        raise Phase2EvidenceError("SQLite initialization-to-seal binding drifted")
    summary_rows = [
        verify_summary_owner(root / PHASE_RELATIVE / f"02-{plan_id}-SUMMARY.md", plan_id)
        for plan_id in ("56", "57", "58", "59", "33")
    ]
    result: dict[str, object] = {
        "status": "PASS",
        "successor_summaries": summary_rows,
        "ddl_sha256": seal.ddl_sha256,
        "logical_schema_manifest_sha256": seal.logical_schema_manifest_sha256,
        "logical_schema_sha256": seal.logical_schema_sha256,
        "tracked_empty_file_sha256": proof.empty_file_sha256,
        "empty_proof_sha256": proof.proof_sha256,
        "initialization_receipt_sha256": initialization_file_sha256,
        "initialization_self_sha256": initialization["receipt_sha256"],
        "sqlite_receipt_sha256": seal.receipt_sha256,
        "logical_seal_sha256": seal.logical_seal_sha256,
        "database_sha256": seal.database_sha256,
        "counts": {"development": 24, "held_out": 12, "total": 36},
        "database_mode": seal.database_mode,
        "database_link_count": seal.database_link_count,
        "no_follow_result": seal.no_follow_result,
        "integrity_check": seal.integrity_check,
        "foreign_key_check_count": seal.foreign_key_check_count,
        "sidecars_absent": True,
        "same_uid_root_residual": "OUTSIDE_CONTEST_LOCAL_CLAIM",
        "postgresql_runtime_preserved": True,
        "postgresql_equivalence_claimed": False,
    }
    _assert_sanitized(result)
    return result


def _requirements_state(raw: bytes) -> dict[str, list[str]]:
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise Phase2EvidenceError("REQUIREMENTS is not UTF-8") from exc
    completed: list[str] = []
    pending: list[str] = []
    for ordinal in range(1, 9):
        requirement_id = f"DATA-{ordinal:02d}"
        checkbox = re.findall(rf"^- \[([ x])\] \*\*{requirement_id}\*\*:", text, re.M)
        trace = re.findall(
            rf"^\| {requirement_id} \| Phase 2 \| (Complete|Pending) \|$", text, re.M
        )
        if len(checkbox) != 1 or len(trace) != 1:
            raise Phase2EvidenceError("DATA requirement state is malformed")
        if checkbox[0] == "x" and trace[0] == "Complete":
            completed.append(requirement_id)
        elif checkbox[0] == " " and trace[0] == "Pending":
            pending.append(requirement_id)
        else:
            raise Phase2EvidenceError("DATA requirement state is inconsistent")
    return {"completed": completed, "pending": pending}


def _strict_utc_timestamp(value: datetime) -> str:
    if value.tzinfo is None or value.utcoffset() is None:
        raise Phase2EvidenceError("acceptance clock must be timezone-aware")
    normalized = value.astimezone(UTC).replace(microsecond=0)
    return normalized.isoformat().replace("+00:00", "Z")


def _last_updated_line(text: str) -> str:
    matches = re.findall(r"^\*Last updated: .+\*$", text, re.M)
    if len(matches) != 1:
        raise Phase2EvidenceError("REQUIREMENTS Last updated line is not unique")
    return cast(str, matches[0])


def _apply_replacements(raw: bytes, replacements: Sequence[Mapping[str, str]]) -> bytes:
    result = raw
    for replacement in replacements:
        before = replacement.get("before")
        after = replacement.get("after")
        if not isinstance(before, str) or not isinstance(after, str):
            raise Phase2EvidenceError("requirements replacement is malformed")
        before_bytes = before.encode("utf-8")
        if result.count(before_bytes) != 1:
            raise Phase2EvidenceError("requirements replacement preimage is not unique")
        result = result.replace(before_bytes, after.encode("utf-8"), 1)
    return result


def build_requirements_transition(
    raw: bytes,
    *,
    clock: Callable[[], datetime] = lambda: datetime.now(UTC),
) -> dict[str, object]:
    """Bind one UTC timestamp and the exact DATA-08 three-replacement postimage."""

    state = _requirements_state(raw)
    if state != {
        "completed": [f"DATA-{ordinal:02d}" for ordinal in range(1, 8)],
        "pending": ["DATA-08"],
    }:
        raise Phase2EvidenceError("REQUIREMENTS is not at the exact pre-acceptance state")
    timestamp = _strict_utc_timestamp(clock())
    text = raw.decode("utf-8")
    old_last_updated = _last_updated_line(text)
    new_last_updated = f"*Last updated: {timestamp[:10]} {ACCEPTANCE_NOTE}*"
    replacements = [
        {
            "kind": "DATA-08-checkbox",
            "before": "- [ ] **DATA-08**:",
            "after": "- [x] **DATA-08**:",
        },
        {
            "kind": "DATA-08-traceability",
            "before": "| DATA-08 | Phase 2 | Pending |",
            "after": "| DATA-08 | Phase 2 | Complete |",
        },
        {
            "kind": "last-updated",
            "before": old_last_updated,
            "after": new_last_updated,
        },
    ]
    postimage = _apply_replacements(raw, replacements)
    if _requirements_state(postimage) != {
        "completed": [f"DATA-{ordinal:02d}" for ordinal in range(1, 9)],
        "pending": [],
    }:
        raise Phase2EvidenceError("predicted REQUIREMENTS postimage is not exact")
    return {
        "acceptance_timestamp": timestamp,
        "acceptance_note": ACCEPTANCE_NOTE,
        "preimage_sha256": _sha256_bytes(raw),
        "original_last_updated_line": old_last_updated,
        "replacement_allowlist": replacements,
        "replacement_count": 3,
        "changed_requirement_ids": ["DATA-08"],
        "predicted_postimage_sha256": _sha256_bytes(postimage),
    }


def _validate_transition_shape(transition: Mapping[str, object]) -> None:
    if transition.get("acceptance_note") != ACCEPTANCE_NOTE:
        raise Phase2EvidenceError("acceptance note drifted")
    timestamp = transition.get("acceptance_timestamp")
    if not isinstance(timestamp, str) or not re.fullmatch(
        r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z", timestamp
    ):
        raise Phase2EvidenceError("acceptance timestamp is not strict UTC")
    if transition.get("replacement_count") != 3:
        raise Phase2EvidenceError("requirements replacement count drifted")
    if transition.get("changed_requirement_ids") != ["DATA-08"]:
        raise Phase2EvidenceError("requirements changed-ID allowlist drifted")
    replacements = transition.get("replacement_allowlist")
    if not isinstance(replacements, list) or len(replacements) != 3:
        raise Phase2EvidenceError("requirements replacement allowlist drifted")
    kinds = [item.get("kind") for item in replacements if isinstance(item, dict)]
    if kinds != ["DATA-08-checkbox", "DATA-08-traceability", "last-updated"]:
        raise Phase2EvidenceError("requirements replacement kinds drifted")


def apply_transition_to_bytes(raw: bytes, transition: Mapping[str, object]) -> bytes:
    """Construct the exact predicted postimage without touching the file."""

    _validate_transition_shape(transition)
    if _sha256_bytes(raw) != transition.get("preimage_sha256"):
        raise Phase2EvidenceError("REQUIREMENTS preimage hash drifted")
    replacements = cast(list[Mapping[str, str]], transition["replacement_allowlist"])
    postimage = _apply_replacements(raw, replacements)
    if _sha256_bytes(postimage) != transition.get("predicted_postimage_sha256"):
        raise Phase2EvidenceError("REQUIREMENTS predicted postimage hash drifted")
    return postimage


def _verify_plan09_owners(root: Path) -> dict[str, object]:
    mapping_path = root / LINEAGE_RELATIVE / "historical-verification-equivalence.json"
    evidence_path = root / LINEAGE_RELATIVE / "historical-verification-evidence.json"
    manifest_path = root / IMMUTABILITY_PATH
    for path in (mapping_path, evidence_path, manifest_path):
        if _sha256_path(path) != PLAN09_ARTIFACT_SHA256[path.name]:
            raise Phase2EvidenceError("Plan 09 immutable artifact drifted")
    verify_summary_owner(root / PHASE_RELATIVE / "02-09-SUMMARY.md", "09")
    try:
        mapping = verify_equivalence(root, mapping_path, evidence_path)
    except FingerprintError as exc:
        if "live recomputation" not in str(exc):
            raise
        mapping = _load_canonical_mapping(mapping_path, trailing_newline=False)
    manifest = _load_canonical_mapping(manifest_path, trailing_newline=False)
    return {
        "status": "PASS",
        "mapping_sha256": _sha256_path(mapping_path),
        "evidence_sha256": _sha256_path(evidence_path),
        "immutability_manifest_sha256": _sha256_path(root / IMMUTABILITY_PATH),
        "replacement_count": len(cast(list[object], mapping["rows"])),
        "catalog_tree_sha256": manifest["catalog_v1"]["tree_sha256"],
        "planning_history_tree_sha256": manifest["planning_history"]["tree_sha256"],
    }


def _adjudication_bundle(root: Path) -> dict[str, object]:
    summary = (root / PHASE_RELATIVE / "02-20-SUMMARY.md").read_text(encoding="utf-8")
    matched = re.search(r"^catalog_adjudication_bundle_path:\s*(\S+)\s*$", summary, re.M)
    if matched is None:
        raise Phase2EvidenceError("Plan 20 adjudication bundle pointer is missing")
    manifest_path = root / matched.group(1)
    result = verify_adjudication_bundle(manifest_path, repository_root=root)
    bundle_root = result.get("bundle_root_sha256")
    if not isinstance(bundle_root, str) or len(bundle_root) != 64:
        raise Phase2EvidenceError("Plan 20 adjudication bundle root is invalid")
    return {
        "status": "PASS",
        "bundle_root_sha256": bundle_root,
        "bundle_manifest_sha256": _sha256_path(manifest_path),
    }


def _final_audit(root: Path, receipt_path: Path) -> dict[str, object]:
    result = verify_catalog_v2_audit(
        root / FINAL_AUDIT_RELATIVE,
        repository_root=root,
        sqlite_seal_receipt=receipt_path,
    )
    return {
        "status": "PASS",
        "manifest_sha256": result.manifest_sha256,
        "row_count": result.row_count,
        "file_hashes": dict(sorted(result.file_hashes.items())),
    }


def _owner_records(root: Path, receipt_path: Path) -> list[dict[str, object]]:
    return [
        {"owner": "plan-09-history", **_verify_plan09_owners(root)},
        {"owner": "plan-20-adjudication", **_adjudication_bundle(root)},
        {"owner": "plan-33-final-audit", **_final_audit(root, receipt_path)},
    ]


def _write_no_replace(path: Path, payload: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor = os.open(
        path,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0),
        0o600,
    )
    try:
        view = memoryview(payload)
        while view:
            written = os.write(descriptor, view)
            if written <= 0:
                raise OSError("short write")
            view = view[written:]
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def build_evidence_index(
    repo_root: Path,
    output_path: Path,
    *,
    receipt_path: Path,
    authority_root: Path,
    clock: Callable[[], datetime] = lambda: datetime.now(UTC),
) -> dict[str, object]:
    """Freshly verify every owner and publish one immutable evidence index."""

    root = repo_root.resolve(strict=True)
    requirements_raw = (root / REQUIREMENTS_RELATIVE).read_bytes()
    transition = build_requirements_transition(requirements_raw, clock=clock)
    sqlite = verify_sqlite_successor(root, receipt_path=receipt_path, authority_root=authority_root)
    history = verify_sqlite_supersession_history(root)
    owners = _owner_records(root, receipt_path)
    payload: dict[str, object] = {
        "schema_version": SCHEMA_VERSION,
        "status": "PASS",
        "active_owner_names": list(ACTIVE_OWNER_NAMES),
        "requirements_state": _requirements_state(requirements_raw),
        "requirements_transition": transition,
        "sqlite_successor": sqlite,
        "postgresql_history": history,
        "current_owners": owners,
        "evidence_index_sha256": "",
    }
    _assert_sanitized(payload)
    payload["evidence_index_sha256"] = _self_hash(payload, "evidence_index_sha256")
    _write_no_replace(output_path, canonical_json_bytes(payload))
    return payload


def _verify_live_requirements_against_transition(
    root: Path, transition: Mapping[str, object]
) -> None:
    raw = (root / REQUIREMENTS_RELATIVE).read_bytes()
    live_sha = _sha256_bytes(raw)
    if live_sha == transition.get("preimage_sha256"):
        if _requirements_state(raw)["pending"] != ["DATA-08"]:
            raise Phase2EvidenceError("live pre-acceptance state is inconsistent")
        return
    if live_sha == transition.get("predicted_postimage_sha256"):
        if _requirements_state(raw)["completed"] != [
            f"DATA-{ordinal:02d}" for ordinal in range(1, 9)
        ]:
            raise Phase2EvidenceError("live post-acceptance state is inconsistent")
        return
    raise Phase2EvidenceError("live REQUIREMENTS is neither bound preimage nor postimage")


def verify_evidence_index(repo_root: Path, index_path: Path) -> dict[str, object]:
    """Verify immutable index bytes plus all live current owners."""

    root = repo_root.resolve(strict=True)
    payload = _load_canonical_mapping(index_path)
    if payload.get("schema_version") != SCHEMA_VERSION or payload.get("status") != "PASS":
        raise Phase2EvidenceError("evidence index schema or status drifted")
    if payload.get("active_owner_names") != list(ACTIVE_OWNER_NAMES):
        raise Phase2EvidenceError("active evidence owner registry drifted")
    if payload.get("evidence_index_sha256") != _self_hash(payload, "evidence_index_sha256"):
        raise Phase2EvidenceError("evidence index self hash drifted")
    transition = payload.get("requirements_transition")
    if not isinstance(transition, dict):
        raise Phase2EvidenceError("requirements transition is missing")
    _validate_transition_shape(transition)
    _verify_live_requirements_against_transition(root, transition)

    expected_root = root / SQLITE_ROOT_RELATIVE
    expected_receipt = expected_root / SQLITE_SEAL_RECEIPT_NAME
    if payload.get("sqlite_successor") != verify_sqlite_successor(
        root,
        receipt_path=expected_receipt,
        authority_root=expected_root,
    ):
        raise Phase2EvidenceError("SQLite successor evidence drifted")
    if payload.get("postgresql_history") != verify_sqlite_supersession_history(root):
        raise Phase2EvidenceError("PostgreSQL supersession evidence drifted")
    if payload.get("current_owners") != _owner_records(root, expected_receipt):
        raise Phase2EvidenceError("current owner evidence drifted")
    _assert_sanitized(payload)
    return cast(dict[str, object], payload)


SOURCE_DOCUMENTS = {
    "goal": Path(".planning/ROADMAP.md"),
    "requirements": REQUIREMENTS_RELATIVE,
    "context": PHASE_RELATIVE / "02-CONTEXT.md",
    "research": PHASE_RELATIVE / "02-RESEARCH.md",
    "remediation_research": PHASE_RELATIVE / "02-REMEDIATION-RESEARCH.md",
    "discovery_research": PHASE_RELATIVE / "02-DISCOVERY-RESEARCH.md",
    "sqlite_transition_research": PHASE_RELATIVE / "02-SQLITE-TRANSITION-RESEARCH.md",
}

SQLITE_RESEARCH_ANCHORS = (
    ("SQLITE-01", "isolated stdlib `sqlite3` authority module"),
    ("SQLITE-02", "canonical logical schema is authoritative"),
    ("SQLITE-03", "provably empty SQLite file is a convenience projection"),
    ("SQLITE-04", "Restricted DB initialization"),
    ("SQLITE-05", "four-plan SQLite successor chain using `journal_mode=DELETE`"),
    ("SQLITE-06", "no-follow/file-identity checks"),
    ("SQLITE-07", "Sidecar Rules"),
    ("SQLITE-08", "Execute `BEGIN IMMEDIATE`"),
    ("SQLITE-09", "restricted sanitized receipt"),
    ("SQLITE-10", "exact-byte history-file pattern"),
    ("SQLITE-11", "same-UID malicious code and root remain outside"),
)

SQLITE_DECISION_OWNERS: dict[str, tuple[tuple[str, ...], tuple[str, ...]]] = {
    "D-30": (
        ("02-56", "02-57", "02-58", "02-59", "02-33", "02-34"),
        (
            "sqlite-logical-schema-and-empty-proof",
            "postgresql-supersession-history-only",
            "sqlite-one-time-seal-receipt",
            "postgresql-runtime-preserved",
            "no-postgresql-equivalence",
            "same-uid-root-residual",
        ),
    ),
    "D-31": (
        ("02-56",),
        ("sqlite-logical-schema-and-empty-proof", "tracked-empty-projection-only"),
    ),
    "D-32": (
        ("02-56", "02-34"),
        (
            "postgresql-supersession-history-only",
            "exact-byte-pointers-and-commits",
            "no-postgresql-equivalence",
        ),
    ),
    "D-33": (
        ("02-57", "02-58", "02-59"),
        (
            "two-human-authority-checkpoints",
            "sqlite-initialization-receipt",
            "begin-immediate-one-time-seal",
            "sqlite-one-time-seal-receipt",
        ),
    ),
    "D-34": (
        ("02-56", "02-57", "02-58", "02-59", "02-33", "02-34"),
        (
            "restricted-untracked-membership-and-sidecars",
            "sanitized-export-hashes-and-counts-only",
            "no-postgresql-equivalence",
            "same-uid-root-residual",
        ),
    ),
}


def _unique_source_line(text: str, needle: str) -> str:
    matches = [line for line in text.splitlines() if needle in line]
    if len(matches) != 1:
        raise Phase2EvidenceError("source audit anchor is missing or ambiguous")
    return matches[0]


def _source_row(
    source: str,
    identifier: str,
    feature: str,
    plan_owners: Sequence[str],
    evidence_owners: Sequence[str],
    *,
    status: str = "COVERED",
) -> dict[str, object]:
    return {
        "source": source,
        "id": identifier,
        "feature_sha256": _sha256_bytes(feature.encode("utf-8")),
        "plan_owners": list(plan_owners),
        "evidence_owners": list(evidence_owners),
        "status": status,
    }


def _completed_summary_owners(root: Path, identifier: str) -> list[str]:
    owners: list[str] = []
    pattern = re.compile(rf"(?<![A-Z0-9-]){re.escape(identifier)}(?!\d)")
    for path in sorted((root / PHASE_RELATIVE).glob("02-??-PLAN.md")):
        plan_id = path.name[3:5]
        if plan_id == "34":
            continue
        summary = path.with_name(f"02-{plan_id}-SUMMARY.md")
        if not summary.exists():
            continue
        if pattern.search(path.read_text(encoding="utf-8")):
            owners.append(f"02-{plan_id}")
    if not owners:
        raise Phase2EvidenceError("source audit feature has no completed plan owner")
    return owners


def _requirements_preimage(root: Path, transition: Mapping[str, object]) -> tuple[bytes, str]:
    raw = (root / REQUIREMENTS_RELATIVE).read_bytes()
    live_sha = _sha256_bytes(raw)
    if live_sha == transition.get("preimage_sha256"):
        return raw, live_sha
    if live_sha != transition.get("predicted_postimage_sha256"):
        raise Phase2EvidenceError("REQUIREMENTS is outside the evidence-bound transition")
    replacements = cast(list[Mapping[str, str]], transition["replacement_allowlist"])
    reverse = [
        {"before": replacement["after"], "after": replacement["before"]}
        for replacement in reversed(replacements)
    ]
    preimage = _apply_replacements(raw, reverse)
    preimage_sha = _sha256_bytes(preimage)
    if preimage_sha != transition.get("preimage_sha256"):
        raise Phase2EvidenceError("REQUIREMENTS postimage cannot recover its preimage")
    return preimage, preimage_sha


def _expected_source_rows(root: Path, requirements_raw: bytes) -> list[dict[str, object]]:
    roadmap = (root / SOURCE_DOCUMENTS["goal"]).read_text(encoding="utf-8")
    requirements = requirements_raw.decode("utf-8")
    context = (root / SOURCE_DOCUMENTS["context"]).read_text(encoding="utf-8")
    sqlite_research = (root / SOURCE_DOCUMENTS["sqlite_transition_research"]).read_text(
        encoding="utf-8"
    )
    rows: list[dict[str, object]] = []

    goal = _unique_source_line(
        roadmap,
        "approved canonical 36 and independently seal a real 24/12 evaluation split",
    )
    rows.append(
        _source_row(
            "GOAL",
            "PHASE-02-GOAL",
            goal,
            ("02-20", "02-56", "02-57", "02-58", "02-59", "02-33", "02-34"),
            (
                "approved-catalog-and-split",
                "sqlite-one-time-seal-receipt",
                "canonical-v2-final-audit",
                "phase-02-final-acceptance",
            ),
        )
    )

    for ordinal in range(1, 9):
        identifier = f"DATA-{ordinal:02d}"
        feature = _unique_source_line(requirements, f"**{identifier}**")
        if identifier == "DATA-08":
            plan_owners = ["02-56", "02-57", "02-58", "02-59", "02-34"]
            evidence_owners = [
                "sqlite-logical-schema-and-empty-proof",
                "sqlite-initialization-receipt",
                "sqlite-one-time-seal-receipt",
                "phase-02-final-acceptance",
            ]
        else:
            plan_owners = _completed_summary_owners(root, identifier)
            evidence_owners = ["completed-phase-02-owner", "phase-02-evidence-index"]
        rows.append(_source_row("REQ", identifier, feature, plan_owners, evidence_owners))

    for identifier, anchor in SQLITE_RESEARCH_ANCHORS:
        feature = _unique_source_line(sqlite_research, anchor)
        rows.append(
            _source_row(
                "RESEARCH",
                identifier,
                feature,
                ("02-56", "02-57", "02-58", "02-59", "02-34"),
                (
                    "sqlite-logical-schema-and-empty-proof",
                    "sqlite-initialization-receipt",
                    "sqlite-one-time-seal-receipt",
                    "postgresql-supersession-history-only",
                ),
            )
        )

    for ordinal in range(1, 35):
        identifier = f"D-{ordinal:02d}"
        feature = _unique_source_line(context, f"**{identifier}")
        if identifier in SQLITE_DECISION_OWNERS:
            decision_plan_owners, decision_evidence_owners = SQLITE_DECISION_OWNERS[identifier]
        else:
            decision_plan_owners = tuple(_completed_summary_owners(root, identifier))
            decision_evidence_owners = (
                "completed-phase-02-owner",
                "phase-02-evidence-index",
            )
        rows.append(
            _source_row(
                "CONTEXT",
                identifier,
                feature,
                decision_plan_owners,
                decision_evidence_owners,
            )
        )

    for ordinal in range(1, 19):
        identifier = f"REINF-{ordinal:02d}"
        if ordinal <= 11:
            feature = _unique_source_line(context, f"**D-{ordinal:02d}")
            reinforcement_plan_owners = _completed_summary_owners(root, f"D-{ordinal:02d}")
        else:
            feature = _unique_source_line(context, f"### {identifier}")
            reinforcement_plan_owners = _completed_summary_owners(root, identifier)
        rows.append(
            _source_row(
                "CONTEXT",
                identifier,
                feature,
                reinforcement_plan_owners,
                ("completed-phase-02-owner", "phase-02-evidence-index"),
            )
        )

    deferred = context.split("<deferred>", 1)[1].split("</deferred>", 1)[0]
    deferred_features = [line for line in deferred.splitlines() if line.startswith("- ")]
    if len(deferred_features) != 4:
        raise Phase2EvidenceError("deferred source inventory drifted")
    for ordinal, feature in enumerate(deferred_features, start=1):
        phase_match = re.search(r"Phase [345]", feature)
        if phase_match is None:
            raise Phase2EvidenceError("deferred source phase owner is missing")
        phase_name = phase_match.group(0)
        rows.append(
            _source_row(
                "CONTEXT",
                f"DEFERRED-{ordinal:02d}",
                feature,
                (phase_name.replace(" ", "-"),),
                ("outside-phase-02",),
                status="EXCLUDED",
            )
        )
    return sorted(rows, key=lambda row: (str(row["source"]), str(row["id"])))


def _expected_source_audit(root: Path, evidence_index_path: Path) -> dict[str, object]:
    index = verify_evidence_index(root, evidence_index_path)
    transition = cast(Mapping[str, object], index["requirements_transition"])
    requirements_raw, requirements_preimage_sha = _requirements_preimage(root, transition)
    rows = _expected_source_rows(root, requirements_raw)
    source_counts = {
        source: sum(row["source"] == source for row in rows)
        for source in ("CONTEXT", "GOAL", "REQ", "RESEARCH")
    }
    source_hashes = {
        name: (
            requirements_preimage_sha if name == "requirements" else _sha256_path(root / relative)
        )
        for name, relative in sorted(SOURCE_DOCUMENTS.items())
    }
    payload: dict[str, object] = {
        "schema_version": SOURCE_AUDIT_SCHEMA_VERSION,
        "status": "PASS",
        "evidence_index_sha256": _sha256_path(evidence_index_path),
        "source_hashes": source_hashes,
        "source_counts": source_counts,
        "status_counts": {
            "COVERED": sum(row["status"] == "COVERED" for row in rows),
            "EXCLUDED": sum(row["status"] == "EXCLUDED" for row in rows),
            "MISSING": 0,
        },
        "reopened_executable_plans": [],
        "rows": rows,
    }
    payload["source_audit_sha256"] = _self_hash(payload, "source_audit_sha256")
    _assert_sanitized(payload)
    return payload


def build_source_audit(
    repo_root: Path, output_path: Path, evidence_index_path: Path
) -> dict[str, object]:
    """Build the exact four-source audit once without replacing prior evidence."""

    root = repo_root.resolve(strict=True)
    payload = _expected_source_audit(root, evidence_index_path)
    _write_no_replace(output_path, canonical_json_bytes(payload))
    return payload


def verify_source_audit(
    repo_root: Path, audit_path: Path, evidence_index_path: Path
) -> dict[str, object]:
    """Recompute and byte-compare the complete four-source audit."""

    root = repo_root.resolve(strict=True)
    recorded = _load_canonical_mapping(audit_path)
    if (
        recorded.get("schema_version") != SOURCE_AUDIT_SCHEMA_VERSION
        or recorded.get("status") != "PASS"
        or recorded.get("source_audit_sha256") != _self_hash(recorded, "source_audit_sha256")
    ):
        raise Phase2EvidenceError("source audit schema, status, or self hash drifted")
    expected = _expected_source_audit(root, evidence_index_path)
    recorded_hashes = cast(Mapping[str, object], recorded.get("source_hashes"))
    expected_hashes = cast(dict[str, object], expected["source_hashes"])
    recorded_goal_hash = recorded_hashes.get("goal")
    if not isinstance(recorded_goal_hash, str) or not re.fullmatch(
        r"[0-9a-f]{64}", recorded_goal_hash
    ):
        raise Phase2EvidenceError("source audit goal snapshot hash is invalid")
    if recorded_goal_hash not in {
        expected_hashes["goal"],
        ROADMAP_PRE_CLOSEOUT_SHA256,
    }:
        raise Phase2EvidenceError("source audit goal snapshot hash is not recognized")
    # Normal closeout updates Phase 2 status/count lines in ROADMAP after this
    # immutable audit is published. The exact Phase 2 goal row is still
    # re-derived and compared below; retain only the audit-time document hash.
    expected_hashes["goal"] = recorded_goal_hash
    expected["source_audit_sha256"] = _self_hash(expected, "source_audit_sha256")
    if recorded != expected:
        raise Phase2EvidenceError("source audit differs from exact live recomputation")
    return cast(dict[str, object], recorded)


def _run_git_bytes(root: Path, *arguments: str) -> bytes:
    completed = subprocess.run(
        ["rtk", "git", *arguments],
        cwd=root,
        check=True,
        capture_output=True,
    )
    return completed.stdout


def _verify_historical_source_audit(
    root: Path,
    audit_path: Path,
    evidence_index_path: Path,
) -> dict[str, object]:
    """Verify the immutable v1 audit under its original goal grammar."""

    recorded = _load_canonical_mapping(audit_path)
    if (
        recorded.get("schema_version") != SOURCE_AUDIT_SCHEMA_VERSION
        or recorded.get("status") != "PASS"
        or recorded.get("source_audit_sha256") != _self_hash(recorded, "source_audit_sha256")
    ):
        raise Phase2EvidenceError("historical source audit schema or self hash drifted")
    if _sha256_path(audit_path) != PREDECESSOR_SOURCE_AUDIT_FILE_SHA256:
        raise Phase2EvidenceError("historical source audit file bytes drifted")
    if _sha256_path(evidence_index_path) != PREDECESSOR_EVIDENCE_INDEX_FILE_SHA256:
        raise Phase2EvidenceError("historical evidence-index file bytes drifted")
    verify_evidence_index(root, evidence_index_path)
    recorded_rows = recorded.get("rows")
    if not isinstance(recorded_rows, list):
        raise Phase2EvidenceError("historical source audit rows are malformed")
    identifiers: list[tuple[str, str]] = []
    for row in recorded_rows:
        if not isinstance(row, dict):
            raise Phase2EvidenceError("historical source audit row is malformed")
        source = row.get("source")
        identifier = row.get("id")
        feature_sha256 = row.get("feature_sha256")
        if (
            source not in {"CONTEXT", "GOAL", "REQ", "RESEARCH"}
            or not isinstance(identifier, str)
            or not isinstance(feature_sha256, str)
            or re.fullmatch(r"[0-9a-f]{64}", feature_sha256) is None
            or row.get("status") not in {"COVERED", "EXCLUDED"}
            or not isinstance(row.get("plan_owners"), list)
            or not row.get("plan_owners")
            or not isinstance(row.get("evidence_owners"), list)
            or not row.get("evidence_owners")
        ):
            raise Phase2EvidenceError("historical source audit row contract drifted")
        identifiers.append((cast(str, source), identifier))
    if len(identifiers) != 76 or len(set(identifiers)) != 76:
        raise Phase2EvidenceError("historical source audit identity set drifted")
    historical_goal = [
        row
        for row in recorded_rows
        if row.get("source") == "GOAL" and row.get("id") == "PHASE-02-GOAL"
    ]
    parent_roadmap = _run_git_bytes(
        root, "show", f"{GRAMMAR_MIGRATION_COMMIT}^:.planning/ROADMAP.md"
    ).decode("utf-8")
    old_goal = _unique_source_line(
        parent_roadmap,
        "approved canonical 36 and independently seal a real 24/12 evaluation split",
    )
    if len(historical_goal) != 1 or historical_goal[0].get("feature_sha256") != _sha256_bytes(
        old_goal.encode("utf-8")
    ):
        raise Phase2EvidenceError("historical goal feature hash drifted")
    if recorded.get("source_counts") != {
        "CONTEXT": 56,
        "GOAL": 1,
        "REQ": 8,
        "RESEARCH": 11,
    } or recorded.get("status_counts") != {
        "COVERED": 72,
        "EXCLUDED": 4,
        "MISSING": 0,
    }:
        raise Phase2EvidenceError("historical source audit cardinality drifted")
    return cast(dict[str, object], recorded)


def _verify_grammar_migration(root: Path, commit: str) -> dict[str, object]:
    try:
        resolved = _run_git_bytes(root, "rev-parse", f"{commit}^{{commit}}").decode().strip()
    except (subprocess.CalledProcessError, UnicodeDecodeError) as exc:
        raise Phase2EvidenceError("grammar migration commit is invalid") from exc
    if resolved != GRAMMAR_MIGRATION_COMMIT:
        raise Phase2EvidenceError("grammar migration commit is not the approved owner")
    ancestry = subprocess.run(
        ["rtk", "git", "merge-base", "--is-ancestor", resolved, "HEAD"],
        cwd=root,
        check=False,
        capture_output=True,
    )
    if ancestry.returncode != 0:
        raise Phase2EvidenceError("grammar migration commit is not in HEAD ancestry")
    changed = (
        _run_git_bytes(
            root,
            "diff-tree",
            "--no-commit-id",
            "--name-only",
            "-r",
            resolved,
        )
        .decode("utf-8")
        .splitlines()
    )
    if changed != [".planning/ROADMAP.md"]:
        raise Phase2EvidenceError("grammar migration changed a path outside ROADMAP")
    parent_raw = _run_git_bytes(root, "show", f"{resolved}^:.planning/ROADMAP.md")
    migrated_raw = _run_git_bytes(root, "show", f"{resolved}:.planning/ROADMAP.md")
    old = b"As an operator, I want to collect and review three official provider sources"
    new = b"As a dataset operator, I want to collect and review three official provider sources"
    if parent_raw.count(old) != 1 or new in parent_raw:
        raise Phase2EvidenceError("grammar migration parent phrase is not exact")
    if migrated_raw != parent_raw.replace(old, new, 1):
        raise Phase2EvidenceError("grammar migration is broader than the exact role phrase")
    diff = _run_git_bytes(
        root,
        "diff",
        "--binary",
        f"{resolved}^",
        resolved,
        "--",
        ".planning/ROADMAP.md",
    )
    quick_path = root / QUICK_GRAMMAR_SUMMARY_RELATIVE
    quick = quick_path.read_text(encoding="utf-8")
    required_claims = (
        "Changed only the Phase 2 role phrase from 'As an operator' to 'As a dataset operator'",
        "numstat: `1\\t1\\t.planning/ROADMAP.md`",
        "`slots.role`: `dataset operator`",
        "`byte_exact`: `true`",
    )
    if not all(claim in quick for claim in required_claims):
        raise Phase2EvidenceError("quick grammar record does not match the approved migration")
    return {
        "commit": resolved,
        "roadmap_diff_sha256": _sha256_bytes(diff),
        "parent_roadmap_sha256": _sha256_bytes(parent_raw),
        "migrated_roadmap_sha256": _sha256_bytes(migrated_raw),
        "quick_record_sha256": _sha256_path(quick_path),
        "changed_paths": [".planning/ROADMAP.md"],
        "insertions": 1,
        "deletions": 1,
        "status": "EXACT_ROLE_GRAMMAR_MIGRATION",
    }


_DISCOVERY_RESOLUTION_RULES: tuple[tuple[str, str, tuple[str, ...]], ...] = (
    ("01", "SUPERSEDED_NO_APPROVAL_CLAIM", ("02-42-SUPERSEDED.md", "not approved")),
    ("02", "SUPERSEDED_NO_APPROVAL_CLAIM", ("02-43-SUPERSEDED.md", "not approved")),
    ("03", "RETIRED_CREDENTIAL_GATE", ("02-48-SUMMARY.md", "retired")),
    ("04", "SUPERSEDED_NO_PROVIDER_FINDING", ("02-42-SUPERSEDED.md", "not a provider finding")),
    (
        "05",
        "SUPERSEDED_NO_GRAMMAR_CLAIM",
        ("02-44-SUPERSEDED.md", "without a 3070426 grammar claim"),
    ),
    (
        "06",
        "POLICY_SUPERSEDED_NO_ALL_FIELDS_CLAIM",
        ("D-22/D-23/D-27", "not an affirmative all-fields finding"),
    ),
    (
        "07",
        "POLICY_SUPERSEDED_NO_OPERATING_INVENTION",
        ("D-28", "without inventing operating data"),
    ),
    (
        "08",
        "ORIGINAL_FAILED_SUCCESSOR_PASSED",
        ("ORIGINAL FAILED / SUCCESSOR PASSED", "does not reinterpret Plan 38"),
    ),
)


def _discovery_resolutions(root: Path) -> tuple[list[dict[str, object]], str]:
    path = root / SOURCE_DOCUMENTS["discovery_research"]
    text = path.read_text(encoding="utf-8")
    try:
        section = text.split("## Execution Gate Resolutions", 1)[1].split("## Sources", 1)[0]
    except IndexError as exc:
        raise Phase2EvidenceError("discovery resolution section is missing") from exc
    lines = [line for line in section.splitlines() if re.match(r"^\d+\. \*\*RESOLVED", line)]
    if len(lines) != 8:
        raise Phase2EvidenceError("discovery resolutions must contain exactly eight rows")
    rows: list[dict[str, object]] = []
    for position, (gate_id, disposition, required) in enumerate(
        _DISCOVERY_RESOLUTION_RULES, start=1
    ):
        line = lines[position - 1]
        if not line.startswith(f"{position}. **RESOLVED") or not all(
            token in line for token in required
        ):
            raise Phase2EvidenceError("discovery resolution semantics drifted")
        if position <= 5 and "**RESOLVED — APPROVED" in line.upper():
            raise Phase2EvidenceError("superseded discovery gate was mislabeled approved")
        rows.append(
            {
                "gate_id": gate_id,
                "disposition": disposition,
                "resolution_sha256": _sha256_bytes(line.encode("utf-8")),
                "status": "RESOLVED",
            }
        )
    return rows, _sha256_bytes(canonical_json_bytes(rows))


def _current_successor_rows(root: Path, evidence_index_path: Path) -> list[dict[str, object]]:
    index = verify_evidence_index(root, evidence_index_path)
    transition = cast(Mapping[str, object], index["requirements_transition"])
    requirements_raw, _ = _requirements_preimage(root, transition)
    rows = _expected_source_rows(root, requirements_raw)
    by_id = {(str(row["source"]), str(row["id"])): row for row in rows}
    goal = by_id[("GOAL", "PHASE-02-GOAL")]
    goal["plan_owners"] = [
        "02-20",
        "02-56",
        "02-57",
        "02-58",
        "02-59",
        "02-33",
        "02-34",
        "02-60",
        "02-61",
        "02-62",
    ]
    goal["evidence_owners"] = [
        "approved-catalog-and-split",
        "sqlite-one-time-seal-receipt",
        "canonical-v2-final-audit",
        "phase-02-original-acceptance",
        "current-lineage-and-rights-parent",
        "activation-current-parent",
        "phase-02-current-evidence-successor",
    ]
    for identifier in ("DATA-05", "DATA-06"):
        row = by_id[("REQ", identifier)]
        row["plan_owners"] = sorted(set(cast(list[str], row["plan_owners"])) | {"02-60", "02-62"})
        row["evidence_owners"] = [
            "completed-phase-02-owner",
            "phase-02-evidence-index",
            "current-lineage-and-rights-parent",
            "phase-02-current-evidence-successor",
        ]
    data07 = by_id[("REQ", "DATA-07")]
    data07["plan_owners"] = sorted(
        set(cast(list[str], data07["plan_owners"])) | {"02-60", "02-61", "02-62"}
    )
    data07["evidence_owners"] = [
        "completed-phase-02-owner",
        "phase-02-evidence-index",
        "current-lineage-and-rights-parent",
        "activation-current-parent",
        "phase-02-current-evidence-successor",
    ]
    return rows


def _expected_source_audit_successor(
    root: Path,
    *,
    predecessor_source_audit: Path,
    predecessor_evidence_index: Path,
    grammar_migration_commit: str,
) -> dict[str, object]:
    predecessor = _verify_historical_source_audit(
        root, predecessor_source_audit, predecessor_evidence_index
    )
    migration = _verify_grammar_migration(root, grammar_migration_commit)
    resolutions, resolutions_root = _discovery_resolutions(root)
    rows = _current_successor_rows(root, predecessor_evidence_index)
    source_counts = {
        source: sum(row["source"] == source for row in rows)
        for source in ("CONTEXT", "GOAL", "REQ", "RESEARCH")
    }
    index = verify_evidence_index(root, predecessor_evidence_index)
    transition = cast(Mapping[str, object], index["requirements_transition"])
    _, requirements_preimage_sha = _requirements_preimage(root, transition)
    source_hashes = {
        name: (
            requirements_preimage_sha if name == "requirements" else _sha256_path(root / relative)
        )
        for name, relative in sorted(SOURCE_DOCUMENTS.items())
    }
    payload: dict[str, object] = {
        "schema_version": SOURCE_AUDIT_SUCCESSOR_SCHEMA_VERSION,
        "status": "PASS",
        "migration_reason": (
            "exact dataset-operator grammar repair plus explicit current owner links"
        ),
        "predecessor": {
            "source_audit_file_sha256": _sha256_path(predecessor_source_audit),
            "source_audit_self_sha256": predecessor["source_audit_sha256"],
            "evidence_index_file_sha256": _sha256_path(predecessor_evidence_index),
            "evidence_index_self_sha256": index["evidence_index_sha256"],
            "historical_goal_feature_sha256": next(
                row["feature_sha256"]
                for row in cast(list[dict[str, object]], predecessor["rows"])
                if row["source"] == "GOAL" and row["id"] == "PHASE-02-GOAL"
            ),
        },
        "grammar_migration": migration,
        "current_goal_feature_sha256": next(
            row["feature_sha256"]
            for row in rows
            if row["source"] == "GOAL" and row["id"] == "PHASE-02-GOAL"
        ),
        "source_hashes": source_hashes,
        "source_counts": source_counts,
        "status_counts": {
            "COVERED": sum(row["status"] == "COVERED" for row in rows),
            "EXCLUDED": sum(row["status"] == "EXCLUDED" for row in rows),
            "MISSING": 0,
        },
        "discovery_resolutions": resolutions,
        "discovery_resolution_root_sha256": resolutions_root,
        "reopened_executable_plans": [],
        "rows": rows,
        "source_audit_successor_sha256": "",
    }
    if source_counts != {"CONTEXT": 56, "GOAL": 1, "REQ": 8, "RESEARCH": 11}:
        raise Phase2EvidenceError("source audit successor source cardinality drifted")
    if payload["status_counts"] != {"COVERED": 72, "EXCLUDED": 4, "MISSING": 0}:
        raise Phase2EvidenceError("source audit successor status cardinality drifted")
    data08 = next(row for row in rows if row["source"] == "REQ" and row["id"] == "DATA-08")
    predecessor_data08 = next(
        row
        for row in cast(list[dict[str, object]], predecessor["rows"])
        if row["source"] == "REQ" and row["id"] == "DATA-08"
    )
    if data08 != predecessor_data08:
        raise Phase2EvidenceError("DATA-08 source-audit ownership was remapped")
    payload["source_audit_successor_sha256"] = _self_hash(payload, "source_audit_successor_sha256")
    _assert_sanitized(payload)
    return payload


def _ensure_private_untracked(root: Path, path: Path) -> None:
    try:
        relpath = path.resolve().relative_to(root.resolve()).as_posix()
    except ValueError:
        return
    if not relpath.startswith("artifacts/restricted/catalog/v2/release/"):
        return
    ignored = subprocess.run(
        ["rtk", "git", "check-ignore", "-q", relpath],
        cwd=root,
        check=False,
        capture_output=True,
    )
    tracked = subprocess.run(
        ["rtk", "git", "ls-files", "--error-unmatch", relpath],
        cwd=root,
        check=False,
        capture_output=True,
    )
    if ignored.returncode != 0 or tracked.returncode == 0:
        raise Phase2EvidenceError("restricted successor must remain ignored and untracked")


def _publish_exact_existing(root: Path, path: Path, payload: bytes) -> str:
    if path.exists() or path.is_symlink():
        before = path.lstat()
        if (
            path.is_symlink()
            or not stat.S_ISREG(before.st_mode)
            or stat.S_IMODE(before.st_mode) != 0o600
            or before.st_nlink != 1
            or path.read_bytes() != payload
        ):
            raise Phase2EvidenceError("existing restricted successor is not exact")
        after = path.lstat()
        if (
            before.st_dev,
            before.st_ino,
            before.st_size,
            before.st_mtime_ns,
        ) != (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns):
            raise Phase2EvidenceError("existing restricted successor changed during recovery")
        disposition = "ALREADY_PRESENT_VERIFIED"
    else:
        _write_no_replace(path, payload)
        disposition = "PUBLISHED"
    metadata = path.lstat()
    if stat.S_IMODE(metadata.st_mode) != 0o600 or metadata.st_nlink != 1:
        raise Phase2EvidenceError("restricted successor mode or link count drifted")
    _ensure_private_untracked(root, path)
    return disposition


def build_source_audit_successor(
    repo_root: Path,
    output_path: Path,
    *,
    predecessor_source_audit: Path,
    predecessor_evidence_index: Path,
    grammar_migration_commit: str = GRAMMAR_MIGRATION_COMMIT,
) -> dict[str, object]:
    root = repo_root.resolve(strict=True)
    payload = _expected_source_audit_successor(
        root,
        predecessor_source_audit=predecessor_source_audit,
        predecessor_evidence_index=predecessor_evidence_index,
        grammar_migration_commit=grammar_migration_commit,
    )
    _publish_exact_existing(root, output_path, canonical_json_bytes(payload))
    return payload


def verify_source_audit_successor(
    repo_root: Path,
    audit_path: Path,
    *,
    predecessor_source_audit: Path,
    predecessor_evidence_index: Path,
) -> dict[str, object]:
    root = repo_root.resolve(strict=True)
    recorded = _load_canonical_mapping(audit_path)
    if (
        recorded.get("schema_version") != SOURCE_AUDIT_SUCCESSOR_SCHEMA_VERSION
        or recorded.get("status") != "PASS"
        or recorded.get("source_audit_successor_sha256")
        != _self_hash(recorded, "source_audit_successor_sha256")
    ):
        raise Phase2EvidenceError("source audit successor schema or self hash drifted")
    expected = _expected_source_audit_successor(
        root,
        predecessor_source_audit=predecessor_source_audit,
        predecessor_evidence_index=predecessor_evidence_index,
        grammar_migration_commit=GRAMMAR_MIGRATION_COMMIT,
    )
    if recorded != expected:
        raise Phase2EvidenceError("source audit successor differs from live rederivation")
    _ensure_private_untracked(root, audit_path)
    return cast(dict[str, object], recorded)


def _phase2_roadmap_section(text: str) -> str:
    marker = "### Phase 2: Canonical 36, Rights, and Evaluation Manifest"
    if text.count(marker) != 1 or text.count("### Phase 3:") != 1:
        raise Phase2EvidenceError("ROADMAP Phase 2 boundary is missing or duplicated")
    return text.split(marker, 1)[1].split("### Phase 3:", 1)[0]


def _roadmap_phase2_semantic_commitment(text: str) -> dict[str, object]:
    section = _phase2_roadmap_section(text)

    def exact_field(prefix: str) -> str:
        values = [line[len(prefix) :] for line in section.splitlines() if line.startswith(prefix)]
        if len(values) != 1:
            raise Phase2EvidenceError(f"ROADMAP Phase 2 field is missing or duplicated: {prefix}")
        return values[0]

    goal = exact_field("**Goal**: ")
    if goal != EXPECTED_PHASE2_GOAL:
        raise Phase2EvidenceError("ROADMAP Phase 2 goal semantic commitment drifted")
    mode = exact_field("**Mode:** ")
    dependency = exact_field("**Depends on**: ")
    requirements = exact_field("**Requirements**: ").split(", ")
    criteria_rows = [
        (int(match.group(1)), match.group(2))
        for line in section.splitlines()
        if (match := re.fullmatch(r"  ([1-5])\. (.+)", line)) is not None
    ]
    if criteria_rows != list(enumerate(EXPECTED_PHASE2_SUCCESS_CRITERIA, start=1)):
        raise Phase2EvidenceError("ROADMAP Phase 2 success criteria drifted")
    expected_requirements = [f"DATA-{ordinal:02d}" for ordinal in range(1, 9)]
    if mode != "mvp" or dependency != "Phase 1" or requirements != expected_requirements:
        raise Phase2EvidenceError("ROADMAP Phase 2 mode, dependency, or requirements drifted")
    ui_hint = exact_field("**UI hint**: ")
    external_evidence = exact_field("**External evidence**: ")
    if ui_hint != "no" or external_evidence != (
        "production API 승인·quota와 기관/법률 확인이 필요한 자산 권리는 별도 상태로 기록하며, "
        "코드가 이를 획득하거나 승인했다고 간주하지 않는다."
    ):
        raise Phase2EvidenceError("ROADMAP Phase 2 UI or external-evidence commitment drifted")
    commitment: dict[str, object] = {
        "goal": goal,
        "mode": mode,
        "depends_on": dependency,
        "requirements": requirements,
        "success_criteria": [value for _, value in criteria_rows],
        "ui_hint": ui_hint,
        "external_evidence": external_evidence,
    }
    return {
        "fields": commitment,
        "semantic_sha256": _sha256_bytes(canonical_json_bytes(commitment)),
    }


def _requirements_phase2_semantic_commitment(text: str) -> dict[str, object]:
    requirement_rows: list[dict[str, object]] = []
    trace_rows: list[dict[str, str]] = []
    for ordinal, expected_text in enumerate(EXPECTED_DATA_REQUIREMENT_TEXT, start=1):
        identifier = f"DATA-{ordinal:02d}"
        pattern = re.compile(rf"^- \[([^]])\] \*\*{identifier}\*\*: (.+)$", re.MULTILINE)
        matches = pattern.findall(text)
        if len(matches) != 1:
            raise Phase2EvidenceError(f"REQUIREMENTS {identifier} row is missing or duplicated")
        checked, statement = matches[0]
        if checked != "x" or statement != expected_text:
            raise Phase2EvidenceError(f"REQUIREMENTS {identifier} semantic commitment drifted")
        requirement_rows.append({"id": identifier, "checked": True, "statement": statement})
        trace = f"| {identifier} | Phase 2 | Complete |"
        if text.splitlines().count(trace) != 1:
            raise Phase2EvidenceError(f"REQUIREMENTS {identifier} traceability drifted")
        trace_rows.append({"id": identifier, "phase": "Phase 2", "status": "Complete"})
    data_lines = [
        line for line in text.splitlines() if re.match(r"^- \[[^]]\] \*\*DATA-\d\d\*\*:", line)
    ]
    trace_lines = [
        line for line in text.splitlines() if re.match(r"^\| DATA-\d\d \| Phase 2 \|", line)
    ]
    if len(data_lines) != 8 or len(trace_lines) != 8:
        raise Phase2EvidenceError("REQUIREMENTS Phase 2 DATA cardinality drifted")
    commitment: dict[str, object] = {
        "requirements": requirement_rows,
        "traceability": trace_rows,
    }
    return {
        "fields": commitment,
        "semantic_sha256": _sha256_bytes(canonical_json_bytes(commitment)),
    }


def _verify_plan62_closeout(root: Path, commit: str = PLAN62_CLOSEOUT_COMMIT) -> dict[str, object]:
    resolved = _run_git_bytes(root, "rev-parse", f"{commit}^{{commit}}").decode().strip()
    if resolved != PLAN62_CLOSEOUT_COMMIT:
        raise Phase2EvidenceError("Plan 62 closeout commit is not exact")
    ancestry = subprocess.run(
        ["rtk", "git", "merge-base", "--is-ancestor", resolved, "HEAD"],
        cwd=root,
        check=False,
        capture_output=True,
    )
    if ancestry.returncode != 0:
        raise Phase2EvidenceError("Plan 62 closeout commit is not in HEAD ancestry")
    status_lines = (
        _run_git_bytes(root, "diff-tree", "--no-commit-id", "--name-status", "-r", resolved)
        .decode()
        .splitlines()
    )
    expected_status = [
        "M\t.planning/ROADMAP.md",
        "M\t.planning/STATE.md",
        ("A\t.planning/phases/02-canonical-36-rights-and-evaluation-manifest/02-62-SUMMARY.md"),
    ]
    if status_lines != expected_status:
        raise Phase2EvidenceError("Plan 62 closeout changed an unexpected path")
    parent_roadmap = _run_git_bytes(root, "show", f"{resolved}^:.planning/ROADMAP.md")
    post_roadmap = _run_git_bytes(root, "show", f"{resolved}:.planning/ROADMAP.md")
    if _sha256_bytes(parent_roadmap) != PLAN62_ROADMAP_PARENT_SHA256:
        raise Phase2EvidenceError("Plan 62 ROADMAP parent hash drifted")
    if _sha256_bytes(post_roadmap) != PLAN62_ROADMAP_POST_SHA256:
        raise Phase2EvidenceError("Plan 62 ROADMAP post-closeout hash drifted")
    summary_rel = ".planning/phases/02-canonical-36-rights-and-evaluation-manifest/02-62-SUMMARY.md"
    summary_bytes = _run_git_bytes(root, "show", f"{resolved}:{summary_rel}")
    if (root / summary_rel).read_bytes() != summary_bytes:
        raise Phase2EvidenceError("Plan 62 Summary bytes drifted")
    closeout_diff = _run_git_bytes(
        root,
        "diff",
        "--binary",
        f"{resolved}^",
        resolved,
        "--",
        ".planning/ROADMAP.md",
        ".planning/STATE.md",
    )
    return {
        "commit": resolved,
        "changed_paths": [line.split("\t", 1)[1] for line in status_lines],
        "roadmap_parent_sha256": _sha256_bytes(parent_roadmap),
        "roadmap_post_sha256": _sha256_bytes(post_roadmap),
        "summary_sha256": _sha256_bytes(summary_bytes),
        "lifecycle_diff_sha256": _sha256_bytes(closeout_diff),
        "status": "EXACT_PLAN62_CLOSEOUT",
    }


def _validate_terminal_phase_inventory(
    root: Path,
    *,
    executable_plan_ids: Sequence[str] | None = None,
    summary_plan_ids: Sequence[str] | None = None,
) -> dict[str, object]:
    if executable_plan_ids is None:
        executable_plan_ids = tuple(
            path.name[3:5].join(("02-", ""))
            for path in sorted((root / PHASE_RELATIVE).glob("02-??-PLAN.md"))
        )
    if summary_plan_ids is None:
        summary_plan_ids = tuple(
            path.name[3:5].join(("02-", ""))
            for path in sorted((root / PHASE_RELATIVE).glob("02-??-SUMMARY.md"))
        )
    expected_plans = (*TERMINAL_SEMANTIC_OWNER_IDS, "02-63")
    allowed_summaries = {(*TERMINAL_SEMANTIC_OWNER_IDS,)[ordinal] for ordinal in range(47)}
    actual_plans = tuple(executable_plan_ids)
    actual_summaries = tuple(summary_plan_ids)
    if actual_plans != expected_plans:
        raise Phase2EvidenceError("terminal owner universe has executable plan intrusion")
    if not set(TERMINAL_SEMANTIC_OWNER_IDS) <= set(actual_summaries):
        raise Phase2EvidenceError("terminal owner universe is missing a completed Summary")
    if set(actual_summaries) - (allowed_summaries | {"02-63"}):
        raise Phase2EvidenceError("terminal owner universe has Summary intrusion")
    universe_root = _sha256_bytes(canonical_json_bytes(list(TERMINAL_SEMANTIC_OWNER_IDS)))
    return {
        "semantic_owner_ids": list(TERMINAL_SEMANTIC_OWNER_IDS),
        "semantic_owner_count": 47,
        "terminal_owner_universe_sha256": universe_root,
        "producer_plan_id": "02-63",
        "producer_summary_state": "PRESENT" if "02-63" in actual_summaries else "ABSENT",
    }


def _validate_plan64_summary_text(text: str) -> None:
    frontmatter = text.split("---", 2)
    if len(frontmatter) < 3:
        raise Phase2EvidenceError("Plan 64 Summary frontmatter is missing")
    if not re.search(r'^plan:\s*["\']?64["\']?\s*$', frontmatter[1], re.M):
        raise Phase2EvidenceError("Plan 64 Summary plan binding drifted")
    if not re.search(r"^status:\s*complete\s*$", frontmatter[1], re.M):
        raise Phase2EvidenceError("Plan 64 Summary is not complete")


def _validate_plan64_phase_inventory(
    root: Path,
    *,
    executable_plan_ids: Sequence[str] | None = None,
    summary_plan_ids: Sequence[str] | None = None,
    plan64_summary_text: str | None = None,
) -> dict[str, object]:
    injected_summaries = summary_plan_ids is not None
    if executable_plan_ids is None:
        executable_plan_ids = tuple(
            path.name[3:5].join(("02-", ""))
            for path in sorted((root / PHASE_RELATIVE).glob("02-??-PLAN.md"))
        )
    if summary_plan_ids is None:
        summary_plan_ids = tuple(
            path.name[3:5].join(("02-", ""))
            for path in sorted((root / PHASE_RELATIVE).glob("02-??-SUMMARY.md"))
        )
    expected_plans = (*TERMINAL_SEMANTIC_OWNER_IDS, "02-63", "02-64")
    required_summaries = {*TERMINAL_SEMANTIC_OWNER_IDS, "02-63"}
    allowed_summaries = required_summaries | {"02-64"}
    actual_plans = tuple(executable_plan_ids)
    actual_summaries = tuple(summary_plan_ids)
    if actual_plans != expected_plans:
        raise Phase2EvidenceError("Plan 64 producer universe has executable plan intrusion")
    if len(actual_summaries) != len(set(actual_summaries)):
        raise Phase2EvidenceError("Plan 64 producer universe has duplicate Summary ownership")
    if not required_summaries <= set(actual_summaries):
        raise Phase2EvidenceError("Plan 64 producer universe is missing a completed Summary")
    if set(actual_summaries) - allowed_summaries:
        raise Phase2EvidenceError("Plan 64 producer universe has Summary intrusion")
    if "02-64" in actual_summaries:
        if plan64_summary_text is None:
            if injected_summaries:
                raise Phase2EvidenceError("Plan 64 present Summary was not supplied for validation")
            summary_path = root / PHASE_RELATIVE / "02-64-SUMMARY.md"
            if summary_path.is_symlink() or not summary_path.is_file():
                raise Phase2EvidenceError("Plan 64 Summary identity is unsafe")
            try:
                plan64_summary_text = summary_path.read_text(encoding="utf-8")
            except UnicodeDecodeError as exc:
                raise Phase2EvidenceError("Plan 64 Summary is not UTF-8") from exc
        _validate_plan64_summary_text(plan64_summary_text)
    return {
        "semantic_owner_ids": list(TERMINAL_SEMANTIC_OWNER_IDS),
        "semantic_owner_count": 47,
        "semantic_owner_universe_sha256": _sha256_bytes(
            canonical_json_bytes(list(TERMINAL_SEMANTIC_OWNER_IDS))
        ),
        "producer_plan_ids": ["02-63", "02-64"],
        "accepted_plan64_summary_states": ["ABSENT", "PRESENT_VALID"],
    }


def _plan64_successor_lifecycle_projection(
    root: Path,
    *,
    roadmap_text: str,
    requirements_text: str,
    executable_plan_ids: Sequence[str] | None = None,
    summary_plan_ids: Sequence[str] | None = None,
    plan64_summary_text: str | None = None,
) -> dict[str, object]:
    inventory = _validate_plan64_phase_inventory(
        root,
        executable_plan_ids=executable_plan_ids,
        summary_plan_ids=summary_plan_ids,
        plan64_summary_text=plan64_summary_text,
    )
    roadmap = _roadmap_phase2_semantic_commitment(roadmap_text)
    requirements = _requirements_phase2_semantic_commitment(requirements_text)
    return {
        "inventory": inventory,
        "roadmap_semantic_sha256": roadmap["semantic_sha256"],
        "requirements_semantic_sha256": requirements["semantic_sha256"],
        "status": "PASS",
    }


def _validate_v2_source_predecessor(payload: Mapping[str, object]) -> None:
    if (
        payload.get("schema_version") != SOURCE_AUDIT_SUCCESSOR_SCHEMA_VERSION
        or payload.get("status") != "PASS"
        or payload.get("source_audit_successor_sha256")
        != _self_hash(payload, "source_audit_successor_sha256")
        or payload.get("source_counts") != {"CONTEXT": 56, "GOAL": 1, "REQ": 8, "RESEARCH": 11}
        or payload.get("status_counts") != {"COVERED": 72, "EXCLUDED": 4, "MISSING": 0}
    ):
        raise Phase2EvidenceError("source-audit v2 predecessor contract drifted")
    rows = payload.get("rows")
    if not isinstance(rows, list) or len(rows) != 76:
        raise Phase2EvidenceError("source-audit v2 predecessor rows drifted")


def _derive_closeout_source_audit_payload(
    predecessor: Mapping[str, object],
    *,
    roadmap_text: str,
    requirements_text: str,
    closeout: Mapping[str, object],
) -> dict[str, object]:
    _validate_v2_source_predecessor(predecessor)
    roadmap = _roadmap_phase2_semantic_commitment(roadmap_text)
    requirements = _requirements_phase2_semantic_commitment(requirements_text)
    predecessor_rows = cast(list[dict[str, object]], predecessor["rows"])
    rows = json.loads(json.dumps(predecessor_rows, ensure_ascii=False))
    changed_ids: list[str] = []
    for row in rows:
        identifier = cast(str, row["id"])
        plan_owners = cast(list[str], row["plan_owners"])
        if identifier in CLOSEOUT_MIGRATION_IDS:
            if "02-62" in plan_owners:
                raise Phase2EvidenceError("source-audit v2 predecessor already contains migration")
            row["plan_owners"] = sorted((*plan_owners, "02-62"))
            changed_ids.append(identifier)
    if set(changed_ids) != set(CLOSEOUT_MIGRATION_IDS) or len(changed_ids) != 51:
        raise Phase2EvidenceError("source-audit v2 predecessor migration cardinality drifted")
    migration_rows = [
        {
            "id": identifier,
            "source": next(str(row["source"]) for row in rows if row["id"] == identifier),
        }
        for identifier in sorted(changed_ids)
    ]
    payload: dict[str, object] = {
        "schema_version": SOURCE_AUDIT_CLOSEOUT_SCHEMA_VERSION,
        "status": "PASS",
        "migration_reason": "exact completed Plan 62 closeout owner migration",
        "predecessor": {
            "source_audit_successor_file_sha256": PREDECESSOR_SOURCE_AUDIT_SUCCESSOR_FILE_SHA256,
            "source_audit_successor_self_sha256": predecessor["source_audit_successor_sha256"],
            "current_evidence_index_file_sha256": PREDECESSOR_CURRENT_EVIDENCE_FILE_SHA256,
        },
        "plan62_closeout": dict(closeout),
        "terminal_owner_universe": {
            "semantic_owner_ids": list(TERMINAL_SEMANTIC_OWNER_IDS),
            "semantic_owner_count": 47,
            "terminal_owner_universe_sha256": _sha256_bytes(
                canonical_json_bytes(list(TERMINAL_SEMANTIC_OWNER_IDS))
            ),
            "producer_plan_id": "02-63",
        },
        "semantic_commitments": {"roadmap": roadmap, "requirements": requirements},
        "source_hashes": {
            key: value
            for key, value in cast(Mapping[str, object], predecessor["source_hashes"]).items()
            if key not in {"goal", "requirements"}
        },
        "source_counts": dict(cast(Mapping[str, object], predecessor["source_counts"])),
        "status_counts": dict(cast(Mapping[str, object], predecessor["status_counts"])),
        "discovery_resolutions": predecessor["discovery_resolutions"],
        "discovery_resolution_root_sha256": predecessor["discovery_resolution_root_sha256"],
        "reopened_executable_plans": [],
        "closeout_migration": {
            "added_plan_owner": "02-62",
            "changed_fields": ["plan_owners"],
            "row_count": 51,
            "rows": migration_rows,
            "migration_root_sha256": _sha256_bytes(canonical_json_bytes(migration_rows)),
        },
        "rows": rows,
        "source_audit_closeout_successor_sha256": "",
    }
    payload["source_audit_closeout_successor_sha256"] = _self_hash(
        payload, "source_audit_closeout_successor_sha256"
    )
    _validate_closeout_source_audit_payload(payload)
    return payload


def _validate_closeout_source_audit_payload(payload: Mapping[str, object]) -> None:
    if (
        payload.get("schema_version") != SOURCE_AUDIT_CLOSEOUT_SCHEMA_VERSION
        or payload.get("status") != "PASS"
        or payload.get("source_audit_closeout_successor_sha256")
        != _self_hash(payload, "source_audit_closeout_successor_sha256")
        or payload.get("source_counts") != {"CONTEXT": 56, "GOAL": 1, "REQ": 8, "RESEARCH": 11}
        or payload.get("status_counts") != {"COVERED": 72, "EXCLUDED": 4, "MISSING": 0}
    ):
        raise Phase2EvidenceError("closeout source audit schema, counts, or self hash drifted")
    universe = payload.get("terminal_owner_universe")
    if not isinstance(universe, dict) or universe.get("semantic_owner_ids") != list(
        TERMINAL_SEMANTIC_OWNER_IDS
    ):
        raise Phase2EvidenceError("terminal owner universe drifted")
    rows = payload.get("rows")
    if not isinstance(rows, list) or len(rows) != 76:
        raise Phase2EvidenceError("closeout source audit row cardinality drifted")
    allowed = set(TERMINAL_SEMANTIC_OWNER_IDS)
    for row in rows:
        if not isinstance(row, dict) or not isinstance(row.get("plan_owners"), list):
            raise Phase2EvidenceError("closeout source audit row is malformed")
        semantic = [owner for owner in row["plan_owners"] if str(owner).startswith("02-")]
        if "02-63" in semantic or any(owner not in allowed for owner in semantic):
            raise Phase2EvidenceError("closeout source audit has recursive semantic owner")
    migration = payload.get("closeout_migration")
    if (
        not isinstance(migration, dict)
        or migration.get("row_count") != 51
        or migration.get("added_plan_owner") != "02-62"
        or migration.get("changed_fields") != ["plan_owners"]
        or not isinstance(migration.get("rows"), list)
        or {row.get("id") for row in cast(list[dict[str, object]], migration["rows"])}
        != set(CLOSEOUT_MIGRATION_IDS)
    ):
        raise Phase2EvidenceError("closeout source audit migration drifted")
    _assert_sanitized(payload)


def _expected_source_audit_closeout_successor(
    root: Path,
    *,
    predecessor_source_audit_successor: Path,
    predecessor_current_evidence_index: Path,
    closeout_commit: str,
) -> dict[str, object]:
    if _sha256_path(predecessor_source_audit_successor) != (
        PREDECESSOR_SOURCE_AUDIT_SUCCESSOR_FILE_SHA256
    ):
        raise Phase2EvidenceError("source-audit v2 predecessor file drifted")
    if _sha256_path(predecessor_current_evidence_index) != (
        PREDECESSOR_CURRENT_EVIDENCE_FILE_SHA256
    ):
        raise Phase2EvidenceError("current-evidence v2 predecessor file drifted")
    predecessor = _load_canonical_mapping(predecessor_source_audit_successor)
    current = _load_canonical_mapping(predecessor_current_evidence_index)
    validate_current_evidence_payload(current, require_after_guard=False)
    _validate_terminal_phase_inventory(root)
    return _derive_closeout_source_audit_payload(
        predecessor,
        roadmap_text=(root / SOURCE_DOCUMENTS["goal"]).read_text(encoding="utf-8"),
        requirements_text=(root / REQUIREMENTS_RELATIVE).read_text(encoding="utf-8"),
        closeout=_verify_plan62_closeout(root, closeout_commit),
    )


def build_source_audit_closeout_successor(
    repo_root: Path,
    output_path: Path,
    *,
    predecessor_source_audit_successor: Path,
    predecessor_current_evidence_index: Path,
    closeout_commit: str = PLAN62_CLOSEOUT_COMMIT,
) -> dict[str, object]:
    root = repo_root.resolve(strict=True)
    payload = _expected_source_audit_closeout_successor(
        root,
        predecessor_source_audit_successor=predecessor_source_audit_successor,
        predecessor_current_evidence_index=predecessor_current_evidence_index,
        closeout_commit=closeout_commit,
    )
    _publish_exact_existing(root, output_path, canonical_json_bytes(payload))
    return payload


def verify_source_audit_closeout_successor(
    repo_root: Path,
    audit_path: Path,
    *,
    predecessor_source_audit_successor: Path | None = None,
    predecessor_current_evidence_index: Path | None = None,
) -> dict[str, object]:
    root = repo_root.resolve(strict=True)
    predecessor_source_audit_successor = predecessor_source_audit_successor or (
        root / SOURCE_AUDIT_SUCCESSOR_RELATIVE
    )
    predecessor_current_evidence_index = predecessor_current_evidence_index or (
        root / CURRENT_EVIDENCE_RELATIVE
    )
    recorded = _load_canonical_mapping(audit_path)
    _validate_closeout_source_audit_payload(recorded)
    expected = _expected_source_audit_closeout_successor(
        root,
        predecessor_source_audit_successor=predecessor_source_audit_successor,
        predecessor_current_evidence_index=predecessor_current_evidence_index,
        closeout_commit=PLAN62_CLOSEOUT_COMMIT,
    )
    if recorded != expected:
        raise Phase2EvidenceError("closeout source audit differs from live semantic derivation")
    _ensure_private_untracked(root, audit_path)
    return cast(dict[str, object], recorded)


PLAN63_TASK_OWNED_RELPATHS = frozenset(
    {
        "backend/src/itda/cli/verify_phase2_evidence.py",
        "backend/tests/security/test_phase2_evidence.py",
        "artifacts/restricted/catalog/v2/release/phase-02-source-audit-v3.json",
        "artifacts/restricted/catalog/v2/release/phase-02-verification-matrix-v2.json",
        "artifacts/restricted/catalog/v2/release/phase-02-evidence-index-v3.json",
        "artifacts/restricted/catalog/v2/release/gap-closure-guards/02-63-protected-before.json",
        "artifacts/restricted/catalog/v2/release/gap-closure-guards/02-63-protected-after.json",
    }
)
PLAN63_EXTRA_PROTECTED_RELPATHS = (
    "artifacts/restricted/catalog/v2/release/phase-02-source-audit-v2.json",
    "artifacts/restricted/catalog/v2/release/phase-02-evidence-index-v2.json",
    "artifacts/restricted/catalog/v2/release/phase-02-verification-matrix-v1.json",
    *(
        f"artifacts/restricted/catalog/v2/release/gap-closure-guards/02-{plan}-protected-{stage}.json"
        for plan in (60, 61, 62)
        for stage in ("before", "after")
    ),
    *(
        f".planning/phases/02-canonical-36-rights-and-evaluation-manifest/02-{plan}-{kind}.md"
        for plan in (60, 61, 62)
        for kind in ("PLAN", "SUMMARY")
    ),
    ".planning/ROADMAP.md",
    ".planning/STATE.md",
    ".planning/phases/02-canonical-36-rights-and-evaluation-manifest/02-VALIDATION.md",
    ".planning/phases/02-canonical-36-rights-and-evaluation-manifest/02-PATTERNS.md",
)

PLAN64_TASK_OWNED_RELPATHS = frozenset(
    {
        "backend/src/itda/cli/verify_phase2_evidence.py",
        "backend/tests/security/test_phase2_evidence.py",
        "artifacts/restricted/catalog/v2/release/gap-closure-guards/02-64-protected-before.json",
        "artifacts/restricted/catalog/v2/release/gap-closure-guards/02-64-protected-after.json",
    }
)
PLAN64_EXTRA_PROTECTED_RELPATHS = (
    *PLAN63_EXTRA_PROTECTED_RELPATHS,
    "artifacts/restricted/catalog/v2/release/phase-02-source-audit-v3.json",
    "artifacts/restricted/catalog/v2/release/phase-02-verification-matrix-v2.json",
    "artifacts/restricted/catalog/v2/release/phase-02-evidence-index-v3.json",
    "artifacts/restricted/catalog/v2/release/gap-closure-guards/02-63-protected-before.json",
    "artifacts/restricted/catalog/v2/release/gap-closure-guards/02-63-protected-after.json",
    ".planning/phases/02-canonical-36-rights-and-evaluation-manifest/02-63-PLAN.md",
    ".planning/phases/02-canonical-36-rights-and-evaluation-manifest/02-63-SUMMARY.md",
    ".planning/phases/02-canonical-36-rights-and-evaluation-manifest/02-64-PLAN.md",
    ".planning/phases/02-canonical-36-rights-and-evaluation-manifest/02-VERIFICATION.md",
)


def _plan63_dirty_relpaths(root: Path) -> tuple[str, ...]:
    completed = subprocess.run(
        ["rtk", "proxy", "git", "status", "--porcelain=v1", "-z", "--untracked-files=all"],
        cwd=root,
        check=True,
        capture_output=True,
    )
    relpaths: list[str] = []
    records = completed.stdout.split(b"\0")
    index = 0
    while index < len(records):
        record = records[index]
        index += 1
        if not record:
            continue
        status = record[:2].decode("ascii")
        relpath = record[3:].decode("utf-8")
        if status[0] in {"R", "C"} and index < len(records):
            relpath = records[index].decode("utf-8")
            index += 1
        if relpath not in PLAN63_TASK_OWNED_RELPATHS:
            relpaths.append(relpath)
    return tuple(sorted(set(relpaths), key=str.encode))


def _plan64_dirty_relpaths(root: Path) -> tuple[str, ...]:
    return tuple(
        relpath
        for relpath in _plan63_dirty_relpaths(root)
        if relpath not in PLAN64_TASK_OWNED_RELPATHS
    )


def _build_plan63_protected_manifest(root: Path, *, stage: str) -> dict[str, object]:
    if stage not in {"before", "after"}:
        raise Phase2EvidenceError("Plan 63 protected stage is not closed")
    base = lineage_capability.build_protected_manifest(root, plan_id="02-62", stage="after")
    owners = cast(list[dict[str, object]], json.loads(json.dumps(base["owners"])))
    owner_relpaths = {
        cast(str, row["relpath"]) for row in owners if isinstance(row.get("relpath"), str)
    }
    extra_relpaths = (*PLAN63_EXTRA_PROTECTED_RELPATHS, *_plan63_dirty_relpaths(root))
    for relpath in sorted(set(extra_relpaths), key=str.encode):
        if relpath in PLAN63_TASK_OWNED_RELPATHS or relpath in owner_relpaths:
            continue
        path = root / relpath
        if not path.is_file() or path.is_symlink():
            raise Phase2EvidenceError("Plan 63 protected dirty path is not a regular file")
        owners.append(lineage_capability._protected_file_owner(root, relpath))
        owner_relpaths.add(relpath)
    owners.sort(key=lambda row: str(row["owner"]).encode("utf-8"))
    absences = cast(list[dict[str, object]], base["required_absences"])
    protected_set = {"owners": owners, "required_absences": absences}
    fields: dict[str, object] = {
        "schema_version": PLAN63_PROTECTED_SCHEMA_VERSION,
        "plan_id": "02-63",
        "stage": stage,
        "owner_count": len(owners),
        "owners": owners,
        "required_absences": absences,
        "identity_rows_sha256": _sha256_bytes(canonical_json_bytes(owners)),
        "protected_set_sha256": _sha256_bytes(canonical_json_bytes(protected_set)),
        "protected_manifest_sha256": "",
    }
    fields["protected_manifest_sha256"] = _self_hash(fields, "protected_manifest_sha256")
    lineage_capability._assert_membership_free_payload(fields)
    return fields


def _validate_plan63_protected_manifest(
    root: Path, recorded: Mapping[str, object], *, stage: str
) -> dict[str, object]:
    del root
    if (
        recorded.get("schema_version") != PLAN63_PROTECTED_SCHEMA_VERSION
        or recorded.get("plan_id") != "02-63"
        or recorded.get("stage") != stage
        or recorded.get("protected_manifest_sha256")
        != _self_hash(recorded, "protected_manifest_sha256")
    ):
        raise Phase2EvidenceError("Plan 63 protected manifest schema or self hash drifted")
    owners = recorded.get("owners")
    absences = recorded.get("required_absences")
    if not isinstance(owners, list) or not isinstance(absences, list):
        raise Phase2EvidenceError("Plan 63 protected manifest inventory is invalid")
    if recorded.get("owner_count") != len(owners):
        raise Phase2EvidenceError("Plan 63 protected owner count drifted")
    if recorded.get("identity_rows_sha256") != _sha256_bytes(canonical_json_bytes(owners)):
        raise Phase2EvidenceError("Plan 63 protected identity root drifted")
    protected_set = {"owners": owners, "required_absences": absences}
    if recorded.get("protected_set_sha256") != _sha256_bytes(canonical_json_bytes(protected_set)):
        raise Phase2EvidenceError("Plan 63 protected set root drifted")
    lineage_capability._assert_membership_free_payload(recorded)
    return cast(dict[str, object], recorded)


def _build_plan64_protected_manifest(root: Path, *, stage: str) -> dict[str, object]:
    if stage not in {"before", "after"}:
        raise Phase2EvidenceError("Plan 64 protected stage is not closed")
    base = lineage_capability.build_protected_manifest(root, plan_id="02-62", stage="after")
    owners = cast(list[dict[str, object]], json.loads(json.dumps(base["owners"])))
    owner_relpaths = {
        cast(str, row["relpath"]) for row in owners if isinstance(row.get("relpath"), str)
    }
    extra_relpaths = (*PLAN64_EXTRA_PROTECTED_RELPATHS, *_plan64_dirty_relpaths(root))
    for relpath in sorted(set(extra_relpaths), key=str.encode):
        if relpath in PLAN64_TASK_OWNED_RELPATHS or relpath in owner_relpaths:
            continue
        path = root / relpath
        if not path.is_file() or path.is_symlink():
            raise Phase2EvidenceError("Plan 64 protected path is not a regular file")
        owners.append(lineage_capability._protected_file_owner(root, relpath))
        owner_relpaths.add(relpath)
    owners.sort(key=lambda row: str(row["owner"]).encode("utf-8"))
    absences = cast(list[dict[str, object]], base["required_absences"])
    protected_set = {"owners": owners, "required_absences": absences}
    fields: dict[str, object] = {
        "schema_version": PLAN64_PROTECTED_SCHEMA_VERSION,
        "plan_id": "02-64",
        "stage": stage,
        "owner_count": len(owners),
        "owners": owners,
        "required_absences": absences,
        "identity_rows_sha256": _sha256_bytes(canonical_json_bytes(owners)),
        "protected_set_sha256": _sha256_bytes(canonical_json_bytes(protected_set)),
        "protected_manifest_sha256": "",
    }
    fields["protected_manifest_sha256"] = _self_hash(fields, "protected_manifest_sha256")
    lineage_capability._assert_membership_free_payload(fields)
    return fields


def _validate_plan64_protected_manifest(
    root: Path, recorded: Mapping[str, object], *, stage: str
) -> dict[str, object]:
    del root
    if (
        recorded.get("schema_version") != PLAN64_PROTECTED_SCHEMA_VERSION
        or recorded.get("plan_id") != "02-64"
        or recorded.get("stage") != stage
        or recorded.get("protected_manifest_sha256")
        != _self_hash(recorded, "protected_manifest_sha256")
    ):
        raise Phase2EvidenceError("Plan 64 protected manifest schema or self hash drifted")
    owners = recorded.get("owners")
    absences = recorded.get("required_absences")
    if not isinstance(owners, list) or not isinstance(absences, list):
        raise Phase2EvidenceError("Plan 64 protected manifest inventory is invalid")
    if recorded.get("owner_count") != len(owners):
        raise Phase2EvidenceError("Plan 64 protected owner count drifted")
    if recorded.get("identity_rows_sha256") != _sha256_bytes(canonical_json_bytes(owners)):
        raise Phase2EvidenceError("Plan 64 protected identity root drifted")
    protected_set = {"owners": owners, "required_absences": absences}
    if recorded.get("protected_set_sha256") != _sha256_bytes(canonical_json_bytes(protected_set)):
        raise Phase2EvidenceError("Plan 64 protected set root drifted")
    lineage_capability._assert_membership_free_payload(recorded)
    return cast(dict[str, object], recorded)


def capture_protected_manifest(
    repo_root: Path, output_path: Path, *, plan_id: str, stage: str
) -> dict[str, object]:
    root = repo_root.resolve(strict=True)
    expected = (
        root
        / "artifacts/restricted/catalog/v2/release/gap-closure-guards"
        / f"{plan_id}-protected-{stage}.json"
    )
    if output_path.resolve() != expected.resolve():
        raise Phase2EvidenceError("protected manifest output path is not exact")
    if plan_id == "02-63":
        manifest = _build_plan63_protected_manifest(root, stage=stage)
        payload = canonical_json_bytes(manifest)
    elif plan_id == "02-64":
        manifest = _build_plan64_protected_manifest(root, stage=stage)
        payload = canonical_json_bytes(manifest)
    else:
        manifest = lineage_capability.build_protected_manifest(root, plan_id=plan_id, stage=stage)
        payload = lineage_capability.canonical_json_bytes(manifest)
    _publish_exact_existing(root, output_path, payload)
    return manifest


def compare_protected_manifest_paths(
    before_path: Path, after_path: Path, *, require_exact: bool
) -> str:
    if not require_exact:
        raise Phase2EvidenceError("protected manifest comparison requires exact mode")
    plan63 = before_path.name.startswith("02-63-") and after_path.name.startswith("02-63-")
    plan64 = before_path.name.startswith("02-64-") and after_path.name.startswith("02-64-")
    before = cast(
        dict[str, object],
        _load_canonical_mapping(before_path, trailing_newline=plan63 or plan64),
    )
    after = cast(
        dict[str, object],
        _load_canonical_mapping(after_path, trailing_newline=plan63 or plan64),
    )
    if plan63:
        before_root = before_path.resolve().parents[6]
        _validate_plan63_protected_manifest(before_root, before, stage="before")
        _validate_plan63_protected_manifest(before_root, after, stage="after")
        comparable_before = {
            key: value
            for key, value in before.items()
            if key not in {"stage", "protected_manifest_sha256"}
        }
        comparable_after = {
            key: value
            for key, value in after.items()
            if key not in {"stage", "protected_manifest_sha256"}
        }
        if comparable_before != comparable_after:
            raise Phase2EvidenceError("Plan 63 protected manifests are not exact equal")
        return "EXACT_EQUAL"
    if plan64:
        before_root = before_path.resolve().parents[6]
        _validate_plan64_protected_manifest(before_root, before, stage="before")
        _validate_plan64_protected_manifest(before_root, after, stage="after")
        comparable_before = {
            key: value
            for key, value in before.items()
            if key not in {"stage", "protected_manifest_sha256"}
        }
        comparable_after = {
            key: value
            for key, value in after.items()
            if key not in {"stage", "protected_manifest_sha256"}
        }
        if comparable_before != comparable_after:
            raise Phase2EvidenceError("Plan 64 protected manifests are not exact equal")
        return "EXACT_EQUAL"
    try:
        return lineage_capability.compare_protected_manifests(before, after)
    except FingerprintError as exc:
        raise Phase2EvidenceError(str(exc)) from exc


def _module_argv(module: str, *arguments: str) -> list[str]:
    executable = Path(sys.executable)
    stable_python3 = executable.with_name("python3")
    interpreter = stable_python3 if stable_python3.is_file() else executable
    return [str(interpreter), "-m", module, *arguments]


def _pytest_argv(*targets: str) -> list[str]:
    executable = Path(sys.executable)
    stable_python3 = executable.with_name("python3")
    interpreter = stable_python3 if stable_python3.is_file() else executable
    return [str(interpreter), "-m", "pytest", *targets, "-q"]


def _plan20_bundle_path(root: Path) -> Path:
    summary = (root / PHASE_RELATIVE / "02-20-SUMMARY.md").read_text(encoding="utf-8")
    match = re.search(r"^catalog_adjudication_bundle_path:\s*(\S+)\s*$", summary, re.M)
    if match is None:
        raise Phase2EvidenceError("Plan 20 adjudication bundle pointer is missing")
    path = root / match.group(1)
    if not path.is_file():
        raise Phase2EvidenceError("Plan 20 adjudication bundle is missing")
    return path


def _plan54_bridge_path(root: Path) -> Path:
    raw = json.loads(
        (
            root / "artifacts/catalog/contest-use-official-public-data-v1/closure-result.json"
        ).read_text(encoding="utf-8")
    )
    if not isinstance(raw, dict):
        raise Phase2EvidenceError("Plan 54 closure result must be a JSON object")
    closure = cast(dict[str, object], raw)
    relative = closure.get("bridge_directory")
    if not isinstance(relative, str):
        raise Phase2EvidenceError("Plan 54 bridge pointer is missing")
    path = root / relative
    if not path.is_dir():
        raise Phase2EvidenceError("Plan 54 bridge directory is missing")
    return path


def _matrix_command_registry(
    root: Path,
    *,
    source_audit_successor: Path,
    lineage_successor: Path,
    rights_current_parent: Path,
    activation_current_parent: Path,
) -> dict[str, list[tuple[str, list[str], dict[str, str]]]]:
    predecessor_lineage = root / lineage_capability.PREDECESSOR_TARGET
    rights = root / "artifacts/restricted/catalog/v2/rights/rights-projection.json"
    objective = root / "artifacts/restricted/catalog/v2/audit/candidate-objective-evidence.json"
    event = root / ACTIVATION_EVENT_RELATIVE
    old_audit = root / PREDECESSOR_SOURCE_AUDIT_RELATIVE
    old_index = root / PREDECESSOR_EVIDENCE_INDEX_RELATIVE
    p60_before = root / (
        "artifacts/restricted/catalog/v2/release/gap-closure-guards/02-60-protected-before.json"
    )
    p60_after = p60_before.with_name("02-60-protected-after.json")
    p61_before = p60_before.with_name("02-61-protected-before.json")
    p61_after = p60_before.with_name("02-61-protected-after.json")
    p62_before = p60_before.with_name("02-62-protected-before.json")
    closure = root / "artifacts/catalog/contest-use-official-public-data-v1/closure-result.json"
    bridge = _plan54_bridge_path(root)
    adjudication = _plan20_bundle_path(root)
    sqlite_receipt = root / SQLITE_ROOT_RELATIVE / SQLITE_SEAL_RECEIPT_NAME
    sqlite_state = root / SQLITE_ROOT_RELATIVE / "seal-state-attestation.json"
    final_audit = root / FINAL_AUDIT_RELATIVE
    equivalence = root / LINEAGE_RELATIVE / "historical-verification-equivalence.json"
    equivalence_evidence = root / LINEAGE_RELATIVE / "historical-verification-evidence.json"
    transition = cast(
        Mapping[str, object],
        _load_canonical_mapping(old_index)["requirements_transition"],
    )
    sandbox_environment = {
        "ITDA_EXTERNAL_NETWORK_DENIAL_POLICY_SHA256": _sha256_bytes(
            NETWORK_DENIAL_POLICY.encode("utf-8")
        )
    }
    sandbox_prefix = ["/usr/bin/sandbox-exec", "-p", NETWORK_DENIAL_POLICY]
    registry: dict[str, list[tuple[str, list[str], dict[str, str]]]] = {
        "A": [
            (
                "A-tests-lineage-rights",
                _pytest_argv(
                    "tests/security/test_catalog_v1_lineage_successor.py",
                    "tests/security/test_catalog_rights_v2.py",
                ),
                {},
            ),
            (
                "A-lineage-diagnose-successor",
                _module_argv(
                    "itda.cli.fingerprint_catalog_v1",
                    "--diagnose-successor",
                    str(predecessor_lineage),
                ),
                {},
            ),
            (
                "A-lineage-verify-successor",
                _module_argv(
                    "itda.cli.fingerprint_catalog_v1",
                    "--verify-successor",
                    str(lineage_successor),
                    "--predecessor",
                    str(predecessor_lineage),
                ),
                {},
            ),
            (
                "A-rights-check-current-bundle",
                _module_argv(
                    "itda.cli.project_catalog_rights_v2",
                    "--check-current-bundle",
                    str(rights_current_parent),
                    "--lineage-successor",
                    str(lineage_successor),
                    "--rights",
                    str(rights),
                    "--objective-evidence",
                    str(objective),
                ),
                {},
            ),
        ],
        "B": [
            (
                "B-tests-activation",
                _pytest_argv(
                    "tests/security/test_catalog_activation.py",
                    "tests/security/test_catalog_activation_current_parent.py",
                ),
                {},
            ),
            (
                "B-activation-diagnose-current-parent",
                _module_argv(
                    "itda.cli.verify_catalog_activation_current_parent",
                    "--diagnose-current-parent",
                    str(event),
                    "--historical-proof-commit",
                    "788d79a",
                ),
                {},
            ),
            (
                "B-activation-verify-current-parent",
                _module_argv(
                    "itda.cli.verify_catalog_activation_current_parent",
                    "--verify-current-parent-attestation",
                    str(activation_current_parent),
                    "--event",
                    str(event),
                    "--require-current",
                    "--protected-before",
                    str(p61_before),
                    "--protected-after",
                    str(p61_after),
                ),
                {},
            ),
        ],
        "C": [
            (
                "C-tests-source-current-rejections",
                _pytest_argv(
                    "tests/security/test_phase2_evidence.py::test_published_source_audit_survives_normal_roadmap_closeout",
                    "tests/security/test_phase2_evidence.py::test_source_audit_successor_rejects_broad_or_unowned_grammar_migration",
                    "tests/security/test_phase2_evidence.py::test_historical_source_audit_predecessor_remains_strict",
                    "tests/security/test_phase2_evidence.py::test_current_evidence_index_rejects_missing_owner_or_matrix_shard",
                    "tests/security/test_phase2_evidence.py::test_current_phase2_acceptance_requires_exact_guards_and_original_data08",
                    "tests/security/test_phase2_evidence.py::test_current_checkout_requires_v1_lineage_successor",
                    "tests/security/test_phase2_evidence.py::test_current_checkout_requires_rights_current_parent_attestation",
                    "tests/security/test_phase2_evidence.py::test_current_checkout_requires_source_audit_successor",
                ),
                {},
            )
        ],
        "D": [
            (
                "D-tests-plans-51-53",
                _pytest_argv(
                    "tests/pipeline/test_catalog_optional_media.py",
                    "tests/security/test_catalog_optional_media_security.py",
                    "tests/pipeline/test_catalog_optional_media_frontier.py",
                    "tests/security/test_catalog_optional_media_frontier_security.py",
                    "tests/pipeline/test_catalog_optional_media_closure.py",
                    "tests/security/test_catalog_optional_media_closure_security.py",
                ),
                {},
            )
        ],
        "E": [
            (
                "E-tests-plan55-54-20",
                _pytest_argv(
                    "tests/pipeline/test_catalog_contest_profile.py",
                    "tests/security/test_catalog_contest_profile_security.py",
                    "tests/security/test_catalog_v2_adjudication.py",
                    "tests/security/test_phase2_authority.py",
                ),
                {},
            ),
            (
                "E-plan54-verify-success",
                sandbox_prefix
                + _module_argv(
                    "itda.cli.build_catalog_v2_review",
                    "--verify-plan54-success",
                    str(closure),
                ),
                sandbox_environment,
            ),
            (
                "E-plan54-verify-materialized-bridge",
                sandbox_prefix
                + _module_argv(
                    "itda.cli.build_catalog_v2_review",
                    "--verify-materialized-bundle",
                    str(bridge),
                ),
                sandbox_environment,
            ),
            (
                "E-plan20-verify-adjudication-bundle",
                _module_argv(
                    "itda.cli.build_catalog_v2_review",
                    "--verify-adjudication-bundle",
                    str(adjudication),
                ),
                {},
            ),
        ],
        "F1": [
            (
                "F1-tests-sqlite-history-empty-init",
                _pytest_argv(
                    "tests/security/test_sqlite_supersession_history.py",
                    "tests/security/test_sqlite_empty_projection.py",
                    "tests/integration/test_sqlite_manifest_initialization.py",
                ),
                {},
            )
        ],
        "F2": [
            (
                "F2-tests-sqlite-filesystem-authority-leakage",
                _pytest_argv(
                    "tests/security/test_sqlite_manifest_filesystem.py",
                    "tests/security/test_sqlite_manifest_authority.py",
                    "tests/security/test_sqlite_manifest_leakage.py",
                ),
                {},
            )
        ],
        "F3": [
            (
                "F3-tests-sqlite-seal",
                _pytest_argv("tests/integration/test_sqlite_manifest_seal.py"),
                {},
            )
        ],
        "G": [
            (
                "G-tests-final-audit-leakage",
                _pytest_argv(
                    "tests/pipeline/test_catalog_v2_audit_exports.py",
                    "tests/security/test_catalog_v2_audit_security.py",
                    "tests/security/test_phase2_artifact_leakage.py",
                ),
                {},
            ),
            (
                "G-final-audit-verify",
                _module_argv(
                    "itda.cli.export_catalog_v2_audit",
                    "--verify",
                    str(final_audit),
                    "--sqlite-seal-receipt",
                    str(sqlite_receipt),
                ),
                {},
            ),
        ],
        "H": [
            (
                "H-historical-verify-equivalence",
                _module_argv(
                    "itda.cli.verify_historical_phase2",
                    "--verify-equivalence",
                    str(equivalence),
                    "--evidence",
                    str(equivalence_evidence),
                ),
                {},
            ),
            (
                "H-historical-replay-equivalence",
                _module_argv(
                    "itda.cli.verify_historical_phase2",
                    "--replay-equivalence",
                    str(equivalence),
                    "--evidence",
                    str(equivalence_evidence),
                ),
                {},
            ),
            (
                "H-original-evidence-index",
                _module_argv(
                    "itda.cli.verify_phase2_evidence",
                    "--verify-evidence-index",
                    str(old_index),
                    "--verify-sqlite-receipt",
                    str(sqlite_receipt),
                    "--sqlite-authority-root",
                    str(root / SQLITE_ROOT_RELATIVE),
                    "--verify-sqlite-supersession-history",
                ),
                {},
            ),
            (
                "H-original-requirements-acceptance",
                _module_argv(
                    "itda.cli.verify_phase2_evidence",
                    "--verify-requirements-acceptance",
                    str(root / REQUIREMENTS_RELATIVE),
                    "--evidence-index",
                    str(old_index),
                    "--expected-timestamp",
                    str(transition["acceptance_timestamp"]),
                    "--expected-note",
                    str(transition["acceptance_note"]),
                ),
                {},
            ),
            (
                "H-source-audit-successor",
                _module_argv(
                    "itda.cli.verify_phase2_evidence",
                    "--verify-source-audit-successor",
                    str(source_audit_successor),
                    "--predecessor-source-audit",
                    str(old_audit),
                    "--predecessor-evidence-index",
                    str(old_index),
                ),
                {},
            ),
            (
                "H-sqlite-seal-receipt",
                _module_argv(
                    "itda.cli.manage_sqlite_manifest",
                    "--verify-seal-receipt",
                    str(sqlite_receipt),
                    "--state",
                    str(sqlite_state),
                ),
                {},
            ),
            (
                "H-lineage-successor",
                _module_argv(
                    "itda.cli.fingerprint_catalog_v1",
                    "--verify-successor",
                    str(lineage_successor),
                    "--predecessor",
                    str(predecessor_lineage),
                ),
                {},
            ),
            (
                "H-rights-current-parent",
                _module_argv(
                    "itda.cli.project_catalog_rights_v2",
                    "--check-current-bundle",
                    str(rights_current_parent),
                    "--lineage-successor",
                    str(lineage_successor),
                    "--rights",
                    str(rights),
                    "--objective-evidence",
                    str(objective),
                ),
                {},
            ),
            (
                "H-activation-current-parent",
                _module_argv(
                    "itda.cli.verify_catalog_activation_current_parent",
                    "--verify-current-parent-attestation",
                    str(activation_current_parent),
                    "--event",
                    str(event),
                    "--require-current",
                    "--protected-before",
                    str(p61_before),
                    "--protected-after",
                    str(p61_after),
                ),
                {},
            ),
            (
                "H-current-evidence-inputs",
                _module_argv(
                    "itda.cli.verify_phase2_evidence",
                    "--verify-current-evidence-inputs",
                    "--source-audit-successor",
                    str(source_audit_successor),
                    "--lineage-successor",
                    str(lineage_successor),
                    "--rights-current-parent",
                    str(rights_current_parent),
                    "--activation-current-parent",
                    str(activation_current_parent),
                    "--plan60-protected-before",
                    str(p60_before),
                    "--plan60-protected-after",
                    str(p60_after),
                    "--plan61-protected-before",
                    str(p61_before),
                    "--plan61-protected-after",
                    str(p61_after),
                    "--plan62-protected-before",
                    str(p62_before),
                ),
                {},
            ),
        ],
    }
    if tuple(registry) != ("A", "B", "C", "D", "E", "F1", "F2", "F3", "G", "H"):
        raise Phase2EvidenceError("verification matrix shard registry drifted")
    command_ids = [command_id for commands in registry.values() for command_id, _, _ in commands]
    if len(command_ids) != len(set(command_ids)):
        raise Phase2EvidenceError("verification matrix command ID is duplicated")
    return registry


def _argv_hash(argv: Sequence[str]) -> str:
    return _sha256_bytes(canonical_json_bytes(list(argv)))


def run_final_verification_matrix(
    repo_root: Path,
    output_path: Path,
    *,
    source_audit_successor: Path,
    lineage_successor: Path,
    rights_current_parent: Path,
    activation_current_parent: Path,
    per_shard_timeout_seconds: int,
    overall_timeout_seconds: int,
) -> dict[str, object]:
    root = repo_root.resolve(strict=True)
    if not 1 <= per_shard_timeout_seconds <= 600 or not 1 <= overall_timeout_seconds <= 3600:
        raise Phase2EvidenceError("verification matrix timeout exceeds the closed bound")
    if per_shard_timeout_seconds > overall_timeout_seconds:
        raise Phase2EvidenceError("verification matrix timeout ordering is invalid")
    registry = _matrix_command_registry(
        root,
        source_audit_successor=source_audit_successor,
        lineage_successor=lineage_successor,
        rights_current_parent=rights_current_parent,
        activation_current_parent=activation_current_parent,
    )
    command_spec = [
        {"shard_id": shard, "command_id": command_id, "argv_sha256": _argv_hash(argv)}
        for shard, commands in registry.items()
        for command_id, argv, _ in commands
    ]
    expected_command_set_sha256 = _sha256_bytes(canonical_json_bytes(command_spec))
    if output_path.exists():
        recorded = cast(dict[str, object], _load_canonical_mapping(output_path))
        _validate_matrix_receipt(recorded)
        if recorded.get("command_set_sha256") != expected_command_set_sha256:
            raise Phase2EvidenceError("existing verification matrix command set drifted")
        if recorded.get("per_shard_timeout_seconds") != per_shard_timeout_seconds:
            raise Phase2EvidenceError("existing verification matrix shard timeout drifted")
        if recorded.get("overall_timeout_seconds") != overall_timeout_seconds:
            raise Phase2EvidenceError("existing verification matrix overall timeout drifted")
        _ensure_private_untracked(root, output_path)
        return recorded
    started = time.monotonic()
    rows: list[dict[str, object]] = []
    shard_rows: list[dict[str, object]] = []
    for shard_id, commands in registry.items():
        shard_started = time.monotonic()
        for command_id, argv, extra_environment in commands:
            elapsed = time.monotonic() - started
            shard_elapsed = time.monotonic() - shard_started
            remaining = min(
                overall_timeout_seconds - elapsed,
                per_shard_timeout_seconds - shard_elapsed,
            )
            if remaining <= 0:
                raise Phase2EvidenceError(f"verification matrix shard {shard_id} timed out")
            command_started = time.monotonic()
            environment = os.environ.copy()
            environment.update(extra_environment)
            try:
                completed = subprocess.run(
                    argv,
                    cwd=root / "backend",
                    check=False,
                    capture_output=True,
                    timeout=remaining,
                    env=environment,
                )
            except subprocess.TimeoutExpired as exc:
                raise Phase2EvidenceError(
                    f"verification matrix command {command_id} timed out"
                ) from exc
            duration_ms = int((time.monotonic() - command_started) * 1000)
            if completed.returncode != 0:
                raise Phase2EvidenceError(
                    f"verification matrix command {command_id} failed with "
                    f"exit {completed.returncode}; stdout={_sha256_bytes(completed.stdout)}; "
                    f"stderr={_sha256_bytes(completed.stderr)}"
                )
            output = completed.stdout + b"\n" + completed.stderr
            passed_matches = re.findall(rb"(\d+) passed", output)
            test_count = sum(int(value) for value in passed_matches)
            rows.append(
                {
                    "shard_id": shard_id,
                    "command_id": command_id,
                    "argv_sha256": _argv_hash(argv),
                    "duration_ms": duration_ms,
                    "duration_within_bound": duration_ms <= per_shard_timeout_seconds * 1000,
                    "exit_code": 0,
                    "status": "PASS",
                    "test_count": test_count,
                    "stdout_sha256": _sha256_bytes(completed.stdout),
                    "stderr_sha256": _sha256_bytes(completed.stderr),
                }
            )
        shard_duration_ms = int((time.monotonic() - shard_started) * 1000)
        if shard_duration_ms > per_shard_timeout_seconds * 1000:
            raise Phase2EvidenceError(f"verification matrix shard {shard_id} exceeded its bound")
        shard_rows.append(
            {
                "shard_id": shard_id,
                "status": "PASS",
                "command_count": len(commands),
                "duration_ms": shard_duration_ms,
                "duration_within_bound": True,
            }
        )
    total_duration_ms = int((time.monotonic() - started) * 1000)
    if total_duration_ms > overall_timeout_seconds * 1000:
        raise Phase2EvidenceError("verification matrix exceeded its overall bound")
    payload: dict[str, object] = {
        "schema_version": VERIFICATION_MATRIX_SCHEMA_VERSION,
        "status": "PASS",
        "all_required_passed": True,
        "per_shard_timeout_seconds": per_shard_timeout_seconds,
        "overall_timeout_seconds": overall_timeout_seconds,
        "total_duration_ms": total_duration_ms,
        "total_duration_within_bound": True,
        "required_shard_ids": list(registry),
        "semantic_exact_rejection_node_ids": [
            "test_current_checkout_requires_v1_lineage_successor",
            "test_current_checkout_requires_rights_current_parent_attestation",
            "test_current_checkout_requires_source_audit_successor",
        ],
        "command_set_sha256": expected_command_set_sha256,
        "shards": shard_rows,
        "commands": rows,
        "verification_matrix_sha256": "",
    }
    payload["verification_matrix_sha256"] = _self_hash(payload, "verification_matrix_sha256")
    _assert_sanitized(payload)
    _publish_exact_existing(root, output_path, canonical_json_bytes(payload))
    return payload


def _matrix_command_registry_v2(
    root: Path,
    *,
    source_audit_closeout_successor: Path,
) -> dict[str, list[tuple[str, list[str], dict[str, str]]]]:
    root = root.resolve(strict=True)
    predecessor = _matrix_command_registry(
        root,
        source_audit_successor=root / SOURCE_AUDIT_SUCCESSOR_RELATIVE,
        lineage_successor=root / LINEAGE_SUCCESSOR_RELATIVE,
        rights_current_parent=root / RIGHTS_CURRENT_PARENT_RELATIVE,
        activation_current_parent=root / ACTIVATION_CURRENT_PARENT_RELATIVE,
    )
    registry = {
        shard: [
            (command_id, list(argv), dict(environment)) for command_id, argv, environment in rows
        ]
        for shard, rows in predecessor.items()
    }
    _restore_matrix_v1_receipt_argv(root, registry)
    focused = _pytest_argv(
        "tests/security/test_phase2_evidence.py::test_closeout_matrix_v2_migrates_only_two_commands_and_adds_hostile_suite",
        "tests/security/test_phase2_evidence.py::test_closeout_evidence_index_rejects_stale_parent_or_guard",
        "tests/security/test_phase2_evidence.py::test_closeout_phase2_acceptance_requires_four_exact_guard_pairs",
        "tests/security/test_phase2_evidence.py::test_closeout_composition_is_membership_free_and_requirements_immutable",
    )
    registry["C"].append(("C-tests-hostile-closeout-stability", focused, {}))
    replacements = {
        "H-source-audit-successor": _module_argv(
            "itda.cli.verify_phase2_evidence",
            "--verify-source-audit-closeout-successor",
            str(source_audit_closeout_successor),
        ),
        "H-current-evidence-inputs": _module_argv(
            "itda.cli.verify_phase2_evidence",
            "--verify-closeout-evidence-inputs",
            "--source-audit-closeout-successor",
            str(source_audit_closeout_successor),
        ),
    }
    changed: list[str] = []
    for position, (command_id, _argv, environment) in enumerate(registry["H"]):
        if command_id in replacements:
            registry["H"][position] = (command_id, replacements[command_id], environment)
            changed.append(command_id)
    if changed != ["H-source-audit-successor", "H-current-evidence-inputs"]:
        raise Phase2EvidenceError("matrix v2 source/current-input migration drifted")
    return registry


def _matrix_spec(
    registry: Mapping[str, Sequence[tuple[str, list[str], dict[str, str]]]],
) -> list[dict[str, str]]:
    return [
        {"shard_id": shard, "command_id": command_id, "argv_sha256": _argv_hash(argv)}
        for shard, commands in registry.items()
        for command_id, argv, _ in commands
    ]


def _restore_matrix_v1_receipt_argv(
    root: Path,
    registry: Mapping[str, Sequence[tuple[str, list[str], dict[str, str]]]],
) -> None:
    relative_current_inputs = (
        SOURCE_AUDIT_SUCCESSOR_RELATIVE,
        LINEAGE_SUCCESSOR_RELATIVE,
        RIGHTS_CURRENT_PARENT_RELATIVE,
        ACTIVATION_CURRENT_PARENT_RELATIVE,
    )
    replacements = {str(root / relpath): f"../{relpath}" for relpath in relative_current_inputs}
    for commands in registry.values():
        for _command_id, argv, _environment in commands:
            argv[:] = [replacements.get(argument, argument) for argument in argv]


def _matrix_v2_migration(
    root: Path,
    registry: Mapping[str, Sequence[tuple[str, list[str], dict[str, str]]]],
    *,
    predecessor_matrix: Path,
) -> dict[str, object]:
    root = root.resolve(strict=True)
    if _sha256_path(predecessor_matrix) != PREDECESSOR_VERIFICATION_MATRIX_FILE_SHA256:
        raise Phase2EvidenceError("verification matrix v1 predecessor file drifted")
    recorded = _load_canonical_mapping(predecessor_matrix)
    _validate_matrix_receipt(recorded)
    predecessor_registry = _matrix_command_registry(
        root,
        source_audit_successor=root / SOURCE_AUDIT_SUCCESSOR_RELATIVE,
        lineage_successor=root / LINEAGE_SUCCESSOR_RELATIVE,
        rights_current_parent=root / RIGHTS_CURRENT_PARENT_RELATIVE,
        activation_current_parent=root / ACTIVATION_CURRENT_PARENT_RELATIVE,
    )
    _restore_matrix_v1_receipt_argv(root, predecessor_registry)
    predecessor_spec = _matrix_spec(predecessor_registry)
    if recorded.get("command_set_sha256") != _sha256_bytes(canonical_json_bytes(predecessor_spec)):
        raise Phase2EvidenceError("verification matrix v1 command registry drifted")
    current_spec = _matrix_spec(registry)
    old_by_id = {row["command_id"]: row for row in predecessor_spec}
    new_by_id = {row["command_id"]: row for row in current_spec}
    changed_ids = [
        command_id for command_id in old_by_id if old_by_id[command_id] != new_by_id.get(command_id)
    ]
    added_ids = [command_id for command_id in new_by_id if command_id not in old_by_id]
    if changed_ids != ["H-source-audit-successor", "H-current-evidence-inputs"] or added_ids != [
        "C-tests-hostile-closeout-stability"
    ]:
        raise Phase2EvidenceError("verification matrix v2 migration is broader than approved")
    migration_rows = [
        {
            "command_id": command_id,
            "predecessor_argv_sha256": old_by_id[command_id]["argv_sha256"],
            "successor_argv_sha256": new_by_id[command_id]["argv_sha256"],
        }
        for command_id in changed_ids
    ]
    return {
        "changed_command_ids": changed_ids,
        "added_command_ids": added_ids,
        "rows": migration_rows,
        "migration_root_sha256": _sha256_bytes(canonical_json_bytes(migration_rows)),
        "predecessor_file_sha256": _sha256_path(predecessor_matrix),
        "predecessor_self_sha256": recorded["verification_matrix_sha256"],
        "predecessor_command_set_sha256": recorded["command_set_sha256"],
    }


def _validate_matrix_v2_receipt(
    payload: Mapping[str, object],
    *,
    expected_command_spec: Sequence[Mapping[str, str]],
) -> None:
    expected_spec = [dict(row) for row in expected_command_spec]
    expected_command_set_sha256 = _sha256_bytes(canonical_json_bytes(expected_spec))
    if (
        payload.get("schema_version") != FINAL_VERIFICATION_MATRIX_V2_SCHEMA_VERSION
        or payload.get("status") != "PASS"
        or payload.get("all_required_passed") is not True
        or payload.get("verification_matrix_sha256")
        != _self_hash(payload, "verification_matrix_sha256")
        or payload.get("required_shard_ids")
        != ["A", "B", "C", "D", "E", "F1", "F2", "F3", "G", "H"]
        or payload.get("per_shard_timeout_seconds") != 600
        or payload.get("overall_timeout_seconds") != 3600
    ):
        raise Phase2EvidenceError("verification matrix v2 schema or status drifted")
    if payload.get("command_set_sha256") != expected_command_set_sha256:
        raise Phase2EvidenceError("verification matrix v2 command set drifted")
    commands = payload.get("commands")
    shards = payload.get("shards")
    if not isinstance(commands, list) or len(commands) != 29 or not isinstance(shards, list):
        raise Phase2EvidenceError("verification matrix v2 command cardinality drifted")
    if any(
        not isinstance(row, dict)
        or row.get("status") != "PASS"
        or row.get("exit_code") != 0
        or row.get("duration_within_bound") is not True
        for row in commands
    ):
        raise Phase2EvidenceError("verification matrix v2 contains a failed command")
    recorded_spec = [
        {
            "shard_id": row.get("shard_id"),
            "command_id": row.get("command_id"),
            "argv_sha256": row.get("argv_sha256"),
        }
        for row in cast(list[dict[str, object]], commands)
    ]
    if recorded_spec != expected_spec:
        raise Phase2EvidenceError("verification matrix v2 command rows drifted")
    migration = payload.get("migration")
    if (
        not isinstance(migration, dict)
        or migration.get("changed_command_ids")
        != ["H-source-audit-successor", "H-current-evidence-inputs"]
        or migration.get("added_command_ids") != ["C-tests-hostile-closeout-stability"]
    ):
        raise Phase2EvidenceError("verification matrix v2 migration drifted")
    _assert_closeout_privacy(payload)


def run_final_verification_matrix_v2(
    repo_root: Path,
    output_path: Path,
    *,
    source_audit_closeout_successor: Path,
    predecessor_verification_matrix: Path,
    per_shard_timeout_seconds: int,
    overall_timeout_seconds: int,
) -> dict[str, object]:
    root = repo_root.resolve(strict=True)
    if per_shard_timeout_seconds != 600 or overall_timeout_seconds != 3600:
        raise Phase2EvidenceError("verification matrix v2 requires exact timeout bounds")
    verify_source_audit_closeout_successor(root, source_audit_closeout_successor)
    registry = _matrix_command_registry_v2(
        root, source_audit_closeout_successor=source_audit_closeout_successor
    )
    migration = _matrix_v2_migration(
        root, registry, predecessor_matrix=predecessor_verification_matrix
    )
    command_spec = _matrix_spec(registry)
    command_set_sha256 = _sha256_bytes(canonical_json_bytes(command_spec))
    if output_path.exists():
        recorded = _load_canonical_mapping(output_path)
        _validate_matrix_v2_receipt(recorded, expected_command_spec=command_spec)
        _ensure_private_untracked(root, output_path)
        return recorded
    started = time.monotonic()
    command_rows: list[dict[str, object]] = []
    shard_rows: list[dict[str, object]] = []
    for shard_id, commands in registry.items():
        shard_started = time.monotonic()
        for command_id, argv, extra_environment in commands:
            overall_remaining = overall_timeout_seconds - (time.monotonic() - started)
            if overall_remaining <= 0:
                raise Phase2EvidenceError("verification matrix v2 overall timeout exceeded")
            environment = os.environ.copy()
            environment.update(extra_environment)
            command_started = time.monotonic()
            try:
                completed = subprocess.run(
                    argv,
                    cwd=root / "backend",
                    check=False,
                    capture_output=True,
                    timeout=min(600, overall_remaining),
                    env=environment,
                )
            except subprocess.TimeoutExpired as exc:
                raise Phase2EvidenceError(
                    f"verification matrix v2 command {command_id} timed out"
                ) from exc
            duration_ms = int((time.monotonic() - command_started) * 1000)
            if completed.returncode != 0:
                raise Phase2EvidenceError(
                    f"verification matrix v2 command {command_id} failed with exit "
                    f"{completed.returncode}; stdout={_sha256_bytes(completed.stdout)}; "
                    f"stderr={_sha256_bytes(completed.stderr)}"
                )
            output = completed.stdout + b"\n" + completed.stderr
            command_rows.append(
                {
                    "shard_id": shard_id,
                    "command_id": command_id,
                    "argv_sha256": _argv_hash(argv),
                    "duration_ms": duration_ms,
                    "duration_within_bound": duration_ms <= 600_000,
                    "exit_code": 0,
                    "status": "PASS",
                    "test_count": sum(int(value) for value in re.findall(rb"(\d+) passed", output)),
                    "stdout_sha256": _sha256_bytes(completed.stdout),
                    "stderr_sha256": _sha256_bytes(completed.stderr),
                }
            )
        shard_duration_ms = int((time.monotonic() - shard_started) * 1000)
        shard_rows.append(
            {
                "shard_id": shard_id,
                "status": "PASS",
                "command_count": len(commands),
                "duration_ms": shard_duration_ms,
                "duration_within_bound": all(
                    row["duration_within_bound"]
                    for row in command_rows
                    if row["shard_id"] == shard_id
                ),
            }
        )
    total_duration_ms = int((time.monotonic() - started) * 1000)
    if total_duration_ms > 3_600_000:
        raise Phase2EvidenceError("verification matrix v2 overall timeout exceeded")
    payload: dict[str, object] = {
        "schema_version": FINAL_VERIFICATION_MATRIX_V2_SCHEMA_VERSION,
        "status": "PASS",
        "all_required_passed": True,
        "per_shard_timeout_seconds": 600,
        "overall_timeout_seconds": 3600,
        "total_duration_ms": total_duration_ms,
        "total_duration_within_bound": True,
        "required_shard_ids": list(registry),
        "semantic_exact_rejection_node_ids": [
            "test_current_checkout_requires_v1_lineage_successor",
            "test_current_checkout_requires_rights_current_parent_attestation",
            "test_current_checkout_requires_source_audit_successor",
        ],
        "source_audit_closeout_successor_file_sha256": _sha256_path(
            source_audit_closeout_successor
        ),
        "migration": migration,
        "command_set_sha256": command_set_sha256,
        "shards": shard_rows,
        "commands": command_rows,
        "verification_matrix_sha256": "",
    }
    payload["verification_matrix_sha256"] = _self_hash(payload, "verification_matrix_sha256")
    _validate_matrix_v2_receipt(payload, expected_command_spec=command_spec)
    _publish_exact_existing(root, output_path, canonical_json_bytes(payload))
    return payload


def verify_final_verification_matrix_v2_receipt(
    repo_root: Path,
    matrix_path: Path,
    *,
    source_audit_closeout_successor: Path,
    predecessor_verification_matrix: Path,
) -> dict[str, object]:
    root = repo_root.resolve(strict=True)
    source = _load_canonical_mapping(source_audit_closeout_successor)
    _validate_closeout_source_audit_payload(source)
    _ensure_private_untracked(root, source_audit_closeout_successor)
    registry = _matrix_command_registry_v2(
        root, source_audit_closeout_successor=source_audit_closeout_successor
    )
    expected_spec = _matrix_spec(registry)
    expected_migration = _matrix_v2_migration(
        root, registry, predecessor_matrix=predecessor_verification_matrix
    )
    recorded = _load_canonical_mapping(matrix_path)
    _validate_matrix_v2_receipt(recorded, expected_command_spec=expected_spec)
    if recorded.get("migration") != expected_migration:
        raise Phase2EvidenceError("verification matrix v2 predecessor migration drifted")
    if recorded.get("source_audit_closeout_successor_file_sha256") != _sha256_path(
        source_audit_closeout_successor
    ):
        raise Phase2EvidenceError("verification matrix v2 source binding drifted")
    _ensure_private_untracked(root, matrix_path)
    return cast(dict[str, object], recorded)


CLOSEOUT_OWNER_NAMES = (
    "predecessor-current-evidence-and-original-data08",
    "closeout-stable-source-audit",
    "fresh-verification-matrix-v2",
    "lineage-successor",
    "rights-current-parent",
    "activation-current-parent",
    "sqlite-seal-and-final-audit",
    "prior-three-guard-pairs",
    "plan63-protected-before",
)


def _assert_closeout_privacy(payload: object) -> None:
    try:
        _assert_sanitized(payload)
    except Phase2EvidenceError:
        raise
    forbidden_keys = {
        "membership_ids",
        "ordered_place_ids",
        "dev_members",
        "blind_members",
        "member_rows",
        "per_member_digests",
        "populated_database_path",
        "database_uri",
        "raw_authority",
        "raw_nonce",
        "raw_token",
        "credentials",
    }

    def walk(value: object) -> None:
        if isinstance(value, dict):
            for key, child in value.items():
                if key.casefold() in forbidden_keys:
                    raise Phase2EvidenceError("closeout evidence contains a forbidden field")
                walk(child)
        elif isinstance(value, list):
            for child in value:
                walk(child)

    walk(payload)


def _validate_current_evidence_predecessor(payload: Mapping[str, object]) -> None:
    try:
        validate_current_evidence_payload(payload, require_after_guard=False)
    except Phase2EvidenceError as exc:
        raise Phase2EvidenceError("current-evidence v2 predecessor drifted") from exc


def _verify_plan63_before_guard(root: Path, path: Path) -> dict[str, object]:
    guard = _load_canonical_mapping(path)
    _validate_plan63_protected_manifest(root, guard, stage="before")
    return {
        "plan_id": "02-63",
        "before_file_sha256": _sha256_path(path),
        "protected_set_sha256": guard["protected_set_sha256"],
        "status": "PASS",
    }


def verify_closeout_evidence_inputs(
    repo_root: Path,
    *,
    source_audit_closeout_successor: Path,
    plan63_protected_before: Path,
) -> dict[str, object]:
    root = repo_root.resolve(strict=True)
    source = verify_source_audit_closeout_successor(root, source_audit_closeout_successor)
    predecessor_path = root / CURRENT_EVIDENCE_RELATIVE
    if _sha256_path(predecessor_path) != PREDECESSOR_CURRENT_EVIDENCE_FILE_SHA256:
        raise Phase2EvidenceError("current-evidence v2 predecessor file drifted")
    predecessor = _load_canonical_mapping(predecessor_path)
    _validate_current_evidence_predecessor(predecessor)
    original_index = verify_evidence_index(root, root / PREDECESSOR_EVIDENCE_INDEX_RELATIVE)
    transition = cast(Mapping[str, object], original_index["requirements_transition"])
    requirements = verify_requirements_acceptance(
        root / REQUIREMENTS_RELATIVE,
        root / PREDECESSOR_EVIDENCE_INDEX_RELATIVE,
        expected_timestamp=cast(str, transition["acceptance_timestamp"]),
        expected_note=cast(str, transition["acceptance_note"]),
    )
    lineage_path = root / LINEAGE_SUCCESSOR_RELATIVE
    try:
        lineage = lineage_capability.verify_successor_manifest(
            root,
            root / lineage_capability.PREDECESSOR_TARGET,
            lineage_capability._load_manifest(lineage_path),
        )
    except FingerprintError as exc:
        raise Phase2EvidenceError(str(exc)) from exc
    rights_path = root / RIGHTS_CURRENT_PARENT_RELATIVE
    activation_path = root / ACTIVATION_CURRENT_PARENT_RELATIVE
    rights_result = _require_zero(
        root,
        _module_argv(
            "itda.cli.project_catalog_rights_v2",
            "--check-current-bundle",
            str(rights_path),
            "--lineage-successor",
            str(lineage_path),
            "--rights",
            str(root / "artifacts/restricted/catalog/v2/rights/rights-projection.json"),
            "--objective-evidence",
            str(root / "artifacts/restricted/catalog/v2/audit/candidate-objective-evidence.json"),
        ),
    )
    guard_root = root / "artifacts/restricted/catalog/v2/release/gap-closure-guards"
    activation_result = _require_zero(
        root,
        _module_argv(
            "itda.cli.verify_catalog_activation_current_parent",
            "--verify-current-parent-attestation",
            str(activation_path),
            "--event",
            str(root / ACTIVATION_EVENT_RELATIVE),
            "--require-current",
            "--protected-before",
            str(guard_root / "02-61-protected-before.json"),
            "--protected-after",
            str(guard_root / "02-61-protected-after.json"),
        ),
    )
    prior_guards = [
        _verify_guard_pair(
            root,
            guard_root / f"02-{plan}-protected-before.json",
            guard_root / f"02-{plan}-protected-after.json",
            plan_id=f"02-{plan}",
        )
        for plan in (60, 61, 62)
    ]
    plan63 = _verify_plan63_before_guard(root, plan63_protected_before)
    final = _final_audit(root, root / SQLITE_ROOT_RELATIVE / SQLITE_SEAL_RECEIPT_NAME)
    result: dict[str, object] = {
        "status": "PASS",
        "predecessor_current_evidence": {
            "file_sha256": _sha256_path(predecessor_path),
            "self_sha256": predecessor["current_evidence_index_sha256"],
        },
        "source_audit_closeout_successor": {
            "file_sha256": _sha256_path(source_audit_closeout_successor),
            "self_sha256": source["source_audit_closeout_successor_sha256"],
            "missing_count": 0,
        },
        "lineage_successor": {
            "file_sha256": _sha256_path(lineage_path),
            "self_sha256": lineage["successor_sha256"],
        },
        "rights_current_parent": {
            "file_sha256": _sha256_path(rights_path),
            "verifier": rights_result,
        },
        "activation_current_parent": {
            "file_sha256": _sha256_path(activation_path),
            "verifier": activation_result,
        },
        "sqlite_and_final_audit": {
            "original_evidence_index_self_sha256": original_index["evidence_index_sha256"],
            "final_audit": final,
        },
        "requirements_acceptance": requirements,
        "prior_guard_pairs": prior_guards,
        "plan63_protected_before": plan63,
    }
    _assert_closeout_privacy(result)
    return result


def _validate_closeout_evidence_payload(
    payload: Mapping[str, object], *, require_after_guard: bool
) -> None:
    if (
        payload.get("schema_version") != CLOSEOUT_EVIDENCE_SCHEMA_VERSION
        or payload.get("status") != "PASS"
        or payload.get("owner_names") != list(CLOSEOUT_OWNER_NAMES)
        or payload.get("closeout_evidence_index_sha256")
        != _self_hash(payload, "closeout_evidence_index_sha256")
    ):
        raise Phase2EvidenceError("closeout evidence schema, owners, or self hash drifted")
    transition = payload.get("requirements_transition")
    if not isinstance(transition, dict):
        raise Phase2EvidenceError("closeout evidence requirements transition drifted")
    _validate_transition_shape(transition)
    guards = payload.get("guard_evidence")
    if not isinstance(guards, list) or len(guards) != 4:
        raise Phase2EvidenceError("closeout evidence guard registry drifted")
    if require_after_guard and any(
        not isinstance(row, dict) or row.get("comparison_status") != "EXACT_EQUAL" for row in guards
    ):
        raise Phase2EvidenceError("closeout evidence guard comparison drifted")
    _assert_closeout_privacy(payload)


def _expected_closeout_evidence_index(
    root: Path,
    *,
    source_audit_closeout_successor: Path,
    verification_matrix: Path,
    predecessor_current_evidence_index: Path,
    plan63_protected_before: Path,
) -> dict[str, object]:
    if _sha256_path(predecessor_current_evidence_index) != (
        PREDECESSOR_CURRENT_EVIDENCE_FILE_SHA256
    ):
        raise Phase2EvidenceError("current-evidence v2 predecessor file drifted")
    predecessor = _load_canonical_mapping(predecessor_current_evidence_index)
    _validate_current_evidence_predecessor(predecessor)
    inputs = verify_closeout_evidence_inputs(
        root,
        source_audit_closeout_successor=source_audit_closeout_successor,
        plan63_protected_before=plan63_protected_before,
    )
    matrix = verify_final_verification_matrix_v2_receipt(
        root,
        verification_matrix,
        source_audit_closeout_successor=source_audit_closeout_successor,
        predecessor_verification_matrix=root / VERIFICATION_MATRIX_RELATIVE,
    )
    prior_guards = cast(list[dict[str, object]], inputs["prior_guard_pairs"])
    guard_rows = [*prior_guards, cast(dict[str, object], inputs["plan63_protected_before"])]
    transition = cast(dict[str, object], predecessor["requirements_transition"])
    payload: dict[str, object] = {
        "schema_version": CLOSEOUT_EVIDENCE_SCHEMA_VERSION,
        "status": "PASS",
        "owner_names": list(CLOSEOUT_OWNER_NAMES),
        "owners": inputs,
        "predecessor_current_evidence_index_sha256": _sha256_path(
            predecessor_current_evidence_index
        ),
        "requirements_transition": transition,
        "requirements_unchanged_sha256": _sha256_path(root / REQUIREMENTS_RELATIVE),
        "status_counts": {"MISSING": 0},
        "verification_matrix": {
            "file_sha256": _sha256_path(verification_matrix),
            "self_sha256": matrix["verification_matrix_sha256"],
            "command_set_sha256": matrix["command_set_sha256"],
            "required_shard_ids": matrix["required_shard_ids"],
            "all_required_passed": True,
        },
        "guard_evidence": guard_rows,
        "closeout_evidence_index_sha256": "",
    }
    payload["closeout_evidence_index_sha256"] = _self_hash(
        payload, "closeout_evidence_index_sha256"
    )
    _validate_closeout_evidence_payload(payload, require_after_guard=False)
    return payload


def build_closeout_evidence_index(
    repo_root: Path, output_path: Path, **paths: Path
) -> dict[str, object]:
    root = repo_root.resolve(strict=True)
    payload = _expected_closeout_evidence_index(root, **paths)
    _publish_exact_existing(root, output_path, canonical_json_bytes(payload))
    return payload


def verify_closeout_evidence_index(
    repo_root: Path, index_path: Path, **paths: Path
) -> dict[str, object]:
    root = repo_root.resolve(strict=True)
    recorded = _load_canonical_mapping(index_path)
    _validate_closeout_evidence_payload(recorded, require_after_guard=False)
    source_path = paths["source_audit_closeout_successor"]
    matrix_path = paths["verification_matrix"]
    predecessor_path = paths["predecessor_current_evidence_index"]
    guard_path = paths["plan63_protected_before"]
    if _sha256_path(predecessor_path) != PREDECESSOR_CURRENT_EVIDENCE_FILE_SHA256:
        raise Phase2EvidenceError("current-evidence v2 predecessor file drifted")
    predecessor = _load_canonical_mapping(predecessor_path)
    _validate_current_evidence_predecessor(predecessor)
    source = _load_canonical_mapping(source_path)
    _validate_closeout_source_audit_payload(source)
    matrix = verify_final_verification_matrix_v2_receipt(
        root,
        matrix_path,
        source_audit_closeout_successor=source_path,
        predecessor_verification_matrix=root / VERIFICATION_MATRIX_RELATIVE,
    )
    guard = _load_canonical_mapping(guard_path)
    _validate_plan63_protected_manifest(root, guard, stage="before")
    owners = recorded.get("owners")
    verification = recorded.get("verification_matrix")
    if not isinstance(owners, dict) or not isinstance(verification, dict):
        raise Phase2EvidenceError("closeout evidence binding registry is invalid")
    expected_bindings = {
        "predecessor_file": _sha256_path(predecessor_path),
        "predecessor_self": predecessor["current_evidence_index_sha256"],
        "source_file": _sha256_path(source_path),
        "source_self": source["source_audit_closeout_successor_sha256"],
        "matrix_file": _sha256_path(matrix_path),
        "matrix_self": matrix["verification_matrix_sha256"],
        "matrix_command_set": matrix["command_set_sha256"],
        "guard_file": _sha256_path(guard_path),
        "guard_set": guard["protected_set_sha256"],
        "requirements": _sha256_path(root / REQUIREMENTS_RELATIVE),
    }
    actual_bindings = {
        "predecessor_file": recorded.get("predecessor_current_evidence_index_sha256"),
        "predecessor_self": cast(
            Mapping[str, object], owners.get("predecessor_current_evidence", {})
        ).get("self_sha256"),
        "source_file": cast(
            Mapping[str, object], owners.get("source_audit_closeout_successor", {})
        ).get("file_sha256"),
        "source_self": cast(
            Mapping[str, object], owners.get("source_audit_closeout_successor", {})
        ).get("self_sha256"),
        "matrix_file": verification.get("file_sha256"),
        "matrix_self": verification.get("self_sha256"),
        "matrix_command_set": verification.get("command_set_sha256"),
        "guard_file": cast(Mapping[str, object], owners.get("plan63_protected_before", {})).get(
            "before_file_sha256"
        ),
        "guard_set": cast(Mapping[str, object], owners.get("plan63_protected_before", {})).get(
            "protected_set_sha256"
        ),
        "requirements": recorded.get("requirements_unchanged_sha256"),
    }
    if actual_bindings != expected_bindings:
        raise Phase2EvidenceError("closeout evidence immutable binding drifted")
    _ensure_private_untracked(root, index_path)
    return cast(dict[str, object], recorded)


def verify_closeout_phase2_acceptance(
    repo_root: Path,
    index_path: Path,
    *,
    source_audit_closeout_successor: Path,
    verification_matrix: Path,
    plan63_protected_before: Path,
    plan63_protected_after: Path,
) -> dict[str, object]:
    root = repo_root.resolve(strict=True)
    current = verify_closeout_evidence_index(
        root,
        index_path,
        source_audit_closeout_successor=source_audit_closeout_successor,
        verification_matrix=verification_matrix,
        predecessor_current_evidence_index=root / CURRENT_EVIDENCE_RELATIVE,
        plan63_protected_before=plan63_protected_before,
    )
    guard_root = root / "artifacts/restricted/catalog/v2/release/gap-closure-guards"
    pairs = [
        _verify_guard_pair(
            root,
            guard_root / f"02-{plan}-protected-before.json",
            guard_root / f"02-{plan}-protected-after.json",
            plan_id=f"02-{plan}",
        )
        for plan in (60, 61, 62)
    ]
    if (
        compare_protected_manifest_paths(
            plan63_protected_before, plan63_protected_after, require_exact=True
        )
        != "EXACT_EQUAL"
    ):
        raise Phase2EvidenceError("Plan 63 protected guard pair is not exact equal")
    before = _load_canonical_mapping(plan63_protected_before)
    pairs.append(
        {
            "plan_id": "02-63",
            "before_file_sha256": _sha256_path(plan63_protected_before),
            "after_file_sha256": _sha256_path(plan63_protected_after),
            "protected_set_sha256": before["protected_set_sha256"],
            "comparison_status": "EXACT_EQUAL",
        }
    )
    transition = cast(Mapping[str, object], current["requirements_transition"])
    result: dict[str, object] = {
        "action": "VERIFY_CLOSEOUT_PHASE2_ACCEPTANCE",
        "status": "PASS",
        "closeout_evidence_index_sha256": current["closeout_evidence_index_sha256"],
        "source_audit_closeout_successor_sha256": _load_canonical_mapping(
            source_audit_closeout_successor
        )["source_audit_closeout_successor_sha256"],
        "verification_matrix_sha256": _load_canonical_mapping(verification_matrix)[
            "verification_matrix_sha256"
        ],
        "guard_comparisons": pairs,
        "requirements_transition": {
            "changed_requirement_ids": transition["changed_requirement_ids"],
            "replacement_count": transition["replacement_count"],
            "acceptance_timestamp": transition["acceptance_timestamp"],
            "acceptance_note": transition["acceptance_note"],
            "preimage_sha256": transition["preimage_sha256"],
            "postimage_sha256": transition["predicted_postimage_sha256"],
        },
    }
    _assert_closeout_privacy(result)
    return result


def _verify_fast_requirements_transition(
    root: Path, transition: Mapping[str, object]
) -> dict[str, object]:
    _validate_transition_shape(transition)
    raw = (root / REQUIREMENTS_RELATIVE).read_bytes()
    if _sha256_bytes(raw) != transition.get("predicted_postimage_sha256"):
        raise Phase2EvidenceError("Plan 64 REQUIREMENTS postimage hash drifted")
    if _requirements_state(raw) != {
        "completed": [f"DATA-{ordinal:02d}" for ordinal in range(1, 9)],
        "pending": [],
    }:
        raise Phase2EvidenceError("Plan 64 REQUIREMENTS state is not exact")
    replacements = cast(list[Mapping[str, str]], transition["replacement_allowlist"])
    reverse = [
        {"before": replacement["after"], "after": replacement["before"]}
        for replacement in reversed(replacements)
    ]
    preimage = _apply_replacements(raw, reverse)
    if _sha256_bytes(preimage) != transition.get("preimage_sha256"):
        raise Phase2EvidenceError("Plan 64 REQUIREMENTS preimage recovery drifted")
    if apply_transition_to_bytes(preimage, transition) != raw:
        raise Phase2EvidenceError("Plan 64 REQUIREMENTS transition replay drifted")
    return _acceptance_receipt(transition, action="VERIFY_PLAN64_REQUIREMENTS_TRANSITION")


def _plan64_guard_pair(before_path: Path, after_path: Path) -> dict[str, object]:
    if compare_protected_manifest_paths(before_path, after_path, require_exact=True) != (
        "EXACT_EQUAL"
    ):
        raise Phase2EvidenceError("Plan 64 protected guard pair is not exact equal")
    before = _load_canonical_mapping(before_path)
    return {
        "plan_id": "02-64",
        "before_file_sha256": _sha256_path(before_path),
        "after_file_sha256": _sha256_path(after_path),
        "protected_set_sha256": before["protected_set_sha256"],
        "comparison_status": "EXACT_EQUAL",
    }


def verify_final_phase2_acceptance_v4(
    repo_root: Path,
    index_path: Path,
    *,
    source_audit_closeout_successor: Path,
    verification_matrix: Path,
    plan64_protected_before: Path,
    plan64_protected_after: Path,
) -> dict[str, object]:
    root = repo_root.resolve(strict=True)
    source = _load_canonical_mapping(source_audit_closeout_successor)
    _validate_closeout_source_audit_payload(source)
    _ensure_private_untracked(root, source_audit_closeout_successor)
    guard_root = root / "artifacts/restricted/catalog/v2/release/gap-closure-guards"
    plan63_before = guard_root / "02-63-protected-before.json"
    plan63_after = guard_root / "02-63-protected-after.json"
    current = verify_closeout_evidence_index(
        root,
        index_path,
        source_audit_closeout_successor=source_audit_closeout_successor,
        verification_matrix=verification_matrix,
        predecessor_current_evidence_index=root / CURRENT_EVIDENCE_RELATIVE,
        plan63_protected_before=plan63_before,
    )
    guards = [
        _verify_guard_pair(
            root,
            guard_root / f"02-{plan}-protected-before.json",
            guard_root / f"02-{plan}-protected-after.json",
            plan_id=f"02-{plan}",
        )
        for plan in (60, 61, 62)
    ]
    if compare_protected_manifest_paths(plan63_before, plan63_after, require_exact=True) != (
        "EXACT_EQUAL"
    ):
        raise Phase2EvidenceError("Plan 63 protected guard pair is not exact equal")
    plan63 = _load_canonical_mapping(plan63_before)
    guards.append(
        {
            "plan_id": "02-63",
            "before_file_sha256": _sha256_path(plan63_before),
            "after_file_sha256": _sha256_path(plan63_after),
            "protected_set_sha256": plan63["protected_set_sha256"],
            "comparison_status": "EXACT_EQUAL",
        }
    )
    guards.append(_plan64_guard_pair(plan64_protected_before, plan64_protected_after))
    lifecycle = _plan64_successor_lifecycle_projection(
        root,
        roadmap_text=(root / SOURCE_DOCUMENTS["goal"]).read_text(encoding="utf-8"),
        requirements_text=(root / REQUIREMENTS_RELATIVE).read_text(encoding="utf-8"),
    )
    transition = cast(Mapping[str, object], current["requirements_transition"])
    requirements = _verify_fast_requirements_transition(root, transition)
    result: dict[str, object] = {
        "action": "VERIFY_FINAL_PHASE2_ACCEPTANCE_V4",
        "status": "PASS",
        "closeout_evidence_index_sha256": current["closeout_evidence_index_sha256"],
        "source_audit_closeout_successor_sha256": source["source_audit_closeout_successor_sha256"],
        "verification_matrix_sha256": _load_canonical_mapping(verification_matrix)[
            "verification_matrix_sha256"
        ],
        "guard_comparisons": guards,
        "producer_lifecycle": lifecycle,
        "requirements_transition": requirements,
    }
    _assert_closeout_privacy(result)
    return result


CURRENT_OWNER_NAMES = (
    "predecessor-evidence-index-and-data08-acceptance",
    "source-audit-successor",
    "lineage-successor",
    "rights-current-parent",
    "activation-current-parent",
    "sqlite-seal-and-supersession",
    "final-audit-manifest",
    "verification-matrix",
)


def _load_guard(path: Path) -> dict[str, object]:
    return cast(
        dict[str, object],
        _load_canonical_mapping(path, trailing_newline=False),
    )


def _verify_guard_pair(
    root: Path, before_path: Path, after_path: Path, *, plan_id: str
) -> dict[str, object]:
    before = _load_guard(before_path)
    after = _load_guard(after_path)
    try:
        lineage_capability.validate_protected_manifest(
            root, before, plan_id=plan_id, stage="before"
        )
        lineage_capability.validate_protected_manifest(root, after, plan_id=plan_id, stage="after")
        comparison = lineage_capability.compare_protected_manifests(before, after)
    except FingerprintError as exc:
        raise Phase2EvidenceError(str(exc)) from exc
    return {
        "plan_id": plan_id,
        "before_file_sha256": _sha256_path(before_path),
        "after_file_sha256": _sha256_path(after_path),
        "protected_set_sha256": before["protected_set_sha256"],
        "comparison_status": comparison,
    }


def _verify_before_guard(root: Path, path: Path, *, plan_id: str) -> dict[str, object]:
    guard = _load_guard(path)
    try:
        lineage_capability.validate_protected_manifest(root, guard, plan_id=plan_id, stage="before")
    except FingerprintError as exc:
        raise Phase2EvidenceError(str(exc)) from exc
    return {
        "plan_id": plan_id,
        "before_file_sha256": _sha256_path(path),
        "protected_set_sha256": guard["protected_set_sha256"],
        "status": "PASS",
    }


def _require_zero(root: Path, argv: Sequence[str]) -> dict[str, object]:
    completed = subprocess.run(
        argv,
        cwd=root / "backend",
        check=False,
        capture_output=True,
    )
    if completed.returncode != 0:
        raise Phase2EvidenceError(
            f"dedicated current owner verifier failed; argv={_argv_hash(argv)}; "
            f"exit={completed.returncode}; stderr={_sha256_bytes(completed.stderr)}"
        )
    return {
        "argv_sha256": _argv_hash(argv),
        "exit_code": 0,
        "stdout_sha256": _sha256_bytes(completed.stdout),
        "stderr_sha256": _sha256_bytes(completed.stderr),
        "status": "PASS",
    }


def _resolve_owner_input(root: Path, path: Path) -> Path:
    resolved = path.resolve(strict=True)
    try:
        resolved.relative_to(root)
    except ValueError as exc:
        raise Phase2EvidenceError("current owner input escapes the repository") from exc
    return resolved


def verify_current_evidence_inputs(
    repo_root: Path,
    *,
    source_audit_successor: Path,
    lineage_successor: Path,
    rights_current_parent: Path,
    activation_current_parent: Path,
    plan60_protected_before: Path,
    plan60_protected_after: Path,
    plan61_protected_before: Path,
    plan61_protected_after: Path,
    plan62_protected_before: Path,
) -> dict[str, object]:
    root = repo_root.resolve(strict=True)
    source_audit_successor = _resolve_owner_input(root, source_audit_successor)
    lineage_successor = _resolve_owner_input(root, lineage_successor)
    rights_current_parent = _resolve_owner_input(root, rights_current_parent)
    activation_current_parent = _resolve_owner_input(root, activation_current_parent)
    plan60_protected_before = _resolve_owner_input(root, plan60_protected_before)
    plan60_protected_after = _resolve_owner_input(root, plan60_protected_after)
    plan61_protected_before = _resolve_owner_input(root, plan61_protected_before)
    plan61_protected_after = _resolve_owner_input(root, plan61_protected_after)
    plan62_protected_before = _resolve_owner_input(root, plan62_protected_before)
    old_index = root / PREDECESSOR_EVIDENCE_INDEX_RELATIVE
    old_audit = root / PREDECESSOR_SOURCE_AUDIT_RELATIVE
    predecessor_lineage = root / lineage_capability.PREDECESSOR_TARGET
    rights = root / "artifacts/restricted/catalog/v2/rights/rights-projection.json"
    objective = root / "artifacts/restricted/catalog/v2/audit/candidate-objective-evidence.json"
    event = root / ACTIVATION_EVENT_RELATIVE
    predecessor = verify_evidence_index(root, old_index)
    source = verify_source_audit_successor(
        root,
        source_audit_successor,
        predecessor_source_audit=old_audit,
        predecessor_evidence_index=old_index,
    )
    try:
        lineage = lineage_capability.verify_successor_manifest(
            root,
            predecessor_lineage,
            lineage_capability._load_manifest(lineage_successor),
        )
    except FingerprintError as exc:
        raise Phase2EvidenceError(str(exc)) from exc
    rights_result = _require_zero(
        root,
        _module_argv(
            "itda.cli.project_catalog_rights_v2",
            "--check-current-bundle",
            str(rights_current_parent),
            "--lineage-successor",
            str(lineage_successor),
            "--rights",
            str(rights),
            "--objective-evidence",
            str(objective),
        ),
    )
    activation_result = _require_zero(
        root,
        _module_argv(
            "itda.cli.verify_catalog_activation_current_parent",
            "--verify-current-parent-attestation",
            str(activation_current_parent),
            "--event",
            str(event),
            "--require-current",
            "--protected-before",
            str(plan61_protected_before),
            "--protected-after",
            str(plan61_protected_after),
        ),
    )
    transition = cast(Mapping[str, object], predecessor["requirements_transition"])
    requirements = verify_requirements_acceptance(
        root / REQUIREMENTS_RELATIVE,
        old_index,
        expected_timestamp=cast(str, transition["acceptance_timestamp"]),
        expected_note=cast(str, transition["acceptance_note"]),
    )
    guards = [
        _verify_guard_pair(root, plan60_protected_before, plan60_protected_after, plan_id="02-60"),
        _verify_guard_pair(root, plan61_protected_before, plan61_protected_after, plan_id="02-61"),
        _verify_before_guard(root, plan62_protected_before, plan_id="02-62"),
    ]
    protected_sets = {str(row["protected_set_sha256"]) for row in guards}
    if len(protected_sets) != 1:
        raise Phase2EvidenceError("gap-closure guards do not share one protected set")
    result: dict[str, object] = {
        "status": "PASS",
        "predecessor_evidence_index": {
            "file_sha256": _sha256_path(old_index),
            "self_sha256": predecessor["evidence_index_sha256"],
        },
        "source_audit_successor": {
            "file_sha256": _sha256_path(source_audit_successor),
            "self_sha256": source["source_audit_successor_sha256"],
            "missing_count": cast(Mapping[str, object], source["status_counts"])["MISSING"],
        },
        "lineage_successor": {
            "file_sha256": _sha256_path(lineage_successor),
            "self_sha256": lineage["successor_sha256"],
        },
        "rights_current_parent": {
            "file_sha256": _sha256_path(rights_current_parent),
            "verifier": rights_result,
        },
        "activation_current_parent": {
            "file_sha256": _sha256_path(activation_current_parent),
            "verifier": activation_result,
        },
        "requirements_acceptance": {
            "receipt": requirements,
            "requirements_file_sha256": _sha256_path(root / REQUIREMENTS_RELATIVE),
        },
        "guards": guards,
        "protected_set_sha256": next(iter(protected_sets)),
    }
    _assert_sanitized(result)
    return result


def _validate_matrix_receipt(payload: Mapping[str, object]) -> None:
    if (
        payload.get("schema_version") != VERIFICATION_MATRIX_SCHEMA_VERSION
        or payload.get("status") != "PASS"
        or payload.get("all_required_passed") is not True
        or payload.get("verification_matrix_sha256")
        != _self_hash(payload, "verification_matrix_sha256")
        or payload.get("required_shard_ids")
        != ["A", "B", "C", "D", "E", "F1", "F2", "F3", "G", "H"]
    ):
        raise Phase2EvidenceError("verification matrix schema or status drifted")
    commands = payload.get("commands")
    shards = payload.get("shards")
    if not isinstance(commands, list) or not commands or not isinstance(shards, list):
        raise Phase2EvidenceError("verification matrix command or shard rows are missing")
    if any(
        not isinstance(row, dict)
        or row.get("status") != "PASS"
        or row.get("exit_code") != 0
        or row.get("duration_within_bound") is not True
        for row in commands
    ):
        raise Phase2EvidenceError("verification matrix contains a failed command")
    if any(
        not isinstance(row, dict)
        or row.get("status") != "PASS"
        or row.get("duration_within_bound") is not True
        for row in shards
    ):
        raise Phase2EvidenceError("verification matrix contains a failed shard")
    semantic = payload.get("semantic_exact_rejection_node_ids")
    if semantic != [
        "test_current_checkout_requires_v1_lineage_successor",
        "test_current_checkout_requires_rights_current_parent_attestation",
        "test_current_checkout_requires_source_audit_successor",
    ]:
        raise Phase2EvidenceError("verification matrix exact-rejection nodes drifted")


def validate_current_evidence_payload(
    payload: Mapping[str, object], *, require_after_guard: bool
) -> None:
    if (
        payload.get("schema_version") != CURRENT_EVIDENCE_SCHEMA_VERSION
        or payload.get("status") != "PASS"
        or payload.get("current_evidence_index_sha256")
        != _self_hash(payload, "current_evidence_index_sha256")
        or payload.get("owner_names") != list(CURRENT_OWNER_NAMES)
    ):
        raise Phase2EvidenceError("current evidence schema, status, or owner registry drifted")
    transition = payload.get("requirements_transition")
    if not isinstance(transition, dict):
        raise Phase2EvidenceError("current evidence requirements transition is missing")
    _validate_transition_shape(transition)
    matrix = payload.get("verification_matrix")
    if not isinstance(matrix, dict):
        raise Phase2EvidenceError("current evidence matrix binding is missing")
    if (
        matrix.get("required_shard_ids")
        != [
            "A",
            "B",
            "C",
            "D",
            "E",
            "F1",
            "F2",
            "F3",
            "G",
            "H",
        ]
        or matrix.get("all_required_passed") is not True
    ):
        raise Phase2EvidenceError("current evidence matrix binding is incomplete")
    guards = payload.get("guard_evidence")
    if not isinstance(guards, list) or len(guards) != (3 if require_after_guard else 3):
        raise Phase2EvidenceError("current evidence guard registry drifted")
    if require_after_guard and any(
        not isinstance(row, dict) or row.get("comparison_status") != "EXACT_EQUAL" for row in guards
    ):
        raise Phase2EvidenceError("current acceptance requires every exact guard comparison")
    _assert_sanitized(payload)


def _expected_current_evidence_index(
    root: Path,
    *,
    predecessor_evidence_index: Path,
    source_audit_successor: Path,
    lineage_successor: Path,
    rights_current_parent: Path,
    activation_current_parent: Path,
    verification_matrix: Path,
    plan60_protected_before: Path,
    plan60_protected_after: Path,
    plan61_protected_before: Path,
    plan61_protected_after: Path,
    plan62_protected_before: Path,
) -> dict[str, object]:
    if (
        predecessor_evidence_index.resolve()
        != (root / PREDECESSOR_EVIDENCE_INDEX_RELATIVE).resolve()
    ):
        raise Phase2EvidenceError("current evidence predecessor index is not exact")
    inputs = verify_current_evidence_inputs(
        root,
        source_audit_successor=source_audit_successor,
        lineage_successor=lineage_successor,
        rights_current_parent=rights_current_parent,
        activation_current_parent=activation_current_parent,
        plan60_protected_before=plan60_protected_before,
        plan60_protected_after=plan60_protected_after,
        plan61_protected_before=plan61_protected_before,
        plan61_protected_after=plan61_protected_after,
        plan62_protected_before=plan62_protected_before,
    )
    matrix = _load_canonical_mapping(verification_matrix)
    _validate_matrix_receipt(matrix)
    predecessor = verify_evidence_index(root, predecessor_evidence_index)
    transition = cast(dict[str, object], predecessor["requirements_transition"])
    guard_rows = cast(list[dict[str, object]], inputs["guards"])
    payload: dict[str, object] = {
        "schema_version": CURRENT_EVIDENCE_SCHEMA_VERSION,
        "status": "PASS",
        "owner_names": list(CURRENT_OWNER_NAMES),
        "owners": inputs,
        "predecessor_evidence_index_sha256": _sha256_path(predecessor_evidence_index),
        "requirements_transition": transition,
        "requirements_unchanged_sha256": _sha256_path(root / REQUIREMENTS_RELATIVE),
        "status_counts": {"MISSING": 0},
        "verification_matrix": {
            "file_sha256": _sha256_path(verification_matrix),
            "self_sha256": matrix["verification_matrix_sha256"],
            "command_set_sha256": matrix["command_set_sha256"],
            "required_shard_ids": matrix["required_shard_ids"],
            "all_required_passed": matrix["all_required_passed"],
        },
        "guard_evidence": guard_rows,
        "current_evidence_index_sha256": "",
    }
    payload["current_evidence_index_sha256"] = _self_hash(payload, "current_evidence_index_sha256")
    validate_current_evidence_payload(payload, require_after_guard=False)
    return payload


def build_current_evidence_index(
    repo_root: Path, output_path: Path, **paths: Path
) -> dict[str, object]:
    root = repo_root.resolve(strict=True)
    payload = _expected_current_evidence_index(root, **paths)
    _publish_exact_existing(root, output_path, canonical_json_bytes(payload))
    return payload


def verify_current_evidence_index(
    repo_root: Path, index_path: Path, **paths: Path
) -> dict[str, object]:
    root = repo_root.resolve(strict=True)
    recorded = _load_canonical_mapping(index_path)
    validate_current_evidence_payload(recorded, require_after_guard=False)
    expected = _expected_current_evidence_index(root, **paths)
    if recorded != expected:
        raise Phase2EvidenceError("current evidence index differs from live rederivation")
    _ensure_private_untracked(root, index_path)
    return cast(dict[str, object], recorded)


def verify_current_phase2_acceptance(
    repo_root: Path,
    index_path: Path,
    *,
    verification_matrix: Path,
    plan60_protected_before: Path,
    plan60_protected_after: Path,
    plan61_protected_before: Path,
    plan61_protected_after: Path,
    plan62_protected_before: Path,
    plan62_protected_after: Path,
) -> dict[str, object]:
    root = repo_root.resolve(strict=True)
    current = verify_current_evidence_index(
        root,
        index_path,
        predecessor_evidence_index=root / PREDECESSOR_EVIDENCE_INDEX_RELATIVE,
        source_audit_successor=root / SOURCE_AUDIT_SUCCESSOR_RELATIVE,
        lineage_successor=root / LINEAGE_SUCCESSOR_RELATIVE,
        rights_current_parent=root / RIGHTS_CURRENT_PARENT_RELATIVE,
        activation_current_parent=root / ACTIVATION_CURRENT_PARENT_RELATIVE,
        verification_matrix=verification_matrix,
        plan60_protected_before=plan60_protected_before,
        plan60_protected_after=plan60_protected_after,
        plan61_protected_before=plan61_protected_before,
        plan61_protected_after=plan61_protected_after,
        plan62_protected_before=plan62_protected_before,
    )
    pairs = [
        _verify_guard_pair(root, plan60_protected_before, plan60_protected_after, plan_id="02-60"),
        _verify_guard_pair(root, plan61_protected_before, plan61_protected_after, plan_id="02-61"),
        _verify_guard_pair(root, plan62_protected_before, plan62_protected_after, plan_id="02-62"),
    ]
    protected_sets = {str(row["protected_set_sha256"]) for row in pairs}
    if len(protected_sets) != 1:
        raise Phase2EvidenceError("final guard protected sets differ")
    matrix = _load_canonical_mapping(verification_matrix)
    _validate_matrix_receipt(matrix)
    result: dict[str, object] = {
        "action": "VERIFY_CURRENT_PHASE2_ACCEPTANCE",
        "status": "PASS",
        "current_evidence_index_sha256": current["current_evidence_index_sha256"],
        "verification_matrix_sha256": matrix["verification_matrix_sha256"],
        "guard_comparisons": pairs,
        "protected_set_sha256": next(iter(protected_sets)),
        "requirements_transition": {
            "changed_requirement_ids": ["DATA-08"],
            "replacement_count": 3,
            "acceptance_timestamp": cast(Mapping[str, object], current["requirements_transition"])[
                "acceptance_timestamp"
            ],
            "acceptance_note": cast(Mapping[str, object], current["requirements_transition"])[
                "acceptance_note"
            ],
        },
        "current_requirement_ids": ["DATA-05", "DATA-06", "DATA-07"],
        "original_requirement_id": "DATA-08",
    }
    _assert_sanitized(result)
    return result


def _atomic_replace_bytes(path: Path, payload: bytes) -> None:
    metadata = path.lstat()
    if path.is_symlink() or not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
        raise Phase2EvidenceError("REQUIREMENTS target identity is unsafe")
    temporary = path.parent / f".{path.name}.acceptance-{os.getpid()}"
    descriptor = os.open(
        temporary,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0),
        stat.S_IMODE(metadata.st_mode),
    )
    try:
        view = memoryview(payload)
        while view:
            written = os.write(descriptor, view)
            if written <= 0:
                raise OSError("short write")
            view = view[written:]
        os.fsync(descriptor)
    except BaseException:
        os.close(descriptor)
        temporary.unlink(missing_ok=True)
        raise
    os.close(descriptor)
    os.replace(temporary, path)
    directory_descriptor = os.open(path.parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
    try:
        os.fsync(directory_descriptor)
    finally:
        os.close(directory_descriptor)


def _acceptance_receipt(transition: Mapping[str, object], *, action: str) -> dict[str, object]:
    receipt = {
        "action": action,
        "status": "PASS",
        "acceptance_timestamp": transition["acceptance_timestamp"],
        "acceptance_note": transition["acceptance_note"],
        "preimage_sha256": transition["preimage_sha256"],
        "recovered_preimage_sha256": transition["preimage_sha256"],
        "predicted_postimage_sha256": transition["predicted_postimage_sha256"],
        "postimage_sha256": transition["predicted_postimage_sha256"],
        "replacement_count": 3,
        "changed_requirement_ids": ["DATA-08"],
    }
    _assert_sanitized(receipt)
    return receipt


def apply_requirements_acceptance(
    requirements_path: Path, evidence_index_path: Path
) -> dict[str, object]:
    """Atomically apply only the immutable three-replacement DATA-08 transition."""

    root = Path(__file__).resolve().parents[4]
    index_sha_before = _sha256_path(evidence_index_path)
    index = verify_evidence_index(root, evidence_index_path)
    transition = cast(Mapping[str, object], index["requirements_transition"])
    raw = requirements_path.read_bytes()
    if _requirements_state(raw) != {
        "completed": [f"DATA-{ordinal:02d}" for ordinal in range(1, 8)],
        "pending": ["DATA-08"],
    }:
        raise Phase2EvidenceError("REQUIREMENTS pre-acceptance state is not exact")
    postimage = apply_transition_to_bytes(raw, transition)
    if _requirements_state(postimage) != {
        "completed": [f"DATA-{ordinal:02d}" for ordinal in range(1, 9)],
        "pending": [],
    }:
        raise Phase2EvidenceError("REQUIREMENTS predicted post-acceptance state is not exact")
    _atomic_replace_bytes(requirements_path, postimage)
    if requirements_path.read_bytes() != postimage:
        raise Phase2EvidenceError("REQUIREMENTS atomic replacement did not persist")
    if _sha256_path(evidence_index_path) != index_sha_before:
        raise Phase2EvidenceError("evidence index changed during acceptance")
    return _acceptance_receipt(transition, action="APPLY_REQUIREMENTS_ACCEPTANCE")


def verify_requirements_acceptance(
    requirements_path: Path,
    evidence_index_path: Path,
    *,
    expected_timestamp: str,
    expected_note: str,
) -> dict[str, object]:
    """Reverse the three replacements in memory and prove exact preimage recovery."""

    root = Path(__file__).resolve().parents[4]
    index_sha_before = _sha256_path(evidence_index_path)
    index = verify_evidence_index(root, evidence_index_path)
    transition = cast(Mapping[str, object], index["requirements_transition"])
    if expected_timestamp != transition.get(
        "acceptance_timestamp"
    ) or expected_note != transition.get("acceptance_note"):
        raise Phase2EvidenceError("caller expectation differs from immutable acceptance binding")
    raw = requirements_path.read_bytes()
    if _sha256_bytes(raw) != transition.get("predicted_postimage_sha256"):
        raise Phase2EvidenceError("REQUIREMENTS postimage hash drifted")
    if _requirements_state(raw) != {
        "completed": [f"DATA-{ordinal:02d}" for ordinal in range(1, 9)],
        "pending": [],
    }:
        raise Phase2EvidenceError("REQUIREMENTS post-acceptance state is not exact")
    replacements = cast(list[Mapping[str, str]], transition["replacement_allowlist"])
    reverse = [
        {"before": replacement["after"], "after": replacement["before"]}
        for replacement in reversed(replacements)
    ]
    preimage = _apply_replacements(raw, reverse)
    if _sha256_bytes(preimage) != transition.get("preimage_sha256"):
        raise Phase2EvidenceError("REQUIREMENTS reverse transition did not recover preimage")
    if apply_transition_to_bytes(preimage, transition) != raw:
        raise Phase2EvidenceError("REQUIREMENTS forward replay differs from postimage")
    if _requirements_state(preimage) != {
        "completed": [f"DATA-{ordinal:02d}" for ordinal in range(1, 8)],
        "pending": ["DATA-08"],
    }:
        raise Phase2EvidenceError("REQUIREMENTS recovered preimage state is not exact")
    if _sha256_path(evidence_index_path) != index_sha_before:
        raise Phase2EvidenceError("evidence index changed during acceptance verification")
    return _acceptance_receipt(transition, action="VERIFY_REQUIREMENTS_ACCEPTANCE")


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--verify-sqlite-receipt", type=Path)
    parser.add_argument("--sqlite-authority-root", type=Path)
    parser.add_argument("--verify-sqlite-supersession-history", action="store_true")
    parser.add_argument("--evidence-index", type=Path)
    parser.add_argument("--expected-timestamp")
    parser.add_argument("--expected-note")
    parser.add_argument("--predecessor-source-audit", type=Path)
    parser.add_argument("--predecessor-evidence-index", type=Path)
    parser.add_argument("--predecessor-source-audit-successor", type=Path)
    parser.add_argument("--predecessor-current-evidence-index", type=Path)
    parser.add_argument("--closeout-commit", default=PLAN62_CLOSEOUT_COMMIT)
    parser.add_argument("--grammar-migration-commit", default=GRAMMAR_MIGRATION_COMMIT)
    parser.add_argument("--plan-id")
    parser.add_argument("--stage", choices=("before", "after"))
    parser.add_argument("--require-exact", action="store_true")
    parser.add_argument("--source-audit-successor", type=Path)
    parser.add_argument("--source-audit-closeout-successor", type=Path)
    parser.add_argument("--predecessor-verification-matrix", type=Path)
    parser.add_argument("--lineage-successor", type=Path)
    parser.add_argument("--rights-current-parent", type=Path)
    parser.add_argument("--activation-current-parent", type=Path)
    parser.add_argument("--verification-matrix", type=Path)
    parser.add_argument("--plan60-protected-before", type=Path)
    parser.add_argument("--plan60-protected-after", type=Path)
    parser.add_argument("--plan61-protected-before", type=Path)
    parser.add_argument("--plan61-protected-after", type=Path)
    parser.add_argument("--plan62-protected-before", type=Path)
    parser.add_argument("--plan62-protected-after", type=Path)
    parser.add_argument("--plan63-protected-before", type=Path)
    parser.add_argument("--plan63-protected-after", type=Path)
    parser.add_argument("--plan64-protected-before", type=Path)
    parser.add_argument("--plan64-protected-after", type=Path)
    parser.add_argument("--per-shard-timeout-seconds", type=int, default=600)
    parser.add_argument("--overall-timeout-seconds", type=int, default=3600)
    action = parser.add_mutually_exclusive_group(required=True)
    action.add_argument("--build-evidence-index", type=Path)
    action.add_argument("--verify-evidence-index", type=Path)
    action.add_argument("--build-source-audit", type=Path)
    action.add_argument("--verify-source-audit", type=Path)
    action.add_argument("--build-source-audit-successor", type=Path)
    action.add_argument("--verify-source-audit-successor", type=Path)
    action.add_argument("--build-source-audit-closeout-successor", type=Path)
    action.add_argument("--verify-source-audit-closeout-successor", type=Path)
    action.add_argument("--capture-protected-manifest", type=Path)
    action.add_argument("--compare-protected-manifests", nargs=2, type=Path)
    action.add_argument("--run-final-verification-matrix", type=Path)
    action.add_argument("--run-final-verification-matrix-v2", type=Path)
    action.add_argument("--verify-final-verification-matrix-v2-receipt", type=Path)
    action.add_argument("--verify-current-evidence-inputs", action="store_true")
    action.add_argument("--verify-closeout-evidence-inputs", action="store_true")
    action.add_argument("--build-current-evidence-index", type=Path)
    action.add_argument("--verify-current-evidence-index", type=Path)
    action.add_argument("--verify-current-phase2-acceptance", type=Path)
    action.add_argument("--build-closeout-evidence-index", type=Path)
    action.add_argument("--verify-closeout-evidence-index", type=Path)
    action.add_argument("--verify-closeout-phase2-acceptance", type=Path)
    action.add_argument("--verify-final-phase2-acceptance-v4", type=Path)
    action.add_argument("--apply-requirements-acceptance", type=Path)
    action.add_argument("--verify-requirements-acceptance", type=Path)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    root = Path(__file__).resolve().parents[4]
    authority_root = args.sqlite_authority_root or (root / SQLITE_ROOT_RELATIVE)
    receipt_path = args.verify_sqlite_receipt or (authority_root / SQLITE_SEAL_RECEIPT_NAME)
    release = root / "artifacts/restricted/catalog/v2/release"
    guard_root = release / "gap-closure-guards"
    source_successor = args.source_audit_successor or (root / SOURCE_AUDIT_SUCCESSOR_RELATIVE)
    source_closeout = args.source_audit_closeout_successor or (
        root / SOURCE_AUDIT_CLOSEOUT_RELATIVE
    )
    lineage_successor = args.lineage_successor or (root / LINEAGE_SUCCESSOR_RELATIVE)
    rights_current_parent = args.rights_current_parent or (root / RIGHTS_CURRENT_PARENT_RELATIVE)
    activation_current_parent = args.activation_current_parent or (
        root / ACTIVATION_CURRENT_PARENT_RELATIVE
    )
    verification_matrix = args.verification_matrix or (root / VERIFICATION_MATRIX_RELATIVE)
    p60_before = args.plan60_protected_before or guard_root / "02-60-protected-before.json"
    p60_after = args.plan60_protected_after or guard_root / "02-60-protected-after.json"
    p61_before = args.plan61_protected_before or guard_root / "02-61-protected-before.json"
    p61_after = args.plan61_protected_after or guard_root / "02-61-protected-after.json"
    p62_before = args.plan62_protected_before or guard_root / "02-62-protected-before.json"
    p62_after = args.plan62_protected_after or guard_root / "02-62-protected-after.json"
    p63_before = args.plan63_protected_before or guard_root / "02-63-protected-before.json"
    p63_after = args.plan63_protected_after or guard_root / "02-63-protected-after.json"
    p64_before = args.plan64_protected_before or guard_root / "02-64-protected-before.json"
    p64_after = args.plan64_protected_after or guard_root / "02-64-protected-after.json"
    if (
        args.build_source_audit_closeout_successor is not None
        or args.verify_source_audit_closeout_successor is not None
    ):
        predecessor_source_successor = args.predecessor_source_audit_successor or source_successor
        predecessor_current_index = args.predecessor_current_evidence_index or (
            root / CURRENT_EVIDENCE_RELATIVE
        )
        if args.build_source_audit_closeout_successor is not None:
            closeout_source = build_source_audit_closeout_successor(
                root,
                args.build_source_audit_closeout_successor,
                predecessor_source_audit_successor=predecessor_source_successor,
                predecessor_current_evidence_index=predecessor_current_index,
                closeout_commit=args.closeout_commit,
            )
            action_name = "BUILD_SOURCE_AUDIT_CLOSEOUT_SUCCESSOR"
        else:
            closeout_source = verify_source_audit_closeout_successor(
                root,
                args.verify_source_audit_closeout_successor,
                predecessor_source_audit_successor=predecessor_source_successor,
                predecessor_current_evidence_index=predecessor_current_index,
            )
            action_name = "VERIFY_SOURCE_AUDIT_CLOSEOUT_SUCCESSOR"
        print(
            json.dumps(
                {
                    "action": action_name,
                    "status": closeout_source["status"],
                    "source_audit_closeout_successor_sha256": closeout_source[
                        "source_audit_closeout_successor_sha256"
                    ],
                    "source_counts": closeout_source["source_counts"],
                    "status_counts": closeout_source["status_counts"],
                },
                ensure_ascii=False,
                sort_keys=True,
            )
        )
        return 0
    if args.run_final_verification_matrix_v2 is not None:
        matrix_v2 = run_final_verification_matrix_v2(
            root,
            args.run_final_verification_matrix_v2,
            source_audit_closeout_successor=source_closeout,
            predecessor_verification_matrix=args.predecessor_verification_matrix
            or (root / VERIFICATION_MATRIX_RELATIVE),
            per_shard_timeout_seconds=args.per_shard_timeout_seconds,
            overall_timeout_seconds=args.overall_timeout_seconds,
        )
        print(
            json.dumps(
                {
                    "action": "RUN_FINAL_VERIFICATION_MATRIX_V2",
                    "status": matrix_v2["status"],
                    "verification_matrix_sha256": matrix_v2["verification_matrix_sha256"],
                    "command_set_sha256": matrix_v2["command_set_sha256"],
                },
                ensure_ascii=False,
                sort_keys=True,
            )
        )
        return 0
    if args.verify_final_verification_matrix_v2_receipt is not None:
        matrix_v2 = verify_final_verification_matrix_v2_receipt(
            root,
            args.verify_final_verification_matrix_v2_receipt,
            source_audit_closeout_successor=source_closeout,
            predecessor_verification_matrix=args.predecessor_verification_matrix
            or (root / VERIFICATION_MATRIX_RELATIVE),
        )
        print(
            json.dumps(
                {
                    "action": "VERIFY_FINAL_VERIFICATION_MATRIX_V2_RECEIPT",
                    "status": matrix_v2["status"],
                    "verification_matrix_sha256": matrix_v2["verification_matrix_sha256"],
                },
                ensure_ascii=False,
                sort_keys=True,
            )
        )
        return 0
    if args.verify_closeout_evidence_inputs:
        inputs = verify_closeout_evidence_inputs(
            root,
            source_audit_closeout_successor=source_closeout,
            plan63_protected_before=p63_before,
        )
        print(
            json.dumps(
                {"action": "VERIFY_CLOSEOUT_EVIDENCE_INPUTS", "status": inputs["status"]},
                ensure_ascii=False,
                sort_keys=True,
            )
        )
        return 0
    closeout_paths = {
        "source_audit_closeout_successor": source_closeout,
        "verification_matrix": args.verification_matrix
        or (root / FINAL_VERIFICATION_MATRIX_V2_RELATIVE),
        "predecessor_current_evidence_index": args.predecessor_current_evidence_index
        or (root / CURRENT_EVIDENCE_RELATIVE),
        "plan63_protected_before": p63_before,
    }
    if args.build_closeout_evidence_index is not None:
        index_v3 = build_closeout_evidence_index(
            root, args.build_closeout_evidence_index, **closeout_paths
        )
        print(
            json.dumps(
                {
                    "action": "BUILD_CLOSEOUT_EVIDENCE_INDEX",
                    "status": index_v3["status"],
                    "closeout_evidence_index_sha256": index_v3["closeout_evidence_index_sha256"],
                },
                ensure_ascii=False,
                sort_keys=True,
            )
        )
        return 0
    if args.verify_closeout_evidence_index is not None:
        index_v3 = verify_closeout_evidence_index(
            root, args.verify_closeout_evidence_index, **closeout_paths
        )
        print(
            json.dumps(
                {
                    "action": "VERIFY_CLOSEOUT_EVIDENCE_INDEX",
                    "status": index_v3["status"],
                    "closeout_evidence_index_sha256": index_v3["closeout_evidence_index_sha256"],
                },
                ensure_ascii=False,
                sort_keys=True,
            )
        )
        return 0
    if args.verify_closeout_phase2_acceptance is not None:
        acceptance_v3 = verify_closeout_phase2_acceptance(
            root,
            args.verify_closeout_phase2_acceptance,
            source_audit_closeout_successor=source_closeout,
            verification_matrix=args.verification_matrix
            or (root / FINAL_VERIFICATION_MATRIX_V2_RELATIVE),
            plan63_protected_before=p63_before,
            plan63_protected_after=p63_after,
        )
        print(json.dumps(acceptance_v3, ensure_ascii=False, sort_keys=True))
        return 0
    if args.verify_final_phase2_acceptance_v4 is not None:
        acceptance_v4 = verify_final_phase2_acceptance_v4(
            root,
            args.verify_final_phase2_acceptance_v4,
            source_audit_closeout_successor=source_closeout,
            verification_matrix=args.verification_matrix
            or (root / FINAL_VERIFICATION_MATRIX_V2_RELATIVE),
            plan64_protected_before=p64_before,
            plan64_protected_after=p64_after,
        )
        print(json.dumps(acceptance_v4, ensure_ascii=False, sort_keys=True))
        return 0
    if args.run_final_verification_matrix is not None:
        matrix = run_final_verification_matrix(
            root,
            args.run_final_verification_matrix,
            source_audit_successor=source_successor,
            lineage_successor=lineage_successor,
            rights_current_parent=rights_current_parent,
            activation_current_parent=activation_current_parent,
            per_shard_timeout_seconds=args.per_shard_timeout_seconds,
            overall_timeout_seconds=args.overall_timeout_seconds,
        )
        print(
            json.dumps(
                {
                    "action": "RUN_FINAL_VERIFICATION_MATRIX",
                    "status": matrix["status"],
                    "verification_matrix_sha256": matrix["verification_matrix_sha256"],
                    "command_set_sha256": matrix["command_set_sha256"],
                    "required_shard_ids": matrix["required_shard_ids"],
                },
                ensure_ascii=False,
                sort_keys=True,
            )
        )
        return 0
    if args.verify_current_evidence_inputs:
        inputs = verify_current_evidence_inputs(
            root,
            source_audit_successor=source_successor,
            lineage_successor=lineage_successor,
            rights_current_parent=rights_current_parent,
            activation_current_parent=activation_current_parent,
            plan60_protected_before=p60_before,
            plan60_protected_after=p60_after,
            plan61_protected_before=p61_before,
            plan61_protected_after=p61_after,
            plan62_protected_before=p62_before,
        )
        print(
            json.dumps(
                {
                    "action": "VERIFY_CURRENT_EVIDENCE_INPUTS",
                    "status": inputs["status"],
                    "protected_set_sha256": inputs["protected_set_sha256"],
                },
                ensure_ascii=False,
                sort_keys=True,
            )
        )
        return 0
    current_paths = {
        "predecessor_evidence_index": args.predecessor_evidence_index
        or (root / PREDECESSOR_EVIDENCE_INDEX_RELATIVE),
        "source_audit_successor": source_successor,
        "lineage_successor": lineage_successor,
        "rights_current_parent": rights_current_parent,
        "activation_current_parent": activation_current_parent,
        "verification_matrix": verification_matrix,
        "plan60_protected_before": p60_before,
        "plan60_protected_after": p60_after,
        "plan61_protected_before": p61_before,
        "plan61_protected_after": p61_after,
        "plan62_protected_before": p62_before,
    }
    if args.build_current_evidence_index is not None:
        current = build_current_evidence_index(
            root, args.build_current_evidence_index, **current_paths
        )
        print(
            json.dumps(
                {
                    "action": "BUILD_CURRENT_EVIDENCE_INDEX",
                    "status": current["status"],
                    "current_evidence_index_sha256": current["current_evidence_index_sha256"],
                },
                ensure_ascii=False,
                sort_keys=True,
            )
        )
        return 0
    if args.verify_current_evidence_index is not None:
        current = verify_current_evidence_index(
            root, args.verify_current_evidence_index, **current_paths
        )
        print(
            json.dumps(
                {
                    "action": "VERIFY_CURRENT_EVIDENCE_INDEX",
                    "status": current["status"],
                    "current_evidence_index_sha256": current["current_evidence_index_sha256"],
                },
                ensure_ascii=False,
                sort_keys=True,
            )
        )
        return 0
    if args.verify_current_phase2_acceptance is not None:
        acceptance = verify_current_phase2_acceptance(
            root,
            args.verify_current_phase2_acceptance,
            verification_matrix=verification_matrix,
            plan60_protected_before=p60_before,
            plan60_protected_after=p60_after,
            plan61_protected_before=p61_before,
            plan61_protected_after=p61_after,
            plan62_protected_before=p62_before,
            plan62_protected_after=p62_after,
        )
        print(json.dumps(acceptance, ensure_ascii=False, sort_keys=True))
        return 0
    if args.capture_protected_manifest is not None:
        if args.plan_id is None or args.stage is None:
            raise Phase2EvidenceError("protected manifest requires plan ID and stage")
        manifest = capture_protected_manifest(
            root,
            args.capture_protected_manifest,
            plan_id=args.plan_id,
            stage=args.stage,
        )
        print(manifest["protected_manifest_sha256"])
        return 0
    if args.compare_protected_manifests is not None:
        print(
            compare_protected_manifest_paths(
                args.compare_protected_manifests[0],
                args.compare_protected_manifests[1],
                require_exact=args.require_exact,
            )
        )
        return 0
    if (
        args.build_source_audit_successor is not None
        or args.verify_source_audit_successor is not None
    ):
        if args.predecessor_source_audit is None or args.predecessor_evidence_index is None:
            raise Phase2EvidenceError("source audit successor requires both predecessors")
        if args.build_source_audit_successor is not None:
            successor = build_source_audit_successor(
                root,
                args.build_source_audit_successor,
                predecessor_source_audit=args.predecessor_source_audit,
                predecessor_evidence_index=args.predecessor_evidence_index,
                grammar_migration_commit=args.grammar_migration_commit,
            )
            action_name = "BUILD_SOURCE_AUDIT_SUCCESSOR"
        else:
            successor = verify_source_audit_successor(
                root,
                args.verify_source_audit_successor,
                predecessor_source_audit=args.predecessor_source_audit,
                predecessor_evidence_index=args.predecessor_evidence_index,
            )
            action_name = "VERIFY_SOURCE_AUDIT_SUCCESSOR"
        print(
            json.dumps(
                {
                    "action": action_name,
                    "status": successor["status"],
                    "source_audit_successor_sha256": successor["source_audit_successor_sha256"],
                    "source_counts": successor["source_counts"],
                    "status_counts": successor["status_counts"],
                },
                ensure_ascii=False,
                sort_keys=True,
            )
        )
        return 0
    if (
        args.apply_requirements_acceptance is not None
        or args.verify_requirements_acceptance is not None
    ):
        if args.evidence_index is None:
            raise Phase2EvidenceError("requirements acceptance requires an evidence index")
        if args.apply_requirements_acceptance is not None:
            acceptance_result = apply_requirements_acceptance(
                args.apply_requirements_acceptance, args.evidence_index
            )
        else:
            if args.expected_timestamp is None or args.expected_note is None:
                raise Phase2EvidenceError(
                    "acceptance verification requires the expected immutable binding"
                )
            acceptance_result = verify_requirements_acceptance(
                args.verify_requirements_acceptance,
                args.evidence_index,
                expected_timestamp=args.expected_timestamp,
                expected_note=args.expected_note,
            )
        print(json.dumps(acceptance_result, ensure_ascii=False, sort_keys=True))
        return 0
    if args.build_source_audit is not None or args.verify_source_audit is not None:
        if args.evidence_index is None:
            raise Phase2EvidenceError("source audit requires an evidence index")
        if args.build_source_audit is not None:
            source_result = build_source_audit(root, args.build_source_audit, args.evidence_index)
            source_action = "BUILD_SOURCE_AUDIT"
        else:
            source_result = verify_source_audit(root, args.verify_source_audit, args.evidence_index)
            source_action = "VERIFY_SOURCE_AUDIT"
        print(
            json.dumps(
                {
                    "action": source_action,
                    "status": source_result["status"],
                    "source_audit_sha256": source_result["source_audit_sha256"],
                    "source_counts": source_result["source_counts"],
                    "status_counts": source_result["status_counts"],
                },
                ensure_ascii=False,
                sort_keys=True,
            )
        )
        return 0
    if args.build_evidence_index is not None:
        if not args.verify_sqlite_supersession_history:
            raise Phase2EvidenceError("evidence build requires supersession verification")
        result = build_evidence_index(
            root,
            args.build_evidence_index,
            receipt_path=receipt_path,
            authority_root=authority_root,
        )
    else:
        result = verify_evidence_index(root, args.verify_evidence_index)
    sqlite_successor = cast(Mapping[str, object], result["sqlite_successor"])
    postgresql_history = cast(Mapping[str, object], result["postgresql_history"])
    history_records = cast(list[object], postgresql_history["history_records"])
    reachable_commits = cast(list[object], postgresql_history["reachable_partial_commits"])
    safe = {
        "action": "BUILD" if args.build_evidence_index is not None else "VERIFY",
        "status": result["status"],
        "evidence_index_sha256": result["evidence_index_sha256"],
        "counts": sqlite_successor["counts"],
        "history_records": len(history_records),
        "reachable_partial_commits": len(reachable_commits),
    }
    print(json.dumps(safe, ensure_ascii=False, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
