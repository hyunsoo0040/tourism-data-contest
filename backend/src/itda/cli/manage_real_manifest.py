"""Inspect, request, apply, or verify the exact Phase 2 real-manifest schema."""

from __future__ import annotations

import argparse
import ast
import hashlib
import json
import os
import re
import secrets
import subprocess
from collections.abc import Iterator, Sequence
from contextlib import contextmanager
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any, Literal, TypedDict, cast

import psycopg
from alembic import command
from alembic.config import Config

from itda.cli.approve_real_split import (
    APPROVAL_LEDGER,
    DEFAULT_APPROVAL,
    DEFAULT_BUNDLE,
    verify_split_approval,
)
from itda.contracts.authority import AuthorityConsumptionReceipt
from itda.contracts.real_manifest_seal import (
    EXACT_0002,
    EXACT_0003,
    LiveSchemaClassification,
    SchemaActionRequest,
    SchemaInspection,
    SchemaStateAttestation,
    build_schema_action_authority,
    classify_live_schema,
    inspect_schema_twice,
)
from itda.domain.canonical import canonical_json_bytes, canonical_sha256

EXPECTED_PREDECESSOR_SHA256 = "ecb7685720404a7f5ad17a776f16372542068e4aa7d7ead35e45723a450d4b1b"
EXPECTED_PREDECESSOR_BLOB = "27f828d031d7f5b08ea4b41a5639b1c5dd73af20"
DEFAULT_CONNECTION_ENV = "ITDA_DATABASE_URL"
DEFAULT_CONNECTION_LABEL = "phase2-schema-admin"
DEFAULT_REVIEWER = "phase2-schema-reviewer"
DEFAULT_STATE = Path("artifacts/restricted/catalog/v2/schema/schema-state-attestation.json")
DEFAULT_REQUEST = Path("artifacts/public/catalog/v2/schema-action-request.json")
DEFAULT_PREDECESSOR = Path("backend/migrations/versions/0002_split_boundaries.py")
DEFAULT_MIGRATION = Path("backend/migrations/versions/0003_real_manifest.py")
_LOCK_ID = 0x4954444130303033


def _run_git(root: Path, *arguments: str) -> str:
    completed = subprocess.run(
        ["git", *arguments], cwd=root, check=True, capture_output=True, text=True
    )
    return completed.stdout.strip()


def _revision_values(path: Path) -> tuple[str | None, str | None]:
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    values: dict[str, str | None] = {}
    for node in tree.body:
        if not isinstance(node, ast.Assign) or len(node.targets) != 1:
            continue
        target = node.targets[0]
        if isinstance(target, ast.Name) and target.id in {"revision", "down_revision"}:
            values[target.id] = cast(str | None, ast.literal_eval(node.value))
    return values.get("revision"), values.get("down_revision")


class PredecessorBinding(TypedDict):
    worktree_head_sha1: str
    predecessor_sha256: str
    predecessor_blob_sha1: str
    predecessor_index_mode: Literal["100644"]
    predecessor_index_stage: Literal[0]
    predecessor_clean: Literal[True]
    predecessor_revision: Literal["0002_split_boundaries"]
    predecessor_down_revision: Literal["0001_app_profiles"]


def verify_predecessor(root: Path, path: Path) -> PredecessorBinding:
    absolute = path if path.is_absolute() else root / path
    if not absolute.exists() and not path.is_absolute():
        backend_relative = root / "backend" / path
        if backend_relative.exists():
            absolute = backend_relative
    relative = absolute.relative_to(root).as_posix()
    file_sha = hashlib.sha256(absolute.read_bytes()).hexdigest()
    index = _run_git(root, "ls-files", "-s", "--", relative).split()
    if len(index) != 4:
        raise ValueError("predecessor must have one exact index entry")
    mode, blob, stage = index[0], index[1], int(index[2])
    revision, down_revision = _revision_values(absolute)
    clean = not _run_git(root, "diff", "--name-only", "--", relative) and not _run_git(
        root, "diff", "--cached", "--name-only", "--", relative
    )
    if (
        file_sha != EXPECTED_PREDECESSOR_SHA256
        or blob != EXPECTED_PREDECESSOR_BLOB
        or mode != "100644"
        or stage != 0
        or not clean
        or revision != EXACT_0002
        or down_revision != "0001_app_profiles"
    ):
        raise ValueError("0002 predecessor worktree/index/revision binding drifted")
    return {
        "worktree_head_sha1": _run_git(root, "rev-parse", "HEAD"),
        "predecessor_sha256": file_sha,
        "predecessor_blob_sha1": blob,
        "predecessor_index_mode": "100644",
        "predecessor_index_stage": 0,
        "predecessor_clean": True,
        "predecessor_revision": "0002_split_boundaries",
        "predecessor_down_revision": "0001_app_profiles",
    }


class PsycopgSchemaConnection:
    """Named secret-bearing connection whose outputs are always sanitized hashes."""

    def __init__(self, dsn: str, *, label: str, backend_root: Path) -> None:
        self._sqlalchemy_dsn = dsn
        self._psycopg_dsn = dsn.replace("postgresql+psycopg://", "postgresql://", 1)
        self.label = label
        self.backend_root = backend_root
        self._connection: psycopg.Connection[tuple[Any, ...]] | None = None

    @contextmanager
    def read_lock(self) -> Iterator[None]:
        with psycopg.connect(self._psycopg_dsn) as connection:
            connection.execute("SELECT pg_advisory_lock_shared(%s)", (_LOCK_ID,))
            self._connection = connection
            try:
                yield
            finally:
                self._connection = None
                connection.execute("SELECT pg_advisory_unlock_shared(%s)", (_LOCK_ID,))

    @contextmanager
    def mutation_lock(self) -> Iterator[None]:
        with psycopg.connect(self._psycopg_dsn, autocommit=True) as connection:
            connection.execute("SELECT pg_advisory_lock(%s)", (_LOCK_ID,))
            self._connection = connection
            try:
                yield
            finally:
                self._connection = None
                connection.execute("SELECT pg_advisory_unlock(%s)", (_LOCK_ID,))

    def _active(self) -> psycopg.Connection[tuple[Any, ...]]:
        if self._connection is None:
            raise RuntimeError("schema inspection requires an active read or mutation lock")
        return self._connection

    @staticmethod
    def _rows(connection: psycopg.Connection[tuple[Any, ...]], query: str) -> list[list[Any]]:
        return [list(row) for row in connection.execute(query).fetchall()]

    def inspect(self) -> SchemaInspection:
        connection = self._active()
        version_table = connection.execute(
            "SELECT to_regclass('public.alembic_version')"
        ).fetchone()
        heads: tuple[str, ...] = ()
        if version_table is not None and version_table[0] is not None:
            heads = tuple(
                sorted(
                    str(row[0])
                    for row in connection.execute("SELECT version_num FROM alembic_version")
                )
            )
        objects = self._rows(
            connection,
            "SELECT n.nspname, c.relname, c.relkind FROM pg_class c "
            "JOIN pg_namespace n ON n.oid=c.relnamespace "
            "WHERE n.nspname IN ('app','dev_eval','blind_eval') "
            "AND c.relkind IN ('r','v') ORDER BY 1,2,3",
        )
        constraints = self._rows(
            connection,
            "SELECT n.nspname, c.relname, con.conname, pg_get_constraintdef(con.oid) "
            "FROM pg_constraint con JOIN pg_class c ON c.oid=con.conrelid "
            "JOIN pg_namespace n ON n.oid=c.relnamespace "
            "WHERE n.nspname IN ('app','dev_eval','blind_eval') ORDER BY 1,2,3",
        )
        functions = self._rows(
            connection,
            "SELECT n.nspname, p.proname, pg_get_function_identity_arguments(p.oid), "
            "p.prosecdef FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace "
            "WHERE n.nspname IN ('dev_eval','blind_eval') ORDER BY 1,2,3",
        )
        acls = self._rows(
            connection,
            "SELECT 'schema', n.nspname, coalesce(n.nspacl::text,'') FROM pg_namespace n "
            "WHERE n.nspname IN ('app','dev_eval','blind_eval') UNION ALL "
            "SELECT 'relation', n.nspname||'.'||c.relname, coalesce(c.relacl::text,'') "
            "FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace "
            "WHERE n.nspname IN ('dev_eval','blind_eval') AND c.relkind IN ('r','v') UNION ALL "
            "SELECT 'function', n.nspname||'.'||p.proname, coalesce(p.proacl::text,'') "
            "FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace "
            "WHERE n.nspname IN ('dev_eval','blind_eval') ORDER BY 1,2",
        )
        identity = connection.execute(
            "SELECT current_database(), current_user, current_setting('server_version_num')"
        ).fetchone()
        if identity is None:
            raise ValueError("named connection identity is unavailable")
        role = str(identity[1])
        safe_role = role if re.fullmatch(r"[A-Za-z0-9._-]{1,64}", role) else "role-hash"
        object_hash = canonical_sha256(objects)
        constraint_hash = canonical_sha256(constraints)
        function_hash = canonical_sha256(functions)
        acl_hash = canonical_sha256(acls)
        aggregate = canonical_sha256(
            {
                "heads": list(heads),
                "schema_objects_sha256": object_hash,
                "constraints_sha256": constraint_hash,
                "functions_sha256": function_hash,
                "acls_sha256": acl_hash,
            }
        )
        expected_objects = {
            ("app", "journey_drafts", "r"),
            ("app", "preference_profiles", "r"),
            ("dev_eval", "manifest_members", "r"),
            ("blind_eval", "manifest_members", "r"),
            ("blind_eval", "manifest_seals", "r"),
            ("blind_eval", "evaluator_manifest_v1", "v"),
            ("blind_eval", "internal_manifest_v1", "v"),
        }
        if heads == (EXACT_0003,):
            expected_objects |= {
                ("dev_eval", "real_manifest_members", "r"),
                ("blind_eval", "real_manifest_members", "r"),
                ("blind_eval", "real_manifest_seals", "r"),
            }
        actual_objects = {tuple(str(value) for value in row) for row in objects}
        required_functions = {"seal_manifest_v1"}
        if heads == (EXACT_0003,):
            required_functions |= {"seal_real_manifest_v1", "lookup_real_manifest_seal_v1"}
        actual_functions = {str(row[1]) for row in functions}
        public_grant = any(
            any(part.startswith("=") for part in str(row[2]).strip("{}").split(",")) for row in acls
        )
        contract_valid = (
            heads in {(EXACT_0002,), (EXACT_0003,)}
            and actual_objects == expected_objects
            and actual_functions == required_functions
            and len(constraints) >= 10
            and not public_grant
        )
        return SchemaInspection(
            heads=heads,
            schema_objects_sha256=object_hash,
            constraints_sha256=constraint_hash,
            functions_sha256=function_hash,
            acls_sha256=acl_hash,
            schema_contract_sha256=aggregate,
            expected_schema_contract_sha256=aggregate if contract_valid else "0" * 64,
            effective_role=safe_role,
            connection_binding_sha256=canonical_sha256(
                {"label": self.label, "database": identity[0], "role": role, "server": identity[2]}
            ),
        )

    def upgrade_exactly_one(self, expected_from: str, target: str) -> None:
        if expected_from != EXACT_0002 or target != EXACT_0003:
            raise ValueError("schema upgrade must be exactly 0002 to 0003")
        if classify_live_schema(self.inspect()) is not LiveSchemaClassification.EXACT_0002:
            raise ValueError("schema changed before exact one-revision upgrade")
        config = Config(str(self.backend_root / "alembic.ini"))
        config.set_main_option("sqlalchemy.url", self._sqlalchemy_dsn.replace("%", "%%"))
        command.upgrade(config, EXACT_0003)


def _repo_root(value: Path) -> Path:
    root = value.resolve()
    if not (root / ".planning").is_dir() and (root.parent / ".planning").is_dir():
        root = root.parent
    return root.resolve(strict=True)


def _named_connection(args: argparse.Namespace, root: Path) -> PsycopgSchemaConnection:
    if not args.named_connection:
        raise ValueError("--named-connection is required")
    dsn = os.environ.get(args.connection_env)
    if not dsn:
        raise ValueError(f"named connection environment {args.connection_env} is unset")
    return PsycopgSchemaConnection(dsn, label=args.connection_label, backend_root=root / "backend")


def _canonical_model(path: Path, model: type[Any]) -> Any:
    raw = path.read_bytes()
    parsed = model.model_validate(json.loads(raw))
    if raw != canonical_json_bytes(parsed.model_dump(mode="json")):
        raise ValueError(f"{path} is not typed canonical JSON")
    return parsed


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo-root", type=Path, default=Path.cwd())
    parser.add_argument("--verify-predecessor", type=Path)
    parser.add_argument("--expected-revision")
    parser.add_argument("--prepare-schema-action", action="store_true")
    parser.add_argument("--check-schema-request", type=Path)
    parser.add_argument("--check-state", type=Path)
    parser.add_argument("--verify-schema-receipt", type=Path)
    parser.add_argument("--require-exact-0003", action="store_true")
    parser.add_argument("--named-connection", action="store_true")
    parser.add_argument("--connection-env", default=DEFAULT_CONNECTION_ENV)
    parser.add_argument("--connection-label", default=DEFAULT_CONNECTION_LABEL)
    parser.add_argument("--reviewer-id", default=DEFAULT_REVIEWER)
    parser.add_argument("--state-output", type=Path, default=DEFAULT_STATE)
    parser.add_argument("--request-output", type=Path, default=DEFAULT_REQUEST)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    root = _repo_root(args.repo_root)
    if args.verify_predecessor is not None:
        binding = verify_predecessor(root, args.verify_predecessor)
        if args.expected_revision and binding["predecessor_revision"] != args.expected_revision:
            raise ValueError("predecessor revision differs from expected revision")
        print(binding["predecessor_sha256"])
        return 0

    connection = _named_connection(args, root)
    if args.prepare_schema_action:
        approval = verify_split_approval(
            root / DEFAULT_APPROVAL,
            repo_root=root,
            materialized_bundle_path=root / DEFAULT_BUNDLE,
            require_independent=True,
        )
        ledger_path = root / APPROVAL_LEDGER / "authority-consumption-ledger.jsonl"
        matches: list[AuthorityConsumptionReceipt] = []
        for raw in ledger_path.read_bytes().splitlines():
            receipt = AuthorityConsumptionReceipt.model_validate(json.loads(raw))
            if receipt.result_sha256 == approval.approval_sha256:
                matches.append(receipt)
        if len(matches) != 1:
            raise ValueError("split approval requires one exact authority receipt")
        inspection = inspect_schema_twice(connection)
        predecessor = verify_predecessor(root, DEFAULT_PREDECESSOR)
        issued_at = datetime.now(UTC).replace(microsecond=0)
        state, request = build_schema_action_authority(
            inspection,
            approved_split_sha256=cast(str, approval.approval_sha256),
            approval_receipt_sha256=cast(str, matches[0].receipt_sha256),
            reviewer_id=args.reviewer_id,
            nonce=secrets.token_hex(32),
            issued_at=issued_at,
            expires_at=issued_at + timedelta(days=7),
            **predecessor,
        )
        # Publication is deliberately no-replace and state-first.
        state_path = root / args.state_output
        request_path = root / args.request_output
        if state_path.exists() or request_path.exists():
            raise ValueError("schema authority artifacts are no-replace")
        state_path.parent.mkdir(parents=True, mode=0o700, exist_ok=True)
        state_path.write_bytes(canonical_json_bytes(state.model_dump(mode="json")))
        os.chmod(state_path, 0o600)
        request_path.parent.mkdir(parents=True, mode=0o755, exist_ok=True)
        request_path.write_bytes(canonical_json_bytes(request.model_dump(mode="json")))
        os.chmod(request_path, 0o644)
        print(request.request_sha256)
        return 0

    if args.check_schema_request is not None or args.check_state is not None:
        if args.check_schema_request is None or args.check_state is None:
            raise ValueError("--check-schema-request and --check-state are required together")
        request = _canonical_model(root / args.check_schema_request, SchemaActionRequest)
        state = _canonical_model(root / args.check_state, SchemaStateAttestation)
        inspection = inspect_schema_twice(connection)
        if (
            request.state_attestation_sha256 != state.state_attestation_sha256
            or inspection.schema_contract_sha256 != state.schema_contract_sha256
            or inspection.connection_binding_sha256 != state.connection_binding_sha256
            or classify_live_schema(inspection).value != state.classification.value
        ):
            raise ValueError("schema request/state differ from the named live connection")
        print(request.request_sha256)
        return 0

    if args.verify_schema_receipt is not None:
        if not args.require_exact_0003:
            raise ValueError("schema receipt verification requires --require-exact-0003")
        inspection = inspect_schema_twice(connection)
        if classify_live_schema(inspection) is not LiveSchemaClassification.EXACT_0003:
            raise ValueError("schema receipt named connection is not exact 0003")
        # Plan 30 owns the typed receipt. Plan 29 only proves the exact live postcondition.
        if not (root / args.verify_schema_receipt).is_file():
            raise ValueError("schema action receipt is unavailable")
        print(inspection.schema_contract_sha256)
        return 0
    raise ValueError("one schema management mode is required")


if __name__ == "__main__":
    raise SystemExit(main())
