"""Add immutable BUILD reconciliation and globally unique transition nonces."""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import re
from datetime import date, datetime
from pathlib import Path
from typing import Any

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects.postgresql import JSONB

from itda.contracts.profile_release import (
    ProfileReleaseApproval,
    ProfileReleaseCompletion,
    ProfileReleaseTransitionReceipt,
    profile_release_activate_binding_sha256_v1,
    profile_release_rollback_binding_sha256_v1,
)
from itda.contracts.profile_release_candidate_validation import (
    validate_profile_release_candidate_payload_v1,
)

revision = "0010_phase3_profile_release_build_reconciliation"
down_revision = "0009_phase3_profile_pin_privileges"
branch_labels = None
depends_on = None

_IDENTIFIER = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")
_GLOBAL_NONCE_CONSTRAINT = "uq_phase3_profile_release_nonce_ledger_nonce_sha256"
_PROFILE_RELEASE_BUILDER_CONSTRAINT = "uq_phase3_profile_release_builder_binding"
def _configured_identifier(name: str) -> str | None:
    config = op.get_context().config
    value = config.attributes.get(name) if config is not None else None
    if value is None:
        value = os.environ.get(f"ITDA_{name.upper()}")
    if value is None:
        return None
    if not isinstance(value, str) or _IDENTIFIER.fullmatch(value) is None:
        raise ValueError(f"invalid PostgreSQL identifier for {name}")
    return value


def _quoted_identifier(name: str) -> str:
    return op.get_bind().dialect.identifier_preparer.quote(name)


def _grant(statement: str, role: str | None) -> None:
    if role is not None:
        op.execute(sa.text(f"{statement} TO {_quoted_identifier(role)}"))


def _configured_sha256(name: str) -> str | None:
    config = op.get_context().config
    value = config.attributes.get(name)
    if value is None:
        value = os.environ.get(f"ITDA_{name.upper()}")
    if value is None:
        return None
    if not isinstance(value, str) or re.fullmatch(r"[0-9a-f]{64}", value) is None:
        raise ValueError(f"invalid SHA-256 approval fingerprint for {name}")
    return value


def _json_value(value: Any) -> Any:
    if isinstance(value, (datetime, date)):
        return value.isoformat()
    if isinstance(value, dict):
        return {str(key): _json_value(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [_json_value(item) for item in value]
    return value


def _canonical_sha256(value: object) -> str:
    encoded = json.dumps(
        _json_value(value),
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
        allow_nan=False,
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _configured_path(name: str) -> Path | None:
    config = op.get_context().config
    value = config.attributes.get(name) if config is not None else None
    if value is None:
        value = os.environ.get(f"ITDA_{name.upper()}")
    if value is None:
        return None
    if not isinstance(value, (str, os.PathLike)):
        raise ValueError(f"invalid path for {name}")
    return Path(value)


def _database_identity(connection: sa.Connection) -> dict[str, object]:
    deployment_sha256 = _configured_sha256("profile_release_database_identity_sha256")
    if deployment_sha256 is None:
        raise RuntimeError(
            "0010 protected predecessor remediation requires an explicit stable database "
            "identity digest"
        )
    row = connection.execute(
        sa.text(
            "SELECT current_database() AS database_name, oid AS database_oid "
            "FROM pg_database WHERE datname = current_database()"
        )
    ).mappings().one()
    return {
        "schema_version": "itda.profile-release-database-identity.v1",
        "database_name": row["database_name"],
        "database_oid": row["database_oid"],
        "deployment_identity_sha256": deployment_sha256,
    }


def _snapshot_table(
    connection: sa.Connection,
    *,
    table: str,
    columns: str,
    order_by: str,
) -> list[dict[str, object]]:
    return [
        _json_value(dict(row))
        for row in connection.execute(
            sa.text(
                f"SELECT {columns} FROM dev_eval.{table} ORDER BY {order_by}"
            )
        ).mappings()
    ]


def _predecessor_snapshot(connection: sa.Connection) -> dict[str, object]:
    return {
        "schema_version": "itda.profile-release-predecessor-snapshot.v1",
        "profile_releases": _snapshot_table(
            connection,
            table="profile_releases",
            columns=(
                "release_sha256, release_id, builder_principal, "
                "canonical_lineage_sha256, dev_lineage_sha256, "
                "profile_schema_sha256, payload, built_at"
            ),
            order_by="release_sha256",
        ),
        "lifecycle_heads": _snapshot_table(
            connection,
            table="profile_release_lifecycle_heads",
            columns="release_sha256, state, head_receipt_sha256",
            order_by="release_sha256",
        ),
        "approvals": _snapshot_table(
            connection,
            table="profile_release_approvals",
            columns=(
                "approval_sha256, release_sha256, builder_principal, "
                "approver_principal, payload, approved_at"
            ),
            order_by="approval_sha256",
        ),
        "transition_events": _snapshot_table(
            connection,
            table="profile_release_transition_events",
            columns=(
                "receipt_sha256, action, release_sha256, previous_release_sha256, "
                "expected_current_sha256, approver_principal, nonce_sha256, payload, "
                "occurred_at"
            ),
            order_by="receipt_sha256",
        ),
        "rollback_receipts": _snapshot_table(
            connection,
            table="profile_release_rollback_receipts",
            columns=(
                "receipt_sha256, transition_receipt_sha256, release_sha256, "
                "approver_principal, reason, reason_sha256, payload"
            ),
            order_by="receipt_sha256",
        ),
        "active_pointer": _snapshot_table(
            connection,
            table="profile_release_active_pointer",
            columns="slot, release_sha256, receipt_sha256",
            order_by="slot",
        ),
        "nonce_ledger": _snapshot_table(
            connection,
            table="profile_release_nonce_ledger",
            columns="binding_sha256, nonce_sha256, receipt_sha256, payload",
            order_by="nonce_sha256, binding_sha256, receipt_sha256",
        ),
        "session_pins": _snapshot_table(
            connection,
            table="profile_release_session_pins",
            columns="session_ref, release_sha256, pin_sha256, pinned_at",
            order_by="session_ref",
        ),
        "result_pins": _snapshot_table(
            connection,
            table="profile_release_result_pins",
            columns="result_ref, release_sha256, pin_sha256, pinned_at",
            order_by="result_ref",
        ),
    }


def _build_binding_sha256(*, builder_principal: str, release_sha256: str) -> str:
    return _canonical_sha256(
        {
            "action": "BUILD",
            "builder": builder_principal,
            "release_sha256": release_sha256,
        }
    )


def _validated_canonical_predecessor_candidate(
    release: dict[str, object],
) -> dict[str, object]:
    payload = release.get("payload")
    if not isinstance(payload, dict):
        raise RuntimeError("0010 predecessor release canonical payload is invalid")
    try:
        validated = validate_profile_release_candidate_payload_v1(payload)
    except (TypeError, ValueError) as error:
        raise RuntimeError(
            "0010 predecessor release canonical payload is invalid"
        ) from error
    if any(
        validated[field] != release.get(field)
        for field in (
            "release_sha256",
            "release_id",
            "builder_principal",
            "canonical_lineage_sha256",
            "dev_lineage_sha256",
            "profile_schema_sha256",
        )
    ):
        raise RuntimeError("0010 predecessor release identity or lineage is invalid")
    return validated


def _validated_predecessor_backfill(
    connection: sa.Connection,
    *,
    predecessor_snapshot: dict[str, object],
    database_identity: dict[str, object],
) -> list[dict[str, str]]:
    releases = predecessor_snapshot["profile_releases"]
    if not isinstance(releases, list) or not releases:
        return []
    database_identity_sha256 = _canonical_sha256(database_identity)
    predecessor_snapshot_sha256 = _canonical_sha256(predecessor_snapshot)
    path = _configured_path("profile_release_provenance_backfill_path")
    if path is None:
        raise RuntimeError(
            "0010 refuses a populated 0009 predecessor without an explicitly approved "
            "cryptographically verifiable BUILD provenance backfill; "
            f"release_count={len(releases)}, "
            f"database_identity_sha256={database_identity_sha256}, "
            f"predecessor_snapshot_sha256={predecessor_snapshot_sha256}"
        )
    raw = path.read_bytes()
    if len(raw) > 8_000_000:
        raise RuntimeError("0010 predecessor provenance backfill exceeds the size limit")
    try:
        manifest = json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise RuntimeError("0010 predecessor provenance backfill is invalid JSON") from error
    if not isinstance(manifest, dict) or set(manifest) != {
        "schema_version",
        "database_identity_sha256",
        "predecessor_snapshot_sha256",
        "receipts",
    }:
        raise RuntimeError("0010 predecessor provenance backfill shape is invalid")
    if (
        manifest["schema_version"]
        != "itda.profile-release-build-provenance-backfill.v1"
        or manifest["database_identity_sha256"] != database_identity_sha256
        or manifest["predecessor_snapshot_sha256"] != predecessor_snapshot_sha256
        or not isinstance(manifest["receipts"], list)
    ):
        raise RuntimeError("0010 predecessor provenance backfill binding is invalid")
    release_rows = {str(row["release_sha256"]): row for row in releases}
    validated: list[dict[str, str]] = []
    seen_releases: set[str] = set()
    seen_receipts: set[str] = set()
    seen_builder_nonces: set[tuple[str, str]] = set()
    for item in manifest["receipts"]:
        if not isinstance(item, dict) or set(item) != {
            "builder_principal",
            "raw_nonce",
            "nonce_sha256",
            "binding_sha256",
            "release_sha256",
            "receipt_sha256",
        }:
            raise RuntimeError("0010 predecessor provenance receipt shape is invalid")
        if any(not isinstance(value, str) for value in item.values()):
            raise RuntimeError("0010 predecessor provenance receipt values are invalid")
        raw_nonce = item["raw_nonce"]
        nonce_sha256 = item["nonce_sha256"]
        release_sha256 = item["release_sha256"]
        builder_principal = item["builder_principal"]
        if re.fullmatch(r"[0-9a-f]{64}", raw_nonce) is None or any(
            re.fullmatch(r"[0-9a-f]{64}", item[field]) is None
            for field in (
                "nonce_sha256",
                "binding_sha256",
                "release_sha256",
                "receipt_sha256",
            )
        ):
            raise RuntimeError("0010 predecessor provenance receipt hashes are invalid")
        release = release_rows.get(release_sha256)
        if release is None or release["builder_principal"] != builder_principal:
            raise RuntimeError("0010 predecessor provenance release binding is invalid")
        payload = _validated_canonical_predecessor_candidate(release)
        if (
            payload["release_sha256"] != release_sha256
            or payload["builder_principal"] != builder_principal
        ):
            raise RuntimeError("0010 predecessor provenance release binding is invalid")
        expected_nonce = hashlib.sha256(raw_nonce.encode("ascii")).hexdigest()
        expected_binding = _build_binding_sha256(
            builder_principal=builder_principal,
            release_sha256=release_sha256,
        )
        expected_receipt = _canonical_sha256(
            {
                "schema_version": "itda.profile-release-build-receipt.v1",
                "release_sha256": release_sha256,
                "builder_principal": builder_principal,
                "nonce_sha256": nonce_sha256,
                "binding_sha256": item["binding_sha256"],
            }
        )
        if (
            not hmac.compare_digest(nonce_sha256, expected_nonce)
            or not hmac.compare_digest(item["binding_sha256"], expected_binding)
            or not hmac.compare_digest(item["receipt_sha256"], expected_receipt)
        ):
            raise RuntimeError("0010 predecessor provenance receipt proof is invalid")
        builder_nonce = (builder_principal, nonce_sha256)
        if (
            release_sha256 in seen_releases
            or item["receipt_sha256"] in seen_receipts
            or builder_nonce in seen_builder_nonces
        ):
            raise RuntimeError("0010 predecessor provenance receipt coverage is ambiguous")
        seen_releases.add(release_sha256)
        seen_receipts.add(item["receipt_sha256"])
        seen_builder_nonces.add(builder_nonce)
        validated.append({key: str(value) for key, value in item.items() if key != "raw_nonce"})
    if seen_releases != set(release_rows):
        raise RuntimeError("0010 predecessor provenance backfill coverage is incomplete")
    manifest_sha256 = _canonical_sha256(manifest)
    expected_approval = _canonical_sha256(
        {
            "schema_version": "itda.profile-release-build-provenance-approval.v1",
            "database_identity_sha256": database_identity_sha256,
            "predecessor_snapshot_sha256": predecessor_snapshot_sha256,
            "manifest_sha256": manifest_sha256,
        }
    )
    approved = _configured_sha256("profile_release_provenance_backfill_approval_sha256")
    if approved is None or not hmac.compare_digest(approved, expected_approval):
        raise RuntimeError(
            "0010 predecessor provenance backfill requires exact human approval; "
            f"approval_sha256={expected_approval}"
        )
    return validated


def _duplicate_inventory(connection: sa.Connection) -> list[dict[str, object]]:
    return [
        _json_value(dict(row))
        for row in connection.execute(
            sa.text(
                "SELECT ledger.binding_sha256, ledger.nonce_sha256, "
                "ledger.receipt_sha256, ledger.payload, "
                "(SELECT count(*) FROM dev_eval.profile_release_transition_events events "
                " WHERE events.receipt_sha256 = ledger.receipt_sha256 "
                " AND events.nonce_sha256 = ledger.nonce_sha256 "
                " AND events.payload = ledger.payload) AS event_matches, "
                "(SELECT count(*) FROM dev_eval.profile_release_lifecycle_heads heads "
                " WHERE heads.head_receipt_sha256 = ledger.receipt_sha256) AS head_references, "
                "(SELECT count(*) FROM dev_eval.profile_release_rollback_receipts rollbacks "
                " WHERE rollbacks.transition_receipt_sha256 = ledger.receipt_sha256) "
                " AS rollback_references, "
                "(SELECT count(*) FROM dev_eval.profile_release_active_pointer pointer "
                " WHERE pointer.receipt_sha256 = ledger.receipt_sha256) AS pointer_references "
                "FROM dev_eval.profile_release_nonce_ledger ledger "
                "WHERE ledger.nonce_sha256 IN ("
                " SELECT nonce_sha256 FROM dev_eval.profile_release_nonce_ledger "
                " GROUP BY nonce_sha256 HAVING count(*) > 1"
                ") ORDER BY ledger.nonce_sha256, ledger.binding_sha256, "
                "ledger.receipt_sha256"
            )
        ).mappings()
    ]


def _validated_transition_history(
    connection: sa.Connection,
) -> dict[str, dict[str, object]]:
    """Validate the complete transition chain and its current two-head projection."""

    releases: dict[str, dict[str, object]] = {}
    for row in connection.execute(
        sa.text(
            "SELECT release_sha256, builder_principal, canonical_lineage_sha256, "
            "dev_lineage_sha256, profile_schema_sha256, payload FROM "
            "dev_eval.profile_releases"
        )
    ).mappings():
        payload = row["payload"]
        if not isinstance(payload, dict):
            raise ValueError("profile release payload is not an object")
        validated_payload = validate_profile_release_candidate_payload_v1(payload)
        if validated_payload != payload or any(
            validated_payload[field] != row[field]
            for field in (
                "release_sha256",
                "builder_principal",
                "canonical_lineage_sha256",
                "dev_lineage_sha256",
                "profile_schema_sha256",
            )
        ):
            raise ValueError("profile release columns differ from canonical payload")
        release_sha256 = str(row["release_sha256"])
        if release_sha256 in releases:
            raise ValueError("profile release authority is ambiguous")
        releases[release_sha256] = validated_payload

    approvals: dict[str, ProfileReleaseApproval] = {}
    for row in connection.execute(
        sa.text(
            "SELECT approval_sha256, release_sha256, builder_principal, "
            "approver_principal, payload FROM dev_eval.profile_release_approvals"
        )
    ).mappings():
        payload = row["payload"]
        if not isinstance(payload, dict):
            raise ValueError("profile release approval payload is not an object")
        approval = ProfileReleaseApproval.model_validate(payload)
        if any(
            getattr(approval, field) != row[field]
            for field in (
                "approval_sha256",
                "release_sha256",
                "builder_principal",
                "approver_principal",
            )
        ):
            raise ValueError("profile release approval columns differ from payload")
        release_sha256 = str(approval.release_sha256)
        release = releases.get(release_sha256)
        if release is None or approval.builder_principal != release["builder_principal"]:
            raise ValueError("profile release approval is not linked to its builder")
        if release_sha256 in approvals:
            raise ValueError("profile release approval authority is ambiguous")
        approvals[release_sha256] = approval

    event_rows = connection.execute(
        sa.text(
            "SELECT receipt_sha256, action, release_sha256, previous_release_sha256, "
            "expected_current_sha256, approver_principal, nonce_sha256, payload, "
            "occurred_at FROM dev_eval.profile_release_transition_events "
            "ORDER BY occurred_at, receipt_sha256"
        )
    ).mappings().all()
    validated: dict[str, dict[str, object]] = {}
    expected_heads: dict[str, tuple[str, str]] = {}
    prior_active_releases: set[str] = set()
    current_release_sha256: str | None = None
    current_receipt_sha256: str | None = None
    for row in event_rows:
        payload = row["payload"]
        if not isinstance(payload, dict):
            raise ValueError("transition payload is not an object")
        receipt = ProfileReleaseTransitionReceipt.model_validate(payload)
        if receipt.completion is not ProfileReleaseCompletion.MUTATION_COMMITTED:
            raise ValueError("persisted transition completion is not authoritative")
        target_release = releases.get(receipt.release_sha256)
        target_approval = approvals.get(receipt.release_sha256)
        if target_release is None or target_approval is None:
            raise ValueError("transition target lacks exact independent approval")
        receipt_payload = receipt.model_dump(mode="json")
        if receipt_payload != payload or any(
            receipt_payload[field] != row[field]
            for field in (
                "receipt_sha256",
                "action",
                "release_sha256",
                "previous_release_sha256",
                "expected_current_sha256",
                "approver_principal",
                "nonce_sha256",
            )
        ):
            raise ValueError("transition columns differ from the typed receipt")
        if receipt.previous_release_sha256 != current_release_sha256:
            raise ValueError("transition history compare-and-swap chain is broken")
        if receipt.release_sha256 == current_release_sha256:
            raise ValueError("transition cannot reactivate the current release")
        if (
            receipt.action == "ROLLBACK"
            and receipt.release_sha256 not in prior_active_releases
        ):
            raise ValueError("rollback target was never previously active")
        if receipt.action == "ACTIVATE":
            if target_approval.approver_principal != receipt.approver_principal:
                raise ValueError("activation principal differs from exact approval")
            binding_sha256 = profile_release_activate_binding_sha256_v1(
                target_sha256=receipt.release_sha256,
                expected_current_sha256=receipt.expected_current_sha256,
            )
            rollback_rows = list(
                connection.execute(
                    sa.text(
                        "SELECT receipt_sha256 FROM "
                        "dev_eval.profile_release_rollback_receipts "
                        "WHERE transition_receipt_sha256 = :receipt"
                    ),
                    {"receipt": receipt.receipt_sha256},
                ).mappings()
            )
            if rollback_rows:
                raise ValueError("activation has a rollback-only receipt")
        else:
            assert receipt.reason is not None
            current_release = releases.get(str(receipt.previous_release_sha256))
            if current_release is None:
                raise ValueError("rollback current release is missing")
            if hmac.compare_digest(
                str(current_release["builder_principal"]),
                receipt.approver_principal,
            ):
                raise ValueError("rollback principal is not independent of current builder")
            if any(
                current_release[field] != target_release[field]
                for field in (
                    "canonical_lineage_sha256",
                    "dev_lineage_sha256",
                    "profile_schema_sha256",
                )
            ):
                raise ValueError("rollback target has incompatible immutable lineage")
            reason_sha256 = hashlib.sha256(receipt.reason.encode("utf-8")).hexdigest()
            binding_sha256 = profile_release_rollback_binding_sha256_v1(
                target_sha256=receipt.release_sha256,
                expected_current_sha256=str(receipt.expected_current_sha256),
                reason_sha256=reason_sha256,
                approver_principal=receipt.approver_principal,
            )
            rollback_rows = list(
                connection.execute(
                    sa.text(
                        "SELECT receipt_sha256, transition_receipt_sha256, "
                        "release_sha256, approver_principal, reason, reason_sha256, "
                        "payload FROM dev_eval.profile_release_rollback_receipts "
                        "WHERE transition_receipt_sha256 = :receipt"
                    ),
                    {"receipt": receipt.receipt_sha256},
                ).mappings()
            )
            if len(rollback_rows) != 1:
                raise ValueError("rollback transition lacks one exact rollback receipt")
            rollback = rollback_rows[0]
            if not (
                rollback["receipt_sha256"] == receipt.receipt_sha256
                and rollback["transition_receipt_sha256"] == receipt.receipt_sha256
                and rollback["release_sha256"] == receipt.release_sha256
                and rollback["approver_principal"] == receipt.approver_principal
                and rollback["reason"] == receipt.reason
                and rollback["reason_sha256"] == reason_sha256
                and rollback["payload"] == receipt_payload
            ):
                raise ValueError("rollback receipt differs from transition authority")
        if current_release_sha256 is not None:
            expected_heads[current_release_sha256] = (
                "APPROVED_INACTIVE",
                str(receipt.receipt_sha256),
            )
        expected_heads[receipt.release_sha256] = (
            "ACTIVE",
            str(receipt.receipt_sha256),
        )
        prior_active_releases.add(receipt.release_sha256)
        current_release_sha256 = receipt.release_sha256
        current_receipt_sha256 = str(receipt.receipt_sha256)
        validated[current_receipt_sha256] = {
            "payload": receipt_payload,
            "nonce_sha256": receipt.nonce_sha256,
            "binding_sha256": binding_sha256,
        }

    actual_heads = {
        str(row["release_sha256"]): (
            str(row["state"]),
            str(row["head_receipt_sha256"]),
        )
        for row in connection.execute(
            sa.text(
                "SELECT release_sha256, state, head_receipt_sha256 FROM "
                "dev_eval.profile_release_lifecycle_heads"
            )
        ).mappings()
        if row["release_sha256"] in expected_heads
    }
    if actual_heads != expected_heads:
        raise ValueError("transition history differs from the lifecycle two-head projection")
    pointers = connection.execute(
        sa.text(
            "SELECT slot, release_sha256, receipt_sha256 FROM "
            "dev_eval.profile_release_active_pointer"
        )
    ).mappings().all()
    if event_rows:
        if len(pointers) != 1 or not (
            pointers[0]["slot"] == "DEV"
            and pointers[0]["release_sha256"] == current_release_sha256
            and pointers[0]["receipt_sha256"] == current_receipt_sha256
        ):
            raise ValueError("transition history differs from the active pointer")
    elif pointers:
        raise ValueError("active pointer exists without transition history")
    return validated


def _duplicate_transition_is_authoritative(
    connection: sa.Connection,
    row: dict[str, object],
) -> bool:
    try:
        validated = _validated_transition_history(connection)
    except (TypeError, ValueError):
        return False
    authority = validated.get(str(row["receipt_sha256"]))
    return bool(
        authority is not None
        and authority["payload"] == row["payload"]
        and authority["nonce_sha256"] == row["nonce_sha256"]
        and hmac.compare_digest(
            str(authority["binding_sha256"]), str(row["binding_sha256"])
        )
    )


def _duplicate_plan(
    connection: sa.Connection,
    rows: list[dict[str, object]],
    *,
    database_identity: dict[str, object],
) -> tuple[str, list[dict[str, object]], dict[str, dict[str, str]]]:
    database_identity_sha256 = _canonical_sha256(database_identity)
    grouped: dict[str, list[dict[str, object]]] = {}
    for row in rows:
        grouped.setdefault(str(row["nonce_sha256"]), []).append(row)
    authoritative: dict[str, dict[str, str]] = {}
    for nonce_sha256, group in grouped.items():
        event_valid = [
            row
            for row in group
            if row["event_matches"] == 1
            and _duplicate_transition_is_authoritative(connection, row)
        ]
        unsafe_reachable = [
            row
            for row in group
            if row not in event_valid
            and any(
                int(row[field]) > 0
                for field in (
                    "event_matches",
                    "head_references",
                    "rollback_references",
                    "pointer_references",
                )
            )
        ]
        if len(event_valid) != 1 or unsafe_reachable:
            raise RuntimeError(
                "0010 duplicate nonce authority is absent or ambiguous; "
                f"duplicate_groups={len(grouped)}"
            )
        winner = event_valid[0]
        authoritative[nonce_sha256] = {
            "binding_sha256": str(winner["binding_sha256"]),
            "receipt_sha256": str(winner["receipt_sha256"]),
        }
    snapshot = {
        "schema_version": "itda.profile-release-nonce-remediation-snapshot.v2",
        "database_identity_sha256": database_identity_sha256,
        "rows": rows,
    }
    snapshot_sha256 = _canonical_sha256(snapshot)
    approval_sha256 = _canonical_sha256(
        {
            "schema_version": "itda.profile-release-nonce-remediation-approval.v2",
            "database_identity_sha256": database_identity_sha256,
            "snapshot_sha256": snapshot_sha256,
        }
    )
    approved = _configured_sha256("profile_release_nonce_reconciliation_approval_sha256")
    if approved is None or not hmac.compare_digest(approved, approval_sha256):
        raise RuntimeError(
            "0010 found predecessor-valid duplicate transition nonce groups; "
            f"duplicate_groups={len(grouped)}, snapshot_sha256={snapshot_sha256}, "
            f"approval_sha256={approval_sha256}; review the non-sensitive count and "
            "fingerprints, then rerun with exact human approval"
        )
    extras = [
        row
        for row in rows
        if (
            str(row["binding_sha256"])
            != authoritative[str(row["nonce_sha256"])]["binding_sha256"]
            or str(row["receipt_sha256"])
            != authoritative[str(row["nonce_sha256"])]["receipt_sha256"]
        )
    ]
    return snapshot_sha256, extras, authoritative


def upgrade() -> None:
    builder = _configured_identifier("label_builder_role")
    approver = _configured_identifier("label_approver_role")
    connection = op.get_bind()
    connection.execute(
        sa.text(
            "LOCK TABLE dev_eval.profile_releases, "
            "dev_eval.profile_release_lifecycle_heads, "
            "dev_eval.profile_release_approvals, "
            "dev_eval.profile_release_transition_events, "
            "dev_eval.profile_release_rollback_receipts, "
            "dev_eval.profile_release_active_pointer, "
            "dev_eval.profile_release_nonce_ledger, "
            "dev_eval.profile_release_session_pins, "
            "dev_eval.profile_release_result_pins IN SHARE ROW EXCLUSIVE MODE"
        )
    )
    predecessor_snapshot = _predecessor_snapshot(connection)
    predecessor_releases = predecessor_snapshot["profile_releases"]
    duplicate_rows = _duplicate_inventory(connection)
    database_identity: dict[str, object] | None = None
    if predecessor_releases or duplicate_rows:
        database_identity = _database_identity(connection)
    backfill_rows = (
        _validated_predecessor_backfill(
            connection,
            predecessor_snapshot=predecessor_snapshot,
            database_identity=database_identity,
        )
        if predecessor_releases and database_identity is not None
        else []
    )
    duplicate_snapshot_sha256: str | None = None
    duplicate_extras: list[dict[str, object]] = []
    duplicate_authoritative: dict[str, dict[str, str]] = {}
    if duplicate_rows and database_identity is not None:
        (
            duplicate_snapshot_sha256,
            duplicate_extras,
            duplicate_authoritative,
        ) = _duplicate_plan(
            connection,
            duplicate_rows,
            database_identity=database_identity,
        )

    op.create_unique_constraint(
        _PROFILE_RELEASE_BUILDER_CONSTRAINT,
        "profile_releases",
        ["release_sha256", "builder_principal"],
        schema="dev_eval",
    )
    op.create_table(
        "profile_release_build_nonce_reservations",
        sa.Column("builder_principal", sa.Text(), nullable=False),
        sa.Column("nonce_sha256", sa.Text(), nullable=False),
        sa.Column("candidate_sha256", sa.Text(), nullable=False),
        sa.Column("draft_ref_sha256", sa.Text(), nullable=True),
        sa.Column(
            "reserved_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.text("CURRENT_TIMESTAMP"),
        ),
        sa.CheckConstraint(
            "nonce_sha256 ~ '^[0-9a-f]{64}$' AND "
            "candidate_sha256 ~ '^[0-9a-f]{64}$' AND "
            "(draft_ref_sha256 IS NULL OR "
            "draft_ref_sha256 ~ '^[0-9a-f]{64}$')",
            name="ck_phase3_profile_release_build_nonce_reservation_hashes",
        ),
        sa.PrimaryKeyConstraint(
            "builder_principal",
            "nonce_sha256",
            name="pk_phase3_profile_release_build_nonce_reservations",
        ),
        sa.UniqueConstraint(
            "builder_principal",
            "nonce_sha256",
            "candidate_sha256",
            name="uq_phase3_profile_release_build_nonce_reservation_candidate",
        ),
        sa.UniqueConstraint(
            "builder_principal",
            "nonce_sha256",
            "candidate_sha256",
            "draft_ref_sha256",
            name="uq_phase3_profile_release_build_nonce_reservation_draft",
        ),
        schema="dev_eval",
    )
    op.create_table(
        "profile_release_build_receipts",
        sa.Column("builder_principal", sa.Text(), nullable=False),
        sa.Column("nonce_sha256", sa.Text(), nullable=False),
        sa.Column("binding_sha256", sa.Text(), nullable=False),
        sa.Column("release_sha256", sa.Text(), nullable=False),
        sa.Column("receipt_sha256", sa.Text(), nullable=False),
        sa.Column(
            "committed_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.text("CURRENT_TIMESTAMP"),
        ),
        sa.ForeignKeyConstraint(
            ["release_sha256", "builder_principal"],
            [
                "dev_eval.profile_releases.release_sha256",
                "dev_eval.profile_releases.builder_principal",
            ],
            name="fk_phase3_profile_release_build_receipt_release",
            ondelete="RESTRICT",
        ),
        sa.ForeignKeyConstraint(
            ["builder_principal", "nonce_sha256", "release_sha256"],
            [
                "dev_eval.profile_release_build_nonce_reservations.builder_principal",
                "dev_eval.profile_release_build_nonce_reservations.nonce_sha256",
                "dev_eval.profile_release_build_nonce_reservations.candidate_sha256",
            ],
            name="fk_phase3_profile_release_build_receipt_nonce_reservation",
            ondelete="RESTRICT",
        ),
        sa.CheckConstraint(
            "nonce_sha256 ~ '^[0-9a-f]{64}$' AND "
            "binding_sha256 ~ '^[0-9a-f]{64}$' AND "
            "release_sha256 ~ '^[0-9a-f]{64}$' AND "
            "receipt_sha256 ~ '^[0-9a-f]{64}$'",
            name="ck_phase3_profile_release_build_receipt_hashes",
        ),
        sa.PrimaryKeyConstraint(
            "builder_principal",
            "nonce_sha256",
            name="pk_phase3_profile_release_build_receipts",
        ),
        sa.UniqueConstraint(
            "release_sha256",
            name="uq_phase3_profile_release_build_receipt_release",
        ),
        sa.UniqueConstraint(
            "receipt_sha256",
            name="uq_phase3_profile_release_build_receipt_receipt",
        ),
        sa.UniqueConstraint(
            "builder_principal",
            "nonce_sha256",
            "release_sha256",
            "receipt_sha256",
            name="uq_phase3_profile_release_build_receipt_consumption_binding",
        ),
        schema="dev_eval",
    )
    if backfill_rows:
        connection.execute(
            sa.text(
                "INSERT INTO dev_eval.profile_release_build_nonce_reservations ("
                "builder_principal, nonce_sha256, candidate_sha256, draft_ref_sha256) "
                "VALUES (:builder_principal, :nonce_sha256, :release_sha256, NULL)"
            ),
            backfill_rows,
        )
        connection.execute(
            sa.text(
                "INSERT INTO dev_eval.profile_release_build_receipts ("
                "builder_principal, nonce_sha256, binding_sha256, release_sha256, "
                "receipt_sha256) VALUES ("
                ":builder_principal, :nonce_sha256, :binding_sha256, "
                ":release_sha256, :receipt_sha256)"
            ),
            backfill_rows,
        )
    op.execute(
        """
        CREATE FUNCTION dev_eval.canonical_jsonb_compact_v1(value jsonb)
        RETURNS text
        LANGUAGE sql
        IMMUTABLE
        STRICT
        SET search_path = pg_catalog
        AS $$
            SELECT CASE jsonb_typeof(value)
                WHEN 'object' THEN COALESCE((
                    SELECT '{' || string_agg(
                        to_json(key)::text || ':' ||
                        dev_eval.canonical_jsonb_compact_v1(item),
                        ',' ORDER BY key
                    ) || '}'
                    FROM jsonb_each(value) AS entries(key, item)
                ), '{}')
                WHEN 'array' THEN COALESCE((
                    SELECT '[' || string_agg(
                        dev_eval.canonical_jsonb_compact_v1(item),
                        ',' ORDER BY ordinal
                    ) || ']'
                    FROM jsonb_array_elements(value)
                    WITH ORDINALITY AS entries(item, ordinal)
                ), '[]')
                ELSE value::text
            END
        $$
        """
    )
    op.execute(
        """
        CREATE FUNCTION dev_eval.validate_profile_release_candidate_payload_v1(
            candidate jsonb
        )
        RETURNS boolean
        LANGUAGE plpgsql
        IMMUTABLE
        STRICT
        SET search_path = pg_catalog, dev_eval
        AS $$
        DECLARE
            member jsonb;
            expected_release_sha256 text;
            required_candidate_keys text[] := ARRAY[
                'schema_version', 'release_id', 'state', 'builder_principal',
                'canonical_lineage_sha256', 'dev_lineage_sha256',
                'profile_schema_sha256', 'label_freeze_sha256',
                'candidate_run_sha256', 'reviewed_manifest_sha256',
                'rights_manifest_sha256', 'source_manifest_sha256',
                'code_sha256', 'config_sha256', 'cohort', 'release_sha256'
            ];
            required_member_keys text[] := ARRAY[
                'place_ref', 'label_ready', 'rights_ready', 'evidence_ready',
                'description_lane', 'odii_lane', 'profile_sha256',
                'label_export_sha256', 'candidate_manifest_sha256',
                'reviewed_evidence_manifest_sha256',
                'accepted_review_set_sha256', 'rights_sha256', 'source_sha256'
            ];
            optional_candidate_digest_keys text[] := ARRAY[
                'label_freeze_sha256', 'candidate_run_sha256',
                'reviewed_manifest_sha256', 'rights_manifest_sha256',
                'source_manifest_sha256', 'code_sha256', 'config_sha256'
            ];
            optional_member_digest_keys text[] := ARRAY[
                'label_export_sha256', 'candidate_manifest_sha256',
                'reviewed_evidence_manifest_sha256',
                'accepted_review_set_sha256', 'rights_sha256', 'source_sha256'
            ];
            digest_key text;
        BEGIN
            IF jsonb_typeof(candidate) IS DISTINCT FROM 'object'
               OR (SELECT count(*) FROM jsonb_object_keys(candidate)) IS DISTINCT FROM 16
               OR NOT candidate ?& required_candidate_keys
               OR jsonb_typeof(candidate -> 'schema_version') IS DISTINCT FROM 'string'
               OR candidate ->> 'schema_version'
                    IS DISTINCT FROM 'itda.profile-release-candidate.v1'
               OR jsonb_typeof(candidate -> 'state') IS DISTINCT FROM 'string'
               OR candidate ->> 'state' IS DISTINCT FROM 'BUILT_UNAPPROVED'
               OR jsonb_typeof(candidate -> 'release_id') IS DISTINCT FROM 'string'
               OR candidate ->> 'release_id'
                    !~ '^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$'
               OR jsonb_typeof(candidate -> 'builder_principal') IS DISTINCT FROM 'string'
               OR candidate ->> 'builder_principal'
                    !~ '^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$'
               OR jsonb_typeof(candidate -> 'canonical_lineage_sha256') IS DISTINCT FROM 'string'
               OR candidate ->> 'canonical_lineage_sha256' !~ '^[0-9a-f]{64}$'
               OR jsonb_typeof(candidate -> 'dev_lineage_sha256') IS DISTINCT FROM 'string'
               OR candidate ->> 'dev_lineage_sha256' !~ '^[0-9a-f]{64}$'
               OR jsonb_typeof(candidate -> 'profile_schema_sha256') IS DISTINCT FROM 'string'
               OR candidate ->> 'profile_schema_sha256' !~ '^[0-9a-f]{64}$'
               OR jsonb_typeof(candidate -> 'release_sha256') IS DISTINCT FROM 'string'
               OR candidate ->> 'release_sha256' !~ '^[0-9a-f]{64}$'
               OR jsonb_typeof(candidate -> 'cohort') IS DISTINCT FROM 'array'
               OR jsonb_array_length(candidate -> 'cohort') IS DISTINCT FROM 24 THEN
                RETURN false;
            END IF;
            FOREACH digest_key IN ARRAY optional_candidate_digest_keys LOOP
                IF jsonb_typeof(candidate -> digest_key) IS DISTINCT FROM 'null' AND (
                    jsonb_typeof(candidate -> digest_key) IS DISTINCT FROM 'string'
                    OR candidate ->> digest_key !~ '^[0-9a-f]{64}$'
                ) THEN
                    RETURN false;
                END IF;
            END LOOP;
            FOR member IN
                SELECT value FROM jsonb_array_elements(candidate -> 'cohort')
            LOOP
                IF jsonb_typeof(member) IS DISTINCT FROM 'object'
                   OR (SELECT count(*) FROM jsonb_object_keys(member)) IS DISTINCT FROM 13
                   OR NOT member ?& required_member_keys
                   OR jsonb_typeof(member -> 'place_ref') IS DISTINCT FROM 'string'
                   OR length(member ->> 'place_ref') NOT BETWEEN 1 AND 200
                   OR jsonb_typeof(member -> 'label_ready') IS DISTINCT FROM 'boolean'
                   OR member -> 'label_ready' IS DISTINCT FROM 'true'::jsonb
                   OR jsonb_typeof(member -> 'rights_ready') IS DISTINCT FROM 'boolean'
                   OR member -> 'rights_ready' IS DISTINCT FROM 'true'::jsonb
                   OR jsonb_typeof(member -> 'evidence_ready') IS DISTINCT FROM 'boolean'
                   OR member -> 'evidence_ready' IS DISTINCT FROM 'true'::jsonb
                   OR jsonb_typeof(member -> 'description_lane') IS DISTINCT FROM 'string'
                   OR NOT (member ->> 'description_lane' = ANY (ARRAY['READY', 'MISSING']))
                   OR jsonb_typeof(member -> 'odii_lane') IS DISTINCT FROM 'string'
                   OR NOT (member ->> 'odii_lane' = ANY (ARRAY['READY', 'MISSING']))
                   OR jsonb_typeof(member -> 'profile_sha256') IS DISTINCT FROM 'string'
                   OR member ->> 'profile_sha256' !~ '^[0-9a-f]{64}$' THEN
                    RETURN false;
                END IF;
                FOREACH digest_key IN ARRAY optional_member_digest_keys LOOP
                    IF jsonb_typeof(member -> digest_key) IS DISTINCT FROM 'null' AND (
                        jsonb_typeof(member -> digest_key) IS DISTINCT FROM 'string'
                        OR member ->> digest_key !~ '^[0-9a-f]{64}$'
                    ) THEN
                        RETURN false;
                    END IF;
                END LOOP;
            END LOOP;
            IF (
                SELECT count(DISTINCT item ->> 'place_ref')
                FROM jsonb_array_elements(candidate -> 'cohort') AS rows(item)
            ) IS DISTINCT FROM 24 OR (
                SELECT count(DISTINCT item ->> 'profile_sha256')
                FROM jsonb_array_elements(candidate -> 'cohort') AS rows(item)
            ) IS DISTINCT FROM 24 THEN
                RETURN false;
            END IF;
            expected_release_sha256 := encode(
                sha256(convert_to(
                    dev_eval.canonical_jsonb_compact_v1(candidate - 'release_sha256'),
                    'UTF8'
                )),
                'hex'
            );
            RETURN expected_release_sha256 IS NOT DISTINCT FROM candidate ->> 'release_sha256';
        END;
        $$
        """
    )
    op.execute(
        """
        CREATE FUNCTION dev_eval.validate_profile_release_build_receipt_v1()
        RETURNS trigger
        LANGUAGE plpgsql
        SECURITY DEFINER
        SET search_path = pg_catalog, dev_eval
        AS $$
        DECLARE
            candidate_payload jsonb;
            expected_release_sha256 text;
            expected_binding_sha256 text;
            expected_receipt_sha256 text;
        BEGIN
            SELECT releases.payload
            INTO candidate_payload
            FROM dev_eval.profile_releases releases
            JOIN dev_eval.profile_release_lifecycle_heads heads
              ON heads.release_sha256 = releases.release_sha256
            WHERE releases.release_sha256 = NEW.release_sha256
              AND releases.builder_principal = NEW.builder_principal
              AND releases.payload ->> 'release_sha256' = NEW.release_sha256
              AND releases.payload ->> 'builder_principal' = NEW.builder_principal
              AND releases.payload ->> 'release_id' = releases.release_id
              AND releases.payload ->> 'canonical_lineage_sha256'
                    = releases.canonical_lineage_sha256
              AND releases.payload ->> 'dev_lineage_sha256'
                    = releases.dev_lineage_sha256
              AND releases.payload ->> 'profile_schema_sha256'
                    = releases.profile_schema_sha256
              AND releases.payload ->> 'schema_version'
                    = 'itda.profile-release-candidate.v1'
              AND releases.payload ->> 'state' = 'BUILT_UNAPPROVED'
              AND heads.state = 'BUILT_UNAPPROVED'
              AND heads.head_receipt_sha256 IS NULL
            FOR SHARE OF releases, heads;
            IF candidate_payload IS NULL THEN
                RAISE EXCEPTION 'profile release build provenance is incomplete'
                    USING ERRCODE = '23514';
            END IF;
            IF NOT dev_eval.validate_profile_release_candidate_payload_v1(
                candidate_payload
            ) THEN
                RAISE EXCEPTION 'profile release candidate payload is not canonical'
                    USING ERRCODE = '23514';
            END IF;
            expected_release_sha256 := encode(
                sha256(convert_to(
                    dev_eval.canonical_jsonb_compact_v1(
                        candidate_payload - 'release_sha256'
                    ),
                    'UTF8'
                )),
                'hex'
            );
            expected_binding_sha256 := encode(
                sha256(convert_to(
                    '{"action":"BUILD","builder":' ||
                    to_json(NEW.builder_principal)::text ||
                    ',"release_sha256":' || to_json(NEW.release_sha256)::text || '}',
                    'UTF8'
                )),
                'hex'
            );
            expected_receipt_sha256 := encode(
                sha256(convert_to(
                    '{"binding_sha256":' || to_json(NEW.binding_sha256)::text ||
                    ',"builder_principal":' || to_json(NEW.builder_principal)::text ||
                    ',"nonce_sha256":' || to_json(NEW.nonce_sha256)::text ||
                    ',"release_sha256":' || to_json(NEW.release_sha256)::text ||
                    ',"schema_version":"itda.profile-release-build-receipt.v1"}',
                    'UTF8'
                )),
                'hex'
            );
            IF expected_release_sha256 <> NEW.release_sha256
               OR expected_binding_sha256 <> NEW.binding_sha256
               OR expected_receipt_sha256 <> NEW.receipt_sha256 THEN
                RAISE EXCEPTION 'profile release build provenance digest is invalid'
                    USING ERRCODE = '23514';
            END IF;
            RETURN NEW;
        END;
        $$
        """
    )
    op.execute(
        "CREATE TRIGGER validate_profile_release_build_receipt_insert_v1 "
        "BEFORE INSERT ON dev_eval.profile_release_build_receipts "
        "FOR EACH ROW EXECUTE FUNCTION dev_eval.validate_profile_release_build_receipt_v1()"
    )
    op.execute(
        "CREATE TRIGGER reject_profile_release_build_receipts_mutation_v1 "
        "BEFORE UPDATE OR DELETE ON dev_eval.profile_release_build_receipts "
        "FOR EACH ROW EXECUTE FUNCTION dev_eval.reject_phase3_label_mutation_v1()"
    )
    op.execute(
        "CREATE TRIGGER reject_profile_release_build_nonce_reservations_mutation_v1 "
        "BEFORE UPDATE OR DELETE ON dev_eval.profile_release_build_nonce_reservations "
        "FOR EACH ROW EXECUTE FUNCTION dev_eval.reject_phase3_label_mutation_v1()"
    )
    op.execute(
        """
        CREATE FUNCTION dev_eval.reserve_profile_release_build_nonce_v1(
            p_builder_principal text,
            p_nonce_sha256 text,
            p_candidate_sha256 text,
            p_draft_ref_sha256 text
        )
        RETURNS void
        LANGUAGE plpgsql
        SECURITY DEFINER
        SET search_path = pg_catalog, dev_eval
        AS $$
        DECLARE
            reservation dev_eval.profile_release_build_nonce_reservations%ROWTYPE;
        BEGIN
            IF p_builder_principal !~ '^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$'
               OR p_nonce_sha256 !~ '^[0-9a-f]{64}$'
               OR p_candidate_sha256 !~ '^[0-9a-f]{64}$'
               OR (
                    p_draft_ref_sha256 IS NOT NULL
                    AND p_draft_ref_sha256 !~ '^[0-9a-f]{64}$'
               ) THEN
                RAISE EXCEPTION 'profile release build nonce reservation is invalid'
                    USING ERRCODE = '23514';
            END IF;
            PERFORM pg_advisory_xact_lock(
                hashtextextended(p_builder_principal || ':' || p_nonce_sha256, 0)
            );
            SELECT reservations.*
            INTO reservation
            FROM dev_eval.profile_release_build_nonce_reservations reservations
            WHERE reservations.builder_principal = p_builder_principal
              AND reservations.nonce_sha256 = p_nonce_sha256
            FOR UPDATE;
            IF FOUND THEN
                IF reservation.candidate_sha256 <> p_candidate_sha256 THEN
                    RAISE EXCEPTION 'profile release build nonce binding conflicts'
                        USING ERRCODE = '23505';
                END IF;
                IF p_draft_ref_sha256 IS NOT NULL THEN
                    IF reservation.draft_ref_sha256 IS DISTINCT FROM p_draft_ref_sha256
                       OR EXISTS (
                            SELECT 1
                            FROM dev_eval.profile_release_build_receipts receipts
                            WHERE receipts.builder_principal = p_builder_principal
                              AND receipts.nonce_sha256 = p_nonce_sha256
                       ) THEN
                        RAISE EXCEPTION 'profile release build nonce is already immutable'
                            USING ERRCODE = '23505';
                    END IF;
                END IF;
                RETURN;
            END IF;
            IF p_draft_ref_sha256 IS NOT NULL AND EXISTS (
                SELECT 1
                FROM dev_eval.profile_release_build_receipts receipts
                WHERE receipts.builder_principal = p_builder_principal
                  AND receipts.nonce_sha256 = p_nonce_sha256
            ) THEN
                RAISE EXCEPTION 'profile release build nonce is already immutable'
                    USING ERRCODE = '23505';
            END IF;
            INSERT INTO dev_eval.profile_release_build_nonce_reservations (
                builder_principal,
                nonce_sha256,
                candidate_sha256,
                draft_ref_sha256
            ) VALUES (
                p_builder_principal,
                p_nonce_sha256,
                p_candidate_sha256,
                p_draft_ref_sha256
            );
        END;
        $$
        """
    )
    op.execute(
        """
        CREATE FUNCTION dev_eval.insert_profile_release_build_receipt_v1(
            p_builder_principal text,
            p_nonce_sha256 text,
            p_binding_sha256 text,
            p_release_sha256 text,
            p_receipt_sha256 text
        )
        RETURNS void
        LANGUAGE plpgsql
        SECURITY DEFINER
        SET search_path = pg_catalog, dev_eval
        AS $$
        BEGIN
            PERFORM dev_eval.reserve_profile_release_build_nonce_v1(
                p_builder_principal,
                p_nonce_sha256,
                p_release_sha256,
                NULL
            );
            INSERT INTO dev_eval.profile_release_build_receipts (
                builder_principal,
                nonce_sha256,
                binding_sha256,
                release_sha256,
                receipt_sha256
            ) VALUES (
                p_builder_principal,
                p_nonce_sha256,
                p_binding_sha256,
                p_release_sha256,
                p_receipt_sha256
            );
        END;
        $$
        """
    )
    op.execute("REVOKE ALL ON dev_eval.profile_release_build_receipts FROM PUBLIC")
    op.execute(
        "REVOKE ALL ON dev_eval.profile_release_build_nonce_reservations FROM PUBLIC"
    )
    op.execute(
        "REVOKE ALL ON FUNCTION dev_eval.reserve_profile_release_build_nonce_v1("
        "text, text, text, text) FROM PUBLIC"
    )
    op.execute(
        "REVOKE ALL ON FUNCTION dev_eval.insert_profile_release_build_receipt_v1("
        "text, text, text, text, text) FROM PUBLIC"
    )
    _grant("GRANT SELECT ON dev_eval.profile_release_build_receipts", builder)
    _grant(
        "GRANT SELECT ON dev_eval.profile_release_build_nonce_reservations",
        builder,
    )
    _grant(
        "GRANT EXECUTE ON FUNCTION "
        "dev_eval.reserve_profile_release_build_nonce_v1(text, text, text, text)",
        builder,
    )
    _grant(
        "GRANT EXECUTE ON FUNCTION "
        "dev_eval.insert_profile_release_build_receipt_v1(text, text, text, text, text)",
        builder,
    )
    _grant("GRANT SELECT ON dev_eval.profile_release_build_receipts", approver)
    _grant(
        "GRANT SELECT ON dev_eval.profile_release_build_nonce_reservations",
        approver,
    )

    op.create_table(
        "profile_release_build_drafts",
        sa.Column("draft_ref_sha256", sa.Text(), nullable=False),
        sa.Column("builder_principal", sa.Text(), nullable=False),
        sa.Column("candidate_payload", JSONB(), nullable=False),
        sa.Column("candidate_sha256", sa.Text(), nullable=False),
        sa.Column("nonce_sha256", sa.Text(), nullable=False),
        sa.Column(
            "expires_at",
            sa.DateTime(timezone=True),
            nullable=False,
        ),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.text("CURRENT_TIMESTAMP"),
        ),
        sa.ForeignKeyConstraint(
            [
                "builder_principal",
                "nonce_sha256",
                "candidate_sha256",
                "draft_ref_sha256",
            ],
            [
                "dev_eval.profile_release_build_nonce_reservations.builder_principal",
                "dev_eval.profile_release_build_nonce_reservations.nonce_sha256",
                "dev_eval.profile_release_build_nonce_reservations.candidate_sha256",
                "dev_eval.profile_release_build_nonce_reservations.draft_ref_sha256",
            ],
            name="fk_phase3_profile_release_build_draft_nonce_reservation",
            ondelete="RESTRICT",
        ),
        sa.CheckConstraint(
            "draft_ref_sha256 ~ '^[0-9a-f]{64}$' AND "
            "candidate_sha256 ~ '^[0-9a-f]{64}$' AND "
            "nonce_sha256 ~ '^[0-9a-f]{64}$' AND expires_at > created_at AND "
            "candidate_payload ->> 'release_sha256' = candidate_sha256 AND "
            "candidate_payload ->> 'builder_principal' = builder_principal AND "
            "dev_eval.validate_profile_release_candidate_payload_v1(candidate_payload)",
            name="ck_phase3_profile_release_build_draft_shape",
        ),
        sa.PrimaryKeyConstraint(
            "draft_ref_sha256",
            name="pk_phase3_profile_release_build_drafts",
        ),
        sa.UniqueConstraint(
            "builder_principal",
            "nonce_sha256",
            name="uq_phase3_profile_release_build_draft_builder_nonce",
        ),
        schema="dev_eval",
    )
    op.execute("REVOKE ALL ON dev_eval.profile_release_build_drafts FROM PUBLIC")
    _grant(
        "GRANT SELECT, INSERT, DELETE ON dev_eval.profile_release_build_drafts",
        builder,
    )

    op.create_table(
        "profile_release_build_draft_consumptions",
        sa.Column("draft_ref_sha256", sa.Text(), nullable=False),
        sa.Column("builder_principal", sa.Text(), nullable=False),
        sa.Column("nonce_sha256", sa.Text(), nullable=False),
        sa.Column("candidate_sha256", sa.Text(), nullable=False),
        sa.Column("receipt_sha256", sa.Text(), nullable=False),
        sa.Column(
            "consumed_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.text("CURRENT_TIMESTAMP"),
        ),
        sa.ForeignKeyConstraint(
            [
                "builder_principal",
                "nonce_sha256",
                "candidate_sha256",
                "receipt_sha256",
            ],
            [
                "dev_eval.profile_release_build_receipts.builder_principal",
                "dev_eval.profile_release_build_receipts.nonce_sha256",
                "dev_eval.profile_release_build_receipts.release_sha256",
                "dev_eval.profile_release_build_receipts.receipt_sha256",
            ],
            name="fk_phase3_profile_release_draft_consumption_receipt",
            ondelete="RESTRICT",
        ),
        sa.ForeignKeyConstraint(
            [
                "builder_principal",
                "nonce_sha256",
                "candidate_sha256",
                "draft_ref_sha256",
            ],
            [
                "dev_eval.profile_release_build_nonce_reservations.builder_principal",
                "dev_eval.profile_release_build_nonce_reservations.nonce_sha256",
                "dev_eval.profile_release_build_nonce_reservations.candidate_sha256",
                "dev_eval.profile_release_build_nonce_reservations.draft_ref_sha256",
            ],
            name="fk_phase3_profile_release_draft_consumption_nonce_reservation",
            ondelete="RESTRICT",
        ),
        sa.CheckConstraint(
            "draft_ref_sha256 ~ '^[0-9a-f]{64}$' AND "
            "nonce_sha256 ~ '^[0-9a-f]{64}$' AND "
            "candidate_sha256 ~ '^[0-9a-f]{64}$' AND "
            "receipt_sha256 ~ '^[0-9a-f]{64}$'",
            name="ck_phase3_profile_release_draft_consumption_hashes",
        ),
        sa.PrimaryKeyConstraint(
            "draft_ref_sha256",
            name="pk_phase3_profile_release_build_draft_consumptions",
        ),
        sa.UniqueConstraint(
            "builder_principal",
            "nonce_sha256",
            name="uq_phase3_profile_release_build_draft_consumption_builder_nonce",
        ),
        schema="dev_eval",
    )
    op.execute(
        "CREATE TRIGGER reject_profile_release_build_draft_consumptions_mutation_v1 "
        "BEFORE UPDATE OR DELETE ON dev_eval.profile_release_build_draft_consumptions "
        "FOR EACH ROW EXECUTE FUNCTION dev_eval.reject_phase3_label_mutation_v1()"
    )
    op.execute(
        "REVOKE ALL ON dev_eval.profile_release_build_draft_consumptions FROM PUBLIC"
    )
    _grant(
        "GRANT SELECT, INSERT ON dev_eval.profile_release_build_draft_consumptions",
        builder,
    )

    op.create_table(
        "profile_release_nonce_quarantine_0010",
        sa.Column("binding_sha256", sa.Text(), nullable=False),
        sa.Column("nonce_sha256", sa.Text(), nullable=False),
        sa.Column("receipt_sha256", sa.Text(), nullable=False),
        sa.Column("payload", JSONB(), nullable=False),
        sa.Column("remediation_snapshot_sha256", sa.Text(), nullable=False),
        sa.Column("database_identity_sha256", sa.Text(), nullable=False),
        sa.Column("authoritative_binding_sha256", sa.Text(), nullable=False),
        sa.Column("authoritative_receipt_sha256", sa.Text(), nullable=False),
        sa.Column("reachability", JSONB(), nullable=False),
        sa.Column(
            "quarantined_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.text("CURRENT_TIMESTAMP"),
        ),
        sa.CheckConstraint(
            "remediation_snapshot_sha256 ~ '^[0-9a-f]{64}$' AND "
            "database_identity_sha256 ~ '^[0-9a-f]{64}$' AND "
            "authoritative_binding_sha256 ~ '^[0-9a-f]{64}$' AND "
            "authoritative_receipt_sha256 ~ '^[0-9a-f]{64}$'",
            name="ck_phase3_profile_release_nonce_quarantine_0010_snapshot",
        ),
        sa.Column(
            "quarantine_reason",
            sa.Text(),
            nullable=False,
            server_default=sa.text("'PRE_0010_DUPLICATE_NONCE'"),
        ),
        sa.PrimaryKeyConstraint(
            "binding_sha256",
            "nonce_sha256",
            name="pk_phase3_profile_release_nonce_quarantine_0010",
        ),
        schema="dev_eval",
    )
    op.execute(
        "CREATE TRIGGER reject_profile_release_nonce_quarantine_0010_mutation_v1 "
        "BEFORE UPDATE OR DELETE ON dev_eval.profile_release_nonce_quarantine_0010 "
        "FOR EACH ROW EXECUTE FUNCTION dev_eval.reject_phase3_label_mutation_v1()"
    )
    op.execute(
        "REVOKE ALL ON dev_eval.profile_release_nonce_quarantine_0010 FROM PUBLIC"
    )
    _grant("GRANT SELECT ON dev_eval.profile_release_nonce_quarantine_0010", approver)

    if duplicate_extras:
        assert duplicate_snapshot_sha256 is not None
        assert database_identity is not None
        database_identity_sha256 = _canonical_sha256(database_identity)
        quarantine_rows = []
        for row in duplicate_extras:
            authoritative = duplicate_authoritative[str(row["nonce_sha256"])]
            quarantine_rows.append(
                {
                    "binding_sha256": row["binding_sha256"],
                    "nonce_sha256": row["nonce_sha256"],
                    "receipt_sha256": row["receipt_sha256"],
                    "payload": json.dumps(row["payload"], ensure_ascii=False, sort_keys=True),
                    "snapshot_sha256": duplicate_snapshot_sha256,
                    "database_identity_sha256": database_identity_sha256,
                    "authoritative_binding_sha256": authoritative["binding_sha256"],
                    "authoritative_receipt_sha256": authoritative["receipt_sha256"],
                    "reachability": json.dumps(
                        {
                            key: row[key]
                            for key in (
                                "event_matches",
                                "head_references",
                                "rollback_references",
                                "pointer_references",
                            )
                        },
                        sort_keys=True,
                    ),
                }
            )
        connection.execute(
            sa.text(
                "INSERT INTO dev_eval.profile_release_nonce_quarantine_0010 "
                "(binding_sha256, nonce_sha256, receipt_sha256, payload, "
                "remediation_snapshot_sha256, database_identity_sha256, "
                "authoritative_binding_sha256, authoritative_receipt_sha256, "
                "reachability) VALUES ("
                ":binding_sha256, :nonce_sha256, :receipt_sha256, "
                "CAST(:payload AS jsonb), :snapshot_sha256, "
                ":database_identity_sha256, :authoritative_binding_sha256, "
                ":authoritative_receipt_sha256, CAST(:reachability AS jsonb))"
            ),
            quarantine_rows,
        )
        op.execute(
            "ALTER TABLE dev_eval.profile_release_nonce_ledger "
            "DISABLE TRIGGER reject_profile_release_nonce_ledger_mutation_v1"
        )
        op.execute(
            "DELETE FROM dev_eval.profile_release_nonce_ledger ledger USING "
            "dev_eval.profile_release_nonce_quarantine_0010 quarantine WHERE "
            "ledger.binding_sha256 = quarantine.binding_sha256 AND "
            "ledger.nonce_sha256 = quarantine.nonce_sha256 AND "
            "ledger.receipt_sha256 = quarantine.receipt_sha256"
        )
        op.execute(
            "ALTER TABLE dev_eval.profile_release_nonce_ledger "
            "ENABLE TRIGGER reject_profile_release_nonce_ledger_mutation_v1"
        )
        remaining = connection.execute(
            sa.text(
                "SELECT binding_sha256, nonce_sha256, receipt_sha256 FROM "
                "dev_eval.profile_release_nonce_ledger WHERE nonce_sha256 IN ("
                "SELECT DISTINCT nonce_sha256 FROM "
                "dev_eval.profile_release_nonce_quarantine_0010)"
            )
        ).mappings().all()
        if len(remaining) != len(duplicate_authoritative) or any(
            str(row["binding_sha256"])
            != duplicate_authoritative[str(row["nonce_sha256"])]["binding_sha256"]
            or str(row["receipt_sha256"])
            != duplicate_authoritative[str(row["nonce_sha256"])]["receipt_sha256"]
            for row in remaining
        ):
            raise RuntimeError("0010 nonce remediation did not preserve exact authority")

    op.create_unique_constraint(
        _GLOBAL_NONCE_CONSTRAINT,
        "profile_release_nonce_ledger",
        ["nonce_sha256"],
        schema="dev_eval",
    )


def downgrade() -> None:
    connection = op.get_bind()
    connection.execute(
        sa.text(
            "LOCK TABLE dev_eval.profile_release_build_receipts, "
            "dev_eval.profile_release_build_drafts, "
            "dev_eval.profile_release_build_draft_consumptions, "
            "dev_eval.profile_release_nonce_quarantine_0010, "
            "dev_eval.profile_release_build_nonce_reservations "
            "IN ACCESS EXCLUSIVE MODE"
        )
    )
    protected_rows = connection.execute(
        sa.text(
            "SELECT "
            "(SELECT count(*) FROM dev_eval.profile_release_build_receipts) + "
            "(SELECT count(*) FROM dev_eval.profile_release_build_drafts) + "
            "(SELECT count(*) FROM dev_eval.profile_release_build_draft_consumptions) + "
            "(SELECT count(*) FROM dev_eval.profile_release_nonce_quarantine_0010) + "
            "(SELECT count(*) FROM dev_eval.profile_release_build_nonce_reservations)"
        )
    ).scalar_one()
    if protected_rows:
        raise RuntimeError(
            "0010 downgrade is intentionally irreversible after protected state exists"
        )
    op.drop_constraint(
        _GLOBAL_NONCE_CONSTRAINT,
        "profile_release_nonce_ledger",
        schema="dev_eval",
        type_="unique",
    )
    op.execute(
        "DROP TRIGGER reject_profile_release_nonce_quarantine_0010_mutation_v1 "
        "ON dev_eval.profile_release_nonce_quarantine_0010"
    )
    op.drop_table("profile_release_nonce_quarantine_0010", schema="dev_eval")
    op.execute(
        "DROP TRIGGER reject_profile_release_build_draft_consumptions_mutation_v1 "
        "ON dev_eval.profile_release_build_draft_consumptions"
    )
    op.drop_table("profile_release_build_draft_consumptions", schema="dev_eval")
    op.drop_table("profile_release_build_drafts", schema="dev_eval")
    op.execute(
        "DROP TRIGGER reject_profile_release_build_receipts_mutation_v1 "
        "ON dev_eval.profile_release_build_receipts"
    )
    op.execute(
        "DROP TRIGGER validate_profile_release_build_receipt_insert_v1 "
        "ON dev_eval.profile_release_build_receipts"
    )
    op.drop_table("profile_release_build_receipts", schema="dev_eval")
    op.execute(
        "DROP FUNCTION dev_eval.insert_profile_release_build_receipt_v1("
        "text, text, text, text, text)"
    )
    op.execute(
        "DROP FUNCTION dev_eval.reserve_profile_release_build_nonce_v1("
        "text, text, text, text)"
    )
    op.execute(
        "DROP TRIGGER reject_profile_release_build_nonce_reservations_mutation_v1 "
        "ON dev_eval.profile_release_build_nonce_reservations"
    )
    op.drop_table(
        "profile_release_build_nonce_reservations",
        schema="dev_eval",
    )
    op.execute("DROP FUNCTION dev_eval.validate_profile_release_build_receipt_v1()")
    op.execute(
        "DROP FUNCTION dev_eval.validate_profile_release_candidate_payload_v1(jsonb)"
    )
    op.execute("DROP FUNCTION dev_eval.canonical_jsonb_compact_v1(jsonb)")
    op.drop_constraint(
        _PROFILE_RELEASE_BUILDER_CONSTRAINT,
        "profile_releases",
        schema="dev_eval",
        type_="unique",
    )
