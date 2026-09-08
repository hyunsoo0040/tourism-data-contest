"""Verify and publish one immutable Phase 3 label-freeze receipt."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import stat
import tempfile
from contextlib import suppress
from datetime import UTC, datetime
from pathlib import Path
from typing import Literal, Self, cast

from pydantic import model_validator

from itda.contracts.base import Sha256, StrictContract, require_utc
from itda.contracts.labeling import AdjudicatedLabelExport, LabelExportBlocked
from itda.domain.canonical import canonical_json_bytes, canonical_sha256

_MAX_INPUT_BYTES = 4 * 1024 * 1024
_HASH_ARGUMENT = re.compile(r"^[0-9a-f]{64}$")


class LabelFreezeReceipt(StrictContract):
    """Digest-only D-11 prerequisite; it grants no downstream authority."""

    schema_version: Literal["phase3-label-freeze-receipt-v1"] = "phase3-label-freeze-receipt-v1"
    status: Literal["APPROVED_FROZEN"] = "APPROVED_FROZEN"
    accepted_revision_set_sha256: Sha256
    adjudicated_label_export_sha256: Sha256
    aggregate_set_sha256: Sha256
    rubric_sha256: Sha256
    source_root_sha256: Sha256
    dev_lineage_sha256: Sha256
    code_version_sha256: Sha256
    config_version_sha256: Sha256
    authority_grants: tuple[()] = ()
    frozen_at: datetime
    receipt_sha256: Sha256 | None = None

    @model_validator(mode="after")
    def validate_receipt(self) -> Self:
        require_utc(self.frozen_at, field_name="frozen_at")
        if self.authority_grants:
            raise ValueError("label freeze cannot grant downstream authority")
        expected = canonical_sha256(self.model_dump(exclude={"receipt_sha256"}, mode="json"))
        if self.receipt_sha256 is None:
            object.__setattr__(self, "receipt_sha256", expected)
        elif self.receipt_sha256 != expected:
            raise ValueError("label freeze receipt sha256 is stale")
        return self


def _read_regular_file(path: Path, *, maximum_bytes: int = _MAX_INPUT_BYTES) -> bytes:
    nofollow = getattr(os, "O_NOFOLLOW", 0)
    if not nofollow:
        raise OSError("platform lacks no-follow file reads")
    descriptor = os.open(path, os.O_RDONLY | nofollow)
    try:
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1:
            raise ValueError("label freeze input must be a single-link regular file")
        if before.st_size > maximum_bytes:
            raise ValueError("label freeze input exceeds the bounded size")
        chunks: list[bytes] = []
        remaining = before.st_size + 1
        while remaining:
            chunk = os.read(descriptor, min(remaining, 65_536))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        payload = b"".join(chunks)
        after = os.fstat(descriptor)
        if len(payload) != before.st_size or (
            before.st_dev,
            before.st_ino,
            before.st_mode,
            before.st_nlink,
            before.st_size,
            before.st_mtime_ns,
        ) != (
            after.st_dev,
            after.st_ino,
            after.st_mode,
            after.st_nlink,
            after.st_size,
            after.st_mtime_ns,
        ):
            raise OSError("label freeze input changed during verification")
        return payload
    finally:
        os.close(descriptor)


def load_adjudicated_export(path: Path) -> AdjudicatedLabelExport:
    raw = _read_regular_file(path)
    parsed = AdjudicatedLabelExport.model_validate_json(raw)
    if raw != canonical_json_bytes(parsed.model_dump(mode="json")):
        raise ValueError("accepted label export is not canonical JSON")
    return parsed


def _validate_export(export: AdjudicatedLabelExport) -> None:
    if export.unresolved_review_trigger_sha256s:
        raise LabelExportBlocked("label freeze requires every review trigger resolution")
    if len(export.accepted_selections) != 3 or len(export.aggregates) != 12:
        raise LabelExportBlocked("label freeze requires three accepted heads and 12 aggregates")
    if any(len(aggregate.numeric_values) < 2 for aggregate in export.aggregates):
        raise LabelExportBlocked("label freeze requires two numeric values per attribute")


def build_label_freeze_receipt(
    export: AdjudicatedLabelExport,
    *,
    rubric_sha256: str,
    source_root_sha256: str,
    dev_lineage_sha256: str,
    frozen_at: datetime | None = None,
) -> LabelFreezeReceipt:
    _validate_export(export)
    if export.export_sha256 is None:
        raise LabelExportBlocked("adjudicated export lacks its canonical digest")
    if _HASH_ARGUMENT.fullmatch(export.rubric_version) and export.rubric_version != rubric_sha256:
        raise LabelExportBlocked("rubric digest differs from the accepted export lineage")
    if (
        _HASH_ARGUMENT.fullmatch(export.source_snapshot_version)
        and export.source_snapshot_version != source_root_sha256
    ):
        raise LabelExportBlocked("source root differs from the accepted export lineage")
    aggregate_set_sha256 = canonical_sha256(
        [cast(str, aggregate.aggregate_sha256) for aggregate in export.aggregates]
    )
    code_version_sha256 = hashlib.sha256(_read_regular_file(Path(__file__))).hexdigest()
    config_version_sha256 = canonical_sha256(
        {
            "rubric_sha256": rubric_sha256,
            "source_root_sha256": source_root_sha256,
            "dev_lineage_sha256": dev_lineage_sha256,
        }
    )
    return LabelFreezeReceipt(
        accepted_revision_set_sha256=export.accepted_revision_set_sha256,
        adjudicated_label_export_sha256=export.export_sha256,
        aggregate_set_sha256=aggregate_set_sha256,
        rubric_sha256=rubric_sha256,
        source_root_sha256=source_root_sha256,
        dev_lineage_sha256=dev_lineage_sha256,
        code_version_sha256=code_version_sha256,
        config_version_sha256=config_version_sha256,
        frozen_at=frozen_at or datetime.now(UTC),
    )


def _load_receipt(path: Path) -> tuple[LabelFreezeReceipt, bytes]:
    raw = _read_regular_file(path)
    receipt = LabelFreezeReceipt.model_validate_json(raw)
    canonical = canonical_json_bytes(receipt.model_dump(mode="json"))
    if raw != canonical:
        raise ValueError("label freeze receipt is not canonical JSON")
    return receipt, raw


def verify_label_freeze(
    output: Path,
    export: AdjudicatedLabelExport,
    *,
    rubric_sha256: str,
    source_root_sha256: str,
    dev_lineage_sha256: str,
) -> LabelFreezeReceipt:
    _validate_export(export)
    receipt, _ = _load_receipt(output)
    expected_bindings = (
        export.accepted_revision_set_sha256,
        cast(str, export.export_sha256),
        canonical_sha256(
            [cast(str, aggregate.aggregate_sha256) for aggregate in export.aggregates]
        ),
        rubric_sha256,
        source_root_sha256,
        dev_lineage_sha256,
        hashlib.sha256(_read_regular_file(Path(__file__))).hexdigest(),
        canonical_sha256(
            {
                "rubric_sha256": rubric_sha256,
                "source_root_sha256": source_root_sha256,
                "dev_lineage_sha256": dev_lineage_sha256,
            }
        ),
    )
    actual_bindings = (
        receipt.accepted_revision_set_sha256,
        receipt.adjudicated_label_export_sha256,
        receipt.aggregate_set_sha256,
        receipt.rubric_sha256,
        receipt.source_root_sha256,
        receipt.dev_lineage_sha256,
        receipt.code_version_sha256,
        receipt.config_version_sha256,
    )
    if actual_bindings != expected_bindings:
        raise LabelExportBlocked("existing label freeze receipt has drifted input bindings")
    return receipt


def publish_label_freeze(
    output: Path,
    export: AdjudicatedLabelExport,
    *,
    rubric_sha256: str,
    source_root_sha256: str,
    dev_lineage_sha256: str,
) -> LabelFreezeReceipt:
    if output.exists() or output.is_symlink():
        return verify_label_freeze(
            output,
            export,
            rubric_sha256=rubric_sha256,
            source_root_sha256=source_root_sha256,
            dev_lineage_sha256=dev_lineage_sha256,
        )
    receipt = build_label_freeze_receipt(
        export,
        rubric_sha256=rubric_sha256,
        source_root_sha256=source_root_sha256,
        dev_lineage_sha256=dev_lineage_sha256,
    )
    payload = canonical_json_bytes(receipt.model_dump(mode="json"))
    parent = output.parent
    parent_descriptor = os.open(
        parent,
        os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0),
    )
    temporary_name: str | None = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="wb",
            prefix=f".{output.name}.",
            suffix=".tmp",
            dir=parent,
            delete=False,
        ) as temporary:
            temporary_name = Path(temporary.name).name
            os.fchmod(temporary.fileno(), 0o600)
            temporary.write(payload)
            temporary.flush()
            os.fsync(temporary.fileno())
        try:
            os.link(
                temporary_name,
                output.name,
                src_dir_fd=parent_descriptor,
                dst_dir_fd=parent_descriptor,
                follow_symlinks=False,
            )
            os.unlink(temporary_name, dir_fd=parent_descriptor)
            temporary_name = None
            os.fsync(parent_descriptor)
        except FileExistsError:
            return verify_label_freeze(
                output,
                export,
                rubric_sha256=rubric_sha256,
                source_root_sha256=source_root_sha256,
                dev_lineage_sha256=dev_lineage_sha256,
            )
    finally:
        if temporary_name is not None:
            with suppress(FileNotFoundError):
                os.unlink(temporary_name, dir_fd=parent_descriptor)
        os.close(parent_descriptor)
    return verify_label_freeze(
        output,
        export,
        rubric_sha256=rubric_sha256,
        source_root_sha256=source_root_sha256,
        dev_lineage_sha256=dev_lineage_sha256,
    )


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--accepted-set", required=True, type=Path)
    parser.add_argument("--rubric-hash", required=True, type=_sha256_argument)
    parser.add_argument("--source-root", required=True, type=_sha256_argument)
    parser.add_argument("--dev-lineage-hash", required=True, type=_sha256_argument)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--verify", action="store_true")
    return parser


def _sha256_argument(value: str) -> str:
    if _HASH_ARGUMENT.fullmatch(value) is None:
        raise argparse.ArgumentTypeError("expected a lowercase SHA-256 digest")
    return value


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    export = load_adjudicated_export(args.accepted_set)
    operation = verify_label_freeze if args.verify else publish_label_freeze
    receipt = operation(
        args.output,
        export,
        rubric_sha256=args.rubric_hash,
        source_root_sha256=args.source_root,
        dev_lineage_sha256=args.dev_lineage_hash,
    )
    print(
        json.dumps(
            {"status": receipt.status, "receipt_sha256": receipt.receipt_sha256},
            sort_keys=True,
            separators=(",", ":"),
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())


__all__ = [
    "LabelFreezeReceipt",
    "build_label_freeze_receipt",
    "load_adjudicated_export",
    "main",
    "publish_label_freeze",
    "verify_label_freeze",
]
