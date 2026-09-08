"""Operator CLI for deterministic catalog planning, preflight, and validation."""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import stat
import sys
import time
from datetime import UTC, datetime
from pathlib import Path

from itda.collectors.base import RequestPolicy
from itda.collectors.diagnostics import ProviderDiagnostics
from itda.collectors.kto import KorService2Client
from itda.collectors.odii import OdiiClient
from itda.collectors.tourism_photo import TourismPhotoGalleryClient
from itda.contracts.catalog_collection import (
    CollectionAttempt,
    CollectionPlan,
    CollectionReport,
    PermissionEvidenceSet,
    PermissionPageSnapshot,
)
from itda.pipeline.collect_catalog import (
    RESTRICTED_OUTPUT_ROOT,
    build_collection_plan,
    build_permission_snapshot,
    collect_catalog,
    load_collection_report,
    load_coverage_seed,
    preflight_credential_reference,
    validate_collection_report,
)
from itda.pipeline.offline_guard import LIVE_COLLECTION_REFUSAL_EXIT_CODE

PHOTO_GALLERY_RECOVERY_DATASET_ID = "15101914"
PHOTO_GALLERY_RECOVERY_SIGNAL = f"photo-gallery-access-repaired:{PHOTO_GALLERY_RECOVERY_DATASET_ID}"


def _repository_root() -> Path:
    return Path(__file__).resolve().parents[4]


def _default_seed_path() -> Path:
    return (
        _repository_root()
        / "fixtures"
        / "catalog"
        / "v1"
        / "public"
        / "proposal-36-coverage-seed.json"
    )


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Plan, preflight, collect, resume, or validate catalog evidence."
    )
    parser.add_argument(
        "--plan",
        nargs="?",
        const="canonical",
        metavar="NAME",
        help="print the canonical secret-free request plan and full SHA-256",
    )
    parser.add_argument(
        "--request-plan",
        dest="plan",
        nargs="?",
        const="canonical",
        metavar="NAME",
        help="compatibility alias for --plan",
    )
    parser.add_argument(
        "--seed-manifest",
        type=Path,
        default=_default_seed_path(),
        help="membership-free proposal coverage seed",
    )
    parser.add_argument(
        "--output-root",
        type=Path,
        default=Path(RESTRICTED_OUTPUT_ROOT),
        help="Git-excluded restricted collection root",
    )
    parser.add_argument("--live", action="store_true", help="issue the authorized live plan")
    parser.add_argument(
        "--authorization-token",
        help="exact digest-bound live authorization token; never auto-generated",
    )
    parser.add_argument("--resume", action="store_true", help="resume missing/retryable requests")
    parser.add_argument(
        "--recover-tourism-photo-access",
        action="store_true",
        help="retry only the prior PhotoGallery 15101914 identities after reviewed access repair",
    )
    parser.add_argument(
        "--recovery-signal",
        help="exact reviewed PhotoGallery access-repaired signal",
    )
    parser.add_argument(
        "--credential-ref",
        action="append",
        default=[],
        metavar="LABEL:PATH:NAME",
        help="named credential reference; raw credential values are forbidden",
    )
    parser.add_argument(
        "--preflight-credential-ref",
        action="append",
        default=[],
        metavar="LABEL:PATH:NAME",
        help="verify plan-bound file/name metadata without displaying values",
    )
    parser.add_argument(
        "--no-print-values",
        action="store_true",
        help="required explicit acknowledgement for credential preflight",
    )
    parser.add_argument(
        "--import-permission-page",
        action="append",
        default=[],
        metavar="DATASET_ID:PATH",
        help="import a separately captured official permission-page record",
    )
    parser.add_argument("--report-json", type=Path, help="collection report input/output")
    parser.add_argument(
        "--validate-report",
        action="store_true",
        help="read and validate a completed restricted report without provider access",
    )
    parser.add_argument("--validation-output", type=Path)
    parser.add_argument("--require-dataset", action="append", default=[])
    parser.add_argument("--min-candidates", type=int, default=60)
    parser.add_argument(
        "--require-terminal-plan-completeness",
        action="store_true",
    )
    parser.add_argument("--require-resume-proof", action="store_true")
    return parser


def _parse_reference(value: str) -> tuple[str, str, str]:
    try:
        label, path_and_name = value.split(":", maxsplit=1)
        path, variable_name = path_and_name.rsplit(":", maxsplit=1)
    except ValueError as exc:
        raise ValueError("credential reference must use LABEL:PATH:VARIABLE_NAME") from exc
    if not label or not path or not variable_name:
        raise ValueError("credential reference components must not be empty")
    return label, path, variable_name


def _preflight_references(values: list[str]) -> list[dict[str, object]]:
    expected = {
        "tourapi": (".secrets/itda-api.env", "TOUR_API_SERVICE_KEY"),
        "odii": (".secrets/itda-odii.env", "ODII_SERVICE_KEY"),
        "tourism-photo": (
            ".secrets/itda-api.env",
            "TOUR_API_SERVICE_KEY",
        ),
    }
    results: list[dict[str, object]] = []
    for value in values:
        label, relative_path, variable_name = _parse_reference(value)
        if label not in expected or (relative_path, variable_name) != expected[label]:
            raise ValueError("credential reference is not bound to the canonical plan")
        absolute_path = _repository_root() / relative_path
        result = preflight_credential_reference(
            provider_label=label,
            credential_reference=f"{absolute_path}:{variable_name}",
            expected_path=absolute_path,
            expected_variable_name=variable_name,
        )
        payload = result.model_dump(mode="json")
        payload["reference"] = f"{relative_path}:{variable_name}"
        results.append(payload)
    return results


def _write_private_json(
    path: Path,
    payload: bytes,
    *,
    allow_replace: bool = False,
) -> None:
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    path.parent.chmod(0o700)
    if path.exists():
        metadata = path.lstat()
        if path.is_symlink() or not stat.S_ISREG(metadata.st_mode):
            raise ValueError("validation output must be a regular non-symlink file")
        if path.read_bytes() == payload:
            return
        if not allow_replace:
            raise ValueError("private output already exists with different bytes")
    target = path
    if path.exists():
        target = path.with_name(f".{path.name}.tmp-{os.getpid()}")
    descriptor = os.open(
        target,
        os.O_WRONLY
        | os.O_CREAT
        | os.O_EXCL
        | getattr(os, "O_NOFOLLOW", 0)
        | getattr(os, "O_CLOEXEC", 0),
        0o600,
    )
    try:
        os.write(descriptor, payload)
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    if target != path:
        os.replace(target, path)


def _latest_attempts(report: CollectionReport) -> dict[str, CollectionAttempt]:
    latest: dict[str, CollectionAttempt] = {}
    for attempt in report.attempts:
        previous = latest.get(attempt.request_identity)
        if previous is None or attempt.attempt_number >= previous.attempt_number:
            latest[attempt.request_identity] = attempt
    return latest


def _private_file_record(path: Path, output_root: Path) -> dict[str, object]:
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0)
    descriptor = os.open(path, flags)
    try:
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1:
            raise ValueError("restricted recovery evidence must be a regular single-link file")
        digest = hashlib.sha256()
        size = 0
        while chunk := os.read(descriptor, 1024 * 1024):
            digest.update(chunk)
            size += len(chunk)
        after = os.fstat(descriptor)
    finally:
        os.close(descriptor)
    if (before.st_dev, before.st_ino, before.st_size) != (
        after.st_dev,
        after.st_ino,
        after.st_size,
    ) or size != after.st_size:
        raise ValueError("restricted recovery evidence changed while hashing")
    return {
        "relative_path": path.relative_to(output_root).as_posix(),
        "sha256": digest.hexdigest(),
        "size_bytes": after.st_size,
        "mtime_ns": after.st_mtime_ns,
    }


def _prepare_photo_gallery_recovery(
    *,
    output_root: Path,
    report_path: Path,
) -> Path:
    report = load_collection_report(report_path)
    latest = _latest_attempts(report)
    identities_by_id = {item.request_identity: item for item in report.request_identities}
    target_ids = tuple(
        item.request_identity
        for item in report.request_identities
        if item.provider == "TOURISM_PHOTO"
        and item.official_dataset_id == PHOTO_GALLERY_RECOVERY_DATASET_ID
    )
    if len(target_ids) != 11:
        raise ValueError("PhotoGallery recovery requires the exact prior 11 identities")
    if any(
        latest.get(identity_id) is None
        or latest[identity_id].terminal_state != "TERMINAL_OPERATOR_ACTION"
        or latest[identity_id].http_status != 403
        or latest[identity_id].provider_result_code is not None
        or latest[identity_id].provider_result_value is not None
        or latest[identity_id].retry_classification != "DO_NOT_RETRY"
        for identity_id in target_ids
    ):
        raise ValueError(
            "PhotoGallery recovery requires the prior reviewed HTTP 403 terminal evidence"
        )
    non_target_ids = set(identities_by_id) - set(target_ids)
    if len(non_target_ids) != 22 or any(
        latest.get(identity_id) is None or latest[identity_id].terminal_state != "SUCCESS"
        for identity_id in non_target_ids
    ):
        raise ValueError("PhotoGallery recovery requires exactly 22 prior provider successes")

    output_root_resolved = output_root.resolve(strict=True)
    success_records: list[dict[str, object]] = []
    for evidence in report.resume_evidence:
        if evidence.request_identity not in non_target_ids:
            continue
        path = (output_root / evidence.relative_path).resolve(strict=True)
        if path != output_root_resolved and output_root_resolved not in path.parents:
            raise ValueError("successful snapshot path escapes the restricted output root")
        record = _private_file_record(path, output_root_resolved)
        if (
            record["sha256"] != evidence.after_sha256
            or evidence.before_sha256 != evidence.after_sha256
            or evidence.before_mtime_ns != evidence.after_mtime_ns
        ):
            raise ValueError("prior successful snapshot bytes or mtime changed")
        if record["mtime_ns"] != evidence.after_mtime_ns:
            delta_ns = int(record["mtime_ns"]) - evidence.after_mtime_ns
            if abs(delta_ns) > 1_000:
                raise ValueError("prior successful snapshot mtime changed")
            metadata = path.stat()
            os.utime(
                path,
                ns=(metadata.st_atime_ns, evidence.after_mtime_ns),
                follow_symlinks=False,
            )
            repaired = _private_file_record(path, output_root_resolved)
            if (
                repaired["sha256"] != evidence.after_sha256
                or repaired["mtime_ns"] != evidence.after_mtime_ns
            ):
                raise ValueError("successful snapshot mtime normalization could not be repaired")
            repaired["mtime_normalization_delta_ns"] = delta_ns
            record = repaired
        record["request_identity"] = evidence.request_identity
        record["category"] = "prior_success_snapshot"
        success_records.append(record)
    if len(success_records) != 22:
        raise ValueError("PhotoGallery recovery requires 22 immutable success snapshots")

    prior_records = [
        _private_file_record(path, output_root_resolved)
        for path in sorted(output_root_resolved.rglob("*"))
        if path.is_file()
    ]
    recovery_base = output_root_resolved / "recovery-attempts"
    recovery_base.mkdir(mode=0o700, exist_ok=True)
    recovery_base.chmod(0o700)
    run_id = datetime.now(UTC).strftime("%Y%m%dT%H%M%S%fZ") + f"-{report.report_sha256[:12]}"
    recovery_root = recovery_base / run_id
    recovery_root.mkdir(mode=0o700)
    recovery_root.chmod(0o700)

    report_bytes = report_path.read_bytes()
    _write_private_json(
        recovery_root / "prior-collection-report.json",
        report_bytes,
    )
    validation_path = output_root_resolved / "live-report-validation.json"
    if validation_path.exists():
        _write_private_json(
            recovery_root / "prior-live-report-validation.json",
            validation_path.read_bytes(),
        )
    inventory = {
        "schema_version": "photo-gallery-recovery-inventory-v1",
        "recovery_signal": PHOTO_GALLERY_RECOVERY_SIGNAL,
        "official_dataset_id": PHOTO_GALLERY_RECOVERY_DATASET_ID,
        "prior_report_sha256": hashlib.sha256(report_bytes).hexdigest(),
        "prior_report_contract_sha256": report.report_sha256,
        "target_request_identities": list(target_ids),
        "successful_snapshot_records": success_records,
        "prior_restricted_file_records": prior_records,
        "created_at": datetime.now(UTC).isoformat().replace("+00:00", "Z"),
    }
    _write_private_json(
        recovery_root / "pre-network-inventory.json",
        (
            json.dumps(
                inventory,
                ensure_ascii=False,
                sort_keys=True,
                separators=(",", ":"),
            ).encode("utf-8")
            + b"\n"
        ),
    )
    return recovery_root


def _finalize_photo_gallery_recovery(
    *,
    recovery_root: Path,
    output_root: Path,
    report_path: Path,
    elapsed_ms: int,
) -> None:
    inventory = json.loads((recovery_root / "pre-network-inventory.json").read_bytes())
    for expected in inventory["successful_snapshot_records"]:
        current = _private_file_record(
            output_root / expected["relative_path"],
            output_root,
        )
        if current["sha256"] != expected["sha256"] or current["mtime_ns"] != expected["mtime_ns"]:
            raise ValueError("PhotoGallery recovery changed a prior success snapshot")
    report = load_collection_report(report_path)
    latest = _latest_attempts(report)
    latest_counts = {
        state: sum(item.terminal_state == state for item in latest.values())
        for state in (
            "SUCCESS",
            "NO_DATA",
            "RETRYABLE_FOR_RESUME",
            "TERMINAL_OPERATOR_ACTION",
        )
    }
    report_bytes = report_path.read_bytes()
    _write_private_json(
        recovery_root / "combined-collection-report.json",
        report_bytes,
    )
    result = {
        "schema_version": "photo-gallery-recovery-result-v1",
        "recovery_signal": PHOTO_GALLERY_RECOVERY_SIGNAL,
        "official_dataset_id": PHOTO_GALLERY_RECOVERY_DATASET_ID,
        "prior_report_sha256": inventory["prior_report_sha256"],
        "combined_report_sha256": hashlib.sha256(report_bytes).hexdigest(),
        "combined_report_contract_sha256": report.report_sha256,
        "target_request_identities": inventory["target_request_identities"],
        "latest_terminal_state_counts": latest_counts,
        "prior_success_snapshots_preserved": True,
        "elapsed_ms": elapsed_ms,
        "completed_at": datetime.now(UTC).isoformat().replace("+00:00", "Z"),
    }
    _write_private_json(
        recovery_root / "post-network-result.json",
        (
            json.dumps(
                result,
                ensure_ascii=False,
                sort_keys=True,
                separators=(",", ":"),
            ).encode("utf-8")
            + b"\n"
        ),
    )


def _read_credential_value(path: Path, variable_name: str) -> str:
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0)
    descriptor = os.open(path, flags)
    try:
        metadata = os.fstat(descriptor)
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_uid != os.getuid()
            or stat.S_IMODE(metadata.st_mode) != 0o600
            or metadata.st_nlink != 1
            or metadata.st_size > 16_384
        ):
            raise ValueError("credential file changed after preflight")
        payload = os.read(descriptor, 16_385)
        if len(payload) != metadata.st_size:
            raise ValueError("credential file changed during credential load")
    finally:
        os.close(descriptor)
    try:
        lines = payload.decode("utf-8").splitlines()
    except UnicodeDecodeError as exc:
        raise ValueError("credential file must be valid UTF-8") from exc
    values: dict[str, str] = {}
    for line in lines:
        if not line or line.startswith("#"):
            continue
        if "=" not in line:
            raise ValueError("credential file contains an invalid assignment")
        name, value = line.split("=", maxsplit=1)
        if not name or not value or name in values:
            raise ValueError("credential file contains an invalid assignment")
        values[name] = value
    try:
        return values[variable_name]
    except KeyError as exc:
        raise ValueError("credential variable name is absent") from exc


def _load_permission_imports(
    values: list[str],
    output_root: Path,
) -> PermissionEvidenceSet:
    imported: dict[str, PermissionPageSnapshot] = {}
    for value in values:
        try:
            dataset_id, path_text = value.split(":", maxsplit=1)
        except ValueError as exc:
            raise ValueError("permission import must use DATASET_ID:PATH") from exc
        path = Path(path_text)
        try:
            payload = json.loads(path.read_bytes())
            if not isinstance(payload, dict):
                raise ValueError
            raw_page = base64.b64decode(payload.pop("raw_page_base64"), validate=True)
            snapshot = build_permission_snapshot(
                official_dataset_id=dataset_id,
                official_url=str(payload["official_url"]),
                retrieved_at=datetime.fromisoformat(
                    str(payload["retrieved_at"]).replace("Z", "+00:00")
                ),
                terms_projection=payload["terms_projection"],
                response_bytes=raw_page,
            )
        except (OSError, KeyError, TypeError, ValueError) as exc:
            raise ValueError(f"permission import for dataset {dataset_id} is invalid") from exc
        if dataset_id in imported:
            raise ValueError("permission import dataset is duplicated")
        imported[dataset_id] = snapshot
        snapshot_bytes = (
            json.dumps(
                snapshot.model_dump(mode="json"),
                ensure_ascii=False,
                sort_keys=True,
                separators=(",", ":"),
            ).encode("utf-8")
            + b"\n"
        )
        _write_private_json(
            output_root / "permission-pages" / f"{dataset_id}.json",
            snapshot_bytes,
        )
    expected = ("15101578", "15101971", "15101914")
    if tuple(imported) != expected:
        raise ValueError(
            "permission imports must contain datasets 15101578/15101971/15101914 in canonical order"
        )
    return PermissionEvidenceSet.from_snapshots(imported.values())


def _validate_report(args: argparse.Namespace, plan: CollectionPlan) -> int:
    if args.report_json is None:
        raise ValueError("--validate-report requires --report-json")
    report = load_collection_report(args.report_json)
    required = tuple(args.require_dataset) or (
        "15101578",
        "15101971",
        "15101914",
    )
    validation = validate_collection_report(
        report=report,
        current_plan=plan,
        required_dataset_ids=required,
        minimum_candidate_count=args.min_candidates,
        require_terminal_plan_completeness=args.require_terminal_plan_completeness,
        require_resume_proof=args.require_resume_proof,
    )
    payload = (
        json.dumps(
            validation.model_dump(mode="json"),
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
        + b"\n"
    )
    if args.validation_output is not None:
        _write_private_json(
            args.validation_output,
            payload,
            allow_replace=args.recover_tourism_photo_access,
        )
    sys.stdout.buffer.write(payload)
    return 0


def _run_live(args: argparse.Namespace, plan: CollectionPlan) -> int:
    expected_token = f"authorize-live-collection:catalog-v1:{plan.collection_plan_sha256}"
    if args.authorization_token != expected_token:
        raise PermissionError(
            "live collection requires the exact current digest-bound authorization"
        )
    if args.output_root.as_posix() != RESTRICTED_OUTPUT_ROOT:
        raise ValueError("live output root must be the canonical restricted path")
    if args.report_json is None:
        raise ValueError("--live requires --report-json")
    if args.recover_tourism_photo_access and not args.resume:
        raise ValueError("PhotoGallery access recovery requires --resume")
    expected_refs = [
        "tourapi:.secrets/itda-api.env:TOUR_API_SERVICE_KEY",
        "odii:.secrets/itda-odii.env:ODII_SERVICE_KEY",
        "tourism-photo:.secrets/itda-api.env:TOUR_API_SERVICE_KEY",
    ]
    if args.credential_ref != expected_refs:
        raise ValueError("live collection requires the exact three canonical credential references")
    preflight = _preflight_references(args.credential_ref)
    shape_fields = (
        "regular_file",
        "no_symlink",
        "owned_by_current_user",
        "mode_0600",
        "variable_name_present",
    )
    if not all(all(bool(item[field]) for field in shape_fields) for item in preflight):
        raise ValueError("credential preflight did not pass")

    repository_root = _repository_root()
    output_root = repository_root / args.output_root
    report_path = (
        args.report_json if args.report_json.is_absolute() else repository_root / args.report_json
    )
    recovery_root = None
    if args.recover_tourism_photo_access:
        recovery_root = _prepare_photo_gallery_recovery(
            output_root=output_root,
            report_path=report_path,
        )
    permission_evidence = _load_permission_imports(
        args.import_permission_page,
        output_root,
    )
    resume_report = load_collection_report(report_path) if args.resume else None
    tour_key = _read_credential_value(
        repository_root / ".secrets/itda-api.env",
        "TOUR_API_SERVICE_KEY",
    )
    odii_key = (
        ""
        if args.recover_tourism_photo_access
        else _read_credential_value(
            repository_root / ".secrets/itda-odii.env",
            "ODII_SERVICE_KEY",
        )
    )

    policy = RequestPolicy(
        timeout_seconds=300,
        max_attempts=3,
        initial_backoff_seconds=1,
        max_backoff_seconds=300,
        jitter_fraction=0.2,
    )
    if args.recover_tourism_photo_access:
        clients = {
            "TOURISM_PHOTO": TourismPhotoGalleryClient(
                service_key=tour_key,
                policy=policy,
            ),
        }
    else:
        clients = {
            "TOUR_API": KorService2Client(service_key=tour_key, policy=policy),
            "ODII": OdiiClient(service_key=odii_key, policy=policy),
            "TOURISM_PHOTO": TourismPhotoGalleryClient(
                service_key=tour_key,
                policy=policy,
            ),
        }
    diagnostics = ProviderDiagnostics.create(output_root / "diagnostics")
    diagnostics.bind_credentials(
        tour_key,
        *(() if args.recover_tourism_photo_access else (odii_key,)),
    )
    diagnostics.run_started()
    live_started = time.monotonic()
    try:
        report = collect_catalog(
            plan=plan,
            seed=load_coverage_seed(args.seed_manifest),
            permission_evidence=permission_evidence,
            clients=clients,
            output_root=output_root,
            resume_report=resume_report,
            terminal_recovery_dataset_id=(
                PHOTO_GALLERY_RECOVERY_DATASET_ID if args.recover_tourism_photo_access else None
            ),
            diagnostics=diagnostics,
        )
        latest_attempts = _latest_attempts(report)
        complete = len(latest_attempts) == 33 and all(
            item.terminal_state in {"SUCCESS", "NO_DATA"} for item in latest_attempts.values()
        )
        if complete:
            diagnostics.terminal_success()
    finally:
        diagnostics.close()
        for client in clients.values():
            client.close()
        tour_key = ""
        odii_key = ""

    report_bytes = (
        json.dumps(
            report.model_dump(mode="json"),
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
        + b"\n"
    )
    _write_private_json(report_path, report_bytes, allow_replace=args.resume)
    if recovery_root is not None:
        _finalize_photo_gallery_recovery(
            recovery_root=recovery_root,
            output_root=output_root,
            report_path=report_path,
            elapsed_ms=round((time.monotonic() - live_started) * 1_000),
        )
    print(
        json.dumps(
            {
                "collection_plan_sha256": plan.collection_plan_sha256,
                "report_sha256": report.report_sha256,
                "candidate_count": len(report.candidates),
                "terminal_state_counts": {
                    state: sum(item.terminal_state == state for item in latest_attempts.values())
                    for state in (
                        "SUCCESS",
                        "NO_DATA",
                        "RETRYABLE_FOR_RESUME",
                        "TERMINAL_OPERATOR_ACTION",
                    )
                },
            },
            sort_keys=True,
            separators=(",", ":"),
        )
    )
    return 0 if complete else 3


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        if args.recover_tourism_photo_access:
            if args.recovery_signal != PHOTO_GALLERY_RECOVERY_SIGNAL:
                raise PermissionError(
                    "PhotoGallery recovery requires the exact reviewed access-repaired signal"
                )
        elif args.recovery_signal is not None:
            raise ValueError("--recovery-signal requires --recover-tourism-photo-access")
        seed = load_coverage_seed(args.seed_manifest)
        plan = build_collection_plan(seed)
        acted = False
        if args.plan is not None:
            if args.plan != "canonical":
                raise ValueError("only the canonical plan name is supported")
            print(
                json.dumps(
                    plan.model_dump(mode="json"),
                    ensure_ascii=False,
                    sort_keys=True,
                    separators=(",", ":"),
                )
            )
            acted = True
        if args.preflight_credential_ref:
            if not args.no_print_values:
                raise ValueError("credential preflight requires --no-print-values acknowledgement")
            print(
                json.dumps(
                    {"credential_preflight": _preflight_references(args.preflight_credential_ref)},
                    ensure_ascii=False,
                    sort_keys=True,
                    separators=(",", ":"),
                )
            )
            acted = True
        if args.validate_report:
            return _validate_report(args, plan)
        if args.live:
            return _run_live(args, plan)
        if not acted:
            parser.error("select --plan, --preflight-credential-ref, --validate-report, or --live")
        return 0
    except PermissionError as exc:
        print(str(exc), file=sys.stderr)
        return LIVE_COLLECTION_REFUSAL_EXIT_CODE
    except (OSError, ValueError, RuntimeError) as exc:
        print(str(exc), file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
