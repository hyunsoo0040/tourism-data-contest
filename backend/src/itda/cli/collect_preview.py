"""Validate review artifacts or explicitly collect review-only PREVIEW candidates."""

from __future__ import annotations

import argparse
import ctypes
import errno
import json
import math
import os
import re
import stat
import subprocess
import sys
import tempfile
from base64 import b64decode
from collections.abc import Sequence
from contextlib import suppress
from copy import deepcopy
from dataclasses import dataclass
from pathlib import Path
from typing import Any, NoReturn
from uuid import uuid4

from pydantic import ValidationError

from itda.cli.freeze_preview import prepared_directory_snapshot
from itda.collectors.base import (
    CollectedResponse,
    CollectionError,
    OfficialApiClient,
    RequestPolicy,
    credential_material_present,
)
from itda.collectors.diagnostics import (
    ProviderDiagnostics,
    ProviderDiagnosticsError,
)
from itda.collectors.kto import KorService2Client
from itda.collectors.odii import OdiiClient
from itda.contracts.candidate_review import (
    BLOCKED_RIGHTS_STATUS,
    CHECK_MALFORMED,
    CHECK_RESOLVED,
    CHECK_UNRESOLVED,
    CandidateReview,
    RawProviderBundle,
    build_review_manifest_from_bytes,
    check_review_manifest,
    render_candidate_review_markdown,
    sha256_bytes,
)
from itda.contracts.provenance import parse_provider_json_bytes
from itda.pipeline.offline_guard import (
    LiveCollectionRefused,
    require_live_collection_allowed,
)

_LIVE_CANDIDATES = ("불국사", "석굴암", "첨성대", "동궁과 월지", "대릉원 일원", "황리단길")
_ALLOWED_ODII_SEARCH_KEYWORDS = {
    "불국사": frozenset({"불국사"}),
    "석굴암": frozenset({"석굴암"}),
    "첨성대": frozenset({"첨성대"}),
    "동궁과 월지": frozenset({"동궁과 월지"}),
    "대릉원 일원": frozenset({"대릉원", "경주 대릉원", "대릉원 일원"}),
    "황리단길": frozenset({"황리단길"}),
}
_CREDENTIAL_PATH = Path(".secrets/itda-api.env")
_TARGETED_ODII_CREDENTIAL_PATH = Path(".secrets/itda-odii.env")
_CREDENTIAL_NAMES = ("TOUR_API_SERVICE_KEY", "ODII_SERVICE_KEY")
_DEFAULT_DIAGNOSTICS_PATH = Path(".diagnostics/provider-collection")
_TARGETED_CANDIDATE_ID = "preview:5"
_TARGETED_CANDIDATE_NAME = "대릉원 일원"
_TARGETED_PROVIDER = "ODII"
_TARGETED_KEYWORD = "대릉원"
_TARGETED_APPROVED_IDENTITIES = {
    "preview:1": ("126166", "2/5"),
    "preview:2": ("126216", "2983/4639"),
    "preview:3": ("126207", "2967/4623"),
    "preview:4": ("128526", "2961/4617"),
    "preview:5": ("1492402", "2960/4616"),
    "preview:6": ("2658227", "1312/2357"),
}
_MAX_TARGETED_THEME_PAIRS = 8
_TARGETED_SOURCE_MANIFEST_SHA256 = (
    "67eaf7f1236c1d615c6a9e178bdef28c798b4c84d92667f2b8b67e9378f54c6f"
)
_MAX_TARGETED_CREDENTIAL_BYTES = 16_384
_MAX_TARGETED_SOURCE_ARTIFACT_BYTES = 8_000_000
_TARGETED_REVIEW_ARTIFACT_NAMES = frozenset(
    {
        "candidate-review.json",
        "candidate-review.md",
        "raw-provider-bundle.redacted.json",
        "review-manifest.json",
    }
)


@dataclass(frozen=True, slots=True)
class _CandidateSelection:
    name: str
    tour_content_id: str
    odii_tid: str
    odii_tlid: str
    odii_search_keyword: str

    @property
    def odii_source_id(self) -> str:
        return f"{self.odii_tid}/{self.odii_tlid}"


@dataclass(frozen=True, slots=True)
class _TargetedSourceSnapshot:
    review: CandidateReview
    bundle: RawProviderBundle
    review_payload: dict[str, Any]
    bundle_payload: dict[str, Any]


class _MalformedCliArguments(ValueError):
    """Raised after argparse has rendered a normalized malformed-command error."""


class _ReviewPublicationStateUncertainError(CollectionError):
    """Raised when published review ownership cannot be proven for cleanup."""


class _ReviewArgumentParser(argparse.ArgumentParser):
    def error(self, message: str) -> NoReturn:
        self.print_usage(sys.stderr)
        self._print_message(f"{self.prog}: error: {message}\n", sys.stderr)
        raise _MalformedCliArguments(message)


class _SinglePathAction(argparse.Action):
    def __call__(
        self,
        parser: argparse.ArgumentParser,
        namespace: argparse.Namespace,
        values: str | Sequence[Any] | None,
        option_string: str | None = None,
    ) -> None:
        if getattr(namespace, self.dest, None) is not None:
            parser.error(f"{option_string or self.dest} may be specified only once")
        if not isinstance(values, Path):
            parser.error(f"{option_string or self.dest} requires one path")
        setattr(namespace, self.dest, values)


class _SingleStringAction(argparse.Action):
    def __call__(
        self,
        parser: argparse.ArgumentParser,
        namespace: argparse.Namespace,
        values: str | Sequence[Any] | None,
        option_string: str | None = None,
    ) -> None:
        if getattr(namespace, self.dest, None) is not None:
            parser.error(f"{option_string or self.dest} may be specified only once")
        if not isinstance(values, str):
            parser.error(f"{option_string or self.dest} requires one value")
        setattr(namespace, self.dest, values)


def _request_timeout_seconds(value: str) -> float:
    try:
        timeout_seconds = float(value)
        RequestPolicy(timeout_seconds=timeout_seconds)
    except (TypeError, ValueError, OverflowError):
        raise argparse.ArgumentTypeError(
            "must be a finite positive number with a maximum of 300 seconds"
        ) from None
    return timeout_seconds


class _SingleTimeoutAction(argparse.Action):
    def __call__(
        self,
        parser: argparse.ArgumentParser,
        namespace: argparse.Namespace,
        values: Any,
        option_string: str | None = None,
    ) -> None:
        if getattr(namespace, self.dest, None) is not None:
            parser.error(f"{option_string or self.dest} may be specified only once")
        if type(values) is not float:
            parser.error(f"{option_string or self.dest} requires one numeric value")
        setattr(namespace, self.dest, values)


def _parser() -> argparse.ArgumentParser:
    parser = _ReviewArgumentParser(description=__doc__)
    action = parser.add_mutually_exclusive_group(required=True)
    action.add_argument("--check-review", type=Path, metavar="PATH")
    action.add_argument("--live", action="store_true")
    action.add_argument(
        "--targeted-odii-review-enrichment",
        type=Path,
        action=_SinglePathAction,
        metavar="SOURCE_MANIFEST",
        help="derive a new exact-four review bundle using only targeted Odii evidence",
    )
    parser.add_argument("--output", type=Path, action=_SinglePathAction)
    parser.add_argument(
        "--source-lock",
        type=Path,
        action=_SinglePathAction,
        metavar="PATH",
        help=(
            "external preview source lock for --check-review; optional for legacy v1 "
            "reviews and required for rights-bearing v2 reviews"
        ),
    )
    parser.add_argument(
        "--diagnostics-dir",
        type=Path,
        action=_SinglePathAction,
        metavar="PATH",
        help=(
            "private provider JSONL directory; defaults to "
            ".diagnostics/provider-collection at the repository root"
        ),
    )
    parser.add_argument(
        "--request-timeout-seconds",
        type=_request_timeout_seconds,
        action=_SingleTimeoutAction,
        metavar="SECONDS",
        help="default 5.0 seconds; maximum 300 seconds",
    )
    parser.add_argument(
        "--candidate-selection",
        action="append",
        nargs=5,
        metavar=("NAME", "TOUR_ID", "ODII_TID", "ODII_TLID", "ODII_KEYWORD"),
        help="repeat in locked candidate order to apply an explicit reviewed identity mapping",
    )
    parser.add_argument(
        "--candidate-id",
        action=_SingleStringAction,
        metavar="preview:5",
        help="targeted mode requires exactly preview:5",
    )
    parser.add_argument(
        "--provider",
        action=_SingleStringAction,
        metavar="ODII",
        help="targeted mode requires exactly ODII",
    )
    parser.add_argument(
        "--keyword",
        action=_SingleStringAction,
        metavar="대릉원",
        help="targeted mode requires exactly 대릉원",
    )
    return parser


def _parse_candidate_selections(
    raw: list[list[str]] | None,
) -> tuple[_CandidateSelection, ...] | None:
    if raw is None:
        return None
    selections = tuple(_CandidateSelection(*values) for values in raw)
    if tuple(item.name for item in selections) != _LIVE_CANDIDATES:
        raise ValueError("candidate selections must cover the exact locked six-place order")
    if any(
        not identifier.isascii() or not identifier.isdigit() or not 1 <= len(identifier) <= 80
        for item in selections
        for identifier in (item.tour_content_id, item.odii_tid, item.odii_tlid)
    ):
        raise ValueError("candidate selection IDs must be bounded ASCII digits")
    if len({item.tour_content_id for item in selections}) != len(selections):
        raise ValueError("TourAPI candidate selection IDs must be unique")
    if len({(item.odii_tid, item.odii_tlid) for item in selections}) != len(selections):
        raise ValueError("Odii candidate selection IDs must be unique")
    if any(
        item.odii_search_keyword not in _ALLOWED_ODII_SEARCH_KEYWORDS[item.name]
        for item in selections
    ):
        raise ValueError("Odii search keyword is not an approved bounded alias")
    return selections


def _item_rows(payload: object) -> list[dict[str, object]]:
    rows: list[dict[str, object]] = []
    if isinstance(payload, dict):
        item = payload.get("item")
        if isinstance(item, dict):
            rows.append(item)
        elif isinstance(item, list):
            rows.extend(row for row in item if isinstance(row, dict))
        for child in payload.values():
            rows.extend(_item_rows(child))
    elif isinstance(payload, list):
        for child in payload:
            rows.extend(_item_rows(child))
    return rows


def _field(row: dict[str, object], *names: str) -> str | None:
    for name in names:
        value = row.get(name)
        if value not in (None, ""):
            return str(value)
    return None


def _normalized_title(value: str) -> str:
    return re.sub(r"[^0-9a-z가-힣]", "", value.casefold())


def _title_identifies_candidate(title: str | None, name: str) -> bool:
    if title is None:
        return False
    normalized_title = _normalized_title(title)
    normalized_name = _normalized_title(name)
    core_name = normalized_name.removesuffix("일원")
    return normalized_name in normalized_title or (
        len(core_name) >= 2 and core_name in normalized_title
    )


def _coordinates(row: dict[str, object]) -> tuple[float, float] | None:
    x_value = _field(row, "mapx", "mapX", "gpsX", "longitude", "lng")
    y_value = _field(row, "mapy", "mapY", "gpsY", "latitude", "lat")
    if x_value is None or y_value is None:
        return None
    try:
        coordinates = (float(x_value), float(y_value))
    except ValueError:
        return None
    return coordinates if all(math.isfinite(value) for value in coordinates) else None


def _matching_rows(payload: object, name: str) -> list[dict[str, object]]:
    normalized = _normalized_title(name)
    return [
        row
        for row in _item_rows(payload)
        if _field(row, "title", "name", "nameKo") is not None
        and _normalized_title(_field(row, "title", "name", "nameKo") or "") == normalized
        and "경주" in (_field(row, "addr1", "address", "addr") or "")
        and _coordinates(row) is not None
    ]


def _same_coordinates(
    first: dict[str, object], second: dict[str, object], *, tolerance: float = 0.01
) -> bool:
    first_coordinates = _coordinates(first)
    second_coordinates = _coordinates(second)
    return (
        first_coordinates is not None
        and second_coordinates is not None
        and abs(first_coordinates[0] - second_coordinates[0]) <= tolerance
        and abs(first_coordinates[1] - second_coordinates[1]) <= tolerance
    )


def _detail_matches(
    row: dict[str, object],
    search_row: dict[str, object],
    *,
    name: str,
    identifier_names: tuple[str, ...],
    expected_identifier: str,
) -> bool:
    matches = _matching_rows({"item": [row]}, name)
    return (
        len(matches) == 1
        and _field(row, *identifier_names) == expected_identifier
        and _same_coordinates(row, search_row)
    )


def _selected_search_row(
    payload: object,
    *,
    name: str,
    identifier_names: tuple[str, ...],
    expected_identifier: str,
    secondary_identifier_names: tuple[str, ...] = (),
    expected_secondary_identifier: str | None = None,
    require_gyeongju_address: bool,
) -> dict[str, object] | None:
    matches = [
        row
        for row in _item_rows(payload)
        if _field(row, *identifier_names) == expected_identifier
        and (
            expected_secondary_identifier is None
            or _field(row, *secondary_identifier_names) == expected_secondary_identifier
        )
        and _title_identifies_candidate(_field(row, "title", "name", "nameKo"), name)
        and _coordinates(row) is not None
        and (
            not require_gyeongju_address
            or "경주" in (_field(row, "addr1", "address", "addr") or "")
        )
    ]
    return matches[0] if len(matches) == 1 else None


def _selected_detail_matches(
    payload: object,
    search_row: dict[str, object] | None,
    *,
    name: str,
    identifier_names: tuple[str, ...],
    expected_identifier: str,
    require_gyeongju_address: bool,
) -> bool:
    if search_row is None:
        return False
    detail_row = _selected_search_row(
        payload,
        name=name,
        identifier_names=identifier_names,
        expected_identifier=expected_identifier,
        require_gyeongju_address=require_gyeongju_address,
    )
    return detail_row is not None and _same_coordinates(detail_row, search_row)


def _selected_story_matches(
    payload: object,
    search_row: dict[str, object] | None,
    *,
    selection: _CandidateSelection,
) -> bool:
    if search_row is None:
        return False
    rows = _item_rows(payload)
    if not rows or any(
        _field(row, "tid", "themeId") != selection.odii_tid
        or _field(row, "tlid", "themeLocationId") != selection.odii_tlid
        for row in rows
    ):
        return False
    return any(
        _title_identifies_candidate(
            _field(row, "title", "name", "nameKo"),
            selection.name,
        )
        and _same_coordinates(row, search_row)
        for row in rows
    )


def _evidence(
    collected: CollectedResponse,
    *,
    source_id: str | None,
) -> dict[str, object]:
    return {
        "provider": collected.provider,
        "source_id": source_id,
        "endpoint": collected.endpoint,
        "request_scope": collected.request_scope,
        "retrieved_at": collected.retrieved_at,
        "http_status": collected.http_status,
        "raw_response_sha256": collected.raw_response_sha256,
        "modifiedtime": collected.modifiedtime,
        "upstream_rights": list(collected.rights),
        "asset_usage_status": BLOCKED_RIGHTS_STATUS,
        "unresolved_reason": None if source_id else "upstream evidence missing",
    }


def _bundle_row(
    collected: CollectedResponse,
    *,
    candidate_place_id: str,
    source_id: str | None,
) -> dict[str, object]:
    return {
        "candidate_place_id": candidate_place_id,
        "provider": collected.provider,
        "endpoint": collected.endpoint,
        "request_scope": collected.request_scope,
        "source_id": source_id,
        "retrieved_at": collected.retrieved_at,
        "http_status": collected.http_status,
        "raw_response_sha256": collected.raw_response_sha256,
        "raw_body_base64": collected.raw_body_base64,
        "modifiedtime": collected.modifiedtime,
        "rights": list(collected.rights),
        "asset_usage_status": BLOCKED_RIGHTS_STATUS,
    }


def _canonical_json_bytes(payload: object) -> bytes:
    return (
        json.dumps(
            payload, ensure_ascii=False, sort_keys=True, separators=(",", ":"), default=str
        ).encode("utf-8")
        + b"\n"
    )


def _load_live_credentials() -> tuple[str, str]:
    root_result = subprocess.run(
        ["git", "rev-parse", "--show-toplevel"],
        check=True,
        capture_output=True,
        text=True,
    )
    repository_root = Path(root_result.stdout.strip()).resolve(strict=True)
    credentials_path = repository_root / _CREDENTIAL_PATH
    ignore_result = subprocess.run(
        [
            "git",
            "-C",
            str(repository_root),
            "check-ignore",
            "--no-index",
            "-q",
            "--",
            _CREDENTIAL_PATH.as_posix(),
        ],
        check=False,
        capture_output=True,
    )
    if ignore_result.returncode != 0:
        raise CollectionError("credential file must be proven Git-ignored before access")
    tracked_result = subprocess.run(
        [
            "git",
            "-C",
            str(repository_root),
            "ls-files",
            "--error-unmatch",
            "--",
            _CREDENTIAL_PATH.as_posix(),
        ],
        check=False,
        capture_output=True,
    )
    if tracked_result.returncode == 0:
        raise CollectionError("credential file must never be tracked by Git")
    metadata = credentials_path.lstat()
    if not stat.S_ISREG(metadata.st_mode) or credentials_path.is_symlink():
        raise CollectionError("credential path must be a regular non-symlink file")
    if stat.S_IMODE(metadata.st_mode) != 0o600:
        raise CollectionError("credential file mode must be exactly 0600")
    values: dict[str, str] = {}
    for line in credentials_path.read_text(encoding="utf-8").splitlines():
        if not line or line.startswith("#") or "=" not in line:
            raise CollectionError("credential file must contain only the two required assignments")
        key, value = line.split("=", maxsplit=1)
        if key not in _CREDENTIAL_NAMES or key in values or not value:
            raise CollectionError("credential file contains invalid, duplicate, or empty fields")
        values[key] = value
    if tuple(values) != _CREDENTIAL_NAMES:
        raise CollectionError("credential file requires both keys in the documented order")
    return values[_CREDENTIAL_NAMES[0]], values[_CREDENTIAL_NAMES[1]]


def _path_has_symlinked_component(path: Path) -> bool:
    absolute = path if path.is_absolute() else Path.cwd() / path
    components = (absolute, *absolute.parents)
    for component in reversed(components):
        try:
            if component.is_symlink():
                return True
            component.lstat()
        except FileNotFoundError:
            break
        except OSError:
            raise CollectionError("path safety could not be established") from None
    return False


def _open_directory_fd_nofollow(path: Path) -> int:
    """Open one directory after walking every ancestor without following links."""

    absolute = Path(os.path.abspath(path))
    flags = (
        os.O_RDONLY
        | getattr(os, "O_DIRECTORY", 0)
        | getattr(os, "O_NOFOLLOW", 0)
        | getattr(os, "O_CLOEXEC", 0)
    )
    try:
        descriptor = os.open(absolute.anchor, flags)
    except OSError:
        raise CollectionError("directory path could not be opened safely") from None
    try:
        for component in absolute.parts[1:]:
            next_descriptor = os.open(component, flags, dir_fd=descriptor)
            os.close(descriptor)
            descriptor = next_descriptor
        return descriptor
    except OSError:
        os.close(descriptor)
        raise CollectionError("directory path must not traverse symlinks") from None


def _is_safe_relative_name(name: str) -> bool:
    return bool(name) and name not in {".", ".."} and Path(name).name == name


def _read_regular_file_at(
    directory_descriptor: int,
    name: str,
    *,
    maximum_bytes: int,
    require_private: bool = False,
) -> bytes:
    if not _is_safe_relative_name(name):
        raise CollectionError("unsafe relative file name")
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0)
    try:
        descriptor = os.open(name, flags, dir_fd=directory_descriptor)
        try:
            before = os.fstat(descriptor)
            if (
                not stat.S_ISREG(before.st_mode)
                or before.st_nlink != 1
                or not 1 <= before.st_size <= maximum_bytes
                or (require_private and stat.S_IMODE(before.st_mode) != 0o600)
            ):
                raise CollectionError("file metadata violates the safe-read contract")
            chunks: list[bytes] = []
            remaining = maximum_bytes + 1
            while remaining:
                chunk = os.read(descriptor, min(remaining, 65_536))
                if not chunk:
                    break
                chunks.append(chunk)
                remaining -= len(chunk)
            payload = b"".join(chunks)
            after = os.fstat(descriptor)
            if (
                len(payload) > maximum_bytes
                or len(payload) != before.st_size
                or (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns)
                != (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns)
            ):
                raise CollectionError("file changed during safe read")
            return payload
        finally:
            os.close(descriptor)
    except OSError:
        raise CollectionError("file could not be read safely") from None


def _read_targeted_source_artifacts_nofollow(source_manifest: Path) -> dict[str, bytes]:
    if source_manifest.name != "review-manifest.json":
        raise CollectionError("targeted source must name review-manifest.json")
    directory_descriptor = _open_directory_fd_nofollow(source_manifest.parent)
    try:
        try:
            names = frozenset(os.listdir(directory_descriptor))
        except OSError:
            raise CollectionError("targeted source directory could not be listed safely") from None
        if names != _TARGETED_REVIEW_ARTIFACT_NAMES:
            raise CollectionError("targeted source must contain exactly four canonical artifacts")
        return {
            name: _read_regular_file_at(
                directory_descriptor,
                name,
                maximum_bytes=_MAX_TARGETED_SOURCE_ARTIFACT_BYTES,
            )
            for name in sorted(_TARGETED_REVIEW_ARTIFACT_NAMES)
        }
    finally:
        os.close(directory_descriptor)


def _validated_targeted_odii_credential_path() -> Path:
    repository_root = _repository_root()
    credentials_path = repository_root / _TARGETED_ODII_CREDENTIAL_PATH
    if _path_has_symlinked_component(credentials_path):
        raise CollectionError("Odii credential path must not traverse symlinks")
    ignore_result = subprocess.run(
        [
            "git",
            "-C",
            str(repository_root),
            "check-ignore",
            "--no-index",
            "-q",
            "--",
            _TARGETED_ODII_CREDENTIAL_PATH.as_posix(),
        ],
        check=False,
        capture_output=True,
    )
    if ignore_result.returncode != 0:
        raise CollectionError("credential file must be proven Git-ignored before access")
    tracked_result = subprocess.run(
        [
            "git",
            "-C",
            str(repository_root),
            "ls-files",
            "--error-unmatch",
            "--",
            _TARGETED_ODII_CREDENTIAL_PATH.as_posix(),
        ],
        check=False,
        capture_output=True,
    )
    if tracked_result.returncode == 0:
        raise CollectionError("credential file must never be tracked by Git")
    metadata = credentials_path.lstat()
    if (
        not stat.S_ISREG(metadata.st_mode)
        or credentials_path.is_symlink()
        or metadata.st_nlink != 1
        or not 1 <= metadata.st_size <= _MAX_TARGETED_CREDENTIAL_BYTES
    ):
        raise CollectionError("credential path must be a regular non-symlink file")
    if stat.S_IMODE(metadata.st_mode) != 0o600:
        raise CollectionError("credential file mode must be exactly 0600")
    return credentials_path


def _read_targeted_odii_credential_nofollow(credentials_path: Path) -> str:
    directory_descriptor = _open_directory_fd_nofollow(credentials_path.parent)
    try:
        payload = _read_regular_file_at(
            directory_descriptor,
            credentials_path.name,
            maximum_bytes=_MAX_TARGETED_CREDENTIAL_BYTES,
            require_private=True,
        )
    finally:
        os.close(directory_descriptor)
    try:
        text = payload.decode("utf-8")
    except UnicodeDecodeError:
        raise CollectionError("Odii credential file must be valid UTF-8") from None
    if text.endswith("\n"):
        text = text[:-1]
    prefix = "ODII_SERVICE_KEY="
    if not text.startswith(prefix) or "\n" in text or "\r" in text or not text.removeprefix(prefix):
        raise CollectionError("Odii credential file must contain exactly one assignment")
    return text.removeprefix(prefix)


def _load_targeted_odii_credential() -> str:
    return _read_targeted_odii_credential_nofollow(_validated_targeted_odii_credential_path())


def _repository_root() -> Path:
    try:
        root_result = subprocess.run(
            ["git", "rev-parse", "--show-toplevel"],
            check=True,
            capture_output=True,
            text=True,
        )
        return Path(root_result.stdout.strip()).resolve(strict=True)
    except (OSError, subprocess.SubprocessError):
        raise CollectionError("repository root could not be established") from None


def _resolve_existing_path_prefix(path: Path) -> tuple[Path, Path, bool]:
    try:
        cursor = path.absolute()
    except OSError:
        raise ProviderDiagnosticsError from None
    missing: list[str] = []
    while True:
        try:
            cursor.lstat()
        except FileNotFoundError:
            if cursor == cursor.parent:
                raise ProviderDiagnosticsError from None
            missing_name = cursor.name
            if missing_name in {".", ".."}:
                raise ProviderDiagnosticsError from None
            missing.append(missing_name)
            cursor = cursor.parent
            continue
        except OSError:
            raise ProviderDiagnosticsError from None
        break
    try:
        resolved = cursor.resolve(strict=True)
        if missing and not stat.S_ISDIR(resolved.stat().st_mode):
            raise ProviderDiagnosticsError
    except (OSError, RuntimeError):
        raise ProviderDiagnosticsError from None
    return resolved.joinpath(*reversed(missing)), resolved, bool(missing)


def _existing_prefix_is_within(child: Path, ancestor: Path) -> bool:
    try:
        return any(candidate.samefile(ancestor) for candidate in (child, *child.parents))
    except OSError:
        raise ProviderDiagnosticsError from None


def _validate_diagnostics_location(output: Path, diagnostics_dir: Path) -> None:
    rendered = str(diagnostics_dir)
    if (
        not rendered
        or len(rendered) > 1_024
        or any(ord(character) < 32 or ord(character) == 127 for character in rendered)
    ):
        raise ProviderDiagnosticsError
    output_path, output_prefix, output_missing = _resolve_existing_path_prefix(output)
    diagnostics_path, diagnostics_prefix, diagnostics_missing = _resolve_existing_path_prefix(
        diagnostics_dir
    )
    if (
        output_path == diagnostics_path
        or output_path.is_relative_to(diagnostics_path)
        or diagnostics_path.is_relative_to(output_path)
        or (
            not diagnostics_missing
            and _existing_prefix_is_within(output_prefix, diagnostics_prefix)
        )
        or (not output_missing and _existing_prefix_is_within(diagnostics_prefix, output_prefix))
    ):
        raise ProviderDiagnosticsError


def _provider_request(
    client: Any,
    operation: str,
    params: dict[str, str],
    *,
    diagnostics: ProviderDiagnostics,
    candidate_place_id: str,
    candidate_name: str,
    provider: str,
) -> CollectedResponse:
    diagnostic_operation = diagnostics.operation(
        candidate_place_id=candidate_place_id,
        candidate_name=candidate_name,
        provider=provider,
        operation=operation,
    )
    if isinstance(client, OfficialApiClient):
        response = client.request(
            operation,
            params,
            explicit_opt_in=True,
            diagnostics=diagnostics,
            diagnostic_operation=diagnostic_operation,
        )
    else:
        response = client.request(operation, params, explicit_opt_in=True)
    diagnostics.complete_operation(diagnostic_operation)
    return response


def _collect_live_artifacts(
    output: Path,
    *,
    output_parent_descriptor: int,
    selections: tuple[_CandidateSelection, ...] | None,
    tour_key: str,
    odii_key: str,
    diagnostics: ProviderDiagnostics,
    policy: RequestPolicy,
) -> int:
    bundle_rows: list[dict[str, object]] = []
    candidate_rows: list[dict[str, Any]] = []
    with (
        KorService2Client(service_key=tour_key, policy=policy) as kto,
        OdiiClient(service_key=odii_key, policy=policy) as odii,
    ):
        for index, name in enumerate(_LIVE_CANDIDATES, start=1):
            place_id = f"preview:{index}"
            selection = selections[index - 1] if selections is not None else None
            kto_search = _provider_request(
                kto,
                "searchKeyword2",
                {"keyword": name},
                diagnostics=diagnostics,
                candidate_place_id=place_id,
                candidate_name=name,
                provider="TOUR_API",
            )
            odii_search_keyword = selection.odii_search_keyword if selection is not None else name
            odii_search = _provider_request(
                odii,
                "themeSearchList",
                {"keyword": odii_search_keyword},
                diagnostics=diagnostics,
                candidate_place_id=place_id,
                candidate_name=name,
                provider="ODII",
            )
            if selection is not None:
                kto_row = _selected_search_row(
                    kto_search.payload,
                    name=name,
                    identifier_names=("contentid", "contentId"),
                    expected_identifier=selection.tour_content_id,
                    require_gyeongju_address=True,
                )
                odii_row = _selected_search_row(
                    odii_search.payload,
                    name=name,
                    identifier_names=("tid", "themeId"),
                    expected_identifier=selection.odii_tid,
                    secondary_identifier_names=("tlid", "themeLocationId"),
                    expected_secondary_identifier=selection.odii_tlid,
                    require_gyeongju_address=False,
                )
                location_row = kto_row
                location_coordinates = (
                    _coordinates(location_row) if location_row is not None else None
                )
                search_identity_valid = (
                    kto_row is not None
                    and odii_row is not None
                    and _same_coordinates(kto_row, odii_row)
                )
                kto_detail = _provider_request(
                    kto,
                    "detailCommon2",
                    {"contentId": selection.tour_content_id},
                    diagnostics=diagnostics,
                    candidate_place_id=place_id,
                    candidate_name=name,
                    provider="TOUR_API",
                )
                kto_images = _provider_request(
                    kto,
                    "detailImage2",
                    {"contentId": selection.tour_content_id},
                    diagnostics=diagnostics,
                    candidate_place_id=place_id,
                    candidate_name=name,
                    provider="TOUR_API",
                )
                odii_story = _provider_request(
                    odii,
                    "storyBasedList",
                    {"tid": selection.odii_tid, "tlid": selection.odii_tlid},
                    diagnostics=diagnostics,
                    candidate_place_id=place_id,
                    candidate_name=name,
                    provider="ODII",
                )
                detail_valid = search_identity_valid and _selected_detail_matches(
                    kto_detail.payload,
                    kto_row,
                    name=name,
                    identifier_names=("contentid", "contentId"),
                    expected_identifier=selection.tour_content_id,
                    require_gyeongju_address=True,
                )
                story_valid = search_identity_valid and _selected_story_matches(
                    odii_story.payload,
                    odii_row,
                    selection=selection,
                )
                kto_id = selection.tour_content_id if detail_valid else None
                odii_id = selection.odii_source_id if story_valid else None
                preserved_results = [
                    (
                        kto_search,
                        selection.tour_content_id if kto_row is not None else None,
                    ),
                    (
                        odii_search,
                        selection.odii_source_id if odii_row is not None else None,
                    ),
                    (kto_detail, kto_id),
                    (kto_images, selection.tour_content_id),
                    (odii_story, odii_id),
                ]
                kto_result = kto_detail
                odii_result = odii_story
            else:
                kto_matches = _matching_rows(kto_search.payload, name)
                odii_matches = _matching_rows(odii_search.payload, name)
                location_row = kto_matches[0] if len(kto_matches) == 1 else None
                location_coordinates = (
                    _coordinates(location_row) if location_row is not None else None
                )
                unique_match = (
                    len(kto_matches) == 1
                    and len(odii_matches) == 1
                    and _same_coordinates(kto_matches[0], odii_matches[0])
                )
                kto_result = kto_search
                odii_result = odii_search
                detailed_results: list[tuple[CollectedResponse, str | None]] = []
                kto_id = None
                odii_id = None
                if unique_match:
                    kto_row = kto_matches[0]
                    odii_row = odii_matches[0]
                    content_id = _field(kto_row, "contentid", "contentId")
                    tid = _field(odii_row, "tid", "themeId")
                    tlid = _field(odii_row, "tlid", "themeLocationId")
                    if content_id is not None and tid is not None and tlid is not None:
                        kto_detail = _provider_request(
                            kto,
                            "detailCommon2",
                            {"contentId": content_id},
                            diagnostics=diagnostics,
                            candidate_place_id=place_id,
                            candidate_name=name,
                            provider="TOUR_API",
                        )
                        kto_images = _provider_request(
                            kto,
                            "detailImage2",
                            {"contentId": content_id},
                            diagnostics=diagnostics,
                            candidate_place_id=place_id,
                            candidate_name=name,
                            provider="TOUR_API",
                        )
                        odii_story = _provider_request(
                            odii,
                            "storyBasedList",
                            {"tid": tid, "tlid": tlid},
                            diagnostics=diagnostics,
                            candidate_place_id=place_id,
                            candidate_name=name,
                            provider="ODII",
                        )
                        detail_rows = _item_rows(kto_detail.payload)
                        story_rows = _item_rows(odii_story.payload)
                        detail_valid = len(detail_rows) == 1 and _detail_matches(
                            detail_rows[0],
                            kto_row,
                            name=name,
                            identifier_names=("contentid", "contentId"),
                            expected_identifier=content_id,
                        )
                        story_id = (
                            _field(
                                story_rows[0],
                                "storyid",
                                "storyId",
                                "sid",
                                "audioid",
                                "audioId",
                            )
                            if len(story_rows) == 1
                            else None
                        )
                        story_valid = (
                            len(story_rows) == 1
                            and story_id is not None
                            and _field(story_rows[0], "tid", "themeId") == tid
                            and _field(story_rows[0], "tlid", "themeLocationId") == tlid
                            and _detail_matches(
                                story_rows[0],
                                odii_row,
                                name=name,
                                identifier_names=(
                                    "storyid",
                                    "storyId",
                                    "sid",
                                    "audioid",
                                    "audioId",
                                ),
                                expected_identifier=story_id,
                            )
                        )
                        kto_result = kto_detail
                        odii_result = odii_story
                        kto_id = content_id if detail_valid else None
                        odii_id = story_id if story_valid else None
                        detailed_results.extend(
                            (
                                (kto_detail, content_id),
                                (kto_images, content_id),
                                (odii_story, story_id),
                            )
                        )
                search_kto_id = (
                    _field(kto_matches[0], "contentid", "contentId")
                    if len(kto_matches) == 1
                    else None
                )
                search_odii_tid = (
                    _field(odii_matches[0], "tid", "themeId") if len(odii_matches) == 1 else None
                )
                search_odii_tlid = (
                    _field(odii_matches[0], "tlid", "themeLocationId")
                    if len(odii_matches) == 1
                    else None
                )
                search_odii_id = (
                    f"{search_odii_tid}/{search_odii_tlid}"
                    if search_odii_tid is not None and search_odii_tlid is not None
                    else None
                )
                preserved_results = [
                    (kto_search, search_kto_id),
                    (odii_search, search_odii_id),
                    *detailed_results,
                ]
            bundle_rows.extend(
                _bundle_row(
                    collected,
                    candidate_place_id=place_id,
                    source_id=source_id,
                )
                for collected, source_id in preserved_results
            )
            resolved = kto_id is not None and odii_id is not None
            candidate_rows.append(
                {
                    "place_id": place_id,
                    "name_ko": name,
                    "address_ko": (
                        _field(location_row, "addr1", "address", "addr")
                        if location_row is not None
                        else None
                    ),
                    "longitude": (
                        location_coordinates[0] if location_coordinates is not None else None
                    ),
                    "latitude": (
                        location_coordinates[1] if location_coordinates is not None else None
                    ),
                    "split": "PREVIEW",
                    "assessment_status": "NOT_SCORED",
                    "resolution_status": "RESOLVED" if resolved else "UNRESOLVED",
                    "evidence": [
                        _evidence(
                            kto_result,
                            source_id=kto_id,
                        ),
                        _evidence(
                            odii_result,
                            source_id=odii_id,
                        ),
                    ],
                }
            )

    bundle_bytes = _canonical_json_bytes(
        {
            "schema_version": "provider-bundle-v1",
            "redacted": True,
            "rows": bundle_rows,
        }
    )
    review = CandidateReview.model_validate(
        {
            "schema_version": "candidate-review-v1",
            "artifact_status": "REVIEW_ONLY",
            "bundle_path": "raw-provider-bundle.redacted.json",
            "redacted_bundle_sha256": sha256_bytes(bundle_bytes),
            "candidates": candidate_rows,
        }
    )
    review_bytes = _canonical_json_bytes(review.model_dump(mode="json", exclude={"rights_review"}))
    bundle = RawProviderBundle.model_validate_json(bundle_bytes)
    markdown_bytes = render_candidate_review_markdown(review, bundle)
    for artifact_bytes in (bundle_bytes, review_bytes, markdown_bytes):
        if any(
            credential_material_present(artifact_bytes, secret) for secret in (tour_key, odii_key)
        ):
            raise CollectionError("review artifact contains credential material")

    fully_resolved = all(row["resolution_status"] == "RESOLVED" for row in candidate_rows)
    expected_exit_code = CHECK_RESOLVED if fully_resolved else CHECK_UNRESOLVED
    _publish_review_artifacts(
        output,
        output_parent_descriptor=output_parent_descriptor,
        payloads={
            "raw-provider-bundle.redacted.json": bundle_bytes,
            "candidate-review.json": review_bytes,
            "candidate-review.md": markdown_bytes,
            "review-manifest.json": build_review_manifest_from_bytes(
                bundle_bytes=bundle_bytes,
                candidate_bytes=review_bytes,
                markdown_bytes=markdown_bytes,
            ),
        },
        expected_exit_code=expected_exit_code,
        staging_prefix=".live-review-",
    )
    return _finish_published_collection(
        diagnostics,
        committed_exit_code=expected_exit_code,
    )


def _preflight_targeted_source(source_manifest: Path) -> _TargetedSourceSnapshot:
    artifacts = _read_targeted_source_artifacts_nofollow(source_manifest)
    manifest_bytes = artifacts["review-manifest.json"]
    if sha256_bytes(manifest_bytes) != _TARGETED_SOURCE_MANIFEST_SHA256:
        raise CollectionError("targeted source manifest does not match reviewed v12")
    with tempfile.TemporaryDirectory(prefix="itda-targeted-source-check-") as temporary_name:
        temporary = Path(temporary_name)
        for name, payload in artifacts.items():
            (temporary / name).write_bytes(payload)
        checked = check_review_manifest(temporary / "review-manifest.json")
        if (temporary / "review-manifest.json").read_bytes() != manifest_bytes:
            raise CollectionError("targeted source manifest changed during validation")
    if (
        checked.exit_code != CHECK_UNRESOLVED
        or checked.review is None
        or checked.bundle_path is None
    ):
        raise CollectionError("source review must be canonical, exact-four, and unresolved")
    bundle_bytes = artifacts["raw-provider-bundle.redacted.json"]
    if sha256_bytes(bundle_bytes) != checked.review.redacted_bundle_sha256:
        raise CollectionError("targeted source bundle changed during validation")
    try:
        bundle_payload = json.loads(bundle_bytes)
        review_payload = json.loads(artifacts["candidate-review.json"])
    except (UnicodeDecodeError, json.JSONDecodeError):
        raise CollectionError("targeted source JSON could not be decoded exactly") from None
    if not isinstance(bundle_payload, dict) or not isinstance(review_payload, dict):
        raise CollectionError("targeted source JSON roots must be objects")
    bundle = RawProviderBundle.model_validate(bundle_payload)
    review = CandidateReview.model_validate(review_payload)
    if review != checked.review:
        raise CollectionError("targeted source review changed during validation")
    expected_place_ids = tuple(f"preview:{index}" for index in range(1, 7))
    if tuple(candidate.place_id for candidate in review.candidates) != expected_place_ids:
        raise CollectionError("targeted source candidate IDs or order are invalid")
    if any(candidate.resolution_status.value != "UNRESOLVED" for candidate in review.candidates):
        raise CollectionError("targeted source candidates must all remain unresolved")
    if len(bundle.rows) != 12:
        raise CollectionError("targeted source must contain exactly twelve baseline rows")

    for candidate in review.candidates:
        rows = [row for row in bundle.rows if row.candidate_place_id == candidate.place_id]
        if tuple(row.endpoint for row in rows) != (
            "KorService2/searchKeyword2",
            "Odii/themeSearchList",
        ) or any(row.source_id is not None for row in rows):
            raise CollectionError("targeted source baseline endpoints are invalid")
        tour_id = _TARGETED_APPROVED_IDENTITIES[candidate.place_id][0]
        tour_payload = parse_provider_json_bytes(b64decode(rows[0].raw_body_base64, validate=True))
        if (
            _selected_search_row(
                tour_payload,
                name=candidate.name_ko,
                identifier_names=("contentid", "contentId"),
                expected_identifier=tour_id,
                require_gyeongju_address=True,
            )
            is None
        ):
            raise CollectionError("targeted source TourAPI identity is not approved")
        if candidate.place_id != _TARGETED_CANDIDATE_ID:
            odii_id = _TARGETED_APPROVED_IDENTITIES[candidate.place_id][1]
            tid, tlid = odii_id.split("/")
            odii_payload = parse_provider_json_bytes(
                b64decode(rows[1].raw_body_base64, validate=True)
            )
            if (
                _selected_search_row(
                    odii_payload,
                    name=candidate.name_ko,
                    identifier_names=("tid", "themeId"),
                    expected_identifier=tid,
                    secondary_identifier_names=("tlid", "themeLocationId"),
                    expected_secondary_identifier=tlid,
                    require_gyeongju_address=False,
                )
                is None
            ):
                raise CollectionError("targeted source Odii identity is not approved")
    return _TargetedSourceSnapshot(
        review=review,
        bundle=bundle,
        review_payload=review_payload,
        bundle_payload=bundle_payload,
    )


def _atomic_rename_directory_noreplace_at(
    parent_descriptor: int,
    source_name: str,
    destination_name: str,
) -> None:
    """Rename within a pinned directory while refusing every existing destination."""

    if not all(_is_safe_relative_name(name) for name in (source_name, destination_name)):
        raise CollectionError("unsafe targeted publication name")
    library = ctypes.CDLL(None, use_errno=True)
    source_bytes = os.fsencode(source_name)
    destination_bytes = os.fsencode(destination_name)
    if hasattr(library, "renameat2"):
        renameat2 = library.renameat2
        renameat2.argtypes = [
            ctypes.c_int,
            ctypes.c_char_p,
            ctypes.c_int,
            ctypes.c_char_p,
            ctypes.c_uint,
        ]
        renameat2.restype = ctypes.c_int
        result = renameat2(
            parent_descriptor,
            source_bytes,
            parent_descriptor,
            destination_bytes,
            1,
        )
    elif hasattr(library, "renameatx_np"):
        renameatx_np = library.renameatx_np
        renameatx_np.argtypes = [
            ctypes.c_int,
            ctypes.c_char_p,
            ctypes.c_int,
            ctypes.c_char_p,
            ctypes.c_uint,
        ]
        renameatx_np.restype = ctypes.c_int
        result = renameatx_np(
            parent_descriptor,
            source_bytes,
            parent_descriptor,
            destination_bytes,
            0x00000004,
        )
    else:
        raise CollectionError("atomic no-replace publication is unavailable")
    if result == 0:
        return
    error_number = ctypes.get_errno()
    if error_number in {errno.EEXIST, errno.ENOTEMPTY}:
        raise CollectionError("targeted review output already exists")
    raise CollectionError("atomic no-replace publication failed")


def _atomic_rename_directory_noreplace(source: Path, destination: Path) -> None:
    """Compatibility wrapper around pinned-parent no-replace publication."""

    if os.path.abspath(source.parent) != os.path.abspath(destination.parent):
        raise CollectionError("targeted publication paths must share one parent")
    parent_descriptor = _open_directory_fd_nofollow(source.parent)
    try:
        _atomic_rename_directory_noreplace_at(
            parent_descriptor,
            source.name,
            destination.name,
        )
    finally:
        os.close(parent_descriptor)


def _targeted_theme_pairs(payload: object) -> list[tuple[str, str]]:
    pairs = {
        (tid, tlid)
        for row in _item_rows(payload)
        if _title_identifies_candidate(
            _field(row, "title", "name", "nameKo"),
            _TARGETED_CANDIDATE_NAME,
        )
        and (tid := _field(row, "tid", "themeId")) is not None
        and (tlid := _field(row, "tlid", "themeLocationId")) is not None
        and tid.isascii()
        and tid.isdigit()
        and tlid.isascii()
        and tlid.isdigit()
        and 1 <= len(tid) <= 80
        and 1 <= len(tlid) <= 80
    }
    if not pairs or len(pairs) > _MAX_TARGETED_THEME_PAIRS:
        raise CollectionError("targeted Odii theme candidates are missing or exceed policy")
    return sorted(pairs, key=lambda pair: (int(pair[0]), int(pair[1]), pair))


def _targeted_story_matches(payload: object, *, tid: str, tlid: str) -> bool:
    rows = _item_rows(payload)
    return (
        bool(rows)
        and all(
            _field(row, "tid", "themeId") == tid and _field(row, "tlid", "themeLocationId") == tlid
            for row in rows
        )
        and any(
            _title_identifies_candidate(
                _field(row, "title", "name", "nameKo"),
                _TARGETED_CANDIDATE_NAME,
            )
            for row in rows
        )
    )


def _write_regular_file_at(
    directory_descriptor: int,
    name: str,
    payload: bytes,
) -> None:
    if not _is_safe_relative_name(name):
        raise CollectionError("unsafe relative file name")
    flags = (
        os.O_WRONLY
        | os.O_CREAT
        | os.O_EXCL
        | getattr(os, "O_NOFOLLOW", 0)
        | getattr(os, "O_CLOEXEC", 0)
    )
    try:
        descriptor = os.open(name, flags, 0o600, dir_fd=directory_descriptor)
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
    except OSError:
        raise CollectionError(
            "review artifact could not be written safely",
            category="filesystem",
            exception_class="OSError",
        ) from None


def _publish_review_artifacts(
    output: Path,
    *,
    output_parent_descriptor: int,
    payloads: dict[str, bytes],
    expected_exit_code: int,
    staging_prefix: str,
) -> None:
    """Validate and fsync an exact-four sibling before no-replace publication."""

    expected_names = {
        "raw-provider-bundle.redacted.json",
        "candidate-review.json",
        "candidate-review.md",
        "review-manifest.json",
    }
    if set(payloads) != expected_names or not _is_safe_relative_name(output.name):
        raise CollectionError("review publication artifact set or output name is invalid")
    staging_name = f"{staging_prefix}{uuid4().hex}"
    if not _is_safe_relative_name(staging_name):
        raise CollectionError("review staging name is unsafe")
    staging_descriptor: int | None = None
    published = False
    preserve_uncertain_state = False
    try:
        os.mkdir(staging_name, 0o700, dir_fd=output_parent_descriptor)
        staging_descriptor = os.open(
            staging_name,
            os.O_RDONLY
            | getattr(os, "O_DIRECTORY", 0)
            | getattr(os, "O_NOFOLLOW", 0)
            | getattr(os, "O_CLOEXEC", 0),
            dir_fd=output_parent_descriptor,
        )
        for name, payload in payloads.items():
            _write_regular_file_at(staging_descriptor, name, payload)
        os.fsync(staging_descriptor)
        staging_path = output.parent / staging_name
        with prepared_directory_snapshot(staging_path) as prepared_snapshot:
            with tempfile.TemporaryDirectory(prefix=".collection-validation-") as validation_parent:
                validation_root = Path(validation_parent) / "review"
                prepared_snapshot.materialize(validation_root)
                checked = check_review_manifest(validation_root / "review-manifest.json")
            if checked.exit_code != expected_exit_code:
                raise CollectionError("staged review failed canonical validation")
            try:
                prepared_snapshot.verify_visible(
                    output_parent_descriptor,
                    staging_name,
                )
            except OSError as identity_error:
                preserve_uncertain_state = True
                raise _ReviewPublicationStateUncertainError(
                    "review publication state is uncertain before rename",
                    category="filesystem",
                    exception_class="OSError",
                ) from identity_error
            try:
                _atomic_rename_directory_noreplace_at(
                    output_parent_descriptor,
                    staging_name,
                    output.name,
                )
            except CollectionError as rename_error:
                try:
                    prepared_snapshot.verify_visible(
                        output_parent_descriptor,
                        staging_name,
                    )
                except OSError as identity_error:
                    preserve_uncertain_state = True
                    raise _ReviewPublicationStateUncertainError(
                        "review publication state is uncertain after rename failure",
                        category="filesystem",
                        exception_class="OSError",
                    ) from identity_error
                raise rename_error
            try:
                prepared_snapshot.verify_visible(
                    output_parent_descriptor,
                    output.name,
                )
                os.fsync(output_parent_descriptor)
            except OSError as commit_error:
                preserve_uncertain_state = True
                raise _ReviewPublicationStateUncertainError(
                    "review publication state is uncertain after identity or durability failure",
                    category="filesystem",
                    exception_class="OSError",
                ) from commit_error
        published = True
    finally:
        cleanup_failures: list[str] = []
        if not published and not preserve_uncertain_state and staging_descriptor is not None:
            for name in payloads:
                try:
                    os.unlink(name, dir_fd=staging_descriptor)
                except FileNotFoundError:
                    pass
                except OSError:
                    cleanup_failures.append(f"unlink:{name}")
        if staging_descriptor is not None:
            try:
                os.close(staging_descriptor)
            except OSError:
                cleanup_failures.append("staging-close")
        if not published and not preserve_uncertain_state:
            try:
                os.rmdir(staging_name, dir_fd=output_parent_descriptor)
            except FileNotFoundError:
                pass
            except OSError:
                cleanup_failures.append("staging-rmdir")
        if cleanup_failures:
            with suppress(Exception):
                sys.stderr.write(
                    "review staging cleanup degraded: " + ",".join(cleanup_failures) + "\n"
                )


def _finish_published_collection(
    diagnostics: ProviderDiagnostics,
    *,
    committed_exit_code: int,
) -> int:
    """Keep a durable publication successful if only its final diagnostic degrades."""

    try:
        diagnostics.terminal_success()
    except ProviderDiagnosticsError:
        with suppress(Exception):
            print(
                "provider collection diagnostics degraded after durable publication",
                file=sys.stderr,
            )
    return committed_exit_code


def _teardown_collection(
    diagnostics: ProviderDiagnostics | None,
    *,
    output_parent_descriptor: int,
) -> None:
    """Attempt every teardown action without replacing the operation outcome."""

    failures: list[str] = []
    if diagnostics is not None:
        try:
            print(
                f"provider collection diagnostics: {diagnostics.file_name}",
                file=sys.stderr,
            )
        except Exception:
            failures.append("diagnostics-report")
        try:
            diagnostics.close()
        except Exception:
            failures.append("diagnostics-close")
    try:
        os.close(output_parent_descriptor)
    except Exception:
        failures.append("output-parent-close")
    if failures:
        with suppress(Exception):
            sys.stderr.write("provider collection teardown degraded: " + ",".join(failures) + "\n")


def _publish_targeted_review(
    output: Path,
    *,
    output_parent_descriptor: int,
    review_payload: dict[str, Any],
    bundle_payload: dict[str, Any],
    odii_key: str,
) -> None:
    preserved_bundle_payload = deepcopy(bundle_payload)
    bundle = RawProviderBundle.model_validate(preserved_bundle_payload)
    bundle_bytes = _canonical_json_bytes(preserved_bundle_payload)
    rebound_review_payload = deepcopy(review_payload)
    rebound_review_payload["redacted_bundle_sha256"] = sha256_bytes(bundle_bytes)
    rebound_review = CandidateReview.model_validate(rebound_review_payload)
    review_bytes = _canonical_json_bytes(rebound_review_payload)
    markdown_bytes = render_candidate_review_markdown(rebound_review, bundle)
    payloads = {
        "raw-provider-bundle.redacted.json": bundle_bytes,
        "candidate-review.json": review_bytes,
        "candidate-review.md": markdown_bytes,
    }
    if any(credential_material_present(payload, odii_key) for payload in payloads.values()):
        raise CollectionError("review artifact contains credential material")

    payloads["review-manifest.json"] = build_review_manifest_from_bytes(
        bundle_bytes=bundle_bytes,
        candidate_bytes=review_bytes,
        markdown_bytes=markdown_bytes,
    )
    _publish_review_artifacts(
        output,
        output_parent_descriptor=output_parent_descriptor,
        payloads=payloads,
        expected_exit_code=CHECK_UNRESOLVED,
        staging_prefix=".targeted-odii-review-",
    )


def _collect_targeted_odii_artifacts(
    source: _TargetedSourceSnapshot,
    output: Path,
    *,
    output_parent_descriptor: int,
    odii_key: str,
    diagnostics: ProviderDiagnostics,
    policy: RequestPolicy,
) -> int:
    with OdiiClient(service_key=odii_key, policy=policy) as odii:
        theme = _provider_request(
            odii,
            "themeSearchList",
            {"keyword": _TARGETED_KEYWORD},
            diagnostics=diagnostics,
            candidate_place_id=_TARGETED_CANDIDATE_ID,
            candidate_name=_TARGETED_CANDIDATE_NAME,
            provider=_TARGETED_PROVIDER,
        )
        tid, tlid = _targeted_theme_pairs(theme.payload)[0]
        story = _provider_request(
            odii,
            "storyBasedList",
            {"tid": tid, "tlid": tlid},
            diagnostics=diagnostics,
            candidate_place_id=_TARGETED_CANDIDATE_ID,
            candidate_name=_TARGETED_CANDIDATE_NAME,
            provider=_TARGETED_PROVIDER,
        )
        if not _targeted_story_matches(story.payload, tid=tid, tlid=tlid):
            raise CollectionError("targeted Odii story evidence does not bind the selected pair")

    pair = f"{tid}/{tlid}"
    bundle_payload = deepcopy(source.bundle_payload)
    rows = bundle_payload.get("rows")
    if not isinstance(rows, list):
        raise CollectionError("validated targeted source bundle lost its row list")
    rows.extend(
        (
            _bundle_row(
                theme,
                candidate_place_id=_TARGETED_CANDIDATE_ID,
                source_id=pair,
            ),
            _bundle_row(
                story,
                candidate_place_id=_TARGETED_CANDIDATE_ID,
                source_id=pair,
            ),
        )
    )
    RawProviderBundle.model_validate(bundle_payload)
    review_payload = deepcopy(source.review_payload)
    candidates = review_payload.get("candidates")
    if (
        not isinstance(candidates, list)
        or len(candidates) != 6
        or not isinstance(candidates[4], dict)
    ):
        raise CollectionError("validated targeted source review lost its candidate list")
    target = candidates[4]
    evidence = target.get("evidence")
    if not isinstance(evidence, list) or len(evidence) != 2:
        raise CollectionError("validated targeted candidate lost its evidence list")
    target["resolution_status"] = "UNRESOLVED"
    evidence[1] = _evidence(story, source_id=None)
    CandidateReview.model_validate(review_payload)
    _publish_targeted_review(
        output,
        output_parent_descriptor=output_parent_descriptor,
        review_payload=review_payload,
        bundle_payload=bundle_payload,
        odii_key=odii_key,
    )
    return _finish_published_collection(
        diagnostics,
        committed_exit_code=CHECK_UNRESOLVED,
    )


def _collect_targeted_odii(
    source_manifest: Path,
    output: Path,
    *,
    diagnostics_dir: Path | None,
    policy: RequestPolicy,
) -> int:
    output_parent_descriptor = _open_directory_fd_nofollow(output.parent)
    diagnostics: ProviderDiagnostics | None = None
    try:
        if not _is_safe_relative_name(output.name):
            raise CollectionError("targeted review output name is unsafe")
        try:
            os.stat(output.name, dir_fd=output_parent_descriptor, follow_symlinks=False)
        except FileNotFoundError:
            pass
        except OSError:
            raise CollectionError(
                "targeted review output safety could not be established"
            ) from None
        else:
            raise CollectionError("targeted review output already exists")
        source = _preflight_targeted_source(source_manifest)
        resolved_diagnostics_dir = (
            diagnostics_dir
            if diagnostics_dir is not None
            else _repository_root() / _DEFAULT_DIAGNOSTICS_PATH
        )
        if _path_has_symlinked_component(resolved_diagnostics_dir):
            raise CollectionError("targeted diagnostics path must not traverse symlinks")
        _validate_diagnostics_location(output, resolved_diagnostics_dir)
        _validate_diagnostics_location(source_manifest.parent, output)
        _validate_diagnostics_location(source_manifest.parent, resolved_diagnostics_dir)
        require_live_collection_allowed(explicit_opt_in=True)
        ProviderDiagnostics.ensure_directory(resolved_diagnostics_dir)
        _validate_diagnostics_location(output, resolved_diagnostics_dir)
        diagnostics = ProviderDiagnostics.create(resolved_diagnostics_dir)
        credentials_bound = False
        try:
            try:
                odii_key = _load_targeted_odii_credential()
            except (CollectionError, OSError, ValueError, UnicodeError):
                diagnostics.terminal_credential_failure()
                raise
            diagnostics.bind_credentials(odii_key)
            credentials_bound = True
            diagnostics.run_started()
            return _collect_targeted_odii_artifacts(
                source,
                output,
                output_parent_descriptor=output_parent_descriptor,
                odii_key=odii_key,
                diagnostics=diagnostics,
                policy=policy,
            )
        except ProviderDiagnosticsError:
            raise
        except (CollectionError, OSError, ValueError, ValidationError) as exc:
            if credentials_bound:
                if isinstance(exc, CollectionError):
                    diagnostics.terminal_failure(
                        outcome=exc.outcome,
                        category=exc.category,
                        http_status=exc.http_status,
                        exception_class=exc.exception_class,
                    )
                else:
                    diagnostics.terminal_failure(
                        outcome="collection_failed",
                        category="filesystem" if isinstance(exc, OSError) else "collection",
                        exception_class=type(exc).__name__,
                    )
            raise
    finally:
        _teardown_collection(
            diagnostics,
            output_parent_descriptor=output_parent_descriptor,
        )


def _collect_live(
    output: Path,
    *,
    selections: tuple[_CandidateSelection, ...] | None,
    diagnostics_dir: Path | None,
    policy: RequestPolicy,
) -> int:
    require_live_collection_allowed(explicit_opt_in=True)
    if os.path.lexists(output):
        print("output already exists; live review artifacts are append-only", file=sys.stderr)
        return CHECK_MALFORMED
    output.parent.mkdir(parents=True, exist_ok=True)
    resolved_diagnostics_dir = (
        diagnostics_dir
        if diagnostics_dir is not None
        else _repository_root() / _DEFAULT_DIAGNOSTICS_PATH
    )
    _validate_diagnostics_location(output, resolved_diagnostics_dir)
    ProviderDiagnostics.ensure_directory(resolved_diagnostics_dir)
    _validate_diagnostics_location(output, resolved_diagnostics_dir)
    output_parent_descriptor = _open_directory_fd_nofollow(output.parent)
    diagnostics: ProviderDiagnostics | None = None
    try:
        diagnostics = ProviderDiagnostics.create(resolved_diagnostics_dir)
        credentials_bound = False
        try:
            tour_key, odii_key = _load_live_credentials()
            diagnostics.bind_credentials(tour_key, odii_key)
            credentials_bound = True
            diagnostics.run_started()
            return _collect_live_artifacts(
                output,
                output_parent_descriptor=output_parent_descriptor,
                selections=selections,
                tour_key=tour_key,
                odii_key=odii_key,
                diagnostics=diagnostics,
                policy=policy,
            )
        except ProviderDiagnosticsError:
            raise
        except (CollectionError, OSError, ValueError, ValidationError) as exc:
            if credentials_bound:
                if isinstance(exc, CollectionError):
                    diagnostics.terminal_failure(
                        outcome=exc.outcome,
                        category=exc.category,
                        http_status=exc.http_status,
                        exception_class=exc.exception_class,
                    )
                else:
                    diagnostics.terminal_failure(
                        outcome="collection_failed",
                        category="filesystem" if isinstance(exc, OSError) else "collection",
                        exception_class=type(exc).__name__,
                    )
            raise
    finally:
        _teardown_collection(
            diagnostics,
            output_parent_descriptor=output_parent_descriptor,
        )


def main(argv: list[str] | None = None) -> int:
    try:
        args = _parser().parse_args(argv)
    except _MalformedCliArguments:
        return CHECK_MALFORMED
    if args.check_review is not None:
        if args.output is not None:
            print("--output is not valid with --check-review", file=sys.stderr)
            return CHECK_MALFORMED
        if args.candidate_selection is not None:
            print("--candidate-selection is not valid with --check-review", file=sys.stderr)
            return CHECK_MALFORMED
        if (
            args.diagnostics_dir is not None
            or args.candidate_id is not None
            or args.provider is not None
            or args.keyword is not None
        ):
            print("--diagnostics-dir is valid only with --live", file=sys.stderr)
            return CHECK_MALFORMED
        if args.request_timeout_seconds is not None:
            print("--request-timeout-seconds is valid only with --live", file=sys.stderr)
            return CHECK_MALFORMED
        result = check_review_manifest(
            args.check_review,
            source_lock_path=args.source_lock,
        )
        return result.exit_code
    if args.source_lock is not None:
        print("--source-lock is valid only with --check-review", file=sys.stderr)
        return CHECK_MALFORMED
    if args.output is None:
        print("collection requires --output", file=sys.stderr)
        return CHECK_MALFORMED
    try:
        policy = (
            RequestPolicy()
            if args.request_timeout_seconds is None
            else RequestPolicy(timeout_seconds=args.request_timeout_seconds)
        )
        if args.targeted_odii_review_enrichment is not None:
            if (
                args.candidate_selection is not None
                or args.candidate_id != _TARGETED_CANDIDATE_ID
                or args.provider != _TARGETED_PROVIDER
                or args.keyword != _TARGETED_KEYWORD
            ):
                raise ValueError("targeted Odii review enrichment arguments are invalid")
            return _collect_targeted_odii(
                args.targeted_odii_review_enrichment,
                args.output,
                diagnostics_dir=args.diagnostics_dir,
                policy=policy,
            )
        if args.candidate_id is not None or args.provider is not None or args.keyword is not None:
            raise ValueError("targeted arguments require targeted Odii review enrichment")
        selections = _parse_candidate_selections(args.candidate_selection)
        return _collect_live(
            args.output,
            selections=selections,
            diagnostics_dir=args.diagnostics_dir,
            policy=policy,
        )
    except LiveCollectionRefused as exc:
        return exc.exit_code
    except (
        CollectionError,
        OSError,
        ProviderDiagnosticsError,
        ValueError,
        ValidationError,
    ):
        print("live review collection refused", file=sys.stderr)
        return CHECK_MALFORMED


if __name__ == "__main__":
    raise SystemExit(main())


__all__ = [
    "CHECK_MALFORMED",
    "CHECK_RESOLVED",
    "CHECK_UNRESOLVED",
    "main",
]
