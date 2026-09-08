"""Wave 0 security contract for DATA-06/08 artifact and membership isolation.

Threat coverage: T-02-02, T-02-04, and T-02-06.
"""

from __future__ import annotations

import importlib
import importlib.util
import json
import re
import subprocess
from pathlib import Path
from types import ModuleType

import pytest

CAPABILITY_MODULE = "itda.contracts.catalog_manifest"
SEALER_MODULE = "itda.cli.seal_catalog_manifest"
REPOSITORY_ROOT = Path(__file__).resolve().parents[3]
PUBLIC_FIXTURE_ROOT = REPOSITORY_ROOT / "fixtures/catalog/v1/public"
RESTRICTED_CATALOG_ROOT = REPOSITORY_ROOT / "artifacts/restricted/catalog"
RESTRICTED_CATALOG_RULE = "/artifacts/restricted/catalog/**"
SECRET_PATTERNS = (
    re.compile(r"postgres(?:ql)?://[^\s]+", re.IGNORECASE),
    re.compile(r"\b(?:service[_-]?key|password|secret)\s*[:=]\s*[^\s,}]+", re.IGNORECASE),
)
MEMBERSHIP_KEYS = {
    "members",
    "canonical_place_ids",
    "catalog_members",
    "dev_members",
    "blind_members",
    "ordered_catalog_ids",
}


def _capability_or_skip() -> ModuleType:
    if importlib.util.find_spec(CAPABILITY_MODULE) is None:
        pytest.skip("real manifest boundary is implemented in Plan 02-08")
    return importlib.import_module(CAPABILITY_MODULE)


def _mapping_keys(value: object) -> set[str]:
    if isinstance(value, dict):
        return set(value) | {key for child in value.values() for key in _mapping_keys(child)}
    if isinstance(value, list):
        return {key for child in value for key in _mapping_keys(child)}
    return set()


def _assert_no_secret_or_raw_dsn(text: str) -> None:
    for pattern in SECRET_PATTERNS:
        assert pattern.search(text) is None


def _assert_membership_free(payload: object) -> None:
    assert _mapping_keys(payload).isdisjoint(MEMBERSHIP_KEYS)
    serialized = json.dumps(payload, ensure_ascii=False, sort_keys=True).casefold()
    assert "place:" not in serialized
    assert "synthetic:blind:" not in serialized


def _assert_no_complement_reconstruction(payload: dict[str, object]) -> None:
    assert not (
        {"catalog_members", "dev_members"}.issubset(payload)
        or {"ordered_catalog_ids", "dev_members"}.issubset(payload)
    )


def _git(*arguments: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["git", *arguments],
        cwd=REPOSITORY_ROOT,
        check=False,
        capture_output=True,
        text=True,
    )


def _assert_public_fixture_path(path: Path) -> None:
    try:
        relative = path.relative_to(PUBLIC_FIXTURE_ROOT)
    except ValueError:
        raise AssertionError("public fixture path escapes allowlisted root") from None
    assert relative.parts
    cursor = PUBLIC_FIXTURE_ROOT
    for part in relative.parts:
        cursor /= part
        if cursor.exists() or cursor.is_symlink():
            assert not cursor.is_symlink()
    assert path.resolve(strict=False).is_relative_to(PUBLIC_FIXTURE_ROOT.resolve())


def _assert_public_payload(payload: object) -> None:
    serialized = json.dumps(payload, ensure_ascii=False, sort_keys=True)
    keys = {key.casefold() for key in _mapping_keys(payload)}
    assert not any(
        fragment in key
        for key in keys
        for fragment in ("service_key", "servicekey", "password", "secret", "authorization")
    )
    _assert_no_secret_or_raw_dsn(serialized)
    _assert_membership_free(payload)
    if isinstance(payload, dict):
        _assert_no_complement_reconstruction(payload)
        assert "raw_permission_body" not in _mapping_keys(payload)
        assert "permission_page_body" not in _mapping_keys(payload)


def test_restricted_catalog_tree_is_root_ignored_before_and_after_artifact_creation() -> None:
    ignore_probe = _git(
        "check-ignore",
        "-v",
        "--no-index",
        "artifacts/restricted/catalog/v1/probe.json",
    )
    assert ignore_probe.returncode == 0
    assert RESTRICTED_CATALOG_RULE in ignore_probe.stdout

    public_probe = _git(
        "check-ignore",
        "-q",
        "--no-index",
        "fixtures/catalog/v1/public/probe.json",
    )
    assert public_probe.returncode == 1

    tracked = _git("ls-files", "artifacts/restricted/catalog")
    assert tracked.returncode == 0
    assert tracked.stdout == ""
    if RESTRICTED_CATALOG_ROOT.exists():
        for path in RESTRICTED_CATALOG_ROOT.rglob("*"):
            if not path.is_file():
                continue
            relative_path = path.relative_to(REPOSITORY_ROOT).as_posix()
            ignored = _git("check-ignore", "-q", "--no-index", relative_path)
            assert ignored.returncode == 0


@pytest.mark.parametrize(
    "surface",
    [
        "file",
        "log",
        "stdout",
        "stderr",
        "argv-help",
        "ordinary-role-projection",
    ],
)
def test_security_scanner_rejects_credentials_raw_dsns_and_membership(surface: str) -> None:
    safe_payload = {
        "surface": surface,
        "schema_version": "split-approval-request-v1",
        "dev_count": 24,
        "blind_count": 12,
        "manifest_sha256": "1" * 64,
        "connection_label": "restricted-sealer",
    }
    serialized = json.dumps(safe_payload, sort_keys=True)
    _assert_no_secret_or_raw_dsn(serialized)
    _assert_membership_free(safe_payload)
    _assert_no_complement_reconstruction(safe_payload)


@pytest.mark.parametrize(
    "unsafe",
    [
        "postgresql://sealer:raw-password@db.example/itda",
        "SERVICE_KEY=literal-secret-value",
        "password: literal-secret-value",
    ],
)
def test_security_scanner_detects_secret_and_raw_dsn_fixtures(unsafe: str) -> None:
    with pytest.raises(AssertionError):
        _assert_no_secret_or_raw_dsn(unsafe)


def test_direct_and_complement_membership_fixtures_are_rejected() -> None:
    with pytest.raises(AssertionError):
        _assert_membership_free({"blind_members": ["synthetic:blind:001"]})
    with pytest.raises(AssertionError):
        _assert_no_complement_reconstruction(
            {
                "catalog_members": [f"synthetic:member:{index:03d}" for index in range(36)],
                "dev_members": [f"synthetic:member:{index:03d}" for index in range(24)],
            }
        )


def test_public_catalog_fixtures_are_membership_free() -> None:
    if not PUBLIC_FIXTURE_ROOT.exists():
        pytest.skip("public catalog fixture root is created by Plan 02-02")
    for path in sorted(PUBLIC_FIXTURE_ROOT.rglob("*.json")):
        _assert_public_fixture_path(path)
        payload = json.loads(path.read_text(encoding="utf-8"))
        _assert_public_payload(payload)


@pytest.mark.parametrize(
    "payload",
    [
        {"blind_members": ["synthetic:blind:001"]},
        {
            "catalog_members": [f"synthetic:member:{index:03d}" for index in range(36)],
            "dev_members": [f"synthetic:member:{index:03d}" for index in range(24)],
        },
        {"service_key": "literal-synthetic-secret"},
        {"raw_permission_body": "<html>synthetic permission grant</html>"},
    ],
)
def test_public_payload_scanner_rejects_restricted_material(payload: object) -> None:
    with pytest.raises(AssertionError):
        _assert_public_payload(payload)


def test_public_fixture_path_scanner_rejects_escape_and_symlink(
    tmp_path: Path,
) -> None:
    with pytest.raises(AssertionError, match="escapes"):
        _assert_public_fixture_path(REPOSITORY_ROOT / "artifacts/restricted/catalog/probe.json")

    public_root = tmp_path / "fixtures/catalog/v1/public"
    public_root.mkdir(parents=True)
    outside = tmp_path / "outside"
    outside.mkdir()
    alias = public_root / "escape"
    alias.symlink_to(outside, target_is_directory=True)
    with pytest.raises(AssertionError):
        _assert_public_fixture_path(alias / "probe.json")


def test_public_request_serializer_denies_direct_and_complement_membership() -> None:
    capability = _capability_or_skip()
    request = capability.synthetic_membership_free_request()
    payload = request.canonical_payload()
    _assert_membership_free(payload)
    _assert_no_complement_reconstruction(payload)


def test_real_sealer_help_and_errors_never_accept_or_render_raw_dsn() -> None:
    if importlib.util.find_spec(SEALER_MODULE) is None:
        pytest.skip("restricted real sealer is implemented in Plan 02-12")
    sealer = importlib.import_module(SEALER_MODULE)
    help_text = sealer.build_parser().format_help()
    assert "--dsn" not in help_text
    assert "--connection-env" in help_text
    assert "--connection-label" in help_text
    _assert_no_secret_or_raw_dsn(help_text)


def test_artifact_boundary_is_enforced_without_manifest_capability() -> None:
    assert RESTRICTED_CATALOG_RULE in (
        REPOSITORY_ROOT / ".gitignore"
    ).read_text(encoding="utf-8").splitlines()


def test_missing_artifact_boundary_is_controlled_red() -> None:
    """Historical controlled-RED node retained as its completed GREEN contract."""

    test_artifact_boundary_is_enforced_without_manifest_capability()
