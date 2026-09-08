from __future__ import annotations

import hashlib
import importlib
import os
import socket
from copy import deepcopy
from pathlib import Path

import pytest

from itda.domain.canonical import canonical_json_bytes, canonical_sha256

REPO_ROOT = Path(__file__).resolve().parents[3]
PHASE_DIR = REPO_ROOT / ".planning/phases/02-canonical-36-rights-and-evaluation-manifest"
COMPLETED_PLAN55_SUMMARY_REL = Path(
    ".planning/phases/02-canonical-36-rights-and-evaluation-manifest/02-55-SUMMARY.md"
)
OPTIONAL_MEDIA_TERMINAL = (
    REPO_ROOT / "artifacts/catalog/optional-media-v2/closure-plan/closure-terminal.json"
)
EXPECTED_LINEAGE_HASHES = {
    "02-49-TERMINAL-HISTORY.md": "20490fa01d86f3653dc29fe9832fdd1da5e0d47af6861c595b2492b64054a058",
    "02-49-FAILURE-RECORD.md": "aa8ee6835bc4fa311186bd7d079b6c31c68fbb8996b6cddaa9db4fa31507020c",
    "02-53-PLAN.md": "17ed9757ce348b376183c43e53ca9f047892cfce1e56009d407e76e3a91dd060",
    "02-53-SUMMARY.md": "4a254bb5804465338967976ff47919b7790d08838d4eccfd8f441ae66134498f",
}


def _api() -> object:
    return importlib.import_module("itda.cli.build_catalog_contest_profile")


@pytest.fixture(autouse=True)
def _historical_plan55_pending_summary(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    cli = _api()
    assert cli.SUMMARY_REL == COMPLETED_PLAN55_SUMMARY_REL
    assert (REPO_ROOT / COMPLETED_PLAN55_SUMMARY_REL).is_file()
    monkeypatch.setattr(cli, "SUMMARY_REL", tmp_path / "02-55-SUMMARY.pending.md")


def test_captured_replay_never_constructs_network_or_dns(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    cli = _api()

    def denied(*args: object, **kwargs: object) -> object:
        raise AssertionError("captured contest replay attempted external network capability")

    monkeypatch.setattr(socket, "socket", denied)
    monkeypatch.setattr(socket, "getaddrinfo", denied)
    result = cli.replay_contest_profile(REPO_ROOT)

    handoff = result.payloads["plan54-handoff.json"]
    assert handoff["provider_traffic_allowed"] is False
    assert handoff["authority_required"] is False
    assert handoff["credential_required"] is False
    assert handoff["provider_attempt_inventory"] == []


def test_mode_security_requires_exact_external_network_deny_policy() -> None:
    cli = _api()
    expected = hashlib.sha256(b"(version 1)(allow default)(deny network*)").hexdigest()
    roots = cli.mode_security_roots(expected)

    assert set(roots) == {
        "execution_mode",
        "network_denial_policy_sha256",
        "null_authority_state_sha256",
        "null_credential_state_sha256",
        "provider_attempt_inventory_sha256",
    }
    assert roots["provider_attempt_inventory_sha256"] == canonical_sha256([])
    with pytest.raises(ValueError, match="network-denial"):
        cli.require_external_network_denial(None)
    with pytest.raises(ValueError, match="network-denial"):
        cli.require_external_network_denial("0" * 64)


def test_nofollow_loader_rejects_symlink_hardlink_noncanonical_and_oversized(
    tmp_path: Path,
) -> None:
    cli = _api()
    canonical = tmp_path / "canonical.json"
    canonical.write_bytes(canonical_json_bytes({"a": 1}))
    os.chmod(canonical, 0o600)
    assert cli.load_canonical_json_nofollow(canonical, max_bytes=32) == {"a": 1}

    symlink = tmp_path / "symlink.json"
    symlink.symlink_to(canonical)
    with pytest.raises(ValueError, match="regular|no-follow"):
        cli.load_canonical_json_nofollow(symlink, max_bytes=32)

    hardlink = tmp_path / "hardlink.json"
    os.link(canonical, hardlink)
    with pytest.raises(ValueError, match="link count"):
        cli.load_canonical_json_nofollow(hardlink, max_bytes=32)

    noncanonical = tmp_path / "noncanonical.json"
    noncanonical.write_text('{"a": 1}\n', encoding="utf-8")
    with pytest.raises(ValueError, match="canonical"):
        cli.load_canonical_json_nofollow(noncanonical, max_bytes=32)

    oversized = tmp_path / "oversized.json"
    oversized.write_bytes(canonical_json_bytes({"a": "x" * 100}))
    with pytest.raises(ValueError, match="size"):
        cli.load_canonical_json_nofollow(oversized, max_bytes=32)


def test_all_direct_plan49_plan53_leaves_and_absence_are_bound() -> None:
    cli = _api()
    snapshot = cli.verify_historical_lineage(REPO_ROOT)

    for name, digest in EXPECTED_LINEAGE_HASHES.items():
        assert snapshot[name]["file_sha256"] == digest
    assert snapshot["02-49-SUMMARY.md"]["disposition"] == "ABSENT_REQUIRED"
    assert snapshot["reentry-exhausted.json"]["file_sha256"] == (
        "882dfa9bb31e0f3c9eeafbc5cfede28e37659c222e5b531d647cce2307d39cab"
    )
    assert snapshot["closure-terminal.json"]["file_sha256"] == (
        "67bfd8507a690af3840d821f2920c521fdccd12fa771277ef74097fda2e827c9"
    )


def test_each_historical_boundary_drift_exits_uncertain_without_publication(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    cli = _api()
    original = cli.PLAN49_HISTORY_SHA256
    monkeypatch.setattr(cli, "PLAN49_HISTORY_SHA256", "0" * 64)
    with pytest.raises(cli.ContestProfileUncertainError, match="historical"):
        cli.replay_contest_profile(REPO_ROOT)
    assert not (tmp_path / "generations").exists()
    monkeypatch.setattr(cli, "PLAN49_HISTORY_SHA256", original)


def test_optional_media_terminal_and_plan49_53_bytes_never_change(tmp_path: Path) -> None:
    cli = _api()
    protected = {
        path: path.read_bytes()
        for path in (
            OPTIONAL_MEDIA_TERMINAL,
            PHASE_DIR / "02-49-TERMINAL-HISTORY.md",
            PHASE_DIR / "02-49-FAILURE-RECORD.md",
                PHASE_DIR / "02-53-PLAN.md",
                PHASE_DIR / "02-53-SUMMARY.md",
                PHASE_DIR / "02-55-SUMMARY.md",
        )
    }
    result = cli.replay_contest_profile(REPO_ROOT)
    cli.publish_contest_generation(
        result,
        output_base=tmp_path / "contest" / "generations",
        repository_root=REPO_ROOT,
    )

    assert all(path.read_bytes() == payload for path, payload in protected.items())
    assert not (PHASE_DIR / "02-49-SUMMARY.md").exists()


@pytest.mark.parametrize(
    "mutation",
    ("manifest", "inventory", "mode", "bytes", "extra", "renamed"),
)
def test_existing_generation_mismatch_is_collision_exit_28(
    tmp_path: Path,
    mutation: str,
) -> None:
    cli = _api()
    result = cli.replay_contest_profile(REPO_ROOT)
    base = tmp_path / "contest" / "generations"
    cli.publish_contest_generation(result, output_base=base, repository_root=REPO_ROOT)
    root = base / result.generation_sha256

    if mutation == "manifest":
        (root / "generation-manifest.json").write_bytes(canonical_json_bytes({"tampered": True}))
    elif mutation == "inventory":
        (root / "policy.json").unlink()
    elif mutation == "mode":
        os.chmod(root / "policy.json", 0o644)
    elif mutation == "bytes":
        (root / "policy.json").write_bytes(canonical_json_bytes({"tampered": True}))
    elif mutation == "extra":
        (root / "extra.json").write_bytes(canonical_json_bytes({}))
    else:
        root.rename(base / ("0" * 64))
        root = base / ("0" * 64)

    before = {path.name: path.read_bytes() for path in root.iterdir()}
    with pytest.raises(cli.ContestProfileCollisionError):
        if mutation == "renamed":
            cli.verify_contest_generation(root, repository_root=REPO_ROOT)
        else:
            cli.publish_contest_generation(result, output_base=base, repository_root=REPO_ROOT)
    assert {path.name: path.read_bytes() for path in root.iterdir()} == before


def test_terminal_never_claims_success_or_side_effects() -> None:
    cli = _api()
    result = cli.build_terminal_generation(
        code="FORBIDDEN_CAPABILITY_REQUESTED",
        reasons=({"reason_code": "FORBIDDEN_ARGUMENT", "evidence_root_sha256": "b" * 64},),
        repository_root=REPO_ROOT,
    )
    terminal = result.payloads["terminal.json"]

    assert terminal["exit_code"] == 27
    assert terminal["plan54_reachable"] is False
    for field in (
        "handoff_created",
        "summary_created",
        "review_created",
        "provider_traffic_observed",
        "credential_accessed",
        "authority_accessed",
        "split_created",
        "schema_mutated",
        "catalog_activated",
        "seal_created",
    ):
        assert terminal[field] is False


def test_receipt_rejects_extra_alias_secret_and_cross_root_fields(tmp_path: Path) -> None:
    cli = _api()
    result = cli.replay_contest_profile(REPO_ROOT)
    base = tmp_path / "contest" / "generations"
    check = cli.receipt_for_result(result, repository_root=REPO_ROOT, disposition="CHECK_ONLY")
    publish = cli.publish_contest_generation(result, output_base=base, repository_root=REPO_ROOT)
    verify = cli.verify_contest_generation(
        base / result.generation_sha256, repository_root=REPO_ROOT
    )

    for key in ("credential", "authority", "token", "generation_root"):
        hostile = deepcopy(check)
        hostile[key] = "secret-or-alias"
        with pytest.raises(ValueError, match="receipt"):
            cli.verify_receipt_triplet(hostile, publish, verify, repository_root=REPO_ROOT)


def test_confidence_or_popularity_cannot_change_preview_selection() -> None:
    cli = _api()
    result = cli.replay_contest_profile(REPO_ROOT)
    frontier = result.payloads["selection-frontier.json"]
    rows = deepcopy(frontier["eligible_pool"])
    baseline = cli.select_noncanonical_preview(rows, frontier["final_quotas"])
    for index, row in enumerate(rows):
        row["confidence_band"] = "HIGH" if index % 2 else "LOW"
        row["popularity"] = 10_000 - index
        row["provider_prominence"] = index
    assert cli.select_noncanonical_preview(rows, frontier["final_quotas"]) == baseline
