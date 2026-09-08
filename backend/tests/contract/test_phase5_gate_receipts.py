"""Public contract for Phase 5 clean/private gate receipts and final sign-off."""

from __future__ import annotations

import hashlib
import json
import subprocess
from pathlib import Path

import pytest

SHA = "a" * 64
RELEASE_SHA = "59c3a6379e1e3de6ef67d95947d80f39d97c21bdcbf368d0080e5d8aa7224c50"
MEMBERSHIP_SHA = "979127c3cfd457fa0a9354acf7fd984c8d8b4d753a97c7c176ac531e0808af7a"
VERIFICATION_SHA = "d" * 64
CONFIG_SHA = "c" * 64
KERNEL_SHA = "e" * 64


def _eligible_release_verification() -> dict[str, object]:
    return {
        "state": "ACTIVE",
        "analysis_origin": "DEMO_MODEL_DERIVED",
        "member_count": 24,
        "profile_count": 24,
        "eligible_count": 24,
        "nondegenerate": True,
        "release_sha256": RELEASE_SHA,
        "membership_sha256": MEMBERSHIP_SHA,
        "config_sha256": CONFIG_SHA,
        "kernel_sha256": KERNEL_SHA,
    }


def _write_json(path: Path, value: object) -> None:
    path.write_text(
        json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")) + "\n",
        encoding="utf-8",
    )


def _sealed_receipt(value: dict[str, object]) -> dict[str, object]:
    encoded = json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return {**value, "receipt_sha256": hashlib.sha256(encoded).hexdigest()}


def _valid_signoff_bundle(tmp_path: Path) -> dict[str, object]:
    validation = tmp_path / "05-VALIDATION.md"
    clean_path = tmp_path / "clean.json"
    private_path = tmp_path / "private.json"
    review_path = tmp_path / "review.json"
    clean = _sealed_receipt(
        {
            "schema_version": "itda.phase5-clean-gate-receipt.v2",
            "gate": "clean",
            "state": "GREEN",
            "checkout_sha256": SHA,
            "command_set_sha256": SHA,
            "suite_ids": ["phase5-gate-receipts", "phase5-clean-browser"],
            "child_exit_statuses": {
                "backend": 0,
                "generated_contract": 0,
                "components": 0,
                "clean_browser": 0,
            },
            "started_at": "2026-08-11T00:00:00Z",
            "completed_at": "2026-08-11T00:01:00Z",
            "duration_ms": 60_000,
            "validation_task_ids": ["05-11-01", "05-11-02"],
            "active_release_sha256": RELEASE_SHA,
            "active_membership_sha256": MEMBERSHIP_SHA,
            "active_release_verification_sha256": VERIFICATION_SHA,
            "analysis_origin": "DEMO_MODEL_DERIVED",
            "member_count": 24,
            "eligible_count": 24,
            "config_sha256": CONFIG_SHA,
            "kernel_sha256": KERNEL_SHA,
        }
    )
    private = _sealed_receipt(
        {
            "schema_version": "itda.phase5-private-gate-receipt.v2",
            "gate": "private",
            "state": "GREEN",
            "checkout_sha256": SHA,
            "command_set_sha256": SHA,
            "suite_ids": ["phase5-active-release", "phase5-private-real-e2e"],
            "child_exit_statuses": {"active_release": 0, "private_browser": 0},
            "started_at": "2026-08-11T00:01:00Z",
            "completed_at": "2026-08-11T00:02:00Z",
            "duration_ms": 60_000,
            "validation_task_ids": ["05-11-01", "05-11-02"],
            "active_release_sha256": RELEASE_SHA,
            "active_membership_sha256": MEMBERSHIP_SHA,
            "active_release_verification_sha256": VERIFICATION_SHA,
            "private_e2e_scenario_id": "phase5-private-real-demo-complete-journey-v1",
            "analysis_origin": "DEMO_MODEL_DERIVED",
            "member_count": 24,
            "eligible_count": 24,
            "config_sha256": CONFIG_SHA,
            "kernel_sha256": KERNEL_SHA,
        }
    )
    _write_json(clean_path, clean)
    _write_json(private_path, private)
    _write_json(
        review_path,
        {
            "schema_version": "itda.phase5-korean-explanation-review.v1",
            "status": "DEFERRED_NON_BLOCKING_EXTERNAL_QUALITY_EVIDENCE",
            "reviewer_pseudonym": "phase5-operator",
            "reviewed_at": "2026-08-11T00:02:00Z",
            "active_release_sha256": RELEASE_SHA,
            "reason": "Bounded human usefulness review is not available in this execution.",
        },
    )
    validation.write_text(
        f"| 05-11-01 | Task 1 | ✅ green | clean-gate-receipt "
        f"{clean['receipt_sha256']} |\n"
        f"| 05-11-02 | Task 2 | ✅ green | private-evidence-receipt "
        f"{private['receipt_sha256']} |\n",
        encoding="utf-8",
    )
    return {
        "validation_path": validation,
        "clean_receipt_path": clean_path,
        "private_receipt_path": private_path,
        "explanation_review_path": review_path,
        "expected_checkout_sha256": SHA,
        "expected_clean_command_set_sha256": SHA,
        "expected_private_command_set_sha256": SHA,
        "expected_clean_suite_ids": ("phase5-gate-receipts", "phase5-clean-browser"),
        "expected_private_suite_ids": ("phase5-active-release", "phase5-private-real-e2e"),
        "allow_deferred_nonblocking_review": True,
    }


def test_valid_current_receipt_pair_reaches_green_signoff(tmp_path: Path) -> None:
    """A caller can verify one current clean/private GREEN pair end to end."""

    from itda.cli.verify_phase5_gate_receipts import signoff_gate_receipts

    report = signoff_gate_receipts(**_valid_signoff_bundle(tmp_path))  # type: ignore[arg-type]

    assert report == {
        "state": "GREEN",
        "clean_gate": "GREEN",
        "private_gate": "GREEN",
        "active_release_sha256": RELEASE_SHA,
        "active_membership_sha256": MEMBERSHIP_SHA,
        "active_release_verification_sha256": VERIFICATION_SHA,
        "member_count": 24,
        "analysis_origin": "DEMO_MODEL_DERIVED",
        "explanation_review_status": "DEFERRED_NON_BLOCKING_EXTERNAL_QUALITY_EVIDENCE",
        "config_sha256": CONFIG_SHA,
        "kernel_sha256": KERNEL_SHA,
        "eligible_count": 24,
    }


def test_explanation_review_cannot_carry_score_or_gate_mutation_authority() -> None:
    """Subjective review metadata cannot alter software or scoring authority."""

    from itda.cli.verify_phase5_gate_receipts import (
        Phase5GateReceiptError,
        validate_explanation_review,
    )

    review = {
        "schema_version": "itda.phase5-korean-explanation-review.v1",
        "status": "COMPLETE_NON_BLOCKING_EXTERNAL_QUALITY_EVIDENCE",
        "reviewer_pseudonym": "phase5-operator",
        "reviewed_at": "2026-08-11T00:02:00Z",
        "active_release_sha256": RELEASE_SHA,
        "profiles": [],
        "score_overrides": {"canonical-place-01": 100},
    }

    with pytest.raises(Phase5GateReceiptError, match="EXPLANATION_REVIEW_MUTATION_FORBIDDEN"):
        validate_explanation_review(review, allow_deferred_nonblocking_review=True)


def test_clean_receipt_emission_is_canonical_and_self_bound(tmp_path: Path) -> None:
    """The clean gate publishes one canonical receipt only after zero exits."""

    from itda.cli.verify_phase5_gate_receipts import (
        CLEAN_COMMAND_SET_SHA256,
        CLEAN_SUITE_IDS,
        emit_clean_gate_receipt,
    )

    output = tmp_path / "clean-gate-receipt.json"
    receipt = emit_clean_gate_receipt(
        output_path=output,
        checkout_sha256=SHA,
        started_at="2026-08-11T00:00:00Z",
        completed_at="2026-08-11T00:01:00Z",
        duration_ms=60_000,
        child_exit_statuses={
            "backend": 0,
            "generated_contract": 0,
            "components": 0,
            "clean_browser": 0,
        },
        release_verification=_eligible_release_verification(),
    )

    encoded = output.read_bytes()
    assert (
        encoded
        == json.dumps(
            receipt,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
        + b"\n"
    )
    assert receipt["command_set_sha256"] == CLEAN_COMMAND_SET_SHA256
    assert receipt["suite_ids"] == list(CLEAN_SUITE_IDS)
    assert (
        receipt["receipt_sha256"]
        == hashlib.sha256(
            json.dumps(
                {key: value for key, value in receipt.items() if key != "receipt_sha256"},
                ensure_ascii=False,
                sort_keys=True,
                separators=(",", ":"),
            ).encode("utf-8")
        ).hexdigest()
    )


def test_private_receipt_binds_exact_active_dev24_release_and_real_scenario(
    tmp_path: Path,
) -> None:
    """Private GREEN binds the safe exact-24 release proof and one real E2E."""

    from itda.cli.verify_phase5_gate_receipts import emit_private_gate_receipt

    output = tmp_path / "private-evidence-receipt.json"
    receipt = emit_private_gate_receipt(
        output_path=output,
        checkout_sha256=SHA,
        started_at="2026-08-11T00:01:00Z",
        completed_at="2026-08-11T00:02:00Z",
        duration_ms=60_000,
        child_exit_statuses={"active_release": 0, "private_browser": 0},
        release_verification={
            **_eligible_release_verification(),
            "artifact_root": "artifacts/restricted/catalog/phase5-demo-profile-materialization",
        },
    )

    assert receipt["active_release_sha256"] == RELEASE_SHA
    assert receipt["active_membership_sha256"] == MEMBERSHIP_SHA
    assert receipt["member_count"] == 24
    assert receipt["analysis_origin"] == "DEMO_MODEL_DERIVED"
    assert receipt["private_e2e_scenario_id"] == "phase5-private-real-demo-complete-journey-v1"
    assert "artifact_root" not in receipt
    assert output.stat().st_mode & 0o777 == 0o600


def test_make_and_ci_keep_clean_private_ownership_disjoint() -> None:
    """Ordinary CI reaches ownership+clean only; private evidence stays opt-in."""

    repository_root = Path(__file__).resolve().parents[3]

    def dry_run(target: str) -> str:
        result = subprocess.run(
            ["make", "--no-print-directory", "-n", target],
            cwd=repository_root,
            check=False,
            capture_output=True,
            text=True,
        )
        assert result.returncode == 0, result.stderr
        return result.stdout

    ownership = dry_run("phase-05-check-ownership")
    clean = dry_run("phase-05-check")
    private = dry_run("phase-05-private-evidence-check")
    ci = (repository_root / ".github/workflows/ci.yml").read_text(encoding="utf-8")

    assert ownership.count("backend/tests/contract/test_phase5_gate_receipts.py") == 1
    assert "backend/tests/contract/test_phase5_gate_receipts.py" not in clean
    for path in (
        "backend/tests/contract/test_demo_profile_materialization.py",
        "backend/tests/contract/test_nvidia_minimax_profile.py",
        "backend/tests/security/test_phase5_provider_boundary.py",
        "backend/tests/security/test_phase5_release_authority.py",
        "backend/tests/integration/test_demo_scored_release.py",
        "backend/tests/integration/test_phase5_demo_source_collection.py",
        "backend/tests/unit/test_recommendation_kernel.py",
        "backend/tests/contract/test_recommendation_contract.py",
        "backend/tests/evals/phase5/test_recommendation_replay.py",
        "backend/tests/integration/test_recommendation_runs.py",
        "backend/tests/api/test_recommendations.py",
    ):
        assert clean.count(path) == 1
        assert path not in private
    for path in (
        "RecommendationResults.test.tsx",
        "RecommendationDetail.test.tsx",
        "RecommendationCompare.test.tsx",
        "RecommendationSavedPlace.test.tsx",
        "RecommendationRecovery.test.tsx",
        "storage.test.ts",
    ):
        assert clean.count(path) == 1
    assert "env -u NVIDIA_KEY -u ZHIPUAI_API_KEY -u BIGMODEL_API_KEY" in clean
    assert "ITDA_OFFLINE=1" in clean
    assert "--offline --no-sync --frozen --no-python-downloads" in clean
    assert "--grep-invert @real-demo" in clean
    assert "artifacts/restricted" not in clean
    assert "current-release" in private
    assert "--release-verification" in private
    assert "@private-real-demo" in private
    assert "env -u NVIDIA_KEY -u ZHIPUAI_API_KEY -u BIGMODEL_API_KEY" in private
    assert "make phase-05-check-ownership" in ci
    assert "make phase-05-check" in ci
    assert "--grep-invert @real-demo" in ci
    assert "phase-05-private-evidence-check" not in ci
    assert "artifacts/restricted" not in ci


def test_checkout_digest_uses_only_exact_phase5_server_source_scope(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """User-owned tracked/untracked artifacts cannot dirty or enter the source digest."""

    from itda.cli.verify_phase5_gate_receipts import (
        _checkout_digest,
        _is_phase5_server_source,
    )

    history_directories = (
        "legacy-canonical-pre-v17",
        *(f"review-rights-v{version}" for version in (*range(2, 8), *range(12, 16))),
    )
    history_files = (
        "candidate-review.json",
        "candidate-review.md",
        "raw-provider-bundle.redacted.json",
        "review-manifest.json",
    )
    unrelated_paths = {
        ".DS_Store",
        ".gsd/dispatch-isolation-sentinel.json",
        "backend/.DS_Store",
        *(
            f"fixtures/preview/review-history/preview-v1/{directory}/{name}"
            for directory in history_directories
            for name in history_files
        ),
    }
    assert len(unrelated_paths) == 47
    assert not any(_is_phase5_server_source(path) for path in unrelated_paths)

    tracked_unrelated = (
        "fixtures/preview/review-history/preview-v1/review-rights-v18/review-manifest.json"
    )
    outputs = {
        ("git", "diff", "--name-only"): tracked_unrelated + "\n",
        ("git", "diff", "--cached", "--name-only"): "",
        ("git", "ls-files", "--others", "--exclude-standard"): (
            "\n".join(sorted(unrelated_paths)) + "\n"
        ),
        ("git", "ls-files", "-s"): (
            f"100644 {'1' * 40} 0\tMakefile\n100644 {'2' * 40} 0\t{tracked_unrelated}\n"
        ),
    }

    def fake_run(
        args: tuple[str, ...], *, check: bool, capture_output: bool, text: bool
    ) -> subprocess.CompletedProcess[str]:
        assert check and capture_output and text
        return subprocess.CompletedProcess(args, 0, stdout=outputs[tuple(args)], stderr="")

    monkeypatch.setattr(subprocess, "run", fake_run)
    expected_rows = [{"mode": "100644", "blob_sha": "1" * 40, "stage": "0", "path": "Makefile"}]
    expected = hashlib.sha256(
        json.dumps(
            expected_rows,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
    ).hexdigest()

    assert _checkout_digest("a" * 40) == expected


@pytest.mark.parametrize(
    ("dirty_channel", "dirty_path"),
    (
        ("unstaged", "backend/src/itda/application/recommendations.py"),
        ("staged", "backend/pyproject.toml"),
        ("unstaged", "backend/uv.lock"),
        ("staged", "backend/uv.lock"),
        ("untracked", "web/src/features/recommendations/NewRecommendationState.tsx"),
        ("staged", "web/next.config.ts"),
        ("untracked", "backend/tests/contract/test_new_phase5_gate.py"),
    ),
)
def test_checkout_digest_rejects_owned_source_and_config_dirtiness(
    monkeypatch: pytest.MonkeyPatch,
    dirty_channel: str,
    dirty_path: str,
) -> None:
    """The narrowed scope remains fail-closed for every owned dirty channel."""

    from itda.cli.verify_phase5_gate_receipts import Phase5GateReceiptError, _checkout_digest

    outputs = {
        ("git", "diff", "--name-only"): dirty_path + "\n" if dirty_channel == "unstaged" else "",
        ("git", "diff", "--cached", "--name-only"): (
            dirty_path + "\n" if dirty_channel == "staged" else ""
        ),
        ("git", "ls-files", "--others", "--exclude-standard"): (
            dirty_path + "\n" if dirty_channel == "untracked" else ""
        ),
        ("git", "ls-files", "-s"): f"100644 {'1' * 40} 0\tMakefile\n",
    }

    def fake_run(
        args: tuple[str, ...], *, check: bool, capture_output: bool, text: bool
    ) -> subprocess.CompletedProcess[str]:
        assert check and capture_output and text
        return subprocess.CompletedProcess(args, 0, stdout=outputs[tuple(args)], stderr="")

    monkeypatch.setattr(subprocess, "run", fake_run)

    with pytest.raises(Phase5GateReceiptError, match="SOURCE_SCOPE_DIRTY"):
        _checkout_digest("a" * 40)


def test_checkout_digest_binds_committed_lockfile_blob(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from itda.cli.verify_phase5_gate_receipts import _checkout_digest

    lock_blob = {"value": "1" * 40}

    def fake_run(
        args: tuple[str, ...], *, check: bool, capture_output: bool, text: bool
    ) -> subprocess.CompletedProcess[str]:
        assert check and capture_output and text
        outputs: dict[tuple[str, ...], str] = {
            ("git", "diff", "--name-only"): "",
            ("git", "diff", "--cached", "--name-only"): "",
            ("git", "ls-files", "--others", "--exclude-standard"): "",
            ("git", "ls-files", "-s"): (
                f"100644 {'2' * 40} 0\tMakefile\n100644 {lock_blob['value']} 0\tbackend/uv.lock\n"
            ),
        }
        return subprocess.CompletedProcess(args, 0, stdout=outputs[tuple(args)], stderr="")

    monkeypatch.setattr(subprocess, "run", fake_run)
    first = _checkout_digest("a" * 40)
    lock_blob["value"] = "3" * 40
    second = _checkout_digest("a" * 40)
    assert first != second


def test_complete_review_requires_three_profiles_with_five_bounded_results() -> None:
    """A COMPLETE quality record cannot be an empty ceremonial approval."""

    from itda.cli.verify_phase5_gate_receipts import (
        Phase5GateReceiptError,
        validate_explanation_review,
    )

    with pytest.raises(Phase5GateReceiptError, match="EXPLANATION_REVIEW_CONTRACT_INVALID"):
        validate_explanation_review(
            {
                "schema_version": "itda.phase5-korean-explanation-review.v1",
                "status": "COMPLETE_NON_BLOCKING_EXTERNAL_QUALITY_EVIDENCE",
                "reviewer_pseudonym": "phase5-operator",
                "reviewed_at": "2026-08-11T00:02:00Z",
                "active_release_sha256": RELEASE_SHA,
                "config_sha256": SHA,
                "run_sha256": SHA,
                "profiles": [],
            },
            allow_deferred_nonblocking_review=True,
        )


def test_validation_rows_must_link_the_exact_receipt_digests(tmp_path: Path) -> None:
    """A green label without the matching receipt hash is not sign-off evidence."""

    from itda.cli.verify_phase5_gate_receipts import (
        Phase5GateReceiptError,
        signoff_gate_receipts,
    )

    bundle = _valid_signoff_bundle(tmp_path)
    validation = bundle["validation_path"]
    assert isinstance(validation, Path)
    validation.write_text(
        "| 05-11-01 | Task 1 | ✅ green | clean-gate-receipt " + "f" * 64 + " |\n"
        "| 05-11-02 | Task 2 | ✅ green | private-evidence-receipt " + "f" * 64 + " |\n",
        encoding="utf-8",
    )

    with pytest.raises(Phase5GateReceiptError, match="VALIDATION_LINKAGE_MISMATCH"):
        signoff_gate_receipts(**bundle)  # type: ignore[arg-type]


@pytest.mark.parametrize(
    ("target", "field", "value", "expected_error"),
    (
        ("clean", "checkout_sha256", "b" * 64, "GATE_RECEIPT_CONTRACT_MISMATCH"),
        ("clean", "state", "GREEN_FABRICATED", "GATE_RECEIPT_CONTRACT_MISMATCH"),
        ("clean", "child_exit_statuses", {"pytest": 1}, "GATE_CHILD_NOT_GREEN"),
        ("clean", "suite_ids", ["phase5-gate-receipts"], "GATE_RECEIPT_CONTRACT_MISMATCH"),
        ("clean", "command_set_sha256", "b" * 64, "GATE_RECEIPT_CONTRACT_MISMATCH"),
        ("private", "analysis_origin", "SYNTHETIC", "PRIVATE_RELEASE_CONTRACT_MISMATCH"),
        ("private", "member_count", 23, "PRIVATE_RELEASE_CONTRACT_MISMATCH"),
        ("private", "active_release_sha256", "wrong", "PRIVATE_RELEASE_CONTRACT_MISMATCH"),
        (
            "private",
            "active_release_verification_sha256",
            17,
            "PRIVATE_RELEASE_CONTRACT_MISMATCH",
        ),
        ("private", "checkout_git_sha", "not-a-git-sha", "CURRENT_CHECKOUT_INVALID"),
        ("private", "artifact_path", "/restricted/body.json", "GATE_RECEIPT_CONTRACT_MISMATCH"),
    ),
)
def test_hostile_receipt_mutations_are_rejected(
    tmp_path: Path,
    target: str,
    field: str,
    value: object,
    expected_error: str,
) -> None:
    """Current hashes do not authorize stale, partial, private-path, or wrong-release claims."""

    from itda.cli.verify_phase5_gate_receipts import (
        Phase5GateReceiptError,
        signoff_gate_receipts,
    )

    bundle = _valid_signoff_bundle(tmp_path)
    target_path = bundle[f"{target}_receipt_path"]
    assert isinstance(target_path, Path)
    mutated = json.loads(target_path.read_text(encoding="utf-8"))
    mutated.pop("receipt_sha256")
    mutated[field] = value
    _write_json(target_path, _sealed_receipt(mutated))
    clean = json.loads(Path(bundle["clean_receipt_path"]).read_text(encoding="utf-8"))
    private = json.loads(Path(bundle["private_receipt_path"]).read_text(encoding="utf-8"))
    validation = bundle["validation_path"]
    assert isinstance(validation, Path)
    validation.write_text(
        f"| 05-11-01 | Task 1 | ✅ green | clean-gate-receipt {clean['receipt_sha256']} |\n"
        f"| 05-11-02 | Task 2 | ✅ green | private-evidence-receipt "
        f"{private['receipt_sha256']} |\n",
        encoding="utf-8",
    )

    with pytest.raises(Phase5GateReceiptError, match=expected_error):
        signoff_gate_receipts(**bundle)  # type: ignore[arg-type]


def test_private_receipt_missing_release_verification_digest_is_rejected(
    tmp_path: Path,
) -> None:
    from itda.cli.verify_phase5_gate_receipts import (
        Phase5GateReceiptError,
        signoff_gate_receipts,
    )

    bundle = _valid_signoff_bundle(tmp_path)
    private_path = bundle["private_receipt_path"]
    assert isinstance(private_path, Path)
    private = json.loads(private_path.read_text(encoding="utf-8"))
    private.pop("receipt_sha256")
    private.pop("active_release_verification_sha256")
    private = _sealed_receipt(private)
    _write_json(private_path, private)
    clean = json.loads(Path(bundle["clean_receipt_path"]).read_text(encoding="utf-8"))
    validation = bundle["validation_path"]
    assert isinstance(validation, Path)
    validation.write_text(
        f"| 05-11-01 | Task 1 | ✅ green | clean-gate-receipt {clean['receipt_sha256']} |\n"
        f"| 05-11-02 | Task 2 | ✅ green | private-evidence-receipt "
        f"{private['receipt_sha256']} |\n",
        encoding="utf-8",
    )

    with pytest.raises(Phase5GateReceiptError, match="GATE_RECEIPT_CONTRACT_MISMATCH"):
        signoff_gate_receipts(**bundle)  # type: ignore[arg-type]


def test_receipt_inputs_reject_symlinks_and_non_regular_files(tmp_path: Path) -> None:
    """No-follow receipt loading rejects substitution before parsing evidence."""

    from itda.cli.verify_phase5_gate_receipts import (
        Phase5GateReceiptError,
        signoff_gate_receipts,
    )

    bundle = _valid_signoff_bundle(tmp_path)
    clean = bundle["clean_receipt_path"]
    assert isinstance(clean, Path)
    target = tmp_path / "moved-clean.json"
    clean.rename(target)
    clean.symlink_to(target)
    with pytest.raises(Phase5GateReceiptError, match="GATE_RECEIPT_UNAVAILABLE"):
        signoff_gate_receipts(**bundle)  # type: ignore[arg-type]

    clean.unlink()
    clean.mkdir()
    with pytest.raises(Phase5GateReceiptError, match="GATE_RECEIPT_INVALID_FILE"):
        signoff_gate_receipts(**bundle)  # type: ignore[arg-type]


def test_private_receipt_must_match_the_independently_resolved_active_release(
    tmp_path: Path,
) -> None:
    """A self-consistent receipt for a different release is still rejected."""

    from itda.cli.verify_phase5_gate_receipts import (
        Phase5GateReceiptError,
        signoff_gate_receipts,
    )

    bundle = _valid_signoff_bundle(tmp_path)
    private_path = bundle["private_receipt_path"]
    review_path = bundle["explanation_review_path"]
    assert isinstance(private_path, Path)
    assert isinstance(review_path, Path)
    private = json.loads(private_path.read_text(encoding="utf-8"))
    private.pop("receipt_sha256")
    private["active_release_sha256"] = "b" * 64
    private = _sealed_receipt(private)
    _write_json(private_path, private)
    review = json.loads(review_path.read_text(encoding="utf-8"))
    review["active_release_sha256"] = "b" * 64
    _write_json(review_path, review)
    clean = json.loads(Path(bundle["clean_receipt_path"]).read_text(encoding="utf-8"))
    Path(bundle["validation_path"]).write_text(
        f"| 05-11-01 | Task 1 | ✅ green | clean-gate-receipt {clean['receipt_sha256']} |\n"
        f"| 05-11-02 | Task 2 | ✅ green | private-evidence-receipt "
        f"{private['receipt_sha256']} |\n",
        encoding="utf-8",
    )

    with pytest.raises(Phase5GateReceiptError, match="GATE_PARENT_IDENTITY_MISMATCH"):
        signoff_gate_receipts(
            **bundle,  # type: ignore[arg-type]
            expected_active_release_sha256=RELEASE_SHA,
            expected_active_membership_sha256=MEMBERSHIP_SHA,
        )


def test_current_release_verification_rejects_low_confidence_only_cohort() -> None:
    from itda.cli.verify_phase5_gate_receipts import (
        Phase5GateReceiptError,
        _validate_active_release_verification,
    )

    invalid = _eligible_release_verification()
    invalid["eligible_count"] = 4
    with pytest.raises(Phase5GateReceiptError, match="PRIVATE_RELEASE_CONTRACT_MISMATCH"):
        _validate_active_release_verification(invalid)


def test_clean_receipt_binds_release_config_and_kernel_identity(tmp_path: Path) -> None:
    from itda.cli.verify_phase5_gate_receipts import emit_clean_gate_receipt

    receipt = emit_clean_gate_receipt(
        output_path=tmp_path / "clean.json",
        checkout_sha256=SHA,
        started_at="2026-08-11T00:00:00Z",
        completed_at="2026-08-11T00:01:00Z",
        duration_ms=60_000,
        child_exit_statuses={
            "backend": 0,
            "generated_contract": 0,
            "components": 0,
            "clean_browser": 0,
        },
        release_verification=_eligible_release_verification(),
    )
    assert receipt["active_release_sha256"] == RELEASE_SHA
    assert receipt["active_membership_sha256"] == MEMBERSHIP_SHA
    assert receipt["config_sha256"] == CONFIG_SHA
    assert receipt["kernel_sha256"] == KERNEL_SHA
    assert receipt["eligible_count"] == 24


def test_validation_normalizer_removes_recoverable_stale_green(tmp_path: Path) -> None:
    from itda.cli.verify_phase5_gate_receipts import normalize_validation_ledger

    path = tmp_path / "05-VALIDATION.md"
    path.write_text(
        "---\n"
        "phase: 05\n"
        "slug: complete-no-photo-recommendation-journey\n"
        "status: complete\n"
        "nyquist_compliant: true\n"
        "wave_0_complete: true\n"
        "current_signoff: GREEN\n"
        "current_signoff_receipt: deadbeef\n"
        "rollback_baseline: phase5-validation-pending-v1\n"
        "ledger_schema_version: itda.phase5-validation-ledger.v8\n"
        "current_task_ledger_sha256: "
        "adb88e8cf6001c606c47667239ed2ee5a3683040d4b5656d4165ba6b50c9ecda\n"
        "---\n\n"
        "Current approval: GREEN final signoff receipt deadbeef\n"
        "| 05-12-01 | Task | ✅ green | receipt deadbeef |\n"
        "| 05-12-02 | Task | ✅ green | receipt deadbeef |\n"
        "| 05-13-01 | Task | ✅ green | receipt deadbeef |\n"
        "| 05-13-02 | Task | ✅ green | receipt deadbeef |\n"
        "| 05-14-01 | Task | ✅ green | receipt deadbeef |\n"
        "| 05-14-02 | Task | ✅ green | receipt deadbeef |\n"
        "| 05-15-01 | Task | ✅ green | receipt deadbeef |\n"
        "| 05-15-02 | Task | ✅ green | receipt deadbeef |\n"
        "| 05-16-01 | Task | ✅ green | receipt deadbeef |\n"
        "| 05-16-02 | Task | ✅ green | receipt deadbeef |\n"
        "| 05-17-01 | Task | ✅ green | receipt deadbeef |\n"
        "| 05-17-02 | Task | ✅ green | receipt deadbeef |\n",
        encoding="utf-8",
    )
    baseline = normalize_validation_ledger(path)
    assert baseline.normalized is True
    installed = path.read_text(encoding="utf-8")
    assert "status: gaps_planned" in installed
    assert "wave_0_complete: false" in installed
    assert "current_signoff: blocked" in installed
    assert "current_signoff_receipt: null" in installed
    assert "✅ green" not in installed
    assert "deadbeef" not in installed
    assert baseline.digest == __import__("hashlib").sha256(path.read_bytes()).hexdigest()


def test_validation_normalizer_preserves_historical_green_rows(tmp_path: Path) -> None:
    """Only current 05-12..05-17 rows are reset; historical evidence stays intact."""

    from itda.cli.verify_phase5_gate_receipts import normalize_validation_ledger

    path = tmp_path / "05-VALIDATION.md"
    current_rows = "\n".join(
        f"| 05-{plan:02d}-{task:02d} | Task | ✅ green | receipt stale |"
        for plan in range(12, 18)
        for task in range(1, 3)
    )
    path.write_text(
        "---\n"
        "phase: 05\nslug: complete-no-photo-recommendation-journey\n"
        "status: complete\nnyquist_compliant: true\nwave_0_complete: true\n"
        "current_signoff: GREEN\ncurrent_signoff_receipt: stale\n"
        "rollback_baseline: phase5-validation-pending-v1\n"
        "ledger_schema_version: itda.phase5-validation-ledger.v8\n"
        "current_task_ledger_sha256: "
        "adb88e8cf6001c606c47667239ed2ee5a3683040d4b5656d4165ba6b50c9ecda\n"
        "---\n\n"
        "| 05-01-01 | Historical task | ✅ green | historical receipt kept |\n"
        + current_rows
        + "\n",
        encoding="utf-8",
    )

    normalize_validation_ledger(path)
    installed = path.read_text(encoding="utf-8")
    assert "| 05-01-01 | Historical task | ✅ green | historical receipt kept |" in installed
    assert "| 05-12-01 | Task | ⬜ planned | ⬜ pending |" in installed


def test_validation_normalizer_rejects_ambiguous_missing_current_row(tmp_path: Path) -> None:
    from itda.cli.verify_phase5_gate_receipts import (
        Phase5GateReceiptError,
        normalize_validation_ledger,
    )

    path = tmp_path / "05-VALIDATION.md"
    path.write_text(
        "---\nphase: 05\nslug: complete-no-photo-recommendation-journey\n"
        "status: gaps_planned\nnyquist_compliant: true\nwave_0_complete: false\n"
        "current_signoff: blocked\ncurrent_signoff_receipt: null\n"
        "rollback_baseline: phase5-validation-pending-v1\n"
        "ledger_schema_version: itda.phase5-validation-ledger.v8\n"
        "current_task_ledger_sha256: "
        "adb88e8cf6001c606c47667239ed2ee5a3683040d4b5656d4165ba6b50c9ecda\n"
        "---\n\n"
        "| 05-14-01 | Task | ⬜ planned | ⬜ pending |\n",
        encoding="utf-8",
    )
    with pytest.raises(Phase5GateReceiptError, match="VALIDATION_LEDGER_AMBIGUOUS"):
        normalize_validation_ledger(path)


def _write_finalization_inputs(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> dict[str, Path]:
    import itda.cli.verify_phase5_gate_receipts as gates

    release = _eligible_release_verification()
    monkeypatch.setattr(gates, "_resolve_current_active_release_verification", lambda: release)
    monkeypatch.setattr(
        gates,
        "_current_recommendation_identity",
        lambda: (CONFIG_SHA, KERNEL_SHA),
    )
    monkeypatch.setattr(gates, "_current_git_sha", lambda: "a" * 40)
    monkeypatch.setattr(gates, "_checkout_digest", lambda _: SHA)

    clean_path = tmp_path / "clean.json"
    private_path = tmp_path / "private.json"
    gates.emit_clean_gate_receipt(
        output_path=clean_path,
        checkout_sha256=SHA,
        started_at="2026-08-16T00:00:00Z",
        completed_at="2026-08-16T00:01:00Z",
        duration_ms=60_000,
        child_exit_statuses={
            "backend": 0,
            "generated_contract": 0,
            "components": 0,
            "clean_browser": 0,
        },
        release_verification=release,
    )
    gates.emit_private_gate_receipt(
        output_path=private_path,
        checkout_sha256=SHA,
        started_at="2026-08-16T00:01:00Z",
        completed_at="2026-08-16T00:02:00Z",
        duration_ms=60_000,
        child_exit_statuses={"active_release": 0, "private_browser": 0},
        release_verification=release,
    )
    validation_path = tmp_path / "05-VALIDATION.md"
    rows = "\n".join(
        f"| 05-{plan:02d}-{task:02d} | Task | ✅ green | receipt stale |"
        for plan in range(12, 18)
        for task in range(1, 3)
    )
    validation_path.write_text(
        "---\n"
        "phase: 05\nslug: complete-no-photo-recommendation-journey\n"
        "status: complete\nnyquist_compliant: true\nwave_0_complete: true\n"
        "current_signoff: GREEN\ncurrent_signoff_receipt: stale\n"
        "rollback_baseline: phase5-validation-pending-v1\n"
        "ledger_schema_version: itda.phase5-validation-ledger.v8\n"
        "current_task_ledger_sha256: "
        "adb88e8cf6001c606c47667239ed2ee5a3683040d4b5656d4165ba6b50c9ecda\n"
        "---\n\n" + rows + "\nCurrent approval: GREEN stale receipt\n",
        encoding="utf-8",
    )
    review_path = tmp_path / "review.json"
    _write_json(
        review_path,
        {
            "schema_version": "itda.phase5-korean-explanation-review.v1",
            "status": "DEFERRED_NON_BLOCKING_EXTERNAL_QUALITY_EVIDENCE",
            "reviewer_pseudonym": "phase5-operator",
            "reviewed_at": "2026-08-16T00:02:00Z",
            "active_release_sha256": RELEASE_SHA,
            "reason": "Deferred for the contest demo.",
        },
    )
    return {
        "validation_path": validation_path,
        "clean_path": clean_path,
        "private_path": private_path,
        "review_path": review_path,
        "final_path": tmp_path / "final.json",
        "record_path": tmp_path / "finalization.json",
    }


def test_finalization_installs_receipt_bound_candidate_only_after_transaction(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from itda.cli.verify_phase5_gate_receipts import finalize_validation_ledger

    paths = _write_finalization_inputs(tmp_path, monkeypatch)
    result = finalize_validation_ledger(
        validation_path=paths["validation_path"],
        clean_receipt_path=paths["clean_path"],
        private_receipt_path=paths["private_path"],
        explanation_review_path=paths["review_path"],
        final_receipt_path=paths["final_path"],
        finalization_record_path=paths["record_path"],
    )

    installed = paths["validation_path"].read_text(encoding="utf-8")
    assert "status: complete" in installed
    assert "current_signoff: GREEN" in installed
    assert result["final_receipt"]["state"] == "GREEN"  # type: ignore[index]
    assert result["finalization_record"]["state"] == "COMMITTED"  # type: ignore[index]
    assert paths["final_path"].exists()
    assert paths["record_path"].exists()


@pytest.mark.parametrize(
    "failure_stage",
    ("after-normalization", "candidate", "receipt", "commit", "rename", "post-swap"),
)
def test_finalization_failures_restore_normalized_pending_baseline(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    failure_stage: str,
) -> None:
    from itda.cli.verify_phase5_gate_receipts import (
        Phase5ValidationTransactionError,
        finalize_validation_ledger,
    )

    paths = _write_finalization_inputs(tmp_path, monkeypatch)
    mixed = paths["validation_path"].read_bytes()
    with pytest.raises(Phase5ValidationTransactionError, match="FINALIZATION_INJECTED"):
        finalize_validation_ledger(
            validation_path=paths["validation_path"],
            clean_receipt_path=paths["clean_path"],
            private_receipt_path=paths["private_path"],
            explanation_review_path=paths["review_path"],
            final_receipt_path=paths["final_path"],
            finalization_record_path=paths["record_path"],
            failure_stage=failure_stage,
        )

    installed = paths["validation_path"].read_bytes()
    assert installed != mixed or failure_stage == "after-normalization"
    assert b"status: gaps_planned" in installed
    assert b"current_signoff: blocked" in installed
    assert b"current_signoff_receipt: null" in installed
    assert "✅ green".encode() not in installed
    assert b"current-gap-receipt" not in installed
    assert not paths["final_path"].exists()


def test_make_owns_provider_free_suite_and_current_release_aggregate() -> None:
    repository_root = Path(__file__).resolve().parents[3]

    def dry_run(target: str) -> str:
        result = subprocess.run(
            ["make", "--no-print-directory", "-n", target],
            cwd=repository_root,
            check=False,
            capture_output=True,
            text=True,
        )
        assert result.returncode == 0, result.stderr
        return result.stdout

    suite = dry_run("phase-05-clean-suite")
    clean = dry_run("phase-05-clean-gate")
    aggregate = dry_run("phase-05-current-release-gates")
    contract = dry_run("phase-05-checkout-gate-contract")
    makefile = (repository_root / "Makefile").read_text(encoding="utf-8")
    assert "phase-05-clean-gate" not in suite
    assert "emit-clean" not in suite
    assert "phase-05-clean-suite" in makefile
    assert "--release-verification" in clean
    assert "phase-05-clean-gate phase-05-private-evidence-check" in makefile
    assert "phase-05-private-evidence-check" in makefile
    assert "phase-05-private-evidence-check" not in suite
    assert "test_phase5_gate_receipts.py" in contract
    for output in (suite, clean, aggregate, contract):
        assert "-u NVIDIA_KEY" in output
        assert "-u ZHIPUAI_API_KEY" in output
        assert "-u BIGMODEL_API_KEY" in output


def test_ci_phase5_owns_only_provider_free_suite() -> None:
    repository_root = Path(__file__).resolve().parents[3]
    ci = (repository_root / ".github/workflows/ci.yml").read_text(encoding="utf-8")
    assert "make phase-05-clean-suite" in ci
    assert "make phase-05-check-ownership" in ci
    assert "phase-05-clean-gate" not in ci
    assert "phase-05-private-evidence-check" not in ci
    assert "-u NVIDIA_KEY" in ci
    assert "-u ZHIPUAI_API_KEY" in ci
    assert "-u BIGMODEL_API_KEY" in ci


def test_phase5_suite_registry_has_exact_eventual_paths_and_one_pending_row() -> None:
    from itda.cli.verify_phase5_gate_receipts import (
        PHASE5_SUITE_REGISTRY_V4,
        validate_phase5_suite_registry,
    )

    report = validate_phase5_suite_registry()

    assert report["schema_version"] == "itda.phase5-suite-registry.v4"
    assert report["registry_total"] == 37
    # The committed 05-35 OpenRouter recovery suite promoted its pending row to
    # active ownership; no planned-but-uncreated suite remains pending.
    assert report["pending"] == 0
    assert report["active_present"] == 37
    assert len(PHASE5_SUITE_REGISTRY_V4) == 37
    assert len({row["path"] for row in PHASE5_SUITE_REGISTRY_V4}) == 37
    assert sum(row["pending_owner"] is not None for row in PHASE5_SUITE_REGISTRY_V4) == 0
    rows = {row["path"]: row for row in PHASE5_SUITE_REGISTRY_V4}
    assert (
        rows["backend/tests/contract/test_phase5_openrouter_recovery.py"]["pending_owner"] is None
    )
    assert rows["backend/tests/contract/test_phase5_openrouter_recovery.py"]["owner"] == (
        "phase5-openrouter-recovery"
    )


def test_phase5_suite_registry_rejects_mutations_before_receipt_output() -> None:
    from itda.cli.verify_phase5_gate_receipts import (
        PHASE5_SUITE_REGISTRY_V4,
        Phase5GateReceiptError,
        validate_phase5_suite_registry,
    )

    mutations = []
    missing = list(PHASE5_SUITE_REGISTRY_V4)
    missing.pop()
    mutations.append(missing)
    duplicate = list(PHASE5_SUITE_REGISTRY_V4)
    duplicate[-1] = dict(duplicate[0])
    mutations.append(duplicate)
    reassigned = [dict(row) for row in PHASE5_SUITE_REGISTRY_V4]
    reassigned[0]["owner"] = reassigned[1]["owner"]
    mutations.append(reassigned)
    openapi_omitted = [
        dict(row)
        for row in PHASE5_SUITE_REGISTRY_V4
        if row["path"] != "backend/tests/contract/test_openapi_contract.py"
    ]
    mutations.append(openapi_omitted)

    for mutation in mutations:
        with pytest.raises(Phase5GateReceiptError, match="SUITE_REGISTRY_"):
            validate_phase5_suite_registry(mutation)


def test_phase5_executed_lanes_own_committed_recovery_suites() -> None:
    """The consumed 05-24..05-27 evidence lanes own their committed test files."""

    from itda.cli.verify_phase5_gate_receipts import PHASE5_SUITE_REGISTRY_V4

    rows = {row["path"]: row for row in PHASE5_SUITE_REGISTRY_V4}
    assert rows["backend/tests/contract/test_phase5_nvidia_recovery.py"]["owner"] == (
        "phase5-nvidia-recovery"
    )
    assert rows["backend/tests/contract/test_phase5_fresh24.py"]["owner"] == "phase5-fresh24"
    for path in (
        "backend/tests/contract/test_phase5_nvidia_recovery.py",
        "backend/tests/contract/test_phase5_fresh24.py",
    ):
        assert rows[path]["pending_owner"] is None


def test_phase5_executed_inventory_must_equal_active_registered_rows() -> None:
    from itda.cli.verify_phase5_gate_receipts import (
        Phase5GateReceiptError,
        phase5_suite_inventory,
        validate_phase5_executed_inventory,
    )

    inventory = phase5_suite_inventory(Path(__file__).resolve().parents[3])
    assert inventory["discovered_registered"] == inventory["active_registered"]
    assert inventory["executed_inventory"] == inventory["active_registered"]

    altered = list(inventory["executed_inventory"])
    altered.pop()
    with pytest.raises(Phase5GateReceiptError, match="SUITE_EXECUTED_INVENTORY_MISMATCH"):
        validate_phase5_executed_inventory(altered)

    altered = list(inventory["executed_inventory"]) + [
        "backend/tests/contract/test_openapi_contract.py"
    ]
    with pytest.raises(Phase5GateReceiptError, match="SUITE_EXECUTED_INVENTORY_MISMATCH"):
        validate_phase5_executed_inventory(altered)


def test_phase5_registry_assigns_direct_openapi_and_e2e_runtime_owners() -> None:
    from itda.cli.verify_phase5_gate_receipts import PHASE5_SUITE_REGISTRY_V4

    rows = {row["path"]: row for row in PHASE5_SUITE_REGISTRY_V4}
    assert rows["backend/tests/contract/test_openapi_contract.py"]["owner"] == (
        "phase5-generated-contract"
    )
    assert rows["backend/tests/integration/test_e2e_runtime.py"]["owner"] == ("phase5-e2e-runtime")
    assert (
        rows["backend/tests/contract/test_openapi_contract.py"]["command_family"]
        != rows["backend/tests/contract/test_recommendation_contract.py"]["command_family"]
    )


def test_phase5_current_task_ledger_is_ordered_49_row_identity() -> None:
    from itda.cli.verify_phase5_gate_receipts import (
        PHASE5_CURRENT_TASK_IDS_V8,
        PHASE5_SUITE_REGISTRY_V4,
        validate_phase5_current_task_ids,
    )

    assert len(PHASE5_CURRENT_TASK_IDS_V8) == 49
    assert validate_phase5_current_task_ids() == PHASE5_CURRENT_TASK_IDS_V8
    assert tuple(row["path"] for row in PHASE5_SUITE_REGISTRY_V4) != PHASE5_CURRENT_TASK_IDS_V8
    assert PHASE5_CURRENT_TASK_IDS_V8[:12] == (
        "05-18-01",
        "05-18-02",
        "05-19-01",
        "05-19-02",
        "05-20-01",
        "05-20-02",
        "05-21-01",
        "05-21-02",
        "05-22-01",
        "05-22-02",
        "05-23-01",
        "05-23-02",
    )
    assert PHASE5_CURRENT_TASK_IDS_V8[12:14] == ("05-34-01", "05-34-02")
    assert PHASE5_CURRENT_TASK_IDS_V8[23:35] == (
        "05-35-01",
        "05-35-02",
        "05-35-03",
        "05-37-01",
        "05-37-02",
        "05-38-01",
        "05-38-02",
        "05-39-01",
        "05-39-02",
        "05-40-01",
        "05-40-02",
        "05-40-03",
    )
    assert not {"05-36-01", "05-36-02", "05-36-03"} & set(PHASE5_CURRENT_TASK_IDS_V8)
    assert "05-27-01" not in PHASE5_CURRENT_TASK_IDS_V8
    assert "05-27-02" not in PHASE5_CURRENT_TASK_IDS_V8
    assert PHASE5_CURRENT_TASK_IDS_V8[-2:] == ("05-17-01", "05-17-02")


def test_phase5_failed_05_36_history_is_separate_non_authority() -> None:
    from itda.cli.verify_phase5_gate_receipts import (
        PHASE5_FAILED_HISTORY_TASK_IDS,
        Phase5GateReceiptError,
        validate_phase5_failed_history_rows,
    )

    assert PHASE5_FAILED_HISTORY_TASK_IDS == ("05-36-01", "05-36-02", "05-36-03")
    with pytest.raises(Phase5GateReceiptError, match="PHASE5_FAILED_HISTORY_ROWS_MISSING"):
        validate_phase5_failed_history_rows(
            "| 05-36-01 | Task | failed history | approval installed |"
        )
    payload = (
        "| 05-36-01 | Task | failed history | approval installed |\n"
        "| 05-36-02 | Task | failed history | one-use claim consumed |\n"
        "| 05-36-03 | Task | failed history | failed before RESERVE |"
    )
    assert validate_phase5_failed_history_rows(payload) == PHASE5_FAILED_HISTORY_TASK_IDS
    with pytest.raises(Phase5GateReceiptError, match="PHASE5_FAILED_HISTORY_STATUS_INVALID"):
        validate_phase5_failed_history_rows(payload.replace("failed history", "complete", 1))
    with pytest.raises(Phase5GateReceiptError, match="PHASE5_FAILED_HISTORY_ROWS_MISSING"):
        validate_phase5_failed_history_rows(payload + "\n" + payload.splitlines()[0])


def test_phase5_halted_05_27_history_is_separate_non_authority() -> None:
    from itda.cli.verify_phase5_gate_receipts import (
        PHASE5_HALTED_HISTORY_TASK_IDS,
        Phase5GateReceiptError,
        validate_phase5_halted_history_rows,
    )

    assert PHASE5_HALTED_HISTORY_TASK_IDS == ("05-27-01", "05-27-02")
    with pytest.raises(Phase5GateReceiptError, match="PHASE5_HALTED_HISTORY_ROWS_MISSING"):
        validate_phase5_halted_history_rows("| 05-26-03 | Task | ⬜ planned | ⬜ pending |")
    payload = (
        "| 05-27-01 | Task | 🕘 halted historical | designed negative |\n"
        "| 05-27-02 | Task | 🕘 halted historical | designed negative |"
    )
    assert validate_phase5_halted_history_rows(payload) == ("05-27-01", "05-27-02")
    with pytest.raises(Phase5GateReceiptError, match="PHASE5_HALTED_HISTORY_ROWS_MISSING"):
        validate_phase5_halted_history_rows(payload + "\n" + payload.splitlines()[0])


@pytest.mark.parametrize(
    "mutation",
    [
        lambda rows: rows[:-1],
        lambda rows: rows[:1] + rows[2:3] + rows[1:2] + rows[3:],
        lambda rows: rows[:4] + ("05-24-01",) + rows[5:],
        lambda rows: tuple(f"suite-path-{index}" for index in range(49)),
    ],
)
def test_phase5_current_task_ledger_rejects_order_and_cross_registry_mutations(mutation) -> None:
    from itda.cli.verify_phase5_gate_receipts import (
        PHASE5_CURRENT_TASK_IDS_V8,
        Phase5GateReceiptError,
        validate_phase5_current_task_ids,
    )

    with pytest.raises(Phase5GateReceiptError, match="PHASE5_TASK_LEDGER_"):
        validate_phase5_current_task_ids(mutation(PHASE5_CURRENT_TASK_IDS_V8))


def test_phase5_receipt_versions_are_distinct_from_legacy_gate_versions() -> None:
    from itda.cli.verify_phase5_gate_receipts import (
        _CLEAN_SCHEMA_VERSION,
        _FINAL_SCHEMA_VERSION,
        _PRIVATE_SCHEMA_VERSION,
        PHASE5_SUITE_COMMAND_SET_SHA256,
        PHASE5_SUITE_REGISTRY_SHA256,
    )

    assert _CLEAN_SCHEMA_VERSION.endswith(".v2")
    assert _PRIVATE_SCHEMA_VERSION.endswith(".v2")
    assert _FINAL_SCHEMA_VERSION.endswith(".v1")
    assert PHASE5_SUITE_REGISTRY_SHA256 != PHASE5_SUITE_COMMAND_SET_SHA256


def test_phase5_structured_probe_declaration_has_exact_totals_and_named_ux_truths() -> None:
    plan = (
        Path(__file__).resolve().parents[3]
        / ".planning/phases/05-complete-no-photo-recommendation-journey/05-23-PLAN.md"
    )
    text = plan.read_text(encoding="utf-8")
    for declaration in (
        "edge_total: 17",
        "explicit_truths: 3",
        "unresolved_assumptions: 14",
        "prohibition_total: 6",
        "unresolved_prohibitions: 6",
        "silent_drops: 0",
    ):
        assert declaration in text
    assert "UX-01 adjacency" in text and "UX-01 empty" in text and "UX-01 ordering" in text
    assert "web/e2e/no-photo-recommendation.spec.ts" in text
    assert "RecommendationResults.test.tsx" in text


def test_phase5_historical_05_16_identity_remains_explicit() -> None:
    plan = (
        Path(__file__).resolve().parents[3]
        / ".planning/phases/05-complete-no-photo-recommendation-journey/05-16-PLAN.md"
    )
    summary = (
        Path(__file__).resolve().parents[3]
        / ".planning/phases/05-complete-no-photo-recommendation-journey/05-16-SUMMARY.md"
    )
    summary_text = summary.read_text(encoding="utf-8")
    assert "FAILED_UNACTIVATED" in summary_text
    assert "Task 2 was correctly skipped" in summary_text
    assert "fresh-provider-terminal.json" in plan.read_text(encoding="utf-8")


def test_phase5_bootstrap_requires_positive_predecessors_and_absent_final_summary() -> None:
    from itda.cli.verify_phase5_gate_receipts import validate_phase5_signoff_bootstrap

    # The real checkout has 05-37/05-38 and downstream Summaries missing, while the
    # failed 05-36 and consumed 05-27 rows remain non-authorizing history.
    with pytest.raises(Exception, match="BOOTSTRAP_POSITIVE_PREDECESSOR_MISSING"):
        validate_phase5_signoff_bootstrap(Path(__file__).resolve().parents[3])


def test_phase5_halted_summary_shapes_are_fail_closed() -> None:
    from itda.cli.verify_phase5_gate_receipts import validate_phase5_halted_summary

    with pytest.raises(Exception, match="HALTED_"):
        validate_phase5_halted_summary(
            {"status": "complete", "requirements_completed": ["RECO-01"]},
            required_requirements=("RECO-01",),
        )

    valid = validate_phase5_halted_summary(
        {
            "status": "halted",
            "one_liner": "Probe declined before provider execution",
            "completed_tasks": 2,
            "attempt_count": 0,
            "requirements_completed": [],
            "requirements_blocked": ["RECO-01"],
            "provider_attempted": False,
        },
        required_requirements=("RECO-01",),
    )
    assert valid["status"] == "halted"


@pytest.mark.parametrize(
    "historical_task_id",
    ("05-36-01", "05-36-02", "05-36-03", "05-27-01", "05-27-02"),
)
def test_phase5_failed_and_halted_history_stay_outside_current_ledger(
    historical_task_id: str,
) -> None:
    """Failed/halted task rows are evidence-only and can never be promoted."""

    from itda.cli.verify_phase5_gate_receipts import (
        PHASE5_CURRENT_TASK_IDS_V8,
        PHASE5_FAILED_HISTORY_TASK_IDS,
        PHASE5_HALTED_HISTORY_TASK_IDS,
        Phase5GateReceiptError,
        validate_phase5_current_task_ids,
    )

    histories = (*PHASE5_FAILED_HISTORY_TASK_IDS, *PHASE5_HALTED_HISTORY_TASK_IDS)
    assert not set(histories) & set(PHASE5_CURRENT_TASK_IDS_V8)
    promoted = (*PHASE5_CURRENT_TASK_IDS_V8[:-1], historical_task_id)
    assert len(promoted) == 49
    with pytest.raises(Phase5GateReceiptError, match="PHASE5_TASK_LEDGER_INVALID"):
        validate_phase5_current_task_ids(promoted)


def test_phase5_no_authoritative_backup_is_unresolved_and_artifact_free() -> None:
    from itda.cli.verify_phase5_gate_receipts import validate_phase5_source_authority_stop

    assert (
        validate_phase5_source_authority_stop(
            {"outcome": "no-authoritative-backup", "artifact_count": 0, "summary_exists": False}
        )["outcome"]
        == "no-authoritative-backup"
    )
    with pytest.raises(Exception, match="SOURCE_AUTHORITY_STOP_"):
        validate_phase5_source_authority_stop(
            {"outcome": "no-authoritative-backup", "artifact_count": 1, "summary_exists": False}
        )


@pytest.mark.parametrize("missing_truth", ["adjacency", "empty", "ordering"])
def test_phase5_probe_truth_mutations_are_rejected(missing_truth: str) -> None:
    from itda.cli.verify_phase5_gate_receipts import validate_phase5_probe_coverage

    truths = {"adjacency", "empty", "ordering"} - {missing_truth}
    with pytest.raises(Exception, match="PROBE_COVERAGE_"):
        validate_phase5_probe_coverage(
            {
                "edge_total": 17,
                "explicit_truths": len(truths),
                "unresolved_assumptions": 14,
                "prohibition_total": 6,
                "unresolved_prohibitions": 6,
                "silent_drops": 0,
                "explicit_truth_names": sorted(truths),
            }
        )


def test_phase5_probe_coverage_accepts_the_canonical_declaration() -> None:
    from itda.cli.verify_phase5_gate_receipts import validate_phase5_probe_coverage

    result = validate_phase5_probe_coverage(
        {
            "edge_total": 17,
            "explicit_truths": 3,
            "unresolved_assumptions": 14,
            "prohibition_total": 6,
            "unresolved_prohibitions": 6,
            "silent_drops": 0,
            "explicit_truth_names": ["adjacency", "empty", "ordering"],
        }
    )
    assert result["edge_total"] == 17
    assert result["silent_drops"] == 0


def test_phase5_receipt_map_requirements_remain_complete() -> None:
    from itda.cli.verify_phase5_gate_receipts import (
        _RECEIPT_MAP_REQUIRED_PARENT_FIELDS,
        validate_phase5_receipt_maps,
    )

    assert len(_RECEIPT_MAP_REQUIRED_PARENT_FIELDS) == 17
    from itda.contracts.phase5_recovery_policy import (
        CANONICAL_CONTRAST_PAIRS,
        CANONICAL_SCENARIO_IDS,
    )

    maps = {
        "scenario_ids": list(CANONICAL_SCENARIO_IDS),
        "contrast_pairs": [list(pair) for pair in CANONICAL_CONTRAST_PAIRS],
        "candidate_smoke": "a" * 64,
        "activation_intent": "b" * 64,
        "promotion": "c" * 64,
        "attestation": "d" * 64,
        "ordinary_run": "e" * 64,
        "hard_duplicate": "f" * 64,
        "cannot_coappear": "1" * 64,
    }
    assert validate_phase5_receipt_maps(maps)["scenario_count"] == 8
    maps["scenario_ids"] = maps["scenario_ids"][:-1]
    with pytest.raises(Exception, match="RECEIPT_MAP_"):
        validate_phase5_receipt_maps(maps)


def test_phase5_current_task_rows_are_declared_in_validation_ledger() -> None:
    from itda.cli.verify_phase5_gate_receipts import (
        PHASE5_CURRENT_TASK_IDS_V8,
        PHASE5_FAILED_HISTORY_TASK_IDS,
        PHASE5_HALTED_HISTORY_TASK_IDS,
    )

    validation = (
        Path(__file__).resolve().parents[3]
        / ".planning/phases/05-complete-no-photo-recommendation-journey/05-VALIDATION.md"
    )
    text = validation.read_text(encoding="utf-8")
    assert sum(f"| {task_id} |" in text for task_id in PHASE5_CURRENT_TASK_IDS_V8) == 49
    assert sum(f"| {task_id} |" in text for task_id in PHASE5_FAILED_HISTORY_TASK_IDS) == 3
    assert sum(f"| {task_id} |" in text for task_id in PHASE5_HALTED_HISTORY_TASK_IDS) == 2


def test_phase5_receipt_maps_require_both_relation_authorities() -> None:
    from itda.cli.verify_phase5_gate_receipts import validate_phase5_receipt_maps
    from itda.contracts.phase5_recovery_policy import (
        CANONICAL_CONTRAST_PAIRS,
        CANONICAL_SCENARIO_IDS,
    )

    payload = {
        "scenario_ids": list(CANONICAL_SCENARIO_IDS),
        "contrast_pairs": [list(pair) for pair in CANONICAL_CONTRAST_PAIRS],
        "candidate_smoke": "a" * 64,
        "activation_intent": "b" * 64,
        "promotion": "c" * 64,
        "attestation": "d" * 64,
        "ordinary_run": "e" * 64,
        "hard_duplicate": "f" * 64,
        "cannot_coappear": "1" * 64,
    }
    assert validate_phase5_receipt_maps(payload)["relation_count"] == 2


def test_phase5_probe_declaration_rejects_wrong_totals() -> None:
    from itda.cli.verify_phase5_gate_receipts import validate_phase5_probe_coverage

    payload = {
        "edge_total": 16,
        "explicit_truths": 3,
        "unresolved_assumptions": 14,
        "prohibition_total": 6,
        "unresolved_prohibitions": 6,
        "silent_drops": 0,
        "explicit_truth_names": ["adjacency", "empty", "ordering"],
    }
    with pytest.raises(Exception, match="PROBE_COVERAGE_"):
        validate_phase5_probe_coverage(payload)


def test_phase5_summary_bootstrap_rejects_halted_ancestor() -> None:
    from itda.cli.verify_phase5_gate_receipts import validate_phase5_signoff_bootstrap

    with pytest.raises(Exception, match="BOOTSTRAP_"):
        validate_phase5_signoff_bootstrap(
            Path(__file__).resolve().parents[3],
            summaries={"05-25": {"status": "halted"}},
        )


def test_phase5_summary_bootstrap_tolerates_only_the_consumed_05_27_halt_history() -> None:
    from itda.cli.verify_phase5_gate_receipts import validate_phase5_signoff_bootstrap

    # The 05-27 halted sibling is accepted as immutable history, but any mutation
    # of its status away from halted is rejected.
    with pytest.raises(Exception, match="BOOTSTRAP_HALTED_HISTORY_MUTATED"):
        validate_phase5_signoff_bootstrap(
            Path(__file__).resolve().parents[3],
            summaries={"05-27": {"status": "complete"}},
        )

    complete = {
        plan_id: {"status": "complete"}
        for plan_id in (
            "05-16",
            "05-18",
            "05-19",
            "05-20",
            "05-21",
            "05-22",
            "05-23",
            "05-34",
            "05-24",
            "05-25",
            "05-26",
            "05-35",
            "05-37",
            "05-38",
            "05-39",
            "05-40",
            "05-28",
            "05-29",
            "05-30",
            "05-31",
            "05-32",
            "05-33",
        )
    }
    complete["05-27"] = {"status": "halted"}
    result = validate_phase5_signoff_bootstrap(
        Path(__file__).resolve().parents[3],
        summaries=complete,
    )
    assert result["state"] == "READY"
    assert result["halted_history_siblings"] == ("05-27",)


def test_phase5_summary_bootstrap_rejects_future_summary() -> None:
    from itda.cli.verify_phase5_gate_receipts import validate_phase5_signoff_bootstrap

    with pytest.raises(Exception, match="BOOTSTRAP_"):
        validate_phase5_signoff_bootstrap(
            Path(__file__).resolve().parents[3],
            summaries={"05-17": {"status": "complete"}},
        )


def test_phase5_source_authority_stop_rejects_summary_or_artifact() -> None:
    from itda.cli.verify_phase5_gate_receipts import validate_phase5_source_authority_stop

    with pytest.raises(Exception, match="SOURCE_AUTHORITY_STOP_"):
        validate_phase5_source_authority_stop(
            {"outcome": "no-authoritative-backup", "artifact_count": 0, "summary_exists": True}
        )


def test_phase5_receipt_maps_reject_omitted_ordinary_run() -> None:
    from itda.cli.verify_phase5_gate_receipts import validate_phase5_receipt_maps
    from itda.contracts.phase5_recovery_policy import (
        CANONICAL_CONTRAST_PAIRS,
        CANONICAL_SCENARIO_IDS,
    )

    payload = {
        "scenario_ids": list(CANONICAL_SCENARIO_IDS),
        "contrast_pairs": [list(pair) for pair in CANONICAL_CONTRAST_PAIRS],
        "candidate_smoke": "a" * 64,
        "activation_intent": "b" * 64,
        "promotion": "c" * 64,
        "attestation": "d" * 64,
        "hard_duplicate": "e" * 64,
        "cannot_coappear": "f" * 64,
    }
    with pytest.raises(Exception, match="RECEIPT_MAP_"):
        validate_phase5_receipt_maps(payload)


def test_phase5_current_task_ledger_digest_is_disjoint_from_suite_digest() -> None:
    from itda.cli.verify_phase5_gate_receipts import (
        PHASE5_CURRENT_TASK_LEDGER_SHA256,
        PHASE5_SUITE_REGISTRY_SHA256,
    )

    assert PHASE5_CURRENT_TASK_LEDGER_SHA256 != PHASE5_SUITE_REGISTRY_SHA256


def test_phase5_v5_task_ledger_name_has_no_backcompat_shim() -> None:
    """The superseded V5 and V6 names are fully removed rather than aliased onto V7."""

    import itda.cli.verify_phase5_gate_receipts as gates

    assert not hasattr(gates, "PHASE5_CURRENT_TASK_IDS_V5")
    assert not hasattr(gates, "PHASE5_CURRENT_TASK_IDS_V6")


def test_phase5_plan_remains_provider_free() -> None:
    plan = (
        Path(__file__).resolve().parents[3]
        / ".planning/phases/05-complete-no-photo-recommendation-journey/05-23-PLAN.md"
    )
    text = plan.read_text(encoding="utf-8")
    assert "Provider invocation and artifact-only lifecycle operations are downstream" in text
    assert "No new framework installation is authorized" not in text


def test_make_ownership_target_delegates_to_literal_registry_and_inventory_verifier() -> None:
    repository_root = Path(__file__).resolve().parents[3]
    result = subprocess.run(
        ["make", "--no-print-directory", "-n", "phase-05-check-ownership"],
        cwd=repository_root,
        check=True,
        capture_output=True,
        text=True,
    )
    output = result.stdout
    assert "phase5-ownership" in output
    assert "PHASE5_SUITE_REGISTRY_V4" in output
    assert "PHASE5_SUITE_COMMAND_SET_SHA256" in output
    assert "phase5_suite_inventory" in output


def test_validation_ledger_declares_exact_49_current_task_rows() -> None:
    from itda.cli.verify_phase5_gate_receipts import (
        PHASE5_CURRENT_TASK_IDS_V8,
        validate_phase5_current_task_ledger,
    )

    validation = (
        Path(__file__).resolve().parents[3]
        / ".planning/phases/05-complete-no-photo-recommendation-journey/05-VALIDATION.md"
    )
    assert (
        validate_phase5_current_task_ledger(validation.read_text(encoding="utf-8"))
        == PHASE5_CURRENT_TASK_IDS_V8
    )


def test_phase5_planning_index_records_failed_05_36_and_v2_successors() -> None:
    repository_root = Path(__file__).resolve().parents[3]
    phase_dir = repository_root / ".planning/phases/05-complete-no-photo-recommendation-journey"
    failed_plan = phase_dir / "05-36-FAILED.md"
    failure_record = (
        repository_root / "artifacts/reports/phase5/openrouter-recovery-pre-reserve-failure.json"
    )

    assert not (phase_dir / "05-36-PLAN.md").exists()
    assert hashlib.sha256(failed_plan.read_bytes()).hexdigest() == (
        "5c9ccd5b169a6b9f584b8361d0b0c40c13c5990830aa2096ba871ce6bb9f351c"
    )
    assert not (phase_dir / "05-36-SUMMARY.md").exists()
    record = json.loads(failure_record.read_text(encoding="utf-8"))
    record_sha256 = record.pop("record_sha256")
    assert (
        record_sha256
        == hashlib.sha256(
            json.dumps(
                record,
                ensure_ascii=False,
                sort_keys=True,
                separators=(",", ":"),
            ).encode("utf-8")
        ).hexdigest()
    )
    assert record["schema_version"] == ("itda.phase5-openrouter-recovery-pre-reserve-failure.v1")
    assert record["old_authority_id"] == ("phase5-openrouter-stealth-ox-alpha-recovery-20260823")
    assert record["packet"] == {
        "raw_sha256": ("619b6fd9b31d6a2dc3d40cde98614fd57e96ef944d268c07364d93b3fccde187"),
        "request_manifest_sha256": (
            "1e28243098b48e48c09e841b53a15dd3518f55690d1dc1e0b3fc29d641313043"
        ),
        "semantic_sha256": ("22e6da6d531befa35bcd7128ae37eadb364acdf846bf20d9beccae737358670f"),
    }
    assert record["checkout"] == {
        "checkout_manifest_sha256": (
            "77092b9a7ae4d78eab6d896bc919d4a3223a9b501c2fac89cd75112a5845253e"
        ),
        "git_commit": "508517d3cf64e0227e9e4c81f6864f07a45efed2",
    }
    assert record["approval"] == {
        "approval_self_sha256": (
            "0c0b46ee40137bea1708f8e9bed94d2a234f280f9e62febd73f5422002b83619"
        ),
        "claim_self_sha256": ("48659483bef9cc40fa461817b3c60d2eecc93c011a22f4ebd300c46ce1eaaa94"),
        "exact_human_approval_received": True,
        "installed": True,
        "one_use_claim_consumed": True,
        "protected_descriptor_sha256": (
            "270a38cb1da259955856a9b4b0a7542b65648666440a74f3321f8c1d0f20da43"
        ),
        "raw_approval_file_sha256": (
            "0d8b10b725b6c69dbc2ddc87cbf47b4e60842cc9ee86d6a2a1eeed5ab6054951"
        ),
        "raw_claim_file_sha256": (
            "831b1476cab010d11191d9ab52d820824c5b6c922787313cb86bdc57f58e8c9f"
        ),
    }
    assert record["history"] == {
        "original_plan_filename": "05-36-PLAN.md",
        "original_plan_raw_sha256": (
            "5c9ccd5b169a6b9f584b8361d0b0c40c13c5990830aa2096ba871ce6bb9f351c"
        ),
        "originating_commit": "e35c019d0d3c1c79a3e58792231e91ec36b70764",
        "retained_filename": "05-36-FAILED.md",
    }
    assert record["failure"] == {
        "actual_repository_root_parent_index": 3,
        "code": "OPENROUTER_REPOSITORY_ROOT_BINDING_OFF_BY_ONE",
        "failed_before": "RESERVE",
        "pipeline_call": "_bind_public_entry().derive_authority()",
        "used_packet_parent_index": 4,
    }
    assert record["inventory"] == {
        "file_count": 2,
        "files": ["approval.json", "claim.json"],
    }
    assert record["traffic_boundary"] == {
        "attempt_count": 0,
        "client_constructed": False,
        "lifecycle_mutated": False,
        "network_attempted": False,
        "provider_attempted": False,
        "reserve_count": 0,
        "secret_read": False,
        "send_attempted": False,
    }
    assert record["terminal_exists"] is False
    assert record["summary_exists"] is False
    assert record["requirements_completed"] == []
    assert len(record["requirements_blocked"]) == 8

    plan_37 = (phase_dir / "05-37-PLAN.md").read_text(encoding="utf-8")
    plan_38 = (phase_dir / "05-38-PLAN.md").read_text(encoding="utf-8")
    plan_39 = (phase_dir / "05-39-PLAN.md").read_text(encoding="utf-8")
    plan_40 = (phase_dir / "05-40-PLAN.md").read_text(encoding="utf-8")
    plan_28 = (phase_dir / "05-28-PLAN.md").read_text(encoding="utf-8")
    assert "plan: 37" in plan_37
    assert "wave: 27" in plan_37
    assert "depends_on: [05-35]" in plan_37
    assert "autonomous: true" in plan_37
    assert plan_37.count('<task type="') == 2
    assert "plan: 38" in plan_38
    assert "wave: 28" in plan_38
    assert "depends_on: [05-37]" in plan_38
    assert "autonomous: true" in plan_38
    assert plan_38.count('<task type="') == 2
    assert "plan: 39" in plan_39
    assert "wave: 29" in plan_39
    assert "depends_on: [05-38]" in plan_39
    assert "autonomous: true" in plan_39
    assert plan_39.count('<task type="') == 2
    assert "openrouter-recovery-v4-request.json" in plan_39
    assert "real production install, live, and reconcile bodies" in plan_39
    assert "plan: 40" in plan_40
    assert "wave: 30" in plan_40
    assert "depends_on: [05-39]" in plan_40
    assert "autonomous: false" in plan_40
    assert plan_40.count('<task type="') == 3
    assert "wave: 31" in plan_28
    assert "depends_on: [05-40]" in plan_28
    assert "openrouter-recovery-v4-request.json" in plan_40
    assert "artifacts/restricted/catalog/phase5-openrouter-recovery-r4/" in plan_40
    assert "backend/src/itda/providers/openrouter_ox_alpha_api_contract_v3.json" in plan_38
    assert "openrouter-recovery-v4-terminal.json" in plan_40


def test_phase5_v8_plan_index_has_one_ready_rollover_and_transitive_human_block() -> None:
    repository_root = Path(__file__).resolve().parents[3]
    result = subprocess.run(
        [
            "node",
            str(Path.home() / ".claude/gsd-core/bin/gsd-tools.cjs"),
            "phase-plan-index",
            "05",
            "--raw",
        ],
        cwd=repository_root,
        check=True,
        capture_output=True,
        text=True,
    )
    plans = {plan["id"]: plan for plan in json.loads(result.stdout)["plans"]}
    assert plans["05-38"]["has_summary"] is True
    assert plans["05-39"]["depends_on"] == ["05-38"]
    assert plans["05-39"]["has_summary"] is False
    assert all(plans[parent]["has_summary"] for parent in plans["05-39"]["depends_on"])
    assert plans["05-40"]["depends_on"] == ["05-39"]
    assert plans["05-40"]["has_summary"] is False
    assert not all(plans[parent]["has_summary"] for parent in plans["05-40"]["depends_on"])
    assert plans["05-28"]["depends_on"] == ["05-40"]
    assert plans["05-28"]["has_summary"] is False
    assert not all(plans[parent]["has_summary"] for parent in plans["05-28"]["depends_on"])


def test_validation_ledger_mutations_fail_before_receipt_output() -> None:
    from itda.cli.verify_phase5_gate_receipts import (
        PHASE5_CURRENT_TASK_IDS_V8,
        Phase5GateReceiptError,
        validate_phase5_current_task_ledger,
    )

    validation = (
        Path(__file__).resolve().parents[3]
        / ".planning/phases/05-complete-no-photo-recommendation-journey/05-VALIDATION.md"
    )
    text = validation.read_text(encoding="utf-8")
    lines = text.splitlines()
    row_by_id = {
        task_id: next(line for line in lines if f"| {task_id} |" in line)
        for task_id in (*PHASE5_CURRENT_TASK_IDS_V8, "05-36-01", "05-27-01")
    }
    missing = text.replace(row_by_id["05-18-01"] + "\n", "", 1)
    with pytest.raises(Phase5GateReceiptError, match="PHASE5_TASK_LEDGER_"):
        validate_phase5_current_task_ledger(missing)
    failed_dropped = text.replace(row_by_id["05-36-01"] + "\n", "", 1)
    with pytest.raises(Phase5GateReceiptError, match="PHASE5_FAILED_HISTORY_ROWS_MISSING"):
        validate_phase5_current_task_ledger(failed_dropped)
    failed_promoted = text.replace(
        row_by_id["05-36-01"],
        row_by_id["05-36-01"].replace("failed history", "complete"),
        1,
    )
    with pytest.raises(Phase5GateReceiptError, match="PHASE5_FAILED_HISTORY_STATUS_INVALID"):
        validate_phase5_current_task_ledger(failed_promoted)
    halted_dropped = text.replace(row_by_id["05-27-01"] + "\n", "", 1)
    with pytest.raises(Phase5GateReceiptError, match="PHASE5_HALTED_HISTORY_ROWS_MISSING"):
        validate_phase5_current_task_ledger(halted_dropped)
    reordered = text.replace(
        row_by_id["05-18-01"] + "\n" + row_by_id["05-18-02"],
        row_by_id["05-18-02"] + "\n" + row_by_id["05-18-01"],
        1,
    )
    with pytest.raises(Phase5GateReceiptError, match="PHASE5_TASK_LEDGER_"):
        validate_phase5_current_task_ledger(reordered)


def test_ci_phase5_ownership_and_clean_commands_are_secret_free() -> None:
    repository_root = Path(__file__).resolve().parents[3]
    ci = (repository_root / ".github/workflows/ci.yml").read_text(encoding="utf-8")
    phase5_lines = [line for line in ci.splitlines() if "phase-05" in line]
    assert phase5_lines
    assert all("-u NVIDIA_KEY" in line for line in phase5_lines if "run:" in line)
    assert all("-u ZHIPUAI_API_KEY" in line for line in phase5_lines if "run:" in line)
    assert all("-u BIGMODEL_API_KEY" in line for line in phase5_lines if "run:" in line)
    assert all("phase-05-private-evidence-check" not in line for line in phase5_lines)
    assert all("phase-05-final-signoff" not in line for line in phase5_lines)


def test_phase5_receipt_parent_map_has_exact_17_parent_fields() -> None:
    from itda.cli.verify_phase5_gate_receipts import (
        _RECEIPT_MAP_REQUIRED_PARENT_FIELDS,
        validate_phase5_receipt_maps,
    )
    from itda.contracts.phase5_recovery_policy import (
        CANONICAL_CONTRAST_PAIRS,
        CANONICAL_SCENARIO_IDS,
    )

    value = {
        "scenario_ids": list(CANONICAL_SCENARIO_IDS),
        "contrast_pairs": [list(pair) for pair in CANONICAL_CONTRAST_PAIRS],
        "candidate_smoke": "a" * 64,
        "activation_intent": "b" * 64,
        "promotion": "c" * 64,
        "attestation": "d" * 64,
        "ordinary_run": "e" * 64,
        "hard_duplicate": "f" * 64,
        "cannot_coappear": "1" * 64,
        "parent_fields": list(_RECEIPT_MAP_REQUIRED_PARENT_FIELDS),
    }
    assert validate_phase5_receipt_maps(value)["parent_count"] == 17
    value["parent_fields"] = value["parent_fields"][:-1]
    with pytest.raises(Exception, match="RECEIPT_MAP_PARENT_"):
        validate_phase5_receipt_maps(value)
