from __future__ import annotations

from pathlib import Path

from itda.cli.manage_mvp_scored_release import main
from itda.db.mvp_scored_release import MvpScoredReleaseStore
from tests.contract.test_mvp_scored_release import release


def test_verify_resolves_valid_active_release_by_default(tmp_path: Path, capsys) -> None:
    root = tmp_path / "synthetic-mvp-releases"
    store = MvpScoredReleaseStore(root)
    snapshot = release(80)
    store.publish(snapshot)
    store.activate(snapshot.release_sha256, expected_current=None)
    assert main(["--root", str(root), "verify"]) == 0
    assert f"release_sha256={snapshot.release_sha256}" in capsys.readouterr().out


def test_no_active_verify_is_informational_unless_required(tmp_path: Path, capsys) -> None:
    root = tmp_path / "synthetic-mvp-releases"
    assert main(["--root", str(root), "verify"]) == 0
    assert "state=NO_ACTIVE_MVP_SCORED_RELEASE" in capsys.readouterr().out
    assert main(["--root", str(root), "verify", "--require-active"]) == 2
