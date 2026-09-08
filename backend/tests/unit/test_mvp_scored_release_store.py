from __future__ import annotations

from pathlib import Path

import pytest

from itda.db.mvp_scored_release import MvpScoredReleaseError, MvpScoredReleaseStore
from tests.contract.test_mvp_scored_release import release


@pytest.mark.parametrize("count", [80, 100])
def test_publish_activate_and_resolve(count: int, tmp_path: Path) -> None:
    store = MvpScoredReleaseStore(tmp_path / "synthetic-mvp-releases")
    snapshot = release(count)
    store.publish(snapshot)
    pointer = store.activate(snapshot.release_sha256, expected_current=None)
    assert pointer.release_sha256 == snapshot.release_sha256
    assert store.resolve_active() == snapshot


def test_cas_activation_and_verified_rollback(tmp_path: Path) -> None:
    store = MvpScoredReleaseStore(tmp_path / "synthetic-mvp-releases")
    first = release(80)
    second = release(100, marker=1)
    store.publish(first)
    store.publish(second)
    store.activate(first.release_sha256, expected_current=None)
    with pytest.raises(MvpScoredReleaseError, match="CAS_MISMATCH"):
        store.activate(second.release_sha256, expected_current=None)
    store.activate(second.release_sha256, expected_current=first.release_sha256)
    pointer = store.rollback(expected_current=second.release_sha256)
    assert pointer.release_sha256 == first.release_sha256
    assert store.resolve_active() == first


def test_corrupt_partial_and_symlink_fail_closed(tmp_path: Path) -> None:
    root = tmp_path / "synthetic-mvp-releases"
    store = MvpScoredReleaseStore(root)
    snapshot = release(80)
    store.publish(snapshot)
    path = root / "releases" / snapshot.release_sha256 / "release.json"
    path.write_bytes(b'{"partial":')
    with pytest.raises(MvpScoredReleaseError, match="MVP_RELEASE_INVALID"):
        store.resolve_release(snapshot.release_sha256)

    root2 = tmp_path / "symlink-root"
    actual = tmp_path / "actual-root"
    actual.mkdir()
    root2.symlink_to(actual, target_is_directory=True)
    with pytest.raises(MvpScoredReleaseError, match="SYMLINK"):
        MvpScoredReleaseStore(root2).publish(release(80))


@pytest.mark.parametrize("target", ["release-directory", "release-file", "active-pointer"])
def test_nested_store_symlinks_fail_closed(tmp_path: Path, target: str) -> None:
    root = tmp_path / "synthetic-mvp-releases"
    store = MvpScoredReleaseStore(root)
    snapshot = release(80)
    store.publish(snapshot)
    external = tmp_path / "external"
    external.mkdir()
    release_directory = root / "releases" / snapshot.release_sha256
    if target == "release-directory":
        original = release_directory.rename(external / "release-directory")
        release_directory.symlink_to(original, target_is_directory=True)

        def action() -> object:
            return store.resolve_release(snapshot.release_sha256)
    elif target == "release-file":
        release_file = release_directory / "release.json"
        original = release_file.rename(external / "release.json")
        release_file.symlink_to(original)

        def action() -> object:
            return store.resolve_release(snapshot.release_sha256)
    else:
        store.activate(snapshot.release_sha256, expected_current=None)
        active = root / "active.json"
        original = active.rename(external / "active.json")
        active.symlink_to(original)
        action = store.active_pointer
    with pytest.raises(MvpScoredReleaseError):
        action()
