"""Install an explicitly pinned PUBLIC snapshot without touching legacy active data."""

from __future__ import annotations

import json
import re
from collections.abc import Mapping
from pathlib import Path

from itda.authenticity.display_photos import load_display_photos
from itda.authenticity.release import Release, load_release
from itda.authenticity.repository import Repository, install_release
from itda.db.session import create_database_engine


def checked_public_release(environment: Mapping[str, str]) -> tuple[Path, Release]:
    directory = Path(environment["ITDA_AUTHENTICITY_RELEASE_DIR"])
    expected = environment["ITDA_AUTHENTICITY_RELEASE_SHA256"]
    places = int(environment["ITDA_AUTHENTICITY_EXPECTED_PLACES"])
    if not re.fullmatch(r"[0-9a-f]{64}", expected) or places < 1:
        raise ValueError("AUTHENTICITY_DEPLOYMENT_PIN_REQUIRED")
    release, _ = load_release(directory)
    # Optional display-only sidecar; never changes the installed analysis release.
    load_display_photos(directory)
    validation = json.loads((directory / "validation.json").read_text())
    if (
        release.scope != "PUBLIC"
        or release.release_sha256 != expected
        or len(release.members) != places
        or "publication_selection" not in validation
    ):
        raise ValueError("AUTHENTICITY_PUBLIC_DEPLOYMENT_PIN_MISMATCH")
    return directory, release


def ensure_initial_authenticity_release(
    environment: Mapping[str, str], *, admin_dsn: str
) -> dict[str, str | int]:
    directory, release = checked_public_release(environment)
    previous = environment.get("ITDA_AUTHENTICITY_PREVIOUS_RELEASE_SHA256", "NONE")
    if previous != "NONE" and not re.fullmatch(r"[0-9a-f]{64}", previous):
        raise ValueError("AUTHENTICITY_PREVIOUS_RELEASE_PIN_INVALID")
    engine = create_database_engine(admin_dsn)
    try:
        repository = Repository(engine)
        active = repository.active_release()
        if active is not None and active.release_sha256 == release.release_sha256:
            # Verify persisted content, rather than trusting just the pointer.
            stored, _ = repository.get_release(active.release_sha256)
            repository.auxiliary(stored)
            state = "retained"
        else:
            installed = install_release(
                engine,
                directory,
                expected_previous=None if previous == "NONE" else previous,
                activate=True,
            )
            if repository.active_release() != installed:
                raise ValueError("AUTHENTICITY_ACTIVATION_READBACK_MISMATCH")
            state = "activated"
        return {
            "state": state,
            "scope": release.scope,
            "places": len(release.members),
            "release_sha256": release.release_sha256,
        }
    finally:
        engine.dispose()
