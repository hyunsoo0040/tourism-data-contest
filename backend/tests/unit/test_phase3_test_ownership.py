"""Regression tests for Phase 3 pytest node ownership manifests."""

from __future__ import annotations

import pytest

from itda.cli.phase3_test_ownership import verify_node_ownership

LABEL_FILE = "tests/contract/test_label_revision.py"
RETENTION_FILE = "tests/contract/test_profile_release_retention_job.py"


def test_node_ownership_accepts_one_owner_per_collected_node() -> None:
    verify_node_ownership(
        {
            "fast": [f"{LABEL_FILE}::test_label"],
            "db": ["tests/integration/test_release.py::test_release"],
            "retention": [f"{RETENTION_FILE}::test_retention"],
            "contract": ["tests/contract/test_other.py::test_other"],
        },
        {LABEL_FILE: "fast", RETENTION_FILE: "retention"},
    )


def test_node_ownership_rejects_duplicate_hidden_by_directory_collection() -> None:
    duplicate = f"{LABEL_FILE}::test_label[param-with-control\ncharacter]"

    with pytest.raises(ValueError, match="duplicate pytest node ownership"):
        verify_node_ownership(
            {
                "fast": [duplicate],
                "contract": [duplicate],
                "retention": [f"{RETENTION_FILE}::test_retention"],
            },
            {LABEL_FILE: "fast", RETENTION_FILE: "retention"},
        )


def test_node_ownership_requires_expected_file_to_be_collected_by_its_owner() -> None:
    with pytest.raises(ValueError, match="no pytest nodes collected"):
        verify_node_ownership(
            {
                "fast": [f"{LABEL_FILE}::test_label"],
                "contract": ["tests/contract/test_other.py::test_other"],
            },
            {LABEL_FILE: "fast", RETENTION_FILE: "retention"},
        )
