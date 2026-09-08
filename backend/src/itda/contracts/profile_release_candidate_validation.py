"""Pure-Python authority for canonical profile-release candidate payloads.

This module deliberately has no Pydantic, SQLAlchemy, or Alembic dependency so
the runtime contract and migration backfill can execute the exact same checks.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import re
from collections.abc import Mapping, Sequence
from typing import Any

_PRINCIPAL_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$", re.ASCII)
_RELEASE_ID_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$", re.ASCII)
_SHA256_PATTERN = re.compile(r"^[0-9a-f]{64}$", re.ASCII)

_CANDIDATE_FIELDS = frozenset(
    {
        "schema_version",
        "release_id",
        "state",
        "builder_principal",
        "canonical_lineage_sha256",
        "dev_lineage_sha256",
        "profile_schema_sha256",
        "label_freeze_sha256",
        "candidate_run_sha256",
        "reviewed_manifest_sha256",
        "rights_manifest_sha256",
        "source_manifest_sha256",
        "code_sha256",
        "config_sha256",
        "cohort",
        "release_sha256",
    }
)
_COHORT_FIELDS = frozenset(
    {
        "place_ref",
        "label_ready",
        "rights_ready",
        "evidence_ready",
        "description_lane",
        "odii_lane",
        "profile_sha256",
        "label_export_sha256",
        "candidate_manifest_sha256",
        "reviewed_evidence_manifest_sha256",
        "accepted_review_set_sha256",
        "rights_sha256",
        "source_sha256",
    }
)
_REQUIRED_TOP_DIGESTS = (
    "canonical_lineage_sha256",
    "dev_lineage_sha256",
    "profile_schema_sha256",
    "label_freeze_sha256",
    "candidate_run_sha256",
    "reviewed_manifest_sha256",
    "rights_manifest_sha256",
    "source_manifest_sha256",
    "code_sha256",
    "config_sha256",
)
_REQUIRED_MEMBER_DIGESTS = (
    "label_export_sha256",
    "candidate_manifest_sha256",
    "reviewed_evidence_manifest_sha256",
    "accepted_review_set_sha256",
    "rights_sha256",
    "source_sha256",
)


def _canonical_sha256(value: object) -> str:
    encoded = json.dumps(
        value,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
        allow_nan=False,
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _require_sha256(value: object, *, field_name: str) -> None:
    if not isinstance(value, str) or _SHA256_PATTERN.fullmatch(value) is None:
        raise ValueError(f"{field_name} must be one lower-case SHA-256 digest")


def validate_profile_release_candidate_payload_v1(
    payload: Mapping[str, object],
) -> dict[str, object]:
    """Validate and return the exact canonical v1 payload with a bound digest.

    ``release_sha256`` may be ``None`` only while a runtime model is being
    constructed.  The returned copy always contains the computed digest.
    """

    if not isinstance(payload, Mapping) or set(payload) != _CANDIDATE_FIELDS:
        raise ValueError("profile release candidate shape is invalid")
    normalized: dict[str, Any] = dict(payload)
    if normalized["schema_version"] != "itda.profile-release-candidate.v1":
        raise ValueError("profile release candidate schema version is invalid")
    if normalized["state"] != "BUILT_UNAPPROVED":
        raise ValueError("profile release candidate state is invalid")
    release_id = normalized["release_id"]
    builder_principal = normalized["builder_principal"]
    if (
        not isinstance(release_id, str)
        or _RELEASE_ID_PATTERN.fullmatch(release_id) is None
    ):
        raise ValueError("profile release ID is invalid")
    if (
        not isinstance(builder_principal, str)
        or _PRINCIPAL_PATTERN.fullmatch(builder_principal) is None
    ):
        raise ValueError("profile release builder principal is invalid")
    for field_name in _REQUIRED_TOP_DIGESTS:
        _require_sha256(normalized[field_name], field_name=field_name)

    cohort = normalized["cohort"]
    if (
        isinstance(cohort, (str, bytes, bytearray))
        or not isinstance(cohort, Sequence)
        or len(cohort) != 24
    ):
        raise ValueError("profile release requires exactly one complete DEV cohort of 24")
    normalized_members: list[dict[str, object]] = []
    place_refs: set[str] = set()
    profile_sha256s: set[str] = set()
    for raw_member in cohort:
        if not isinstance(raw_member, Mapping) or set(raw_member) != _COHORT_FIELDS:
            raise ValueError("profile release cohort member shape is invalid")
        member = dict(raw_member)
        place_ref = member["place_ref"]
        if not isinstance(place_ref, str) or not 1 <= len(place_ref) <= 200:
            raise ValueError("profile release cohort place reference is invalid")
        if any(
            member[field_name] is not True
            for field_name in ("label_ready", "rights_ready", "evidence_ready")
        ):
            raise ValueError("profile release cohort member is not gate-clean")
        if member["description_lane"] not in {"READY", "MISSING"}:
            raise ValueError("profile release description lane is invalid")
        if member["odii_lane"] not in {"READY", "MISSING"}:
            raise ValueError("profile release Odii lane is invalid")
        _require_sha256(member["profile_sha256"], field_name="profile_sha256")
        for field_name in _REQUIRED_MEMBER_DIGESTS:
            _require_sha256(member[field_name], field_name=field_name)
        place_refs.add(place_ref)
        profile_sha256s.add(str(member["profile_sha256"]))
        normalized_members.append(member)
    if len(place_refs) != 24:
        raise ValueError("profile release cohort members must be unique")
    if len(profile_sha256s) != 24:
        raise ValueError("profile release cohort profiles must be unique")
    normalized["cohort"] = normalized_members

    supplied_release_sha256 = normalized["release_sha256"]
    if supplied_release_sha256 is not None:
        _require_sha256(supplied_release_sha256, field_name="release_sha256")
    expected_release_sha256 = _canonical_sha256(
        {key: value for key, value in normalized.items() if key != "release_sha256"}
    )
    if supplied_release_sha256 is not None and not hmac.compare_digest(
        str(supplied_release_sha256), expected_release_sha256
    ):
        raise ValueError("profile release hash drifted from exact candidate bytes")
    normalized["release_sha256"] = expected_release_sha256
    return normalized
