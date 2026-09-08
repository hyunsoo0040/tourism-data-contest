"""Local-only authority grammar for retaining immutable NVIDIA V5 attempt 5.

The module deliberately has no CLI entry point and performs no transport during
plan construction or preflight.  A future caller must provide a separately
approved execution capability, a durably claimed journal, and an adapter.
"""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass, field, replace
from datetime import UTC, datetime
from pathlib import Path
from typing import Literal, cast

from itda.contracts.demo_profile_materialization import (
    NVIDIA_AUTHORITY_SHA256,
    NVIDIA_V5_ATTEMPT8_RESUME_AUTHORITY_SHA256,
    NVIDIA_V5_THREE_VALIDATED_RESUME_AUTHORITY_SHA256,
    NVIDIA_V5_TWO_PROBE_RESUME_AUTHORITY_SHA256,
    DemoSourceBundle,
    NvidiaMinimaxModelDerivedProfile,
    NvidiaMinimaxProfileAttempt,
    NvidiaMinimaxProfileMaterializationConfig,
    seal_demo_contract,
)
from itda.domain.canonical import canonical_json_bytes, canonical_sha256
from itda.domain.demo_profile_eligibility import (
    evaluate_nvidia_profile_publication,
    evaluate_nvidia_publication_cohort,
)
from itda.providers.nvidia_minimax_profile import (
    NvidiaAttemptLedger,
    NvidiaMinimaxProfileAdapter,
    NvidiaProfileAdapterResult,
)

from .demo_profile_materialization import (
    DemoProfileMaterializationError,
    DemoProfileMaterializationFailure,
    DurableNvidiaJournal,
    _nvidia_v5_lineage_for,
    _publish_private_files,
    _read_private_regular_file,
    _require_private_evidence_inventory,
    build_nvidia_v5_request_bytes,
    nvidia_v5_prompt_binding,
    validate_demo_source_inventory,
    verify_nvidia_v5_request_bytes,
)

ATTEMPT5_RETAINING_SCHEMA_VERSION = "itda.phase5-nvidia-v5-attempt5-retaining-authority.v1"
ATTEMPT5_RETAINING_RECEIPT_SCHEMA_VERSION = (
    "itda.phase5-nvidia-v5-attempt5-retaining-preflight-receipt.v1"
)
ATTEMPT5_RETAINING_EXECUTION_RECEIPT_SCHEMA_VERSION = (
    "itda.phase5-nvidia-v5-attempt5-retaining-materialization-receipt.v1"
)
ATTEMPT5_RETAINING_EXECUTION_APPROVAL_SCHEMA_VERSION = (
    "itda.phase5-nvidia-v5-attempt5-retaining-execution-approval.v1"
)
ATTEMPT5_RETAINING_MAX_NEW_HTTP_ATTEMPTS = 26
ATTEMPT5_RETAINING_MAX_CUMULATIVE_HTTP_ATTEMPTS = 34
ATTEMPT5_RETAINING_MAX_CONNECT_RETRIES = 3
ATTEMPT5_RETAINING_MINIMUM_INTERVAL_SECONDS = 60

_SOURCE_INVENTORY_SHA256 = "2245b16896f273b926bae4ee60efe09c3472271642c42b8ec0a6fcc40f99df1e"
_ACTIVE_POINTER_SHA256 = "9c3d28fb770b3c8b53acee419abdefe1fed21fb14d2854c9f2f5fd685566d0fc"
_PREDECESSOR_MANIFEST_SHA256 = "2fc09decd2ab9c57111f2bf2d20db1462e869cd9b0479d7a433522f9a8d80506"
_FAILURE_MANIFEST_SHA256 = "2e4de1046c269250f785bd305aeef11dcaaa02a4e7a2a77036f245220f5729d2"
_FAILURE_SHA256 = "d7f373f45036728e02f1f16526b893b2e8bf1d02daf27b835500a0f928fc0db7"
_ATTEMPT5_PLACE_ID = "place:119da6ea8756c8731f65f3fae9c5553ac16c8317f6688a68013cf3ead04916d8"
_ATTEMPT5_PROFILE_SHA256 = "4feff1d3e1c1bc727c6511d879706b0fbace2527c731d5e6df5580590f5596ae"
_ATTEMPT5_AUTHORITY_SHA256 = NVIDIA_V5_TWO_PROBE_RESUME_AUTHORITY_SHA256
_OUTER_PROCESS_AUTHORITY_SHA256 = "5f4c4c84e34b0032700b688ad66bba40a32821c3384c5265e95f508a71a50371"

_ATTEMPT_SHA256 = (
    "31951a8d0928261b3e5d88bcd8629613e662c3160af7c44d9d5c712dbfbde12b",
    "60266facd4cd0cacebd7b9ec161c5990e05185af7cd77e2578ed0300827a3a9d",
    "2871b6d1967c8b910855a1d583adf4d915aa518a4d6b2a3382a282bce7aedc63",
    "3cdd40d2c9615d8d833f2c17e70772d78d0493eed4a20774d2d45b8645a529c7",
    "7196ea968459e5adda5b5189708728ac96b4f870cd852508ef46b949eea8ea8b",
    "b978308d8605d581f83861644b63cd8b16d148b4c42a4b897f959dc61be51be8",
    "b7f330f21b83e7aa1056fb2d9b0e7f4205b285c84cc0827b20bcba110f49f438",
    "e028e8e5a26754bf7330ee9a6c2ef17a8c3512f2d3953825f568d3e8f2e09a7b",
)
_RESPONSE_SHA256 = (
    "a36c4649f1cae74f95f72d67baf76497313145907b0bed3e903b15c7a4744798",
    "0672a656dccbd0dffc75a1e32a28f7126d5b351d6285c815656ab1f2a44956fc",
    "4c662d2992cfef894291152d819212057b1ceba5ec175699f181f4ebe2a4f154",
    "17be0c4a166b295b18dd81be37a529e9b8bc8d6303bda62f44d8f16de3c94311",
    "6922b37d5f73590e437df5a9b802584b736382c72f9f6183736ec2cd64fad29f",
    "d805415abe66787220a2eabaaf865f8750d0235358485a790b51d7edffb8b876",
    "5fbb46d717e8f567a5d4a68557458ce6d70d7dabbeb94f9eefe574cc41d6a6f9",
    "a2bb47219a0f85673b63ad8f64ccdaa03d621658089e7a5e03eac9a5594a82f9",
)
_REQUEST_SHA256 = (
    "5caa5678525ae5c69a865cb89ad71d90a29b6f33bf0ddafddac49fe0a0f2aadc",
    "5caa5678525ae5c69a865cb89ad71d90a29b6f33bf0ddafddac49fe0a0f2aadc",
    "3f8ba29065922d51bb7592bc0e7402f2c4370a0784b816482232cc13bf81bb49",
    "4c081bb9bc9145242dd8796aace7fa4822b6a488ce44e516131ffdb423d1bcaf",
    "945fbfb904560eef36befe54574c0cccba101c335f22524fae3461a560487d23",
    "48a706dcddfd974953fc6d64dfed8acb202a2aac2498c446d45df127f00d3bc3",
    "28f67f56eaa5cdc5d8b3ee8563cd2057be12de203bf8b9aa9fd40ec9e350c623",
    "3f8e2f8619e245aba23d8048dc3b2398aa142bfe266a87d92200bf92ab241766",
)
_LINEAGE_AUTHORITY_BY_ATTEMPT = {
    3: _ATTEMPT5_AUTHORITY_SHA256,
    4: _ATTEMPT5_AUTHORITY_SHA256,
    5: _ATTEMPT5_AUTHORITY_SHA256,
    6: _ATTEMPT5_AUTHORITY_SHA256,
    7: NVIDIA_V5_THREE_VALIDATED_RESUME_AUTHORITY_SHA256,
    8: NVIDIA_V5_ATTEMPT8_RESUME_AUTHORITY_SHA256,
}
_PREDECESSOR_FILES = {
    "authority.json": "5188d69a663cdb3fa433863c8fb27d35ae7fcfc3a8118f5626f249f4327806ef",
    "live-start/live-start.json": (
        "4af961f7392513a952f2874d05ca43459689f8c9128defe647adfc53da3235a1"
    ),
    (
        "reservations/08-ac8302059f9cdf24a956a1077b4eec20c74d37670b183a491100ca4828a90cb5/"
        "reservation.json"
    ): ("7b3ef9b4def865a40a4a5a7963d98620577bb6b1e00fbe35d4832e0c15e297cb"),
    "attempts/08-e028e8e5a26754bf7330ee9a6c2ef17a8c3512f2d3953825f568d3e8f2e09a7b/attempt.json": (
        "5590dd7126d653f13e0d8eb460ca212dcfca3cdd5ae651f83d4ba29eed1e35d6"
    ),
    (
        "attempts/08-e028e8e5a26754bf7330ee9a6c2ef17a8c3512f2d3953825f568d3e8f2e09a7b/"
        "raw-response.bin"
    ): (_RESPONSE_SHA256[7]),
    "terminal/terminal.json": "5b53a40e7adae8646f3207383837e20d8661548a110da96d826c9684215760e3",
}
_FAILURE_FILES = {
    "attempts.json": "5880bf10ec64a1f42e3a0a11a6d1928bbc46bb5c6794869757a0b22b49bddad6",
    "failure.json": "6a6ba1e2bb7da2960bd45561a2091fe0792d2e9459546632580472b093a674f4",
    **{
        f"raw-{attempt_sha256}.bin": response_sha256
        for attempt_sha256, response_sha256 in zip(_ATTEMPT_SHA256, _RESPONSE_SHA256, strict=True)
    },
}
_EXPECTED_ELIGIBILITY = {3: False, 4: False, 5: True, 6: False, 7: False, 8: False}
_CONSUMED_AUTHORITY_OUTCOMES = (
    {
        "authority_sha256": "eb8ae4a76babea5012eeccc49e6484deabda17c373ddb3d55167f3bdda1277f2",
        "attempt_numbers": [1],
        "outcome": "CONSUMED_TERMINAL_INVALID_NO_REPLAY",
    },
    {
        "authority_sha256": "d35af02c8865a2f03561bd52024c6934bf39373298ea9def54d3c55c2f1cce7e",
        "attempt_numbers": [2],
        "outcome": "CONSUMED_TERMINAL_INVALID_NO_REPLAY",
    },
    {
        "authority_sha256": _ATTEMPT5_AUTHORITY_SHA256,
        "attempt_numbers": [3, 4, 5, 6],
        "outcome": "CONSUMED_ATTEMPT5_ONLY_ELIGIBLE_NO_HTTP_REPLAY",
    },
    {
        "authority_sha256": NVIDIA_V5_THREE_VALIDATED_RESUME_AUTHORITY_SHA256,
        "attempt_numbers": [7],
        "outcome": "CONSUMED_TERMINAL_INVALID_NO_REPLAY",
    },
    {
        "authority_sha256": NVIDIA_V5_ATTEMPT8_RESUME_AUTHORITY_SHA256,
        "attempt_numbers": [8],
        "outcome": "CONSUMED_TERMINAL_INVALID_NO_REPLAY",
    },
    {
        "authority_sha256": _OUTER_PROCESS_AUTHORITY_SHA256,
        "attempt_numbers": [8],
        "outcome": "CONSUMED_PROCESS_AUTHORITY_NEVER_RESTART",
    },
)
_SHA_PATTERN = re.compile(r"^[0-9a-f]{64}$")
_GIT_SHA_PATTERN = re.compile(r"^[0-9a-f]{40,64}$")


@dataclass(frozen=True, slots=True)
class Attempt5RetainingPlan:
    retained_profile: NvidiaMinimaxModelDerivedProfile
    retained_resume_authority_sha256: str
    predecessor_attempts: tuple[NvidiaMinimaxProfileAttempt, ...]
    predecessor_raw_responses: tuple[tuple[str, bytes], ...] = field(repr=False)
    eligibility_by_attempt: Mapping[int, bool]
    remaining_place_ids: tuple[str, ...]
    v5_request_sha256_by_place: Mapping[str, str]
    schema_example_sha256_by_place: Mapping[str, str]
    all_v5_request_manifest_sha256: str
    remaining_v5_request_manifest_sha256: str
    all_schema_example_manifest_sha256: str
    remaining_schema_example_manifest_sha256: str
    predecessor_file_sha256: Mapping[str, str]
    predecessor_manifest_sha256: str
    failure_file_sha256: Mapping[str, str]
    failure_manifest_sha256: str
    active_pointer_sha256: str
    state_sha256: str


@dataclass(frozen=True, slots=True)
class Attempt5RetainingAuthority:
    text: str
    canonical_bytes: bytes = field(repr=False)
    authority_sha256: str
    receipt: Mapping[str, object]


@dataclass(frozen=True, slots=True)
class Attempt5RetainingExecutionApproval:
    text: str
    canonical_bytes: bytes = field(repr=False)
    approval_sha256: str
    receipt: Mapping[str, object]


@dataclass(frozen=True, slots=True)
class Attempt5RetainingProfileLineage:
    place_id: str
    role: Literal["RETAINED_ATTEMPT5", "NEW_DEV23"]
    profile_sha256: str
    attempt_number: int
    attempt_sha256: str
    request_sha256: str
    response_sha256: str
    resume_authority_sha256: str
    lineage_sha256: str


@dataclass(frozen=True, slots=True)
class Attempt5RetainingExecutionResult:
    profiles: tuple[NvidiaMinimaxModelDerivedProfile, ...]
    attempts: tuple[NvidiaMinimaxProfileAttempt, ...]
    profile_lineage: tuple[Attempt5RetainingProfileLineage, ...]
    authority_sha256: str
    receipt: Mapping[str, object]


def _hash_inventory(root: Path, expected: Mapping[str, str], *, error_code: str) -> dict[str, str]:
    _require_private_evidence_inventory(
        root=root,
        expected_files=set(expected),
        error_code=error_code,
    )
    actual = {
        relative: hashlib.sha256(
            _read_private_regular_file(root / relative, maximum_bytes=2 * 1024 * 1024)
        ).hexdigest()
        for relative in sorted(expected)
    }
    if actual != dict(expected):
        raise DemoProfileMaterializationError(error_code)
    return actual


def _plan_state_payload(plan: Attempt5RetainingPlan) -> dict[str, object]:
    return {
        "schema_version": "itda.phase5-nvidia-v5-attempt5-retaining-state.v1",
        "retained_profile_sha256": plan.retained_profile.profile_sha256,
        "retained_place_id": plan.retained_profile.place_id,
        "retained_resume_authority_sha256": plan.retained_resume_authority_sha256,
        "predecessor_attempt_sha256": [
            attempt.attempt_sha256 for attempt in plan.predecessor_attempts
        ],
        "predecessor_request_sha256": [
            attempt.request_sha256 for attempt in plan.predecessor_attempts
        ],
        "predecessor_response_sha256": [
            attempt.response_sha256 for attempt in plan.predecessor_attempts
        ],
        "eligibility_by_attempt": {
            str(number): eligible
            for number, eligible in sorted(plan.eligibility_by_attempt.items())
        },
        "remaining_place_ids": list(plan.remaining_place_ids),
        "all_v5_request_manifest_sha256": plan.all_v5_request_manifest_sha256,
        "remaining_v5_request_manifest_sha256": plan.remaining_v5_request_manifest_sha256,
        "all_schema_example_manifest_sha256": plan.all_schema_example_manifest_sha256,
        "remaining_schema_example_manifest_sha256": (plan.remaining_schema_example_manifest_sha256),
        "predecessor_file_sha256": dict(plan.predecessor_file_sha256),
        "predecessor_manifest_sha256": plan.predecessor_manifest_sha256,
        "failure_sha256": _FAILURE_SHA256,
        "failure_file_sha256": dict(plan.failure_file_sha256),
        "failure_manifest_sha256": plan.failure_manifest_sha256,
        "active_pointer_sha256": plan.active_pointer_sha256,
    }


def build_attempt5_retaining_plan(
    *,
    source_bundles: Sequence[DemoSourceBundle],
    predecessor_root: Path,
    failure_root: Path,
    active_pointer_path: Path,
) -> Attempt5RetainingPlan:
    """Reconstruct exact attempt-5 eligibility without replaying any HTTP request."""

    bundles = validate_demo_source_inventory(source_bundles)
    if (
        canonical_sha256([bundle.source_bundle_sha256 for bundle in bundles])
        != _SOURCE_INVENTORY_SHA256
    ):
        raise DemoProfileMaterializationError("NVIDIA_ATTEMPT5_RETAINING_SOURCE_DRIFT")
    predecessor_files = _hash_inventory(
        predecessor_root,
        _PREDECESSOR_FILES,
        error_code="NVIDIA_ATTEMPT5_RETAINING_PREDECESSOR_DRIFT",
    )
    failure_files = _hash_inventory(
        failure_root,
        _FAILURE_FILES,
        error_code="NVIDIA_ATTEMPT5_RETAINING_FAILURE_DRIFT",
    )
    if (
        canonical_sha256(predecessor_files) != _PREDECESSOR_MANIFEST_SHA256
        or canonical_sha256(failure_files) != _FAILURE_MANIFEST_SHA256
    ):
        raise DemoProfileMaterializationError("NVIDIA_ATTEMPT5_RETAINING_MANIFEST_DRIFT")
    active_pointer_sha256 = hashlib.sha256(
        _read_private_regular_file(active_pointer_path, maximum_bytes=1_048_576)
    ).hexdigest()
    if active_pointer_sha256 != _ACTIVE_POINTER_SHA256:
        raise DemoProfileMaterializationError("NVIDIA_ATTEMPT5_RETAINING_ACTIVE_POINTER_DRIFT")

    attempts_raw = _read_private_regular_file(
        failure_root / "attempts.json", maximum_bytes=2 * 1024 * 1024
    )
    try:
        attempt_rows = json.loads(attempts_raw)
        attempts = tuple(NvidiaMinimaxProfileAttempt.model_validate(row) for row in attempt_rows)
    except Exception as error:
        raise DemoProfileMaterializationError(
            "NVIDIA_ATTEMPT5_RETAINING_ATTEMPTS_INVALID"
        ) from error
    if (
        canonical_json_bytes(attempt_rows) != attempts_raw
        or tuple(attempt.attempt_number for attempt in attempts) != tuple(range(1, 9))
        or tuple(attempt.attempt_sha256 for attempt in attempts) != _ATTEMPT_SHA256
        or tuple(attempt.request_sha256 for attempt in attempts) != _REQUEST_SHA256
        or tuple(attempt.response_sha256 for attempt in attempts) != _RESPONSE_SHA256
        or any(attempt.retry for attempt in attempts)
    ):
        raise DemoProfileMaterializationError("NVIDIA_ATTEMPT5_RETAINING_ATTEMPT_DRIFT")
    raw_by_attempt = {
        attempt.attempt_sha256: _read_private_regular_file(
            failure_root / f"raw-{attempt.attempt_sha256}.bin", maximum_bytes=1_048_576
        )
        for attempt in attempts
    }
    if any(
        hashlib.sha256(raw_by_attempt[attempt.attempt_sha256]).hexdigest()
        != attempt.response_sha256
        for attempt in attempts
    ):
        raise DemoProfileMaterializationError("NVIDIA_ATTEMPT5_RETAINING_RAW_DRIFT")

    by_id = {bundle.place_id: bundle for bundle in bundles}
    replay_adapter = NvidiaMinimaxProfileAdapter(
        secret="local-attempt5-eligibility-reconstruction-only",
        ledger=NvidiaAttemptLedger.for_v5_two_probe_resume(),
    )
    retained: NvidiaMinimaxModelDerivedProfile | None = None
    eligibility: dict[int, bool] = {}
    for attempt in attempts[2:]:
        bundle = by_id.get(attempt.place_id)
        if bundle is None:
            raise DemoProfileMaterializationError("NVIDIA_ATTEMPT5_RETAINING_MEMBERSHIP_INVALID")
        lineage = _nvidia_v5_lineage_for(
            bundle,
            replay_adapter.config,
            resume_authority_sha256=_LINEAGE_AUTHORITY_BY_ATTEMPT[attempt.attempt_number],
        )
        lineage["created_at"] = attempt.started_at.isoformat().replace("+00:00", "Z")
        if attempt.request_sha256 != lineage["request_sha256"]:
            raise DemoProfileMaterializationError(
                "NVIDIA_ATTEMPT5_RETAINING_REPLAY_LINEAGE_INVALID"
            )
        replayed = replay_adapter.validate_replay_raw_response(
            place_id=attempt.place_id,
            raw_response=raw_by_attempt[attempt.attempt_sha256],
            lineage=lineage,
        )
        is_eligible = replayed.candidate is not None
        eligibility[attempt.attempt_number] = is_eligible
        if is_eligible:
            if attempt.attempt_number != 5 or retained is not None:
                raise DemoProfileMaterializationError("NVIDIA_ATTEMPT5_RETAINING_ELIGIBILITY_DRIFT")
            retained = replayed.candidate
    if eligibility != _EXPECTED_ELIGIBILITY or retained is None:
        raise DemoProfileMaterializationError("NVIDIA_ATTEMPT5_RETAINING_ELIGIBILITY_DRIFT")
    if (
        retained.place_id != _ATTEMPT5_PLACE_ID
        or retained.profile_sha256 != _ATTEMPT5_PROFILE_SHA256
        or retained.schema_version != "itda.nvidia-minimax-model-derived-profile.v5"
        or not evaluate_nvidia_profile_publication(retained.model_dump(mode="json")).eligible
    ):
        raise DemoProfileMaterializationError("NVIDIA_ATTEMPT5_RETAINING_PROFILE_DRIFT")

    remaining = tuple(bundle.place_id for bundle in bundles if bundle.place_id != retained.place_id)
    config = NvidiaMinimaxProfileMaterializationConfig()
    requests = {
        bundle.place_id: hashlib.sha256(build_nvidia_v5_request_bytes(bundle, config)).hexdigest()
        for bundle in bundles
    }
    examples = {
        bundle.place_id: cast(str, nvidia_v5_prompt_binding(bundle)["schema_example_sha256"])
        for bundle in bundles
    }
    remaining_requests = {place_id: requests[place_id] for place_id in remaining}
    remaining_examples = {place_id: examples[place_id] for place_id in remaining}
    if len(remaining) != 23 or remaining != tuple(
        bundle.place_id for bundle in bundles if bundle.place_id != _ATTEMPT5_PLACE_ID
    ):
        raise DemoProfileMaterializationError("NVIDIA_ATTEMPT5_RETAINING_MEMBERSHIP_INVALID")

    provisional = Attempt5RetainingPlan(
        retained_profile=retained,
        retained_resume_authority_sha256=_ATTEMPT5_AUTHORITY_SHA256,
        predecessor_attempts=attempts,
        predecessor_raw_responses=tuple(
            (attempt.attempt_sha256, raw_by_attempt[attempt.attempt_sha256]) for attempt in attempts
        ),
        eligibility_by_attempt=eligibility,
        remaining_place_ids=remaining,
        v5_request_sha256_by_place=requests,
        schema_example_sha256_by_place=examples,
        all_v5_request_manifest_sha256=canonical_sha256(requests),
        remaining_v5_request_manifest_sha256=canonical_sha256(remaining_requests),
        all_schema_example_manifest_sha256=canonical_sha256(examples),
        remaining_schema_example_manifest_sha256=canonical_sha256(remaining_examples),
        predecessor_file_sha256=predecessor_files,
        predecessor_manifest_sha256=_PREDECESSOR_MANIFEST_SHA256,
        failure_file_sha256=failure_files,
        failure_manifest_sha256=_FAILURE_MANIFEST_SHA256,
        active_pointer_sha256=active_pointer_sha256,
        state_sha256="0" * 64,
    )
    return replace(
        provisional,
        state_sha256=canonical_sha256(_plan_state_payload(provisional)),
    )


def _validate_plan(
    source_bundles: Sequence[DemoSourceBundle], plan: Attempt5RetainingPlan
) -> tuple[DemoSourceBundle, ...]:
    bundles = validate_demo_source_inventory(source_bundles)
    raw_by_attempt = dict(plan.predecessor_raw_responses)
    expected_remaining = tuple(
        bundle.place_id for bundle in bundles if bundle.place_id != _ATTEMPT5_PLACE_ID
    )
    profile_payload = plan.retained_profile.model_dump(mode="json")
    if (
        canonical_sha256([bundle.source_bundle_sha256 for bundle in bundles])
        != _SOURCE_INVENTORY_SHA256
        or tuple(attempt.attempt_number for attempt in plan.predecessor_attempts)
        != tuple(range(1, 9))
        or tuple(attempt.attempt_sha256 for attempt in plan.predecessor_attempts) != _ATTEMPT_SHA256
        or tuple(attempt.request_sha256 for attempt in plan.predecessor_attempts) != _REQUEST_SHA256
        or tuple(attempt.response_sha256 for attempt in plan.predecessor_attempts)
        != _RESPONSE_SHA256
        or set(raw_by_attempt) != set(_ATTEMPT_SHA256)
        or any(
            hashlib.sha256(raw_by_attempt[attempt.attempt_sha256]).hexdigest()
            != attempt.response_sha256
            for attempt in plan.predecessor_attempts
        )
        or dict(plan.eligibility_by_attempt) != _EXPECTED_ELIGIBILITY
        or plan.retained_resume_authority_sha256 != _ATTEMPT5_AUTHORITY_SHA256
        or plan.retained_profile.place_id != _ATTEMPT5_PLACE_ID
        or plan.retained_profile.profile_sha256 != _ATTEMPT5_PROFILE_SHA256
        or plan.retained_profile.schema_version != "itda.nvidia-minimax-model-derived-profile.v5"
        or canonical_sha256(
            plan.retained_profile.model_dump(mode="json", exclude={"profile_sha256"})
        )
        != plan.retained_profile.profile_sha256
        or not evaluate_nvidia_profile_publication(profile_payload).eligible
        or plan.retained_profile.request_sha256 != _REQUEST_SHA256[4]
        or plan.retained_profile.response_sha256 != _RESPONSE_SHA256[4]
        or plan.remaining_place_ids != expected_remaining
        or len(plan.remaining_place_ids) != 23
        or canonical_sha256(dict(plan.v5_request_sha256_by_place))
        != plan.all_v5_request_manifest_sha256
        or canonical_sha256(dict(plan.schema_example_sha256_by_place))
        != plan.all_schema_example_manifest_sha256
        or canonical_sha256(
            {
                place_id: plan.v5_request_sha256_by_place[place_id]
                for place_id in plan.remaining_place_ids
            }
        )
        != plan.remaining_v5_request_manifest_sha256
        or canonical_sha256(
            {
                place_id: plan.schema_example_sha256_by_place[place_id]
                for place_id in plan.remaining_place_ids
            }
        )
        != plan.remaining_schema_example_manifest_sha256
        or dict(plan.predecessor_file_sha256) != _PREDECESSOR_FILES
        or plan.predecessor_manifest_sha256 != _PREDECESSOR_MANIFEST_SHA256
        or canonical_sha256(dict(plan.predecessor_file_sha256)) != _PREDECESSOR_MANIFEST_SHA256
        or dict(plan.failure_file_sha256) != _FAILURE_FILES
        or plan.failure_manifest_sha256 != _FAILURE_MANIFEST_SHA256
        or canonical_sha256(dict(plan.failure_file_sha256)) != _FAILURE_MANIFEST_SHA256
        or plan.active_pointer_sha256 != _ACTIVE_POINTER_SHA256
        or canonical_sha256(_plan_state_payload(plan)) != plan.state_sha256
    ):
        raise ValueError("NVIDIA_ATTEMPT5_RETAINING_PLAN_DRIFT")
    return bundles


def _authority_payload(
    *,
    source_bundles: Sequence[DemoSourceBundle],
    plan: Attempt5RetainingPlan,
    implementation_commit: str,
    implementation_tree: str,
) -> dict[str, object]:
    bundles = _validate_plan(source_bundles, plan)
    if not _GIT_SHA_PATTERN.fullmatch(implementation_commit) or not _GIT_SHA_PATTERN.fullmatch(
        implementation_tree
    ):
        raise ValueError("NVIDIA_ATTEMPT5_RETAINING_IMPLEMENTATION_IDENTITY_INVALID")
    config = NvidiaMinimaxProfileMaterializationConfig()
    binding = nvidia_v5_prompt_binding(bundles[0])
    profile_lineage = _nvidia_v5_lineage_for(bundles[0], config)
    request_config_sha256 = cast(str, profile_lineage["config_sha256"])
    execution_budget_config = {
        "provider_request_config_sha256": request_config_sha256,
        "historical_attempt_count": 8,
        "new_http_attempt_cap": ATTEMPT5_RETAINING_MAX_NEW_HTTP_ATTEMPTS,
        "cumulative_http_attempt_cap": ATTEMPT5_RETAINING_MAX_CUMULATIVE_HTTP_ATTEMPTS,
    }
    return {
        "schema_version": ATTEMPT5_RETAINING_SCHEMA_VERSION,
        "implementation_commit": implementation_commit,
        "implementation_tree": implementation_tree,
        "provider_lane": config.provider_lane,
        "endpoint": config.endpoint,
        "model": config.model,
        "prompt_version": "phase5-demo-profile-sentinel-json.v5",
        "prompt_sha256": binding["prompt_sha256"],
        "profile_schema_sha256": profile_lineage["profile_schema_sha256"],
        "provider_request_config_sha256": request_config_sha256,
        "provider_request_config_max_http_attempts": config.max_http_attempts,
        "execution_ledger_max_attempts": ATTEMPT5_RETAINING_MAX_CUMULATIVE_HTTP_ATTEMPTS,
        "execution_budget_config_sha256": canonical_sha256(execution_budget_config),
        "source_inventory_sha256": _SOURCE_INVENTORY_SHA256,
        "dev_place_ids": [bundle.place_id for bundle in bundles],
        "plan_state_sha256": plan.state_sha256,
        "predecessor_manifest_sha256": plan.predecessor_manifest_sha256,
        "failure_sha256": _FAILURE_SHA256,
        "failure_manifest_sha256": plan.failure_manifest_sha256,
        "active_pointer_sha256": plan.active_pointer_sha256,
        "consumed_authority_outcomes": list(_CONSUMED_AUTHORITY_OUTCOMES),
        "consumed_attempt_count": 8,
        "consumed_attempt_sha256": [
            attempt.attempt_sha256 for attempt in plan.predecessor_attempts
        ],
        "consumed_request_sha256": [
            attempt.request_sha256 for attempt in plan.predecessor_attempts
        ],
        "consumed_response_sha256": [
            attempt.response_sha256 for attempt in plan.predecessor_attempts
        ],
        "eligibility_by_attempt": {
            str(number): eligible
            for number, eligible in sorted(plan.eligibility_by_attempt.items())
        },
        "retained_profile": {
            "place_id": plan.retained_profile.place_id,
            "profile_sha256": plan.retained_profile.profile_sha256,
            "attempt_number": 5,
            "attempt_sha256": plan.predecessor_attempts[4].attempt_sha256,
            "request_sha256": plan.retained_profile.request_sha256,
            "response_sha256": plan.retained_profile.response_sha256,
            "resume_authority_sha256": plan.retained_resume_authority_sha256,
            "schema_version": plan.retained_profile.schema_version,
        },
        "retained_count": 1,
        "remaining_count": 23,
        "remaining_place_ids": list(plan.remaining_place_ids),
        "remaining_membership_sha256": canonical_sha256(list(plan.remaining_place_ids)),
        "all_v5_request_manifest_sha256": plan.all_v5_request_manifest_sha256,
        "remaining_v5_request_manifest_sha256": plan.remaining_v5_request_manifest_sha256,
        "all_schema_example_manifest_sha256": plan.all_schema_example_manifest_sha256,
        "remaining_schema_example_manifest_sha256": (plan.remaining_schema_example_manifest_sha256),
        "future_profile_lineage_policy": (
            "EXPLICIT_PER_PROFILE_V5_AUTHORITY_ATTEMPT_REQUEST_RESPONSE_PROFILE"
        ),
        "mixed_v4_v5_lineage_allowed": False,
        "historical_attempt_http_replay_allowed": False,
        "next_attempt_number": 9,
        "new_http_attempt_cap": ATTEMPT5_RETAINING_MAX_NEW_HTTP_ATTEMPTS,
        "first_pass_request_count": 23,
        "connect_retry_max_per_place": 1,
        "connect_retry_max_total": ATTEMPT5_RETAINING_MAX_CONNECT_RETRIES,
        "connect_retry_classes": ["ConnectError", "ConnectTimeout"],
        "connect_failure_consumes_reservation": True,
        "connect_failure_cost_exposure": "ONE_REQUEST_EQUIVALENT_UNKNOWN_PRICE",
        "cumulative_http_attempt_cap": ATTEMPT5_RETAINING_MAX_CUMULATIVE_HTTP_ATTEMPTS,
        "minimum_interval_seconds": ATTEMPT5_RETAINING_MINIMUM_INTERVAL_SECONDS,
        "whole_attempt_timeout_seconds": 300,
        "first_429_policy": "CIRCUIT_BREAK_BATCH_NO_RETRY",
        "terminal_invalid_policy": "CIRCUIT_BREAK_BATCH_NO_RETRY",
        "http_5xx_policy": "CIRCUIT_BREAK_BATCH_NO_RETRY",
        "read_write_transport_policy": "CIRCUIT_BREAK_BATCH_NO_RETRY",
        "deadline_policy": "CIRCUIT_BREAK_BATCH_NO_RETRY",
        "single_live_invocation": True,
        "durable_claim_required": True,
        "split": "DEV_ONLY",
        "blind_excluded": True,
        "generation_allowed_before_exact_24_v5": False,
        "activation_allowed_before_exact_24_v5": False,
        "execution_approval_required": True,
        "provider_execution_approved": False,
        "trusted_execution_decision_root_installed": False,
        "trusted_execution_decision_root_path": (
            "execution-approvals/<EXACT_AUTHORITY_SHA256>/trusted-decision-record.sha256"
        ),
        "trusted_execution_decision_root_install_policy": (
            "ABSENT_UNTIL_SEPARATE_HUMAN_APPROVAL_THEN_PRIVATE_IMMUTABLE_LOCAL_INSTALL"
        ),
        "preflight_command_grammar": (
            "nvidia-v5-attempt5-retaining-preflight --authority-text <EXACT_TEXT> "
            "--authority-sha256 <EXACT_SHA256>"
        ),
        "live_command_grammar": (
            "nvidia-v5-attempt5-retaining-live --authority-text <EXACT_TEXT> "
            "--authority-sha256 <EXACT_SHA256> --execution-approval-text "
            "<EXACT_SEPARATE_APPROVAL_TEXT> --execution-approval-sha256 "
            "<SEPARATE_APPROVAL_SHA256> --secret-env-file .secrets/itda-api.env"
        ),
        "network_attempted": False,
    }


def derive_attempt5_retaining_authority(
    *,
    source_bundles: Sequence[DemoSourceBundle],
    plan: Attempt5RetainingPlan,
    implementation_commit: str,
    implementation_tree: str,
) -> Attempt5RetainingAuthority:
    payload = _authority_payload(
        source_bundles=source_bundles,
        plan=plan,
        implementation_commit=implementation_commit,
        implementation_tree=implementation_tree,
    )
    authority_bytes = canonical_json_bytes(payload)
    authority_sha256 = hashlib.sha256(authority_bytes).hexdigest()
    receipt: dict[str, object] = {
        **payload,
        "schema_version": ATTEMPT5_RETAINING_RECEIPT_SCHEMA_VERSION,
        "authority_text": authority_bytes.decode("utf-8"),
        "authority_text_bytes": len(authority_bytes),
        "authority_sha256": authority_sha256,
    }
    receipt["receipt_sha256"] = canonical_sha256(receipt)
    return Attempt5RetainingAuthority(
        text=authority_bytes.decode("utf-8"),
        canonical_bytes=authority_bytes,
        authority_sha256=authority_sha256,
        receipt=receipt,
    )


def _reject_duplicate_pairs(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate authority field")
        result[key] = value
    return result


def preflight_attempt5_retaining_authority(
    *,
    authority_text: str,
    authority_sha256: str,
    source_bundles: Sequence[DemoSourceBundle],
    plan: Attempt5RetainingPlan,
    implementation_commit: str,
    implementation_tree: str,
) -> Mapping[str, object]:
    """Perform a canonical, duplicate-rejecting, network-free preflight."""

    try:
        parsed = json.loads(authority_text, object_pairs_hook=_reject_duplicate_pairs)
    except (UnicodeError, ValueError, json.JSONDecodeError) as error:
        raise PermissionError("NVIDIA_ATTEMPT5_RETAINING_AUTHORITY_INVALID") from error
    expected = derive_attempt5_retaining_authority(
        source_bundles=source_bundles,
        plan=plan,
        implementation_commit=implementation_commit,
        implementation_tree=implementation_tree,
    )
    supplied_bytes = authority_text.encode("utf-8")
    if (
        not isinstance(parsed, dict)
        or canonical_json_bytes(parsed) != supplied_bytes
        or authority_text != expected.text
        or authority_sha256 != expected.authority_sha256
        or hashlib.sha256(supplied_bytes).hexdigest() != authority_sha256
    ):
        raise PermissionError("NVIDIA_ATTEMPT5_RETAINING_AUTHORITY_MISMATCH")
    return expected.receipt


def derive_attempt5_retaining_execution_approval(
    *,
    authority: Attempt5RetainingAuthority,
    decision_record_sha256: str,
) -> Attempt5RetainingExecutionApproval:
    """Derive the future checkpoint artifact bound to one exact authority."""

    authority_receipt_sha256 = authority.receipt.get("receipt_sha256")
    if (
        not _SHA_PATTERN.fullmatch(decision_record_sha256)
        or not isinstance(authority_receipt_sha256, str)
        or not _SHA_PATTERN.fullmatch(authority_receipt_sha256)
        or decision_record_sha256 in {authority.authority_sha256, authority_receipt_sha256}
    ):
        raise ValueError("NVIDIA_ATTEMPT5_RETAINING_DECISION_RECORD_INVALID")
    payload: dict[str, object] = {
        "schema_version": ATTEMPT5_RETAINING_EXECUTION_APPROVAL_SCHEMA_VERSION,
        "decision": "APPROVE_EXACT_SINGLE_PROVIDER_EXECUTION",
        "decision_record_sha256": decision_record_sha256,
        "authority_sha256": authority.authority_sha256,
        "authority_receipt_sha256": authority_receipt_sha256,
        "implementation_commit": authority.receipt.get("implementation_commit"),
        "implementation_tree": authority.receipt.get("implementation_tree"),
        "provider_lane": authority.receipt.get("provider_lane"),
        "endpoint": authority.receipt.get("endpoint"),
        "model": authority.receipt.get("model"),
        "new_http_attempt_cap": ATTEMPT5_RETAINING_MAX_NEW_HTTP_ATTEMPTS,
        "cumulative_http_attempt_cap": ATTEMPT5_RETAINING_MAX_CUMULATIVE_HTTP_ATTEMPTS,
        "cost_exposure": "MAX_26_UNKNOWN_PRICE_REQUEST_EQUIVALENTS",
        "single_live_invocation": True,
        "provider_execution_approved": True,
    }
    approval_bytes = canonical_json_bytes(payload)
    approval_sha256 = hashlib.sha256(approval_bytes).hexdigest()
    receipt: dict[str, object] = {
        **payload,
        "approval_text": approval_bytes.decode("utf-8"),
        "approval_text_bytes": len(approval_bytes),
        "approval_sha256": approval_sha256,
    }
    receipt["receipt_sha256"] = canonical_sha256(receipt)
    return Attempt5RetainingExecutionApproval(
        text=approval_bytes.decode("utf-8"),
        canonical_bytes=approval_bytes,
        approval_sha256=approval_sha256,
        receipt=receipt,
    )


def preflight_attempt5_retaining_execution_approval(
    *,
    authority: Attempt5RetainingAuthority,
    approval_text: str,
    approval_sha256: str,
    trusted_decision_record_sha256: str | None,
) -> Mapping[str, object]:
    """Validate canonical approval bytes and their exact authority/scope binding."""

    if trusted_decision_record_sha256 is None:
        raise PermissionError("NVIDIA_ATTEMPT5_RETAINING_TRUSTED_DECISION_ROOT_REQUIRED")
    try:
        parsed = json.loads(approval_text, object_pairs_hook=_reject_duplicate_pairs)
    except (UnicodeError, ValueError, json.JSONDecodeError) as error:
        raise PermissionError("NVIDIA_ATTEMPT5_RETAINING_EXECUTION_APPROVAL_INVALID") from error
    decision_record_sha256 = (
        parsed.get("decision_record_sha256") if isinstance(parsed, dict) else None
    )
    if not isinstance(decision_record_sha256, str):
        raise PermissionError("NVIDIA_ATTEMPT5_RETAINING_EXECUTION_APPROVAL_INVALID")
    if decision_record_sha256 != trusted_decision_record_sha256:
        raise PermissionError("NVIDIA_ATTEMPT5_RETAINING_TRUSTED_DECISION_ROOT_MISMATCH")
    try:
        expected = derive_attempt5_retaining_execution_approval(
            authority=authority,
            decision_record_sha256=decision_record_sha256,
        )
    except ValueError as error:
        raise PermissionError("NVIDIA_ATTEMPT5_RETAINING_EXECUTION_APPROVAL_INVALID") from error
    supplied_bytes = approval_text.encode("utf-8")
    if (
        canonical_json_bytes(parsed) != supplied_bytes
        or approval_text != expected.text
        or approval_sha256 != expected.approval_sha256
        or hashlib.sha256(supplied_bytes).hexdigest() != approval_sha256
    ):
        raise PermissionError("NVIDIA_ATTEMPT5_RETAINING_EXECUTION_APPROVAL_MISMATCH")
    return expected.receipt


def _profile_lineage(
    *,
    profile: NvidiaMinimaxModelDerivedProfile,
    attempt: NvidiaMinimaxProfileAttempt,
    role: Literal["RETAINED_ATTEMPT5", "NEW_DEV23"],
    resume_authority_sha256: str,
) -> Attempt5RetainingProfileLineage:
    fields = {
        "place_id": profile.place_id,
        "role": role,
        "profile_sha256": profile.profile_sha256,
        "attempt_number": attempt.attempt_number,
        "attempt_sha256": attempt.attempt_sha256,
        "request_sha256": attempt.request_sha256,
        "response_sha256": attempt.response_sha256,
        "resume_authority_sha256": resume_authority_sha256,
    }
    if (
        attempt.place_id != profile.place_id
        or attempt.request_sha256 != profile.request_sha256
        or attempt.response_sha256 != profile.response_sha256
        or attempt.response_sha256 is None
    ):
        raise DemoProfileMaterializationError("NVIDIA_ATTEMPT5_RETAINING_PROFILE_LINEAGE_INVALID")
    return Attempt5RetainingProfileLineage(
        place_id=profile.place_id,
        role=role,
        profile_sha256=profile.profile_sha256,
        attempt_number=attempt.attempt_number,
        attempt_sha256=attempt.attempt_sha256,
        request_sha256=attempt.request_sha256,
        response_sha256=attempt.response_sha256,
        resume_authority_sha256=resume_authority_sha256,
        lineage_sha256=canonical_sha256(fields),
    )


def _with_retry_policy(
    result: NvidiaProfileAdapterResult,
    *,
    retry: bool,
) -> NvidiaProfileAdapterResult:
    """Reseal attempt evidence to the continuation's actual retry decision."""

    if result.retry is retry and result.attempt.retry is retry:
        return result
    fields = result.attempt.model_dump(mode="json", exclude={"attempt_sha256"})
    fields["retry"] = retry
    attempt = NvidiaMinimaxProfileAttempt.model_validate(
        seal_demo_contract(fields, digest_field="attempt_sha256")
    )
    return replace(result, attempt=attempt, retry=retry)


async def execute_attempt5_retaining_materialization(
    *,
    source_bundles: Sequence[DemoSourceBundle],
    plan: Attempt5RetainingPlan,
    authority: Attempt5RetainingAuthority,
    adapter: NvidiaMinimaxProfileAdapter,
    journal: DurableNvidiaJournal,
    execution_approval_text: str | None,
    execution_approval_sha256: str | None,
    trusted_decision_record_sha256: str | None,
    state_guard: Callable[[], str],
    redaction_token: bytes | None = None,
) -> Attempt5RetainingExecutionResult:
    """Execute only after a future separate approval; tests use MockTransport."""

    if execution_approval_text is None or execution_approval_sha256 is None:
        raise PermissionError("NVIDIA_ATTEMPT5_RETAINING_SEPARATE_EXECUTION_APPROVAL_REQUIRED")
    implementation_commit = authority.receipt.get("implementation_commit")
    implementation_tree = authority.receipt.get("implementation_tree")
    if not isinstance(implementation_commit, str) or not isinstance(implementation_tree, str):
        raise PermissionError("NVIDIA_ATTEMPT5_RETAINING_AUTHORITY_INVALID")
    exact_authority_receipt = preflight_attempt5_retaining_authority(
        authority_text=authority.text,
        authority_sha256=authority.authority_sha256,
        source_bundles=source_bundles,
        plan=plan,
        implementation_commit=implementation_commit,
        implementation_tree=implementation_tree,
    )
    if canonical_json_bytes(authority.receipt) != canonical_json_bytes(exact_authority_receipt):
        raise PermissionError("NVIDIA_ATTEMPT5_RETAINING_AUTHORITY_RECEIPT_MISMATCH")
    approval_receipt = preflight_attempt5_retaining_execution_approval(
        authority=authority,
        approval_text=execution_approval_text,
        approval_sha256=execution_approval_sha256,
        trusted_decision_record_sha256=trusted_decision_record_sha256,
    )
    journal.require_live_started(execution_approval_receipt=approval_receipt)
    journal.require_authority(authority.receipt)
    if state_guard() != plan.state_sha256:
        raise PermissionError("NVIDIA_ATTEMPT5_RETAINING_POST_CLAIM_STATE_DRIFT")
    if adapter.ledger.attempt_count != 8 or adapter.ledger.remaining_attempts != 26:
        raise PermissionError("NVIDIA_ATTEMPT5_RETAINING_LEDGER_INVALID")
    try:
        validated_config = NvidiaMinimaxProfileMaterializationConfig.model_validate(
            adapter.config.model_dump(mode="json")
        )
    except ValueError as error:
        raise PermissionError("NVIDIA_ATTEMPT5_RETAINING_ADAPTER_CONFIG_INVALID") from error
    if (
        validated_config != adapter.config
        or validated_config.endpoint != authority.receipt.get("endpoint")
        or validated_config.model != authority.receipt.get("model")
        or validated_config.provider_lane != authority.receipt.get("provider_lane")
        or canonical_sha256(validated_config.model_dump(mode="json"))
        != authority.receipt.get("provider_request_config_sha256")
    ):
        raise PermissionError("NVIDIA_ATTEMPT5_RETAINING_ADAPTER_CONFIG_INVALID")
    if not adapter.unknown_price_request_exposure:
        raise PermissionError("NVIDIA_ATTEMPT5_RETAINING_ADAPTER_COST_EXPOSURE_INVALID")

    bundles = _validate_plan(source_bundles, plan)
    by_id = {bundle.place_id: bundle for bundle in bundles}
    raw_by_attempt = dict(plan.predecessor_raw_responses)
    results: list[NvidiaProfileAdapterResult] = []
    retained_result: NvidiaProfileAdapterResult | None = None
    for attempt in plan.predecessor_attempts:
        candidate = plan.retained_profile if attempt.attempt_number == 5 else None
        result = NvidiaProfileAdapterResult(
            attempt=attempt,
            candidate=candidate,
            retry=False,
            raw_response=raw_by_attempt[attempt.attempt_sha256],
        )
        results.append(result)
        if candidate is not None:
            retained_result = result
    if retained_result is None:
        raise DemoProfileMaterializationError("NVIDIA_ATTEMPT5_RETAINING_PROFILE_ABSENT")

    successful_by_place: dict[str, NvidiaProfileAdapterResult] = {
        plan.retained_profile.place_id: retained_result
    }
    retry_count = 0

    def terminal_failure(
        *,
        failure_code: str,
        failed_place_id: str,
        cause: Exception | None = None,
    ) -> DemoProfileMaterializationFailure:
        journal.record_terminal(
            failure_code=failure_code,
            failed_place_id=failed_place_id,
            attempt_count=adapter.ledger.attempt_count,
        )
        failure = DemoProfileMaterializationFailure(
            failed_place_id=failed_place_id,
            failure_code=failure_code,
            results=results,
            committed_cost_micro_usd=0,
            outstanding_cost_micro_usd=0,
            nvidia_authority_sha256=NVIDIA_AUTHORITY_SHA256,
            nvidia_resume_authority_sha256=authority.authority_sha256,
            cost_exposure_request_equivalents=max(0, adapter.ledger.attempt_count - 8),
            provider_price_status="UNKNOWN",
        )
        if cause is not None:
            failure.__cause__ = cause
        return failure

    for place_id in plan.remaining_place_ids:
        bundle = by_id[place_id]
        request_body = build_nvidia_v5_request_bytes(bundle, adapter.config)
        request_binding = nvidia_v5_prompt_binding(bundle)
        verify_nvidia_v5_request_bytes(
            bundle,
            request_body,
            expected_predecessor_request_sha256=cast(
                str, request_binding["predecessor_request_bytes_sha256"]
            ),
            expected_prompt_sha256=cast(str, authority.receipt["prompt_sha256"]),
            expected_schema_example_sha256=plan.schema_example_sha256_by_place[place_id],
            expected_request_sha256=plan.v5_request_sha256_by_place[place_id],
        )
        place_connect_retries = 0
        while True:
            if state_guard() != plan.state_sha256:
                if adapter.ledger.attempt_count == 8:
                    raise PermissionError("NVIDIA_ATTEMPT5_RETAINING_POST_CLAIM_STATE_DRIFT")
                raise terminal_failure(
                    failure_code="NVIDIA_ATTEMPT5_RETAINING_STATE_DRIFT",
                    failed_place_id=place_id,
                )
            started_at = datetime.now(UTC)
            try:
                result = await journal._execute_adapter_attempt(
                    adapter=adapter,
                    place_id=place_id,
                    request_body=request_body,
                    lineage=_nvidia_v5_lineage_for(
                        bundle,
                        adapter.config,
                        resume_authority_sha256=authority.authority_sha256,
                    ),
                )
            except RuntimeError as error:
                if str(error) != "NVIDIA_ATTEMPT_BUDGET_EXHAUSTED":
                    raise
                raise terminal_failure(
                    failure_code="NVIDIA_ATTEMPT5_RETAINING_ATTEMPT_BUDGET_EXHAUSTED",
                    failed_place_id=place_id,
                    cause=error,
                ) from error
            connect_failure = result.attempt.error_code in {"CONNECTERROR", "CONNECTTIMEOUT"}
            will_retry = (
                result.candidate is None
                and connect_failure
                and place_connect_retries == 0
                and retry_count < ATTEMPT5_RETAINING_MAX_CONNECT_RETRIES
            )
            result = journal._set_attested_retry_policy(result, retry=will_retry)
            journal.record_attempt(
                result,
                started_at=started_at,
                completed_at=datetime.now(UTC),
                redaction_token=redaction_token,
            )
            results.append(result)
            if result.candidate is not None:
                successful_by_place[place_id] = result
                break

            if will_retry:
                place_connect_retries += 1
                retry_count += 1
                await adapter.pace_retry(ATTEMPT5_RETAINING_MINIMUM_INTERVAL_SECONDS)
                continue
            if result.attempt.http_status == 429:
                failure_code = "NVIDIA_RATE_LIMITED"
            elif connect_failure:
                failure_code = "NVIDIA_ATTEMPT5_RETAINING_CONNECT_RETRY_EXHAUSTED"
            elif result.attempt.outcome == "TRANSPORT_ERROR":
                failure_code = "NVIDIA_ATTEMPT5_RETAINING_TRANSPORT_FAILED"
            elif result.attempt.outcome == "ATTEMPT_DEADLINE_EXCEEDED":
                failure_code = "NVIDIA_ATTEMPT5_RETAINING_DEADLINE"
            elif result.attempt.outcome == "HTTP_ERROR":
                failure_code = "NVIDIA_ATTEMPT5_RETAINING_HTTP_FAILED"
            else:
                failure_code = "NVIDIA_ATTEMPT5_RETAINING_MEMBER_FAILED"
            raise terminal_failure(
                failure_code=failure_code,
                failed_place_id=place_id,
            )

    if state_guard() != plan.state_sha256:
        raise terminal_failure(
            failure_code="NVIDIA_ATTEMPT5_RETAINING_STATE_DRIFT",
            failed_place_id="COHORT_POSTFLIGHT",
        )
    terminal = tuple(successful_by_place[place_id] for place_id in sorted(successful_by_place))
    profiles = tuple(
        cast(NvidiaMinimaxModelDerivedProfile, result.candidate) for result in terminal
    )
    cohort = evaluate_nvidia_publication_cohort(
        tuple(profile.model_dump(mode="json") for profile in profiles)
    )
    if not cohort.eligible:
        raise terminal_failure(
            failure_code="NVIDIA_ATTEMPT5_RETAINING_COHORT_REJECTED",
            failed_place_id="COHORT_POSTFLIGHT",
        )
    attempts = tuple(result.attempt for result in results)
    if (
        len(profiles) != 24
        or not 31 <= len(attempts) <= 34
        or tuple(attempt.attempt_number for attempt in attempts)
        != tuple(range(1, len(attempts) + 1))
        or adapter.ledger.attempt_count != len(attempts)
    ):
        raise terminal_failure(
            failure_code="NVIDIA_ATTEMPT5_RETAINING_FINAL_INVENTORY_INVALID",
            failed_place_id="COHORT_POSTFLIGHT",
        )

    lineages: list[Attempt5RetainingProfileLineage] = []
    for result in terminal:
        profile = cast(NvidiaMinimaxModelDerivedProfile, result.candidate)
        retained = profile.place_id == _ATTEMPT5_PLACE_ID
        try:
            lineages.append(
                _profile_lineage(
                    profile=profile,
                    attempt=result.attempt,
                    role="RETAINED_ATTEMPT5" if retained else "NEW_DEV23",
                    resume_authority_sha256=(
                        _ATTEMPT5_AUTHORITY_SHA256 if retained else authority.authority_sha256
                    ),
                )
            )
        except DemoProfileMaterializationError as error:
            raise terminal_failure(
                failure_code="NVIDIA_ATTEMPT5_RETAINING_LINEAGE_INVALID",
                failed_place_id=profile.place_id,
                cause=error,
            ) from error
    receipt: dict[str, object] = {
        "schema_version": ATTEMPT5_RETAINING_EXECUTION_RECEIPT_SCHEMA_VERSION,
        "status": "COMPLETE_UNACTIVATED",
        "authority_sha256": authority.authority_sha256,
        "execution_approval_sha256": execution_approval_sha256,
        "execution_approval_receipt_sha256": approval_receipt["receipt_sha256"],
        "profile_count": 24,
        "profile_sha256": [profile.profile_sha256 for profile in profiles],
        "profile_lineage": [
            {
                "place_id": item.place_id,
                "role": item.role,
                "profile_sha256": item.profile_sha256,
                "attempt_number": item.attempt_number,
                "attempt_sha256": item.attempt_sha256,
                "request_sha256": item.request_sha256,
                "response_sha256": item.response_sha256,
                "resume_authority_sha256": item.resume_authority_sha256,
                "lineage_sha256": item.lineage_sha256,
            }
            for item in lineages
        ],
        "attempt_sha256": [attempt.attempt_sha256 for attempt in attempts],
        "http_attempt_count": len(attempts),
        "historical_attempt_count": 8,
        "first_pass_request_count": 23,
        "retry_count": retry_count,
        "provider_price_status": "UNKNOWN",
        "cost_exposure_request_equivalents": len(attempts) - 8,
        "new_http_attempt_cap": ATTEMPT5_RETAINING_MAX_NEW_HTTP_ATTEMPTS,
        "cumulative_http_attempt_cap": ATTEMPT5_RETAINING_MAX_CUMULATIVE_HTTP_ATTEMPTS,
        "network_attempted": True,
    }
    receipt["generation_sha256"] = canonical_sha256(
        {
            "authority_sha256": authority.authority_sha256,
            "profile_sha256": receipt["profile_sha256"],
            "profile_lineage": receipt["profile_lineage"],
            "attempt_sha256": receipt["attempt_sha256"],
        }
    )
    receipt["receipt_sha256"] = canonical_sha256(receipt)
    return Attempt5RetainingExecutionResult(
        profiles=profiles,
        attempts=attempts,
        profile_lineage=tuple(lineages),
        authority_sha256=authority.authority_sha256,
        receipt=receipt,
    )


def publish_attempt5_retaining_generation(
    result: Attempt5RetainingExecutionResult,
    *,
    output_root: Path,
) -> Path:
    """Publish the complete unactivated grammar without accepting it as a release."""

    generation_sha256 = result.receipt.get("generation_sha256")
    profile_sha256 = [profile.profile_sha256 for profile in result.profiles]
    attempt_sha256 = [attempt.attempt_sha256 for attempt in result.attempts]
    lineage_rows = [
        {
            "place_id": item.place_id,
            "role": item.role,
            "profile_sha256": item.profile_sha256,
            "attempt_number": item.attempt_number,
            "attempt_sha256": item.attempt_sha256,
            "request_sha256": item.request_sha256,
            "response_sha256": item.response_sha256,
            "resume_authority_sha256": item.resume_authority_sha256,
            "lineage_sha256": item.lineage_sha256,
        }
        for item in result.profile_lineage
    ]
    expected_generation_sha256 = canonical_sha256(
        {
            "authority_sha256": result.authority_sha256,
            "profile_sha256": profile_sha256,
            "profile_lineage": lineage_rows,
            "attempt_sha256": attempt_sha256,
        }
    )
    if (
        not isinstance(generation_sha256, str)
        or not _SHA_PATTERN.fullmatch(generation_sha256)
        or generation_sha256 != expected_generation_sha256
        or result.receipt.get("receipt_sha256")
        != canonical_sha256(
            {key: value for key, value in result.receipt.items() if key != "receipt_sha256"}
        )
        or result.receipt.get("authority_sha256") != result.authority_sha256
        or result.receipt.get("profile_sha256") != profile_sha256
        or result.receipt.get("attempt_sha256") != attempt_sha256
        or result.receipt.get("profile_lineage") != lineage_rows
        or len(result.profiles) != 24
        or len(result.profile_lineage) != 24
        or not 31 <= len(result.attempts) <= 34
        or any(
            canonical_sha256(profile.model_dump(mode="json", exclude={"profile_sha256"}))
            != profile.profile_sha256
            for profile in result.profiles
        )
        or any(
            canonical_sha256(
                {
                    key: value
                    for key, value in attempt.model_dump(mode="json").items()
                    if key != "attempt_sha256"
                }
            )
            != attempt.attempt_sha256
            for attempt in result.attempts
        )
        or any(
            canonical_sha256({key: value for key, value in row.items() if key != "lineage_sha256"})
            != row["lineage_sha256"]
            for row in lineage_rows
        )
    ):
        raise ValueError("NVIDIA_ATTEMPT5_RETAINING_GENERATION_OR_RECEIPT_INVALID")
    files = {
        "profiles.json": canonical_json_bytes(
            [profile.model_dump(mode="json") for profile in result.profiles]
        ),
        "attempts.json": canonical_json_bytes(
            [attempt.model_dump(mode="json") for attempt in result.attempts]
        ),
        "receipt.json": canonical_json_bytes(result.receipt),
    }
    return _publish_private_files(
        output_root / generation_sha256,
        files,
        prefix=".phase5-attempt5-retaining-generation-",
    )


__all__ = [
    "ATTEMPT5_RETAINING_MAX_CUMULATIVE_HTTP_ATTEMPTS",
    "ATTEMPT5_RETAINING_MAX_NEW_HTTP_ATTEMPTS",
    "Attempt5RetainingAuthority",
    "Attempt5RetainingExecutionApproval",
    "Attempt5RetainingExecutionResult",
    "Attempt5RetainingPlan",
    "Attempt5RetainingProfileLineage",
    "build_attempt5_retaining_plan",
    "derive_attempt5_retaining_authority",
    "derive_attempt5_retaining_execution_approval",
    "execute_attempt5_retaining_materialization",
    "publish_attempt5_retaining_generation",
    "preflight_attempt5_retaining_authority",
    "preflight_attempt5_retaining_execution_approval",
]
