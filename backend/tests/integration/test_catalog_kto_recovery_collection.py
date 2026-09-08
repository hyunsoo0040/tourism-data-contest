from __future__ import annotations

import contextlib
import hashlib
from collections.abc import Iterator
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest

from itda.cli import collect_catalog_enrichment as collector
from itda.contracts.catalog_enrichment import canonical_json_bytes

REPOSITORY_ROOT = Path(__file__).parents[3]
ISSUED_AT = datetime(2026, 7, 30, 14, 30, tzinfo=UTC)
DEADLINE = datetime(2026, 7, 31, 14, 30, tzinfo=UTC)
REVIEWER_ID = "phase2-operator"
ELIGIBILITY_ROOT = "e8fb691be0715b149a4cd9d9601aac76a90a42827a0c7c6367fa3a7261af97d0"
REQUEST_MANIFEST_SHA256 = "a6bb2a08f5a48a38b413ea817825269cb0e2f5abaf60d047b3b664f06f6c465b"
ALLOWLIST_SHA256 = "028ea8dfa5361bc8a46e7c66346f7b3c4b65de17e8713d50ce64ef16f431aa22"
TYPED_INTRO_POLICY_SHA256 = "96a8586c036f4adfd86a6d4f1b949546942aef32d5261c8ad676570c90092e4a"


class FakeStreamResponse:
    def __init__(
        self,
        body: bytes,
        *,
        status_code: int = 200,
        headers: dict[str, str] | None = None,
        chunks: list[bytes] | None = None,
    ) -> None:
        self.status_code = status_code
        self.headers = headers or {"content-type": "application/json"}
        self._body = body
        self._chunks = chunks
        self.iterated = False

    def iter_bytes(self) -> Iterator[bytes]:
        self.iterated = True
        if self._chunks is not None:
            yield from self._chunks
        else:
            yield self._body


class RecordingStreamRequester:
    def __init__(self, responses: list[FakeStreamResponse]) -> None:
        self.responses = responses
        self.calls: list[dict[str, Any]] = []

    @contextlib.contextmanager
    def stream(self, method: str, url: str, **kwargs: Any) -> Iterator[FakeStreamResponse]:
        self.calls.append({"method": method, "url": url, **kwargs})
        yield self.responses.pop(0)


def _preflight() -> dict[str, object]:
    return collector.build_kto_collection_preflight(
        REPOSITORY_ROOT,
        issued_at=ISSUED_AT,
        deadline=DEADLINE,
        reviewer_id=REVIEWER_ID,
    )


def _success_body(*, item: object | None = None) -> bytes:
    value = [] if item is None else item
    return canonical_json_bytes(
        {
            "response": {
                "header": {"resultCode": "0000", "resultMsg": "OK"},
                "body": {"items": {"item": value}},
            }
        }
    )


def _authority_token(preflight: dict[str, object], nonce: str = "7" * 64) -> str:
    context = collector.derive_kto_authority_context(preflight, nonce=nonce)
    return context.expected_token().serialize()


def _credential(tmp_path: Path, value: str = "fixture-kto-service-key") -> Path:
    path = tmp_path / "kto.env"
    path.write_text(f"TOUR_API_SERVICE_KEY={value}\n", encoding="utf-8")
    path.chmod(0o600)
    return path


def test_preflight_replays_exact_plan47_packet_without_external_side_effects() -> None:
    preflight = _preflight()

    assert preflight["status"] == "AWAITING_SEPARATE_AUTHORITY"
    assert preflight["kto_eligibility_root"] == ELIGIBILITY_ROOT
    assert preflight["kto_request_manifest_sha256"] == REQUEST_MANIFEST_SHA256
    assert preflight["kto_allowlist_revision_sha256"] == ALLOWLIST_SHA256
    assert preflight["typed_intro_policy_sha256"] == TYPED_INTRO_POLICY_SHA256
    assert preflight["request_count"] == 48
    assert preflight["base_url"] == "https://apis.data.go.kr/B551011/KorService2"
    assert preflight["reviewer_id"] == REVIEWER_ID
    assert preflight["issued_at"] == ISSUED_AT.isoformat()
    assert preflight["deadline"] == DEADLINE.isoformat()
    assert preflight["attempt_policy"] == {
        "maximum_total_attempts": 3,
        "per_attempt_timeout_seconds": 300,
        "redirects_allowed": False,
        "retryable_outcomes": [
            "TRANSIENT_TRANSPORT",
            "HTTP_408",
            "HTTP_429",
            "HTTP_5XX",
            "TRANSIENT_PROVIDER_CODE",
        ],
    }
    assert preflight["response_policy"] == {
        "maximum_body_bytes": 8 * 1024 * 1024,
        "maximum_json_depth": 32,
        "maximum_items": 100,
        "enforce_declared_num_of_rows": True,
    }
    assert str(preflight["output_root"]).endswith(
        f"/collections/{preflight['collection_root_sha256']}"
    )

    serialized = canonical_json_bytes(preflight)
    for forbidden in (
        b"serviceKey",
        b"authority_token",
        b'"nonce"',
        b"fixture-kto-service-key",
    ):
        assert forbidden not in serialized


def test_separate_issuer_authority_binds_all_exact_preflight_fields() -> None:
    preflight = _preflight()
    context = collector.derive_kto_authority_context(preflight, nonce="8" * 64)
    token = context.expected_token().serialize()

    validated = collector.validate_kto_collection_authority(
        preflight,
        raw_token=token,
        now=ISSUED_AT,
    )

    assert validated.issuance_context.action == "enrichment-collect"
    assert validated.issuance_context.request_sha256 == preflight["request_sha256"]
    assert (
        validated.issuance_context.state_attestation_sha256 == preflight["state_attestation_sha256"]
    )
    assert validated.issuance_context.target_sha256 == preflight["target_sha256"]
    assert validated.issuance_context.reviewer_id == REVIEWER_ID
    assert validated.issuance_context.nonce == "8" * 64

    patched = dict(preflight)
    patched["request_count"] = 47
    with pytest.raises(ValueError, match="request|preflight|stale"):
        collector.validate_kto_collection_authority(
            patched,
            raw_token=token,
            now=ISSUED_AT,
        )


def test_streaming_response_gate_rejects_size_depth_and_item_excess() -> None:
    over_length = FakeStreamResponse(
        b"",
        headers={
            "content-type": "application/json",
            "content-length": str(8 * 1024 * 1024 + 1),
        },
    )
    with pytest.raises(ValueError, match="8 MiB|body limit"):
        collector.read_kto_response_bounded(over_length, declared_num_of_rows=100)
    assert over_length.iterated is False

    chunked = FakeStreamResponse(
        b"",
        chunks=[b"x" * (8 * 1024 * 1024), b"x"],
    )
    with pytest.raises(ValueError, match="8 MiB|body limit"):
        collector.read_kto_response_bounded(chunked, declared_num_of_rows=100)

    nested: object = "leaf"
    for _ in range(33):
        nested = {"nested": nested}
    too_deep = FakeStreamResponse(canonical_json_bytes(nested))
    with pytest.raises(ValueError, match="depth"):
        collector.read_kto_response_bounded(too_deep, declared_num_of_rows=100)

    excess = FakeStreamResponse(_success_body(item=[{"id": index} for index in range(2)]))
    with pytest.raises(ValueError, match="declared numOfRows|item count"):
        collector.read_kto_response_bounded(excess, declared_num_of_rows=1)


@pytest.mark.parametrize(
    ("status", "provider_code", "transport_reason", "expected"),
    [
        (408, None, None, True),
        (429, None, None, True),
        (500, None, None, True),
        (503, None, None, True),
        (200, "01", None, True),
        (200, "02", None, True),
        (200, "04", None, True),
        (200, "05", None, True),
        (200, "22", None, True),
        (200, "0000", None, False),
        (200, "03", None, False),
        (200, "10", None, False),
        (200, "20", None, False),
        (200, "30", None, False),
        (200, "99", None, False),
        (None, None, "timeout", True),
        (None, None, "connection-reset", True),
        (None, None, "tls-error", False),
    ],
)
def test_retry_classifier_is_closed_and_transient_only(
    status: int | None,
    provider_code: str | None,
    transport_reason: str | None,
    expected: bool,
) -> None:
    assert (
        collector.is_kto_retryable(
            http_status=status,
            provider_code=provider_code,
            transport_reason=transport_reason,
        )
        is expected
    )


def test_exact_packet_collection_is_private_append_only_and_secret_safe(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    collections_base = tmp_path / "collections"
    monkeypatch.setattr(collector, "KTO_COLLECTIONS_BASE", collections_base)
    preflight = _preflight()
    credential = _credential(tmp_path)
    requester = RecordingStreamRequester([FakeStreamResponse(_success_body()) for _ in range(48)])
    token = _authority_token(preflight)

    result = collector.collect_kto_recovery_packet(
        REPOSITORY_ROOT,
        authorization_token=token,
        credential_path=credential,
        issued_at=ISSUED_AT,
        deadline=DEADLINE,
        reviewer_id=REVIEWER_ID,
        now=ISSUED_AT,
        requester=requester,
    )

    assert result["request_count"] == 48
    assert result["terminal_request_count"] == 48
    assert result["missing_request_count"] == 0
    assert result["provider_requests_sent"] == 48
    assert len(requester.calls) == 48
    assert {call["url"] for call in requester.calls} <= {
        "https://apis.data.go.kr/B551011/KorService2/detailCommon2",
        "https://apis.data.go.kr/B551011/KorService2/detailImage2",
    }
    assert all(call["method"] == "GET" for call in requester.calls)
    assert all(call["follow_redirects"] is False for call in requester.calls)
    assert all(call["timeout"] == 300 for call in requester.calls)
    assert all(
        call["params"]["serviceKey"] == "fixture-kto-service-key" for call in requester.calls
    )

    output_root = Path(str(preflight["output_root"]))
    assert output_root.parent == collections_base
    assert output_root.stat().st_mode & 0o777 == 0o700
    assert all(
        path.stat().st_mode & 0o777 == (0o700 if path.is_dir() else 0o600)
        for path in output_root.rglob("*")
    )
    durable = b"".join(path.read_bytes() for path in output_root.rglob("*") if path.is_file())
    assert b"fixture-kto-service-key" not in durable
    assert token.encode("ascii") not in durable
    assert b"itda-auth-v2:" not in durable

    before = {
        path.relative_to(output_root).as_posix(): hashlib.sha256(path.read_bytes()).hexdigest()
        for path in output_root.rglob("*")
        if path.is_file()
    }
    replay_requester = RecordingStreamRequester([])
    with pytest.raises(Exception, match="nonce|consumed|replay"):
        collector.collect_kto_recovery_packet(
            REPOSITORY_ROOT,
            authorization_token=token,
            credential_path=credential,
            issued_at=ISSUED_AT,
            deadline=DEADLINE,
            reviewer_id=REVIEWER_ID,
            now=ISSUED_AT,
            requester=replay_requester,
        )
    after = {
        path.relative_to(output_root).as_posix(): hashlib.sha256(path.read_bytes()).hexdigest()
        for path in output_root.rglob("*")
        if path.is_file()
    }
    assert replay_requester.calls == []
    assert after == before


def test_exact_terminal_verifier_seals_two_identical_replays(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    collections_base = tmp_path / "collections"
    monkeypatch.setattr(collector, "KTO_COLLECTIONS_BASE", collections_base)
    preflight = _preflight()
    credential = _credential(tmp_path)
    requester = RecordingStreamRequester([FakeStreamResponse(_success_body()) for _ in range(48)])

    collector.collect_kto_recovery_packet(
        REPOSITORY_ROOT,
        authorization_token=_authority_token(preflight),
        credential_path=credential,
        issued_at=ISSUED_AT,
        deadline=DEADLINE,
        reviewer_id=REVIEWER_ID,
        now=ISSUED_AT,
        requester=requester,
    )

    first = collector.verify_and_seal_kto_recovery_collection(
        REPOSITORY_ROOT,
        collections_base=collections_base,
    )
    output_root = collections_base / str(first["kto_collection_base"])
    first_raw_manifest = (output_root / "raw-manifest.json").read_bytes()
    first_collection_manifest = (output_root / "collection-manifest.json").read_bytes()
    second = collector.verify_and_seal_kto_recovery_collection(
        REPOSITORY_ROOT,
        collections_base=collections_base,
    )

    assert first == second
    assert first["status"] == "SUCCESS"
    assert first["request_count"] == 48
    assert first["terminal_request_count"] == 48
    assert first["successful_request_count"] == 48
    assert first["success_empty_count"] == 48
    assert first["plan49_reachable"] is True
    assert (output_root / "raw-manifest.json").read_bytes() == first_raw_manifest
    assert (output_root / "collection-manifest.json").read_bytes() == first_collection_manifest
    assert all(
        path.stat().st_mode & 0o777 == (0o700 if path.is_dir() else 0o600)
        for path in output_root.rglob("*")
    )


def test_exact_terminal_verifier_rejects_provider_failure_without_sealing(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    collections_base = tmp_path / "collections"
    monkeypatch.setattr(collector, "KTO_COLLECTIONS_BASE", collections_base)
    preflight = _preflight()
    credential = _credential(tmp_path)
    requester = RecordingStreamRequester(
        [
            FakeStreamResponse(_success_body(), status_code=403),
            *[FakeStreamResponse(_success_body()) for _ in range(47)],
        ]
    )

    result = collector.collect_kto_recovery_packet(
        REPOSITORY_ROOT,
        authorization_token=_authority_token(preflight),
        credential_path=credential,
        issued_at=ISSUED_AT,
        deadline=DEADLINE,
        reviewer_id=REVIEWER_ID,
        now=ISSUED_AT,
        requester=requester,
    )

    assert result["status"] == "TERMINAL_FAILURE"
    assert result["terminal_failure_count"] == 1
    with pytest.raises(ValueError, match="terminal request failure"):
        collector.verify_and_seal_kto_recovery_collection(
            REPOSITORY_ROOT,
            collections_base=collections_base,
        )
    output_root = collections_base / str(preflight["collection_root_sha256"])
    assert not (output_root / "raw-manifest.json").exists()
    assert not (output_root / "collection-manifest.json").exists()


def test_exact_terminal_verifier_rejects_extra_raw_evidence(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    collections_base = tmp_path / "collections"
    monkeypatch.setattr(collector, "KTO_COLLECTIONS_BASE", collections_base)
    preflight = _preflight()
    credential = _credential(tmp_path)
    requester = RecordingStreamRequester([FakeStreamResponse(_success_body()) for _ in range(48)])
    collector.collect_kto_recovery_packet(
        REPOSITORY_ROOT,
        authorization_token=_authority_token(preflight),
        credential_path=credential,
        issued_at=ISSUED_AT,
        deadline=DEADLINE,
        reviewer_id=REVIEWER_ID,
        now=ISSUED_AT,
        requester=requester,
    )
    output_root = collections_base / str(preflight["collection_root_sha256"])
    extra = output_root / "raw" / ("f" * 64) / "attempt-001.response"
    extra.parent.mkdir(mode=0o700)
    extra.write_bytes(_success_body())
    extra.chmod(0o600)

    with pytest.raises(ValueError, match="extra or missing"):
        collector.verify_and_seal_kto_recovery_collection(
            REPOSITORY_ROOT,
            collections_base=collections_base,
        )
    assert not (output_root / "raw-manifest.json").exists()
    assert not (output_root / "collection-manifest.json").exists()


def test_kto_recovery_verifier_cli_requires_discovery_base_not_authority() -> None:
    args = collector.kto_recovery_parser().parse_args(
        [
            "--repo-root",
            str(REPOSITORY_ROOT),
            "--verify-kto-recovery",
            "--discover-exact-success-under",
            "collections",
        ]
    )

    assert args.verify_kto_recovery is True
    assert args.discover_exact_success_under == Path("collections")
    assert args.authority_issued_at is None
    assert args.authority_deadline is None
    assert args.reviewer_id is None
