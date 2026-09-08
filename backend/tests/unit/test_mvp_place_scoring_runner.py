from __future__ import annotations

import hashlib
import json
import shutil
from collections import Counter
from datetime import UTC, datetime
from pathlib import Path

import httpx
import pytest

from itda.cli import score_mvp_places
from itda.contracts.mvp_place_scoring import SCORING_DIMENSIONS, PublicScoringRequest
from itda.domain.canonical import canonical_json_bytes, canonical_sha256
from itda.pipeline.mvp_place_scoring import (
    MAX_OUTPUT_TOKENS,
    MAX_RESPONSE_BYTES,
    REQUEST_TIMEOUT_SECONDS,
    GlmCodingScoringTransport,
    MvpScoringError,
    ScoringAttemptEvent,
    build_canary_plan,
    build_http_client,
    build_run_plan,
    consume_execution_authority,
    execute_batch,
    execute_diagnostic,
    load_attempt_counts,
    parse_openrouter_pricing_snapshot,
    persist_attempt_event,
    prepare_continuation_state,
    redact_error,
    result_manifest,
    verify_canary_plan,
    verify_run_plan,
)

SHA = "0" * 64
EVIDENCE_ID = f"evidence:{'1' * 64}"
REPO_ROOT = Path(__file__).resolve().parents[3]
RUN_PLAN_PATH = REPO_ROOT / "artifacts/public/catalog/mvp-place-scoring-run-plan-v1.json"
REQUESTS_PATH = REPO_ROOT / "artifacts/public/catalog/mvp-place-scoring-requests-v1.json"
CANARY_REQUEST_PATH = (
    REPO_ROOT / "artifacts/public/catalog/mvp-place-scoring-canary-request-v2.json"
)
CANARY_SELECTION_PATH = (
    REPO_ROOT / "artifacts/public/catalog/mvp-place-scoring-canary-selection-v3.json"
)
CANARY_EVIDENCE_PATH = (
    REPO_ROOT / "artifacts/public/catalog/mvp-place-scoring-canary-evidence-v2.json"
)
RUN_PLAN_SHA256 = "f031bd15b6e07c3b4523a81667b824600f4012b2d53941a4a591805da1e7f069"
CONTINUATION_PLAN_PATH = (
    REPO_ROOT / "artifacts/public/catalog/mvp-place-scoring-continuation-plan-v1.json"
)
PREDECESSOR_ROOT = (
    REPO_ROOT
    / "artifacts/public/catalog/mvp-place-scoring-runs"
    / "1ee70778bb098b63bb7368bfe3aea26ef5c93f8ff6f1609608db2b3487011874"
)
CONTINUATION_REQUESTS_PATH = (
    REPO_ROOT / "artifacts/public/catalog/mvp-place-scoring-requests-v2.json"
)


def requests() -> tuple[PublicScoringRequest, ...]:
    rows = []
    for index in range(100):
        fields = {
            "schema_version": "mvp-place-scoring-request.v2",
            "model": "glm-5.3-flash",
            "place": {
                "place_id": f"public:gyeongju:{index:064x}",
                "name_ko": f"합성 공개 장소 {index}",
                "category": "관광지",
                "administrative_area": "경주시",
                "address_ko": f"경주시 합성로 {index}",
                "latitude": 35.5 + index / 1000,
                "longitude": 129.0 + index / 1000,
            },
            "evidence": [{"evidence_id": EVIDENCE_ID, "excerpt": "합성 공개 근거"}],
            "rubric": {
                dimension: f"{dimension} 공개 평가 기준" for dimension in SCORING_DIMENSIONS
            },
        }
        rows.append(PublicScoringRequest(**fields, request_sha256=canonical_sha256(fields)))
    return tuple(rows)


def mvp_attempt_event(request: PublicScoringRequest) -> ScoringAttemptEvent:
    return ScoringAttemptEvent(
        run_plan_sha256=RUN_PLAN_SHA256,
        place_id=request.place.place_id,
        request_sha256=request.request_sha256,
        attempt_number=1,
        status="STARTED",
    )


def response_bytes() -> bytes:
    return json.dumps(
        {
            "H": 50,
            "E": 51,
            "R": 52,
            **{dimension: 2 for dimension in SCORING_DIMENSIONS[3:15]},
            **{dimension: 50 for dimension in SCORING_DIMENSIONS[15:]},
            "confidence": 20,
            "justifications": {
                dimension: {
                    "evidence_ids": [EVIDENCE_ID],
                    "justification_ko": f"{dimension} 합성 근거",
                }
                for dimension in SCORING_DIMENSIONS
            },
        },
        ensure_ascii=False,
    ).encode()


class FakeTransport:
    def __init__(self, fail_until: dict[str, int] | None = None, body: bytes | None = None) -> None:
        self.fail_until = fail_until or {}
        self.calls: Counter[str] = Counter()
        self.body = response_bytes() if body is None else body

    def score(
        self, request: PublicScoringRequest, *, timeout_seconds: int, max_tokens: int
    ) -> bytes:
        assert timeout_seconds == REQUEST_TIMEOUT_SECONDS
        assert max_tokens == MAX_OUTPUT_TOKENS
        place_id = request.place.place_id
        self.calls[place_id] += 1
        if self.calls[place_id] <= self.fail_until.get(place_id, 0):
            raise RuntimeError("Authorization: Bearer never-log-this")
        return self.body


def run(transport: FakeTransport, *, resumed=None, resumed_attempt_counts=None, on_attempt=None):
    return execute_batch(
        requests(),
        transport=transport,
        run_plan_sha256=RUN_PLAN_SHA256,
        catalog_sha256=SHA,
        evidence_inventory_sha256=SHA,
        prompt_sha256=SHA,
        resumed_results=resumed,
        resumed_attempt_counts=resumed_attempt_counts,
        on_attempt=on_attempt,
    )


def _pricing_payload(*, duplicate: bool = False, prompt: str = "0.000001") -> bytes:
    model = {
        "id": "stealth/ox-alpha",
        "context_length": 1048576,
        "supported_parameters": ["response_format", "max_tokens", "reasoning"],
        "pricing": {"prompt": prompt, "completion": "0.000002"},
    }
    return json.dumps({"data": [model, model] if duplicate else [model]}).encode()


def _parse_pricing(raw: bytes):
    return parse_openrouter_pricing_snapshot(
        raw,
        retrieved_at=datetime(2026, 8, 26, tzinfo=UTC),
        corpus_file_sha256="1" * 64,
        catalog_sha256="2" * 64,
        evidence_inventory_sha256="3" * 64,
        prompt_sha256="4" * 64,
        response_schema_sha256="5" * 64,
    )


def test_glm_transport_uses_fixed_bounded_json_object_request() -> None:
    response = response_bytes().decode()

    def handler(request: httpx.Request) -> httpx.Response:
        assert str(request.url) == "https://api.z.ai/api/coding/paas/v4/chat/completions"
        assert request.headers["authorization"] == "Bearer synthetic-key"
        body = json.loads(request.content)
        assert body["model"] == "glm-5.3-flash"
        assert body["max_tokens"] == MAX_OUTPUT_TOKENS
        assert body["thinking"] == {"type": "enabled"}
        assert body["reasoning_effort"] == "max"
        assert body["response_format"] == {"type": "json_object"}
        assert "json_schema" not in json.dumps(body["response_format"])
        assert "ProviderJustificationMap" in body["messages"][0]["content"]
        assert len(body["messages"]) == 2
        return httpx.Response(
            200,
            json={
                "model": "glm-5.3-flash",
                "choices": [
                    {"finish_reason": "stop", "message": {"content": response}}
                ],
            },
        )

    client = httpx.Client(transport=httpx.MockTransport(handler))
    transport = GlmCodingScoringTransport("synthetic-key", http_client=client)
    try:
        raw = transport.score(
            requests()[0],
            timeout_seconds=REQUEST_TIMEOUT_SECONDS,
            max_tokens=MAX_OUTPUT_TOKENS,
        )
    finally:
        transport.close()

    assert raw == response_bytes()


def test_glm_transport_rejects_credential_reflection() -> None:
    client = httpx.Client(
        transport=httpx.MockTransport(
            lambda request: httpx.Response(200, content=b"synthetic-key")
        )
    )
    transport = GlmCodingScoringTransport("synthetic-key", http_client=client)
    try:
        with pytest.raises(MvpScoringError, match="GLM_CREDENTIAL_REFLECTED"):
            transport.score(
                requests()[0],
                timeout_seconds=REQUEST_TIMEOUT_SECONDS,
                max_tokens=MAX_OUTPUT_TOKENS,
            )
    finally:
        transport.close()


def test_pricing_preflight_parses_exact_model_and_completion_reasoning_fallback() -> None:
    snapshot = _parse_pricing(_pricing_payload())

    assert snapshot.model == "stealth/ox-alpha"
    assert snapshot.prompt_per_token_usd == "0.000001"
    assert snapshot.completion_per_token_usd == "0.000002"
    assert snapshot.reasoning_per_token_usd == "0.000002"
    assert snapshot.reasoning_pricing_basis == "COMPLETION_RATE"
    assert snapshot.request_fee_usd == "0"
    assert snapshot.supported_parameters == ("max_tokens", "reasoning", "response_format")


@pytest.mark.parametrize(
    ("raw", "error"),
    [
        (_pricing_payload(duplicate=True), "PREFLIGHT_MODEL_NOT_UNIQUE"),
        (_pricing_payload(prompt="unknown"), "PREFLIGHT_PROMPT_PRICE_INVALID"),
        (b'{"data": []}', "PREFLIGHT_MODEL_NOT_UNIQUE"),
    ],
)
def test_pricing_preflight_rejects_ambiguous_or_invalid_metadata(raw: bytes, error: str) -> None:
    with pytest.raises(MvpScoringError, match=error):
        _parse_pricing(raw)


def test_100_first_passes_continue_after_early_failure() -> None:
    first_id = requests()[0].place.place_id
    transport = FakeTransport({first_id: 1})
    outcome = run(transport)
    assert len(outcome.results) == 100
    assert outcome.call_count == 101
    assert tuple(outcome.attempted_place_ids[:100]) == tuple(
        row.place.place_id for row in requests()
    )
    assert transport.calls[first_id] == 2


def test_all_failures_retry_once_for_exact_200_calls() -> None:
    transport = FakeTransport({row.place.place_id: 2 for row in requests()})
    outcome = run(transport)
    assert outcome.call_count == 200
    assert len(outcome.failed) == 100
    assert set(transport.calls.values()) == {2}


def test_only_failed_places_are_retried() -> None:
    failed_ids = {row.place.place_id for row in requests()[::10]}
    transport = FakeTransport({place_id: 1 for place_id in failed_ids})
    outcome = run(transport)
    assert outcome.call_count == 110
    assert {place_id for place_id, count in transport.calls.items() if count == 2} == failed_ids


def test_resume_success_is_not_resent() -> None:
    initial = run(FakeTransport())
    keep = dict(tuple(initial.results.items())[:30])
    counts = {place_id: initial.attempt_counts[place_id] for place_id in keep}
    transport = FakeTransport()
    resumed = run(transport, resumed=keep, resumed_attempt_counts=counts)
    assert resumed.call_count == 70
    assert not set(transport.calls).intersection(keep)


def test_interrupted_continuation_reuses_89_results_with_at_most_19_new_calls() -> None:
    initial = run(FakeTransport())
    ordered = requests()
    carried = dict(tuple(initial.results.items())[:89])
    counts = {row.place.place_id: 1 for row in ordered[:92]}
    failed_ids = {row.place.place_id for row in ordered[89:92]}
    transport = FakeTransport({row.place.place_id: 1 for row in ordered[92:]})

    outcome = execute_batch(
        ordered,
        transport=transport,
        run_plan_sha256=RUN_PLAN_SHA256,
        catalog_sha256=SHA,
        evidence_inventory_sha256=SHA,
        prompt_sha256=SHA,
        resumed_results=carried,
        resumed_attempt_counts=counts,
        maximum_new_calls=19,
    )

    assert outcome.call_count == 19
    assert len(outcome.results) == 100
    assert outcome.failed == {}
    assert not set(transport.calls).intersection(carried)
    assert all(transport.calls[place_id] == 1 for place_id in failed_ids)
    assert all(transport.calls[row.place.place_id] == 2 for row in ordered[92:])


def test_continuation_call_cap_fails_before_an_extra_transport_call() -> None:
    transport = FakeTransport({row.place.place_id: 2 for row in requests()})
    with pytest.raises(MvpScoringError, match="MAXIMUM_NEW_CALLS_EXCEEDED"):
        execute_batch(
            requests(),
            transport=transport,
            run_plan_sha256=RUN_PLAN_SHA256,
            catalog_sha256=SHA,
            evidence_inventory_sha256=SHA,
            prompt_sha256=SHA,
            maximum_new_calls=19,
        )
    assert sum(transport.calls.values()) == 19


def test_started_attempt_is_durable_before_transport_and_consumed_on_resume(
    tmp_path: Path,
) -> None:
    class InterruptedTransport(FakeTransport):
        def score(
            self,
            request: PublicScoringRequest,
            *,
            timeout_seconds: int,
            max_tokens: int,
        ) -> bytes:
            raise KeyboardInterrupt

    output_root = tmp_path / "run"
    first_id = requests()[0].place.place_id
    with pytest.raises(KeyboardInterrupt):
        run(
            InterruptedTransport(),
            on_attempt=lambda event: persist_attempt_event(output_root, event),
        )

    persisted = load_attempt_counts(
        output_root,
        run_plan_sha256=RUN_PLAN_SHA256,
        requests=requests(),
    )
    assert persisted == {first_id: 1}

    transport = FakeTransport()
    resumed = run(
        transport,
        resumed_attempt_counts=persisted,
        on_attempt=lambda event: persist_attempt_event(output_root, event),
    )
    assert resumed.call_count == 100
    assert transport.calls[first_id] == 1
    assert resumed.attempt_counts[first_id] == 2
    assert len(resumed.results) == 100


def test_attempt_state_is_bound_to_run_plan_and_request_corpus(tmp_path: Path) -> None:
    output_root = tmp_path / "run"
    first = requests()[0]
    event = mvp_attempt_event(first)
    persist_attempt_event(output_root, event)

    with pytest.raises(MvpScoringError, match="ATTEMPT_STATE_PLAN_MISMATCH"):
        load_attempt_counts(
            output_root,
            run_plan_sha256="a" * 64,
            requests=requests(),
        )

    changed = first.model_copy(update={"request_sha256": "b" * 64})
    corpus = (changed, *requests()[1:])
    with pytest.raises(MvpScoringError, match="ATTEMPT_STATE_INVALID"):
        load_attempt_counts(
            output_root,
            run_plan_sha256=RUN_PLAN_SHA256,
            requests=corpus,
        )


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("request_sha256", "a" * 64),
        ("catalog_sha256", "a" * 64),
        ("evidence_inventory_sha256", "a" * 64),
        ("prompt_sha256", "a" * 64),
        ("model", "wrong/model"),
        ("place_id", f"public:gyeongju:{999:064x}"),
    ],
)
def test_stale_resume_binding_is_rejected_before_transport(field: str, value: str) -> None:
    initial = run(FakeTransport())
    place_id, result = next(iter(initial.results.items()))
    stale = result.model_copy(update={field: value})
    transport = FakeTransport()
    with pytest.raises(MvpScoringError, match="RESUME_RESULT_BINDING_MISMATCH"):
        run(transport, resumed={place_id: stale})
    assert transport.calls == Counter()


def test_resume_key_outside_plan_is_rejected_before_transport() -> None:
    initial = run(FakeTransport())
    result = next(iter(initial.results.values()))
    transport = FakeTransport()
    with pytest.raises(MvpScoringError, match="RESUME_RESULT_NOT_IN_PLAN"):
        run(transport, resumed={f"public:gyeongju:{999:064x}": result})
    assert transport.calls == Counter()


def test_glm_json_object_rejects_fence_and_surrounding_text() -> None:
    fenced = b"```json\n" + response_bytes() + b"\n```"
    fenced_outcome = run(FakeTransport(body=fenced))
    assert set(fenced_outcome.failed.values()) == {"PROVIDER_RESPONSE_JSON_INVALID"}

    surrounded = run(FakeTransport(body=b"result:\n" + response_bytes()))
    assert set(surrounded.failed.values()) == {"PROVIDER_RESPONSE_JSON_INVALID"}


def test_wire_justification_map_projects_to_canonical_tuple() -> None:
    request = requests()[0]
    payload = json.loads(response_bytes())
    payload["justifications"] = dict(reversed(tuple(payload["justifications"].items())))
    outcome = execute_batch(
        requests(),
        transport=FakeTransport(body=json.dumps(payload, ensure_ascii=False).encode()),
        run_plan_sha256=RUN_PLAN_SHA256,
        catalog_sha256=SHA,
        evidence_inventory_sha256=SHA,
        prompt_sha256=SHA,
    )
    result = outcome.results[request.place.place_id]
    assert tuple(row.dimension.value for row in result.scores.justifications) == SCORING_DIMENSIONS


def test_missing_wire_justification_dimension_is_rejected() -> None:
    payload = json.loads(response_bytes())
    payload["justifications"].pop("M6")
    outcome = run(FakeTransport(body=json.dumps(payload).encode()))
    assert set(outcome.failed.values()) == {
        "PROVIDER_RESPONSE_JUSTIFICATION_SHAPE_INVALID"
    }


def test_response_body_limit_and_error_redaction() -> None:
    outcome = run(FakeTransport(body=b"x" * (MAX_RESPONSE_BYTES + 1)))
    assert outcome.call_count == 200
    assert set(outcome.failed.values()) == {"RESPONSE_BODY_LIMIT_EXCEEDED"}
    assert (
        redact_error(RuntimeError("Authorization: Bearer secret-provider-echo"))
        == "PROVIDER_ATTEMPT_FAILED"
    )


def _run_plan(*, corpus_file_sha256: str = SHA) -> dict[str, object]:
    return build_run_plan(
        requests(),
        catalog_sha256=SHA,
        evidence_inventory_sha256=SHA,
        prompt_sha256=SHA,
        corpus_file_sha256=corpus_file_sha256,
        entitlement_snapshot_sha256=SHA,
        canary_plan_sha256="1" * 64,
        canary_outcome_sha256="2" * 64,
    )


def _reseal(plan: dict[str, object]) -> dict[str, object]:
    plan["run_plan_sha256"] = canonical_sha256(
        {key: value for key, value in plan.items() if key != "run_plan_sha256"}
    )
    return plan


def _continuation_requests() -> tuple[PublicScoringRequest, ...]:
    rows = json.loads(CONTINUATION_REQUESTS_PATH.read_bytes())
    return tuple(PublicScoringRequest.model_validate(row) for row in rows)


def _tree_sha256(root: Path) -> dict[str, str]:
    return {
        str(path.relative_to(root)): hashlib.sha256(path.read_bytes()).hexdigest()
        for path in sorted(root.rglob("*"))
        if path.is_file()
    }


@pytest.mark.parametrize(
    "mutation",
    [
        lambda plan: plan.update(consumed_completion_calls=91),
        lambda plan: plan.update(retry_candidate_count=2, maximum_new_calls=18),
    ],
)
def test_continuation_plan_rejects_inconsistent_accounting(mutation) -> None:
    plan = json.loads(CONTINUATION_PLAN_PATH.read_bytes())
    mutation(plan)
    plan["maximum_aggregate_calls"] = (
        plan["consumed_completion_calls"] + plan["maximum_new_calls"]
    )
    _reseal(plan)

    with pytest.raises(MvpScoringError, match="CONTINUATION_PLAN_INVALID"):
        verify_run_plan(plan)


def test_continuation_plan_rejects_manifest_membership_drift() -> None:
    plan = json.loads(CONTINUATION_PLAN_PATH.read_bytes())
    manifest = plan["predecessor_result_manifest"]
    manifest[0]["request_sha256"] = "a" * 64
    plan["predecessor_result_manifest_sha256"] = canonical_sha256(manifest)
    _reseal(plan)

    with pytest.raises(MvpScoringError, match="CONTINUATION_PLAN_INVALID"):
        verify_run_plan(plan)


def test_prepare_continuation_preserves_predecessor_and_closes_started(
    tmp_path: Path,
) -> None:
    predecessor = tmp_path / "predecessor"
    output_root = tmp_path / "continuation"
    shutil.copytree(PREDECESSOR_ROOT, predecessor)
    before = _tree_sha256(predecessor)
    plan = json.loads(CONTINUATION_PLAN_PATH.read_bytes())
    request_rows = _continuation_requests()

    prepare_continuation_state(
        plan=plan,
        predecessor_root=predecessor,
        output_root=output_root,
        requests=request_rows,
    )

    assert _tree_sha256(predecessor) == before
    state = json.loads((output_root / "attempt-state.json").read_bytes())
    assert state["run_plan_sha256"] == plan["run_plan_sha256"]
    assert len(state["attempts"]) == 92
    assert sum(row["status"] == "STARTED" for row in state["attempts"]) == 0
    interrupted = [
        row
        for row in state["attempts"]
        if row.get("reason") == "PROCESS_INTERRUPTED_UNKNOWN_OUTCOME"
    ]
    assert len(interrupted) == 1
    assert interrupted[0]["status"] == "FAILED"
    assert list(result_manifest(output_root, request_rows)) == plan[
        "predecessor_result_manifest"
    ]

    with pytest.raises(MvpScoringError, match="CONTINUATION_OUTPUT_ALREADY_EXISTS"):
        prepare_continuation_state(
            plan=plan,
            predecessor_root=predecessor,
            output_root=output_root,
            requests=request_rows,
        )


def test_prepare_continuation_rejects_attempt_state_drift(tmp_path: Path) -> None:
    predecessor = tmp_path / "predecessor"
    shutil.copytree(PREDECESSOR_ROOT, predecessor)
    with (predecessor / "attempt-state.json").open("ab") as handle:
        handle.write(b"\n")

    with pytest.raises(MvpScoringError, match="CONTINUATION_ATTEMPT_STATE_DRIFT"):
        prepare_continuation_state(
            plan=json.loads(CONTINUATION_PLAN_PATH.read_bytes()),
            predecessor_root=predecessor,
            output_root=tmp_path / "continuation",
            requests=_continuation_requests(),
        )


def test_prepare_continuation_rejects_result_manifest_drift(tmp_path: Path) -> None:
    predecessor = tmp_path / "predecessor"
    shutil.copytree(PREDECESSOR_ROOT, predecessor)
    next((predecessor / "results").glob("*.json")).unlink()

    with pytest.raises(MvpScoringError, match="CONTINUATION_RESULT_MANIFEST_DRIFT"):
        prepare_continuation_state(
            plan=json.loads(CONTINUATION_PLAN_PATH.read_bytes()),
            predecessor_root=predecessor,
            output_root=tmp_path / "continuation",
            requests=_continuation_requests(),
        )


def _write_synthetic_plan(tmp_path: Path) -> tuple[Path, Path, Path, str]:
    requests_path = tmp_path / "requests.json"
    requests_path.write_bytes(
        canonical_json_bytes([row.model_dump(mode="json") for row in requests()]) + b"\n"
    )
    canary_plan_sha256 = "1" * 64
    canary_outcome = {
        "schema_version": "mvp-place-scoring-canary-outcome.v1",
        "canary_plan_sha256": canary_plan_sha256,
        "endpoint": "https://api.z.ai/api/coding/paas/v4/chat/completions",
        "model": "glm-5.3-flash",
        "successful": True,
        "failure": None,
        "completion_call_count": 1,
    }
    canary_outcome_path = tmp_path / "canary-outcome.json"
    canary_outcome_path.write_bytes(canonical_json_bytes(canary_outcome) + b"\n")
    plan = build_run_plan(
        requests(),
        catalog_sha256=SHA,
        evidence_inventory_sha256=SHA,
        prompt_sha256=SHA,
        corpus_file_sha256=hashlib.sha256(requests_path.read_bytes()).hexdigest(),
        entitlement_snapshot_sha256=SHA,
        canary_plan_sha256=canary_plan_sha256,
        canary_outcome_sha256=hashlib.sha256(canary_outcome_path.read_bytes()).hexdigest(),
    )
    plan_path = tmp_path / "run-plan.json"
    plan_path.write_bytes(canonical_json_bytes(plan) + b"\n")
    return plan_path, requests_path, canary_outcome_path, str(plan["run_plan_sha256"])


def test_cli_build_canary_inputs_is_byte_stable_from_public_100(tmp_path: Path) -> None:
    selection_output = tmp_path / "selection.json"
    evidence_output = tmp_path / "evidence.json"
    request_output = tmp_path / "request.json"

    assert (
        score_mvp_places.main(
            [
                "build-canary-inputs",
                "--catalog",
                str(REPO_ROOT / "artifacts/public/catalog/public-place-catalog-v1.json"),
                "--evidence",
                str(REPO_ROOT / "artifacts/public/catalog/public-evidence-inventory-v1.json"),
                "--selection-output",
                str(selection_output),
                "--evidence-output",
                str(evidence_output),
                "--request-output",
                str(request_output),
            ]
        )
        == 0
    )
    assert selection_output.read_bytes() == CANARY_SELECTION_PATH.read_bytes()
    assert evidence_output.read_bytes() == CANARY_EVIDENCE_PATH.read_bytes()
    assert request_output.read_bytes() == CANARY_REQUEST_PATH.read_bytes()


def test_cli_canary_selection_binds_request_catalog_and_inner_hash(tmp_path: Path) -> None:
    output = tmp_path / "plan.json"
    request = PublicScoringRequest.model_validate_json(CANARY_REQUEST_PATH.read_bytes())
    selection = json.loads(CANARY_SELECTION_PATH.read_bytes())

    assert (
        score_mvp_places.main(
            [
                "build-canary-plan",
                "--request",
                str(CANARY_REQUEST_PATH),
                "--selection",
                str(CANARY_SELECTION_PATH),
                "--output",
                str(output),
                "--catalog-sha256",
                selection["public_catalog_sha256"],
                "--evidence-inventory-sha256",
                selection["canary_evidence_inventory_sha256"],
                "--prompt-sha256",
                SHA,
                "--entitlement-snapshot-sha256",
                SHA,
            ]
        )
        == 0
    )
    plan = json.loads(output.read_bytes())
    assert plan["place_id"] == request.place.place_id
    assert plan["canary_selection_sha256"] == selection["selection_sha256"]

    selection["public_catalog_overlap_count"] = 1
    tampered = tmp_path / "selection.json"
    tampered.write_bytes(canonical_json_bytes(selection) + b"\n")
    with pytest.raises(MvpScoringError, match="CANARY_SELECTION_HASH_INVALID"):
        score_mvp_places.main(
            [
                "build-canary-plan",
                "--request",
                str(CANARY_REQUEST_PATH),
                "--selection",
                str(tampered),
                "--output",
                str(tmp_path / "tampered-plan.json"),
                "--catalog-sha256",
                selection["public_catalog_sha256"],
                "--evidence-inventory-sha256",
                selection["canary_evidence_inventory_sha256"],
                "--prompt-sha256",
                SHA,
                "--entitlement-snapshot-sha256",
                SHA,
            ]
        )


def test_canary_plan_and_execution_are_exactly_one_safe_call(tmp_path: Path) -> None:
    request = requests()[50]
    plan = build_canary_plan(
        request,
        catalog_sha256=SHA,
        evidence_inventory_sha256=SHA,
        prompt_sha256=SHA,
        response_schema_sha256=SHA,
        entitlement_snapshot_sha256=SHA,
        canary_selection_sha256=SHA,
    )
    actual = verify_canary_plan(plan)
    output_root = tmp_path / "canary"
    transport = FakeTransport({request.place.place_id: 1})

    outcome = execute_diagnostic(
        request,
        transport=transport,
        diagnostic_plan_sha256=actual,
        catalog_sha256=SHA,
        evidence_inventory_sha256=SHA,
        prompt_sha256=SHA,
        on_attempt=lambda event: persist_attempt_event(output_root, event),
        on_result=lambda result: None,
    )

    assert outcome.result is None
    assert outcome.failure == "PROVIDER_ATTEMPT_FAILED"
    assert transport.calls[request.place.place_id] == 1
    assert load_attempt_counts(
        output_root,
        run_plan_sha256=actual,
        requests=requests(),
    ) == {request.place.place_id: 1}


def test_safe_provider_error_code_does_not_expose_message() -> None:
    assert redact_error(MvpScoringError("GLM_HTTP_QUOTA_REJECTED")) == (
        "GLM_HTTP_QUOTA_REJECTED"
    )
    assert redact_error(MvpScoringError("provider body secret")) == "PROVIDER_ATTEMPT_FAILED"


def test_build_and_verify_plan_has_fixed_bounds() -> None:
    plan = _run_plan()
    assert verify_run_plan(plan) == plan["run_plan_sha256"]
    assert plan["first_pass_count"] == 100
    assert plan["maximum_calls"] == 200
    assert plan["concurrency"] == 1
    assert plan["reasoning_effort"] == "max"
    assert plan["response_format"] == "json_object"


def test_canary_plan_binds_selection_provenance() -> None:
    request = requests()[50]
    plan = build_canary_plan(
        request,
        catalog_sha256=SHA,
        evidence_inventory_sha256=SHA,
        prompt_sha256=SHA,
        response_schema_sha256=SHA,
        entitlement_snapshot_sha256=SHA,
        canary_selection_sha256="3" * 64,
    )

    assert verify_canary_plan(plan) == plan["canary_plan_sha256"]
    assert plan["canary_selection_sha256"] == "3" * 64

    plan.pop("canary_selection_sha256")
    with pytest.raises(MvpScoringError, match="CANARY_PLAN_FIELDS_INVALID"):
        verify_canary_plan(plan)


@pytest.mark.parametrize(
    ("mutation", "error"),
    [
        (lambda plan: plan.update(schema_version="wrong.v1"), "RUN_PLAN_BOUNDS_INVALID"),
        (lambda plan: plan.update(catalog_sha256="not-a-sha"), "RUN_PLAN_SHA256_INVALID"),
        (
            lambda plan: plan["place_request_sha256"].__setitem__(
                1, plan["place_request_sha256"][0]
            ),
            "RUN_PLAN_MEMBERSHIP_INVALID",
        ),
        (
            lambda plan: plan["place_request_sha256"].__setitem__(0, "not-a-sha"),
            "RUN_PLAN_MEMBERSHIP_INVALID",
        ),
        (lambda plan: plan.pop("entitlement_snapshot_sha256"), "RUN_PLAN_FIELDS_INVALID"),
        (lambda plan: plan.update(unexpected=True), "RUN_PLAN_FIELDS_INVALID"),
    ],
)
def test_verify_plan_rejects_mutated_shape_and_hashes(mutation, error: str) -> None:
    plan = _run_plan()
    mutation(plan)
    if "run_plan_sha256" in plan and error != "RUN_PLAN_FIELDS_INVALID":
        _reseal(plan)
    with pytest.raises(MvpScoringError, match=error):
        verify_run_plan(plan)


def test_cli_execute_offline_denies_before_credential_or_transport(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    constructed = False

    class ForbiddenTransport:
        def __init__(self, api_key: str) -> None:
            nonlocal constructed
            constructed = True

    plan_path, requests_path, canary_outcome_path, plan_sha256 = _write_synthetic_plan(
        tmp_path
    )
    monkeypatch.setattr(score_mvp_places, "GlmCodingScoringTransport", ForbiddenTransport)
    monkeypatch.setenv("ITDA_OFFLINE", "1")
    monkeypatch.delenv("ZHIPUAI_API_KEY", raising=False)
    with pytest.raises(MvpScoringError, match="NETWORK_DISABLED_BEFORE_CLIENT_CONSTRUCTION"):
        score_mvp_places.main(
            [
                "execute",
                "--plan",
                str(plan_path),
                "--requests",
                str(requests_path),
                "--canary-outcome",
                str(canary_outcome_path),
                "--output-root",
                str(tmp_path / "out"),
                "--reviewed-plan-sha256",
                plan_sha256,
                "--approval",
                f"approve-glm-mvp-scoring:{plan_sha256}",
                "--live",
            ]
        )
    assert constructed is False


def test_execution_authority_is_plan_bound_and_one_use(tmp_path: Path) -> None:
    output_root = tmp_path / "out"

    consume_execution_authority(output_root, RUN_PLAN_SHA256)

    assert json.loads((output_root / "execution-started.json").read_bytes()) == {
        "schema_version": "mvp-scoring-execution-started.v1",
        "run_plan_sha256": RUN_PLAN_SHA256,
    }
    with pytest.raises(MvpScoringError, match="SCORING_EXECUTION_ALREADY_STARTED"):
        consume_execution_authority(output_root, RUN_PLAN_SHA256)


def test_cli_execute_rejects_used_output_before_transport(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    constructed = False

    class ForbiddenTransport:
        def __init__(self, api_key: str) -> None:
            nonlocal constructed
            constructed = True

    plan_path, requests_path, canary_outcome_path, plan_sha256 = _write_synthetic_plan(
        tmp_path
    )
    output_root = tmp_path / "out"
    consume_execution_authority(output_root, plan_sha256)
    monkeypatch.setattr(score_mvp_places, "GlmCodingScoringTransport", ForbiddenTransport)
    monkeypatch.delenv("ITDA_OFFLINE", raising=False)
    monkeypatch.delenv("ITDA_NO_NETWORK", raising=False)
    monkeypatch.setenv("ZHIPUAI_API_KEY", "test-only-placeholder")

    with pytest.raises(MvpScoringError, match="SCORING_EXECUTION_ALREADY_STARTED"):
        score_mvp_places.main(
            [
                "execute",
                "--plan",
                str(plan_path),
                "--requests",
                str(requests_path),
                "--canary-outcome",
                str(canary_outcome_path),
                "--output-root",
                str(output_root),
                "--reviewed-plan-sha256",
                plan_sha256,
                "--approval",
                f"approve-glm-mvp-scoring:{plan_sha256}",
                "--live",
            ]
        )
    assert constructed is False


def test_cli_execute_rejects_consumed_interrupted_plan_before_network(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delenv("ITDA_OFFLINE", raising=False)
    monkeypatch.delenv("ZHIPUAI_API_KEY", raising=False)
    with pytest.raises(MvpScoringError, match="CONSUMED_INTERRUPTED_RUN_PLAN"):
        score_mvp_places.main(
            [
                "execute",
                "--plan",
                str(RUN_PLAN_PATH),
                "--requests",
                str(REQUESTS_PATH),
                "--canary-outcome",
                str(tmp_path / "unused.json"),
                "--output-root",
                str(tmp_path / "out"),
                "--reviewed-plan-sha256",
                RUN_PLAN_SHA256,
                "--approval",
                f"approve-glm-mvp-scoring:{RUN_PLAN_SHA256}",
                "--live",
            ]
        )


def test_cli_execute_rejects_wrong_approval_before_network(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    plan_path, requests_path, canary_outcome_path, plan_sha256 = _write_synthetic_plan(
        tmp_path
    )
    monkeypatch.delenv("ITDA_OFFLINE", raising=False)
    monkeypatch.delenv("ZHIPUAI_API_KEY", raising=False)
    with pytest.raises(MvpScoringError, match="SCORING_APPROVAL_MISMATCH"):
        score_mvp_places.main(
            [
                "execute",
                "--plan",
                str(plan_path),
                "--requests",
                str(requests_path),
                "--canary-outcome",
                str(canary_outcome_path),
                "--output-root",
                str(tmp_path / "out"),
                "--reviewed-plan-sha256",
                plan_sha256,
                "--approval",
                "approve-glm-mvp-scoring:" + "0" * 64,
                "--live",
            ]
        )


def test_offline_denies_before_client_construction(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("ITDA_OFFLINE", "1")
    with pytest.raises(MvpScoringError, match="NETWORK_DISABLED_BEFORE_CLIENT_CONSTRUCTION"):
        build_http_client()
