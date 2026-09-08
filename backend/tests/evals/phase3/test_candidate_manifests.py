"""Wave 0 RED contracts for freeze-first deterministic candidate manifests."""

from __future__ import annotations

import copy
import hashlib
import importlib
import importlib.util
import json
import os
import shutil
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from pathlib import Path
from types import ModuleType, SimpleNamespace
from typing import Any

import pytest

from itda.domain.canonical import canonical_json_bytes, canonical_sha256

CAPABILITY_MODULE = "itda.analysis.text.candidate_pipeline"
REPOSITORY_ROOT = Path(__file__).resolve().parents[4]
FIXTURE_PATH = REPOSITORY_ROOT / "fixtures/synthetic/phase3/candidate-manifest.json"
RECEIPT_PATH = REPOSITORY_ROOT / "fixtures/synthetic/phase3/approved-label-freeze-receipt.json"
NOW = "2026-08-03T12:00:00Z"


def _capability() -> ModuleType:
    try:
        available = importlib.util.find_spec(CAPABILITY_MODULE) is not None
    except ModuleNotFoundError:
        available = False
    if not available:
        pytest.fail("PHASE3-MISSING:candidate-pipeline", pytrace=False)
    return importlib.import_module(CAPABILITY_MODULE)


def _runner() -> ModuleType:
    return importlib.import_module("itda.cli.build_text_candidates")


def _load(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def _fixture() -> dict[str, Any]:
    return _load(FIXTURE_PATH)


def _receipt() -> dict[str, Any]:
    return _load(RECEIPT_PATH)


def _sha256_text(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _rehash_authority(receipt: dict[str, Any]) -> None:
    authority = copy.deepcopy(receipt["authority"])
    authority.pop("authority_sha256", None)
    receipt["authority"]["authority_sha256"] = canonical_sha256(authority)


def _rehash_receipt(receipt: dict[str, Any]) -> None:
    payload = copy.deepcopy(receipt)
    payload.pop("receipt_sha256", None)
    receipt["receipt_sha256"] = canonical_sha256(payload)


def _rehash_candidate_manifest(manifest: dict[str, Any]) -> None:
    provenance = manifest["provenance"]
    provenance.pop("output_sha256", None)
    provenance["output_sha256"] = canonical_sha256(manifest)


def _forbidden_markers() -> tuple[str, ...]:
    return tuple(_fixture()["forbidden_canaries"])


def _assert_redacted(surfaces: dict[str, object]) -> None:
    for surface, payload in surfaces.items():
        rendered = json.dumps(payload, ensure_ascii=False, sort_keys=True, default=str)
        if any(marker in rendered for marker in _forbidden_markers()):
            pytest.fail(f"PHASE3-LEAK:{surface}", pytrace=False)


@dataclass
class DeterministicFakeEncoder:
    """Label-free local test double with no model import, path, cache, or network access."""

    inputs: list[str] = field(default_factory=list)

    @staticmethod
    def _vector(text: str) -> tuple[float, float, float, float]:
        digest = hashlib.sha256(text.encode("utf-8")).digest()
        return tuple(round(value / 255.0, 12) for value in digest[:4])  # type: ignore[return-value]

    def encode_document(self, texts: list[str], **_: object) -> tuple[tuple[float, ...], ...]:
        self.inputs.extend(texts)
        return tuple(self._vector(text) for text in texts)

    def encode_query(self, texts: list[str], **_: object) -> tuple[tuple[float, ...], ...]:
        self.inputs.extend(texts)
        return tuple(self._vector(text) for text in texts)


@dataclass
class ObservationRecorder:
    events: list[str] = field(default_factory=list)
    event_payloads: list[dict[str, object]] = field(default_factory=list)
    encoder: DeterministicFakeEncoder = field(default_factory=DeterministicFakeEncoder)

    def observe(self, stage: str, **payload: object) -> None:
        self.events.append(stage)
        self.event_payloads.append(dict(payload))

    def resolve_model_location(self) -> str:
        self.events.append("MODEL_LOCATION_RESOLVED")
        return "synthetic-model-location"

    def resolve_cache_location(self) -> str:
        self.events.append("CACHE_LOCATION_RESOLVED")
        return "synthetic-cache-location"

    def create_encoder(self, _: str) -> DeterministicFakeEncoder:
        self.events.append("ENCODER_CREATED")
        return self.encoder


@dataclass
class ControlledClock:
    instants: list[datetime]
    calls: int = 0

    def __call__(self) -> datetime:
        if self.calls >= len(self.instants):
            raise AssertionError("candidate clock was read more often than expected")
        instant = self.instants[self.calls]
        self.calls += 1
        return instant


def _production_span_manifest() -> dict[str, Any]:
    text = "왕궁 터의 석축과 전통 경관이 선명하다."
    text_sha256 = _sha256_text(text)
    return {
        "schema_version": "text-span-dedup-manifest-v1",
        "normalization_version": "ko-segmentation-v1",
        "spans": [
            {
                "lane": "DESCRIPTION",
                "kind": "SENTENCE",
                "source_id": "synthetic-description-source",
                "source_text_sha256": text_sha256,
                "span_id": "synthetic-description-span",
                "source_slice_sha256": text_sha256,
                "start_char": 0,
                "end_char": len(text),
                "start_byte": 0,
                "end_byte": len(text.encode("utf-8")),
                "original_text": text,
            }
        ],
        "dedup_clusters": [
            {
                "cluster_id": "synthetic-description-cluster",
                "originals": [{"span_id": "synthetic-description-span"}],
            }
        ],
        "dedup_edges": [],
    }


def _production_model_manifest() -> SimpleNamespace:
    return SimpleNamespace(
        model_id="BAAI/bge-m3",
        model_revision="b28ce2a6fcc9c75ef1c0619575d0ec19af760082",
        model_config_sha256="1" * 64,
        tokenizer_sha256="2" * 64,
        weight_sha256="3" * 64,
    )


def _build_production_manifest(
    monkeypatch: pytest.MonkeyPatch,
    *,
    started_at: datetime,
    completed_at: datetime,
) -> dict[str, Any]:
    runner = _runner()
    monkeypatch.setattr(
        runner,
        "_SentenceTransformerAdapter",
        lambda _: DeterministicFakeEncoder(),
    )
    clock = ControlledClock([completed_at])
    result = runner._span_candidate_manifest(
        span_manifest=_production_span_manifest(),
        span_manifest_sha256="4" * 64,
        freeze_receipt_sha256=_receipt()["receipt_sha256"],
        accepted_revision_set_sha256=_receipt()["freeze"]["accepted_revision_set_sha256"],
        data_lineage_sha256=_receipt()["freeze"]["data_lineage_sha256"],
        started_at=started_at,
        clock=clock,
        model_manifest=_production_model_manifest(),
        model_root=Path("synthetic-model-root"),
    )
    assert clock.calls == 1
    result.pop("_lane_payloads")
    return result


def _build_publishable_production_manifest(
    monkeypatch: pytest.MonkeyPatch,
) -> dict[str, Any]:
    runner = _runner()
    monkeypatch.setattr(
        runner,
        "_SentenceTransformerAdapter",
        lambda _: DeterministicFakeEncoder(),
    )
    return runner._span_candidate_manifest(
        span_manifest=_production_span_manifest(),
        span_manifest_sha256="4" * 64,
        freeze_receipt_sha256=_receipt()["receipt_sha256"],
        accepted_revision_set_sha256=_receipt()["freeze"]["accepted_revision_set_sha256"],
        data_lineage_sha256=_receipt()["freeze"]["data_lineage_sha256"],
        started_at=datetime(2026, 8, 3, 12, 5, tzinfo=UTC),
        clock=ControlledClock([datetime(2026, 8, 3, 12, 5, 7, tzinfo=UTC)]),
        model_manifest=_production_model_manifest(),
        model_root=Path("synthetic-model-root"),
    )


def _build(capability: ModuleType, recorder: ObservationRecorder) -> dict[str, Any]:
    return capability.build_candidate_manifest(
        source_manifest=copy.deepcopy(_fixture()),
        freeze_receipt=copy.deepcopy(_receipt()),
        expected_authority_sha256=_receipt()["authority"]["authority_sha256"],
        now=NOW,
        resolve_model_location=recorder.resolve_model_location,
        resolve_cache_location=recorder.resolve_cache_location,
        encoder_factory=recorder.create_encoder,
        observation_hook=recorder.observe,
    )


def test_synthetic_fixture_and_freeze_receipt_are_canonical_and_self_authenticating() -> None:
    fixture = _fixture()
    receipt = _receipt()

    assert fixture["synthetic_only"] is True
    assert fixture["partition"] == "SYNTHETIC_ONLY"
    assert receipt["synthetic_only"] is True
    assert receipt["authority"]["scope"] == "SYNTHETIC_ONLY"
    assert receipt["freeze"]["source_manifest_sha256"] == canonical_sha256(fixture)

    authority = copy.deepcopy(receipt["authority"])
    authority_sha256 = authority.pop("authority_sha256")
    assert authority_sha256 == canonical_sha256(authority)
    receipt_payload = copy.deepcopy(receipt)
    receipt_sha256 = receipt_payload.pop("receipt_sha256")
    assert receipt_sha256 == canonical_sha256(receipt_payload)

    for source in fixture["sources"]:
        if source.get("status") == "MISSING":
            assert source["spans"] == []
            assert source["source_sha256"] is None
            continue
        raw_text = source["raw_text"]
        assert _sha256_text(raw_text) == source["source_sha256"]
        raw_bytes = raw_text.encode("utf-8")
        for span in source["spans"]:
            char_slice = raw_text[span["start_char"] : span["end_char"]]
            byte_slice = raw_bytes[span["start_byte"] : span["end_byte"]].decode("utf-8")
            assert char_slice == byte_slice
            assert _sha256_text(char_slice) == span["slice_sha256"]


@pytest.mark.parametrize(
    "case",
    ("missing", "malformed", "stale", "drifted", "non_synthetic"),
)
def test_invalid_freeze_receipt_fails_before_model_or_cache_observation(case: str) -> None:
    capability = _capability()
    recorder = ObservationRecorder()
    receipt: dict[str, Any] | None = copy.deepcopy(_receipt())

    if case == "missing":
        receipt = None
    elif case == "malformed":
        receipt["schema_version"] = "unexpected-schema"
        _rehash_receipt(receipt)
    elif case == "stale":
        receipt["authority"]["expires_at"] = "2026-08-03T11:59:59Z"
        _rehash_authority(receipt)
        _rehash_receipt(receipt)
    elif case == "drifted":
        receipt["freeze"]["source_manifest_sha256"] = "c" * 64
    else:
        receipt["synthetic_only"] = False
        receipt["authority"]["scope"] = "UNAPPROVED"
        _rehash_authority(receipt)
        _rehash_receipt(receipt)

    with pytest.raises(ValueError, match="freeze|receipt|synthetic|expired|digest"):
        capability.build_candidate_manifest(
            source_manifest=copy.deepcopy(_fixture()),
            freeze_receipt=receipt,
            expected_authority_sha256=_receipt()["authority"]["authority_sha256"],
            now=NOW,
            resolve_model_location=recorder.resolve_model_location,
            resolve_cache_location=recorder.resolve_cache_location,
            encoder_factory=recorder.create_encoder,
            observation_hook=recorder.observe,
        )

    assert recorder.events == []


def test_verified_freeze_precedes_every_model_and_cache_observation() -> None:
    capability = _capability()
    recorder = ObservationRecorder()

    result = _build(capability, recorder)

    assert recorder.events[0] == "FREEZE_VERIFIED"
    first_model_event = min(
        recorder.events.index("MODEL_LOCATION_RESOLVED"),
        recorder.events.index("CACHE_LOCATION_RESOLVED"),
        recorder.events.index("ENCODER_CREATED"),
    )
    assert recorder.events.index("FREEZE_VERIFIED") < first_model_event
    capability.validate_candidate_manifest(result)


def test_fake_encoder_is_label_free_and_same_controlled_run_is_reproducible() -> None:
    capability = _capability()
    results: list[dict[str, Any]] = []
    recorders: list[ObservationRecorder] = []

    for _ in range(3):
        recorder = ObservationRecorder()
        recorders.append(recorder)
        results.append(_build(capability, recorder))

    payloads = [canonical_json_bytes(result) for result in results]
    hashes = [hashlib.sha256(payload).hexdigest() for payload in payloads]
    semantic_hashes = [canonical_sha256(result["lanes"]) for result in results]
    assert semantic_hashes[0] == semantic_hashes[1] == semantic_hashes[2]
    assert payloads[0] == payloads[1] == payloads[2]
    assert hashes[0] == hashes[1] == hashes[2]

    allowed_text = {item["query_ko"] for item in _fixture()["attributes"]} | {
        source["raw_text"][span["start_char"] : span["end_char"]]
        for source in _fixture()["sources"]
        for span in source["spans"]
        if "raw_text" in source
    }
    assert all(set(recorder.encoder.inputs) <= allowed_text for recorder in recorders)
    _assert_redacted(
        {
            "artifacts": results,
            "cache_keys": [recorder.event_payloads for recorder in recorders],
            "encoder_inputs": [recorder.encoder.inputs for recorder in recorders],
        }
    )


def test_stable_ties_lane_isolation_missing_and_complete_provenance() -> None:
    capability = _capability()
    result = _build(capability, ObservationRecorder())

    description = result["lanes"]["DESCRIPTION"]
    odii = result["lanes"]["ODII"]
    assert [item["span_id"] for item in description["candidates"][:2]] == _fixture()["expected"][
        "stable_tie_order"
    ]
    assert all(item["lane"] == "DESCRIPTION" for item in description["candidates"])
    assert len(description["published_evidence"]) <= 3
    assert odii == {"status": "MISSING", "candidates": [], "published_evidence": []}

    required_provenance = {
        "freeze_receipt_sha256",
        "accepted_revision_set_sha256",
        "source_manifest_sha256",
        "data_lineage_sha256",
        "data_version",
        "model_id",
        "model_revision",
        "model_config_sha256",
        "tokenizer_sha256",
        "weight_sha256",
        "prompt_anchor_version",
        "preprocessing_version",
        "scoring_version",
        "code_git_sha",
        "config_sha256",
        "started_at",
        "completed_at",
        "output_sha256",
    }
    assert set(result["provenance"]) == required_provenance
    capability.validate_candidate_manifest(result)


def test_production_candidate_clock_is_distinct_from_freeze_and_preserved(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    started_at = datetime(2026, 8, 3, 12, 5, tzinfo=UTC)
    completed_at = started_at + timedelta(seconds=7)

    result = _build_production_manifest(
        monkeypatch,
        started_at=started_at,
        completed_at=completed_at,
    )

    provenance = result["provenance"]
    assert provenance["started_at"] == "2026-08-03T12:05:00Z"
    assert provenance["completed_at"] == "2026-08-03T12:05:07Z"
    assert provenance["started_at"] != _receipt()["freeze"]["frozen_at"]
    assert provenance["completed_at"] != _receipt()["freeze"]["frozen_at"]
    _capability().validate_candidate_manifest(result)


def test_candidate_runner_orders_freeze_start_compute_complete_and_publish(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    runner = _runner()
    events: list[str] = []
    started_at = datetime(2026, 8, 3, 12, 5, tzinfo=UTC)
    completed_at = started_at + timedelta(seconds=7)
    clock_values = iter((started_at, completed_at))
    published: dict[str, Any] = {}

    def clock() -> datetime:
        instant = next(clock_values)
        events.append(f"CLOCK_{len([event for event in events if event.startswith('CLOCK_')])}")
        return instant

    class FreezeGuardStub:
        @staticmethod
        def from_path(_: Path) -> tuple[dict[str, Any], str]:
            events.append("FREEZE_VERIFIED")
            return copy.deepcopy(_receipt()), _receipt()["receipt_sha256"]

    original_freeze_bindings = runner._freeze_bindings

    def freeze_bindings(receipt: dict[str, Any]) -> tuple[str, str, str]:
        events.append("FREEZE_BOUND")
        return original_freeze_bindings(receipt)

    def verify_model(_: Path) -> tuple[SimpleNamespace, Path]:
        events.append("MODEL_OBSERVED")
        manifest = _production_model_manifest()
        manifest.freeze_receipt_sha256 = _receipt()["receipt_sha256"]
        return manifest, Path("synthetic-model-root")

    def read_span(_: Path) -> bytes:
        events.append("SPAN_OBSERVED")
        return canonical_json_bytes({"schema_version": "text-span-dedup-manifest-v1"})

    def build_manifest(**kwargs: Any) -> dict[str, Any]:
        events.append("LANES_COMPUTED")
        assert kwargs["started_at"] == started_at
        completion = kwargs["clock"]()
        events.append("MANIFEST_HASHED")
        return {
            "provenance": {
                "started_at": started_at,
                "completed_at": completion,
            }
        }

    def publish(_: Path, manifest: dict[str, Any]) -> None:
        events.append("PUBLISHED")
        published.update(manifest)

    def verify(_: Path) -> dict[str, Any]:
        events.append("READ_ONLY_VERIFIED")
        return published

    monkeypatch.setattr(runner, "VerifiedFreezeGuard", FreezeGuardStub)
    monkeypatch.setattr(runner, "_freeze_bindings", freeze_bindings)
    monkeypatch.setattr(runner, "verify_local_snapshot", verify_model)
    monkeypatch.setattr(runner, "_read_stable_source_manifest", read_span)
    monkeypatch.setattr(runner, "_reject_evaluation_shaped_keys", lambda _: None)
    monkeypatch.setattr(runner, "_span_candidate_manifest", build_manifest)
    monkeypatch.setattr(runner, "_publish_candidate_directory", publish)
    monkeypatch.setattr(runner, "_verify_candidate_directory", verify)

    result = runner._run_candidate(
        SimpleNamespace(
            freeze_receipt=Path("synthetic-freeze.json"),
            model_manifest=Path("synthetic-model.json"),
            span_manifest=Path("synthetic-spans.json"),
            output=Path("synthetic-output"),
        ),
        clock=clock,
    )

    assert result is published
    assert events == [
        "FREEZE_VERIFIED",
        "FREEZE_BOUND",
        "CLOCK_0",
        "MODEL_OBSERVED",
        "SPAN_OBSERVED",
        "LANES_COMPUTED",
        "CLOCK_1",
        "MANIFEST_HASHED",
        "PUBLISHED",
        "READ_ONLY_VERIFIED",
    ]


def test_candidate_publication_never_replaces_a_racing_directory(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    runner = _runner()
    output = tmp_path / "candidate-output"
    collision_identity: tuple[int, int] | None = None
    real_rename = runner._rename_directory_noreplace_at

    def insert_collision_then_rename(
        parent_descriptor: int,
        source_name: str,
        destination_name: str,
    ) -> None:
        nonlocal collision_identity
        os.mkdir(destination_name, dir_fd=parent_descriptor)
        metadata = os.stat(
            destination_name,
            dir_fd=parent_descriptor,
            follow_symlinks=False,
        )
        collision_identity = (metadata.st_dev, metadata.st_ino)
        real_rename(parent_descriptor, source_name, destination_name)

    monkeypatch.setattr(
        runner,
        "_rename_directory_noreplace_at",
        insert_collision_then_rename,
    )

    with pytest.raises(FileExistsError):
        runner._publish_candidate_directory(
            output,
            _build_publishable_production_manifest(monkeypatch),
        )

    assert collision_identity is not None
    visible = output.stat()
    assert (visible.st_dev, visible.st_ino) == collision_identity
    assert list(output.iterdir()) == []


def test_candidate_publication_fails_closed_without_atomic_noreplace_primitive(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    runner = _runner()
    monkeypatch.setattr(runner.ctypes, "CDLL", lambda *_args, **_kwargs: SimpleNamespace())

    with pytest.raises(OSError, match="atomic no-replace"):
        runner._rename_directory_noreplace_at(-1, "prepared", "visible")


def test_candidate_verification_rejects_visible_directory_swap(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    runner = _runner()
    output = tmp_path / "candidate-output"
    runner._publish_candidate_directory(
        output,
        _build_publishable_production_manifest(monkeypatch),
    )
    replacement = tmp_path / "replacement"
    displaced = tmp_path / "displaced"
    shutil.copytree(output, replacement)
    real_read = runner._read_candidate_file_at
    swapped = False

    def swap_before_first_file_read(directory_descriptor: int, name: str) -> bytes:
        nonlocal swapped
        if not swapped:
            swapped = True
            os.rename(output, displaced)
            os.rename(replacement, output)
        return real_read(directory_descriptor, name)

    monkeypatch.setattr(runner, "_read_candidate_file_at", swap_before_first_file_read)

    with pytest.raises(ValueError, match="changed|identity|directory"):
        runner._verify_candidate_directory(output)


def test_candidate_run_timestamps_change_only_run_manifest_hashes(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    first_start = datetime(2026, 8, 3, 12, 5, tzinfo=UTC)
    second_start = first_start + timedelta(minutes=1)

    first = _build_production_manifest(
        monkeypatch,
        started_at=first_start,
        completed_at=first_start + timedelta(seconds=2),
    )
    repeated = _build_production_manifest(
        monkeypatch,
        started_at=first_start,
        completed_at=first_start + timedelta(seconds=2),
    )
    second = _build_production_manifest(
        monkeypatch,
        started_at=second_start,
        completed_at=second_start + timedelta(seconds=2),
    )

    assert first["artifacts"] == repeated["artifacts"] == second["artifacts"]
    assert first["lanes"] == repeated["lanes"] == second["lanes"]
    assert canonical_json_bytes(first) == canonical_json_bytes(repeated)
    assert first["provenance"]["output_sha256"] != second["provenance"]["output_sha256"]
    _capability().validate_candidate_manifest(first)
    _capability().validate_candidate_manifest(repeated)
    _capability().validate_candidate_manifest(second)


@pytest.mark.parametrize(
    ("started_at", "completed_at"),
    (
        ("not-a-timestamp", "2026-08-03T12:05:07Z"),
        ("2026-08-03T12:05:00", "2026-08-03T12:05:07Z"),
        ("2026-08-03T21:05:00+09:00", "2026-08-03T12:05:07Z"),
        ("2026-08-03T12:05:08Z", "2026-08-03T12:05:07Z"),
    ),
    ids=("malformed", "naive", "non-utc", "reversed"),
)
def test_candidate_run_timestamp_validation_fails_closed(
    started_at: str,
    completed_at: str,
) -> None:
    capability = _capability()
    result = _build(capability, ObservationRecorder())
    result["provenance"]["started_at"] = started_at
    result["provenance"]["completed_at"] = completed_at
    _rehash_candidate_manifest(result)

    with pytest.raises(ValueError, match="time|timestamp|UTC|precede"):
        capability.validate_candidate_manifest(result)


def test_label_shaped_input_is_rejected_without_leaking_the_matched_value() -> None:
    capability = _capability()
    source_manifest = copy.deepcopy(_fixture())
    source_manifest["expert_score"] = _forbidden_markers()[0]
    recorder = ObservationRecorder()

    with pytest.raises(ValueError) as failure:
        capability.build_candidate_manifest(
            source_manifest=source_manifest,
            freeze_receipt=copy.deepcopy(_receipt()),
            expected_authority_sha256=_receipt()["authority"]["authority_sha256"],
            now=NOW,
            resolve_model_location=recorder.resolve_model_location,
            resolve_cache_location=recorder.resolve_cache_location,
            encoder_factory=recorder.create_encoder,
            observation_hook=recorder.observe,
        )

    _assert_redacted({"error": str(failure.value), "events": recorder.event_payloads})
    assert recorder.events == []


@pytest.mark.parametrize(
    "case",
    ("cross_lane", "fabricated_missing", "over_three", "incomplete_provenance"),
)
def test_hostile_candidate_outputs_fail_closed(case: str) -> None:
    capability = _capability()
    result = _build(capability, ObservationRecorder())
    hostile = copy.deepcopy(result)

    if case == "cross_lane":
        hostile["lanes"]["DESCRIPTION"]["candidates"][0]["lane"] = "ODII"
    elif case == "fabricated_missing":
        hostile["lanes"]["ODII"]["published_evidence"] = [
            copy.deepcopy(hostile["lanes"]["DESCRIPTION"]["candidates"][0])
        ]
    elif case == "over_three":
        evidence = hostile["lanes"]["DESCRIPTION"]["candidates"][0]
        hostile["lanes"]["DESCRIPTION"]["published_evidence"] = [
            {**copy.deepcopy(evidence), "candidate_id": f"synthetic-candidate-{index}"}
            for index in range(4)
        ]
    else:
        hostile["provenance"].pop("model_revision")

    with pytest.raises(ValueError, match="lane|MISSING|evidence|provenance|model"):
        capability.validate_candidate_manifest(hostile)


def test_redaction_scanner_failure_names_only_the_surface() -> None:
    with pytest.raises(pytest.fail.Exception) as failure:
        _assert_redacted({"report": {"value": _forbidden_markers()[0]}})

    assert str(failure.value) == "PHASE3-LEAK:report"
