"""Wave 0 RED contracts for lossless Korean and Odii source segmentation."""

from __future__ import annotations

import hashlib
import importlib
import importlib.util
import json
from pathlib import Path
from types import ModuleType
from typing import Any

import pytest

CAPABILITY_MODULE = "itda.analysis.text.segmentation"
FIXTURE_PATH = Path(__file__).resolve().parents[4] / "fixtures/synthetic/phase3/text-evidence.json"


def _capability() -> ModuleType:
    try:
        available = importlib.util.find_spec(CAPABILITY_MODULE) is not None
    except ModuleNotFoundError:
        available = False
    if not available:
        pytest.fail("PHASE3-MISSING:text-segmentation", pytrace=False)
    return importlib.import_module(CAPABILITY_MODULE)


def _fixture() -> dict[str, Any]:
    return json.loads(FIXTURE_PATH.read_text(encoding="utf-8"))


def _sha256(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _segment(
    capability: ModuleType, source: dict[str, Any], **overrides: object
) -> tuple[Any, ...]:
    arguments: dict[str, object] = {
        "raw_text": source["raw_text"],
        "lane": source["lane"],
        "source_id": source["source_id"],
        "source_url": source["source_url"],
        "raw_response_sha256": source["raw_response_sha256"],
        "normalization_version": _fixture()["normalization_version"],
        "rights_approved": True,
        "selected_odii_story": source.get("selected_odii_story"),
    }
    arguments.update(overrides)
    return tuple(capability.segment_official_source(**arguments))


@pytest.mark.parametrize("source_name", ["description", "odii"])
def test_original_character_and_utf8_offsets_round_trip(source_name: str) -> None:
    capability = _capability()
    source = _fixture()["sources"][source_name]

    spans = _segment(capability, source)

    assert len(spans) == len(source["expected_spans"])
    assert _sha256(source["raw_text"]) == source["source_text_sha256"]
    raw_bytes = source["raw_text"].encode("utf-8")
    for span, expected in zip(spans, source["expected_spans"], strict=True):
        assert span.kind.value == expected["kind"]
        assert span.original_text == expected["text"]
        assert (span.start_char, span.end_char) == (
            expected["start_char"],
            expected["end_char"],
        )
        assert (span.start_byte, span.end_byte) == (
            expected["start_byte"],
            expected["end_byte"],
        )
        assert source["raw_text"][span.start_char : span.end_char] == span.original_text
        assert raw_bytes[span.start_byte : span.end_byte].decode("utf-8") == span.original_text
        assert span.source_text_sha256 == source["source_text_sha256"]
        assert span.source_slice_sha256 == _sha256(span.original_text)
        assert span.normalization_version == _fixture()["normalization_version"]


def test_odii_spans_bind_the_selected_response_identity() -> None:
    capability = _capability()
    source = _fixture()["sources"]["odii"]

    spans = _segment(capability, source)

    assert all(span.selected_odii_story is not None for span in spans)
    assert all(
        span.selected_odii_story.model_dump(mode="json") == source["selected_odii_story"]
        for span in spans
    )

    drifted = dict(source["selected_odii_story"])
    drifted["raw_response_sha256"] = "c" * 64
    with pytest.raises(ValueError, match="selected Odii|response"):
        _segment(capability, source, selected_odii_story=drifted)


def test_source_digest_drift_fails_before_any_span_is_returned() -> None:
    capability = _capability()
    source = _fixture()["sources"]["description"]

    with pytest.raises(ValueError, match="source|digest"):
        _segment(capability, source, expected_source_text_sha256="d" * 64)


def test_rights_blocked_source_creates_no_span_artifact() -> None:
    capability = _capability()
    source = _fixture()["sources"]["description"]

    with pytest.raises(ValueError, match="rights"):
        _segment(capability, source, rights_approved=False)


def test_over_cap_section_splits_into_exact_parent_child_spans_without_truncation() -> None:
    capability = _capability()
    source = _fixture()["sources"]["odii"]
    raw_text = ("봄바람, " * 260) + ("달빛, " * 260) + "끝."

    spans = _segment(
        capability,
        source,
        raw_text=raw_text,
        expected_source_text_sha256=_sha256(raw_text),
        token_limit=512,
        token_counter=lambda value: len(value.split()),
    )
    children = tuple(span for span in spans if span.parent_span_id is not None)

    assert len(children) >= 2
    assert all(len(span.original_text.split()) <= 512 for span in children)
    assert all(raw_text[span.start_char : span.end_char] == span.original_text for span in children)
    assert all(
        raw_text.encode("utf-8")[span.start_byte : span.end_byte].decode("utf-8")
        == span.original_text
        for span in children
    )
    assert "".join(span.original_text for span in children) == raw_text
    parent_ids = {span.span_id for span in spans if span.parent_span_id is None}
    assert {span.parent_span_id for span in children} <= parent_ids
