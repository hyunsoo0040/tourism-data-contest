"""Lossless Korean description and Odii segmentation over immutable source text."""

from __future__ import annotations

import hashlib
import re
from collections.abc import Callable, Iterator
from dataclasses import dataclass

from pydantic import HttpUrl

from itda.contracts.candidate_review import SelectedOdiiStoryIdentity
from itda.contracts.text_evidence import (
    EvidenceLane,
    SourceSpan,
    SourceSpanKind,
)

_LIST_ITEM = re.compile(r"^\s*(?:[-*+]|\d+[.)])\s+", re.UNICODE)
_ODII_SECTION_TITLE = re.compile(r"^\s*(?:해설|이야기|장|절)\s*\d+\s*$", re.UNICODE)
_SENTENCE_BOUNDARY = re.compile(r".*?[.!?。！？](?=\s|$)|.+$", re.DOTALL)
_RECOVERABLE_PIECE = re.compile(r"\S+\s*", re.UNICODE)


@dataclass(frozen=True, slots=True)
class _RawUnit:
    start_char: int
    end_char: int
    kind: SourceSpanKind
    parent_section: str | None


def _sha256_text(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _span_id(
    *,
    lane: EvidenceLane,
    source_id: str,
    source_text_sha256: str,
    start_char: int,
    end_char: int,
    kind: SourceSpanKind,
) -> str:
    identity = (
        f"text-span-v1\0{lane.value}\0{source_id}\0{source_text_sha256}\0"
        f"{start_char}\0{end_char}\0{kind.value}"
    )
    return _sha256_text(identity)


def _line_units(raw_text: str, lane: EvidenceLane) -> Iterator[_RawUnit]:
    """Yield non-empty line/sentence slices without changing source indices."""

    offset = 0
    current_odii_section: str | None = None
    for physical_line in raw_text.splitlines(keepends=True):
        line_end = len(physical_line.rstrip("\r\n"))
        content = physical_line[:line_end]
        if not content.strip():
            offset += len(physical_line)
            continue

        leading = len(content) - len(content.lstrip())
        trailing = len(content.rstrip())
        start = offset + leading
        end = offset + trailing
        trimmed = raw_text[start:end]

        if lane is EvidenceLane.ODII and _ODII_SECTION_TITLE.fullmatch(trimmed):
            current_odii_section = trimmed
            yield _RawUnit(start, end, SourceSpanKind.ODII_SECTION_TITLE, trimmed)
        elif lane is EvidenceLane.DESCRIPTION and _LIST_ITEM.match(trimmed):
            yield _RawUnit(start, end, SourceSpanKind.LIST_ITEM, None)
        elif not re.search(r"[.!?。！？]", trimmed):
            kind = (
                SourceSpanKind.TITLE
                if lane is EvidenceLane.DESCRIPTION
                else SourceSpanKind.SENTENCE
            )
            yield _RawUnit(start, end, kind, current_odii_section)
        else:
            for match in _SENTENCE_BOUNDARY.finditer(trimmed):
                sentence = match.group(0)
                left = len(sentence) - len(sentence.lstrip())
                right = len(sentence.rstrip())
                if left == right:
                    continue
                yield _RawUnit(
                    start + match.start() + left,
                    start + match.start() + right,
                    SourceSpanKind.SENTENCE,
                    current_odii_section,
                )
        offset += len(physical_line)

    if offset < len(raw_text):
        # splitlines(keepends=True) normally consumes the final unterminated line.
        raise ValueError("source segmentation did not consume the complete input")


def _chunk_exactly(
    text: str,
    *,
    token_limit: int,
    token_counter: Callable[[str], int],
) -> tuple[tuple[int, int], ...]:
    """Split a unit at recoverable whitespace/punctuation boundaries without loss."""

    pieces = tuple((match.start(), match.end()) for match in _RECOVERABLE_PIECE.finditer(text))
    if not pieces or pieces[0][0] != 0 or pieces[-1][1] != len(text):
        pieces = tuple((index, index + 1) for index in range(len(text)))

    chunks: list[tuple[int, int]] = []
    chunk_start = pieces[0][0]
    chunk_end = pieces[0][1]
    if token_counter(text[chunk_start:chunk_end]) > token_limit:
        raise ValueError("a source token exceeds the configured recoverable token limit")
    for piece_start, piece_end in pieces[1:]:
        candidate = text[chunk_start:piece_end]
        if token_counter(candidate) <= token_limit:
            chunk_end = piece_end
            continue
        chunks.append((chunk_start, chunk_end))
        chunk_start, chunk_end = piece_start, piece_end
        if token_counter(text[chunk_start:chunk_end]) > token_limit:
            raise ValueError("a source token exceeds the configured recoverable token limit")
    chunks.append((chunk_start, chunk_end))
    if "".join(text[start:end] for start, end in chunks) != text:
        raise ValueError("source chunking lost original text")
    return tuple(chunks)


def _make_span(
    *,
    raw_text: str,
    lane: EvidenceLane,
    source_id: str,
    source_url: str,
    raw_response_sha256: str,
    source_text_sha256: str,
    normalization_version: str,
    selected_odii_story: SelectedOdiiStoryIdentity | None,
    start_char: int,
    end_char: int,
    kind: SourceSpanKind,
    parent_span_id: str | None,
    parent_section: str | None,
) -> SourceSpan:
    original_text = raw_text[start_char:end_char]
    start_byte = len(raw_text[:start_char].encode("utf-8"))
    end_byte = start_byte + len(original_text.encode("utf-8"))
    return SourceSpan(
        span_id=_span_id(
            lane=lane,
            source_id=source_id,
            source_text_sha256=source_text_sha256,
            start_char=start_char,
            end_char=end_char,
            kind=kind,
        ),
        lane=lane,
        kind=kind,
        source_id=source_id,
        source_url=HttpUrl(source_url),
        raw_response_sha256=raw_response_sha256,
        source_text_sha256=source_text_sha256,
        source_slice_sha256=_sha256_text(original_text),
        normalization_version=normalization_version,
        original_text=original_text,
        start_char=start_char,
        end_char=end_char,
        start_byte=start_byte,
        end_byte=end_byte,
        parent_span_id=parent_span_id,
        parent_section=parent_section,
        selected_odii_story=selected_odii_story,
    )


def segment_official_source(
    *,
    raw_text: str,
    lane: EvidenceLane | str,
    source_id: str,
    source_url: str,
    raw_response_sha256: str,
    normalization_version: str,
    rights_approved: bool,
    selected_odii_story: SelectedOdiiStoryIdentity | dict[str, object] | None = None,
    expected_source_text_sha256: str | None = None,
    token_limit: int = 512,
    token_counter: Callable[[str], int] | None = None,
) -> tuple[SourceSpan, ...]:
    """Return exact original-source spans or fail before yielding any artifact."""

    if not rights_approved:
        raise ValueError("rights approval is required before source segmentation")
    if not raw_text:
        raise ValueError("source text must not be empty")
    if token_limit <= 0:
        raise ValueError("token limit must be positive")
    evidence_lane = EvidenceLane(lane)
    source_text_sha256 = _sha256_text(raw_text)
    if (
        expected_source_text_sha256 is not None
        and expected_source_text_sha256 != source_text_sha256
    ):
        raise ValueError("source text digest does not match the approved snapshot")

    odii_identity: SelectedOdiiStoryIdentity | None = None
    if selected_odii_story is not None:
        odii_identity = SelectedOdiiStoryIdentity.model_validate(selected_odii_story)
    if evidence_lane is EvidenceLane.ODII:
        if odii_identity is None:
            raise ValueError("selected Odii story identity is required")
        if odii_identity.raw_response_sha256 != raw_response_sha256:
            raise ValueError("selected Odii story response digest does not match source response")
    elif odii_identity is not None:
        raise ValueError("description lane cannot accept selected Odii story identity")

    count_tokens = token_counter or (lambda value: len(value.split()))
    result: list[SourceSpan] = []
    for unit in _line_units(raw_text, evidence_lane):
        unit_text = raw_text[unit.start_char : unit.end_char]
        if count_tokens(unit_text) <= token_limit:
            result.append(
                _make_span(
                    raw_text=raw_text,
                    lane=evidence_lane,
                    source_id=source_id,
                    source_url=source_url,
                    raw_response_sha256=raw_response_sha256,
                    source_text_sha256=source_text_sha256,
                    normalization_version=normalization_version,
                    selected_odii_story=odii_identity,
                    start_char=unit.start_char,
                    end_char=unit.end_char,
                    kind=unit.kind,
                    parent_span_id=None,
                    parent_section=unit.parent_section,
                )
            )
            continue

        parent = _make_span(
            raw_text=raw_text,
            lane=evidence_lane,
            source_id=source_id,
            source_url=source_url,
            raw_response_sha256=raw_response_sha256,
            source_text_sha256=source_text_sha256,
            normalization_version=normalization_version,
            selected_odii_story=odii_identity,
            start_char=unit.start_char,
            end_char=unit.end_char,
            kind=SourceSpanKind.PARENT_SECTION,
            parent_span_id=None,
            parent_section=unit.parent_section,
        )
        result.append(parent)
        for relative_start, relative_end in _chunk_exactly(
            unit_text,
            token_limit=token_limit,
            token_counter=count_tokens,
        ):
            result.append(
                _make_span(
                    raw_text=raw_text,
                    lane=evidence_lane,
                    source_id=source_id,
                    source_url=source_url,
                    raw_response_sha256=raw_response_sha256,
                    source_text_sha256=source_text_sha256,
                    normalization_version=normalization_version,
                    selected_odii_story=odii_identity,
                    start_char=unit.start_char + relative_start,
                    end_char=unit.start_char + relative_end,
                    kind=unit.kind,
                    parent_span_id=parent.span_id,
                    parent_section=unit.parent_section,
                )
            )
    return tuple(result)
