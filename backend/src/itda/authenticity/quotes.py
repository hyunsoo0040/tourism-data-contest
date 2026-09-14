"""Recover harmless typography while keeping offsets into the exact source.

No fuzzy matching, synonym substitution, punctuation deletion or Unicode NFKC:
normalization cannot remove a negation, alter a number or silently paraphrase.
"""

from __future__ import annotations

from typing import Literal

from pydantic import Field, model_validator

from itda.contracts.base import StrictContract

QUOTE_MAPPING_VERSION: Literal["quote-offset-mapping-v1"] = "quote-offset-mapping-v1"
_QUOTES = {"‘": "'", "’": "'", "‚": "'", "“": '"', "”": '"', "„": '"'}


class QuoteMatch(StrictContract):
    version: Literal["quote-offset-mapping-v1"] = QUOTE_MAPPING_VERSION
    submitted: str = Field(min_length=1, max_length=4000)
    original: str = Field(min_length=1, max_length=4000)
    start: int = Field(strict=True, ge=0)
    end: int = Field(strict=True, gt=0)
    method: Literal["EXACT", "NORMALIZED_AND_MAPPED"]

    @model_validator(mode="after")
    def bounds(self) -> QuoteMatch:
        if self.end - self.start != len(self.original):
            raise ValueError("QUOTE_OFFSET_LENGTH_MISMATCH")
        if self.method == "EXACT" and self.submitted != self.original:
            raise ValueError("EXACT_QUOTE_CHANGED")
        if self.method == "NORMALIZED_AND_MAPPED" and (
            normalize(self.submitted)[0] != normalize(self.original)[0]
        ):
            raise ValueError("NORMALIZED_QUOTE_CHANGED_MEANING")
        return self


def normalize(text: str) -> tuple[str, list[tuple[int, int]]]:
    chars: list[str] = []
    offsets: list[tuple[int, int]] = []
    for i, char in enumerate(text):
        if char.isspace():
            if chars and chars[-1] == " ":
                offsets[-1] = (offsets[-1][0], i + 1)
            else:
                chars.append(" ")
                offsets.append((i, i + 1))
        else:
            chars.append(_QUOTES.get(char, char))
            offsets.append((i, i + 1))
    return "".join(chars), offsets


def match_quote(source: str, submitted: str) -> QuoteMatch:
    if not submitted or not submitted.strip() or len(submitted) > 4000:
        raise ValueError("EMPTY_OR_OVERSIZED_QUOTE")
    direct = source.find(submitted)
    if direct >= 0:
        return QuoteMatch(
            submitted=submitted,
            original=submitted,
            start=direct,
            end=direct + len(submitted),
            method="EXACT",
        )
    normalized, offsets = normalize(source)
    query, _ = normalize(submitted)
    start = normalized.find(query)
    if start < 0:
        raise ValueError("QUOTE_NOT_IN_BOUND_SOURCE")
    # Repeated normalized matches with different original typography are not
    # resolved by choosing a convenient fragment; exact quoted context is needed.
    if normalized.find(query, start + 1) >= 0:
        raise ValueError("AMBIGUOUS_NORMALIZED_QUOTE")
    left, right = offsets[start][0], offsets[start + len(query) - 1][1]
    return QuoteMatch(
        submitted=submitted,
        original=source[left:right],
        start=left,
        end=right,
        method="NORMALIZED_AND_MAPPED",
    )


def verify_quote(source: str, quote: QuoteMatch) -> None:
    QuoteMatch.model_validate_json(quote.model_dump_json())
    if source[quote.start : quote.end] != quote.original:
        raise ValueError("QUOTE_NOT_AT_BOUND_OFFSETS")
