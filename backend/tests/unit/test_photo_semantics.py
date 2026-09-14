"""Semantic observations, never text bytes, carry photo preference values."""

import pytest

from itda.domain.photo_semantics import (
    PHOTO_SEMANTIC_VERSION,
    resolve_photo_semantic,
    trusted_photo_value,
)


def test_canonical_meaning_is_invariant_to_korean_whitespace() -> None:
    first = resolve_photo_semantic("M5", "산책·장시간 체류")
    second = resolve_photo_semantic("M5", " 산책·장시간   체류 ")
    assert first == second
    assert first is not None and first.value == 100


def test_ids_match_place_rubric_and_unknown_text_has_no_score() -> None:
    assert resolve_photo_semantic("M3", "한적함").value == 0
    assert resolve_photo_semantic("M4", "참여·체험").value == 100
    assert resolve_photo_semantic("M4", "넓게 걷기 좋은 길") is None
    assert resolve_photo_semantic("M5", "아무 새로운 문장") is None


@pytest.mark.parametrize(
    "kind,version",
    [
        ("synthetic", PHOTO_SEMANTIC_VERSION),
        ("legacy", PHOTO_SEMANTIC_VERSION),
        ("semantic", "photo-text-hash-v1"),
    ],
)
def test_untrusted_provenance_cannot_promote_even_canonical_text(kind, version) -> None:
    assert (
        trusted_photo_value(
            trait_id="M5",
            text_ko="산책·장시간 체류",
            semantic_id="M5.long_stay",
            semantic_version=version,
            analysis_kind=kind,
            provider_id="fixture-semantic",
        )
        is None
    )


def test_user_edit_requires_supported_same_dimension_meaning() -> None:
    base = dict(
        trait_id="M5",
        semantic_id="M5.long_stay",
        semantic_version=PHOTO_SEMANTIC_VERSION,
        analysis_kind="semantic",
        provider_id="fixture-semantic",
    )
    assert trusted_photo_value(text_ko="산책·장시간 체류", **base) == 100
    assert trusted_photo_value(text_ko="짧은 관람", **base) == 0
    assert trusted_photo_value(text_ko="특별한 나만의 여행", **base) is None
    assert (
        trusted_photo_value(
            text_ko="산책·장시간 체류", **(base | {"provider_id": "synthetic-photo-analyzer"})
        )
        is None
    )
