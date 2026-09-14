from __future__ import annotations

import pytest

from itda.contracts.visual_mood import MoodChoice, MoodObservation, VisualMoodDimension
from itda.domain.visual_mood import (
    aggregate_moods,
    build_candidate_set,
    confirm_moods,
    mood_draft_sha256,
)


def observations(**values: int) -> tuple[MoodObservation, ...]:
    return tuple(
        MoodObservation(
            dimension=dimension,
            state="OBSERVED" if dimension.value in values else "UNKNOWN",
            level=values.get(dimension.value),
            certainty="HIGH" if dimension.value in values else "LOW",
        )
        for dimension in VisualMoodDimension
    )


def batch(image: str, **values: int):
    return build_candidate_set(
        job_id="a" * 64,
        image_index=1,
        image_sha256=image * 64,
        observations=observations(**values),
        provider_id="glm-mood-test",
        analysis_kind="MODEL",
        model="glm-5.3-flash",
    )


def test_closed_visual_authority_and_unknown() -> None:
    with pytest.raises(ValueError):
        MoodObservation(dimension="M3.quiet", state="OBSERVED", level=4, certainty="HIGH")
    with pytest.raises(ValueError):
        MoodObservation(dimension="water", state="UNKNOWN", level=0, certainty="LOW")
    with pytest.raises(ValueError):
        MoodObservation(dimension="water", state="OBSERVED", level=4, certainty="LOW")
    with pytest.raises(ValueError):
        MoodObservation(dimension="water", state="OBSERVED", level=4, certainty="HIGH", crowd=10)


def test_distinct_images_equal_weight_and_unknown_never_zero() -> None:
    first, second = batch("b", water=4), batch("c", water=2, greenery=0)
    actual = aggregate_moods((first, second, first))
    assert actual == aggregate_moods((second, first))
    by_id = {row.dimension.value: row for row in actual}
    assert by_id["water"].value == 75
    assert by_id["greenery"].value == 0
    assert by_id["warm_light"].value is None


def test_empty_and_all_excluded_are_valid() -> None:
    first = batch("b", water=4)
    assert all(row.value is None for row in aggregate_moods((first,), selected_candidate_ids=()))
    assert all(row.value is None for row in aggregate_moods((batch("c"),)))


def test_synthetic_has_no_model_authority() -> None:
    with pytest.raises(ValueError):
        build_candidate_set(
            job_id="a" * 64,
            image_index=1,
            image_sha256="b" * 64,
            observations=observations(water=4),
            provider_id="synthetic-mood-v1",
            analysis_kind="SYNTHETIC",
            model=None,
        )


def test_confirmation_requires_current_stored_references_and_is_order_stable() -> None:
    first, second = batch("b", water=4), batch("c", greenery=2)
    batches = first, second
    choices = tuple(
        MoodChoice(candidate_id=row.candidate_id, included=True)
        for b in batches
        for row in b.candidates
        if row.observation.state == "OBSERVED"
    )
    draft = mood_draft_sha256(job_id="a" * 64, profile_id="profile:one", batches=batches)
    actual = confirm_moods(
        job_id="a" * 64,
        profile_id="profile:one",
        batches=batches,
        choices=choices,
        draft_sha256=draft,
    )
    assert actual == confirm_moods(
        job_id="a" * 64,
        profile_id="profile:one",
        batches=tuple(reversed(batches)),
        choices=tuple(reversed(choices)),
        draft_sha256=draft,
    )
    with pytest.raises(ValueError):
        confirm_moods(
            job_id="a" * 64,
            profile_id="profile:other",
            batches=batches,
            choices=choices,
            draft_sha256=draft,
        )
    with pytest.raises(ValueError):
        confirm_moods(
            job_id="a" * 64,
            profile_id="profile:one",
            batches=batches,
            choices=(MoodChoice(candidate_id="f" * 64, included=True),),
            draft_sha256=draft,
        )


def test_lifecycle_dispatches_stored_family_deduplicates_and_preserves_unknown(
    monkeypatch, tmp_path
) -> None:
    from contextlib import nullcontext

    from itda.api.routes import photo as route
    from itda.photo.provider.mood import SyntheticMoodProvider

    class CountingProvider(SyntheticMoodProvider):
        calls = 0

        def analyze(self, **kwargs):
            self.calls += 1
            return super().analyze(**kwargs)

    provider = CountingProvider()
    gateway = route.PhotoLifecycleGateway(
        factory=None,
        service_dsn="test-only",
        quarantine_root=tmp_path,
        runtime_role="unused",
        builder_role="unused",
        mood_provider=provider,
        synthetic_test_mode=True,
        mood_enabled=False,
    )  # persisted family survives a deployment flag change
    monkeypatch.setattr(gateway._mood_store, "family", lambda **_kw: "photo-mood-v1")
    monkeypatch.setattr(route.psycopg, "connect", lambda *_a, **_kw: nullcontext(None))
    monkeypatch.setattr(
        gateway,
        "_durable_slot_inventory",
        lambda *_a, **_kw: {i: ("a" * 32, 100, "image/png") for i in (1, 2, 3)},
    )
    monkeypatch.setattr(
        gateway, "_sanitized_bytes", lambda **_kw: b"\x89PNG\r\n\x1a\nmock-sanitized"
    )
    tmp_path.chmod(0o700)
    batches = gateway._analyze_stored_images(job_id="a" * 64, profile_id="profile:one")
    assert provider.calls == 1
    assert len(batches) == 3
    assert all(len(row.candidates) == 8 for row in batches)
    assert all(row.value is None for row in aggregate_moods(tuple(batches)))


def test_mood_routes_require_owner_and_only_accept_choices(monkeypatch) -> None:
    from fastapi import FastAPI
    from fastapi.testclient import TestClient

    from itda.api.dependencies import (
        ProfileSessionPrincipal,
        get_profile_session,
    )
    from itda.api.routes import photo_moods
    from itda.api.routes.photo import get_photo_lifecycle
    from itda.api.routes.photo_moods import router
    from itda.photo.mood_service import PhotoMoodService

    first = batch("b", water=4)

    class Store:
        def family(self, *, job_id, profile_id):
            if profile_id != "profile:one":
                raise PermissionError()
            return "photo-mood-v1"

        def read_batches(self, **_kwargs):
            return (first,)

        def read_confirmation(self, **_kwargs):
            return None

        def confirm(self, *, job_id, profile_id, choices, draft_sha256):
            return confirm_moods(
                job_id=job_id,
                profile_id=profile_id,
                batches=(first,),
                choices=choices,
                draft_sha256=draft_sha256,
            )

    class Gateway:
        mood_service = PhotoMoodService(Store())

        def _acquire(self, *_args):
            return None

        def _read_owned(self, **_kwargs):
            return {"state": "succeeded"}

    app = FastAPI()
    app.include_router(router)
    app.dependency_overrides[get_photo_lifecycle] = Gateway
    app.dependency_overrides[get_profile_session] = lambda: ProfileSessionPrincipal(
        profile_id="profile:one", session_digest="c" * 64, raw_reference="test"
    )
    monkeypatch.setattr(photo_moods, "require_same_origin_mutation", lambda _request: None)
    client = TestClient(app)
    review = client.get("/v1/photo-jobs/" + "a" * 64 + "/moods")
    assert review.status_code == 200
    payload = {"draft_sha256": review.json()["draft_sha256"], "choices": []}
    url = "/v1/photo-jobs/" + "a" * 64 + "/moods/confirm"
    # Body validation cannot turn a browser number into provider authority.
    assert client.post(url, json=payload | {"value": 100}).status_code == 422
    assert client.post(url, json=payload | {"draft_sha256": "f" * 64}).status_code == 409
    assert (
        client.post(
            url, json=payload | {"choices": [{"candidate_id": "f" * 64, "included": True}]}
        ).status_code
        == 409
    )
    confirmed = client.post(url, json=payload)
    assert confirmed.status_code == 200
    assert all(row["value"] is None for row in confirmed.json()["moods"])
    app.dependency_overrides[get_profile_session] = lambda: ProfileSessionPrincipal(
        profile_id="profile:other", session_digest="d" * 64, raw_reference="test"
    )
    assert client.get("/v1/photo-jobs/" + "a" * 64 + "/moods").status_code == 403
