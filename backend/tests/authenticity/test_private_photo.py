import hashlib
import io

import pytest
from PIL import Image, UnidentifiedImageError

from itda.authenticity.intent import effective_importance
from itda.authenticity.photo import analyze_uploads, confirm, sanitize_upload
from itda.contracts.visual_mood import MoodObservation, VisualMoodDimension
from itda.domain.visual_mood import build_candidate_set
from tests.authenticity.test_intent_and_ranking import intent


class TestMoodProvider:
    __test__ = False
    provider_id = "glm-5.3-flash-test"

    def analyze(self, *, image_png, job_id, image_index):
        assert Image.open(io.BytesIO(image_png)).getexif() == {}
        return build_candidate_set(
            job_id=job_id,
            image_index=image_index,
            image_sha256=hashlib.sha256(image_png).hexdigest(),
            observations=tuple(
                MoodObservation(dimension=d, state="OBSERVED", level=3, certainty="HIGH")
                for d in VisualMoodDimension
            ),
            provider_id=self.provider_id,
            analysis_kind="MODEL",
            model="glm-5.3-flash",
        )


def photo_bytes():
    image = Image.new("RGB", (500, 400), (12, 30, 60))
    out = io.BytesIO()
    exif = Image.Exif()
    exif[315] = "must be discarded"
    image.save(out, format="JPEG", exif=exif)
    return bytearray(out.getvalue())


def test_private_upload_strips_exif_wipes_input_and_confirms_observed_subset():
    raw = photo_bytes()
    review = analyze_uploads([raw], TestMoodProvider())
    assert set(raw) == {0} and review.original_retained is False
    ids = (review.batches[0].candidates[0].candidate_id,)
    result = confirm(review, ids)
    assert result.targets == {VisualMoodDimension.GREENERY: 3}
    assert result.receipt_sha256
    with pytest.raises(ValueError):
        confirm(review, ("a" * 64,))
    with pytest.raises(ValueError):
        confirm(review, ids + ids)


def test_invalid_image_is_wiped_even_on_failure():
    raw = bytearray(b"not an image")
    with pytest.raises(UnidentifiedImageError):
        sanitize_upload(raw)
    assert set(raw) == {0}


def test_explicit_visual_selection_changes_only_visual_owned_facets():
    profile = intent(
        {}, visual_targets={"greenery": 4, "traditional_appearance": 3}, visual_input_kind="MANUAL"
    )
    weights = effective_importance(profile.submission)
    assert weights["R.b"] == weights["E.c"] == 2
    assert all((weights[k] or 0) == 0 for k in weights if k.startswith("H"))
    assert profile.requested_axes == ("E", "R")
