import json

import pytest

from itda.authenticity.binding import bind_response
from itda.authenticity.contracts import Policy
from itda.authenticity.publication_scope import PublicationSelection
from itda.authenticity.release import build_release, load_release
from itda.authenticity.rubric import FACET_KEYS
from itda.authenticity.scoring import build_assessment
from itda.domain.canonical import canonical_sha256

from .helpers import NOW, PID, evidence, source


def selection(bundle, decision="INCLUDE_ACTIVITY", quote=None):
    original = bundle.evidence[0]
    text = quote or original.text
    payload = dict(
        schema_version="authenticity-publication-selection.v1",
        rule="EXCLUDE_LODGING_PARENTS_RETAIN_SEPARATELY_IDENTIFIED_ACTIVITIES",
        review_scope="AI_SOURCE_REVIEW_OF_NAME_FLAGGED_RECORDS_NOT_EXHAUSTIVE",
        parent_manifest_sha256="d" * 64,
        analyzed_place_ids=[PID],
        decisions=[
            dict(
                place_id=PID,
                source_bundle_sha256=bundle.bundle_sha256,
                decision=decision,
                reason_ko="현재는 문화시설이다.",
                evidence_id=original.evidence_id,
                quote=text,
                start=0,
                end=len(text),
            )
        ],
    )
    return PublicationSelection.model_validate(
        payload | {"selection_sha256": canonical_sha256(payload)}
    )


def test_exclusion_does_not_change_analyzed_membership_or_source():
    bundle = source(evidence(text="현재는 펜션이다."))
    before = bundle.model_dump_json()
    report = selection(bundle, "EXCLUDE_ACCOMMODATION")
    report.verify_sources({PID: bundle})
    assert report.analyzed_place_ids == (PID,)
    assert report.eligible_ids == ()
    assert bundle.model_dump_json() == before
    with pytest.raises(ValueError, match="RELEASE_SELECTION"):
        report.verify_release((PID,), "d" * 64)


def test_fabricated_quote_and_changed_membership_are_rejected():
    bundle = source(evidence())
    with pytest.raises(ValueError, match="EXACT_OFFICIAL_QUOTE"):
        selection(bundle, quote="이곳은 펜션이다.").verify_sources({PID: bundle})
    with pytest.raises(ValueError, match="SOURCE_MEMBERSHIP"):
        selection(bundle).verify_sources({})
    changed = source(evidence(text="바뀐 원문이다."))
    with pytest.raises(ValueError, match="SOURCE_CHANGED"):
        selection(bundle).verify_sources({PID: changed})


def test_food_exclusion_requires_v2_and_does_not_change_v1_membership():
    bundle = source(evidence(text="현재 음식점들이 모인 거리이다."))
    old = selection(bundle)
    payload = old.model_dump(mode="json", exclude={"selection_sha256"})
    payload["decisions"][0]["decision"] = "EXCLUDE_FOOD_SERVICE"
    with pytest.raises(ValueError, match="RULE_VERSION"):
        PublicationSelection.model_validate(
            payload | {"selection_sha256": canonical_sha256(payload)}
        )
    payload.update(
        schema_version="authenticity-publication-selection.v2",
        rule="EXCLUDE_LODGING_AND_FOOD_SERVICE_RETAIN_EXPLICIT_SIGHTSEEING_OR_ACTIVITIES",
    )
    current = PublicationSelection.model_validate(
        payload | {"selection_sha256": canonical_sha256(payload)}
    )
    current.verify_sources({PID: bundle})
    assert current.eligible_ids == ()
    assert old.eligible_ids == (PID,)
    assert PublicationSelection.model_validate_json(old.model_dump_json()) == old


@pytest.mark.parametrize("with_selection", [None, "v1", "v2", "v3"])
def test_portable_release_pins_selection_and_preserves_legacy_format(tmp_path, with_selection):
    bundle = source(evidence(text="옛 모텔을 개축한 현재 미술관이다."))
    wire = {
        "judgments": [
            dict(
                key=k,
                state="UNKNOWN",
                level=None,
                basis="INSUFFICIENT",
                subject="UNRESOLVED",
                citations=[],
                reason="미확인",
            )
            for k in FACET_KEYS
        ]
    }
    judgments, rejections = bind_response(wire, bundle)
    assessment = build_assessment(
        source=bundle, judgments=judgments, rejections=rejections, policy=Policy(), assessed_at=NOW
    )
    chosen = selection(bundle) if with_selection else None
    if with_selection in {"v2", "v3"}:
        payload = chosen.model_dump(mode="json", exclude={"selection_sha256"})
        payload.update(
            schema_version="authenticity-publication-selection.v2",
            rule="EXCLUDE_LODGING_AND_FOOD_SERVICE_RETAIN_EXPLICIT_SIGHTSEEING_OR_ACTIVITIES",
        )
        if with_selection == "v3":
            payload.update(
                schema_version="authenticity-publication-selection.v3",
                rule="SIGHTSEEING_OR_SEPARATELY_USABLE_ACTIVITY_ONLY",
                review_scope="AI_SOURCE_REVIEW_OF_NAME_OR_DESCRIPTION_FLAGGED_RECORDS_NOT_EXHAUSTIVE",
            )
        chosen = PublicationSelection.model_validate(
            payload | {"selection_sha256": canonical_sha256(payload)}
        )
    release = build_release(
        assessments=(assessment,),
        directory=tmp_path,
        expected_ids=(PID,),
        parent_manifest_sha256="d" * 64,
        scope="DEVELOPMENT",
        created_at=NOW,
        publication_selection=chosen,
    )
    assert load_release(tmp_path) == (release, (assessment,))
    report_path = tmp_path / "validation.json"
    report = json.loads(report_path.read_text())
    assert ("publication_selection" in report) == bool(with_selection)
    if chosen:
        report["publication_selection"]["decisions"][0]["quote"] = "改ざん"
        report_path.write_text(json.dumps(report))
        with pytest.raises(ValueError, match="VALIDATION_REPORT_MISMATCH"):
            load_release(tmp_path)


def test_retail_exclusion_cannot_silently_change_prior_selection_rules():
    bundle = source(evidence(text="일상용품을 판매하는 매장이다."))
    old = selection(bundle)
    payload = old.model_dump(mode="json", exclude={"selection_sha256"})
    payload["decisions"][0]["decision"] = "EXCLUDE_RETAIL"
    with pytest.raises(ValueError, match="RULE_VERSION"):
        PublicationSelection.model_validate(
            payload | {"selection_sha256": canonical_sha256(payload)}
        )
    payload.update(
        schema_version="authenticity-publication-selection.v3",
        rule="SIGHTSEEING_OR_SEPARATELY_USABLE_ACTIVITY_ONLY",
        review_scope="AI_SOURCE_REVIEW_OF_NAME_OR_DESCRIPTION_FLAGGED_RECORDS_NOT_EXHAUSTIVE",
    )
    current = PublicationSelection.model_validate(
        payload | {"selection_sha256": canonical_sha256(payload)}
    )
    current.verify_sources({PID: bundle})
    assert current.eligible_ids == () and old.eligible_ids == (PID,)
