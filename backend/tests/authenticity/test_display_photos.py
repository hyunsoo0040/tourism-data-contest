"""Display permissions must not loosen the analysis photo gate."""

import base64
import hashlib
import importlib.util
import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from itda.authenticity.auxiliary import Auxiliary
from itda.authenticity.binding import bind_response
from itda.authenticity.contracts import Policy
from itda.authenticity.display_photos import DisplayPhotoCatalog, load_display_photos
from itda.authenticity.ranking import rank
from itda.authenticity.scoring import build_assessment
from itda.authenticity.service import Service
from itda.domain.canonical import canonical_sha256
from tests.authenticity.helpers import NOW, PID, evidence, raw, source
from tests.authenticity.test_intent_and_ranking import intent

ROOT = Path(__file__).resolve().parents[3]
spec = importlib.util.spec_from_file_location(
    "export_display_photos", ROOT / "scripts/export_display_photos.py"
)
exporter = importlib.util.module_from_spec(spec)
spec.loader.exec_module(exporter)


def photo(kind):
    return {
        "url": f"https://tong.visitkorea.or.kr/cms/resource/1/{kind}.jpg",
        "attribution_ko": "한국관광공사 · 검증 장소",
        "license": f"KOGL_TYPE_{kind}",
        "source_url": "https://data.visitkorea.or.kr/page/1",
        "source_record_sha256": "b" * 64,
        "source_response_sha256": "c" * 64,
        "retrieved_at": NOW.isoformat(),
    }


def catalog(rows=None):
    payload = {
        "schema_version": "display-photos.v1",
        "release_sha256": "a" * 64,
        "photos": {PID: rows if rows is not None else [photo(k) for k in range(5)]},
    }
    return DisplayPhotoCatalog.model_validate(
        payload | {"catalog_sha256": canonical_sha256(payload)}
    )


def test_all_known_types_display_in_noncommercial_mode_without_analysis():
    c = catalog()
    assert len(c.for_place("a" * 64, PID, noncommercial=True)) == 5
    assert [p["license"] for p in c.for_place("a" * 64, PID, noncommercial=False)] == [
        "KOGL_TYPE_0",
        "KOGL_TYPE_1",
        "KOGL_TYPE_3",
    ]
    assert c.for_place("d" * 64, PID, noncommercial=True) == ()
    assert c.for_place("a" * 64, "public:korea:missing", noncommercial=True) == ()


@pytest.mark.parametrize(
    "patch",
    [
        {"license": "UNKNOWN"},
        {"url": "https://example.com/unrelated.jpg"},
        {"attribution_ko": ""},
        {"source_url": "javascript:alert(1)"},
    ],
)
def test_display_rejects_unverified_or_unsafe_photos(patch):
    with pytest.raises(ValueError):
        catalog([photo(3) | patch])


def test_display_manifest_checks_integrity_and_release_membership(tmp_path):
    assert load_display_photos(tmp_path) is None
    c = catalog()
    (tmp_path / "display-photos.json").write_text(c.model_dump_json())
    release = {"release_sha256": "a" * 64, "members": [{"place_id": PID}]}
    (tmp_path / "release.json").write_text(json.dumps(release))
    assert load_display_photos(tmp_path) == c
    (tmp_path / "release.json").write_text(json.dumps(release | {"members": []}))
    with pytest.raises(ValueError, match="OUTSIDE_PINNED_RELEASE"):
        load_display_photos(tmp_path)
    payload = c.model_dump(mode="json")
    payload["photos"][PID][0]["attribution_ko"] = "tampered"
    with pytest.raises(ValueError, match="DIGEST_MISMATCH"):
        DisplayPhotoCatalog.model_validate(payload)


def snapshot(rows, operation="detailCommon2"):
    body = json.dumps({"response": {"body": {"items": {"item": rows}}}}).encode()
    return {
        "place": {"place_id": PID},
        "raw_responses": [
            {
                "provider": "TOUR_API",
                "endpoint": "KorService2/" + operation,
                "raw_body_base64": base64.b64encode(body).decode(),
            }
        ],
        "receipts": [
            {
                "operation": operation,
                "status": "AVAILABLE",
                "response_sha256": hashlib.sha256(body).hexdigest(),
                "retrieved_at": NOW.isoformat(),
            }
        ],
    }


def test_exporter_uses_exact_place_rights_and_verified_raw_response():
    place = source().place
    row = {"contentid": "1", "cpyrhtDivCd": "Type3", "firstimage": photo(3)["url"]}
    src = snapshot([row, row | {"contentid": "2"}, row | {"cpyrhtDivCd": "UNKNOWN"}])
    result = exporter.source_photos(src, place)
    assert len(result) == 1
    assert result[0].license == "KOGL_TYPE_3"
    assert result[0].url == row["firstimage"]
    src["receipts"][0]["response_sha256"] = "f" * 64
    with pytest.raises(ValueError, match="RESPONSE_MISMATCH"):
        exporter.source_photos(src, place)


def test_exporter_orders_representative_first_and_deduplicates_additional_images():
    rows = [
        {"contentid": "1", "cpyrhtDivCd": "Type4", "originimgurl": photo(4)["url"]},
        {"contentid": "1", "cpyrhtDivCd": "Type3", "originimgurl": photo(3)["url"]},
    ]
    src = snapshot(rows, "detailImage2")
    common = snapshot([{"contentid": "1", "cpyrhtDivCd": "Type3", "firstimage": photo(3)["url"]}])
    src["raw_responses"] += common["raw_responses"]
    src["receipts"] += common["receipts"]
    result = exporter.source_photos(src, source().place)
    assert [p.license for p in result] == ["KOGL_TYPE_3", "KOGL_TYPE_4"]


def test_detail_adds_photos_without_changing_scores_rank_or_auxiliary():
    history = "실제 유물을 전시하고 있다."
    interpretation = "시대별 유물 해설로 원래 생활 맥락을 설명한다."
    src = source(evidence(history + " " + interpretation))
    judgments, rejections = bind_response(
        {
            "judgments": [
                raw("H.a", history, "HERITAGE_FACT"),
                raw("H.d", interpretation, "HERITAGE_INTERPRETATION"),
            ]
        },
        src,
    )
    assessment = build_assessment(
        source=src, judgments=judgments, rejections=rejections, policy=Policy(), assessed_at=NOW
    )
    run = rank(assessments=(assessment,), intent=intent({"H.a": 4}), created_at=NOW)
    aux = Auxiliary()
    before = aux.model_dump_json(), assessment.model_dump_json(), canonical_sha256(run)
    service = Service(
        SimpleNamespace(get_run=lambda *_: {"release_sha256": "a" * 64}),
        display_photos=catalog(),
        noncommercial_photos=True,
    )
    service.run = lambda *_: run
    service.pinned = lambda _: (None, (assessment,), aux)
    detail = service.detail("session", "run", PID)
    assert len(detail.photos) == 5
    assert detail.axes == assessment.axes
    assert before == (aux.model_dump_json(), assessment.model_dump_json(), canonical_sha256(run))
    assert not aux.photos and not aux.moods
