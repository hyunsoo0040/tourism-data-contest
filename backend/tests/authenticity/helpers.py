from datetime import UTC, datetime

from itda.authenticity.contracts import Appearance, Place, Receipt
from itda.authenticity.sources import seal_bundle, seal_evidence

NOW = datetime(2026, 9, 11, tzinfo=UTC)
PID = "public:korea:" + "a" * 64


def evidence(
    text="이곳은 실제 유적을 보존하고 역사를 해설하는 장소이다.",
    *,
    eid="text:1",
    provider="KorService2",
    role="OFFICIAL_DESCRIPTION",
    field="overview",
):
    actor = (
        dict(actor_id="apify/test", actor_build_id="build:1", actor_run_id="run:1")
        if provider == "APIFY_INSTAGRAM"
        else {}
    )
    receipt = Receipt(
        provider=provider,
        operation="detailCommon2",
        provider_record_id="1",
        retrieved_at=NOW,
        request_sha256="a" * 64,
        response_sha256="b" * 64,
        source_record_sha256="c" * 64,
        **actor,
    )
    return seal_evidence(
        dict(
            evidence_id=eid,
            place_id=PID,
            modality="TEXT",
            state="AVAILABLE",
            receipt=receipt,
            place_match="VERIFIED",
            match_basis=("place verified",),
            source_role=role,
            field=field,
            text=text,
        )
    )


def source(*records):
    place = Place(
        place_id=PID,
        name_ko="검증 장소",
        address="서울",
        region_code="11",
        region_name="서울",
        category="관광지",
        duplicate_group_id="duplicate:" + "a" * 64,
        provider_content_id="1",
        cohort="synthetic",
    )
    return seal_bundle(place, tuple(records), "d" * 64)


def photo(key, level, *, eid="photo:1", sha="e" * 64):
    receipt = Receipt(
        provider="KorService2",
        operation="detailImage2",
        provider_record_id="1",
        retrieved_at=NOW,
        request_sha256="a" * 64,
        response_sha256="b" * 64,
        source_record_sha256="c" * 64,
    )
    return seal_evidence(
        dict(
            evidence_id=eid,
            place_id=PID,
            modality="IMAGE",
            state="AVAILABLE",
            receipt=receipt,
            place_match="VERIFIED",
            match_basis=("official match",),
            source_role="OFFICIAL_PHOTO",
            field="pixels",
            image_sha256=sha,
            image_license="KOGL_TYPE_1",
            appearance=Appearance(
                key=key, state="OBSERVED", level=level, reason="사진에서 직접 보임"
            ),
        )
    )


def raw(key, quote, claim, *, eid="text:1", level=3, reason="해당 장소의 직접 근거다."):
    return dict(
        key=key,
        state="SUPPORTED",
        level=level,
        basis="EXPLICIT_LOW" if level == 0 else "DIRECT_SUPPORT",
        subject="THIS_PLACE",
        citations=[dict(evidence_id=eid, claim=claim, quote=quote)],
        reason=reason,
    )
