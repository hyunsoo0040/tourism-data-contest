"""Official Korea Tourism Organization KorService2 adapter."""

from __future__ import annotations

from typing import ClassVar

from itda.collectors.base import OfficialApiClient


class KorService2Client(OfficialApiClient):
    provider: ClassVar[str] = "TOUR_API"
    official_dataset_id: ClassVar[str] = "15101578"
    service_name: ClassVar[str] = "KorService2"
    base_url: ClassVar[str] = "https://apis.data.go.kr/B551011/KorService2"
    allowed_operations: ClassVar[frozenset[str]] = frozenset(
        {
            "searchKeyword2",
            "areaBasedList2",
            "detailCommon2",
            "detailIntro2",
            "detailInfo2",
            "detailImage2",
        }
    )
    classification_fields: ClassVar[tuple[str, ...]] = (
        "lDongRegnCd",
        "lDongSignguCd",
        "lclsSystm1",
        "lclsSystm2",
        "lclsSystm3",
    )
    forbidden_parameter_names: ClassVar[frozenset[str]] = frozenset(
        {"areaCode", "sigunguCode", "cat1", "cat2", "cat3"}
    )
    common_parameters: ClassVar[dict[str, str]] = {
        "MobileOS": "ETC",
        "MobileApp": "IT-DA",
        "_type": "json",
    }
