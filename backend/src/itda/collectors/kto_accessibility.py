"""Fixed official barrier-free tourism API, independent of KorService IDs."""

from typing import ClassVar

from itda.collectors.base import OfficialApiClient


class KorWithService2Client(OfficialApiClient):
    provider: ClassVar[str] = "TOUR_API_ACCESSIBILITY"
    official_dataset_id: ClassVar[str] = "15101897"
    service_name: ClassVar[str] = "KorWithService2"
    base_url: ClassVar[str] = "https://apis.data.go.kr/B551011/KorWithService2"
    allowed_operations: ClassVar[frozenset[str]] = frozenset(
        {"searchKeyword2", "areaBasedList2", "detailCommon2", "detailWithTour2"}
    )
    forbidden_parameter_names: ClassVar[frozenset[str]] = frozenset(
        {"areaCode", "sigunguCode", "cat1", "cat2", "cat3"}
    )
    common_parameters: ClassVar[dict[str, str]] = {
        "MobileOS": "ETC",
        "MobileApp": "IT-DA",
        "_type": "json",
    }
