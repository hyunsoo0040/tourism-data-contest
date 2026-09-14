"""Official GoCamping discovery and published facilities."""

from typing import ClassVar

from itda.collectors.base import OfficialApiClient


class CampingClient(OfficialApiClient):
    provider: ClassVar[str] = "KTO_CAMPING"
    official_dataset_id: ClassVar[str] = "15101933"
    service_name: ClassVar[str] = "GoCamping"
    base_url: ClassVar[str] = "https://apis.data.go.kr/B551011/GoCamping"
    allowed_operations: ClassVar[frozenset[str]] = frozenset(
        {"basedList", "basedSyncList", "searchList", "locationBasedList", "imageList"}
    )
    common_parameters: ClassVar[dict[str, str]] = {
        "MobileOS": "ETC",
        "MobileApp": "IT-DA",
        "_type": "json",
    }
