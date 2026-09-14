"""Official Durunubi registered walking courses and routes."""

from typing import ClassVar

from itda.collectors.base import OfficialApiClient


class WalkingClient(OfficialApiClient):
    provider: ClassVar[str] = "KTO_WALKING"
    official_dataset_id: ClassVar[str] = "15101974"
    service_name: ClassVar[str] = "Durunubi"
    base_url: ClassVar[str] = "https://apis.data.go.kr/B551011/Durunubi"
    allowed_operations: ClassVar[frozenset[str]] = frozenset({"courseList", "routeList"})
    common_parameters: ClassVar[dict[str, str]] = {
        "MobileOS": "ETC",
        "MobileApp": "IT-DA",
        "_type": "json",
    }
