"""Official regional daily visitor estimates; never place-level occupancy."""

from typing import ClassVar

from itda.collectors.base import OfficialApiClient


class RegionalVisitorsClient(OfficialApiClient):
    provider: ClassVar[str] = "KTO_REGIONAL_VISITORS"
    official_dataset_id: ClassVar[str] = "15101972"
    service_name: ClassVar[str] = "DataLabService"
    base_url: ClassVar[str] = "https://apis.data.go.kr/B551011/DataLabService"
    allowed_operations: ClassVar[frozenset[str]] = frozenset(
        {"locgoRegnVisitrDDList", "metcoRegnVisitrDDList"}
    )
    common_parameters: ClassVar[dict[str, str]] = {
        "MobileOS": "ETC",
        "MobileApp": "IT-DA",
        "_type": "json",
    }
