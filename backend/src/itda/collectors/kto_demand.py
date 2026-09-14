"""Official regional stay/spending intensity, with independent indicator units."""

from typing import ClassVar

from itda.collectors.base import OfficialApiClient


class RegionalDemandClient(OfficialApiClient):
    provider: ClassVar[str] = "KTO_REGIONAL_DEMAND"
    official_dataset_id: ClassVar[str] = "15151868"
    service_name: ClassVar[str] = "AreaTarDemDsService"
    base_url: ClassVar[str] = "https://apis.data.go.kr/B551011/AreaTarDemDsService"
    allowed_operations: ClassVar[frozenset[str]] = frozenset(
        {"areaTarSjrnDsList", "areaTarExpDsList"}
    )
    common_parameters: ClassVar[dict[str, str]] = {
        "MobileOS": "ETC",
        "MobileApp": "IT-DA",
        "_type": "json",
    }
