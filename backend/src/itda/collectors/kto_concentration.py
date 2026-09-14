"""Official place-relative visitor concentration forecasts."""

from typing import ClassVar

from itda.collectors.base import OfficialApiClient


class ConcentrationClient(OfficialApiClient):
    provider: ClassVar[str] = "KTO_CONCENTRATION"
    official_dataset_id: ClassVar[str] = "15128555"
    service_name: ClassVar[str] = "TatsCnctrRateService"
    base_url: ClassVar[str] = "https://apis.data.go.kr/B551011/TatsCnctrRateService"
    allowed_operations: ClassVar[frozenset[str]] = frozenset({"tatsCnctrRatedList"})
    common_parameters: ClassVar[dict[str, str]] = {
        "MobileOS": "ETC",
        "MobileApp": "IT-DA",
        "_type": "json",
    }
