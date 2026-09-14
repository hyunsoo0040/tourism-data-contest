"""Official navigation-associated destinations; not an affinity signal."""

from typing import ClassVar

from itda.collectors.base import OfficialApiClient


class RelatedDestinationsClient(OfficialApiClient):
    provider: ClassVar[str] = "KTO_RELATED_DESTINATIONS"
    official_dataset_id: ClassVar[str] = "15128560"
    service_name: ClassVar[str] = "TarRlteTarService1"
    base_url: ClassVar[str] = "https://apis.data.go.kr/B551011/TarRlteTarService1"
    allowed_operations: ClassVar[frozenset[str]] = frozenset({"areaBasedList1", "searchKeyword1"})
    common_parameters: ClassVar[dict[str, str]] = {
        "MobileOS": "ETC",
        "MobileApp": "IT-DA",
        "_type": "json",
    }
