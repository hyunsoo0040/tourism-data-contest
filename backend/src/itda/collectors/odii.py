"""Official Korea Tourism Organization Odii API adapter."""

from __future__ import annotations

from typing import ClassVar

from itda.collectors.base import OfficialApiClient


class OdiiClient(OfficialApiClient):
    provider: ClassVar[str] = "ODII"
    official_dataset_id: ClassVar[str] = "15101971"
    dataset_rights_identity: ClassVar[str] = "ODII_DATASET_15101971"
    service_name: ClassVar[str] = "Odii"
    base_url: ClassVar[str] = "https://apis.data.go.kr/B551011/Odii"
    allowed_operations: ClassVar[frozenset[str]] = frozenset(
        {"themeSearchList", "themeBasedList", "storyBasedList"}
    )
    provenance_fields: ClassVar[tuple[str, ...]] = (
        "tid",
        "tlid",
        "storyId",
        "themeName",
        "storyTitle",
    )
    common_parameters: ClassVar[dict[str, str]] = {
        "MobileOS": "ETC",
        "MobileApp": "IT-DA",
        "_type": "json",
        "langCode": "ko",
    }
