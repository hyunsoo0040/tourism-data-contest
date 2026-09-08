"""Official Korea Tourism Organization PhotoGalleryService1 adapter."""

from __future__ import annotations

from typing import ClassVar

from itda.collectors.base import OfficialApiClient


class TourismPhotoGalleryClient(OfficialApiClient):
    """Fixed-target adapter for official dataset 15101914 only."""

    provider: ClassVar[str] = "TOURISM_PHOTO"
    official_dataset_id: ClassVar[str] = "15101914"
    dataset_rights_identity: ClassVar[str] = "KOGL_TYPE_1_ATTRIBUTION"
    service_name: ClassVar[str] = "PhotoGalleryService1"
    base_url: ClassVar[str] = "https://apis.data.go.kr/B551011/PhotoGalleryService1"
    allowed_operations: ClassVar[frozenset[str]] = frozenset(
        {
            "galleryList1",
            "gallerySearchList1",
            "galleryDetailList1",
            "gallerySyncDetailList1",
        }
    )
    provenance_fields: ClassVar[tuple[str, ...]] = (
        "galContentId",
        "galTitle",
        "galWebImageUrl",
        "galPhotographyLocation",
        "galPhotographer",
        "galSearchKeyword",
    )
    common_parameters: ClassVar[dict[str, str]] = {
        "MobileOS": "ETC",
        "MobileApp": "IT-DA",
        "_type": "json",
    }


__all__ = ["TourismPhotoGalleryClient"]
