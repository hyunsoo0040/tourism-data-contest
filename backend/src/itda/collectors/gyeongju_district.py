"""Fixed-host adapter for Gyeongju district-tourism dataset 15114464."""

from __future__ import annotations

from typing import Any, ClassVar

import httpx

from itda.collectors.base import CollectedResponse, OfficialApiClient, RequestPolicy
from itda.collectors.diagnostics import DiagnosticOperation, ProviderDiagnostics
from itda.contracts.catalog_discovery import D1Request


class GyeongjuDistrictClient(OfficialApiClient):
    """D1 adapter whose transport policy must match the approved packet exactly."""

    provider: ClassVar[str] = "TOUR_API"
    official_dataset_id: ClassVar[str] = "15114464"
    dataset_rights_identity: ClassVar[str | None] = None
    service_name: ClassVar[str] = "dstrctsTrrsrtService"
    base_url: ClassVar[str] = "https://apis.data.go.kr/5050000/dstrctsTrrsrtService"
    allowed_operations: ClassVar[frozenset[str]] = frozenset({"getDstrctsTrrsrt"})
    common_parameters: ClassVar[dict[str, str]] = {}
    forbidden_parameter_names: ClassVar[frozenset[str]] = frozenset({"serviceKey", "ServiceKey"})
    provenance_fields: ClassVar[tuple[str, ...]] = (
        "CON_UID",
        "CON_TITLE",
        "CON_IMGFILENAME",
        "SRC_TITLE",
        "LINKURL",
        "CON_ISENABLED",
    )

    def __init__(
        self,
        *,
        service_key: str,
        http_client: httpx.Client | None = None,
        policy: RequestPolicy | None = None,
        **kwargs: Any,
    ) -> None:
        super().__init__(
            service_key=service_key,
            http_client=http_client,
            policy=policy,
            **kwargs,
        )
        if self._policy != RequestPolicy(timeout_seconds=300, max_attempts=3):
            self.close()
            raise ValueError("D1 adapter requires exactly three 300-second attempts")

    @property
    def policy(self) -> RequestPolicy:
        return self._policy

    def fetch_page(
        self,
        planned: D1Request,
        *,
        explicit_opt_in: bool,
        diagnostics: ProviderDiagnostics | None = None,
        diagnostic_operation: DiagnosticOperation | None = None,
    ) -> CollectedResponse:
        """Execute only one already-approved, secret-free request identity."""

        return self.request(
            "getDstrctsTrrsrt",
            {
                "pageNo": planned.page_no,
                "numOfRows": planned.num_of_rows,
                "type": planned.response_type,
            },
            explicit_opt_in=explicit_opt_in,
            diagnostics=diagnostics,
            diagnostic_operation=diagnostic_operation,
        )


__all__ = ["GyeongjuDistrictClient"]
