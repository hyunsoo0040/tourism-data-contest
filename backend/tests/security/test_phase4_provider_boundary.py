from __future__ import annotations

import inspect
from copy import deepcopy
from pathlib import Path

import pytest
from pydantic import ValidationError

from itda.contracts.image_observation import FORBIDDEN_PROVIDER_AUTHORITY_FIELDS
from itda.contracts.vlm_inference import (
    FORBIDDEN_PROVIDER_INPUT_KEYS,
    Glm5VProviderConfig,
    SafeInferenceRequest,
    seal_inference_contract,
)
from itda.providers import zhipu_glm5v
from tests.contract.test_vlm_inference import _config_payload, _request_payload


@pytest.mark.parametrize(
    "forbidden_key",
    tuple(FORBIDDEN_PROVIDER_INPUT_KEYS)
    + ("label", "labels", "blind", "blind_membership", "api_key", "authorization"),
)
def test_provider_contracts_reject_protected_input_keys_recursively(forbidden_key: str) -> None:
    for model, payload, digest_field in (
        (Glm5VProviderConfig, _config_payload(), "config_sha256"),
        (SafeInferenceRequest, _request_payload(), "semantic_request_sha256"),
    ):
        hostile = deepcopy(payload)
        hostile["nested"] = {forbidden_key.upper(): "must-not-cross-boundary"}
        hostile = seal_inference_contract(hostile, digest_field=digest_field)
        with pytest.raises(ValidationError, match="forbidden provider input field"):
            model.model_validate(hostile)


def test_safe_projections_contain_no_raw_or_authority_capability() -> None:
    config = Glm5VProviderConfig.model_validate(_config_payload())
    request = SafeInferenceRequest.model_validate(_request_payload())
    payloads = (config.model_dump(mode="json"), request.model_dump(mode="json"))

    def collect_keys(value: object) -> set[str]:
        if isinstance(value, dict):
            return {str(key).casefold() for key in value} | set().union(
                *(collect_keys(nested) for nested in value.values())
            )
        if isinstance(value, (list, tuple)):
            return set().union(*(collect_keys(nested) for nested in value))
        return set()

    keys = set().union(*(collect_keys(payload) for payload in payloads))
    assert not keys & {
        "api_key",
        "authorization",
        "base64",
        "image_bytes",
        "blind_membership",
        "expert_label",
        *FORBIDDEN_PROVIDER_AUTHORITY_FIELDS,
    }
    assert "bearer " not in repr(payloads).casefold()


def test_model_authority_fields_are_never_part_of_request_contract() -> None:
    for authority_field in FORBIDDEN_PROVIDER_AUTHORITY_FIELDS:
        hostile = _request_payload()
        hostile[authority_field] = True
        hostile = seal_inference_contract(hostile, digest_field="semantic_request_sha256")
        with pytest.raises(ValidationError, match="forbidden provider input field"):
            SafeInferenceRequest.model_validate(hostile)


def test_adapter_has_no_provider_sdk_or_orchestration_dependency() -> None:
    source = Path(inspect.getsourcefile(zhipu_glm5v) or "").read_text(encoding="utf-8")
    forbidden_imports = (
        "import zhipuai",
        "from zhipuai",
        "import zai",
        "from zai",
        "langchain",
        "langgraph",
        "crewai",
    )
    assert all(name not in source for name in forbidden_imports)
    assert "trust_env=False" in source
    assert "follow_redirects=False" in source
    assert "httpx.AsyncClient" in source


def test_adapter_does_not_read_credentials_or_provider_configuration_from_environment() -> None:
    source = inspect.getsource(zhipu_glm5v)
    assert "os.environ" not in source
    assert "os.getenv" not in source
    assert "ZHIPUAI_API_KEY" not in source
    assert "BIGMODEL_API_KEY" not in source
