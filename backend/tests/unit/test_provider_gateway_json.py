"""The recorded KTO authorization rejection uses the JSON gateway envelope."""

from itda.collectors.base import _provider_result_fields


def test_gateway_json_authentication_error_is_not_missing_or_success():
    body = {
        "OpenAPI_ServiceResponse": {
            "cmmMsgHeader": {
                "errMsg": "SERVICE_KEY_IS_NOT_REGISTERED_ERROR",
                "returnAuthMsg": "등록되지 않은 서비스키",
                "returnReasonCode": "30",
            }
        }
    }
    assert _provider_result_fields(body) == ("30", "등록되지 않은 서비스키")


def test_body_text_named_return_reason_code_is_not_a_gateway_error():
    body = {
        "response": {
            "header": {"resultCode": "0000", "resultMsg": "OK"},
            "body": {"items": {"item": [{"returnReasonCode": "30", "title": "example"}]}},
        }
    }
    assert _provider_result_fields(body) == ("0000", "OK")
