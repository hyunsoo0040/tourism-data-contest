from itda.authenticity.format_recovery import eligible


def test_only_two_protocol_failures_qualify_not_low_scores_partial_or_auth_errors():
    failed = {"status": "UNAVAILABLE", "attempts": [{"code": "MODEL_JSON_RESPONSE_REJECTED"}] * 2}
    assert eligible(failed)
    assert not eligible(failed | {"status": "PARTIAL"})
    assert not eligible(
        failed | {"attempts": [{"code": "MODEL_HTTP_ERROR", "http_status": 401}] * 2}
    )
    assert not eligible(failed | {"attempts": [{"code": "MODEL_JSON_RESPONSE_REJECTED"}] * 3})


def inputs(tmp_path):
    import json

    from itda.domain.canonical import canonical_sha256
    from tests.authenticity.helpers import evidence, source

    src = source(evidence())
    file = tmp_path / "source.json"
    file.write_text(src.model_dump_json())
    member = {
        "place_id": src.place.place_id,
        "name_ko": src.place.name_ko,
        "source_file": str(file),
        "source_bundle_sha256": src.bundle_sha256,
    }
    manifest = {"members": [member]}
    manifest["manifest_sha256"] = canonical_sha256(manifest)
    (tmp_path / "manifest.json").write_text(json.dumps(manifest))
    audit = {
        "status": "UNAVAILABLE",
        "input_source_sha256": src.bundle_sha256,
        "attempts": [{"code": "MODEL_JSON_RESPONSE_REJECTED"}] * 2,
    }
    path = tmp_path / "audits" / (src.place.place_id.split(":")[-1] + ".json")
    path.parent.mkdir()
    path.write_text(json.dumps(audit))
    return src, path, audit


def test_recovery_reserves_before_dispatch_and_does_not_repeat_invalid_response(
    tmp_path, monkeypatch
):
    from itda.authenticity import format_recovery
    from itda.authenticity.model import ModelExchangeError

    inputs(tmp_path)
    calls = []

    class Client:
        def complete(self, payload, *, directory, live):
            if not live:
                raise ModelExchangeError("OFFLINE_MODEL_CACHE_MISS")
            assert list((tmp_path / "format-recovery/reservations").glob("*.json"))
            calls.append(payload)
            raise ModelExchangeError("MODEL_JSON_RESPONSE_REJECTED")

    monkeypatch.setattr(format_recovery, "GlmClient", lambda **_: Client())
    assert format_recovery.recover(tmp_path, api_key="test", live=True)["still_unavailable"] == 1
    again = format_recovery.recover(tmp_path, api_key="test", live=True)
    assert len(calls) == 1 and again["rows"][0]["code"] == "FORMAT_RECOVERY_ATTEMPT_LIMIT_REACHED"


def test_first_valid_recovery_preserves_old_audit_and_then_reuses_assessment(tmp_path, monkeypatch):
    import json

    from itda.authenticity import format_recovery
    from itda.authenticity.model import ModelExchangeError
    from itda.authenticity.rubric import FACET_KEYS
    from itda.domain.canonical import canonical_sha256

    _, path, old = inputs(tmp_path)
    calls = []

    class Client:
        def complete(self, payload, *, directory, live):
            if not live:
                raise ModelExchangeError("OFFLINE_MODEL_CACHE_MISS")
            calls.append(payload)
            return {
                "judgments": [
                    {
                        "key": k,
                        "state": "UNKNOWN",
                        "level": None,
                        "basis": "INSUFFICIENT",
                        "subject": "UNRESOLVED",
                        "citations": [],
                        "reason": "기술 검사 표본",
                    }
                    for k in FACET_KEYS
                ]
            }, {"request_sha256": canonical_sha256(payload)}

    monkeypatch.setattr(format_recovery, "GlmClient", lambda **_: Client())
    assert format_recovery.recover(tmp_path, api_key="test", live=True)["recovered"] == 1
    assert json.loads(path.read_text())["status"] == "VALIDATED"
    assert json.loads(next((tmp_path / "audits/history").glob("*.json")).read_text()) == old
    assert format_recovery.recover(tmp_path, api_key="test", live=True)["rows"] == []
    assert len(calls) == 1
