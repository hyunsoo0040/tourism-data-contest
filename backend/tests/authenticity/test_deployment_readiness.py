import pytest
from fastapi import HTTPException

from itda.api.routes.authenticity import provider
from itda.cli.authenticity_health import ready


@pytest.mark.parametrize(
    "field,value",
    [
        ("scope", "DEVELOPMENT"),
        ("places", 120),
        ("release_sha256", "b" * 64),
        ("photo_enabled", False),
    ],
)
def test_health_rejects_static_or_wrong_active_data(field, value):
    environment = {
        "ITDA_AUTHENTICITY_RELEASE_SHA256": "a" * 64,
        "ITDA_AUTHENTICITY_EXPECTED_PLACES": "1984",
        "ITDA_AUTHENTICITY_PHOTO_ENABLED": "1",
    }
    info = {"scope": "PUBLIC", "places": 1984, "release_sha256": "a" * 64, "photo_enabled": True}
    assert ready(info, environment)
    assert not ready(info | {field: value}, environment)
    assert not ready({}, environment)


def test_authenticity_photo_uses_mounted_key_and_rejects_unreadable_override(tmp_path, monkeypatch):
    from itda.api.routes import authenticity

    for name in ("ITDA_PHOTO_VLM_API_KEY", "ITDA_PHOTO_VLM_API_KEY_FILE"):
        monkeypatch.delenv(name, raising=False)
    secret = tmp_path / "secret"
    secret.write_text("synthetic-mounted-key")
    monkeypatch.setenv("ITDA_AUTHENTICITY_PHOTO_ENABLED", "1")
    monkeypatch.setenv("ITDA_ZHIPUAI_API_KEY_FILE", str(secret))
    monkeypatch.setenv("ZHIPUAI_API_KEY", "synthetic-environment-key")
    seen = {}
    monkeypatch.setattr(authenticity, "GlmMoodProvider", lambda **kwargs: seen.update(kwargs))
    provider()
    assert seen == {"api_key": "synthetic-mounted-key", "explicit_opt_in": True, "session_limit": 5}
    secret.unlink()
    with pytest.raises(HTTPException) as error:
        provider()
    assert error.value.status_code == 503
