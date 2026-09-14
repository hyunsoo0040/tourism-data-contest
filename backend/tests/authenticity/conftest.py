import pytest


@pytest.fixture(autouse=True)
def isolated_model_slots(tmp_path, monkeypatch):
    """Mock-transport unit tests must not contend with live batch capacity."""
    monkeypatch.setenv("ITDA_MODEL_SESSION_LOCK_DIR", str(tmp_path / "model-slots"))
