"""Deployment invariants for mood credentials and the shared model-session cap."""

from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[3]
LOCK_ROOT = "/var/lib/itda/model-sessions"
DAILY_ROOT = "/var/lib/itda/grounded-daily"


def mounts(service):
    return {entry.split(":")[1]: entry.split(":")[0] for entry in service.get("volumes", [])}


@pytest.mark.parametrize(
    "path,initializer",
    [
        ("deploy/swarm-stack.yaml", "quarantine-init"),
        ("deploy/portainer-stack.yaml", "photo-volume-init"),
        ("docker-compose.yml", "quarantine-init"),
    ],
)
def test_photo_templates_default_to_mood_and_share_initialized_lock_volume(path, initializer):
    config = yaml.safe_load((ROOT / path).read_text())
    backend = config["services"]["backend"]
    init = config["services"][initializer]
    assert backend["environment"]["ITDA_PHOTO_MOOD_ENABLED"] == "${ITDA_PHOTO_MOOD_ENABLED:-1}"
    assert backend["environment"]["ITDA_MODEL_SESSION_LIMIT"] == "${ITDA_MODEL_SESSION_LIMIT:-5}"
    assert backend["environment"]["ITDA_MODEL_SESSION_LOCK_DIR"] == LOCK_ROOT
    assert "glm-5.3-flash" in backend["environment"]["ITDA_PHOTO_VLM_MODEL"]
    assert "/coding/paas/" in backend["environment"]["ITDA_PHOTO_VLM_ENDPOINT"]
    assert mounts(backend)[LOCK_ROOT] == mounts(init)[LOCK_ROOT]
    assert mounts(backend)[LOCK_ROOT] in config["volumes"]
    assert mounts(backend)[LOCK_ROOT] != mounts(backend)["/var/lib/itda/photo-quarantine"]
    assert init["user"] == "0:0"
    assert "10001, 10001" in init["command"][-1]
    assert LOCK_ROOT in init["command"][-1]
    if "daily-glm-refresh" in config["services"]:
        daily = config["services"]["daily-glm-refresh"]
        assert daily["environment"]["ITDA_MODEL_SESSION_LOCK_DIR"] == LOCK_ROOT
        assert (
            daily["environment"]["ITDA_MODEL_SESSION_LIMIT"]
            == backend["environment"]["ITDA_MODEL_SESSION_LIMIT"]
        )
        assert mounts(daily)[LOCK_ROOT] == mounts(backend)[LOCK_ROOT]
        assert mounts(daily)[DAILY_ROOT] == mounts(init)[DAILY_ROOT]
        assert mounts(daily)[DAILY_ROOT] in config["volumes"]
        assert DAILY_ROOT not in mounts(backend)
        assert DAILY_ROOT in init["command"][-1]
        assert daily["environment"]["ITDA_GROUNDED_DAILY_OUTPUT_ROOT"].startswith(DAILY_ROOT + "/")
        assert daily["environment"]["ITDA_GROUNDED_DAILY_CACHE_ROOT"].startswith(DAILY_ROOT + "/")
        if path != "docker-compose.yml":
            assert (
                backend["deploy"]["placement"]["constraints"]
                == daily["deploy"]["placement"]["constraints"]
            )


def test_swarm_backend_mounts_the_declared_model_secret():
    config = yaml.safe_load((ROOT / "deploy/swarm-stack.yaml").read_text())
    backend = config["services"]["backend"]
    assert (
        backend["environment"]["ITDA_ZHIPUAI_API_KEY_FILE"] == "/run/secrets/itda_zhipuai_api_key"
    )
    assert "itda_zhipuai_api_key" in backend["secrets"]
    assert config["secrets"]["itda_zhipuai_api_key"]["external"] is True


def test_env_based_templates_pass_the_existing_shared_key_without_requiring_feature_activation():
    for path in ("deploy/portainer-stack.yaml", "docker-compose.yml"):
        config = yaml.safe_load((ROOT / path).read_text())
        assert (
            config["services"]["backend"]["environment"]["ZHIPUAI_API_KEY"]
            == "${ZHIPUAI_API_KEY:-}"
        )
    config = yaml.safe_load((ROOT / "docker-compose.yml").read_text())
    # The old app/data networks are internal; explicit egress is necessary for
    # configured appearance-only provider calls.
    assert "model-egress" in config["services"]["backend"]["networks"]
    assert not (config["networks"]["model-egress"] or {}).get("internal", False)
    assert "ports" not in config["services"]["backend"]
