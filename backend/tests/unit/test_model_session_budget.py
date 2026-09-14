import subprocess
import sys
from concurrent.futures import ThreadPoolExecutor
from threading import Lock
from time import sleep

import pytest

from itda.photo.model_budget import ModelSessionCapacityUnavailable, model_session


def test_concurrent_clients_share_bounded_sessions_and_release_on_errors(tmp_path):
    guard = Lock()
    counts = {"active": 0, "peak": 0}

    def work(index):
        try:
            with model_session(directory=tmp_path, limit=2):
                with guard:
                    counts["active"] += 1
                    counts["peak"] = max(counts["peak"], counts["active"])
                sleep(0.02)
                with guard:
                    counts["active"] -= 1
                if index == 0:
                    raise RuntimeError("provider failure")
        except RuntimeError:
            pass

    with ThreadPoolExecutor(max_workers=8) as pool:
        list(pool.map(work, range(12)))
    assert counts["peak"] == 2 and counts["active"] == 0
    with model_session(directory=tmp_path, limit=2):
        pass


def test_busy_capacity_times_out_without_issuing_an_extra_call(tmp_path):
    with (
        model_session(directory=tmp_path, limit=1),
        pytest.raises(ModelSessionCapacityUnavailable),
        model_session(directory=tmp_path, limit=1, timeout_seconds=0.01),
    ):
        raise AssertionError("must not issue request")


@pytest.mark.parametrize("limit", [0, 41, True])
def test_user_authorized_maximum_cannot_be_exceeded(tmp_path, limit):
    with pytest.raises(ValueError), model_session(directory=tmp_path, limit=limit):
        pass


def test_separate_process_cannot_exceed_the_same_host_budget(tmp_path):
    script = """
import sys
from pathlib import Path
from itda.photo.model_budget import model_session, ModelSessionCapacityUnavailable
try:
    with model_session(directory=Path(sys.argv[1]), limit=1, timeout_seconds=.03):
        raise SystemExit(2)
except ModelSessionCapacityUnavailable:
    print('shared-capacity-enforced')
"""
    with model_session(directory=tmp_path, limit=1):
        result = subprocess.run(
            [sys.executable, "-c", script, str(tmp_path)], capture_output=True, text=True, timeout=5
        )
    assert result.returncode == 0 and result.stdout.strip() == "shared-capacity-enforced"
