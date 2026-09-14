"""Run the remaining frozen evaluation and full-corpus stages sequentially."""

from __future__ import annotations

import argparse
import fcntl
import json
import os
import subprocess
import sys
from datetime import UTC, datetime
from pathlib import Path

from itda.domain.canonical import canonical_sha256
from itda.pipeline.destination_evidence import atomic_json


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=Path("artifacts/authenticity-v1/20260911"))
    parser.add_argument(
        "--wait-for-active",
        action="store_true",
        help="Wait for the existing workflow lock, then validate and resume once.",
    )
    args = parser.parse_args()
    root = args.root
    os.environ["ITDA_MODEL_SESSION_LIMIT"] = "5"
    stages = [
        ("new-evaluation", "photo-review", True),
        ("new-evaluation", "evaluate-new", False),
        ("full-2000", "analyze", True),
        ("full-2000", "photos", True),
        ("full-2000", "review", True),
        ("full-2000", "photo-review", True),
    ]
    with (root / ".workflow.lock").open("a") as lock:
        try:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            if not args.wait_for_active:
                raise SystemExit("AUTHENTICITY_WORKFLOW_ALREADY_ACTIVE") from None
            print(
                json.dumps({"status": "WAITING_FOR_ACTIVE_WORKFLOW", "pid": os.getpid()}),
                flush=True,
            )
            # The active process remains untouched. Its terminal status and all
            # caches are inspected only after obtaining the same exclusive lock.
            fcntl.flock(lock, fcntl.LOCK_EX)
        if any(
            json.loads(p.read_text()).get("status") == "UNAVAILABLE"
            for p in (root / "full-2000/audits").glob("*.json")
        ):
            stages.insert(2, ("full-2000", "recover-format", True))
        # Evaluate-new must complete before the full corpus starts. Every stage's
        # own manifests/caches validate resumption and retain previous artifacts.
        for directory, stage, live in stages:
            if directory == "full-2000":
                result = json.loads((root / "new-evaluation/evaluation/results.json").read_text())
                if result["report_sha256"] != canonical_sha256(
                    {k: v for k, v in result.items() if k != "report_sha256"}
                ):
                    raise ValueError("NEW_EVALUATION_RESULT_CHANGED")
                if any(
                    c["hard_violations"] or c["places"] != 60 for c in result["conditions"].values()
                ):
                    raise ValueError("NEW_EVALUATION_HARD_GATE_FAILED")
            log = root / directory / ("workflow-" + stage + ".log")
            state = {
                "version": "authenticity-workflow-v1",
                "status": "RUNNING",
                "directory": directory,
                "stage": stage,
                "parent_pid": os.getpid(),
                "started_at": datetime.now(UTC).isoformat(),
                "log": str(log),
                "model_concurrency": 5,
                "official_collection": "PAUSED_NO_RETRY",
            }
            command = [
                sys.executable,
                "-m",
                "itda.cli.authenticity_analysis",
                stage,
                "--output",
                str(root / directory),
                "--workers",
                "5",
            ]
            if live:
                command.append("--live")
            with log.open("a") as output:
                child = subprocess.Popen(command, stdout=output, stderr=subprocess.STDOUT)
                state["child_pid"] = child.pid
                atomic_json(root / "workflow.json", state)
                print(json.dumps(state), flush=True)
                code = child.wait()
            state.update(
                status="COMPLETE" if code == 0 else "STOPPED",
                exit_code=code,
                completed_at=datetime.now(UTC).isoformat(),
            )
            atomic_json(root / directory / ("workflow-" + stage + ".json"), state)
            atomic_json(root / "workflow.json", state)
            print(json.dumps(state), flush=True)
            if code:
                return code
        return 0


if __name__ == "__main__":
    raise SystemExit(main())
