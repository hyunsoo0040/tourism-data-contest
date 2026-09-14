"""Read current national analysis progress; --watch refreshes without API calls."""

from __future__ import annotations

import argparse
from collections import Counter
from datetime import datetime, timezone
import json
from pathlib import Path
import subprocess
import sys
import time

REPO = Path(__file__).resolve().parents[1]
DEFAULT_RECORD = (
    REPO / "artifacts/national/20260911-additional-1000/reanalysis-active-run.json"
)


def read_json(path: Path):
    return json.loads(path.read_text())


def stamp(value: str):
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


def snapshot(record_path: Path):
    record = read_json(record_path)
    directory = REPO / record["analysis_directory"]
    log = REPO / record["log_path"]
    now = datetime.now(timezone.utc)
    process = subprocess.run(
        ["ps", "-p", str(record["pid"]), "-o", "command="],
        capture_output=True,
        text=True,
    )
    launcher_running = (
        bool(record.get("launcher_marker"))
        and record["launcher_marker"] in process.stdout
    )
    running = launcher_running or (
        "itda.cli.analyze_grounded_places" in process.stdout
        and record["analysis_directory"] in process.stdout
    )
    audits = [read_json(p) for p in (directory / "audits").glob("*.json")]
    moods = [read_json(p) for p in (directory / "moods").glob("*.json")]
    statuses = Counter(a["model_status"] for a in audits)
    state = "실행 중" if running else "중단 또는 종료"
    retry = record.get("deferred_retry") if launcher_running else None
    if launcher_running and retry and stamp(retry["retry_not_before"]) > now:
        state = "실행 준비 · 재시도 대기"
    retry_path = directory / "model-retry.json"
    if retry_path.exists():
        recent = read_json(retry_path)
        if stamp(recent["observed_at"]) >= stamp(record["started_at"]):
            retry = recent
            if running and stamp(retry["retry_not_before"]) > now:
                state = "실행 중 · 재시도 대기"
    candidate = directory / "candidate.json"
    if (
        not running
        and candidate.exists()
        and candidate.stat().st_mtime >= stamp(record["started_at"]).timestamp()
    ):
        state = "배치 종료 · 결과 생성됨"
    return {
        "checked_at": now.astimezone().strftime("%m-%d %H:%M:%S %Z"),
        "state": state,
        "sessions": record["model_session_limit"],
        "total": len(audits),
        "target": record.get("target", 1000),
        "validated": statuses["VALIDATED"],
        "partial": statuses["PARTIAL"],
        "unavailable": statuses["UNAVAILABLE"],
        "reprocessed": max(0, len(audits) - record.get("reused_text_records", 95)),
        "retry_target": record.get("retry_target", 905),
        "photo_images": sum(len(m["images"]) for m in moods),
        "latest_retry": retry,
        "log_updated_at": datetime.fromtimestamp(log.stat().st_mtime)
        .astimezone()
        .strftime("%H:%M:%S %Z")
        if log.exists()
        else None,
    }


def display(value):
    print(
        f"[{value['checked_at']}] {value['state']} | 설정: 동시 {value['sessions']}세션"
    )
    print(
        f"텍스트 처리 {value['total']}/{value['target']}곳 ({100 * value['total'] / value['target']:.1f}%) — 검증 통과 {value['validated']}, 부분 유효 {value['partial']}, 분석 불가 {value['unavailable']}"
    )
    print(
        f"실패분 재처리 {value['reprocessed']}/{value['retry_target']}곳 | 사진 분석 결과 {value['photo_images']}장"
    )
    retry = value["latest_retry"]
    if retry and "대기" in value["state"]:
        reason = "HTTP 429" if retry.get("http_status") == 429 else "연결 오류"
        deadline = stamp(retry["retry_not_before"]).astimezone().strftime("%H:%M:%S %Z")
        print(f"{reason} 대기: {deadline} 이후 자동 재시도")
    print(f"마지막 로그 갱신: {value['log_updated_at']}", flush=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--run-record", type=Path, default=DEFAULT_RECORD)
    parser.add_argument(
        "--watch",
        action="store_true",
        help="Refresh until Ctrl+C; does not stop analysis",
    )
    parser.add_argument("--interval", type=float, default=10)
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args()
    if args.interval < 1:
        parser.error("--interval must be at least 1 second")
    try:
        while True:
            value = snapshot(args.run_record)
            if args.watch and sys.stdout.isatty() and not args.json:
                print("\033[2J\033[H", end="")
            if args.json:
                print(json.dumps(value, ensure_ascii=False), flush=True)
            else:
                display(value)
            if not args.watch:
                return 0
            time.sleep(args.interval)
    except KeyboardInterrupt:
        return 0


if __name__ == "__main__":
    raise SystemExit(main())
