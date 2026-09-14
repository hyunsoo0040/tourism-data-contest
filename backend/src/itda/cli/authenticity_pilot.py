"""Prepare and run the specifically authorized, bounded Instagram pilot."""

from __future__ import annotations

import argparse
import json
import time
from pathlib import Path

from itda.authenticity.pilot import prepare_pilot
from itda.authenticity.social import TERMINAL, ApifyPilot
from itda.cli.collect_national_public_catalog import _environment
from itda.domain.canonical import canonical_sha256


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("command", choices=("prepare", "run", "status", "collect"))
    parser.add_argument("--repository", type=Path, default=Path.cwd())
    parser.add_argument(
        "--output", type=Path, default=Path("artifacts/authenticity-v1/20260911/instagram-pilot")
    )
    parser.add_argument("--env-file", type=Path, default=Path(".secrets/itda-apify.env"))
    parser.add_argument("--wait", action="store_true")
    parser.add_argument("--mode", choices=("ANALYTICS", "POSTS", "DETAILS"), default="ANALYTICS")
    args = parser.parse_args()
    if args.command == "prepare":
        result = prepare_pilot(repository=args.repository, output=args.output)
        print(
            json.dumps(
                {
                    k: result[k]
                    for k in ("place_count", "tag_count", "budget_usd", "manifest_sha256")
                },
                ensure_ascii=False,
            )
        )
        return 0
    manifest = json.loads((args.output / "pilot-manifest.json").read_text())
    if (
        canonical_sha256({k: v for k, v in manifest.items() if k != "manifest_sha256"})
        != manifest["manifest_sha256"]
    ):
        raise ValueError("PILOT_MANIFEST_DIGEST_MISMATCH")
    if (
        manifest["place_count"] > 40
        or manifest["tag_count"] > 120
        or manifest["budget_usd"] != "10.00"
    ):
        raise ValueError("PILOT_EXCEEDS_AUTHORIZED_SCOPE")
    token = _environment(args.env_file).get("APIFY_API_TOKEN", "")
    directory = args.output if args.mode == "ANALYTICS" else args.output / args.mode.lower()
    client = ApifyPilot(
        token=token,
        directory=directory,
        total_budget_usd=manifest["budget_usd"],
        mode=args.mode,
        budget_ledger=args.output / "budget.json",
    )
    try:
        if args.command == "run":
            print(
                json.dumps(
                    client.start(
                        tuple(manifest["tags"])
                        if args.mode == "ANALYTICS"
                        else tuple(dict.fromkeys(p["primary_tag"] for p in manifest["places"])),
                        max_usd="10.00" if args.mode == "ANALYTICS" else "3.00",
                    )
                ),
                flush=True,
            )
        if args.command == "collect":
            print(json.dumps({"items": len(client.results())}), flush=True)
            return 0
        while True:
            result = client.poll()
            print(json.dumps(result), flush=True)
            if result["status"] in TERMINAL:
                print(
                    json.dumps(
                        {"retained_items": len(client.results()), "status": result["status"]}
                    ),
                    flush=True,
                )
                return 0 if result["status"] == "SUCCEEDED" else 2
            if not args.wait:
                return 0
            time.sleep(10)
    finally:
        client.close()


if __name__ == "__main__":
    raise SystemExit(main())
