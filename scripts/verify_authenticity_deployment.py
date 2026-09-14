#!/usr/bin/env python3
"""Read-only HTTPS verification of the exact public deployment, without provider calls."""

import argparse
import json
import re
import ssl
import urllib.error
import urllib.parse
import urllib.request


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--origin", required=True)
    parser.add_argument("--release-sha256", required=True)
    parser.add_argument("--places", required=True, type=int)
    parser.add_argument("--photo-enabled", choices=("0", "1"), default="1")
    parser.add_argument(
        "--ca-file", help="Local rehearsal CA; system trust is the default"
    )
    args = parser.parse_args()
    origin = args.origin.rstrip("/")
    parsed = urllib.parse.urlsplit(origin)
    if (
        parsed.scheme != "https"
        or not parsed.hostname
        or parsed.username
        or parsed.password
        or parsed.path
        or parsed.query
        or parsed.fragment
        or not re.fullmatch(r"[0-9a-f]{64}", args.release_sha256)
        or args.places < 1
    ):
        parser.error(
            "an HTTPS origin, release SHA-256 and positive place count are required"
        )
    context = ssl.create_default_context(cafile=args.ca_file)
    paths = {
        "/": 200,
        "/trip": 200,
        "/internal": 404,
        "/internal/evaluation/profile-releases/probe": 404,
        "/v1/authenticity/info": 200,
    }
    try:
        info = None
        for path, expected in paths.items():
            try:
                response = urllib.request.urlopen(
                    origin + path, context=context, timeout=45
                )
            except urllib.error.HTTPError as error:
                response = error
            with response:
                if response.status != expected or response.url != origin + path:
                    raise ValueError("unexpected status or redirect: " + path)
                if path.endswith("/info"):
                    info = json.loads(response.read(65536))
        if not isinstance(info, dict) or (
            info.get("scope") != "PUBLIC"
            or info.get("release_sha256") != args.release_sha256
            or info.get("places") != args.places
            or info.get("photo_enabled") is not (args.photo_enabled == "1")
        ):
            raise ValueError("PUBLIC release, count or photo configuration mismatch")
    except (OSError, ValueError, TypeError) as error:
        # No credentials are accepted or read by this command.
        print(json.dumps({"verified": False, "reason": str(error)}))
        return 1
    print(
        json.dumps(
            {
                "verified": True,
                "origin": origin,
                "scope": "PUBLIC",
                "places": args.places,
                "release_sha256": args.release_sha256,
                "photo_enabled": args.photo_enabled == "1",
                "paths": paths,
            }
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
