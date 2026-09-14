"""Check actual PUBLIC readiness; no model calls or collection requests."""

from __future__ import annotations

import json
import os
import urllib.request
from collections.abc import Mapping
from typing import Any


def ready(info: Mapping[str, Any], environment: Mapping[str, str]) -> bool:
    expected = environment.get("ITDA_AUTHENTICITY_RELEASE_SHA256", "")
    count = environment.get("ITDA_AUTHENTICITY_EXPECTED_PLACES", "")
    return bool(
        expected
        and count.isdigit()
        and info.get("scope") == "PUBLIC"
        and info.get("release_sha256") == expected
        and info.get("places") == int(count)
        and info.get("photo_enabled") == (environment.get("ITDA_AUTHENTICITY_PHOTO_ENABLED") == "1")
    )


def main() -> int:
    try:
        with urllib.request.urlopen(
            "http://127.0.0.1:8000/v1/authenticity/info", timeout=35
        ) as response:
            info = json.loads(response.read(65536))
        return 0 if ready(info, os.environ) else 1
    except (OSError, ValueError, TypeError):
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
