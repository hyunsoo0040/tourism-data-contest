"""Test-only browser fixture from actual app/kernel/PostgreSQL with mock HTTP.

Input is a synthetic browser journey's profile and recommendation request on
stdin. The artifact never contains DB credentials or provider credentials.
"""

from __future__ import annotations

import json
import sys
from contextlib import closing
from pathlib import Path

import pytest

from itda.contracts.preference import PreferenceProfile
from itda.db.repositories import ProfileRepository
from itda.db.session import create_session_factory
from itda.domain.canonical import canonical_sha256
from tests.conftest import postgres_harness
from tests.integration.test_source_grounding_tracer import stack


def main() -> None:
    incoming = json.load(sys.stdin)
    profile = PreferenceProfile.model_validate(incoming["profile"])
    request = incoming["request"]
    if request["preference_profile_id"] != profile.profile_id:
        raise ValueError("browser profile identity mismatch")
    with closing(postgres_harness.__wrapped__()) as harness_generator:
        harness = next(harness_generator)
        with (
            pytest.MonkeyPatch.context() as patch,
            closing(stack.__wrapped__(harness, patch)) as stack_generator,
        ):
            runtime = next(stack_generator)
            ProfileRepository(create_session_factory(runtime.engine)).create(profile)
            runtime.profile_id = profile.profile_id
            baseline_id = runtime.create(runtime.request("baseline:browser-fixture"))
            baseline = runtime.service.get_run(baseline_id)
            runtime.state.unknown.add(baseline.items[1].place_id)
            response = runtime.client.post("/v1/recommendation-runs", json=request)
            if response.status_code != 201:
                raise RuntimeError(
                    f"actual tracer create failed: {response.status_code}"
                )
            created = response.json()
            run_id = created["recommendation_run_id"]
            results = runtime.client.get(f"/v1/recommendation-runs/{run_id}")
            context = runtime.client.get(
                f"/v1/recommendation-runs/{run_id}/trip-context"
            )
            if results.status_code != 200 or context.status_code != 200:
                raise RuntimeError("actual tracer read failed")
            artifact = {
                "schema_version": "source-grounding-browser-fixture.v1",
                "provenance": "SYNTHETIC_CATALOG_REAL_APP_POSTGRES_MOCK_OFFICIAL_HTTP",
                "limitations": "Browser replays captured application responses; provider transport uses recorded facility wording and synthetic identity. This is not a live provider end-to-end test.",
                "profile": profile.model_dump(mode="json"),
                "request": request,
                "created": created,
                "results": results.json(),
                "context": context.json(),
                "provider_request_count": len(runtime.state.calls),
            }
            artifact["artifact_sha256"] = canonical_sha256(artifact)
    destination = Path(sys.argv[1])
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_text(json.dumps(artifact, ensure_ascii=False, indent=2) + "\n")
    print(
        json.dumps({"fixture": str(destination), "run_id": run_id, "status": "created"})
    )


if __name__ == "__main__":
    main()
