from decimal import Decimal

import httpx
import pytest

from itda.authenticity.social import (
    ACTOR_ID,
    ApifyPilot,
    BudgetLedger,
    SocialCollectionPaused,
    minimal_result,
    pilot_input,
)


def test_budget_reservations_bound_all_runs_and_unknown_cost_is_not_free(tmp_path):
    ledger = BudgetLedger(tmp_path / "budget.json", total_usd="10")
    ledger.reserve("a", max_usd="6", input_sha="a" * 64)
    with pytest.raises(SocialCollectionPaused):
        ledger.reserve("b", max_usd="5", input_sha="b" * 64)
    ledger.update("a", status="SUCCEEDED", actual_usd="2.5")
    ledger.reserve("b", max_usd="7.5", input_sha="b" * 64)
    with pytest.raises(SocialCollectionPaused):
        ledger.reserve("c", max_usd=".01", input_sha="c" * 64)
    with pytest.raises(ValueError):
        BudgetLedger(tmp_path / "budget.json", total_usd="20")
    with pytest.raises(SocialCollectionPaused):
        ledger.update("a", actual_usd="6.01")


def test_uncertain_post_is_never_restarted_automatically(tmp_path):
    starts = []

    def handle(request):
        starts.append(request)
        raise httpx.ReadTimeout("simulated", request=request)

    client = ApifyPilot(
        token="test-key",
        directory=tmp_path,
        total_budget_usd="10",
        transport=httpx.MockTransport(handle),
    )
    with pytest.raises(httpx.ReadTimeout):
        client.start(("불국사",), max_usd="10")
    with pytest.raises(SocialCollectionPaused, match="START_UNCERTAIN"):
        client.start(("불국사",), max_usd="10")
    assert len(starts) == 1
    assert starts[0].url.params["maxTotalChargeUsd"] == "10"
    assert "token" not in str(starts[0].url)
    client.close()


def test_realistic_run_poll_result_and_resume_without_another_start(tmp_path):
    starts = []
    run = {
        "id": "run1",
        "actId": "cHedUknx10dsaavpI",
        "buildId": "build1",
        "status": "RUNNING",
        "defaultDatasetId": "data1",
        "options": {"maxTotalChargeUsd": 10},
    }

    def handle(request):
        if request.method == "POST":
            starts.append(request)
            assert request.url.path == f"/v2/acts/{ACTOR_ID}/runs"
            return httpx.Response(201, json={"data": run})
        if "/actor-runs/" in request.url.path:
            return httpx.Response(
                200, json={"data": run | {"status": "SUCCEEDED", "usageTotalUsd": 0.0163}}
            )
        return httpx.Response(
            200,
            json=[
                {
                    "name": "불국사",
                    "postsCount": 123,
                    "topPosts": [
                        {
                            "id": "post1",
                            "caption": "경주 불국사",
                            "ownerUsername": "not retained",
                            "comments": [{"text": "not retained"}],
                        }
                    ],
                }
            ],
        )

    client = ApifyPilot(
        token="test-key",
        directory=tmp_path,
        total_budget_usd="10",
        transport=httpx.MockTransport(handle),
    )
    first = client.start(("불국사",), max_usd="10")
    assert first["run_id"] == "run1"
    assert client.start(("불국사",), max_usd="10")["run_id"] == "run1"
    assert client.poll()["actual_usd"] == "0.0163"
    result = client.results()
    assert result[0]["postsCount"] == 123 and len(starts) == 1
    assert "ownerUsername" not in result[0]["topPosts"][0]
    assert "comments" not in result[0]["topPosts"][0]
    assert Decimal(client.poll()["actual_usd"]) <= 10
    client.close()


def test_missing_count_remains_missing_and_duplicate_post_sample_is_deduplicated():
    result = minimal_result(
        {
            "name": "empty",
            "topPosts": [{"id": "x", "caption": "same"}, {"id": "x", "caption": "same"}],
        }
    )
    assert "postsCount" not in result
    assert len(result["topPosts"]) == 1
    with pytest.raises(ValueError):
        pilot_input(tuple(str(i) for i in range(121)))


def test_rate_limit_stops_without_automatic_restart(tmp_path):
    calls = []

    def handle(request):
        calls.append(request)
        return httpx.Response(429, json={"error": {"message": "limited"}})

    client = ApifyPilot(
        token="test-key",
        directory=tmp_path,
        total_budget_usd="10",
        transport=httpx.MockTransport(handle),
    )
    with pytest.raises(SocialCollectionPaused, match="RATE_LIMIT"):
        client.start(("불국사",), max_usd="10")
    assert len(calls) == 1
    client.close()


def test_posts_fallback_uses_same_budget_and_bounded_payload(tmp_path):
    import json

    ledger = tmp_path / "budget.json"
    BudgetLedger(ledger, total_usd="10").reserve("existing", max_usd="8", input_sha="a" * 64)
    calls = []

    def handle(request):
        calls.append(request)
        assert request.url.path == "/v2/acts/apify~instagram-hashtag-scraper/runs"
        assert request.url.params["maxTotalChargeUsd"] == "2"
        assert json.loads(request.content) == {
            "hashtags": ["불국사"],
            "resultsType": "posts",
            "resultsLimit": 5,
        }
        return httpx.Response(
            201,
            json={
                "data": {
                    "id": "posts1",
                    "status": "READY",
                    "buildId": "build2",
                    "defaultDatasetId": "data2",
                }
            },
        )

    client = ApifyPilot(
        token="test-key",
        directory=tmp_path / "posts",
        total_budget_usd="10",
        mode="POSTS",
        budget_ledger=ledger,
        transport=httpx.MockTransport(handle),
    )
    with pytest.raises(SocialCollectionPaused):
        client.start(("불국사",), max_usd="3")
    assert not calls
    assert client.start(("불국사",), max_usd="2")["run_id"] == "posts1"
    client.close()
