from __future__ import annotations

import json
import re
from pathlib import Path

import pytest

REPOSITORY_ROOT = Path(__file__).resolve().parents[3]
RETENTION_JOB = REPOSITORY_ROOT / "infra/gcp/profile-release-draft-retention.tf.json"


def _retention_contract() -> dict[str, object]:
    return json.loads(RETENTION_JOB.read_text())


def _validate_local_plan_variables(
    contract: dict[str, object],
    variables: dict[str, str],
) -> None:
    job = contract["resource"]["google_cloud_run_v2_job"][
        "profile_release_draft_retention"
    ]
    for precondition in job["lifecycle"]["precondition"]:
        matched = re.fullmatch(
            r"\$\{var\.([a-z_]+) != var\.([a-z_]+)\}",
            precondition["condition"],
        )
        assert matched is not None
        left, right = matched.groups()
        if variables[left] == variables[right]:
            raise ValueError(precondition["error_message"])


def test_retention_job_runs_only_the_builder_scoped_purge_command() -> None:
    contract = _retention_contract()
    resources = contract["resource"]
    job = resources["google_cloud_run_v2_job"]["profile_release_draft_retention"]
    task = job["template"]["template"]
    container = task["containers"][0]

    assert job["deletion_protection"] is True
    assert job["template"]["task_count"] == 1
    assert job["template"]["parallelism"] == 1
    assert task["max_retries"] == 2
    assert task["timeout"] == "300s"
    assert container["command"] == ["python"]
    assert container["args"] == [
        "-m",
        "itda.cli.manage_profile_release",
        "--purge-expired-build-drafts",
    ]
    environment = {entry["name"]: entry for entry in container["env"]}
    assert set(environment) == {
        "ITDA_PHASE3_CAPABILITY",
        "ITDA_PHASE3_BUILDER_CAPABILITY_SHA256",
        "ITDA_PHASE3_BUILDER_DATABASE_URL",
    }
    assert all("value_source" in entry for entry in environment.values())
    assert "ADMIN" not in json.dumps(environment)
    assert "APPROVER" not in json.dumps(environment)


def test_retention_schedule_is_bounded_and_uses_authenticated_jobs_run() -> None:
    contract = _retention_contract()
    scheduler = contract["resource"]["google_cloud_scheduler_job"][
        "profile_release_draft_retention"
    ]

    assert scheduler["schedule"] == "*/5 * * * *"
    assert scheduler["time_zone"] == "Etc/UTC"
    assert scheduler["attempt_deadline"] == "320s"
    assert scheduler["retry_config"]["retry_count"] == 2
    target = scheduler["http_target"]
    assert target["http_method"] == "POST"
    assert target["uri"].endswith(":run")
    assert target["oauth_token"]["service_account_email"] == (
        "${var.scheduler_service_account}"
    )
    assert scheduler["depends_on"] == [
        "google_cloud_run_v2_job_iam_member."
        "profile_release_draft_retention_scheduler_invoker"
    ]


def test_retention_identities_have_only_required_invoker_and_secret_access() -> None:
    contract = _retention_contract()
    resources = contract["resource"]
    assert "check" not in contract
    separation = resources["google_cloud_run_v2_job"][
        "profile_release_draft_retention"
    ]["lifecycle"]["precondition"]
    assert separation == [
        {
            "condition": (
                "${var.scheduler_service_account != "
                "var.retention_job_service_account}"
            ),
            "error_message": (
                "The profile release retention scheduler and runtime service "
                "accounts must be distinct."
            ),
        }
    ]
    invoker = resources["google_cloud_run_v2_job_iam_member"][
        "profile_release_draft_retention_scheduler_invoker"
    ]
    assert invoker == {
        "project": "${var.project_id}",
        "location": "${var.region}",
        "name": "${google_cloud_run_v2_job.profile_release_draft_retention.name}",
        "role": "roles/run.invoker",
        "member": "serviceAccount:${var.scheduler_service_account}",
    }

    secret_members = resources["google_secret_manager_secret_iam_member"]
    assert set(secret_members) == {
        "profile_release_draft_retention_capability",
        "profile_release_draft_retention_builder_capability_sha256",
        "profile_release_draft_retention_builder_database_url",
    }
    expected_secrets = {
        "${var.phase3_capability_secret}",
        "${var.phase3_builder_capability_sha256_secret}",
        "${var.phase3_builder_database_url_secret}",
    }
    assert {member["secret_id"] for member in secret_members.values()} == expected_secrets
    assert all(
        member["role"] == "roles/secretmanager.secretAccessor"
        and member["member"]
        == "serviceAccount:${var.retention_job_service_account}"
        for member in secret_members.values()
    )

    job = resources["google_cloud_run_v2_job"][
        "profile_release_draft_retention"
    ]
    assert set(job["depends_on"]) == {
        "google_secret_manager_secret_iam_member."
        "profile_release_draft_retention_capability",
        "google_secret_manager_secret_iam_member."
        "profile_release_draft_retention_builder_capability_sha256",
        "google_secret_manager_secret_iam_member."
        "profile_release_draft_retention_builder_database_url",
    }


def test_retention_blocking_precondition_rejects_aliased_accounts_locally() -> None:
    """Exercise plan-time resource preconditions without contacting a provider."""

    contract = _retention_contract()
    _validate_local_plan_variables(
        contract,
        {
            "scheduler_service_account": (
                "retention-scheduler@example.iam.gserviceaccount.com"
            ),
            "retention_job_service_account": (
                "retention-runtime@example.iam.gserviceaccount.com"
            ),
        },
    )
    with pytest.raises(
        ValueError,
        match="scheduler and runtime service accounts must be distinct",
    ):
        _validate_local_plan_variables(
            contract,
            {
                "scheduler_service_account": (
                    "collapsed@example.iam.gserviceaccount.com"
                ),
                "retention_job_service_account": (
                    "collapsed@example.iam.gserviceaccount.com"
                ),
            },
        )


def test_retention_metrics_cover_success_failure_and_missing_execution() -> None:
    resources = _retention_contract()["resource"]
    metrics = resources["google_logging_metric"]
    success = metrics["profile_release_draft_retention_success"]
    assert success["metric_descriptor"] == {
        "metric_kind": "DELTA",
        "value_type": "INT64",
        "unit": "1",
    }
    assert "value_extractor" not in success
    deleted_count = metrics["profile_release_draft_retention_deleted_count"]
    assert deleted_count["metric_descriptor"] == {
        "metric_kind": "DELTA",
        "value_type": "DISTRIBUTION",
        "unit": "1",
    }
    assert deleted_count["value_extractor"] == "EXTRACT(jsonPayload.deleted_count)"
    assert deleted_count["bucket_options"] == {
        "exponential_buckets": {
            "num_finite_buckets": 10,
            "growth_factor": 2,
            "scale": 1,
        }
    }
    assert "jsonPayload.status=\"FAILED\"" in metrics[
        "profile_release_draft_retention_failure"
    ]["filter"]
    scheduler_chain = [
        "google_cloud_scheduler_job.profile_release_draft_retention",
        "google_cloud_run_v2_job_iam_member."
        "profile_release_draft_retention_scheduler_invoker",
    ]
    assert all(metric["depends_on"] == scheduler_chain for metric in metrics.values())

    alerts = resources["google_monitoring_alert_policy"]
    assert set(alerts) == {
        "profile_release_draft_retention_failure",
        "profile_release_draft_retention_missing_success",
    }
    missing = alerts["profile_release_draft_retention_missing_success"]["conditions"][0]
    assert missing["condition_absent"]["duration"] == "900s"
    assert alerts["profile_release_draft_retention_failure"]["depends_on"] == [
        "google_logging_metric.profile_release_draft_retention_failure"
    ]
    assert alerts["profile_release_draft_retention_missing_success"]["depends_on"] == [
        "google_logging_metric.profile_release_draft_retention_success"
    ]
