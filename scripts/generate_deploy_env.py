#!/usr/bin/env python3
"""Generate a private Docker Swarm deployment environment without exposing secrets."""

from __future__ import annotations

import argparse
import base64
import os
import re
import secrets
from pathlib import Path

_DOMAIN = re.compile(
    r"(?=.{1,253}\Z)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+"
    r"[a-z](?:[a-z0-9-]{0,61}[a-z0-9])?"
)
_IMAGE_TAG = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}")
_REGISTRY = "pengginregistry.pengbot.app/itda"
_STACK_NAME = re.compile(r"[a-z0-9][a-z0-9_-]{0,62}")
_EMAIL = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,63}")
_ENV_SAFE_PATH = re.compile(r"/[A-Za-z0-9_./-]+")


def _password() -> str:
    return secrets.token_hex(32)


def _session_key() -> str:
    return base64.urlsafe_b64encode(secrets.token_bytes(32)).decode().rstrip("=")


def _validate_domain(value: str) -> str:
    if _DOMAIN.fullmatch(value) is None:
        raise argparse.ArgumentTypeError(
            "domain must be a lowercase fully-qualified hostname"
        )
    return value


def _validate_image_reference(value: str) -> str:
    if _IMAGE_TAG.fullmatch(value) is None:
        raise argparse.ArgumentTypeError("image reference must be a valid tag")
    return value


def _validate_stack_name(value: str) -> str:
    if _STACK_NAME.fullmatch(value) is None:
        raise argparse.ArgumentTypeError(
            "stack name must be a safe lowercase identifier"
        )
    return value


def _validate_email(value: str) -> str:
    if _EMAIL.fullmatch(value) is None:
        raise argparse.ArgumentTypeError("ACME email is invalid")
    return value


def _validate_path(value: str) -> Path:
    if _ENV_SAFE_PATH.fullmatch(value) is None:
        raise argparse.ArgumentTypeError("dashboard users path is invalid")
    return Path(value)


def _render(
    domain: str,
    backend_image: str,
    web_image: str,
    *,
    stack_name: str,
    acme_email: str,
    dashboard_domain: str,
    whoami_domain: str,
    dashboard_users_file: Path,
    authenticity_release_sha256: str,
    authenticity_places: int,
) -> str:
    variables = {
        "STACK_NAME": stack_name,
        "APP_DOMAIN": domain,
        "TRAEFIK_NETWORK": "proxy",
        "TRAEFIK_CERT_RESOLVER": "le",
        "TRAEFIK_ACME_EMAIL": acme_email,
        "TRAEFIK_DASHBOARD_DOMAIN": dashboard_domain,
        "TRAEFIK_WHOAMI_DOMAIN": whoami_domain,
        "TRAEFIK_DASHBOARD_USERS_FILE": str(dashboard_users_file),
        "ITDA_GLM_DASHBOARD_BASIC_AUTH_USERS": (
            "replace-with-username-and-bcrypt-hash"
        ),
        "BACKEND_IMAGE": f"{_REGISTRY}/backend:{backend_image}",
        "WEB_IMAGE": f"{_REGISTRY}/web:{web_image}",
        "ITDA_POSTGRES_DB": "itda",
        "ITDA_POSTGRES_ADMIN_USER": "itda_admin",
        "ITDA_POSTGRES_ADMIN_PASSWORD": _password(),
        "ITDA_RUNTIME_ROLE": "itda_runtime",
        "ITDA_RUNTIME_PASSWORD": _password(),
        "ITDA_LABEL_BUILDER_ROLE": "itda_label_builder",
        "ITDA_LABEL_BUILDER_PASSWORD": _password(),
        "ITDA_LABEL_APPROVER_ROLE": "itda_label_approver",
        "ITDA_LABEL_APPROVER_PASSWORD": _password(),
        "ITDA_PROFILE_RELEASE_AUTHORITY_SERVICE_PASSWORD": _password(),
        "ITDA_PHOTO_SERVICE_PASSWORD": _password(),
        "ITDA_PROFILE_SESSION_SERVICE_PASSWORD": _password(),
        "ITDA_DAILY_GLM_REFRESH_SERVICE_PASSWORD": _password(),
        "ITDA_PROFILE_SESSION_CURRENT_KID": "current",
        "ITDA_PROFILE_SESSION_KEYRING": f"current.{_session_key()}",
        "ITDA_OPERATING_INFORMATION_ENABLED": "0",
        "ITDA_TOUR_API_SERVICE_KEY_SECRET": "itda_tour_api_service_key",
        "ITDA_OPERATING_INFORMATION_TIMEOUT_SECONDS": "1.5",
        "ITDA_OPERATING_INFORMATION_TTL_SECONDS": "900",
        "ITDA_OPERATING_INFORMATION_NEGATIVE_TTL_SECONDS": "120",
        "ITDA_GROUNDED_RECOMMENDATIONS_ENABLED": "0",
        "ITDA_TOURISM_ENABLED": "0",
        "ITDA_PHOTO_MOOD_ENABLED": "1",
        "ITDA_GROUNDED_DAILY_ENABLED": "0",
        "ITDA_GROUNDED_DAILY_WORKERS": "4",
        "ITDA_GROUNDED_DAILY_REPLICAS": "0",
        "ITDA_AUTHENTICITY_RELEASE_SHA256": authenticity_release_sha256,
        "ITDA_AUTHENTICITY_EXPECTED_PLACES": str(authenticity_places),
        "ITDA_AUTHENTICITY_PREVIOUS_RELEASE_SHA256": "NONE",
        "ITDA_AUTHENTICITY_ALLOW_DEVELOPMENT": "0",
        "ITDA_AUTHENTICITY_PHOTO_ENABLED": "1",
        "ITDA_GROUNDED_DAILY_GATE_FILE": "",
        "ITDA_GROUNDED_DAILY_REPORT_DIR": "",
        "ITDA_MODEL_SESSION_LIMIT": "5",
        "ITDA_ZHIPUAI_API_KEY_SECRET": "itda_zhipuai_api_key",
        "ITDA_DAILY_GLM_REFRESH_SERVICE_PASSWORD_SECRET": (
            "itda_daily_glm_refresh_service_password"
        ),
        "ITDA_DAILY_TOUR_API_TIMEOUT_SECONDS": "15",
    }
    return "".join(f"{name}={value}\n" for name, value in variables.items())


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--domain", required=True, type=_validate_domain)
    parser.add_argument(
        "--backend-image", required=True, type=_validate_image_reference
    )
    parser.add_argument("--web-image", required=True, type=_validate_image_reference)
    parser.add_argument("--stack-name", required=True, type=_validate_stack_name)
    parser.add_argument("--acme-email", required=True, type=_validate_email)
    parser.add_argument("--dashboard-domain", required=True, type=_validate_domain)
    parser.add_argument("--whoami-domain", required=True, type=_validate_domain)
    parser.add_argument("--dashboard-users-file", required=True, type=_validate_path)
    parser.add_argument("--release-sha256", required=True)
    parser.add_argument("--places", required=True, type=int)
    parser.add_argument("--output", type=Path, default=Path("deploy/.env"))
    arguments = parser.parse_args()
    if (
        not re.fullmatch(r"[0-9a-f]{64}", arguments.release_sha256)
        or arguments.places < 1
    ):
        parser.error("a PUBLIC release SHA-256 and positive place count are required")

    output = arguments.output.resolve()
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    previous_umask = os.umask(0o077)
    created = False
    try:
        descriptor = os.open(output, flags, 0o600)
        created = True
        os.fchmod(descriptor, 0o600)
        with os.fdopen(descriptor, "w", encoding="utf-8", newline="\n") as handle:
            handle.write(
                _render(
                    arguments.domain,
                    arguments.backend_image,
                    arguments.web_image,
                    stack_name=arguments.stack_name,
                    acme_email=arguments.acme_email,
                    dashboard_domain=arguments.dashboard_domain,
                    whoami_domain=arguments.whoami_domain,
                    dashboard_users_file=arguments.dashboard_users_file.resolve(),
                    authenticity_release_sha256=arguments.release_sha256,
                    authenticity_places=arguments.places,
                )
            )
            handle.flush()
            os.fsync(handle.fileno())
    except FileExistsError:
        parser.error("output already exists; refusing to overwrite it")
    except Exception:
        if created:
            output.unlink(missing_ok=True)
        raise
    finally:
        os.umask(previous_umask)

    print(f"Created private deployment environment: {output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
