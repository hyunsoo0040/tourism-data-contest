"""FastAPI dependency wiring and closed anonymous-session authority."""

from __future__ import annotations

import base64
import hashlib
import hmac
import ipaddress
import os
import re
import secrets
import threading
import time
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from functools import lru_cache
from pathlib import Path
from typing import Annotated, Literal
from urllib.parse import urlsplit

from fastapi import Cookie, Depends, HTTPException, Request, Security
from fastapi.security import APIKeyHeader
from sqlalchemy import Engine, text

from itda.application.preferences import PreferenceService
from itda.application.recommendations import RecommendationService
from itda.contracts.base import ExperienceAxis, StableId, StrictContract
from itda.contracts.preference import PreferenceProfile
from itda.db.evaluation_repositories import EvaluationRepository
from itda.db.mvp_release_overlay import ActiveReleaseOverlayResolver, DailyReleaseOverlayReader
from itda.db.mvp_scored_release import resolve_active_mvp_scored_release
from itda.db.photo_repositories import PhotoRecommendationProjectionReader
from itda.db.recommendation_repositories import RecommendationRunRepository
from itda.db.repositories import ProfileRepository
from itda.db.session import create_database_engine, create_session_factory
from itda.operating.service import (
    OperatingInformationService,
    PublicCatalogLookup,
    TourApiOperatingProvider,
)
from itda.pipeline.offline_guard import require_live_collection_allowed

DATABASE_URL_ENVIRONMENT_VARIABLE = "ITDA_DATABASE_URL"
PROFILE_SESSION_DATABASE_URL_ENVIRONMENT_VARIABLE = "ITDA_PROFILE_SESSION_DATABASE_URL"
PHOTO_SERVICE_DATABASE_URL_ENVIRONMENT_VARIABLE = "ITDA_PHOTO_SERVICE_DATABASE_URL"
PROFILE_SESSION_COOKIE_NAME = "itda_current_profile"
_PROFILE_SESSION_TTL = timedelta(minutes=30)
_PROFILE_SESSION_ERROR = "profile session configuration rejected"
_PROFILE_SESSION_UNAUTHORIZED = "current profile session required"
_PROFILE_SESSION_REFERENCE = re.compile(r"^[A-Za-z0-9_-]{43}$")
_PROFILE_SESSION_KID = re.compile(r"^[A-Za-z0-9_-]{1,24}$")
PROFILE_RELEASE_AUTHORITY_DATABASE_URL_ENVIRONMENT_VARIABLE = (
    "ITDA_PHASE4_PROFILE_RELEASE_AUTHORITY_DATABASE_URL"
)
PROFILE_RELEASE_BUILDER_DATABASE_ROLE_ENVIRONMENT_VARIABLE = "ITDA_LABEL_BUILDER_ROLE"


@dataclass(frozen=True, slots=True)
class ProfileSessionPrincipal:
    profile_id: str
    session_digest: str
    raw_reference: str


@dataclass(frozen=True, slots=True)
class ProfileSessionKeyring:
    current_kid: str
    keys: dict[str, bytes]


@dataclass(frozen=True, slots=True)
class CookiePolicy:
    secure: bool


_RATE_LOCK = threading.Lock()
_RATE_WINDOWS: dict[str, tuple[float, int]] = {}


def _uniform_config_error() -> RuntimeError:
    return RuntimeError(_PROFILE_SESSION_ERROR)


@lru_cache(maxsize=1)
def get_profile_session_keyring() -> ProfileSessionKeyring:
    try:
        encoded = os.environ.get("ITDA_PROFILE_SESSION_KEYRING")
        current_kid = os.environ.get("ITDA_PROFILE_SESSION_CURRENT_KID")
        if (
            encoded is None
            or current_kid is None
            or _PROFILE_SESSION_KID.fullmatch(current_kid) is None
        ):
            raise ValueError
        entries = encoded.split(",")
        if not 1 <= len(entries) <= 2:
            raise ValueError
        keys: dict[str, bytes] = {}
        for entry in entries:
            kid, separator, value = entry.partition(".")
            if not separator or _PROFILE_SESSION_KID.fullmatch(kid) is None or kid in keys:
                raise ValueError
            padding = "=" * (-len(value) % 4)
            key = base64.b64decode(value + padding, altchars=b"-_", validate=True)
            if len(key) != 32:
                raise ValueError
            keys[kid] = key
        if current_kid not in keys:
            raise ValueError
        return ProfileSessionKeyring(current_kid=current_kid, keys=keys)
    except Exception:
        raise _uniform_config_error() from None


def _canonical_origin() -> str:
    try:
        raw = os.environ.get("ITDA_CANONICAL_APP_ORIGIN")
        if raw is None or raw.endswith("/") or len(raw) > 200:
            raise ValueError
        parsed = urlsplit(raw)
        if parsed.scheme not in {"http", "https"} or not parsed.hostname:
            raise ValueError
        if parsed.username or parsed.password or parsed.path or parsed.query or parsed.fragment:
            raise ValueError
        if parsed.hostname != parsed.hostname.lower():
            raise ValueError
        return raw
    except Exception:
        raise _uniform_config_error() from None


def _loopback(value: str | None) -> bool:
    try:
        return value is not None and ipaddress.ip_address(value).is_loopback
    except ValueError:
        return False


def _cookie_policy_for_request(request: Request) -> CookiePolicy:
    origin = _canonical_origin()
    e2e = os.environ.get("ITDA_E2E_ALLOW_INSECURE_COOKIE") == "1"
    bind = os.environ.get("ITDA_API_BIND_HOST")
    peer = request.client.host if request.client is not None else None
    parsed = urlsplit(origin)
    exact_loopback_origin = (
        parsed.scheme == "http"
        and parsed.hostname == "127.0.0.1"
        and parsed.port is not None
        and origin == f"http://127.0.0.1:{parsed.port}"
    )
    if e2e and _loopback(bind) and _loopback(peer) and exact_loopback_origin:
        return CookiePolicy(secure=False)
    return CookiePolicy(secure=True)


def validate_profile_session_startup() -> None:
    get_profile_session_keyring()
    _canonical_origin()
    if os.environ.get("ITDA_E2E_ALLOW_INSECURE_COOKIE") == "1":
        parsed = urlsplit(_canonical_origin())
        if not (
            _loopback(os.environ.get("ITDA_API_BIND_HOST"))
            and parsed.scheme == "http"
            and parsed.hostname == "127.0.0.1"
            and parsed.port is not None
            and _canonical_origin() == f"http://127.0.0.1:{parsed.port}"
        ):
            raise _uniform_config_error()


def require_same_origin_mutation(request: Request) -> None:
    if request.headers.get("origin") != _canonical_origin():
        raise HTTPException(status_code=403, detail="same-origin request required")
    fetch_site = request.headers.get("sec-fetch-site")
    if fetch_site is not None and fetch_site != "same-origin":
        raise HTTPException(status_code=403, detail="same-origin request required")


def _actual_peer_digest(request: Request) -> str:
    peer = request.client.host if request.client is not None else "unavailable"
    return hashlib.sha256(peer.encode()).hexdigest()


def enforce_profile_create_rate(request: Request) -> None:
    peer = request.client.host if request.client else "unavailable"
    key = hashlib.sha256(f"{peer}\0{_canonical_origin()}".encode()).hexdigest()
    now = time.monotonic()
    with _RATE_LOCK:
        start, count = _RATE_WINDOWS.get(key, (now, 0))
        if now - start >= 60:
            start, count = now, 0
        limit = 64 if os.environ.get("ITDA_E2E_ALLOW_INSECURE_COOKIE") == "1" else 8
        if count >= limit:
            raise HTTPException(status_code=429, detail="profile creation temporarily unavailable")
        _RATE_WINDOWS[key] = (start, count + 1)


def _sign_reference(reference: str, kid: str, key: bytes) -> str:
    material = f"v1.{kid}.{reference}".encode()
    signature = base64.urlsafe_b64encode(hmac.digest(key, material, "sha256")).decode().rstrip("=")
    return f"v1.{kid}.{reference}.{signature}"


def _decode_cookie(cookie: str | None) -> tuple[str, str] | None:
    if cookie is None or len(cookie) > 160:
        return None
    parts = cookie.split(".")
    if len(parts) != 4 or parts[0] != "v1":
        return None
    _, kid, reference, signature = parts
    if (
        _PROFILE_SESSION_KID.fullmatch(kid) is None
        or _PROFILE_SESSION_REFERENCE.fullmatch(reference) is None
    ):
        return None
    key = get_profile_session_keyring().keys.get(kid)
    if key is None:
        return None
    expected = _sign_reference(reference, kid, key).rsplit(".", 1)[1]
    if not hmac.compare_digest(signature, expected):
        return None
    return reference, hashlib.sha256(reference.encode()).hexdigest()


@lru_cache(maxsize=4)
def _session_engine_for_dsn(dsn: str) -> Engine:
    return create_database_engine(dsn)


def _session_engine() -> Engine:
    dsn = os.environ.get(PROFILE_SESSION_DATABASE_URL_ENVIRONMENT_VARIABLE)
    if not dsn:
        raise _uniform_config_error()
    return _session_engine_for_dsn(dsn)


def resolve_optional_profile_session(cookie: str | None) -> ProfileSessionPrincipal | None:
    decoded = _decode_cookie(cookie)
    if decoded is None:
        return None
    reference, digest = decoded
    with _session_engine().connect() as connection:
        profile_id = connection.execute(
            text("SELECT app.resolve_current_profile_session_v1(:digest)"), {"digest": digest}
        ).scalar_one_or_none()
    if profile_id is None:
        return None
    return ProfileSessionPrincipal(
        profile_id=str(profile_id), session_digest=digest, raw_reference=reference
    )


def get_optional_profile_session(
    cookie: Annotated[str | None, Cookie(alias=PROFILE_SESSION_COOKIE_NAME)] = None,
) -> ProfileSessionPrincipal | None:
    return resolve_optional_profile_session(cookie)


def get_profile_session(
    principal: Annotated[ProfileSessionPrincipal | None, Depends(get_optional_profile_session)],
) -> ProfileSessionPrincipal:
    if principal is None:
        raise HTTPException(status_code=401, detail=_PROFILE_SESSION_UNAUTHORIZED)
    return principal


def create_profile_and_issue_session(
    *, request: Request, profile: PreferenceProfile, predecessor: ProfileSessionPrincipal | None
) -> tuple[str, int, bool] | None:
    """Persist a new profile and its only usable authority in one transaction."""

    raw = base64.urlsafe_b64encode(secrets.token_bytes(32)).decode().rstrip("=")
    digest = hashlib.sha256(raw.encode()).hexdigest()
    issued_at = datetime.now(UTC)
    expires_at = issued_at + _PROFILE_SESSION_TTL
    scores = {score.axis: score for score in profile.scores}
    keyring = get_profile_session_keyring()
    cookie = _sign_reference(raw, keyring.current_kid, keyring.keys[keyring.current_kid])
    secure = _cookie_policy_for_request(request).secure
    parameters: dict[str, object] = {
        "profile_id": profile.profile_id,
        "request_id": profile.request_id,
        "trip_conditions": profile.trip_conditions.model_dump_json(),
        "answers": profile.answers.model_dump_json(),
        "history_bp": scores[ExperienceAxis.HISTORY_TRADITION].basis_points,
        "history_display": scores[ExperienceAxis.HISTORY_TRADITION].display_score,
        "emotion_bp": scores[ExperienceAxis.EMOTION_IMAGE].basis_points,
        "emotion_display": scores[ExperienceAxis.EMOTION_IMAGE].display_score,
        "rest_bp": scores[ExperienceAxis.REST_IMMERSION].basis_points,
        "rest_display": scores[ExperienceAxis.REST_IMMERSION].display_score,
        "description": profile.description_ko,
        "schema_version": profile.schema_version,
        "questionnaire_version": profile.questionnaire_version,
        "scoring_version": profile.scoring_version,
        "template_version": profile.description_template_version,
        "config_hash": profile.config_hash,
        "created_at": profile.created_at,
        "is_current": profile.is_current_trip_expectation,
        "digest": digest,
        "issued": issued_at,
        "expires": expires_at,
        "peer": _actual_peer_digest(request),
        "origin": hashlib.sha256(_canonical_origin().encode()).hexdigest(),
        "predecessor": predecessor.session_digest if predecessor else None,
    }
    with _session_engine().begin() as connection:
        created = connection.execute(
            text(
                "SELECT app.create_preference_profile_and_issue_session_v1("
                ":profile_id,:request_id,CAST(:trip_conditions AS jsonb),CAST(:answers AS jsonb),"
                ":history_bp,:history_display,:emotion_bp,:emotion_display,:rest_bp,"
                ":rest_display,:description,:schema_version,:questionnaire_version,"
                ":scoring_version,:template_version,:config_hash,:created_at,:is_current,"
                ":digest,:issued,:expires,:peer,:origin,:predecessor)"
            ),
            parameters,
        ).scalar_one()
    if not bool(created):
        return None
    return cookie, int(_PROFILE_SESSION_TTL.total_seconds()), secure


def rotate_profile_session(
    *, request: Request, principal: ProfileSessionPrincipal
) -> tuple[str, int, bool] | None:
    raw = base64.urlsafe_b64encode(secrets.token_bytes(32)).decode().rstrip("=")
    digest = hashlib.sha256(raw.encode()).hexdigest()
    issued_at = datetime.now(UTC)
    with _session_engine().begin() as connection:
        profile_id = connection.execute(
            text(
                "SELECT app.rotate_current_profile_session_v1(:old,:new,:issued,:expires,"
                ":peer,:origin)"
            ),
            {
                "old": principal.session_digest,
                "new": digest,
                "issued": issued_at,
                "expires": issued_at + _PROFILE_SESSION_TTL,
                "peer": _actual_peer_digest(request),
                "origin": hashlib.sha256(_canonical_origin().encode()).hexdigest(),
            },
        ).scalar_one_or_none()
    if profile_id is None:
        return None
    keyring = get_profile_session_keyring()
    return (
        _sign_reference(raw, keyring.current_kid, keyring.keys[keyring.current_kid]),
        int(_PROFILE_SESSION_TTL.total_seconds()),
        _cookie_policy_for_request(request).secure,
    )


def reset_profile_session_caches() -> None:
    get_profile_session_keyring.cache_clear()
    _session_engine_for_dsn.cache_clear()
    with _RATE_LOCK:
        _RATE_WINDOWS.clear()


Phase3Role = Literal[
    "evaluator_a",
    "evaluator_b",
    "evaluator_c",
    "adjudicator",
    "model_runner",
    "builder",
    "approver",
]
_PHASE3_CAPABILITY_ENVIRONMENTS: tuple[tuple[Phase3Role, str, str], ...] = (
    ("evaluator_a", "phase3-evaluator-a", "ITDA_PHASE3_EVALUATOR_A_CAPABILITY_SHA256"),
    ("evaluator_b", "phase3-evaluator-b", "ITDA_PHASE3_EVALUATOR_B_CAPABILITY_SHA256"),
    ("evaluator_c", "phase3-evaluator-c", "ITDA_PHASE3_EVALUATOR_C_CAPABILITY_SHA256"),
    ("adjudicator", "phase3-adjudicator", "ITDA_PHASE3_ADJUDICATOR_CAPABILITY_SHA256"),
    ("model_runner", "phase3-model-runner", "ITDA_PHASE3_MODEL_RUNNER_CAPABILITY_SHA256"),
    ("builder", "phase3-builder", "ITDA_PHASE3_BUILDER_CAPABILITY_SHA256"),
    ("approver", "phase3-approver", "ITDA_PHASE3_APPROVER_CAPABILITY_SHA256"),
)
_PHASE3_DATABASE_ENVIRONMENTS: dict[Phase3Role, str] = {
    role: f"ITDA_PHASE3_{role.upper()}_DATABASE_URL"
    for role, _, _ in _PHASE3_CAPABILITY_ENVIRONMENTS
}
_REVOKED_PHASE3_CAPABILITY_DIGESTS: set[str] = set()
_PHASE3_REVOCATION_LOCK = threading.Lock()
_PHASE3_CAPABILITY_HEADER = APIKeyHeader(
    name="X-ITDA-Phase3-Capability", scheme_name="Phase3Capability", auto_error=False
)


class Phase3Principal(StrictContract):
    actor_id: StableId
    role: Phase3Role


def resolve_phase3_principal(raw_capability: str) -> Phase3Principal:
    if not raw_capability:
        raise HTTPException(status_code=401, detail="phase 3 capability rejected")
    candidate_digest = hashlib.sha256(raw_capability.encode()).hexdigest()
    with _PHASE3_REVOCATION_LOCK:
        if candidate_digest in _REVOKED_PHASE3_CAPABILITY_DIGESTS:
            raise HTTPException(status_code=401, detail="phase 3 capability rejected")
    configured = False
    for role, actor_id, environment_name in _PHASE3_CAPABILITY_ENVIRONMENTS:
        expected_digest = os.environ.get(environment_name)
        if expected_digest is None:
            continue
        configured = True
        if len(expected_digest) == 64 and hmac.compare_digest(candidate_digest, expected_digest):
            return Phase3Principal(actor_id=actor_id, role=role)
    if not configured:
        raise RuntimeError("Phase 3 server capabilities are not configured")
    raise HTTPException(status_code=401, detail="phase 3 capability rejected")


def revoke_phase3_capability(raw_capability: str) -> None:
    resolve_phase3_principal(raw_capability)
    with _PHASE3_REVOCATION_LOCK:
        _REVOKED_PHASE3_CAPABILITY_DIGESTS.add(hashlib.sha256(raw_capability.encode()).hexdigest())


def get_phase3_principal(
    capability: Annotated[str | None, Security(_PHASE3_CAPABILITY_HEADER)] = None,
) -> Phase3Principal:
    if capability is None:
        raise HTTPException(status_code=401, detail="phase 3 capability rejected")
    return resolve_phase3_principal(capability)


@lru_cache(maxsize=8)
def _evaluation_repository_for_dsn(
    dsn: str,
    authority_dsn: str | None = None,
) -> EvaluationRepository:
    if authority_dsn is not None and authority_dsn == dsn:
        raise RuntimeError("profile release authority DSN must be distinct from builder DSN")
    engine = create_database_engine(dsn)
    if authority_dsn is None:
        return EvaluationRepository(create_session_factory(engine))
    authority_engine = create_database_engine(authority_dsn)
    try:
        with authority_engine.connect() as connection:
            authority_session_user = str(
                connection.execute(text("SELECT session_user")).scalar_one()
            )
        if authority_session_user != "itda_profile_release_authority_service":
            raise RuntimeError("profile release authority database role is invalid")
        with engine.connect() as connection:
            builder_session_user = str(connection.execute(text("SELECT session_user")).scalar_one())
            expected_builder = os.environ.get(
                PROFILE_RELEASE_BUILDER_DATABASE_ROLE_ENVIRONMENT_VARIABLE
            )
            if expected_builder is None or builder_session_user != expected_builder:
                raise RuntimeError("profile release builder database role is invalid")
            builder_flags = connection.execute(
                text(
                    "SELECT rolcanlogin, rolinherit, rolsuper, rolcreatedb, "
                    "rolcreaterole, rolreplication, rolbypassrls "
                    "FROM pg_catalog.pg_roles WHERE rolname = :builder"
                ),
                {"builder": expected_builder},
            ).one_or_none()
            if builder_flags is None or tuple(bool(value) for value in builder_flags) != (
                True,
                False,
                False,
                False,
                False,
                False,
                False,
            ):
                raise RuntimeError("profile release builder database role flags are unsafe")
            related = connection.execute(
                text(
                    "SELECT pg_catalog.pg_has_role(:builder, :owner, 'MEMBER'), "
                    "pg_catalog.pg_has_role(:owner, :builder, 'MEMBER'), "
                    "pg_catalog.pg_has_role(:builder, :service, 'MEMBER'), "
                    "pg_catalog.pg_has_role(:service, :builder, 'MEMBER')"
                ),
                {
                    "builder": expected_builder,
                    "owner": "itda_profile_release_write_authority",
                    "service": "itda_profile_release_authority_service",
                },
            ).one()
            if any(bool(value) for value in related):
                raise RuntimeError("profile release builder database role membership is unsafe")
        if builder_session_user == authority_session_user:
            raise RuntimeError("profile release authority connection reuses builder role")
        return EvaluationRepository(
            create_session_factory(engine),
            authority_connection_factory=create_session_factory(authority_engine),
        )
    except Exception:
        authority_engine.dispose()
        engine.dispose()
        raise


def get_evaluation_repository(
    principal: Annotated[Phase3Principal, Depends(get_phase3_principal)],
) -> EvaluationRepository:
    dsn = os.environ.get(_PHASE3_DATABASE_ENVIRONMENTS[principal.role])
    if not dsn:
        raise RuntimeError("Phase 3 database capability is not configured")
    authority_dsn = None
    if principal.role == "builder":
        authority_dsn = os.environ.get(PROFILE_RELEASE_AUTHORITY_DATABASE_URL_ENVIRONMENT_VARIABLE)
        if not authority_dsn:
            raise RuntimeError("profile release authority database capability is not configured")
    return _evaluation_repository_for_dsn(dsn, authority_dsn)


@lru_cache(maxsize=4)
def _profile_repository_for_dsn(dsn: str) -> ProfileRepository:
    engine = create_database_engine(dsn)
    return ProfileRepository(create_session_factory(engine))


def get_profile_repository() -> ProfileRepository:
    dsn = os.environ.get(DATABASE_URL_ENVIRONMENT_VARIABLE)
    if not dsn:
        raise RuntimeError(
            f"{DATABASE_URL_ENVIRONMENT_VARIABLE} must be set for database-backed requests"
        )
    return _profile_repository_for_dsn(dsn)


def get_preference_service(
    repository: Annotated[ProfileRepository, Depends(get_profile_repository)],
) -> PreferenceService:
    return PreferenceService(repository)


@lru_cache(maxsize=4)
def _daily_release_overlay_reader_for_dsn(dsn: str) -> DailyReleaseOverlayReader:
    engine = create_database_engine(dsn)
    return DailyReleaseOverlayReader(create_session_factory(engine))


def get_daily_release_overlay_reader() -> DailyReleaseOverlayReader:
    dsn = os.environ.get(DATABASE_URL_ENVIRONMENT_VARIABLE)
    if not dsn:
        raise RuntimeError(
            f"{DATABASE_URL_ENVIRONMENT_VARIABLE} must be set for database-backed requests"
        )
    return _daily_release_overlay_reader_for_dsn(dsn)


def _operating_information_service() -> OperatingInformationService | None:
    enabled = os.environ.get("ITDA_OPERATING_INFORMATION_ENABLED", "").strip().casefold()
    if enabled not in {"1", "true", "yes", "on"}:
        return None
    require_live_collection_allowed(explicit_opt_in=True)
    credential_path = os.environ.get("ITDA_TOUR_API_SERVICE_KEY_FILE")
    credential = (
        Path(credential_path).read_text(encoding="utf-8").strip()
        if credential_path
        else os.environ.get("TOUR_API_SERVICE_KEY", "").strip()
    )
    if not credential:
        return None
    catalog_path = Path(
        os.environ.get(
            "ITDA_PUBLIC_PLACE_CATALOG_PATH",
            "artifacts/public/catalog/public-place-catalog-v1.json",
        )
    )
    timeout_seconds = float(os.environ.get("ITDA_OPERATING_INFORMATION_TIMEOUT_SECONDS", "1.5"))
    return OperatingInformationService(
        catalog=PublicCatalogLookup(catalog_path=catalog_path),
        provider=TourApiOperatingProvider(
            service_key=credential,
            timeout_seconds=timeout_seconds,
        ),
        ttl_seconds=float(os.environ.get("ITDA_OPERATING_INFORMATION_TTL_SECONDS", "900")),
        negative_ttl_seconds=float(
            os.environ.get("ITDA_OPERATING_INFORMATION_NEGATIVE_TTL_SECONDS", "120")
        ),
    )


@lru_cache(maxsize=4)
def _recommendation_service_for_dsn(
    dsn: str,
    photo_service_dsn: str | None = None,
) -> RecommendationService:
    engine = create_database_engine(dsn)
    factory = create_session_factory(engine)
    photo_reader = None
    if photo_service_dsn is not None:
        photo_engine = create_database_engine(photo_service_dsn)
        photo_reader = PhotoRecommendationProjectionReader(
            create_session_factory(photo_engine)
        )
    release_resolver = ActiveReleaseOverlayResolver(
        overlay_reader=DailyReleaseOverlayReader(factory),
        bundled_resolver=resolve_active_mvp_scored_release,
    )
    return RecommendationService(
        profile_repository=ProfileRepository(factory),
        recommendation_repository=RecommendationRunRepository(factory),
        release_resolver=release_resolver,
        photo_projection_reader=photo_reader,
        operating_information_service=_operating_information_service(),
    )


def get_recommendation_service() -> RecommendationService:
    dsn = os.environ.get(DATABASE_URL_ENVIRONMENT_VARIABLE)
    if not dsn:
        raise RuntimeError(
            f"{DATABASE_URL_ENVIRONMENT_VARIABLE} must be set for database-backed requests"
        )
    return _recommendation_service_for_dsn(
        dsn,
        os.environ.get(PHOTO_SERVICE_DATABASE_URL_ENVIRONMENT_VARIABLE),
    )
