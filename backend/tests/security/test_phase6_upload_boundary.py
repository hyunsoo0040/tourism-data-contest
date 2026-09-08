"""Controlled-RED Phase 6 streaming upload and consent boundary contract.

Wave 0 (Plan 06-02): every test below freezes behavior for the planned
``PUT /v1/photo-jobs/{job_id}/images/{image_index}`` raw streaming boundary
before any production owner exists.  Owners are imported inside the tests so
collection always succeeds and execution fails only because the planned Phase 6
owners are absent:

- ``itda.api.routes.photo`` (Plan 06-08) — raw streaming route contract.
- ``itda.photo.quarantine`` (Plan 06-05) — bounded chunk accumulator contract.

Frozen contract (Wave 0 authority for Plans 06-05 and 06-08):

- ``QuarantinePolicy.max_image_bytes == 10 MiB``; nonempty enforcement; one
  explicit cumulative per-job aggregate byte bound no larger than three images.
- ``await stream_to_quarantine(root_fd=..., job_directory=..., image_index=...,
  chunks=..., policy=..., declared_byte_length=...) -> QuarantinedImage``.
  binding_claim_created=True,
  ``declared_byte_length`` is the advisory Content-Length handoff: it is an
  early-rejection optimization only, and the accumulated byte cap is enforced
  independently before each chunk is appended.  Iteration stops at the first
  cap-crossing (or declared-length-crossing) chunk and the remaining tail is
  never materialized.  ``QuarantinedImage.stored_name`` is a generated 32-hex
  identity unrelated to any input; ``byte_length`` records the stored size.
- The route declares operation_id ``put_photo_job_image`` on path
  ``/v1/photo-jobs/{job_id}/images/{image_index}`` with contract-visible
  ``image_index`` bounds 1..3, consumes ``request.stream()`` only, never
  materializes the body via ``request.body()``/``request.form()`` or
  ``UploadFile``/``File``/``Form``, and keeps filenames out of the request
  contract entirely.
- Consent, count, profile-ownership, and rate gates precede stream iteration:
  any gate failure maps to one closed public reason code plus a bounded Korean
  message with zero chunks consumed.
- Public rejections never reflect input markers, header values, or paths.

No production source, dependency, lock, provider client, credential, or network
traffic is touched by this module.
"""

from __future__ import annotations

import ast
import asyncio
import errno
import importlib
import inspect
import json
import os
import re
import secrets
import stat as stat_module
import sys
from collections.abc import AsyncIterator, Mapping
from types import ModuleType, SimpleNamespace
from typing import Annotated, Any, NoReturn, get_args, get_origin

import pytest
from fastapi import Depends, FastAPI, HTTPException, Request
from starlette.responses import Response

MIIB = 1024 * 1024
UPLOAD_MARKER = "phase6-upload-marker-7f3a9c"
ROUTE_MODULE = "itda.api.routes.photo"
QUARANTINE_MODULE = "itda.photo.quarantine"
UPLOAD_ROUTE_PATH = "/v1/photo-jobs/{job_id}/images/{image_index}"
UPLOAD_OPERATION_ID = "put_photo_job_image"
JOB_ID = "job-9f2c-opaque-7c31"
_DETAIL_KEYS = frozenset({"code", "message_ko", "request_id", "job_id", "preference_profile_id"})


@pytest.fixture
def phase6_origin(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("ITDA_CANONICAL_APP_ORIGIN", "https://app.test")


def _phase6_owner(module_name: str) -> ModuleType:
    """Import one planned Phase 6 owner or fail with the controlled-RED reason."""

    try:
        return importlib.import_module(module_name)
    except ImportError as error:
        pytest.fail(
            "controlled RED: planned Phase 6 photo upload owner is absent: "
            f"{module_name} ({error}). Implement the Plan 06-05/06-08 owners "
            "before this streaming boundary contract can proceed.",
            pytrace=False,
        )


def _require(condition: object, message: str) -> None:
    if not condition:
        pytest.fail(f"phase6 upload boundary contract violated: {message}", pytrace=False)


def _require_attribute(owner: object, attribute: str, description: str) -> Any:
    if not hasattr(owner, attribute):
        pytest.fail(
            "phase6 upload boundary contract violated: planned owner attribute is "
            f"absent: {description}.{attribute}",
            pytrace=False,
        )
    return getattr(owner, attribute)


def _root_descriptor(root: object) -> int:
    return os.open(
        root,  # type: ignore[arg-type]
        os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_CLOEXEC", 0),
    )


def _job_entries(root: object, job_directory: str) -> list[str]:
    try:
        return sorted(
            entry
            for entry in os.listdir(os.path.join(str(root), job_directory))
            if entry != ".itda-owner-v1"
        )
    except FileNotFoundError:
        return []


class _RecordedChunks:
    """Async chunk source that records exactly how much of the stream was read."""

    def __init__(self, chunks: list[bytes]) -> None:
        self._chunks = chunks
        self.requested = 0

    @property
    def consumed_chunks(self) -> int:
        return self.requested

    @property
    def unread_chunks(self) -> int:
        return len(self._chunks) - self.requested

    async def __aiter__(self) -> AsyncIterator[bytes]:
        for chunk in self._chunks:
            self.requested += 1
            yield chunk


class _HostileUploadRequest:
    """Synthetic Starlette-shaped request with body-materialization traps."""

    def __init__(self, *, content_length: str | None, chunks: list[bytes]) -> None:
        self.headers = (
            {"origin": "https://app.test", "sec-fetch-site": "same-origin"}
            if content_length is None
            else {
                "content-length": content_length,
                "origin": "https://app.test",
                "sec-fetch-site": "same-origin",
            }
        )
        self.method = "PUT"
        self.url = SimpleNamespace(path=UPLOAD_ROUTE_PATH)
        self.client = SimpleNamespace(host="127.0.0.1")
        self.cookies = {}
        self._chunks = chunks
        self.requested = 0

    @property
    def consumed_chunks(self) -> int:
        return self.requested

    @property
    def unread_chunks(self) -> int:
        return len(self._chunks) - self.requested

    async def stream(self) -> AsyncIterator[bytes]:
        for chunk in self._chunks:
            self.requested += 1
            yield chunk

    async def body(self) -> bytes:
        raise AssertionError("unbounded request.body() materialization is forbidden")

    async def form(self) -> None:
        raise AssertionError("multipart request.form() materialization is forbidden")


class _DenyingPhotoService:
    """Every service interaction denies, before the upload stream is iterated."""

    def __getattr__(self, name: str) -> Any:
        async def _deny(*_args: object, **_kwargs: object) -> NoReturn:
            raise PermissionError("synthetic phase6 ownership gate denial")

        return _deny


def _marked_chunk(index: int, size: int) -> bytes:
    body = (UPLOAD_MARKER.encode() + f"-{index:04d}-".encode()) * max(1, size // 32)
    return body[:size]


def _resolve_upload_endpoint(module: ModuleType) -> Any:
    router = _require_attribute(module, "router", ROUTE_MODULE)
    matches = [
        route
        for route in getattr(router, "routes", [])
        if getattr(route, "path", "") == UPLOAD_ROUTE_PATH
        and "PUT" in set(getattr(route, "methods", ()) or ())
    ]
    _require(
        len(matches) == 1,
        f"exactly one PUT route must exist at {UPLOAD_ROUTE_PATH}",
    )
    endpoint = getattr(matches[0], "endpoint", None)
    _require(
        inspect.iscoroutinefunction(endpoint),
        "the streaming upload endpoint must be an async def handler",
    )
    _require(
        getattr(matches[0], "operation_id", None) == UPLOAD_OPERATION_ID,
        f"upload route must declare operation_id {UPLOAD_OPERATION_ID!r}",
    )
    return endpoint


def _is_request_annotation(annotation: object) -> bool:
    if isinstance(annotation, str) or annotation is inspect.Parameter.empty:
        return False
    return isinstance(annotation, type) and issubclass(annotation, Request)


def _annotation_parts(annotation: object) -> tuple[object, tuple[object, ...]]:
    if get_origin(annotation) is Annotated:
        args = get_args(annotation)
        return args[0], tuple(args[1:])
    return annotation, ()


async def _call_put_photo_image(
    module: ModuleType,
    *,
    job_id: str,
    image_index: int,
    request: _HostileUploadRequest,
) -> object:
    endpoint = _resolve_upload_endpoint(module)
    kwargs: dict[str, object] = {}
    for name, parameter in inspect.signature(endpoint, eval_str=True).parameters.items():
        if parameter.kind in (parameter.VAR_POSITIONAL, parameter.VAR_KEYWORD):
            continue
        base_annotation, extras = _annotation_parts(parameter.annotation)
        if name == "job_id":
            kwargs[name] = job_id
        elif name == "image_index":
            kwargs[name] = image_index
        elif _is_request_annotation(base_annotation) or name == "request":
            kwargs[name] = request
        elif isinstance(parameter.default, Depends) or any(
            isinstance(extra, Depends) for extra in extras
        ):
            kwargs[name] = _DenyingPhotoService()
        elif parameter.default is not inspect.Parameter.empty:
            kwargs[name] = parameter.default
        else:
            pytest.fail(
                "phase6 upload boundary contract violated: endpoint parameter "
                f"{name!r} is not composable from path values, the request, or "
                "dependency injection",
                pytrace=False,
            )
    return await endpoint(**kwargs)


def _extract_rejection(outcome: object) -> tuple[int, Mapping[str, object]]:
    if isinstance(outcome, HTTPException):
        detail = outcome.detail
        status_code = outcome.status_code
    elif isinstance(outcome, Response):
        status_code = outcome.status_code
        try:
            detail = json.loads(bytes(outcome.body))
        except (ValueError, AttributeError) as error:
            pytest.fail(
                "phase6 upload boundary contract violated: rejection response body "
                f"is not bounded JSON ({error})",
                pytrace=False,
            )
    else:
        pytest.fail(
            "phase6 upload boundary contract violated: upload endpoint must raise "
            "HTTPException or return a bounded Response; got "
            f"{type(outcome).__name__}",
            pytrace=False,
        )
    if not isinstance(detail, Mapping):
        pytest.fail(
            "phase6 upload boundary contract violated: rejection detail must be a "
            "bounded object, not raw text",
            pytrace=False,
        )
    return status_code, detail


def _assert_closed_public_rejection(
    status_code: int,
    detail: Mapping[str, object],
    *,
    allow_internal_mapping: bool,
    case: str,
) -> None:
    upper_bound = 599 if allow_internal_mapping else 499
    _require(
        isinstance(status_code, int) and 400 <= status_code <= upper_bound,
        f"{case}: rejection must be an HTTP 4xx"
        + (" or mapped 5xx" if allow_internal_mapping else "")
        + f" status; got {status_code}",
    )
    _require(
        set(detail) <= _DETAIL_KEYS,
        f"{case}: rejection detail keys {sorted(detail)} exceed the closed public set",
    )
    _require(
        {"code", "message_ko"} <= set(detail),
        f"{case}: rejection detail must expose code and message_ko",
    )
    code = detail["code"]
    message_ko = detail["message_ko"]
    _require(
        isinstance(code, str) and re.fullmatch(r"[A-Z][A-Z0-9_]*", code) is not None,
        f"{case}: rejection code must be one closed UPPER_SNAKE reason, got {code!r}",
    )
    _require(
        isinstance(message_ko, str) and any("가" <= character <= "힣" for character in message_ko),
        f"{case}: rejection message_ko must be a bounded Korean message",
    )
    serialized = json.dumps(detail, default=str)
    _require(len(serialized) <= 1000, f"{case}: rejection detail must stay bounded")
    _require(
        UPLOAD_MARKER not in serialized,
        f"{case}: rejection detail must not reflect uploaded byte markers",
    )


async def _store_via_quarantine(
    module: ModuleType,
    *,
    root_fd: int,
    job_directory: str,
    profile_id: str = "profile-quarantine-test",
    image_index: int,
    chunks: list[bytes],
    declared_byte_length: int | None = None,
) -> Any:
    policy = module.QuarantinePolicy()
    stream = _RecordedChunks(chunks)
    return await module.stream_to_quarantine(
        root_fd=root_fd,
        job_directory=job_directory,
        profile_id=profile_id,
        image_index=image_index,
        chunks=stream,
        policy=policy,
        binding_claim_created=True,
        declared_byte_length=declared_byte_length,
    )


def test_streaming_put_route_owner_declares_contracted_operation() -> None:
    module = _phase6_owner(ROUTE_MODULE)
    _resolve_upload_endpoint(module)


def test_photo_routes_have_no_caller_selected_profile_authority() -> None:
    module = _phase6_owner(ROUTE_MODULE)
    source = inspect.getsource(module)
    _require(
        "X-ITDA-Preference-Profile" not in source
        and "x-itda-preference-profile" not in source
        and "PreferenceProfilePrincipal" not in source,
        "all photo ownership must come from the digest-backed cookie session",
    )
    _require(
        "get_profile_session" in source and "require_same_origin_mutation" in source,
        "photo routes must share cookie ownership and exact-origin mutation guards",
    )


def test_streaming_route_rejects_unbounded_body_materialization_paths() -> None:
    module = _phase6_owner(ROUTE_MODULE)
    source = inspect.getsource(module)
    tree = ast.parse(source)
    forbidden_names = {"UploadFile", "File", "Form"}
    forbidden_attributes = {"body", "form"}
    materializes_body = False
    streams_body = False
    for node in ast.walk(tree):
        if isinstance(node, ast.Name) and node.id in forbidden_names:
            materializes_body = True
        if isinstance(node, ast.Attribute) and node.attr in forbidden_attributes:
            materializes_body = True
        if isinstance(node, ast.Attribute) and node.attr == "stream":
            streams_body = True
    _require(
        not materializes_body,
        "route module must never reference UploadFile/File/Form or request.body()/"
        "request.form() materialization",
    )
    _require(streams_body, "route module must consume request.stream() chunks")
    _require(
        "filename" not in source.casefold(),
        "filenames must stay absent from the upload request contract and responses",
    )


def test_route_contract_declares_index_bounds_and_non_multipart_request() -> None:
    module = _phase6_owner(ROUTE_MODULE)
    application = FastAPI()
    application.include_router(module.router)
    schema = application.openapi()
    operation = schema.get("paths", {}).get(UPLOAD_ROUTE_PATH, {}).get("put")
    _require(operation is not None, f"OpenAPI must publish PUT {UPLOAD_ROUTE_PATH}")
    parameters = operation.get("parameters", [])  # type: ignore[union-attr]
    index_parameters = [
        parameter
        for parameter in parameters
        if parameter.get("name") == "image_index" and parameter.get("in") == "path"
    ]
    _require(
        len(index_parameters) == 1,
        "image_index path parameter must be declared exactly once",
    )
    index_schema = index_parameters[0].get("schema", {})
    _require(
        index_schema.get("minimum") == 1 and index_schema.get("maximum") == 3,
        "image_index bounds 1..3 must be visible in the published contract",
    )
    request_body = operation.get("requestBody")  # type: ignore[union-attr]
    if request_body is not None:
        for media in request_body.get("content", {}):
            _require(
                "multipart" not in media.casefold(),
                "multipart request bodies are forbidden at the upload boundary",
            )


@pytest.mark.parametrize(
    ("case", "content_length", "chunk_count", "chunk_size"),
    (
        ("missing", None, 2, 64),
        ("malformed_text", "many", 2, 64),
        ("malformed_float", "10.5", 2, 64),
        ("negative", "-5", 2, 64),
        ("oversized", str(10 * MIIB + 1), 2, 64),
        ("zero_declared", "0", 0, 0),
    ),
)
@pytest.mark.asyncio
@pytest.mark.usefixtures("phase6_origin")
async def test_content_length_hostility_is_rejected_before_stream_iteration(
    case: str, content_length: str | None, chunk_count: int, chunk_size: int
) -> None:
    module = _phase6_owner(ROUTE_MODULE)
    chunks = [_marked_chunk(index, chunk_size) for index in range(chunk_count)]
    request = _HostileUploadRequest(content_length=content_length, chunks=chunks)
    outcome = await _call_put_photo_image(
        module,
        job_id=JOB_ID,
        image_index=1,
        request=request,
    )
    status_code, detail = _extract_rejection(outcome)
    _assert_closed_public_rejection(
        status_code,
        detail,
        allow_internal_mapping=False,
        case=f"content-length:{case}",
    )
    _require(
        request.consumed_chunks == 0,
        f"{case}: declared-length rejection must precede stream iteration",
    )


@pytest.mark.asyncio
@pytest.mark.usefixtures("phase6_origin")
async def test_consent_and_ownership_gates_precede_stream_iteration() -> None:
    module = _phase6_owner(ROUTE_MODULE)
    chunks = [_marked_chunk(1, 128), _marked_chunk(2, 128)]
    request = _HostileUploadRequest(
        content_length=str(sum(len(chunk) for chunk in chunks)),
        chunks=chunks,
    )
    outcome = await _call_put_photo_image(
        module,
        job_id=JOB_ID,
        image_index=1,
        request=request,
    )
    status_code, detail = _extract_rejection(outcome)
    _assert_closed_public_rejection(
        status_code,
        detail,
        allow_internal_mapping=True,
        case="gate-denial",
    )
    _require(
        "denial" not in json.dumps(detail, default=str).casefold(),
        "gate denial must map to a closed public reason without internal text",
    )
    _require(
        request.consumed_chunks == 0 and request.unread_chunks == 2,
        "consent/ownership gates must reject before a single chunk is iterated",
    )


@pytest.mark.asyncio
@pytest.mark.usefixtures("phase6_origin")
async def test_index_bounds_are_enforced_without_iterating_the_stream() -> None:
    module = _phase6_owner(ROUTE_MODULE)
    chunks = [_marked_chunk(1, 64)]
    for image_index in (0, 4, -1, 99):
        request = _HostileUploadRequest(
            content_length=str(sum(len(chunk) for chunk in chunks)),
            chunks=list(chunks),
        )
        outcome = await _call_put_photo_image(
            module,
            job_id=JOB_ID,
            image_index=image_index,
            request=request,
        )
        status_code, detail = _extract_rejection(outcome)
        _assert_closed_public_rejection(
            status_code,
            detail,
            allow_internal_mapping=False,
            case=f"image-index:{image_index}",
        )
        _require(
            request.consumed_chunks == 0,
            f"image_index {image_index}: out-of-bounds index must stop before iteration",
        )


@pytest.mark.asyncio
async def test_policy_declares_streaming_and_aggregate_byte_bounds(tmp_path) -> None:
    module = _phase6_owner(QUARANTINE_MODULE)
    policy = module.QuarantinePolicy()
    _require(
        getattr(policy, "max_image_bytes", None) == 10 * MIIB,
        "QuarantinePolicy.max_image_bytes must freeze the 10 MiB cumulative cap",
    )
    aggregate_fields = [
        field
        for field in getattr(policy, "__dataclass_fields__", {}).values()
        if re.search(r"job|aggregate|total|cumulative", field.name)
        and field.name.endswith(("bytes", "byte", "cap", "limit"))
    ]
    _require(
        len(aggregate_fields) == 1,
        "QuarantinePolicy must declare exactly one per-job aggregate byte bound",
    )
    aggregate_value = getattr(policy, aggregate_fields[0].name)
    _require(
        isinstance(aggregate_value, int) and 0 < aggregate_value <= 3 * 10 * MIIB,
        "aggregate job byte bound must be positive and no larger than three images",
    )
    try:
        policy.max_image_bytes = 1  # type: ignore[misc]
    except Exception:
        return
    pytest.fail(
        "phase6 upload boundary contract violated: QuarantinePolicy must be frozen",
        pytrace=False,
    )


@pytest.mark.asyncio
async def test_binding_rejections_precede_stream_consumption(tmp_path) -> None:
    module = _phase6_owner(QUARANTINE_MODULE)
    profile_id = "profile-preconsume"
    for binding_claim_created, binding_profile in (
        (True, None),
        (False, None),
        (False, "profile-foreign"),
    ):
        job_directory = secrets.token_hex(32)
        job_path = tmp_path / job_directory
        job_path.mkdir(mode=0o700)
        if binding_profile is not None:
            binding = job_path / ".itda-owner-v1"
            binding.write_text(f"{job_directory}\n{binding_profile}\n")
            binding.chmod(0o600)
        stream = _RecordedChunks([b"must-not-be-read"])
        root_fd = _root_descriptor(tmp_path)
        try:
            with pytest.raises(module.QuarantineError):
                await module.stream_to_quarantine(
                    root_fd=root_fd,
                    job_directory=job_directory,
                    profile_id=profile_id,
                    image_index=1,
                    chunks=stream,
                    policy=module.QuarantinePolicy(),
                    binding_claim_created=binding_claim_created,
                )
        finally:
            os.close(root_fd)
        assert stream.consumed_chunks == 0


@pytest.mark.asyncio
async def test_new_claim_failure_removes_binding_and_directory(tmp_path) -> None:
    module = _phase6_owner(QUARANTINE_MODULE)
    job_directory = secrets.token_hex(32)
    stream = _RecordedChunks([b"short"])
    root_fd = _root_descriptor(tmp_path)
    try:
        with pytest.raises(module.QuarantineError):
            await module.stream_to_quarantine(
                root_fd=root_fd,
                job_directory=job_directory,
                profile_id="profile-new-claim-rollback",
                image_index=1,
                chunks=stream,
                policy=module.QuarantinePolicy(),
                binding_claim_created=True,
                declared_byte_length=100,
            )
    finally:
        os.close(root_fd)
    assert not (tmp_path / job_directory).exists()


@pytest.mark.parametrize("case", ("symlink", "mode"))
def test_secure_root_open_rejects_hostile_authority(tmp_path, case: str) -> None:
    module = _phase6_owner(QUARANTINE_MODULE)
    real_root = tmp_path / "real-root"
    real_root.mkdir(mode=0o700)
    candidate = real_root
    if case == "symlink":
        candidate = tmp_path / "linked-root"
        candidate.symlink_to(real_root, target_is_directory=True)
    else:
        real_root.chmod(0o750)
    with pytest.raises(module.QuarantineError):
        module.open_quarantine_root(candidate)


@pytest.mark.asyncio
async def test_zero_byte_stream_is_rejected_without_writing(tmp_path) -> None:
    module = _phase6_owner(QUARANTINE_MODULE)
    job_directory = secrets.token_hex(32)
    root_fd = _root_descriptor(tmp_path)
    try:
        with pytest.raises(module.QuarantineError):
            await _store_via_quarantine(
                module,
                root_fd=root_fd,
                job_directory=job_directory,
                profile_id="profile-quarantine-test",
                image_index=1,
                chunks=[],
                declared_byte_length=0,
            )
    finally:
        os.close(root_fd)
    _require(
        _job_entries(tmp_path, job_directory) == [],
        "zero-byte uploads must leave no partial quarantine residue",
    )


@pytest.mark.asyncio
async def test_cap_crossing_chunk_stops_iteration_and_tail_stays_unread(tmp_path) -> None:
    module = _phase6_owner(QUARANTINE_MODULE)
    job_directory = secrets.token_hex(32)
    chunks = [bytes([0xA0 + (index % 16)]) * MIIB for index in range(11)]
    tail_marker = (UPLOAD_MARKER.encode() * (MIIB // len(UPLOAD_MARKER) + 1))[:MIIB]
    chunks.append(tail_marker)
    stream = _RecordedChunks(chunks)
    root_fd = _root_descriptor(tmp_path)
    try:
        with pytest.raises(module.QuarantineError) as captured:
            await module.stream_to_quarantine(
                root_fd=root_fd,
                job_directory=job_directory,
                profile_id="profile-quarantine-test",
                image_index=1,
                chunks=stream,
                policy=module.QuarantinePolicy(),
                binding_claim_created=True,
                declared_byte_length=None,
            )
    finally:
        os.close(root_fd)

    _require(
        stream.consumed_chunks == 11,
        "iteration must stop at the first cap-crossing chunk (10 MiB crossed)",
    )
    _require(
        stream.unread_chunks == 1,
        "the tail chunk after the cap crossing must remain unread",
    )
    error_text = f"{captured.value!s} {captured.value!r} {captured.value.args!r}"
    _require(
        UPLOAD_MARKER not in error_text,
        "overflow errors must never reflect streamed byte markers",
    )
    _require(
        _job_entries(tmp_path, job_directory) == [],
        "cap overflow must remove partial quarantine residue",
    )


@pytest.mark.asyncio
async def test_empty_chunk_sequence_is_rejected_as_zero_residue(tmp_path) -> None:
    module = _phase6_owner(QUARANTINE_MODULE)
    job_directory = secrets.token_hex(32)
    root_fd = _root_descriptor(tmp_path)
    try:
        with pytest.raises(module.QuarantineError) as captured:
            await module.stream_to_quarantine(
                root_fd=root_fd,
                job_directory=job_directory,
                profile_id="profile-empty-chunk",
                image_index=1,
                chunks=_RecordedChunks([b""]),
                policy=module.QuarantinePolicy(),
                binding_claim_created=True,
            )
    finally:
        os.close(root_fd)
    _require(captured.value.reason == "QUARANTINE_EMPTY_STREAM", "empty chunk reason")
    _require(_job_entries(tmp_path, job_directory) == [], "empty chunk residue must be zero")
    _require(not (tmp_path / job_directory).exists(), "new empty upload directory must roll back")


@pytest.mark.asyncio
async def test_runtime_error_and_cancellation_remove_partial_and_preserve_original(
    tmp_path,
) -> None:
    module = _phase6_owner(QUARANTINE_MODULE)

    async def runtime_failure() -> AsyncIterator[bytes]:
        yield b"abc"
        raise RuntimeError("iterator failed")

    runtime_job = secrets.token_hex(32)
    root_fd = _root_descriptor(tmp_path)
    try:
        with pytest.raises(RuntimeError, match="iterator failed"):
            await module.stream_to_quarantine(
                root_fd=root_fd,
                job_directory=runtime_job,
                profile_id="profile-runtime-failure",
                image_index=1,
                chunks=runtime_failure(),
                policy=module.QuarantinePolicy(),
                binding_claim_created=True,
            )
    finally:
        os.close(root_fd)
    _require(not (tmp_path / runtime_job).exists(), "runtime failure must rollback new directory")

    ready = asyncio.Event()
    continue_stream = asyncio.Event()

    async def cancellable() -> AsyncIterator[bytes]:
        yield b"abc"
        ready.set()
        await continue_stream.wait()
        yield b"tail"

    cancel_job = secrets.token_hex(32)
    root_fd = _root_descriptor(tmp_path)
    task = asyncio.create_task(
        module.stream_to_quarantine(
            root_fd=root_fd,
            job_directory=cancel_job,
            profile_id="profile-cancelled",
            image_index=1,
            chunks=cancellable(),
            policy=module.QuarantinePolicy(),
            binding_claim_created=True,
        )
    )
    try:
        await ready.wait()
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task
    finally:
        os.close(root_fd)
    _require(not (tmp_path / cancel_job).exists(), "cancellation must rollback new directory")


@pytest.mark.asyncio
@pytest.mark.parametrize("adversary", ("wrong_mode", "wrong_owner", "visible_substitution"))
async def test_existing_retry_directory_authority_rejects_before_stream(
    tmp_path, monkeypatch: pytest.MonkeyPatch, adversary: str
) -> None:
    module = _phase6_owner(QUARANTINE_MODULE)
    job_directory = secrets.token_hex(32)
    profile_id = "profile-retry-authority"
    job_path = tmp_path / job_directory
    job_path.mkdir(mode=0o700)
    binding = job_path / ".itda-owner-v1"
    binding.write_bytes(f"{job_directory}\n{profile_id}\n".encode())
    binding.chmod(0o600)
    if adversary == "wrong_mode":
        job_path.chmod(0o755)
    real_fstat = module.os.fstat
    real_stat = module.os.stat
    if adversary == "wrong_owner":
        calls = 0

        def wrong_owner(fd: int) -> object:
            nonlocal calls
            value = real_fstat(fd)
            calls += 1
            if calls >= 2 and stat_module.S_ISDIR(value.st_mode):
                fields = {
                    name: getattr(value, name) for name in dir(value) if name.startswith("st_")
                }
                fields["st_uid"] = value.st_uid + 1
                return SimpleNamespace(**fields)
            return value

        monkeypatch.setattr(module.os, "fstat", wrong_owner)
    elif adversary == "visible_substitution":

        def substituted(path: object, *args: object, **kwargs: object) -> object:
            value = real_stat(path, *args, **kwargs)
            if path == job_directory:
                fields = {
                    name: getattr(value, name) for name in dir(value) if name.startswith("st_")
                }
                fields["st_ino"] = value.st_ino + 1
                return SimpleNamespace(**fields)
            return value

        monkeypatch.setattr(module.os, "stat", substituted)
    stream = _RecordedChunks([b"abc"])
    root_fd = _root_descriptor(tmp_path)
    try:
        with pytest.raises(module.QuarantineError):
            await module.stream_to_quarantine(
                root_fd=root_fd,
                job_directory=job_directory,
                profile_id=profile_id,
                image_index=1,
                chunks=stream,
                policy=module.QuarantinePolicy(),
                binding_claim_created=False,
            )
    finally:
        os.close(root_fd)
    _require(stream.consumed_chunks == 0, "retry authority rejection must precede stream")
    _require(_job_entries(tmp_path, job_directory) == [], "retry rejection must not mutate FS")


@pytest.mark.asyncio
async def test_single_oversized_chunk_is_rejected_before_appending(tmp_path) -> None:
    module = _phase6_owner(QUARANTINE_MODULE)
    job_directory = secrets.token_hex(32)
    stream = _RecordedChunks([_marked_chunk(1, 10 * MIIB + 1)])
    root_fd = _root_descriptor(tmp_path)
    try:
        with pytest.raises(module.QuarantineError):
            await module.stream_to_quarantine(
                root_fd=root_fd,
                job_directory=job_directory,
                profile_id="profile-quarantine-test",
                image_index=1,
                chunks=stream,
                policy=module.QuarantinePolicy(),
                binding_claim_created=True,
            )
    finally:
        os.close(root_fd)
    _require(stream.consumed_chunks == 1, "the oversized chunk itself is consumed once")
    _require(
        _job_entries(tmp_path, job_directory) == [],
        "oversized single chunks must leave no partial file",
    )


@pytest.mark.asyncio
async def test_exact_cap_stream_is_stored_under_generated_identity(tmp_path) -> None:
    module = _phase6_owner(QUARANTINE_MODULE)
    job_directory = secrets.token_hex(32)
    chunks = [_marked_chunk(index, MIIB) for index in range(10)]
    stream = _RecordedChunks(chunks)
    root_fd = _root_descriptor(tmp_path)
    try:
        stored = await module.stream_to_quarantine(
            root_fd=root_fd,
            job_directory=job_directory,
            profile_id="profile-quarantine-test",
            image_index=1,
            chunks=stream,
            policy=module.QuarantinePolicy(),
            binding_claim_created=True,
        )
    finally:
        os.close(root_fd)

    _require(stream.consumed_chunks == 10 and stream.unread_chunks == 0, "cap-fit input")
    stored_name = _require_attribute(stored, "stored_name", "QuarantinedImage")
    _require(
        isinstance(stored_name, str) and re.fullmatch(r"[0-9a-f]{32}", stored_name),
        "stored_name must be a generated 32-hex identity unrelated to any input",
    )
    _require(stored_name != job_directory, "stored name must differ from the job name")
    byte_length = _require_attribute(stored, "byte_length", "QuarantinedImage")
    _require(
        byte_length == 10 * MIIB,
        "byte_length must record the exact stored size",
    )
    stored_path = os.path.join(str(tmp_path), job_directory, stored_name)
    stat_result = os.stat(stored_path)
    _require(
        stat_module.S_ISREG(stat_result.st_mode) and stat_result.st_size == 10 * MIIB,
        "the cap-fit upload must land as a regular file of exactly 10 MiB",
    )


@pytest.mark.asyncio
async def test_declared_length_mismatch_stops_at_first_violating_chunk(tmp_path) -> None:
    module = _phase6_owner(QUARANTINE_MODULE)
    job_directory = secrets.token_hex(32)
    over_declared = [_marked_chunk(index, 2) for index in range(50)]
    stream = _RecordedChunks(over_declared)
    root_fd = _root_descriptor(tmp_path)
    try:
        with pytest.raises(module.QuarantineError):
            await module.stream_to_quarantine(
                root_fd=root_fd,
                job_directory=job_directory,
                profile_id="profile-quarantine-test",
                image_index=1,
                chunks=stream,
                policy=module.QuarantinePolicy(),
                binding_claim_created=True,
                declared_byte_length=5,
            )
    finally:
        os.close(root_fd)
    _require(
        stream.consumed_chunks == 3,
        "declared mismatch must stop when cumulative bytes first cross the declaration",
    )
    _require(
        stream.unread_chunks == 47,
        "chunks beyond the cumulative declared-length crossing must remain unread",
    )
    _require(
        _job_entries(tmp_path, job_directory) == [],
        "declared-length mismatch must remove partial residue",
    )

    under_delivered_job = secrets.token_hex(32)
    under_stream = _RecordedChunks([_marked_chunk(index, 1) for index in range(5)])
    root_fd = _root_descriptor(tmp_path)
    try:
        with pytest.raises(module.QuarantineError):
            await module.stream_to_quarantine(
                root_fd=root_fd,
                job_directory=under_delivered_job,
                profile_id="profile-quarantine-test",
                image_index=1,
                chunks=under_stream,
                policy=module.QuarantinePolicy(),
                binding_claim_created=True,
                declared_byte_length=100,
            )
    finally:
        os.close(root_fd)
    _require(
        under_stream.consumed_chunks == 5 and under_stream.unread_chunks == 0,
        "an exhausted short stream is fully read before the mismatch is raised",
    )
    _require(
        _job_entries(tmp_path, under_delivered_job) == [],
        "short-delivery mismatch must remove partial residue",
    )


@pytest.mark.asyncio
async def test_aggregate_job_byte_cap_and_duplicate_index_are_enforced(tmp_path) -> None:
    module = _phase6_owner(QUARANTINE_MODULE)
    policy = module.QuarantinePolicy()
    aggregate_fields = [
        field
        for field in getattr(policy, "__dataclass_fields__", {}).values()
        if re.search(r"job|aggregate|total|cumulative", field.name)
        and field.name.endswith(("bytes", "byte", "cap", "limit"))
    ]
    _require(
        len(aggregate_fields) == 1,
        "aggregate byte bound must exist before the exhaustion contract runs",
    )
    aggregate_limit = getattr(policy, aggregate_fields[0].name)
    job_directory = secrets.token_hex(32)
    stored_names: list[str] = []
    root_fd = _root_descriptor(tmp_path)
    try:
        for image_index in (1, 2, 3):
            chunks = [_marked_chunk(index, MIIB) for index in range(10)]
            stored = await module.stream_to_quarantine(
                root_fd=root_fd,
                job_directory=job_directory,
                profile_id="profile-quarantine-test",
                image_index=image_index,
                chunks=_RecordedChunks(chunks),
                policy=policy,
                binding_claim_created=image_index == 1,
            )
            stored_names.append(str(stored.stored_name))
    finally:
        os.close(root_fd)
    _require(
        len(set(stored_names)) == 3,
        "three cap-fit uploads must store three distinct generated names",
    )

    fourth_job = secrets.token_hex(32)
    fourth_stream = _RecordedChunks([_marked_chunk(1, 64)])
    root_fd = _root_descriptor(tmp_path)
    try:
        with pytest.raises(module.QuarantineError):
            await module.stream_to_quarantine(
                root_fd=root_fd,
                job_directory=fourth_job,
                profile_id="profile-quarantine-test",
                image_index=4,
                chunks=fourth_stream,
                policy=policy,
                binding_claim_created=True,
            )
    finally:
        os.close(root_fd)
    _require(
        fourth_stream.consumed_chunks == 0,
        "the fourth image index must be rejected before stream iteration",
    )
    _require(
        _job_entries(tmp_path, fourth_job) == [],
        "fourth-index rejection must leave no residue",
    )

    duplicate_job = secrets.token_hex(32)
    duplicate_stream = _RecordedChunks([_marked_chunk(1, 64)])
    root_fd = _root_descriptor(tmp_path)
    try:
        with pytest.raises(module.QuarantineError):
            await module.stream_to_quarantine(
                root_fd=root_fd,
                job_directory=duplicate_job,
                profile_id="profile-quarantine-test",
                image_index=1,
                chunks=duplicate_stream,
                policy=policy,
                binding_claim_created=True,
            )
    finally:
        os.close(root_fd)
    _require(
        duplicate_stream.consumed_chunks == 0,
        "duplicate image index must be rejected before stream iteration",
    )
    _require(
        _job_entries(tmp_path, duplicate_job) == [],
        "duplicate-index rejection must leave no residue",
    )

    exhausted_job = secrets.token_hex(32)
    per_image = MIIB
    image_count = max(1, aggregate_limit // per_image)
    if aggregate_limit % per_image != 0:
        image_count += 1
    if image_count > 3:
        image_count = 4
    root_fd = _root_descriptor(tmp_path)
    try:
        for image_index in range(1, image_count + 1):
            chunks = [_marked_chunk(index, per_image) for index in range(10)]
            stream = _RecordedChunks(chunks)
            try:
                await module.stream_to_quarantine(
                    root_fd=root_fd,
                    job_directory=exhausted_job,
                    profile_id="profile-quarantine-test",
                    image_index=image_index,
                    chunks=stream,
                    policy=policy,
                    binding_claim_created=image_index == 1,
                )
            except module.QuarantineError:
                _require(
                    stream.consumed_chunks <= 1,
                    "aggregate exhaustion must reject before consuming further chunks",
                )
                break
        else:
            pytest.fail(
                "phase6 upload boundary contract violated: the aggregate job byte "
                "cap never rejected a fourth-image stream",
                pytrace=False,
            )
    finally:
        os.close(root_fd)
    _require(
        _job_entries(tmp_path, exhausted_job) == [],
        "aggregate-byte exhaustion must remove all partial residue",
    )


@pytest.mark.asyncio
async def test_f02_existing_children_are_validated_descriptor_relatively_before_second_chunk(
    tmp_path,
) -> None:
    """F-02: existing child accounting must open/fstat each child before consumption.

    Hostile state: one existing generated child whose visible no-follow stat
    is a regular singly-linked file but whose read-open is denied (mode 0000).
    The accounting must open the child descriptor-relatively and fail closed
    before the second stream chunk is consumed, and must not delete the
    pre-existing child it did not create.
    """

    module = _phase6_owner(QUARANTINE_MODULE)
    profile_id = "profile-f02-descriptor-child"
    job_directory = secrets.token_hex(32)
    job_path = tmp_path / job_directory
    job_path.mkdir(mode=0o700)
    f02_directory = getattr(os, "O_DIRECTORY", 0)
    f02_nofollow = getattr(os, "O_NOFOLLOW", 0)
    f02_cloexec = getattr(os, "O_CLOEXEC", 0)
    job_dir_fd = os.open(job_path, os.O_RDONLY | f02_directory | f02_nofollow | f02_cloexec)
    try:
        binding_fd = os.open(
            ".itda-owner-v1",
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | f02_nofollow | f02_cloexec,
            dir_fd=job_dir_fd,
            mode=0o600,
        )
        with os.fdopen(binding_fd, "wb") as binding:
            binding.write(f"{job_directory}\n{profile_id}\n".encode())
        hostile_child = secrets.token_hex(16)
        existing_fd = os.open(
            hostile_child,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | f02_nofollow | f02_cloexec,
            dir_fd=job_dir_fd,
            mode=0o600,
        )
        with os.fdopen(existing_fd, "wb") as handle:
            handle.write(b"x" * 16)
        os.chmod(job_path / hostile_child, 0o000)
    finally:
        os.close(job_dir_fd)

    stream = _RecordedChunks([b"first-chunk", b"second-chunk"])
    root_fd = _root_descriptor(tmp_path)
    try:
        with pytest.raises(module.QuarantineError):
            await module.stream_to_quarantine(
                root_fd=root_fd,
                job_directory=job_directory,
                profile_id=profile_id,
                image_index=2,
                chunks=stream,
                policy=module.QuarantinePolicy(),
                binding_claim_created=False,
                declared_byte_length=1000,
            )
    finally:
        os.close(root_fd)
    _require(
        stream.consumed_chunks == 0,
        "F-02: existing-child validation must reject before body consumption",
    )
    _require(
        hostile_child in _job_entries(tmp_path, job_directory),
        "F-02: rejection must not delete the pre-existing hostile child",
    )


@pytest.mark.asyncio
async def test_new_directory_initializes_exact_mode_under_restrictive_umask(tmp_path) -> None:
    module = _phase6_owner(QUARANTINE_MODULE)
    job_directory = secrets.token_hex(32)
    root_fd = _root_descriptor(tmp_path)
    previous = os.umask(0o177)
    try:
        stored = await module.stream_to_quarantine(
            root_fd=root_fd,
            job_directory=job_directory,
            profile_id="profile-restrictive-umask",
            image_index=1,
            chunks=_RecordedChunks([b"payload"]),
            policy=module.QuarantinePolicy(),
            binding_claim_created=True,
            declared_byte_length=7,
        )
    finally:
        os.umask(previous)
        os.close(root_fd)
    _require(
        stat_module.S_IMODE((tmp_path / job_directory).stat().st_mode) == 0o700,
        "new directory initialization must produce exact 0700 despite umask",
    )
    _require(
        (tmp_path / job_directory / stored.stored_name).is_file(),
        "restrictive umask upload must store the generated file",
    )


@pytest.mark.asyncio
async def test_corrupt_reserved_partial_rejects_before_stream_consumption(tmp_path) -> None:
    module = _phase6_owner(QUARANTINE_MODULE)
    job_directory = secrets.token_hex(32)
    profile_id = "profile-reserved-corrupt"
    stored_name = secrets.token_hex(16)
    job_path = tmp_path / job_directory
    job_path.mkdir(mode=0o700)
    job_fd = os.open(job_path, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
    try:
        binding_fd = os.open(
            ".itda-owner-v1",
            os.O_WRONLY | os.O_CREAT | os.O_EXCL,
            0o600,
            dir_fd=job_fd,
        )
        with os.fdopen(binding_fd, "wb") as binding:
            binding.write(f"{job_directory}\n{profile_id}\n".encode())
        partial_fd = os.open(
            stored_name,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL,
            0o600,
            dir_fd=job_fd,
        )
        os.close(partial_fd)
        os.chmod(job_path / stored_name, 0o644)
    finally:
        os.close(job_fd)
    stream = _RecordedChunks([b"must-not-be-read"])
    root_fd = _root_descriptor(tmp_path)
    try:
        with pytest.raises(module.QuarantineError):
            await module.stream_to_quarantine(
                root_fd=root_fd,
                job_directory=job_directory,
                profile_id=profile_id,
                image_index=1,
                chunks=stream,
                policy=module.QuarantinePolicy(),
                binding_claim_created=False,
                expected_stored_name=stored_name,
                resume_reserved=True,
            )
    finally:
        os.close(root_fd)
    _require(stream.consumed_chunks == 0, "corrupt reserved partial must reject pre-stream")


@pytest.mark.asyncio
async def test_rev12_post_mkdir_stat_failure_preserves_bound_retry_authority(
    tmp_path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A failed visible proof preserves bound state for one exact safe retry."""

    module = _phase6_owner(QUARANTINE_MODULE)
    job_directory = secrets.token_hex(32)
    profile_id = "profile-rev10-post-mkdir-stat"
    stream = _RecordedChunks([b"rev10-payload"])

    original_stat = os.stat
    armed = True

    def failing_stat(path: object, *args: object, **kwargs: object) -> object:
        if (
            armed
            and path == job_directory
            and kwargs.get("dir_fd") is not None
            and kwargs.get("follow_symlinks") is False
        ):
            raise OSError(errno.EIO, "post-mkdir visible authority check failed")
        return original_stat(path, *args, **kwargs)  # type: ignore[arg-type, return-value]

    # Preserve the descriptor-capability registry the way the F-02 probe of
    # record does: the proxy must remain a registered dir_fd-capable stat or
    # the module rejects for the wrong (platform) reason.
    monkeypatch.setattr(
        os,
        "supports_dir_fd",
        os.supports_dir_fd | {failing_stat},  # type: ignore[operator]
    )
    monkeypatch.setattr(os, "stat", failing_stat)

    root_fd = _root_descriptor(tmp_path)
    try:
        with pytest.raises(module.QuarantineError):
            await module.stream_to_quarantine(
                root_fd=root_fd,
                job_directory=job_directory,
                profile_id=profile_id,
                image_index=1,
                chunks=stream,
                policy=module.QuarantinePolicy(),
                binding_claim_created=True,
                declared_byte_length=len(b"rev10-payload"),
            )
    finally:
        os.close(root_fd)
    _require(
        stream.consumed_chunks == 0,
        "Rev10: post-mkdir authority failure must reject before body consumption",
    )
    job_path = tmp_path / job_directory
    _require(
        job_path.is_dir() and (job_path / ".itda-owner-v1").is_file(),
        "Rev12: failed visible rollback proof must preserve the bound directory",
    )
    _require(
        _job_entries(tmp_path, job_directory) == [],
        "Rev12: failed visible rollback proof must leave no image residue",
    )

    armed = False
    retry_stream = _RecordedChunks([b"rev10-payload"])
    root_fd = _root_descriptor(tmp_path)
    try:
        stored = await module.stream_to_quarantine(
            root_fd=root_fd,
            job_directory=job_directory,
            profile_id=profile_id,
            image_index=1,
            chunks=retry_stream,
            policy=module.QuarantinePolicy(),
            binding_claim_created=False,
            declared_byte_length=len(b"rev10-payload"),
        )
    finally:
        os.close(root_fd)
    _require(
        (tmp_path / job_directory / stored.stored_name).is_file(),
        "Rev12: the exact bound retry must store the payload",
    )


# ---------------------------------------------------------------------------
# Rev11: post-mkdir initial open failure and held-inode rollback proof
# ---------------------------------------------------------------------------


class _RestrictiveMkdir:
    def __init__(self) -> None:
        self._real_mkdir: Any = os.mkdir
        self._real_chmod: Any = os.chmod

    def __call__(self, path: object, mode: int = 0o777, *args: object, **kwargs: object) -> None:
        self._real_mkdir(path, mode, *args, **kwargs)
        self._real_chmod(
            path,
            0o600,
            dir_fd=kwargs.get("dir_fd"),
            follow_symlinks=False,
        )


class _FailingOpens:
    """Deterministic os.open seam: exact failure counts then real behavior.

    Registered in ``os.supports_dir_fd`` the way the F-02 probe of record
    does, so the capability gate accepts the seam as a dir_fd-capable open.
    """

    def __init__(self, failures: int, err: int) -> None:
        self._real_open: Any = os.open
        self._remaining = failures
        self._err = err
        self.dir_attempts = 0

    def __call__(self, path: object, flags: int, *args: object, **kwargs: object) -> int:
        uses_dir_fd = kwargs.get("dir_fd") is not None
        reads_directory = bool(getattr(os, "O_DIRECTORY", 0) & flags)
        if uses_dir_fd and reads_directory:
            self.dir_attempts += 1
            if self._remaining > 0:
                self._remaining -= 1
                raise OSError(self._err, "injected no-follow directory open failure")
        return self._real_open(path, flags, *args, **kwargs)


def _arm_open_seam(monkeypatch: pytest.MonkeyPatch, seam: _FailingOpens) -> None:
    monkeypatch.setattr(os, "supports_dir_fd", os.supports_dir_fd | {seam})
    monkeypatch.setattr(os, "open", seam)


@pytest.mark.asyncio
async def test_rev11_transient_post_mkdir_open_failure_rolls_back_strictly(
    tmp_path, monkeypatch: pytest.MonkeyPatch
) -> None:
    module = _phase6_owner(QUARANTINE_MODULE)
    job_directory = secrets.token_hex(32)
    profile_id = "profile-rev11-transient-open"
    stream = _RecordedChunks([b"rev11-payload"])
    seam = _FailingOpens(failures=1, err=errno.EIO)
    _arm_open_seam(monkeypatch, seam)
    root_fd = _root_descriptor(tmp_path)
    try:
        with pytest.raises(module.QuarantineError):
            await module.stream_to_quarantine(
                root_fd=root_fd,
                job_directory=job_directory,
                profile_id=profile_id,
                image_index=1,
                chunks=stream,
                policy=module.QuarantinePolicy(),
                binding_claim_created=True,
                declared_byte_length=len(b"rev11-payload"),
            )
    finally:
        os.close(root_fd)
    _require(seam.dir_attempts >= 1, "Rev11: the seam must see the initial open")
    _require(
        not (tmp_path / job_directory).exists(),
        "Rev11: a transient post-mkdir open failure must strictly roll back the "
        "newly created directory",
    )
    retry_stream = _RecordedChunks([b"rev11-payload"])
    root_fd = _root_descriptor(tmp_path)
    try:
        stored = await module.stream_to_quarantine(
            root_fd=root_fd,
            job_directory=job_directory,
            profile_id=profile_id,
            image_index=1,
            chunks=retry_stream,
            policy=module.QuarantinePolicy(),
            binding_claim_created=True,
            declared_byte_length=len(b"rev11-payload"),
        )
    finally:
        os.close(root_fd)
    _require(
        (tmp_path / job_directory / stored.stored_name).is_file(),
        "Rev11: a transient failure must leave the exact retry free to rematerialize",
    )


@pytest.mark.asyncio
async def test_rev12_restrictive_creation_and_persistent_open_converges_on_exact_retry(
    tmp_path, monkeypatch: pytest.MonkeyPatch
) -> None:
    module = _phase6_owner(QUARANTINE_MODULE)
    job_directory = secrets.token_hex(32)
    profile_id = "profile-rev12-restrictive-persistent"
    stored_name = secrets.token_hex(16)
    mkdir_seam = _RestrictiveMkdir()
    open_seam = _FailingOpens(failures=10**6, err=errno.EIO)
    monkeypatch.setattr(os, "supports_dir_fd", os.supports_dir_fd | {mkdir_seam, open_seam})
    monkeypatch.setattr(os, "mkdir", mkdir_seam)
    monkeypatch.setattr(os, "open", open_seam)
    root_fd = _root_descriptor(tmp_path)
    try:
        with pytest.raises(module.QuarantineError):
            await module.stream_to_quarantine(
                root_fd=root_fd,
                job_directory=job_directory,
                profile_id=profile_id,
                image_index=1,
                chunks=_RecordedChunks([b"rev12-payload"]),
                policy=module.QuarantinePolicy(),
                binding_claim_created=True,
                expected_stored_name=stored_name,
                declared_byte_length=len(b"rev12-payload"),
            )
    finally:
        os.close(root_fd)
        monkeypatch.undo()

    job_path = tmp_path / job_directory
    _require(job_path.is_dir(), "Rev12: persistent open failure preserves durable intent")
    _require(
        stat_module.S_IMODE(os.stat(job_path, follow_symlinks=False).st_mode) == 0o700,
        "Rev12: preserved restrictive-creation intent must be normalized to exact 0700",
    )
    _require(os.listdir(job_path) == [], "Rev12: preserved intent must remain unbound and empty")

    root_fd = _root_descriptor(tmp_path)
    try:
        stored = await module.stream_to_quarantine(
            root_fd=root_fd,
            job_directory=job_directory,
            profile_id=profile_id,
            image_index=1,
            chunks=_RecordedChunks([b"rev12-payload"]),
            policy=module.QuarantinePolicy(),
            binding_claim_created=False,
            expected_stored_name=stored_name,
            materialize_reserved_missing=True,
            declared_byte_length=len(b"rev12-payload"),
        )
    finally:
        os.close(root_fd)
    _require(
        stored.stored_name == stored_name and (job_path / stored_name).is_file(),
        "Rev12: exact retry must converge using the same durable slot identity",
    )


@pytest.mark.asyncio
async def test_rev12_creation_mode_normalization_failure_rolls_back_unsafe_directory(
    tmp_path, monkeypatch: pytest.MonkeyPatch
) -> None:
    module = _phase6_owner(QUARANTINE_MODULE)
    job_directory = secrets.token_hex(32)
    profile_id = "profile-rev12-normalize-failure"
    mkdir_seam = _RestrictiveMkdir()
    real_chmod: Any = os.chmod

    def failing_chmod(path: object, mode: int, *args: object, **kwargs: object) -> None:
        if path == job_directory and kwargs.get("dir_fd") is not None:
            raise OSError(errno.EIO, "injected normalization failure")
        real_chmod(path, mode, *args, **kwargs)

    monkeypatch.setattr(os, "supports_dir_fd", os.supports_dir_fd | {mkdir_seam})
    monkeypatch.setattr(os, "mkdir", mkdir_seam)
    monkeypatch.setattr(os, "chmod", failing_chmod)
    root_fd = _root_descriptor(tmp_path)
    try:
        with pytest.raises(module.QuarantineError):
            await module.stream_to_quarantine(
                root_fd=root_fd,
                job_directory=job_directory,
                profile_id=profile_id,
                image_index=1,
                chunks=_RecordedChunks([b"must-not-be-read"]),
                policy=module.QuarantinePolicy(),
                binding_claim_created=True,
                declared_byte_length=len(b"must-not-be-read"),
            )
    finally:
        os.close(root_fd)
        monkeypatch.undo()
    _require(
        not (tmp_path / job_directory).exists(),
        "Rev12: failed normalization must not preserve a wrong-mode durable intent",
    )


@pytest.mark.asyncio
async def test_rev11_persistent_post_mkdir_open_failure_preserves_durable_intent(
    tmp_path, monkeypatch: pytest.MonkeyPatch
) -> None:
    module = _phase6_owner(QUARANTINE_MODULE)
    job_directory = secrets.token_hex(32)
    profile_id = "profile-rev11-persistent-open"
    stream = _RecordedChunks([b"rev11-payload"])
    seam = _FailingOpens(failures=10**6, err=errno.EIO)
    _arm_open_seam(monkeypatch, seam)
    root_fd = _root_descriptor(tmp_path)
    try:
        with pytest.raises(module.QuarantineError):
            await module.stream_to_quarantine(
                root_fd=root_fd,
                job_directory=job_directory,
                profile_id=profile_id,
                image_index=1,
                chunks=stream,
                policy=module.QuarantinePolicy(),
                binding_claim_created=True,
                declared_byte_length=len(b"rev11-payload"),
            )
    finally:
        os.close(root_fd)
    monkeypatch.undo()
    visible = tmp_path / job_directory
    _require(
        visible.is_dir() and not visible.is_symlink(),
        "Rev11: a persistent open failure must keep the durable reserved intent "
        "(the created canonical directory) for the exact retry",
    )
    entries = sorted(entry for entry in os.listdir(visible))
    _require(
        entries == [],
        "Rev11: a persistent open failure must leave the canonical directory empty "
        "(an adoptable unbound empty dir) with no partial image bytes",
    )
    mode = stat_module.S_IMODE(os.stat(str(visible), follow_symlinks=False).st_mode)
    _require(
        mode == 0o700,
        "Rev11: the preserved canonical directory must stay exactly 0700",
    )
    retry_stream = _RecordedChunks([b"rev11-payload"])
    root_fd = _root_descriptor(tmp_path)
    try:
        stored = await module.stream_to_quarantine(
            root_fd=root_fd,
            job_directory=job_directory,
            profile_id=profile_id,
            image_index=1,
            chunks=retry_stream,
            policy=module.QuarantinePolicy(),
            binding_claim_created=False,
            materialize_reserved_missing=True,
            declared_byte_length=len(b"rev11-payload"),
        )
    finally:
        os.close(root_fd)
    _require(
        (visible / stored.stored_name).is_file(),
        "Rev11: the exact retry must adopt the empty unbound canonical directory",
    )


class _DirectorySwapSeam:
    """After the stored partial unlink during rollback, swap the directory.

    Renames the original held directory aside and plants an empty same-UID
    0700 substitute at the canonical name, so the rollback must prove the
    visible entry no longer matches the held inode and fail closed.
    """

    def __init__(self, root: object, job_directory: str) -> None:
        self._root = str(root)
        self._job_directory = job_directory
        self.armed = False
        self.real_unlink: Any = os.unlink
        self.held_path: str | None = None
        self.substitute_path: str | None = None

    def __call__(self, path: object, *args: object, **kwargs: object) -> None:
        name = path if isinstance(path, str) else str(path)
        if self.armed and name.endswith(".itda-owner-v1") and self.held_path is None:
            held = os.path.join(self._root, self._job_directory)
            substitute = os.path.join(self._root, "substitute-" + secrets.token_hex(8))
            os.mkdir(substitute, 0o700)
            os.chmod(substitute, 0o700)
            os.rename(held, substitute)
            os.mkdir(held, 0o700)
            os.chmod(held, 0o700)
            self.held_path = substitute
            self.substitute_path = held
            self.armed = False
        self.real_unlink(path, *args, **kwargs)


@pytest.mark.asyncio
async def test_rev11_directory_substitution_during_stream_rollback_fails_closed(
    tmp_path, monkeypatch: pytest.MonkeyPatch
) -> None:
    module = _phase6_owner(QUARANTINE_MODULE)
    job_directory = secrets.token_hex(32)
    profile_id = "profile-rev11-swap"
    first = b"rev11-payload"
    stream = _RecordedChunks([first, b"exceeds-the-declared-length"])
    seam = _DirectorySwapSeam(tmp_path, job_directory)
    seam.armed = True
    monkeypatch.setattr(os, "supports_dir_fd", os.supports_dir_fd | {seam})
    monkeypatch.setattr(os, "unlink", seam)
    root_fd = _root_descriptor(tmp_path)
    raised: object = None
    try:
        with pytest.raises(module.QuarantineError) as caught:
            await module.stream_to_quarantine(
                root_fd=root_fd,
                job_directory=job_directory,
                profile_id=profile_id,
                image_index=1,
                chunks=stream,
                policy=module.QuarantinePolicy(),
                binding_claim_created=True,
                declared_byte_length=len(first),
            )
        raised = caught.value
    finally:
        os.close(root_fd)
        monkeypatch.undo()
    _require(seam.held_path is not None, "Rev11: the seam must perform its swap")
    _require(raised is not None, "Rev11: rollback substitution must fail closed")
    _require(
        seam.substitute_path is not None and os.path.isdir(seam.substitute_path),
        "Rev11: the planted substitute must survive — it must never be rmdir-ed",
    )
    assert seam.held_path is not None
    held_st = os.stat(seam.held_path)
    _require(
        held_st.st_nlink >= 1,
        "Rev11: the renamed held original must survive for postcondition proof",
    )


class _RollbackVisibleStatFailureSeam:
    """Swap the held directory, then fail its rollback visible observation."""

    def __init__(self, root: object, job_directory: str, stat_errno: int) -> None:
        self._root = str(root)
        self._job_directory = job_directory
        self._stat_errno = stat_errno
        self.real_unlink: Any = os.unlink
        self.real_stat: Any = os.stat
        self.held_path: str | None = None
        self.substitute_path: str | None = None
        self.rmdir_targets: list[str] = []
        self.real_rmdir: Any = os.rmdir

    def unlink(self, path: object, *args: object, **kwargs: object) -> None:
        name = path if isinstance(path, str) else str(path)
        if name.endswith(".itda-owner-v1") and self.held_path is None:
            held = os.path.join(self._root, self._job_directory)
            moved = os.path.join(self._root, "held-" + secrets.token_hex(8))
            os.rename(held, moved)
            os.mkdir(held, 0o700)
            os.chmod(held, 0o700)
            self.held_path = moved
            self.substitute_path = held
        self.real_unlink(path, *args, **kwargs)

    def stat(self, path: object, *args: object, **kwargs: object) -> object:
        if (
            self.held_path is not None
            and path == self._job_directory
            and kwargs.get("dir_fd") is not None
            and kwargs.get("follow_symlinks") is False
        ):
            raise OSError(self._stat_errno, "injected rollback visible-stat failure")
        return self.real_stat(path, *args, **kwargs)  # type: ignore[arg-type, return-value]

    def rmdir(self, path: object, *args: object, **kwargs: object) -> None:
        self.rmdir_targets.append(str(path))
        self.real_rmdir(path, *args, **kwargs)


@pytest.mark.parametrize("stat_errno", (errno.EIO, errno.ENOENT))
@pytest.mark.asyncio
async def test_rev12_rollback_visible_stat_failure_never_removes_substitute(
    tmp_path, monkeypatch: pytest.MonkeyPatch, stat_errno: int
) -> None:
    module = _phase6_owner(QUARANTINE_MODULE)
    job_directory = secrets.token_hex(32)
    profile_id = f"profile-rev12-stat-{stat_errno}"
    first = b"rev12-payload"
    seam = _RollbackVisibleStatFailureSeam(tmp_path, job_directory, stat_errno)
    monkeypatch.setattr(os, "supports_dir_fd", os.supports_dir_fd | {seam.unlink, seam.stat})
    monkeypatch.setattr(os, "unlink", seam.unlink)
    monkeypatch.setattr(os, "stat", seam.stat)
    monkeypatch.setattr(os, "rmdir", seam.rmdir)
    root_fd = _root_descriptor(tmp_path)
    try:
        with pytest.raises(module.QuarantineError):
            await module.stream_to_quarantine(
                root_fd=root_fd,
                job_directory=job_directory,
                profile_id=profile_id,
                image_index=1,
                chunks=_RecordedChunks([first, b"declared-overflow"]),
                policy=module.QuarantinePolicy(),
                binding_claim_created=True,
                declared_byte_length=len(first),
            )
    finally:
        os.close(root_fd)
        monkeypatch.undo()
    _require(seam.held_path is not None, "Rev12: substitution seam must run")
    _require(
        seam.substitute_path is not None and os.path.isdir(seam.substitute_path),
        "Rev12: visible-stat failure must leave the canonical substitute untouched",
    )
    _require(
        job_directory not in seam.rmdir_targets,
        "Rev12: no pathname rmdir is allowed without successful visible observation",
    )
    assert seam.held_path is not None
    _require(
        os.stat(seam.held_path).st_nlink >= 1,
        "Rev12: the renamed held original must remain linked after fail-closed rollback",
    )


def _arm_post_rmdir_proof_seam(monkeypatch: pytest.MonkeyPatch, proof: dict[str, object]) -> None:
    """Record every fstat that runs after a dir_fd rmdir until close.

    The rollback's post-rmdir proof is an ``os.fstat(job_fd)`` whose result
    shows ``st_nlink == 0``: the rmdir severed the last name of the held
    directory. Recording fstats between the rmdir and the descriptor close
    observes that proof without reimplementing it.
    """

    real_rmdir: Any = os.rmdir
    real_fstat: Any = os.fstat
    real_close: Any = os.close

    def _rmdir(path: object, **kwargs: object) -> None:
        real_rmdir(path, **kwargs)
        if isinstance(kwargs.get("dir_fd"), int):
            proof["armed"] = True

    def _fstat(fd: int, **kwargs: object) -> object:
        result = real_fstat(fd, **kwargs)
        if proof.get("armed"):
            seen = proof.setdefault("nlinks", [])
            seen.append(int(result.st_nlink))  # type: ignore[union-attr]
        return result

    def _close(fd: int) -> None:
        proof["armed"] = False
        real_close(fd)

    monkeypatch.setattr(os, "rmdir", _rmdir)
    monkeypatch.setattr(os, "fstat", _fstat)
    monkeypatch.setattr(os, "close", _close)


def _assert_post_rmdir_proof(proof: dict[str, object], case: str) -> None:
    nlinks = [int(value) for value in proof.get("nlinks", [])]  # type: ignore[union-attr]
    removed_nlink = 2 if sys.platform == "darwin" else 0
    _require(
        removed_nlink in nlinks,
        f"{case}: the rollback must prove the held directory reached the "
        "removed-directory nlink state (post-rmdir fstat on the held descriptor)",
    )


@pytest.mark.asyncio
async def test_rev11_validation_rollback_proves_held_directory_removed(
    tmp_path, monkeypatch: pytest.MonkeyPatch
) -> None:
    module = _phase6_owner(QUARANTINE_MODULE)
    job_directory = secrets.token_hex(32)
    profile_id = "profile-rev11-validation-nlink"
    stream = _RecordedChunks([b"rev11-first", b"rev11-excess-over-declared"])
    proof: dict[str, object] = {}
    _arm_post_rmdir_proof_seam(monkeypatch, proof)
    root_fd = _root_descriptor(tmp_path)
    try:
        with pytest.raises(module.QuarantineError):
            await module.stream_to_quarantine(
                root_fd=root_fd,
                job_directory=job_directory,
                profile_id=profile_id,
                image_index=1,
                chunks=stream,
                policy=module.QuarantinePolicy(),
                binding_claim_created=True,
                declared_byte_length=len(b"rev11-first"),
            )
    finally:
        os.close(root_fd)
        monkeypatch.undo()
    _require(
        not (tmp_path / job_directory).exists(),
        "Rev11: stream-validation rollback must remove the directory",
    )
    _assert_post_rmdir_proof(proof, "Rev11")


@pytest.mark.asyncio
async def test_rev11_base_exception_rollback_proves_held_directory_removed(
    tmp_path, monkeypatch: pytest.MonkeyPatch
) -> None:
    module = _phase6_owner(QUARANTINE_MODULE)
    job_directory = secrets.token_hex(32)
    profile_id = "profile-rev11-baseexception-nlink"

    class _ExplodingStream:
        async def __aiter__(self) -> AsyncIterator[bytes]:
            yield b"rev11-partial"
            raise KeyboardInterrupt("Rev11 cancellation probe")

    proof: dict[str, object] = {}
    _arm_post_rmdir_proof_seam(monkeypatch, proof)
    root_fd = _root_descriptor(tmp_path)
    try:
        with pytest.raises(KeyboardInterrupt):
            await module.stream_to_quarantine(
                root_fd=root_fd,
                job_directory=job_directory,
                profile_id=profile_id,
                image_index=1,
                chunks=_ExplodingStream(),
                policy=module.QuarantinePolicy(),
                binding_claim_created=True,
                declared_byte_length=4096,
            )
    finally:
        os.close(root_fd)
        monkeypatch.undo()
    _require(
        not (tmp_path / job_directory).exists(),
        "Rev11: BaseException rollback must remove the directory",
    )
    _assert_post_rmdir_proof(proof, "Rev11")


@pytest.mark.asyncio
async def test_rev12_first_chunk_aggregate_crossing_rejects_before_file_creation(
    tmp_path,
) -> None:
    module = _phase6_owner(QUARANTINE_MODULE)
    policy = module.QuarantinePolicy(max_image_bytes=8, max_job_total_bytes=10)
    job_directory = secrets.token_hex(32)
    profile_id = "profile-rev12-first-aggregate"
    job_path = tmp_path / job_directory
    job_path.mkdir(mode=0o700)
    binding = job_path / ".itda-owner-v1"
    binding.write_bytes(f"{job_directory}\n{profile_id}\n".encode())
    binding.chmod(0o600)
    existing_name = secrets.token_hex(16)
    existing = job_path / existing_name
    existing.write_bytes(b"12345678")
    existing.chmod(0o600)
    reserved_name = secrets.token_hex(16)
    crossing = _RecordedChunks([b"abc"])

    root_fd = _root_descriptor(tmp_path)
    try:
        with pytest.raises(module.QuarantineError):
            await module.stream_to_quarantine(
                root_fd=root_fd,
                job_directory=job_directory,
                profile_id=profile_id,
                image_index=2,
                chunks=crossing,
                policy=policy,
                binding_claim_created=False,
                expected_stored_name=reserved_name,
                declared_byte_length=3,
            )
    finally:
        os.close(root_fd)
    _require(crossing.consumed_chunks == 1, "Rev12: inspect only the crossing first chunk")
    _require(
        sorted(_job_entries(tmp_path, job_directory)) == [existing_name],
        "Rev12: aggregate first-chunk rejection must not create a new file",
    )

    root_fd = _root_descriptor(tmp_path)
    try:
        stored = await module.stream_to_quarantine(
            root_fd=root_fd,
            job_directory=job_directory,
            profile_id=profile_id,
            image_index=2,
            chunks=_RecordedChunks([b"ab"]),
            policy=policy,
            binding_claim_created=False,
            expected_stored_name=reserved_name,
            declared_byte_length=2,
        )
    finally:
        os.close(root_fd)
    _require(
        stored.stored_name == reserved_name and stored.byte_length == 2,
        "Rev12: the exact aggregate boundary must accept the same durable reservation",
    )


@pytest.mark.asyncio
async def test_rev12_oversized_existing_child_rejects_before_new_file(
    tmp_path,
) -> None:
    module = _phase6_owner(QUARANTINE_MODULE)
    policy = module.QuarantinePolicy(max_image_bytes=8, max_job_total_bytes=16)
    job_directory = secrets.token_hex(32)
    profile_id = "profile-rev12-existing-oversized"
    job_path = tmp_path / job_directory
    job_path.mkdir(mode=0o700)
    binding = job_path / ".itda-owner-v1"
    binding.write_bytes(f"{job_directory}\n{profile_id}\n".encode())
    binding.chmod(0o600)
    existing_name = secrets.token_hex(16)
    existing = job_path / existing_name
    existing.write_bytes(b"123456789")
    existing.chmod(0o600)
    reserved_name = secrets.token_hex(16)
    stream = _RecordedChunks([b"x"])

    root_fd = _root_descriptor(tmp_path)
    try:
        with pytest.raises(module.QuarantineError):
            await module.stream_to_quarantine(
                root_fd=root_fd,
                job_directory=job_directory,
                profile_id=profile_id,
                image_index=2,
                chunks=stream,
                policy=policy,
                binding_claim_created=False,
                expected_stored_name=reserved_name,
                declared_byte_length=1,
            )
    finally:
        os.close(root_fd)
    _require(stream.consumed_chunks == 0, "Rev12: reject oversized inventory pre-stream")
    _require(
        sorted(_job_entries(tmp_path, job_directory)) == [existing_name],
        "Rev12: oversized inventory rejection must preserve it and create no file",
    )


@pytest.mark.asyncio
async def test_rev12_existing_aggregate_overflow_rejects_before_stream(
    tmp_path,
) -> None:
    module = _phase6_owner(QUARANTINE_MODULE)
    policy = module.QuarantinePolicy(max_image_bytes=10, max_job_total_bytes=15)
    job_directory = secrets.token_hex(32)
    profile_id = "profile-rev12-existing-aggregate"
    job_path = tmp_path / job_directory
    job_path.mkdir(mode=0o700)
    binding = job_path / ".itda-owner-v1"
    binding.write_bytes(f"{job_directory}\n{profile_id}\n".encode())
    binding.chmod(0o600)
    existing_names = [secrets.token_hex(16), secrets.token_hex(16)]
    for existing_name in existing_names:
        existing = job_path / existing_name
        existing.write_bytes(b"12345678")
        existing.chmod(0o600)
    reserved_name = secrets.token_hex(16)
    stream = _RecordedChunks([b"x"])

    root_fd = _root_descriptor(tmp_path)
    try:
        with pytest.raises(module.QuarantineError):
            await module.stream_to_quarantine(
                root_fd=root_fd,
                job_directory=job_directory,
                profile_id=profile_id,
                image_index=3,
                chunks=stream,
                policy=policy,
                binding_claim_created=False,
                expected_stored_name=reserved_name,
                declared_byte_length=1,
            )
    finally:
        os.close(root_fd)
    _require(stream.consumed_chunks == 0, "Rev12: reject aggregate-invalid inventory pre-stream")
    _require(
        sorted(_job_entries(tmp_path, job_directory)) == sorted(existing_names),
        "Rev12: aggregate-invalid inventory must remain unchanged with no new file",
    )


def test_rev12_rollback_created_entry_rejects_wrong_held_mode_before_rmdir(
    tmp_path,
) -> None:
    module = _phase6_owner(QUARANTINE_MODULE)
    job_directory = secrets.token_hex(32)
    job_path = tmp_path / job_directory
    job_path.mkdir(mode=0o700)
    job_path.chmod(0o755)
    root_fd = _root_descriptor(tmp_path)
    job_fd = os.open(
        job_directory,
        os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0),
        dir_fd=root_fd,
    )
    try:
        with pytest.raises(module.QuarantineError):
            module._rollback_created_entry(root_fd, job_fd, job_directory)
    finally:
        os.close(job_fd)
        os.close(root_fd)
    _require(job_path.is_dir(), "Rev12: wrong-mode held directory must never be removed")


@pytest.mark.parametrize("stat_errno", (errno.EIO, errno.ENOENT))
def test_rev12_binding_rollback_stat_failure_precedes_binding_unlink(
    tmp_path, monkeypatch: pytest.MonkeyPatch, stat_errno: int
) -> None:
    module = _phase6_owner(QUARANTINE_MODULE)
    job_directory = secrets.token_hex(32)
    profile_id = f"profile-rev12-binding-stat-{stat_errno}"
    job_path = tmp_path / job_directory
    job_path.mkdir(mode=0o700)
    binding = job_path / ".itda-owner-v1"
    binding.write_bytes(f"{job_directory}\n{profile_id}\n".encode())
    binding.chmod(0o600)
    root_fd = _root_descriptor(tmp_path)
    job_fd = os.open(
        job_directory,
        os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0),
        dir_fd=root_fd,
    )
    real_stat: Any = os.stat

    def failing_stat(path: object, *args: object, **kwargs: object) -> object:
        if (
            path == job_directory
            and kwargs.get("dir_fd") == root_fd
            and kwargs.get("follow_symlinks") is False
        ):
            raise OSError(stat_errno, "injected binding rollback stat failure")
        return real_stat(path, *args, **kwargs)  # type: ignore[arg-type, return-value]

    monkeypatch.setattr(os, "stat", failing_stat)
    try:
        with pytest.raises(module.QuarantineError):
            module._rollback_binding_initialization(root_fd, job_fd, job_directory)
    finally:
        os.close(root_fd)
        monkeypatch.undo()
    _require(job_path.is_dir(), "Rev12: binding rollback stat failure must keep directory")
    _require(binding.is_file(), "Rev12: visible proof must precede destructive binding unlink")


@pytest.mark.parametrize("observation", ("visible_eio", "wrong_mode"))
def test_rev13_stream_rollback_proves_directory_before_binding_unlink(
    tmp_path, monkeypatch: pytest.MonkeyPatch, observation: str
) -> None:
    module = _phase6_owner(QUARANTINE_MODULE)
    job_directory = secrets.token_hex(32)
    profile_id = f"profile-rev13-new-rollback-{observation}"
    job_path = tmp_path / job_directory
    job_path.mkdir(mode=0o700)
    binding = job_path / ".itda-owner-v1"
    binding_bytes = f"{job_directory}\n{profile_id}\n".encode()
    binding.write_bytes(binding_bytes)
    binding.chmod(0o600)
    binding_identity = os.stat(binding, follow_symlinks=False)
    root_fd = _root_descriptor(tmp_path)
    job_fd = os.open(
        job_directory,
        os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0),
        dir_fd=root_fd,
    )
    real_stat: Any = os.stat
    real_fstat: Any = os.fstat

    def stat(path: object, *args: object, **kwargs: object) -> object:
        if observation == "visible_eio" and path == job_directory:
            raise OSError(errno.EIO, "injected rollback directory stat failure")
        return real_stat(path, *args, **kwargs)  # type: ignore[arg-type, return-value]

    def fstat(fd: int) -> object:
        value = real_fstat(fd)
        if observation == "wrong_mode" and fd == job_fd:
            fields = {name: getattr(value, name) for name in dir(value) if name.startswith("st_")}
            fields["st_mode"] = stat_module.S_IFDIR | 0o755
            return SimpleNamespace(**fields)
        return value

    monkeypatch.setattr(os, "stat", stat)
    monkeypatch.setattr(os, "fstat", fstat)
    try:
        with pytest.raises(module.QuarantineError):
            module._rollback_new_job_directory(root_fd, job_fd, job_directory, profile_id)
    finally:
        os.close(job_fd)
        os.close(root_fd)
        monkeypatch.undo()
    after = os.stat(binding, follow_symlinks=False)
    _require(binding.read_bytes() == binding_bytes, "Rev13: binding bytes must remain untouched")
    _require(
        (after.st_dev, after.st_ino, after.st_mode, after.st_nlink, after.st_uid)
        == (
            binding_identity.st_dev,
            binding_identity.st_ino,
            binding_identity.st_mode,
            binding_identity.st_nlink,
            binding_identity.st_uid,
        ),
        "Rev13: binding inode must remain untouched before directory proof",
    )
    verify_root_fd = _root_descriptor(tmp_path)
    verify_fd = os.open(
        job_directory,
        os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0),
        dir_fd=verify_root_fd,
    )
    try:
        module._verify_binding(verify_fd, job_directory, profile_id)
    finally:
        os.close(verify_fd)
        os.close(verify_root_fd)


@pytest.mark.parametrize(
    "fault_stage",
    ("binding_fstat", "write", "fchmod", "binding_fsync", "directory_fsync", "root_fsync"),
)
@pytest.mark.asyncio
async def test_rev12_adoption_binding_fault_restores_exact_empty_intent(
    tmp_path, monkeypatch: pytest.MonkeyPatch, fault_stage: str
) -> None:
    module = _phase6_owner(QUARANTINE_MODULE)
    job_directory = secrets.token_hex(32)
    profile_id = f"profile-rev12-adoption-{fault_stage}"
    stored_name = secrets.token_hex(16)
    open_seam = _FailingOpens(failures=10**6, err=errno.EIO)
    _arm_open_seam(monkeypatch, open_seam)
    root_fd = _root_descriptor(tmp_path)
    try:
        with pytest.raises(module.QuarantineError):
            await module.stream_to_quarantine(
                root_fd=root_fd,
                job_directory=job_directory,
                profile_id=profile_id,
                image_index=1,
                chunks=_RecordedChunks([b"payload"]),
                policy=module.QuarantinePolicy(),
                binding_claim_created=True,
                expected_stored_name=stored_name,
                declared_byte_length=7,
            )
    finally:
        os.close(root_fd)
        monkeypatch.undo()

    real_write_binding: Any = module._write_binding
    real_fstat: Any = os.fstat
    real_fchmod: Any = os.fchmod
    real_fsync: Any = os.fsync
    baseline_fds = len(os.listdir("/dev/fd"))
    fsync_calls = 0
    fired = False

    def fstat(fd: int) -> object:
        nonlocal fired
        value = real_fstat(fd)
        if (
            fault_stage == "binding_fstat"
            and not fired
            and stat_module.S_ISREG(value.st_mode)
            and stat_module.S_IMODE(value.st_mode) == 0o600
            and value.st_nlink == 1
            and value.st_size == 0
        ):
            fired = True
            raise OSError(errno.EIO, "injected adoption binding fstat failure")
        return value

    def write_binding(fd: int, data: bytes) -> None:
        nonlocal fired
        if fault_stage == "write" and not fired:
            fired = True
            raise OSError(errno.EIO, "injected adoption binding write failure")
        real_write_binding(fd, data)

    def fchmod(fd: int, mode: int) -> None:
        nonlocal fired
        if fault_stage == "fchmod" and mode == 0o600 and not fired:
            fired = True
            raise OSError(errno.EIO, "injected adoption binding chmod failure")
        real_fchmod(fd, mode)

    def fsync(fd: int) -> None:
        nonlocal fired, fsync_calls
        fsync_calls += 1
        expected = {"binding_fsync": 1, "directory_fsync": 2, "root_fsync": 3}.get(fault_stage)
        if expected == fsync_calls and not fired:
            fired = True
            raise OSError(errno.EIO, "injected adoption fsync failure")
        real_fsync(fd)

    monkeypatch.setattr(module, "_write_binding", write_binding)
    monkeypatch.setattr(os, "fstat", fstat)
    monkeypatch.setattr(os, "fchmod", fchmod)
    monkeypatch.setattr(os, "fsync", fsync)
    root_fd = _root_descriptor(tmp_path)
    try:
        with pytest.raises(module.QuarantineError):
            await module.stream_to_quarantine(
                root_fd=root_fd,
                job_directory=job_directory,
                profile_id=profile_id,
                image_index=1,
                chunks=_RecordedChunks([b"payload"]),
                policy=module.QuarantinePolicy(),
                binding_claim_created=False,
                expected_stored_name=stored_name,
                materialize_reserved_missing=True,
                declared_byte_length=7,
            )
    finally:
        os.close(root_fd)
        monkeypatch.undo()
    job_path = tmp_path / job_directory
    _require(fired, f"Rev13: {fault_stage} fault must execute")
    _require(
        len(os.listdir("/dev/fd")) == baseline_fds,
        "Rev13: adoption binding fault must not leak its exclusive descriptor",
    )
    _require(os.listdir(job_path) == [], "Rev13: adoption fault restores empty durable intent")
    _require(
        stat_module.S_IMODE(os.stat(job_path).st_mode) == 0o700,
        "Rev12: adoption fault preserves exact 0700 intent",
    )

    root_fd = _root_descriptor(tmp_path)
    try:
        stored = await module.stream_to_quarantine(
            root_fd=root_fd,
            job_directory=job_directory,
            profile_id=profile_id,
            image_index=1,
            chunks=_RecordedChunks([b"payload"]),
            policy=module.QuarantinePolicy(),
            binding_claim_created=False,
            expected_stored_name=stored_name,
            materialize_reserved_missing=True,
            declared_byte_length=7,
        )
    finally:
        os.close(root_fd)
    _require(
        stored.stored_name == stored_name and (job_path / stored_name).is_file(),
        "Rev12: third exact adoption retry must converge on the same reserved name",
    )


async def _rev14_leave_empty_intent(
    module: Any,
    tmp_path,
    monkeypatch: pytest.MonkeyPatch,
    job_directory: str,
    profile_id: str,
    stored_name: str,
) -> None:
    open_seam = _FailingOpens(failures=10**6, err=errno.EIO)
    _arm_open_seam(monkeypatch, open_seam)
    root_fd = _root_descriptor(tmp_path)
    try:
        with pytest.raises(module.QuarantineError):
            await module.stream_to_quarantine(
                root_fd=root_fd,
                job_directory=job_directory,
                profile_id=profile_id,
                image_index=1,
                chunks=_RecordedChunks([b"payload"]),
                policy=module.QuarantinePolicy(),
                binding_claim_created=True,
                expected_stored_name=stored_name,
                declared_byte_length=7,
            )
    finally:
        os.close(root_fd)
        monkeypatch.undo()


@pytest.mark.asyncio
async def test_rev14_double_binding_fstat_fault_recovers_exact_partial_retry(
    tmp_path, monkeypatch: pytest.MonkeyPatch
) -> None:
    module = _phase6_owner(QUARANTINE_MODULE)
    job_directory = secrets.token_hex(32)
    profile_id = "profile-rev14-double-fstat"
    stored_name = secrets.token_hex(16)
    await _rev14_leave_empty_intent(
        module, tmp_path, monkeypatch, job_directory, profile_id, stored_name
    )
    job_path = tmp_path / job_directory
    real_fstat: Any = os.fstat
    failures = 0
    baseline_fds = len(os.listdir("/dev/fd"))

    def fail_twice(fd: int) -> object:
        nonlocal failures
        value = real_fstat(fd)
        if stat_module.S_ISREG(value.st_mode) and value.st_size == 0 and failures < 2:
            failures += 1
            raise OSError(errno.EIO, "injected repeated binding fstat failure")
        return value

    monkeypatch.setattr(os, "fstat", fail_twice)
    root_fd = _root_descriptor(tmp_path)
    try:
        with pytest.raises(module.QuarantineError):
            await module.stream_to_quarantine(
                root_fd=root_fd,
                job_directory=job_directory,
                profile_id=profile_id,
                image_index=1,
                chunks=_RecordedChunks([b"payload"]),
                policy=module.QuarantinePolicy(),
                binding_claim_created=False,
                expected_stored_name=stored_name,
                materialize_reserved_missing=True,
                declared_byte_length=7,
            )
    finally:
        os.close(root_fd)
        monkeypatch.undo()
    _require(failures == 2, "Rev14: both binding fstat observations must fail")
    _require(len(os.listdir("/dev/fd")) == baseline_fds, "Rev14: binding fd must close")
    binding = job_path / ".itda-owner-v1"
    _require(binding.is_file() and binding.stat().st_size == 0, "Rev14: exact partial remains")

    root_fd = _root_descriptor(tmp_path)
    try:
        stored = await module.stream_to_quarantine(
            root_fd=root_fd,
            job_directory=job_directory,
            profile_id=profile_id,
            image_index=1,
            chunks=_RecordedChunks([b"payload"]),
            policy=module.QuarantinePolicy(),
            binding_claim_created=False,
            expected_stored_name=stored_name,
            materialize_reserved_missing=True,
            declared_byte_length=7,
        )
    finally:
        os.close(root_fd)
    _require(stored.stored_name == stored_name, "Rev14: exact reserved name must converge")


@pytest.mark.parametrize(
    "collision",
    (
        "nonzero",
        "extra",
        "symlink",
        "hardlink",
        "binding-mode",
        "directory-mode",
        "directory-world-mode",
    ),
)
@pytest.mark.asyncio
async def test_rev14_partial_binding_recovery_rejects_hostile_shapes(
    tmp_path, collision: str
) -> None:
    module = _phase6_owner(QUARANTINE_MODULE)
    job_directory = secrets.token_hex(32)
    profile_id = f"profile-rev14-collision-{collision}"
    stored_name = secrets.token_hex(16)
    job_path = tmp_path / job_directory
    job_path.mkdir(mode=0o700)
    binding = job_path / ".itda-owner-v1"
    if collision == "symlink":
        target = tmp_path / "target"
        target.write_bytes(b"")
        binding.symlink_to(target)
    else:
        binding.write_bytes(b"x" if collision == "nonzero" else b"")
        binding.chmod(0o666 if collision == "binding-mode" else 0o600)
    if collision == "extra":
        (job_path / "unknown").write_bytes(b"sentinel")
    elif collision == "hardlink":
        os.link(binding, job_path / "second-link")
    elif collision == "directory-mode":
        job_path.chmod(0o755)
    elif collision == "directory-world-mode":
        job_path.chmod(0o777)
    before = {entry.name: entry.lstat() for entry in job_path.iterdir()}

    root_fd = _root_descriptor(tmp_path)
    try:
        with pytest.raises(module.QuarantineError):
            await module.stream_to_quarantine(
                root_fd=root_fd,
                job_directory=job_directory,
                profile_id=profile_id,
                image_index=1,
                chunks=_RecordedChunks([b"payload"]),
                policy=module.QuarantinePolicy(),
                binding_claim_created=False,
                expected_stored_name=stored_name,
                materialize_reserved_missing=True,
                declared_byte_length=7,
            )
    finally:
        os.close(root_fd)
    after = {entry.name: entry.lstat() for entry in job_path.iterdir()}
    _require(after.keys() == before.keys(), "Rev14: hostile entries must not be deleted")
    _require(
        all(
            (after[name].st_dev, after[name].st_ino) == (state.st_dev, state.st_ino)
            for name, state in before.items()
        ),
        "Rev14: hostile inode identities must remain unchanged",
    )


@pytest.mark.parametrize(
    "fault_stage",
    ("removed_binding_fstat", "job_fsync", "final_visible_stat", "post_rmdir_fstat"),
)
@pytest.mark.asyncio
async def test_rev14_post_unlink_rollback_fault_allows_exact_retry(
    tmp_path, monkeypatch: pytest.MonkeyPatch, fault_stage: str
) -> None:
    module = _phase6_owner(QUARANTINE_MODULE)
    job_directory = secrets.token_hex(32)
    profile_id = f"profile-rev14-rollback-{fault_stage}"
    stored_name = secrets.token_hex(16)
    job_path = tmp_path / job_directory
    job_path.mkdir(mode=0o700)
    binding = job_path / ".itda-owner-v1"
    binding.write_bytes(f"{job_directory}\n{profile_id}\n".encode())
    binding.chmod(0o600)
    neighbor = tmp_path / f"neighbor-{fault_stage}"
    neighbor.write_bytes(b"sentinel")
    real_fstat: Any = os.fstat
    real_fsync: Any = os.fsync
    real_stat: Any = os.stat
    fired = False
    baseline_fds = len(os.listdir("/dev/fd"))
    root_fd = _root_descriptor(tmp_path)
    job_fd = os.open(
        job_directory,
        os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0),
        dir_fd=root_fd,
    )

    def fail_fstat(fd: int) -> object:
        nonlocal fired
        value = real_fstat(fd)
        if (
            not fired
            and fault_stage == "removed_binding_fstat"
            and stat_module.S_ISREG(value.st_mode)
            and value.st_nlink == 0
        ):
            fired = True
            raise OSError(errno.EIO, "injected removed binding fstat failure")
        if (
            not fired
            and fault_stage == "post_rmdir_fstat"
            and fd == job_fd
            and not job_path.exists()
        ):
            fired = True
            raise OSError(errno.EIO, "injected removed directory fstat failure")
        return value

    def fail_fsync(fd: int) -> None:
        nonlocal fired
        if not fired and fault_stage == "job_fsync" and fd == job_fd and not binding.exists():
            fired = True
            raise OSError(errno.EIO, "injected job fsync failure")
        real_fsync(fd)

    def fail_stat(path: object, *args: object, **kwargs: object) -> object:
        nonlocal fired
        if (
            not fired
            and fault_stage == "final_visible_stat"
            and path == job_directory
            and not binding.exists()
        ):
            fired = True
            raise OSError(errno.EIO, "injected final visible stat failure")
        return real_stat(path, *args, **kwargs)  # type: ignore[arg-type, return-value]

    monkeypatch.setattr(os, "fstat", fail_fstat)
    monkeypatch.setattr(os, "fsync", fail_fsync)
    monkeypatch.setattr(os, "stat", fail_stat)
    try:
        with pytest.raises(module.QuarantineError):
            module._rollback_new_job_directory(root_fd, job_fd, job_directory, profile_id)
    finally:
        os.close(job_fd)
        os.close(root_fd)
        monkeypatch.undo()
    _require(fired, f"Rev14: {fault_stage} must execute")
    _require(len(os.listdir("/dev/fd")) == baseline_fds, "Rev14: rollback fault must not leak fds")
    _require(neighbor.read_bytes() == b"sentinel", "Rev14: unknown root entry must survive")

    root_fd = _root_descriptor(tmp_path)
    try:
        stored = await module.stream_to_quarantine(
            root_fd=root_fd,
            job_directory=job_directory,
            profile_id=profile_id,
            image_index=1,
            chunks=_RecordedChunks([b"payload"]),
            policy=module.QuarantinePolicy(),
            binding_claim_created=False,
            expected_stored_name=stored_name,
            materialize_reserved_missing=True,
            declared_byte_length=7,
        )
    finally:
        os.close(root_fd)
    _require(stored.stored_name == stored_name, "Rev14: rollback retry must converge")
    _require(neighbor.read_bytes() == b"sentinel", "Rev14: retry must preserve unknown root entry")


@pytest.mark.asyncio
async def test_rev14_double_mode_normalization_fault_recovers_restrictive_intent(
    tmp_path, monkeypatch: pytest.MonkeyPatch
) -> None:
    module = _phase6_owner(QUARANTINE_MODULE)
    job_directory = secrets.token_hex(32)
    profile_id = "profile-rev14-restrictive-mode"
    stored_name = secrets.token_hex(16)
    job_path = tmp_path / job_directory
    real_mkdir: Any = os.mkdir
    real_chmod: Any = os.chmod
    real_fchmod: Any = os.fchmod
    chmod_failed = False
    fchmod_failed = False
    baseline_fds = len(os.listdir("/dev/fd"))

    def restrictive_mkdir(path: object, mode: int = 0o777, **kwargs: object) -> None:
        real_mkdir(path, mode, **kwargs)
        real_chmod(path, 0o600, **kwargs)

    def fail_chmod(path: object, mode: int, **kwargs: object) -> None:
        nonlocal chmod_failed
        if path == job_directory and mode == 0o700 and not chmod_failed:
            chmod_failed = True
            raise OSError(errno.EIO, "injected pathname chmod failure")
        real_chmod(path, mode, **kwargs)

    def fail_fchmod(fd: int, mode: int) -> None:
        nonlocal fchmod_failed
        if mode == 0o700 and not fchmod_failed:
            fchmod_failed = True
            raise OSError(errno.EIO, "injected held fchmod failure")
        real_fchmod(fd, mode)

    monkeypatch.setattr(os, "supports_dir_fd", os.supports_dir_fd | {restrictive_mkdir})
    monkeypatch.setattr(os, "mkdir", restrictive_mkdir)
    monkeypatch.setattr(os, "chmod", fail_chmod)
    monkeypatch.setattr(os, "fchmod", fail_fchmod)
    root_fd = _root_descriptor(tmp_path)
    try:
        with pytest.raises(module.QuarantineError):
            await module.stream_to_quarantine(
                root_fd=root_fd,
                job_directory=job_directory,
                profile_id=profile_id,
                image_index=1,
                chunks=_RecordedChunks([b"payload"]),
                policy=module.QuarantinePolicy(),
                binding_claim_created=True,
                expected_stored_name=stored_name,
                declared_byte_length=7,
            )
    finally:
        os.close(root_fd)
        monkeypatch.undo()
    _require(
        chmod_failed and fchmod_failed,
        "Rev14: both normalization faults must execute",
    )
    _require(
        len(os.listdir("/dev/fd")) == baseline_fds, "Rev14: normalization fault must not leak fds"
    )
    _require(
        job_path.is_dir() and not os.listdir(job_path), "Rev14: restrictive empty intent remains"
    )
    _require(stat_module.S_IMODE(job_path.stat().st_mode) == 0o600, "Rev14: mode must remain 0600")

    root_fd = _root_descriptor(tmp_path)
    try:
        stored = await module.stream_to_quarantine(
            root_fd=root_fd,
            job_directory=job_directory,
            profile_id=profile_id,
            image_index=1,
            chunks=_RecordedChunks([b"payload"]),
            policy=module.QuarantinePolicy(),
            binding_claim_created=False,
            expected_stored_name=stored_name,
            materialize_reserved_missing=True,
            declared_byte_length=7,
        )
    finally:
        os.close(root_fd)
    _require(stored.stored_name == stored_name, "Rev14: restrictive intent retry must converge")


class _RejectUnreadableOpen:
    def __init__(self) -> None:
        self._real_open: Any = os.open
        self.rejections = 0

    def __call__(self, path: object, flags: int, *args: object, **kwargs: object) -> int:
        if kwargs.get("dir_fd") is not None and flags & os.O_ACCMODE == os.O_RDONLY:
            visible = os.stat(path, dir_fd=kwargs["dir_fd"], follow_symlinks=False)
            if stat_module.S_IMODE(visible.st_mode) & stat_module.S_IRUSR == 0:
                self.rejections += 1
                raise PermissionError(errno.EACCES, "owner-read absent")
        return self._real_open(path, flags, *args, **kwargs)


@pytest.mark.parametrize("directory_mode", (0o300, 0o000))
@pytest.mark.asyncio
async def test_rev15_owner_unreadable_directory_intent_recovers_before_open(
    tmp_path, monkeypatch: pytest.MonkeyPatch, directory_mode: int
) -> None:
    module = _phase6_owner(QUARANTINE_MODULE)
    job_directory = secrets.token_hex(32)
    profile_id = f"profile-rev15-directory-{directory_mode:o}"
    stored_name = secrets.token_hex(16)
    job_path = tmp_path / job_directory
    job_path.mkdir(mode=0o700)
    job_path.chmod(directory_mode)
    seam = _RejectUnreadableOpen()
    _arm_open_seam(monkeypatch, seam)
    baseline_fds = len(os.listdir("/dev/fd"))
    root_fd = _root_descriptor(tmp_path)
    try:
        stored = await module.stream_to_quarantine(
            root_fd=root_fd,
            job_directory=job_directory,
            profile_id=profile_id,
            image_index=1,
            chunks=_RecordedChunks([b"payload"]),
            policy=module.QuarantinePolicy(),
            binding_claim_created=False,
            expected_stored_name=stored_name,
            materialize_reserved_missing=True,
            declared_byte_length=7,
        )
    finally:
        os.close(root_fd)
        monkeypatch.undo()
    _require(seam.rejections == 0, "Rev15: normalization must precede O_RDONLY open")
    _require(len(os.listdir("/dev/fd")) == baseline_fds, "Rev15: no descriptor leak")
    _require(stored.stored_name == stored_name, "Rev15: same reserved name must converge")


@pytest.mark.parametrize("binding_mode", (0o200, 0o000))
@pytest.mark.asyncio
async def test_rev15_owner_unreadable_partial_binding_recovers_before_open(
    tmp_path, monkeypatch: pytest.MonkeyPatch, binding_mode: int
) -> None:
    module = _phase6_owner(QUARANTINE_MODULE)
    job_directory = secrets.token_hex(32)
    profile_id = f"profile-rev15-binding-{binding_mode:o}"
    stored_name = secrets.token_hex(16)
    job_path = tmp_path / job_directory
    job_path.mkdir(mode=0o700)
    binding = job_path / ".itda-owner-v1"
    binding.write_bytes(b"")
    binding.chmod(binding_mode)
    seam = _RejectUnreadableOpen()
    _arm_open_seam(monkeypatch, seam)
    baseline_fds = len(os.listdir("/dev/fd"))
    root_fd = _root_descriptor(tmp_path)
    try:
        stored = await module.stream_to_quarantine(
            root_fd=root_fd,
            job_directory=job_directory,
            profile_id=profile_id,
            image_index=1,
            chunks=_RecordedChunks([b"payload"]),
            policy=module.QuarantinePolicy(),
            binding_claim_created=False,
            expected_stored_name=stored_name,
            materialize_reserved_missing=True,
            declared_byte_length=7,
        )
    finally:
        os.close(root_fd)
        monkeypatch.undo()
    _require(seam.rejections == 0, "Rev15: binding normalization must precede O_RDONLY")
    _require(len(os.listdir("/dev/fd")) == baseline_fds, "Rev15: no binding descriptor leak")
    _require(stored.stored_name == stored_name, "Rev15: partial binding retry must converge")


@pytest.mark.parametrize(
    ("kind", "mode"),
    (
        ("directory", 0o755),
        ("directory", 0o777),
        ("binding", 0o666),
    ),
)
@pytest.mark.asyncio
async def test_rev15_permission_broad_shapes_stay_untouched(
    tmp_path, monkeypatch: pytest.MonkeyPatch, kind: str, mode: int
) -> None:
    module = _phase6_owner(QUARANTINE_MODULE)
    job_directory = secrets.token_hex(32)
    profile_id = f"profile-rev15-negative-{kind}-{mode:o}"
    stored_name = secrets.token_hex(16)
    job_path = tmp_path / job_directory
    job_path.mkdir(mode=0o700)
    if kind == "directory":
        job_path.chmod(mode)
    else:
        binding = job_path / ".itda-owner-v1"
        binding.write_bytes(b"")
        binding.chmod(mode)
    before_mode = stat_module.S_IMODE(job_path.stat().st_mode)
    before = {entry.name: entry.lstat() for entry in job_path.iterdir()}
    seam = _RejectUnreadableOpen()
    _arm_open_seam(monkeypatch, seam)
    root_fd = _root_descriptor(tmp_path)
    try:
        with pytest.raises(module.QuarantineError):
            await module.stream_to_quarantine(
                root_fd=root_fd,
                job_directory=job_directory,
                profile_id=profile_id,
                image_index=1,
                chunks=_RecordedChunks([b"payload"]),
                policy=module.QuarantinePolicy(),
                binding_claim_created=False,
                expected_stored_name=stored_name,
                materialize_reserved_missing=True,
                declared_byte_length=7,
            )
    finally:
        os.close(root_fd)
        monkeypatch.undo()
    after = {entry.name: entry.lstat() for entry in job_path.iterdir()}
    _require(stat_module.S_IMODE(job_path.stat().st_mode) == before_mode, "Rev15: mode unchanged")
    _require(after.keys() == before.keys(), "Rev15: negative inventory unchanged")
    _require(
        all(
            (after[name].st_dev, after[name].st_ino) == (state.st_dev, state.st_ino)
            for name, state in before.items()
        ),
        "Rev15: negative inode identities unchanged",
    )
