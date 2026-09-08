"""Stdlib-only pre-import gate for capability-bearing minimal probe commands."""

from __future__ import annotations

import os
import stat
import subprocess
import sys
import sysconfig
from pathlib import Path

_CAPABILITY_COMMANDS = frozenset(
    {
        "nvidia-minimal-probe-install-approval",
        "nvidia-minimal-probe-live",
        "nvidia-minimal-probe-reconcile",
        "nvidia-fresh24-install-approval",
        "nvidia-fresh24-live",
        "nvidia-fresh24-reconcile",
        "openrouter-recovery-install-approval",
        "openrouter-recovery-live",
        "openrouter-recovery-reconcile",
        "openrouter-recovery-v2-install-approval",
        "openrouter-recovery-v2-live",
        "openrouter-recovery-v2-reconcile",
        "openrouter-recovery-v3-install-approval",
        "openrouter-recovery-v3-live",
        "openrouter-recovery-v3-reconcile",
        "openrouter-recovery-v4-install-approval",
        "openrouter-recovery-v4-live",
        "openrouter-recovery-v4-reconcile",
    }
)
_FRESH24_COMMAND_PREFIXES = frozenset(
    {"nvidia-fresh24-install-approval", "nvidia-fresh24-live", "nvidia-fresh24-reconcile"}
)
_OPENROUTER_COMMAND_PREFIXES = frozenset(
    {
        "openrouter-recovery-install-approval",
        "openrouter-recovery-live",
        "openrouter-recovery-reconcile",
    }
)
_OPENROUTER_V2_COMMAND_PREFIXES = frozenset(
    {
        "openrouter-recovery-v2-install-approval",
        "openrouter-recovery-v2-live",
        "openrouter-recovery-v2-reconcile",
    }
)
# Plan 05-38: the disjoint r3/v3 capability names route through their own
# sanitized dispatcher AFTER checkout validation; the v2 inert branch still
# precedes everything.
_OPENROUTER_V3_COMMAND_PREFIXES = frozenset(
    {
        "openrouter-recovery-v3-install-approval",
        "openrouter-recovery-v3-live",
        "openrouter-recovery-v3-reconcile",
    }
)
_OPENROUTER_V4_COMMAND_PREFIXES = frozenset(
    {
        "openrouter-recovery-v4-install-approval",
        "openrouter-recovery-v4-live",
        "openrouter-recovery-v4-reconcile",
    }
)
_ALLOWED_UNTRACKED_PREFIXES = (
    ".claude/",
    ".planning/",
    ".secrets/",
    "artifacts/restricted/",
)
_ALLOWED_UNTRACKED_EXACT = frozenset({"milestone.lock"})
_ALLOWED_TRACKED_DIRTY_EXACT = ".planning/config.json"
_MAX_CONFIG_BYTES = 256 * 1024
_FORBIDDEN_SUFFIXES = (
    ".py",
    ".pyc",
    ".pth",
    ".so",
    ".dylib",
    "sitecustomize.py",
    "usercustomize.py",
)


def _repository_root() -> Path:
    return Path(__file__).absolute().parents[3]


def _reject_environment() -> None:
    if os.environ.get("PYTHONPATH") or os.environ.get("PYTHONHOME"):
        raise PermissionError("MINIMAL_PROBE_BOOTSTRAP_PYTHON_ENV_FORBIDDEN")
    if "sitecustomize" in sys.modules or "usercustomize" in sys.modules:
        raise PermissionError("MINIMAL_PROBE_BOOTSTRAP_IMPORT_HOOK_FORBIDDEN")


def _validate_allowed_untracked(root: Path, relative: str) -> None:
    allowed = relative in _ALLOWED_UNTRACKED_EXACT or relative.startswith(
        _ALLOWED_UNTRACKED_PREFIXES
    )
    if not allowed or relative.endswith(_FORBIDDEN_SUFFIXES):
        raise PermissionError("MINIMAL_PROBE_BOOTSTRAP_UNTRACKED_FORBIDDEN")
    current = root
    for component in Path(relative).parts:
        current = current / component
        metadata = os.lstat(current)
        if stat.S_ISLNK(metadata.st_mode):
            raise PermissionError("MINIMAL_PROBE_BOOTSTRAP_SYMLINK_FORBIDDEN")


def _validate_tracked_config_exception(root: Path, relative: str) -> None:
    if relative != _ALLOWED_TRACKED_DIRTY_EXACT or Path(relative).suffix != ".json":
        raise PermissionError("MINIMAL_PROBE_BOOTSTRAP_TRACKED_DIRTY")
    path = root / ".planning" / "config.json"
    if path != root / relative:
        raise PermissionError("MINIMAL_PROBE_BOOTSTRAP_CONFIG_PATH_INVALID")
    parent = os.lstat(path.parent)
    metadata = os.lstat(path)
    if (
        not stat.S_ISDIR(parent.st_mode)
        or stat.S_ISLNK(parent.st_mode)
        or not stat.S_ISREG(metadata.st_mode)
        or stat.S_ISLNK(metadata.st_mode)
        or metadata.st_nlink != 1
        or metadata.st_uid != os.getuid()
        or not 0 < metadata.st_size <= _MAX_CONFIG_BYTES
        or relative.endswith(_FORBIDDEN_SUFFIXES)
    ):
        raise PermissionError("MINIMAL_PROBE_BOOTSTRAP_CONFIG_INVALID")


def _validate_checkout(root: Path) -> None:
    completed = subprocess.run(
        ["git", "status", "--porcelain=v1", "-z", "--untracked-files=all"],
        cwd=root,
        check=True,
        capture_output=True,
    )
    for raw in completed.stdout.split(b"\0"):
        if not raw:
            continue
        row = raw.decode("utf-8")
        code, relative = row[:2], row[3:]
        if code == "??":
            _validate_allowed_untracked(root, relative)
        else:
            _validate_tracked_config_exception(root, relative)


def _canonical(path: str | os.PathLike[str]) -> Path:
    value = Path(path).absolute()
    probe = Path(value.anchor)
    for component in value.parts[1:]:
        probe = probe / component
        try:
            metadata = os.lstat(probe)
        except FileNotFoundError:
            continue
        if stat.S_ISLNK(metadata.st_mode):
            raise PermissionError("MINIMAL_PROBE_BOOTSTRAP_SYMLINKED_ORIGIN_FORBIDDEN")
    return value


def _interpreter_roots() -> frozenset[Path]:
    paths = sysconfig.get_paths()
    roots = {
        _canonical(paths[name])
        for name in ("stdlib", "platstdlib", "purelib", "platlib")
        if paths.get(name)
    }
    stdlib = _canonical(paths["stdlib"])
    roots.add(_canonical(stdlib / "lib-dynload"))
    roots.add(
        _canonical(
            stdlib.parent / f"python{sys.version_info.major}{sys.version_info.minor}.zip"
        )
    )
    return frozenset(roots)


def _origin_within(candidate: Path, roots: frozenset[Path]) -> bool:
    return any(candidate == root or root in candidate.parents for root in roots)


def validate_capability_process() -> None:
    """Idempotent stdlib-only gate for ANY capability handler entry.

    Re-runs the full bootstrap validation — environment, import origin,
    checkout — against the *current* process state.  The production bootstrap
    calls it before dispatching; the application's capability dispatcher calls
    it again on every entry, so a direct imported-dispatcher call under a
    hostile environment, dirty checkout, or poisoned import surface fails
    before any handler sentinel.  Raises PermissionError on any violation.
    """

    root = _repository_root()
    _reject_environment()
    _validate_import_origin(root)
    _validate_checkout(root)


def _validate_import_origin(
    root: Path,
    *,
    modules: dict[str, object] | None = None,
    search_path: list[str] | None = None,
) -> None:
    package = _canonical(Path(__file__).parent)
    backend_src = _canonical(package.parent)
    expected = _canonical(root / "backend/src/itda")
    if package != expected or _canonical(sys.argv[0]) != _canonical(__file__):
        raise PermissionError("MINIMAL_PROBE_BOOTSTRAP_ORIGIN_INVALID")
    interpreter_roots = _interpreter_roots()
    module_roots = interpreter_roots | frozenset({package})
    loaded = sys.modules if modules is None else modules
    for name, module in tuple(loaded.items()):
        origin = getattr(module, "__file__", None)
        if not origin or name in {"__main__", "__mp_main__"}:
            continue
        candidate = _canonical(origin)
        if not _origin_within(candidate, module_roots):
            raise PermissionError("MINIMAL_PROBE_BOOTSTRAP_MODULE_ORIGIN_INVALID")
        if backend_src in candidate.parents and package not in candidate.parents:
            raise PermissionError("MINIMAL_PROBE_BOOTSTRAP_MODULE_ORIGIN_INVALID")
    source_candidates = {backend_src, package}
    purelib = sysconfig.get_paths().get("purelib")
    if purelib:
        environment_backend_src = _canonical(Path(purelib).parents[3] / "src")
        if environment_backend_src.name == "src":
            source_candidates.add(environment_backend_src)
    allowed_paths = interpreter_roots | frozenset(source_candidates)
    entries = sys.path if search_path is None else search_path
    for entry in entries:
        if not entry:
            continue
        candidate = _canonical(entry)
        if candidate not in allowed_paths:
            raise PermissionError("MINIMAL_PROBE_BOOTSTRAP_SYS_PATH_INVALID")


def main(argv: list[str] | None = None) -> int:
    arguments = list(sys.argv[1:] if argv is None else argv)
    if not arguments or arguments[0] not in _CAPABILITY_COMMANDS:
        print("MINIMAL_PROBE_BOOTSTRAP_COMMAND_REQUIRED", file=sys.stderr)
        return 2
    if arguments[0] in _OPENROUTER_V2_COMMAND_PREFIXES:
        # Task 1 exposes names only.  Reject before checkout validation or any
        # application import so there is no secret/client/socket/protected-state
        # or broader filesystem capability in the r2 bootstrap surface.
        print("OPENROUTER_V2_CAPABILITY_INERT", file=sys.stderr)
        return 2
    try:
        validate_capability_process()
    except (OSError, PermissionError, subprocess.CalledProcessError, UnicodeError):
        print("MINIMAL_PROBE_BOOTSTRAP_REJECTED", file=sys.stderr)
        return 2
    if arguments[0] in _FRESH24_COMMAND_PREFIXES:
        # Fresh24 capability commands dispatch through the private one-shot
        # dispatcher; the application's public ``main`` has no capability
        # surface at all.  The dispatcher re-runs validate_capability_process()
        # itself on every entry, so the double validation on this production
        # path is safe and intentional.
        from itda.cli.materialize_phase5_demo_profiles import (
            _fresh24_capability_dispatch as fresh24_dispatch,
        )

        return fresh24_dispatch(arguments)
    if arguments[0] in _OPENROUTER_V2_COMMAND_PREFIXES:
        # Plan 05-37 registers a separate r2 namespace but deliberately keeps
        # every capability inert.  The dispatcher rejects before parsing any
        # path, opening a secret, constructing a client/socket, or touching
        # protected state; Plan 05-38 may replace that inert boundary later.
        from itda.cli.materialize_phase5_demo_profiles import (
            _openrouter_v2_capability_dispatch,
        )

        return _openrouter_v2_capability_dispatch(arguments)
    if arguments[0] in _OPENROUTER_V3_COMMAND_PREFIXES:
        from itda.cli.materialize_phase5_demo_profiles import (
            _openrouter_v3_capability_dispatch,
        )

        return _openrouter_v3_capability_dispatch(arguments)
    if arguments[0] in _OPENROUTER_V4_COMMAND_PREFIXES:
        from itda.cli.phase5_openrouter_recovery_v4 import v4_capability_dispatch

        return v4_capability_dispatch(arguments)
    if arguments[0] in _OPENROUTER_COMMAND_PREFIXES:
        # OpenRouter recovery capability commands follow the identical
        # sanitized-dispatcher pattern: the private dispatcher re-validates
        # the process on every entry before any handler runs.  The imported
        # symbol is THE production dispatcher (verified by wiring tests that
        # drive bootstrap main() end to end).
        from itda.cli.materialize_phase5_demo_profiles import (
            _openrouter_capability_dispatch,
        )

        return _openrouter_capability_dispatch(arguments)
    from itda.cli.materialize_phase5_demo_profiles import main as application_main

    return application_main(arguments)


if __name__ == "__main__":
    raise SystemExit(main())
