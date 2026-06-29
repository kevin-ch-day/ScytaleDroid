"""Utility helpers for configuring project loggers.

The module now offers richer facilities for structured logging and contextual
information propagation.  Each category logger writes both a human readable log
file and a JSONL companion file.  A ``ContextAdapter`` wrapper makes it easy to
bind run level metadata (``run_id``, ``device_serial`` and similar) to each log
record without having to repeat the values for every call.
"""

from __future__ import annotations

import logging
import platform
import re
import sys
import uuid
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path

from scytaledroid.Config import app_config

from .logging_core import (
    DATE_FORMAT,
    LOG_DIR,
    LOG_FORMAT,
    JsonFormatter,
    SafeFormatter,
    make_rotating_handler,
    setup_logger,
)

try:  # pragma: no cover - optional dependency
    from loguru import logger as _loguru_logger
except Exception:  # pragma: no cover - optional dependency
    _loguru_logger = None

@dataclass(frozen=True)
class _LoggerConfig:
    text_file: str | None
    json_file: str | None
    level: int = logging.INFO
    subdir: str | None = None
    max_bytes: int = 10 * 1024 * 1024
    backup_count: int = 14


LOG_CONFIGS: dict[str, _LoggerConfig] = {
    "application": _LoggerConfig(text_file="app.log", json_file="app.jsonl", level=logging.INFO),
    "database": _LoggerConfig(text_file="db.log", json_file="db.jsonl", level=logging.DEBUG),
    "device": _LoggerConfig(text_file="device_analysis.log", json_file="device_analysis.jsonl"),
    "harvest": _LoggerConfig(text_file="harvest.log", json_file="harvest.jsonl"),
    "static": _LoggerConfig(text_file="static_analysis.log", json_file="static_analysis.jsonl"),
    "dynamic": _LoggerConfig(text_file="dynamic_analysis.log", json_file="dynamic_analysis.jsonl"),
    "error": _LoggerConfig(text_file="error.log", json_file=None, level=logging.ERROR),
    "metrics": _LoggerConfig(text_file=None, json_file="metrics.jsonl"),
    "audit": _LoggerConfig(text_file="audit.log", json_file="audit.jsonl"),
}


@dataclass(frozen=True)
class LogTarget:
    """Resolved log file destinations for a logging category."""

    text_path: Path | None
    json_path: Path | None


@dataclass(frozen=True)
class _SessionMirror:
    adapter: "ContextAdapter"
    logger: logging.Logger
    handlers: tuple[logging.Handler, ...]


_LOGGERS: dict[str, logging.Logger] = {}
_HARVEST_LOGGERS: dict[str, ContextAdapter] = {}
_STATIC_SESSION_LOGGERS: dict[str, _SessionMirror] = {}
_DYNAMIC_RUN_LOGGERS: dict[str, _SessionMirror] = {}

_HARVEST_SUBDIR = "harvest"
_STATIC_SUBDIR = "static"
_DYNAMIC_SUBDIR = "dynamic"

_FILTER_ATTR = "_scd_androguard_filter"
_LOGURU_FILTER_ATTR = "_scd_loguru_filter"


class _AndroguardNoiseFilter(logging.Filter):
    """Filter extremely noisy androguard messages."""

    _SUBSTRINGS = (
        "get_resource_dimen",
        "Out of range dimension unit index",
    )

    def filter(self, record: logging.LogRecord) -> bool:  # pragma: no cover - trivial
        message = record.getMessage()
        return not any(snippet in message for snippet in self._SUBSTRINGS)


def get_logger(category: str) -> logging.Logger:
    """Return the configured logger for *category*."""

    config = LOG_CONFIGS.get(category)
    if config is None:
        raise ValueError(f"Unknown log category: {category}")

    if category not in _LOGGERS:
        _LOGGERS[category] = setup_logger(
            category,
            text_file=config.text_file,
            json_file=config.json_file,
            subdir=config.subdir,
            level=config.level,
            max_bytes=config.max_bytes,
            backup_count=config.backup_count,
        )

    return _LOGGERS[category]


# Convenience getters for each subsystem
def get_app_logger() -> logging.Logger:
    return get_logger("application")


def get_db_logger() -> logging.Logger:
    return get_logger("database")


def get_device_logger() -> logging.Logger:
    return get_logger("device")


def get_static_logger() -> logging.Logger:
    return get_logger("static")


def get_dynamic_logger() -> logging.Logger:
    return get_logger("dynamic")


def get_error_logger() -> logging.Logger:
    return get_logger("error")


def get_metrics_logger() -> logging.Logger:
    return get_logger("metrics")


def get_audit_logger() -> logging.Logger:
    return get_logger("audit")


def list_log_files() -> dict[str, LogTarget]:
    """Return resolved log file destinations for all logging categories."""

    files: dict[str, LogTarget] = {}
    base_dir = LOG_DIR.expanduser()

    for category, config in LOG_CONFIGS.items():
        root = base_dir
        if config.subdir:
            root = (base_dir / config.subdir).expanduser()
        text_path = (root / config.text_file).resolve() if config.text_file else None
        json_path = (root / config.json_file).resolve() if config.json_file else None
        files[category] = LogTarget(text_path=text_path, json_path=json_path)

    harvest_dir = (base_dir / _HARVEST_SUBDIR).expanduser().resolve()
    files["harvest_runs"] = LogTarget(text_path=harvest_dir, json_path=harvest_dir)
    static_dir = (base_dir / _STATIC_SUBDIR).expanduser().resolve()
    files["static_sessions"] = LogTarget(text_path=static_dir, json_path=static_dir)

    return files


class ContextAdapter(logging.LoggerAdapter):
    """Logger adapter that merges ``extra`` payloads recursively."""

    def process(self, msg, kwargs):  # pragma: no cover - thin wrapper
        incoming = kwargs.get("extra") or {}
        merged = {**self.extra, **incoming}
        kwargs["extra"] = merged
        return msg, kwargs


def bind_logger(category: str, **context: object) -> ContextAdapter:
    """Return a logger adapter for ``category`` carrying persistent context."""

    base_logger = get_logger(category)
    return ContextAdapter(base_logger, {k: v for k, v in context.items() if v is not None})


def ensure_trace(extra: Mapping[str, object] | None = None) -> dict[str, object]:
    """Return a mutable copy of ``extra`` containing a ``trace_id`` field."""

    payload = dict(extra or {})
    payload.setdefault("trace_id", uuid.uuid4().hex[:8])
    return payload


def emit_environment_snapshot(logger: logging.Logger | None = None) -> None:
    """Log runtime environment metadata to aid debugging."""

    target = logger or get_app_logger()
    details = ensure_trace(
        {
            "event": "app.env",
            "python_version": platform.python_version(),
            "platform": platform.platform(),
            "implementation": platform.python_implementation(),
            "executable": sys.executable,
            "debug_mode": app_config.DEBUG_MODE,
            "sys_test": app_config.SYS_TEST,
            "runtime_preset": app_config.RUNTIME_PRESET,
            "execution_mode": app_config.EXECUTION_MODE,
            "sys_env": app_config.SYS_ENV,
        }
    )
    target.info("Application environment", extra=details)


def _clear_handlers(logger: logging.Logger) -> None:
    """Detach and close all handlers for *logger*."""

    for handler in list(logger.handlers):
        logger.removeHandler(handler)
        try:
            handler.close()
        except Exception:  # pragma: no cover - defensive close
            pass


def _detach_owned_filter(logger: logging.Logger) -> None:
    """Remove any gate filter previously attached by this module."""

    owned = getattr(logger, _FILTER_ATTR, None)
    if owned is None:
        return
    try:
        logger.removeFilter(owned)
    except ValueError:  # pragma: no cover - defensive cleanup
        pass
    try:
        delattr(logger, _FILTER_ATTR)
    except AttributeError:  # pragma: no cover - defensive cleanup
        pass


def _iter_androguard_loggers() -> tuple[logging.Logger, list[logging.Logger]]:
    """Return the base androguard logger and all instantiated descendants."""

    base_logger = logging.getLogger("androguard")
    discovered: dict[str, logging.Logger] = {"androguard": base_logger}

    for name, instance in logging.Logger.manager.loggerDict.items():
        if not name.startswith("androguard"):
            continue
        if isinstance(instance, logging.PlaceHolder):  # pragma: no cover - defensive
            logger = logging.getLogger(name)
        elif isinstance(instance, logging.Logger):
            logger = instance
        else:  # pragma: no cover - defensive
            continue
        discovered[name] = logger

    ordered = list(discovered.values())
    descendants = [logger for logger in ordered if logger is not base_logger]
    return base_logger, descendants


def _slugify(identifier: str) -> str:
    slug = re.sub(r"[^A-Za-z0-9_.-]+", "-", identifier.strip())
    slug = slug.strip("-")
    return slug or "run"


def create_harvest_run_logger(
    run_id: str,
    *,
    started_at: datetime | None = None,
    context: Mapping[str, object] | None = None,
) -> ContextAdapter:
    """Create a dedicated JSONL logger for the given harvest run."""

    if not run_id:
        raise ValueError("run_id must be provided for harvest logging")

    started = started_at or datetime.now(UTC)
    timestamp = started.astimezone(UTC).strftime("%Y%m%dT%H%M%SZ")
    slug = _slugify(run_id)
    json_filename = f"{timestamp}_run-{slug}.jsonl"
    text_filename = f"{timestamp}_run-{slug}.log"
    log_path = (LOG_DIR / _HARVEST_SUBDIR / json_filename).expanduser()
    text_path = (LOG_DIR / _HARVEST_SUBDIR / text_filename).expanduser()
    log_path.parent.mkdir(parents=True, exist_ok=True)

    logger_name = f"harvest.{slug}"
    logger = logging.getLogger(logger_name)
    for handler in list(logger.handlers):
        logger.removeHandler(handler)
        try:
            handler.close()
        except Exception:  # pragma: no cover - defensive cleanup
            pass

    handler = make_rotating_handler(
        log_path,
        max_bytes=10 * 1024 * 1024,
        backup_count=10,
        formatter=JsonFormatter(),
    )
    handler.setLevel(logging.DEBUG)

    text_handler = make_rotating_handler(
        text_path,
        max_bytes=10 * 1024 * 1024,
        backup_count=10,
        formatter=SafeFormatter(LOG_FORMAT, DATE_FORMAT),
    )
    text_handler.setLevel(logging.DEBUG)

    logger.setLevel(logging.DEBUG)
    logger.propagate = False
    logger.addHandler(handler)
    logger.addHandler(text_handler)

    base_extra: dict[str, object] = {
        "run_id": run_id,
        "log_path": str(log_path),
        "log_path_text": str(text_path),
        "run_started": started.isoformat(),
    }
    if context:
        base_extra.update({k: v for k, v in context.items() if v is not None})

    adapter = ContextAdapter(logger, base_extra)
    _HARVEST_LOGGERS[run_id] = adapter
    return adapter


def close_harvest_run_logger(run_id: str) -> None:
    """Close and dispose the harvest logger associated with *run_id*."""

    adapter = _HARVEST_LOGGERS.pop(run_id, None)
    if adapter is None:
        return

    logger = adapter.logger
    for handler in list(logger.handlers):
        logger.removeHandler(handler)
        try:
            handler.close()
        except Exception:  # pragma: no cover - defensive cleanup
            pass


def create_dynamic_run_logger(
    dynamic_run_id: str,
    *,
    started_at: datetime | None = None,
    context: Mapping[str, object] | None = None,
) -> ContextAdapter:
    """Create a dedicated text + JSONL logger for a dynamic analysis run."""

    if not dynamic_run_id:
        raise ValueError("dynamic_run_id must be provided for dynamic run logging")
    existing = _DYNAMIC_RUN_LOGGERS.get(dynamic_run_id)
    if existing is not None:
        return existing.adapter

    started = started_at or datetime.now(UTC)
    timestamp = started.astimezone(UTC).strftime("%Y%m%dT%H%M%SZ")
    slug = _slugify(dynamic_run_id)
    json_filename = f"{timestamp}_run-{slug}.jsonl"
    text_filename = f"{timestamp}_run-{slug}.log"
    log_path = (LOG_DIR / _DYNAMIC_SUBDIR / json_filename).expanduser()
    text_path = (LOG_DIR / _DYNAMIC_SUBDIR / text_filename).expanduser()
    log_path.parent.mkdir(parents=True, exist_ok=True)

    logger = get_logger("dynamic")

    handler = make_rotating_handler(
        log_path,
        max_bytes=10 * 1024 * 1024,
        backup_count=10,
        formatter=JsonFormatter(),
    )
    handler.setLevel(logging.DEBUG)

    text_handler = make_rotating_handler(
        text_path,
        max_bytes=10 * 1024 * 1024,
        backup_count=10,
        formatter=SafeFormatter(LOG_FORMAT, DATE_FORMAT),
    )
    text_handler.setLevel(logging.DEBUG)

    class _DynamicRunFilter(logging.Filter):
        def filter(self, record: logging.LogRecord) -> bool:  # pragma: no cover - simple predicate
            record_dynamic_run_id = getattr(record, "dynamic_run_id", None)
            record_run = getattr(record, "run_id", None)
            return record_dynamic_run_id == dynamic_run_id or record_run == dynamic_run_id

    run_filter = _DynamicRunFilter()
    handler.addFilter(run_filter)
    text_handler.addFilter(run_filter)
    logger.addHandler(handler)
    logger.addHandler(text_handler)

    base_extra: dict[str, object] = {
        "run_id": dynamic_run_id,
        "dynamic_run_id": dynamic_run_id,
        "log_path": str(log_path),
        "log_path_text": str(text_path),
        "run_started": started.isoformat(),
    }
    if context:
        base_extra.update({k: v for k, v in context.items() if v is not None})

    adapter = ContextAdapter(logger, base_extra)
    _DYNAMIC_RUN_LOGGERS[dynamic_run_id] = _SessionMirror(
        adapter=adapter,
        logger=logger,
        handlers=(handler, text_handler),
    )
    return adapter


def close_dynamic_run_logger(dynamic_run_id: str) -> None:
    """Close and dispose the dynamic run logger associated with *dynamic_run_id*."""

    mirror = _DYNAMIC_RUN_LOGGERS.pop(dynamic_run_id, None)
    if mirror is None:
        return

    for handler in mirror.handlers:
        try:
            mirror.logger.removeHandler(handler)
        except Exception:  # pragma: no cover - defensive cleanup
            pass
        try:
            handler.close()
        except Exception:  # pragma: no cover - defensive cleanup
            pass


def create_static_session_logger(
    session_stamp: str,
    *,
    started_at: datetime | None = None,
    context: Mapping[str, object] | None = None,
) -> ContextAdapter:
    """Create a dedicated text + JSONL logger for a static analysis session."""

    if not session_stamp:
        raise ValueError("session_stamp must be provided for static session logging")
    existing = _STATIC_SESSION_LOGGERS.get(session_stamp)
    if existing is not None:
        return existing.adapter

    started = started_at or datetime.now(UTC)
    timestamp = started.astimezone(UTC).strftime("%Y%m%dT%H%M%SZ")
    slug = _slugify(session_stamp)
    json_filename = f"{timestamp}_session-{slug}.jsonl"
    text_filename = f"{timestamp}_session-{slug}.log"
    log_path = (LOG_DIR / _STATIC_SUBDIR / json_filename).expanduser()
    text_path = (LOG_DIR / _STATIC_SUBDIR / text_filename).expanduser()
    log_path.parent.mkdir(parents=True, exist_ok=True)

    logger = get_logger("static")

    handler = make_rotating_handler(
        log_path,
        max_bytes=10 * 1024 * 1024,
        backup_count=10,
        formatter=JsonFormatter(),
    )
    handler.setLevel(logging.DEBUG)

    text_handler = make_rotating_handler(
        text_path,
        max_bytes=10 * 1024 * 1024,
        backup_count=10,
        formatter=SafeFormatter(LOG_FORMAT, DATE_FORMAT),
    )
    text_handler.setLevel(logging.DEBUG)

    class _StaticSessionFilter(logging.Filter):
        def filter(self, record: logging.LogRecord) -> bool:  # pragma: no cover - simple predicate
            record_session = getattr(record, "session_stamp", None)
            record_run = getattr(record, "run_id", None)
            return record_session == session_stamp or record_run == session_stamp

    session_filter = _StaticSessionFilter()
    handler.addFilter(session_filter)
    text_handler.addFilter(session_filter)
    logger.addHandler(handler)
    logger.addHandler(text_handler)

    base_extra: dict[str, object] = {
        "run_id": session_stamp,
        "session_stamp": session_stamp,
        "log_path": str(log_path),
        "log_path_text": str(text_path),
        "run_started": started.isoformat(),
    }
    if context:
        base_extra.update({k: v for k, v in context.items() if v is not None})

    adapter = ContextAdapter(logger, base_extra)
    _STATIC_SESSION_LOGGERS[session_stamp] = _SessionMirror(
        adapter=adapter,
        logger=logger,
        handlers=(handler, text_handler),
    )
    return adapter


def get_static_session_logger(session_stamp: str | None) -> ContextAdapter | None:
    """Return the dedicated static-session logger when one is active."""

    if not session_stamp:
        return None
    state = _STATIC_SESSION_LOGGERS.get(session_stamp)
    return state.adapter if state is not None else None


def close_static_session_logger(session_stamp: str) -> None:
    """Close and dispose the static-session logger associated with *session_stamp*."""

    state = _STATIC_SESSION_LOGGERS.pop(session_stamp, None)
    if state is None:
        return

    logger = state.logger
    for handler in state.handlers:
        logger.removeHandler(handler)
        try:
            handler.close()
        except Exception:  # pragma: no cover - defensive cleanup
            pass


def _configure_loguru(
    *, verbosity: str, log_path: Path | None, noise_filter: Callable[[str], bool]
) -> None:
    """Apply loguru gating that mirrors the python-logging behaviour."""

    if _loguru_logger is None:  # pragma: no cover - optional dependency
        return

    try:
        _loguru_logger.remove()
    except Exception:  # pragma: no cover - defensive cleanup
        pass

    target_attr = _LOGURU_FILTER_ATTR

    if hasattr(_loguru_logger, target_attr):
        try:
            delattr(_loguru_logger, target_attr)
        except Exception:  # pragma: no cover - defensive cleanup
            pass

    def _toggle(names: tuple[str, ...], action: str) -> None:
        for target in names:
            try:
                getattr(_loguru_logger, action)(target)
            except Exception:  # pragma: no cover - defensive
                pass

    namespaces = ("", "androguard", "androguard.core", "androguard.core.axml")

    if verbosity != "debug":
        _toggle(namespaces, "disable")

        def _sink(_: object) -> None:  # pragma: no cover - trivial sink
            return None

        try:
            _loguru_logger.add(_sink, level=1000)
        except Exception:  # pragma: no cover - defensive
            pass
        return

    _toggle(namespaces, "enable")

    if log_path is None:
        return

    def _loguru_filter(record: dict) -> bool:
        try:
            message = str(record.get("message", ""))
            name = str(record.get("name", ""))
        except Exception:  # pragma: no cover - defensive
            return False
        if not name.startswith("androguard"):
            return False
        return noise_filter(message)

    filter_handle = _loguru_filter
    setattr(_loguru_logger, target_attr, filter_handle)

    _loguru_logger.add(
        str(log_path),
        level="DEBUG",
        filter=filter_handle,
        format="{time:YYYY-MM-DD HH:mm:ss.SSS} {level:<8} {name}:{function}:{line} - {message}",
        enqueue=False,
        backtrace=False,
        diagnose=False,
    )


def configure_third_party_loggers(
    *,
    verbosity: str,
    run_id: str | None,
    debug_dir: str | None = None,
) -> Path | None:
    """Configure androguard logging based on the requested verbosity.

    Returns the path to the debug log file when running in debug mode, otherwise
    ``None``.
    """

    base_logger, descendants = _iter_androguard_loggers()
    all_loggers = [base_logger, *descendants]

    for logger in all_loggers:
        _clear_handlers(logger)
        _detach_owned_filter(logger)
        logger.disabled = False

    if verbosity not in {"detail", "debug", "normal"}:
        verbosity = "normal"

    root_logger = logging.getLogger()
    root_level = logging.DEBUG if verbosity == "debug" else logging.WARNING
    root_logger.setLevel(root_level)

    noise_filter = lambda message: not any(  # noqa: E731 - simple predicate
        snippet in message
        for snippet in (
            "get_resource_dimen",
            "Out of range dimension unit index",
            "invalid decoded string length",
        )
    )

    log_path: Path | None = None

    if verbosity != "debug":
        for logger in all_loggers:
            logger.setLevel(logging.ERROR)
            logger.propagate = False
            null_handler = logging.NullHandler()
            logger.addHandler(null_handler)
        _configure_loguru(verbosity=verbosity, log_path=None, noise_filter=noise_filter)
        return None

    base_logger.propagate = False
    for logger in descendants:
        logger.propagate = True
        logger.setLevel(logging.DEBUG)

    resolved_debug_dir = debug_dir
    if not resolved_debug_dir:
        default_root = LOG_DIR / "third_party"
        resolved_debug_dir = str(default_root)

    target_dir = Path(resolved_debug_dir).expanduser().resolve()
    target_dir.mkdir(parents=True, exist_ok=True)

    identifier = run_id or "session"
    log_path = target_dir / f"androguard.{identifier}.log"

    file_handler = logging.FileHandler(log_path, encoding="utf-8")
    file_handler.setLevel(logging.DEBUG)
    file_handler.setFormatter(
        logging.Formatter("%(asctime)s %(levelname)s %(name)s: %(message)s")
    )
    file_handler.addFilter(_AndroguardNoiseFilter())

    base_logger.setLevel(logging.DEBUG)
    base_logger.addHandler(file_handler)

    _configure_loguru(verbosity=verbosity, log_path=log_path, noise_filter=noise_filter)

    return log_path


__all__ = [
    "close_dynamic_run_logger",
    "close_harvest_run_logger",
    "close_static_session_logger",
    "LogTarget",
    "ContextAdapter",
    "bind_logger",
    "configure_third_party_loggers",
    "create_static_session_logger",
    "emit_environment_snapshot",
    "ensure_trace",
    "get_app_logger",
    "get_audit_logger",
    "get_db_logger",
    "get_device_logger",
    "get_dynamic_logger",
    "get_error_logger",
    "get_logger",
    "get_metrics_logger",
    "get_static_session_logger",
    "get_static_logger",
    "list_log_files",
    "create_dynamic_run_logger",
    "create_harvest_run_logger",
]
