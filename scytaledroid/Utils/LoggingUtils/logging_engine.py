"""Utility helpers for configuring project loggers."""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Callable, Optional

from .logging_core import setup_logger

try:  # pragma: no cover - optional dependency
    from loguru import logger as _loguru_logger
except Exception:  # pragma: no cover - optional dependency
    _loguru_logger = None

# Define log file mapping
LOG_FILES = {
    "application": "application.log",
    "database": "database.log",
    "device": "device_analysis.log",
    "static": "static_analysis.log",
    "dynamic": "dynamic_analysis.log",
    "virustotal": "virus_total.log",
    "error": "error.log",
}

# Cache loggers so we don’t recreate them
_LOGGERS: dict[str, logging.Logger] = {}

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
    """
    Get a logger for a given category.
    Valid categories: application, database, device, static, dynamic, virustotal, error
    """
    if category not in LOG_FILES:
        raise ValueError(f"Unknown log category: {category}")

    if category not in _LOGGERS:
        _LOGGERS[category] = setup_logger(category, LOG_FILES[category])

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


def get_vt_logger() -> logging.Logger:
    return get_logger("virustotal")


def get_error_logger() -> logging.Logger:
    return get_logger("error")


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


def _configure_loguru(
    *, verbosity: str, log_path: Optional[Path], noise_filter: Callable[[str], bool]
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

    if verbosity != "debug":
        try:
            _loguru_logger.disable("")
        except Exception:  # pragma: no cover - defensive
            pass

        def _sink(_: object) -> None:  # pragma: no cover - trivial sink
            return None

        try:
            _loguru_logger.add(_sink, level=1000)
        except Exception:  # pragma: no cover - defensive
            pass
        return

    try:
        _loguru_logger.enable("")
    except Exception:  # pragma: no cover - defensive
        pass

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
    run_id: Optional[str],
    debug_dir: str,
) -> Optional[Path]:
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

    noise_filter = lambda message: not any(  # noqa: E731 - simple predicate
        snippet in message
        for snippet in (
            "get_resource_dimen",
            "Out of range dimension unit index",
            "invalid decoded string length",
        )
    )

    log_path: Optional[Path] = None

    if verbosity != "debug":
        for logger in all_loggers:
            logger.setLevel(logging.CRITICAL)
            logger.propagate = False
            logger.disabled = True
            logger.addHandler(logging.NullHandler())
        _configure_loguru(verbosity=verbosity, log_path=None, noise_filter=noise_filter)
        return None

    base_logger.propagate = False
    for logger in descendants:
        logger.propagate = True

    target_dir = Path(debug_dir).expanduser().resolve()
    target_dir.mkdir(parents=True, exist_ok=True)

    identifier = run_id or "session"
    log_path = target_dir / f"androguard.{identifier}.log"

    file_handler = logging.FileHandler(log_path, encoding="utf-8")
    file_handler.setLevel(logging.DEBUG)
    file_handler.setFormatter(
        logging.Formatter("%(asctime)s %(levelname)s %(name)s: %(message)s")
    )
    file_handler.addFilter(_AndroguardNoiseFilter())

    base_logger.addHandler(file_handler)

    for logger in all_loggers:
        logger.setLevel(logging.DEBUG)

    _configure_loguru(verbosity=verbosity, log_path=log_path, noise_filter=noise_filter)

    return log_path


__all__ = [
    "configure_third_party_loggers",
    "get_app_logger",
    "get_db_logger",
    "get_device_logger",
    "get_dynamic_logger",
    "get_error_logger",
    "get_logger",
    "get_static_logger",
    "get_vt_logger",
]
