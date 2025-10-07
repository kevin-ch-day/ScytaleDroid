"""Utility helpers for configuring project loggers."""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Optional

from .logging_core import setup_logger

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

    logger = logging.getLogger("androguard")
    logger.propagate = False

    _clear_handlers(logger)

    if verbosity not in {"detail", "debug", "normal"}:
        verbosity = "normal"

    if verbosity != "debug":
        logger.setLevel(logging.WARNING)
        return None

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

    logger.addHandler(file_handler)
    logger.setLevel(logging.DEBUG)

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
