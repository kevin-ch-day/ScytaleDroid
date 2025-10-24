"""Developer friendly logging facade with contextual helpers."""

from __future__ import annotations

import logging
from datetime import datetime
from typing import Mapping, MutableMapping, Optional

from . import logging_engine


def _coerce_extra(extra: Optional[Mapping[str, object]]) -> MutableMapping[str, object]:
    payload = logging_engine.ensure_trace(extra)
    return payload


def _get_logger(category: str) -> logging.Logger:
    """Return the logger for the given category, defaulting to application."""

    try:
        return logging_engine.get_logger(category)
    except ValueError:
        return logging_engine.get_app_logger()


def debug(message: str, category: str = "application", *, extra: Optional[Mapping[str, object]] = None) -> None:
    """Log a DEBUG message with optional structured context."""

    logger = _get_logger(category)
    logger.debug(message, extra=_coerce_extra(extra))


def info(message: str, category: str = "application", *, extra: Optional[Mapping[str, object]] = None) -> None:
    """Log an INFO message with optional structured context."""

    logger = _get_logger(category)
    logger.info(message, extra=_coerce_extra(extra))


def warning(message: str, category: str = "application", *, extra: Optional[Mapping[str, object]] = None) -> None:
    """Log a WARNING message with optional structured context."""

    logger = _get_logger(category)
    logger.warning(message, extra=_coerce_extra(extra))


def error(message: str, category: str = "application", *, extra: Optional[Mapping[str, object]] = None) -> None:
    """Log an ERROR message and also send it to error.log."""

    payload = _coerce_extra(extra)
    logger = _get_logger(category)
    logger.error(message, extra=payload)

    err_logger = logging_engine.get_error_logger()
    if logger is not err_logger:
        err_payload = dict(payload)
        err_payload.setdefault("source_category", category)
        err_logger.error(f"[{category.upper()}] {message}", extra=err_payload)


def critical(message: str, category: str = "application", *, extra: Optional[Mapping[str, object]] = None) -> None:
    """Log a CRITICAL message and also send it to error.log."""

    payload = _coerce_extra(extra)
    logger = _get_logger(category)
    logger.critical(message, extra=payload)

    err_logger = logging_engine.get_error_logger()
    if logger is not err_logger:
        err_payload = dict(payload)
        err_payload.setdefault("source_category", category)
        err_logger.critical(f"[{category.upper()}] {message}", extra=err_payload)


def bind(category: str = "application", **context: object) -> logging_engine.ContextAdapter:
    """Return a contextual logger adapter for repetitive structured logging."""

    return logging_engine.bind_logger(category, **context)


def harvest_adapter(
    run_id: str,
    *,
    started_at: Optional[datetime] = None,
    context: Optional[Mapping[str, object]] = None,
) -> logging_engine.ContextAdapter:
    """Return a per-run harvest logger bound to ``run_id``."""

    base_context = dict(context or {})
    return logging_engine.create_harvest_run_logger(
        run_id,
        started_at=started_at,
        context=base_context,
    )


def close_harvest_adapter(run_id: str) -> None:
    """Close the harvest logger associated with ``run_id``."""

    logging_engine.close_harvest_run_logger(run_id)


__all__ = [
    "close_harvest_adapter",
    "bind",
    "critical",
    "debug",
    "error",
    "info",
    "harvest_adapter",
    "warning",
]
