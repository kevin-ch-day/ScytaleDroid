"""Core helpers for consistent logging configuration.

This module consolidates all handler/formatter creation logic so each logging
category shares the same behaviour.  The updated implementation introduces a
structured JSON log alongside the traditional line formatter, automatic log
directory management and gzip compression for rotated log archives.
"""

from __future__ import annotations

import gzip
import json
import logging
import logging.handlers
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, Mapping, MutableMapping, Optional

from scytaledroid.Config import app_config

# Base log directory resolved from configuration so tests can override it.
LOG_DIR = Path(getattr(app_config, "LOGS_DIR", "logs")).expanduser()


def _ensure_log_dir(path: Optional[Path] = None) -> Path:
    """Ensure that the base log directory and optional *path* parents exist."""

    LOG_DIR.mkdir(parents=True, exist_ok=True)
    if path is not None:
        path.parent.mkdir(parents=True, exist_ok=True)
        return path
    return LOG_DIR


# Standard formatter used for human readable logs and console output.
LOG_FORMAT = (
    "[%(asctime)s] [%(levelname)s] [%(name)s] %(message)s"
    "%(extra_suffix)s"
)
DATE_FORMAT = "%Y-%m-%d %H:%M:%S"


def _serialize_extra(record: logging.LogRecord) -> Dict[str, Any]:
    """Return a serialisable copy of ``record`` extras.

    ``logging`` stores standard attributes in ``LogRecord.__dict__`` alongside
    arbitrary ``extra`` values.  The helper strips the standard keys and
    redacts sensitive values before returning a clean mapping that can be
    attached to either the JSON or human readable output.
    """

    standard = {
        "args",
        "asctime",
        "created",
        "exc_info",
        "exc_text",
        "filename",
        "funcName",
        "levelname",
        "levelno",
        "lineno",
        "module",
        "msecs",
        "message",
        "msg",
        "name",
        "pathname",
        "process",
        "processName",
        "relativeCreated",
        "stack_info",
        "thread",
        "threadName",
        "extra_suffix",
    }

    payload: Dict[str, Any] = {}
    for key, value in record.__dict__.items():
        if key in standard:
            continue
        payload[key] = value
    return _redact(payload)


SENSITIVE_KEYS = {
    "api_key",
    "auth",
    "authorization",
    "password",
    "secret",
    "token",
}


def _redact(value: Any) -> Any:
    """Recursively redact values for sensitive keys in mapping containers."""

    if isinstance(value, Mapping):
        redacted: MutableMapping[str, Any] = type(value)()
        for key, val in value.items():
            if str(key).lower() in SENSITIVE_KEYS:
                redacted[key] = "***REDACTED***"
            else:
                redacted[key] = _redact(val)
        return redacted
    if isinstance(value, (list, tuple, set)):
        factory = type(value)
        return factory(_redact(item) for item in value)
    if isinstance(value, (str, int, float, bool)) or value is None:
        return value
    return str(value)


class JsonFormatter(logging.Formatter):
    """Formatter that emits structured JSON for downstream tooling."""

    def format(self, record: logging.LogRecord) -> str:  # pragma: no cover - thin
        data: Dict[str, Any] = {
            "ts": datetime.fromtimestamp(record.created, tz=timezone.utc).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
        }

        extras = _serialize_extra(record)
        if extras:
            data.update(extras)

        if record.exc_info:
            data["stack"] = self.formatException(record.exc_info)

        return json.dumps(data, ensure_ascii=False)


def _gzip_rotator(source: str, dest: str) -> None:  # pragma: no cover - filesystem
    """Compress rotated log files using gzip for compact retention."""

    with open(source, "rb") as src, gzip.open(dest, "wb") as dst:
        dst.writelines(src)
    os.remove(source)


def _make_rotating_handler(
    path: Path,
    *,
    max_bytes: int,
    backup_count: int,
    formatter: logging.Formatter,
) -> logging.Handler:
    """Create a rotating handler with gzip compression for archives."""

    _ensure_log_dir(path)
    handler = logging.handlers.RotatingFileHandler(
        path,
        maxBytes=max_bytes,
        backupCount=backup_count,
        encoding="utf-8",
    )

    handler.setFormatter(formatter)
    handler.namer = lambda name: f"{name}.gz"
    handler.rotator = _gzip_rotator
    return handler


def _format_suffix(extras: Mapping[str, Any]) -> str:
    if not extras:
        return ""
    serialised = ", ".join(f"{key}={value}" for key, value in sorted(extras.items()))
    return f" | {serialised}"


def _prepare_handlers(
    *,
    level: int,
    max_bytes: int,
    backup_count: int,
    text_path: Optional[Path] = None,
    json_path: Optional[Path] = None,
) -> Iterable[logging.Handler]:
    text_formatter = logging.Formatter(LOG_FORMAT, DATE_FORMAT)
    json_formatter = JsonFormatter()

    handlers: list[logging.Handler] = []

    if text_path is not None:
        handlers.append(
            _make_rotating_handler(
                text_path,
                max_bytes=max_bytes,
                backup_count=backup_count,
                formatter=text_formatter,
            )
        )

    if json_path is not None:
        handlers.append(
            _make_rotating_handler(
                json_path,
                max_bytes=max_bytes,
                backup_count=backup_count,
                formatter=json_formatter,
            )
        )

    for handler in handlers:
        handler.setLevel(level)

    return handlers


def setup_logger(
    name: str,
    *,
    text_file: Optional[str] = None,
    json_file: Optional[str] = None,
    subdir: Optional[str] = None,
    level: int = logging.INFO,
    max_bytes: int = 10 * 1024 * 1024,
    backup_count: int = 10,
) -> logging.Logger:
    """Return a logger pre-configured with rotating text/JSON handlers."""

    if text_file is None and json_file is None:
        raise ValueError("At least one of text_file/json_file must be provided")

    logger = logging.getLogger(name)
    if logger.handlers:
        logger.setLevel(level)
        return logger

    base_dir = LOG_DIR
    if subdir:
        base_dir = _ensure_log_dir(LOG_DIR / subdir)
    else:
        _ensure_log_dir()

    text_path = base_dir / text_file if text_file else None
    json_path = base_dir / json_file if json_file else None

    for handler in _prepare_handlers(
        level=level,
        max_bytes=max_bytes,
        backup_count=backup_count,
        text_path=text_path,
        json_path=json_path,
    ):
        logger.addHandler(handler)

    if getattr(app_config, "ENABLE_CONSOLE_LOGS", False) and text_file is not None:
        console_handler = logging.StreamHandler()
        console_handler.setLevel(level)
        console_handler.setFormatter(logging.Formatter(LOG_FORMAT, DATE_FORMAT))
        logger.addHandler(console_handler)

    logger.setLevel(level)
    logger.addFilter(_ExtraSuffixFilter())
    return logger


class _ExtraSuffixFilter(logging.Filter):
    """Inject a string representation of contextual extras for text logs."""

    def filter(self, record: logging.LogRecord) -> bool:  # pragma: no cover - trivial
        extras = _serialize_extra(record)
        record.extra_suffix = _format_suffix(extras)
        return True


__all__ = [
    "JsonFormatter",
    "setup_logger",
]
