"""
logging_utils.py - Developer-friendly logging API
"""

import logging
from . import logging_engine


def _get_logger(category: str) -> logging.Logger:
    """Return the logger for the given category, default to application."""
    try:
        return logging_engine.get_logger(category)
    except ValueError:
        return logging_engine.get_app_logger()


def debug(message: str, category: str = "application") -> None:
    """Log a DEBUG message."""
    logger = _get_logger(category)
    logger.debug(message)


def info(message: str, category: str = "application") -> None:
    """Log an INFO message."""
    logger = _get_logger(category)
    logger.info(message)


def warning(message: str, category: str = "application") -> None:
    """Log a WARNING message."""
    logger = _get_logger(category)
    logger.warning(message)


def error(message: str, category: str = "application") -> None:
    """Log an ERROR message and also send it to error.log."""
    logger = _get_logger(category)
    logger.error(message)

    # Always log to error.log as well
    err_logger = logging_engine.get_error_logger()
    if logger != err_logger:
        err_logger.error(f"[{category.upper()}] {message}")


def critical(message: str, category: str = "application") -> None:
    """Log a CRITICAL message and also send it to error.log."""
    logger = _get_logger(category)
    logger.critical(message)

    # Always log to error.log as well
    err_logger = logging_engine.get_error_logger()
    if logger != err_logger:
        err_logger.critical(f"[{category.upper()}] {message}")
