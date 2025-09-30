"""
logging_core.py - Core logging setup
"""

import logging
import logging.handlers
from pathlib import Path

from scytaledroid.Config import app_config


# Base log directory
LOG_DIR = Path("logs")
LOG_DIR.mkdir(parents=True, exist_ok=True)


# Standard formatter
LOG_FORMAT = "[%(asctime)s] [%(levelname)s] [%(name)s] %(message)s"
DATE_FORMAT = "%Y-%m-%d %H:%M:%S"


def setup_logger(
    name: str,
    log_file: str,
    level: int = logging.INFO,
    max_bytes: int = 5 * 1024 * 1024,
    backup_count: int = 5,
) -> logging.Logger:
    """
    Set up a rotating file logger with console output.

    Args:
        name: Logger name (e.g., "application", "device").
        log_file: File path (relative to logs/).
        level: Logging level (default: INFO).
        max_bytes: Max size per log file before rotation.
        backup_count: Number of rotated log files to keep.

    Returns:
        Configured logging.Logger instance.
    """
    logger = logging.getLogger(name)
    logger.setLevel(level)

    if logger.handlers:
        return logger  # Already configured

    # File handler (rotating)
    file_path = LOG_DIR / log_file
    file_handler = logging.handlers.RotatingFileHandler(
        file_path, maxBytes=max_bytes, backupCount=backup_count, encoding="utf-8"
    )
    file_handler.setFormatter(logging.Formatter(LOG_FORMAT, DATE_FORMAT))

    logger.addHandler(file_handler)

    if getattr(app_config, "ENABLE_CONSOLE_LOGS", False):
        console_handler = logging.StreamHandler()
        console_handler.setFormatter(logging.Formatter(LOG_FORMAT, DATE_FORMAT))
        logger.addHandler(console_handler)

    return logger
