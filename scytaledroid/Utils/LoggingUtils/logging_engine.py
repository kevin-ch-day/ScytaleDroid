"""
logging_engine.py - Preconfigured loggers for subsystems
"""

import logging
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
