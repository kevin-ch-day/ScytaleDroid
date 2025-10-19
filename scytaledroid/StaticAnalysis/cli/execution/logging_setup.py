"""Logging configuration helpers for the CLI runs."""

from __future__ import annotations

import logging
from pathlib import Path

from scytaledroid.Config import app_config
from scytaledroid.Utils.LoggingUtils import logging_utils as log
from scytaledroid.Utils.LoggingUtils.logging_engine import configure_third_party_loggers


def configure_logging_for_cli(level: str) -> None:
    """Normalise CLI logging level and configure downstream libraries."""

    level = (level or "").strip().lower()
    if level not in {"debug", "info"}:
        level = "info"

    verbosity = "debug" if level == "debug" else "normal"
    debug_dir = getattr(log, "LOGS_DIR", app_config.LOGS_DIR)
    debug_dir_str = str(Path(debug_dir).resolve()) if debug_dir else None
    configure_third_party_loggers(
        verbosity=verbosity,
        run_id="cli",
        debug_dir=debug_dir_str,
    )

    root_level = logging.DEBUG if level == "debug" else logging.INFO
    logging.getLogger().setLevel(root_level)

    androguard_level = logging.DEBUG if level == "debug" else logging.ERROR
    for name in ("androguard", "androguard.core", "androguard.core.axml"):
        logging.getLogger(name).setLevel(androguard_level)

    quiet_level = logging.DEBUG if level == "debug" else logging.WARNING
    for name in ("zipfile", "urllib3"):
        logging.getLogger(name).setLevel(quiet_level)


__all__ = ["configure_logging_for_cli"]

