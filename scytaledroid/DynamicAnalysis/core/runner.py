"""Dynamic analysis runner scaffolding."""

from __future__ import annotations

from datetime import datetime, timezone

from scytaledroid.Utils.LoggingUtils import logging_engine

from .session import DynamicSessionConfig, DynamicSessionResult, make_session_result


def run_dynamic_session(config: DynamicSessionConfig) -> DynamicSessionResult:
    logger = logging_engine.get_dynamic_logger()
    result = make_session_result(config)
    logger.info(
        "Dynamic session start",
        extra={
            "package_name": config.package_name,
            "duration_seconds": config.duration_seconds,
            "device_serial": config.device_serial,
            "tier": config.tier,
        },
    )
    result.status = "not_implemented"
    result.ended_at = datetime.now(timezone.utc)
    result.notes = "Dynamic analysis runner not implemented yet."
    logger.warning(
        "Dynamic session not implemented",
        extra={
            "package_name": config.package_name,
            "duration_seconds": config.duration_seconds,
        },
    )
    return result
