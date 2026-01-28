"""Dynamic analysis runner scaffolding."""

from __future__ import annotations

from datetime import datetime, timezone

from scytaledroid.Utils.LoggingUtils import logging_engine

from scytaledroid.DynamicAnalysis.core.orchestrator import DynamicRunOrchestrator
from scytaledroid.DynamicAnalysis.observers import NetworkCaptureObserver, SystemLogObserver

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
    observer_ids = set(config.observer_ids or ("network_capture", "system_log_capture"))
    observers = []
    if "network_capture" in observer_ids:
        observers.append(NetworkCaptureObserver())
    if "system_log_capture" in observer_ids:
        observers.append(SystemLogObserver())

    orchestrator = DynamicRunOrchestrator(config, observers=observers)
    manifest, run_dir = orchestrator.run()
    result.status = manifest.status
    if manifest.ended_at:
        result.ended_at = datetime.fromisoformat(manifest.ended_at)
    else:
        result.ended_at = datetime.now(timezone.utc)
    result.notes = f"Dynamic run captured at {run_dir}."
    result.dynamic_run_id = manifest.dynamic_run_id
    result.evidence_path = str(run_dir)
    return result
