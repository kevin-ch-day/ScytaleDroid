"""Dynamic analysis runner scaffolding."""

from __future__ import annotations

from datetime import UTC, datetime

from scytaledroid.DynamicAnalysis.core.orchestrator import DynamicRunOrchestrator
from scytaledroid.DynamicAnalysis.observers import (
    NetworkCaptureObserver,
    PcapdroidCaptureObserver,
    ProxyCaptureObserver,
    SystemLogObserver,
)
from scytaledroid.DynamicAnalysis.plans.loader import (
    PlanValidationError,
    build_plan_validation_event,
)
from scytaledroid.Utils.LoggingUtils import logging_engine

from .session import DynamicSessionConfig, DynamicSessionResult, make_session_result


def run_dynamic_session(
    config: DynamicSessionConfig,
    *,
    plan_payload: dict[str, object] | None = None,
) -> DynamicSessionResult:
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
    observer_ids = set(config.observer_ids or ("system_log_capture",))
    observers = []
    if "proxy_capture" in observer_ids:
        observers.append(ProxyCaptureObserver())
    if "network_capture" in observer_ids:
        observers.append(NetworkCaptureObserver())
    if "pcapdroid_capture" in observer_ids:
        observers.append(PcapdroidCaptureObserver())
    if "system_log_capture" in observer_ids:
        observers.append(SystemLogObserver())

    orchestrator = DynamicRunOrchestrator(config, observers=observers, plan_payload=plan_payload)
    try:
        manifest, run_dir, telemetry_payload = orchestrator.run()
    except PlanValidationError as exc:
        result.status = "blocked"
        result.errors = list(exc.outcome.reasons) if exc.outcome.reasons else ["dynamic plan validation failed"]
        result.notes = "Dynamic execution blocked by plan validation."
        result.ended_at = datetime.now(UTC)
        logger.warning(
            "Dynamic plan validation blocked run",
            extra=build_plan_validation_event(exc.outcome),
        )
        return result
    result.status = manifest.status
    if manifest.ended_at:
        result.ended_at = datetime.fromisoformat(manifest.ended_at)
    else:
        result.ended_at = datetime.now(UTC)
    result.notes = f"Dynamic run captured at {run_dir}."
    result.dynamic_run_id = manifest.dynamic_run_id
    result.evidence_path = str(run_dir)
    if telemetry_payload:
        result.telemetry_process = list(telemetry_payload.get("telemetry_process") or [])
        result.telemetry_network = list(telemetry_payload.get("telemetry_network") or [])
        result.telemetry_stats = dict(telemetry_payload.get("telemetry_stats") or {})
        for key in (
            "host_time_utc_start",
            "host_time_utc_end",
            "device_time_utc_start",
            "device_time_utc_end",
            "device_uptime_ms_start",
            "device_uptime_ms_end",
            "drift_ms_start",
            "drift_ms_end",
        ):
            if key in telemetry_payload:
                result.telemetry_stats[key] = telemetry_payload[key]
    return result
