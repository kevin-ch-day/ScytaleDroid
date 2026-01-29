"""Dynamic analysis entrypoints."""

from __future__ import annotations

from .core import DynamicSessionConfig, DynamicSessionResult
from .engine import run_dynamic_engine


def run_dynamic_analysis(
    package_name: str,
    *,
    duration_seconds: int = 120,
    device_serial: str | None = None,
    scenario_id: str = "basic_usage",
    observer_ids: tuple[str, ...] = ("proxy_capture", "system_log_capture"),
    interactive: bool = True,
    output_root: str | None = None,
    plan_path: str | None = None,
    tier: str = "baseline",
    probes: tuple[str, ...] = (),
    static_run_id: int | None = None,
    harvest_session_id: int | None = None,
    clear_logcat: bool = True,
    proxy_port: int = 8890,
) -> DynamicSessionResult:
    config = DynamicSessionConfig(
        package_name=package_name,
        duration_seconds=duration_seconds,
        device_serial=device_serial,
        scenario_id=scenario_id,
        observer_ids=observer_ids,
        interactive=interactive,
        output_root=output_root,
        plan_path=plan_path,
        tier=tier,
        probes=probes,
        static_run_id=static_run_id,
        harvest_session_id=harvest_session_id,
        clear_logcat=clear_logcat,
        proxy_port=proxy_port,
    )
    engine_result = run_dynamic_engine(config)
    return engine_result.session


__all__ = ["run_dynamic_analysis"]
