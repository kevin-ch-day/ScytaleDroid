"""Dynamic analysis entrypoints."""

from __future__ import annotations

from .core import DynamicSessionConfig, DynamicSessionResult
from .core.run_specs import DynamicRunSpec
from .engine import run_dynamic_engine


def run_dynamic_analysis(
    package_name: str,
    *,
    duration_seconds: int = 120,
    device_serial: str | None = None,
    scenario_id: str = "basic_usage",
    observer_ids: tuple[str, ...] = ("system_log_capture",),
    interactive: bool = True,
    output_root: str | None = None,
    plan_path: str | None = None,
    tier: str = "baseline",
    probes: tuple[str, ...] = (),
    static_run_id: int | None = None,
    harvest_session_id: int | None = None,
    clear_logcat: bool = True,
    proxy_port: int = 8890,
    sampling_rate_s: int = 2,
    batch_id: str | None = None,
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
        sampling_rate_s=sampling_rate_s,
        batch_id=batch_id,
    )
    engine_result = run_dynamic_engine(config)
    return engine_result.session


def execute_dynamic_run_spec(spec: DynamicRunSpec) -> DynamicSessionResult:
    return run_dynamic_analysis(
        spec.package_name,
        duration_seconds=spec.duration_seconds,
        device_serial=spec.device_serial,
        scenario_id=spec.scenario_id,
        observer_ids=spec.observer_ids,
        interactive=spec.interactive,
        plan_path=spec.plan_path,
        tier=spec.tier,
        static_run_id=spec.static_run_id,
        clear_logcat=spec.clear_logcat,
        batch_id=getattr(spec, "batch_id", None),
    )


__all__ = ["run_dynamic_analysis", "execute_dynamic_run_spec"]
