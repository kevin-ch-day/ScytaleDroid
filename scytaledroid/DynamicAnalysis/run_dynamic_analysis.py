"""Dynamic analysis entrypoints."""

from __future__ import annotations

from .core import DynamicSessionConfig, DynamicSessionResult, run_dynamic_session


def run_dynamic_analysis(
    package_name: str,
    *,
    duration_seconds: int = 120,
    device_serial: str | None = None,
    scenario_id: str = "basic_usage",
    observer_ids: tuple[str, ...] = ("network_capture", "system_log_capture"),
    interactive: bool = True,
    output_root: str | None = None,
    plan_path: str | None = None,
    tier: str = "baseline",
    probes: tuple[str, ...] = (),
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
    )
    return run_dynamic_session(config)


__all__ = ["run_dynamic_analysis"]
