"""Pure run-spec builders for dynamic analysis (no IO, no prompts)."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable


@dataclass(frozen=True)
class DynamicRunSpec:
    package_name: str
    device_serial: str
    observer_ids: tuple[str, ...]
    scenario_id: str
    tier: str
    duration_seconds: int
    plan_path: str | None
    static_run_id: int | None
    clear_logcat: bool
    interactive: bool = True
    batch_id: str | None = None


def build_dynamic_run_spec(
    *,
    package_name: str,
    device_serial: str,
    observer_ids: Iterable[str],
    scenario_id: str,
    tier: str,
    duration_seconds: int,
    plan_path: str | None,
    static_run_id: int | None,
    clear_logcat: bool,
    interactive: bool = True,
    batch_id: str | None = None,
) -> DynamicRunSpec:
    return DynamicRunSpec(
        package_name=package_name,
        device_serial=device_serial,
        observer_ids=tuple(observer_ids),
        scenario_id=scenario_id,
        tier=tier,
        duration_seconds=duration_seconds,
        plan_path=plan_path,
        static_run_id=static_run_id,
        clear_logcat=clear_logcat,
        interactive=interactive,
        batch_id=batch_id,
    )


__all__ = ["DynamicRunSpec", "build_dynamic_run_spec"]
