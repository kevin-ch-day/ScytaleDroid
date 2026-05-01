"""Pure run-spec builders for dynamic analysis (no IO, no prompts)."""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass


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
    # Operator protocol metadata (recorded in evidence pack for QA + stratified analysis).
    run_profile: str | None = None
    interaction_level: str | None = None
    messaging_activity: str | None = None
    # UI intent: whether the operator expects this run to count toward completion.
    # Final quota marking is computed at finalize-time by the dataset tracker.
    counts_toward_completion: bool | None = None
    # Frozen execution semantics: avoid env reads in execution paths.
    require_dynamic_schema: bool = True
    observer_prompts_enabled: bool = False
    # Secret for PCAPdroid capture (never persisted).
    pcapdroid_api_key: str | None = None


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
    run_profile: str | None = None,
    interaction_level: str | None = None,
    messaging_activity: str | None = None,
    counts_toward_completion: bool | None = None,
    require_dynamic_schema: bool = True,
    observer_prompts_enabled: bool = False,
    pcapdroid_api_key: str | None = None,
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
        run_profile=run_profile,
        interaction_level=interaction_level,
        messaging_activity=messaging_activity,
        counts_toward_completion=counts_toward_completion,
        require_dynamic_schema=require_dynamic_schema,
        observer_prompts_enabled=observer_prompts_enabled,
        pcapdroid_api_key=pcapdroid_api_key,
    )


__all__ = ["DynamicRunSpec", "build_dynamic_run_spec"]
