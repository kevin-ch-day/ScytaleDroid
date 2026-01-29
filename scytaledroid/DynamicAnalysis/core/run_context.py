"""Run context for dynamic analysis orchestration."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class RunContext:
    dynamic_run_id: str
    package_name: str
    duration_seconds: int
    scenario_id: str
    run_dir: Path
    artifacts_dir: Path
    analysis_dir: Path
    notes_dir: Path
    interactive: bool
    device_serial: str | None = None
    clear_logcat: bool = True
    static_run_id: int | None = None
    harvest_session_id: int | None = None
    static_plan: dict[str, object] | None = None
    proxy_port: int = 8890
    scenario_hint: str | None = None


__all__ = ["RunContext"]
