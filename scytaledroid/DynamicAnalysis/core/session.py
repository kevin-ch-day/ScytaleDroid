"""Session models for dynamic analysis."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Optional, Sequence


@dataclass(frozen=True)
class DynamicSessionConfig:
    package_name: str
    duration_seconds: int
    device_serial: Optional[str] = None
    tier: str = "baseline"
    static_run_id: Optional[int] = None
    harvest_session_id: Optional[int] = None
    plan_path: Optional[str] = None
    plan_validation: Optional[object] = None
    sampling_rate_s: int = 2
    probes: Sequence[str] = field(default_factory=tuple)
    scenario_id: str = "basic_usage"
    observer_ids: Sequence[str] = field(default_factory=tuple)
    interactive: bool = True
    output_root: Optional[str] = None
    clear_logcat: bool = True
    proxy_port: int = 8890


@dataclass
class DynamicSessionResult:
    package_name: str
    duration_seconds: int
    started_at: datetime
    ended_at: Optional[datetime] = None
    status: str = "pending"
    notes: Optional[str] = None
    errors: list[str] = field(default_factory=list)
    dynamic_run_id: Optional[str] = None
    evidence_path: Optional[str] = None
    telemetry_process: list[dict[str, object]] = field(default_factory=list)
    telemetry_network: list[dict[str, object]] = field(default_factory=list)
    telemetry_stats: dict[str, object] = field(default_factory=dict)

    @property
    def elapsed_seconds(self) -> Optional[int]:
        if not self.ended_at:
            return None
        return int((self.ended_at - self.started_at).total_seconds())


def make_session_result(config: DynamicSessionConfig) -> DynamicSessionResult:
    return DynamicSessionResult(
        package_name=config.package_name,
        duration_seconds=config.duration_seconds,
        started_at=datetime.now(timezone.utc),
    )
