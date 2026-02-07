"""Session models for dynamic analysis."""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass, field
from datetime import UTC, datetime


@dataclass(frozen=True)
class DynamicSessionConfig:
    package_name: str
    duration_seconds: int
    device_serial: str | None = None
    tier: str = "baseline"
    static_run_id: int | None = None
    harvest_session_id: int | None = None
    plan_path: str | None = None
    plan_validation: object | None = None
    sampling_rate_s: int = 2
    probes: Sequence[str] = field(default_factory=tuple)
    scenario_id: str = "basic_usage"
    observer_ids: Sequence[str] = field(default_factory=tuple)
    interactive: bool = True
    output_root: str | None = None
    clear_logcat: bool = True
    proxy_port: int = 8890
    enable_monitor: bool = False
    monitor_verbose: bool = False
    batch_id: str | None = None
    # Paper-grade/reproducibility rule: env vars influence defaults only at entrypoint.
    # Downstream modules must rely on this frozen flag, not os.getenv().
    require_dynamic_schema: bool = True


@dataclass
class DynamicSessionResult:
    package_name: str
    duration_seconds: int
    started_at: datetime
    ended_at: datetime | None = None
    status: str = "pending"
    notes: str | None = None
    errors: list[str] = field(default_factory=list)
    dynamic_run_id: str | None = None
    evidence_path: str | None = None
    telemetry_process: list[dict[str, object]] = field(default_factory=list)
    telemetry_network: list[dict[str, object]] = field(default_factory=list)
    telemetry_stats: dict[str, object] = field(default_factory=dict)

    @property
    def elapsed_seconds(self) -> int | None:
        if not self.ended_at:
            return None
        return int((self.ended_at - self.started_at).total_seconds())


def make_session_result(config: DynamicSessionConfig) -> DynamicSessionResult:
    return DynamicSessionResult(
        package_name=config.package_name,
        duration_seconds=config.duration_seconds,
        started_at=datetime.now(UTC),
    )
