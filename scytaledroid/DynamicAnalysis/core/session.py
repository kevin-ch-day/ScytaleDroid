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
    probes: Sequence[str] = field(default_factory=tuple)


@dataclass
class DynamicSessionResult:
    package_name: str
    duration_seconds: int
    started_at: datetime
    ended_at: Optional[datetime] = None
    status: str = "pending"
    notes: Optional[str] = None
    errors: list[str] = field(default_factory=list)

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

