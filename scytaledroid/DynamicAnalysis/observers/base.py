"""Observer contracts for dynamic analysis."""

from __future__ import annotations

from dataclasses import dataclass

from scytaledroid.DynamicAnalysis.core.manifest import ArtifactRecord
from scytaledroid.DynamicAnalysis.core.run_context import RunContext


@dataclass(frozen=True)
class ObserverHandle:
    observer_id: str
    payload: object | None = None


@dataclass(frozen=True)
class ObserverResult:
    observer_id: str
    status: str
    error: str | None
    artifacts: list[ArtifactRecord]


class Observer:
    observer_id: str
    observer_name: str

    def start(self, run_ctx: RunContext) -> ObserverHandle:
        raise NotImplementedError

    def stop(self, handle: ObserverHandle | None, run_ctx: RunContext) -> ObserverResult:
        raise NotImplementedError


__all__ = ["Observer", "ObserverHandle", "ObserverResult"]
