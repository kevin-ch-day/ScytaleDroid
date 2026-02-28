"""Core dynamic analysis session primitives.

This package has legitimate internal dependency cycles (analysis <-> core) and also
optional heavyweight deps upstream (ml). Avoid importing the whole orchestrator stack
at package import time; provide lazy attribute access for legacy imports.
"""

from __future__ import annotations

from typing import Any

__all__ = [
    "ArtifactRecord",
    "DynamicRunOrchestrator",
    "DynamicSessionConfig",
    "DynamicSessionResult",
    "ObserverRecord",
    "RunManifest",
    "RunEvent",
    "RunEventLogger",
    "TargetManager",
    "TargetSnapshot",
    "run_dynamic_session",
]


def __getattr__(name: str) -> Any:  # pragma: no cover - import-time shim
    if name in {"RunEvent", "RunEventLogger"}:
        from .event_logger import RunEvent, RunEventLogger

        return {"RunEvent": RunEvent, "RunEventLogger": RunEventLogger}[name]
    if name in {"ArtifactRecord", "ObserverRecord", "RunManifest"}:
        from .manifest import ArtifactRecord, ObserverRecord, RunManifest

        return {"ArtifactRecord": ArtifactRecord, "ObserverRecord": ObserverRecord, "RunManifest": RunManifest}[name]
    if name in {"TargetManager", "TargetSnapshot"}:
        from .target_manager import TargetManager, TargetSnapshot

        return {"TargetManager": TargetManager, "TargetSnapshot": TargetSnapshot}[name]
    if name in {"DynamicSessionConfig", "DynamicSessionResult"}:
        from .session import DynamicSessionConfig, DynamicSessionResult

        return {"DynamicSessionConfig": DynamicSessionConfig, "DynamicSessionResult": DynamicSessionResult}[name]
    if name == "DynamicRunOrchestrator":
        from .orchestrator import DynamicRunOrchestrator

        return DynamicRunOrchestrator
    if name == "run_dynamic_session":
        from .runner import run_dynamic_session

        return run_dynamic_session
    raise AttributeError(name)

