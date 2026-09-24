"""Structured event logging for dynamic analysis runs."""

from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from scytaledroid.DynamicAnalysis.core.manifest import ArtifactRecord
from scytaledroid.DynamicAnalysis.core.run_context import RunContext
from scytaledroid.DynamicAnalysis.utils.path_utils import (
    artifact_relative_path,
    resolve_contained_path,
)


@dataclass
class RunEvent:
    timestamp: str
    event_type: str
    details: dict[str, Any]


class RunEventLogger:
    def __init__(self, run_ctx: RunContext) -> None:
        self.run_ctx = run_ctx
        self.path = resolve_contained_path(run_ctx.run_dir, "notes/run_events.jsonl")
        if self.path is None:
            raise ValueError("Event log must remain inside the evidence run directory")
        self.path.parent.mkdir(parents=True, exist_ok=True)

    def log(self, event_type: str, details: dict[str, Any] | None = None) -> None:
        append_run_event(self.run_ctx.run_dir, event_type, details)

    def finalize(self) -> ArtifactRecord | None:
        if not self.path.exists():
            return None
        # Defer hashing until canonical final sealing. Later events are routed
        # to a separate postseal sidecar and cannot change this retained log.
        return ArtifactRecord(
            relative_path=artifact_relative_path(self.run_ctx.run_dir, self.path),
            type="run_events",
            sha256=None,
            size_bytes=self.path.stat().st_size,
            produced_by="event_logger",
            origin="host",
            pull_status="n/a",
        )

    # V2 final sealer owns hashing; producers do not duplicate that rule.

    @staticmethod
    def _now() -> str:
        return datetime.now(UTC).isoformat()


def append_run_event(
    run_dir: Path,
    event_type: str,
    details: dict[str, Any] | None = None,
) -> None:
    payload = RunEvent(
        timestamp=RunEventLogger._now(),
        event_type=event_type,
        details=details or {},
    )
    # Once sealed, operational logging must not mutate canonical evidence.
    if (run_dir / "run_manifest.json").exists():
        run_dir = run_dir.parent / (run_dir.name + ".postseal")
    path = resolve_contained_path(run_dir, "notes/run_events.jsonl")
    if path is None:
        return
    # Best-effort logging: evidence-pack deletion mid-run (e.g. an operator
    # pruning "incomplete" dirs in another terminal) must not hard-crash a run.
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(payload.__dict__, sort_keys=True) + "\n")
    except OSError:
        return


__all__ = ["RunEvent", "RunEventLogger", "append_run_event"]
