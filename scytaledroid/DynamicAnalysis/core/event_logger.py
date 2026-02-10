"""Structured event logging for dynamic analysis runs."""

from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

from scytaledroid.DynamicAnalysis.core.manifest import ArtifactRecord
from scytaledroid.DynamicAnalysis.core.run_context import RunContext


@dataclass
class RunEvent:
    timestamp: str
    event_type: str
    details: dict[str, Any]


class RunEventLogger:
    def __init__(self, run_ctx: RunContext) -> None:
        self.run_ctx = run_ctx
        self.path = run_ctx.run_dir / "notes/run_events.jsonl"
        self.path.parent.mkdir(parents=True, exist_ok=True)

    def log(self, event_type: str, details: dict[str, Any] | None = None) -> None:
        payload = RunEvent(
            timestamp=self._now(),
            event_type=event_type,
            details=details or {},
        )
        with self.path.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(payload.__dict__, sort_keys=True) + "\n")

    def finalize(self) -> ArtifactRecord | None:
        if not self.path.exists():
            return None
        # Do not hash mutable logs inside the per-run manifest. Freeze-level
        # immutability uses included_run_checksums in the dataset freeze manifest.
        return ArtifactRecord(
            relative_path=str(self.path.relative_to(self.run_ctx.run_dir)),
            type="run_events",
            sha256=None,
            size_bytes=self.path.stat().st_size,
            produced_by="event_logger",
            origin="host",
            pull_status="n/a",
        )

    # Intentionally no hash_file here (run_events.jsonl is mutable).

    @staticmethod
    def _now() -> str:
        return datetime.now(UTC).isoformat()


__all__ = ["RunEvent", "RunEventLogger"]
