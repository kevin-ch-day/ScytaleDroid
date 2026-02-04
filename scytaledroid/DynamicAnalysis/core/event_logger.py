"""Structured event logging for dynamic analysis runs."""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
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
        digest = self._hash_file(self.path)
        return ArtifactRecord(
            relative_path=str(self.path.relative_to(self.run_ctx.run_dir)),
            type="run_events",
            sha256=digest,
            size_bytes=self.path.stat().st_size,
            produced_by="event_logger",
        )

    def _hash_file(self, path: Path) -> str:
        hasher = hashlib.sha256()
        with path.open("rb") as handle:
            for chunk in iter(lambda: handle.read(8192), b""):
                hasher.update(chunk)
        return hasher.hexdigest()

    @staticmethod
    def _now() -> str:
        return datetime.now(UTC).isoformat()


__all__ = ["RunEvent", "RunEventLogger"]
