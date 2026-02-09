"""Helpers for resolving evidence pack paths."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class EvidencePackPaths:
    run_dir: Path
    artifacts_dir: Path
    analysis_dir: Path
    notes_dir: Path

    @classmethod
    def from_run_dir(cls, run_dir: Path) -> "EvidencePackPaths":
        return cls(
            run_dir=run_dir,
            artifacts_dir=run_dir / "artifacts",
            analysis_dir=run_dir / "analysis",
            notes_dir=run_dir / "notes",
        )
