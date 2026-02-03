"""Path helpers for dynamic analysis."""

from __future__ import annotations

from pathlib import Path

from scytaledroid.Config import app_config


def resolve_evidence_path(evidence_path: str | None) -> Path | None:
    if not evidence_path:
        return None
    path = Path(evidence_path)
    if path.is_absolute():
        return path
    candidate = Path.cwd() / path
    if candidate.exists():
        return candidate
    output_root = Path(app_config.OUTPUT_DIR)
    output_candidate = output_root / path
    if output_candidate.exists():
        return output_candidate
    return candidate


__all__ = ["resolve_evidence_path"]
