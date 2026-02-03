"""Structured rejection report helper."""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any


@dataclass(frozen=True)
class FailedCheck:
    name: str
    observed: str
    expected: str
    evidence: dict[str, Any]
    remediation_hint: str


def write_rejection_report(
    *,
    output_dir: Path,
    run_id: str,
    ruleset_version: str,
    failed_checks: list[FailedCheck],
    trust_score: dict[str, float] | None = None,
) -> Path:
    output_dir.mkdir(parents=True, exist_ok=True)
    payload = {
        "run_id": run_id,
        "ruleset_version": ruleset_version,
        "failed_checks": [check.__dict__ for check in failed_checks],
        "trust_score": trust_score or {},
    }
    path = output_dir / "rejection_report.json"
    path.write_text(json.dumps(payload, indent=2, sort_keys=True), encoding="utf-8")
    return path


__all__ = ["FailedCheck", "write_rejection_report"]
