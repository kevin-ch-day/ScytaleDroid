"""ML preflight reporting over evidence packs (Paper #2, DB-free)."""

from __future__ import annotations

import csv
from dataclasses import asdict
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from scytaledroid.Config import app_config

from .evidence_pack_ml_preflight import compute_ml_preflight, is_valid_dataset_run, load_run_inputs


def write_ml_preflight_report(*, output_path: Path | None = None) -> Path:
    """Scan evidence packs and write a single CSV summarizing ML readiness."""

    root = Path(app_config.OUTPUT_DIR) / "evidence" / "dynamic"
    out_dir = Path(app_config.DATA_DIR) / "archive" / "ml"
    out_dir.mkdir(parents=True, exist_ok=True)

    path = output_path or (out_dir / "ml_preflight_report_v1.csv")
    fieldnames = [
        "generated_at",
        "run_id",
        "package_name",
        "run_profile",
        "identity_key",
        "dataset_valid",
        "frozen_inputs_ok",
        "skip_reason",
        "missing_inputs",
        "sampling_duration_seconds",
        "windows_total_expected",
        "dropped_partial_windows_expected",
    ]

    rows: list[dict[str, Any]] = []
    generated_at = datetime.now(UTC).isoformat()
    if root.exists():
        run_dirs = sorted([p for p in root.iterdir() if p.is_dir()], key=lambda p: p.name)
        for run_dir in run_dirs:
            inputs = load_run_inputs(run_dir)
            if not inputs:
                continue
            pre = compute_ml_preflight(inputs)
            rows.append(
                {
                    "generated_at": generated_at,
                    "run_id": pre.run_id,
                    "package_name": pre.package_name,
                    "run_profile": pre.run_profile,
                    "identity_key": pre.identity_key,
                    "dataset_valid": bool(is_valid_dataset_run(inputs)),
                    "frozen_inputs_ok": bool(pre.frozen_inputs_ok),
                    "skip_reason": pre.skip_reason,
                    "missing_inputs": ",".join(pre.missing_inputs),
                    "sampling_duration_seconds": pre.sampling_duration_seconds,
                    "windows_total_expected": pre.windows_total_expected,
                    "dropped_partial_windows_expected": pre.dropped_partial_windows_expected,
                }
            )

    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames)
        writer.writeheader()
        for row in rows:
            writer.writerow({k: row.get(k) for k in fieldnames})

    return path


__all__ = ["write_ml_preflight_report"]
