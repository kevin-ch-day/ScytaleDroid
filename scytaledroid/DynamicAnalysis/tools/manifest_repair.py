"""One-time repair utilities for legacy dynamic evidence packs.

This module is intentionally DB-free and operates only on evidence packs on disk.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any


@dataclass(frozen=True)
class RepairResult:
    scanned: int
    repaired: int
    skipped: int
    errors: int


def backfill_dataset_block(
    output_root: Path,
    *,
    dry_run: bool = True,
) -> RepairResult:
    """Backfill top-level manifest.dataset for legacy runs.

    Contract:
    - If run_manifest.json lacks "dataset" but has operator.dataset_validity, copy it into
      the top-level "dataset" key.
    - Do not recompute validity. Do not touch any other derived artifacts.
    - Preserve operator.dataset_validity for backwards compatibility.
    """
    scanned = repaired = skipped = errors = 0
    if not output_root.exists():
        return RepairResult(scanned=0, repaired=0, skipped=0, errors=0)

    for run_dir in sorted([p for p in output_root.iterdir() if p.is_dir()]):
        manifest_path = run_dir / "run_manifest.json"
        if not manifest_path.exists():
            continue
        scanned += 1
        try:
            payload = json.loads(manifest_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            errors += 1
            continue

        if not isinstance(payload, dict):
            skipped += 1
            continue
        if isinstance(payload.get("dataset"), dict) and payload.get("dataset"):
            skipped += 1
            continue

        operator = payload.get("operator")
        if not isinstance(operator, dict):
            skipped += 1
            continue
        legacy = operator.get("dataset_validity")
        if not isinstance(legacy, dict):
            skipped += 1
            continue

        dataset_block: dict[str, Any] = dict(legacy)
        # Ensure minimal keys exist for downstream consumers.
        dataset_block.setdefault("tier", operator.get("tier") or "dataset")
        dataset_block.setdefault("countable", str(dataset_block.get("tier")).lower() == "dataset")
        dataset_block.setdefault("valid_dataset_run", legacy.get("valid_dataset_run"))
        dataset_block.setdefault("invalid_reason_code", legacy.get("invalid_reason_code"))
        dataset_block.setdefault("short_run", int(legacy.get("short_run") or 0))
        dataset_block.setdefault("no_traffic_observed", int(legacy.get("no_traffic_observed") or 0))

        payload["dataset"] = dataset_block
        payload.setdefault("qa", {})
        # Add an audit breadcrumb inside the manifest (no DB / no events dependency).
        migrations = operator.get("manifest_migrations")
        if not isinstance(migrations, list):
            migrations = []
        migrations.append(
            {
                "id": "backfill_dataset_block_v1",
                "applied_at": datetime.now(UTC).isoformat(),
                "dry_run": bool(dry_run),
            }
        )
        operator["manifest_migrations"] = migrations
        payload["operator"] = operator

        if not dry_run:
            try:
                manifest_path.write_text(json.dumps(payload, indent=2, sort_keys=True), encoding="utf-8")
            except OSError:
                errors += 1
                continue
        repaired += 1

    return RepairResult(scanned=scanned, repaired=repaired, skipped=skipped, errors=errors)


__all__ = ["RepairResult", "backfill_dataset_block"]

