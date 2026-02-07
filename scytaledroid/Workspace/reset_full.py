"""Full reset utilities (destructive).

This module is intentionally small and explicit. It is used when we want to wipe
all analysis history (static + dynamic) from both:
1) the database (non-protected tables), and
2) generated run artifacts on disk.

Protected catalog tables (e.g., permission dictionaries, schema_version) are
preserved by design via reset_all_analysis_data().
"""

from __future__ import annotations

import argparse
import json
import os
import shutil
from dataclasses import asdict
from datetime import UTC, datetime
from pathlib import Path

from scytaledroid.Database.db_core import database_session
from scytaledroid.Database.db_utils.reset_static import PROTECTED_TABLES, ResetOutcome


def _utc_stamp() -> str:
    return datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")


def _safe_rmtree(path: Path) -> int:
    """Delete a directory tree if it exists. Returns number of entries removed (best-effort)."""
    if not path.exists():
        return 0
    if not path.is_dir():
        path.unlink(missing_ok=True)
        return 1
    # Best-effort count before deletion (avoid walking huge trees if not needed).
    try:
        count = sum(1 for _ in path.rglob("*"))
    except OSError:
        count = 0
    shutil.rmtree(path, ignore_errors=False)
    return count


def _clear_dir_contents(path: Path) -> int:
    """Remove children under a directory, keeping the directory itself."""
    if not path.exists():
        return 0
    if not path.is_dir():
        path.unlink(missing_ok=True)
        return 1
    removed = 0
    for child in sorted(path.iterdir()):
        if child.is_dir():
            removed += _safe_rmtree(child)
        else:
            child.unlink(missing_ok=True)
            removed += 1
    return removed


def _reset_analysis_tables() -> ResetOutcome:
    """Truncate analysis result tables, preserving catalogs, governance inputs, and harvest/library tables."""

    # Tables that are inputs, inventories, or long-lived catalogs and must survive a reset.
    keep: set[str] = set(PROTECTED_TABLES)
    keep.update(
        {
            # Governance inputs (Erebus-aligned permission governance snapshot).
            "permission_governance_snapshots",
            "permission_governance_snapshot_rows",
            # Harvest/library/inventory tables.
            "android_apk_repository",
            "apk_split_groups",
            "harvest_artifact_paths",
            "harvest_source_paths",
            "harvest_storage_roots",
            "device_inventory_snapshots",
            "device_inventory",
        }
    )

    with database_session(reuse_connection=False) as engine:
        tables: list[str] = []
        rows = engine.fetch_all("SHOW TABLES;") or []
        for row in rows:
            if isinstance(row, (list, tuple)) and row:
                tables.append(str(row[0]))

    # Auto-discover analysis tables by naming convention. This keeps the reset resilient to schema growth.
    def is_analysis_table(name: str) -> bool:
        if name in keep:
            return False
        if name.startswith(("static_", "dynamic_")):
            return True
        if name.startswith("permission_audit_"):
            return True
        if name in {
            # Shared run-level and analysis rollups
            "runs",
            "findings",
            "metrics",
            "buckets",
            "contributors",
            "correlations",
            "risk_scores",
            # Permission cohort observations are derived outputs (catalogs are protected above).
            "permission_signal_observations",
        }:
            return True
        return False

    candidate_tables = [t for t in tables if is_analysis_table(t)]
    # Stable-ish ordering helps with FK chains even with FOREIGN_KEY_CHECKS disabled.
    candidate_tables.sort()

    truncated: list[str] = []
    cleared: list[str] = []
    skipped_missing: list[str] = []
    failed: list[tuple[str, str]] = []

    with database_session(reuse_connection=False) as engine:
        foreign_key_reset_error: tuple[str, str] | None = None
        try:
            engine.execute("SET FOREIGN_KEY_CHECKS=0")
        except RuntimeError as exc:  # pragma: no cover
            failed.append(("SET FOREIGN_KEY_CHECKS=0", str(exc)))
            foreign_key_reset_error = ("SET FOREIGN_KEY_CHECKS=0", str(exc))

        for table in candidate_tables:
            # Table list comes from SHOW TABLES; existence should be stable, but keep defensive.
            try:
                engine.execute(f"TRUNCATE TABLE `{table}`")
                truncated.append(table)
            except RuntimeError as exc:  # pragma: no cover - requires specific DB permissions/state
                error_text = str(exc)
                if "command denied" in error_text.lower():
                    try:
                        engine.execute(f"DELETE FROM `{table}`")
                        cleared.append(table)
                        continue
                    except RuntimeError as delete_exc:  # pragma: no cover
                        failed.append((table, str(delete_exc)))
                        continue
                failed.append((table, error_text))

        try:
            engine.execute("SET FOREIGN_KEY_CHECKS=1")
        except RuntimeError as exc:  # pragma: no cover
            failed.append(("SET FOREIGN_KEY_CHECKS=1", str(exc)))
            foreign_key_reset_error = ("SET FOREIGN_KEY_CHECKS=1", str(exc))

        if foreign_key_reset_error and not failed:
            failed.append(foreign_key_reset_error)

    return ResetOutcome(
        truncated=truncated,
        cleared=cleared,
        skipped_protected=sorted(keep),
        skipped_missing=skipped_missing,
        failed=failed,
    )


def full_reset_files_and_db(*, project_root: Path) -> Path:
    """Perform full destructive reset and write a reset manifest. Returns manifest path."""

    stamp = _utc_stamp()
    output_dir = project_root / "output" / "resets"
    output_dir.mkdir(parents=True, exist_ok=True)
    manifest_path = output_dir / f"full-reset-{stamp}.json"

    # 1) DB reset (analysis tables only; preserve catalogs + harvest + governance inputs).
    outcome = _reset_analysis_tables()

    # 2) Filesystem reset (generated artifacts only).
    targets_clear_contents = [
        project_root / "evidence" / "static_runs",
        project_root / "output" / "evidence" / "dynamic",
        project_root / "output" / "batches" / "static",
    ]
    targets_remove_tree = [
        project_root / "data" / "archive" / "pcap",
    ]
    targets_remove_files = [
        project_root / "data" / "archive" / "dataset_plan.json",
    ]
    # Plans are derived convenience; remove all generated plan exports.
    plan_dir = project_root / "data" / "static_analysis" / "dynamic_plan"

    file_ops: dict[str, object] = {
        "cleared_dirs": [],
        "removed_trees": [],
        "removed_files": [],
        "plan_dir_cleared": None,
    }

    for path in targets_clear_contents:
        removed = _clear_dir_contents(path)
        file_ops["cleared_dirs"].append({"path": str(path), "removed_entries": removed})

    for path in targets_remove_tree:
        removed = _safe_rmtree(path)
        file_ops["removed_trees"].append({"path": str(path), "removed_entries": removed})

    for path in targets_remove_files:
        existed = path.exists()
        path.unlink(missing_ok=True)
        file_ops["removed_files"].append({"path": str(path), "existed": existed})

    if plan_dir.exists() and plan_dir.is_dir():
        # Remove only *.json to avoid wiping unexpected files.
        removed = 0
        for child in plan_dir.glob("*.json"):
            child.unlink(missing_ok=True)
            removed += 1
        file_ops["plan_dir_cleared"] = {"path": str(plan_dir), "removed_json_files": removed}
    else:
        file_ops["plan_dir_cleared"] = {"path": str(plan_dir), "removed_json_files": 0}

    payload = {
        "kind": "full_reset_files_and_db",
        "timestamp_utc": stamp,
        "cwd": os.getcwd(),
        "project_root": str(project_root),
        "db_reset": asdict(outcome),
        "fs_reset": file_ops,
    }
    manifest_path.write_text(json.dumps(payload, indent=2, sort_keys=True), encoding="utf-8")
    return manifest_path


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="Full destructive reset (DB + generated artifacts).")
    ap.add_argument(
        "--force",
        action="store_true",
        help="Required. Confirms you understand this will wipe analysis history from DB and disk.",
    )
    args = ap.parse_args(argv)
    if not args.force:
        raise SystemExit("Refusing to run without --force.")

    project_root = Path(__file__).resolve().parents[2]
    manifest_path = full_reset_files_and_db(project_root=project_root)
    print(f"Full reset complete. Manifest: {manifest_path}")
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
