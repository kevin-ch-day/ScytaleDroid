"""Snapshot-level output writing for query-mode ML runs."""

from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Callable


@dataclass(frozen=True)
class SnapshotOutputResult:
    bundle_manifest: Path
    freeze_ok: bool
    freeze_error: str | None
    lint_ok: bool
    generated_at_utc: str


def finalize_query_snapshot_outputs(
    *,
    snapshot_dir: Path,
    sid: str,
    selection: object,
    groups_seen: int,
    groups_trained: int,
    groups_skipped_no_baseline: int,
    groups_union_fallback: int,
    groups_skipped_baseline_gate_fail: int,
    groups_baseline_thin: int,
    runs_scored: int,
    runs_skipped: int,
    manifest_path: Path,
    model_registry_rows: list[dict[str, Any]],
    write_tables: Callable[..., None],
    write_snapshot_freeze_manifest: Callable[..., None],
    lint_operational_snapshot: Callable[[Path], Any],
    write_snapshot_bundle_manifest: Callable[[Path], Path],
    write_snapshot_summary: Callable[[Path, dict[str, Any]], None],
    output_dir: str,
    per_run_rows: list[dict[str, Any]],
    per_group_mode_rows: list[dict[str, Any]],
    persistence_rows: list[dict[str, Any]],
    stability_rows: list[dict[str, Any]],
    coverage_rows: list[dict[str, Any]],
    risk_rows: list[dict[str, Any]],
    dynamic_math_audit_rows: list[dict[str, Any]],
    overlap_rows: list[dict[str, Any]],
    transport_rows: list[dict[str, Any]],
    transport_group_mode_rows: list[dict[str, Any]],
) -> SnapshotOutputResult:
    write_tables(
        snapshot_dir,
        per_run_rows=per_run_rows,
        per_group_mode_rows=per_group_mode_rows,
        persistence_rows=persistence_rows,
        stability_rows=stability_rows,
        coverage_rows=coverage_rows,
        risk_rows=risk_rows,
        dynamic_math_audit_rows=dynamic_math_audit_rows,
        overlap_rows=overlap_rows,
        transport_rows=transport_rows,
        transport_group_mode_rows=transport_group_mode_rows,
    )

    evidence_root_fs = Path(output_dir) / "evidence" / "dynamic"
    freeze_ok = True
    freeze_err: str | None = None
    try:
        write_snapshot_freeze_manifest(snapshot_dir=snapshot_dir, evidence_root=evidence_root_fs, overwrite=True)
    except Exception as exc:  # noqa: BLE001
        freeze_ok = False
        freeze_err = str(exc)
        (snapshot_dir / "freeze_manifest_error.txt").write_text(freeze_err + "\n", encoding="utf-8")

    lint = lint_operational_snapshot(snapshot_dir)
    lint_path = snapshot_dir / "operational_lint.json"
    lint_path.write_text(json.dumps({"ok": lint.ok, "issues": lint.issues}, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    reg_path = snapshot_dir / "model_registry.json"
    generated_at_utc = datetime.now(UTC).isoformat()
    reg_path.write_text(
        json.dumps(
            {
                "artifact_type": "operational_model_registry",
                "created_at_utc": generated_at_utc,
                "snapshot_id": sid,
                "models": model_registry_rows,
            },
            indent=2,
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
    )

    bundle_manifest = write_snapshot_bundle_manifest(snapshot_dir)

    write_snapshot_summary(
        snapshot_dir,
        {
            "snapshot_id": sid,
            "selector_type": selection.selector_type,
            "generated_at_utc": generated_at_utc,
            "groups_seen": int(groups_seen),
            "groups_trained": int(groups_trained),
            "groups_skipped_no_baseline": int(groups_skipped_no_baseline),
            "groups_union_fallback": int(groups_union_fallback),
            "groups_skipped_baseline_gate_fail": int(groups_skipped_baseline_gate_fail),
            "groups_baseline_thin": int(groups_baseline_thin),
            "runs_selected": int(len(selection.included)),
            "runs_scored": int(runs_scored),
            "runs_skipped": int(runs_skipped),
            "outputs": {
                "selection_manifest": str(manifest_path),
                "tables_dir": str(snapshot_dir / "tables"),
                "runs_dir": str(snapshot_dir / "runs"),
                "freeze_manifest": str(snapshot_dir / "freeze_manifest.json"),
                "operational_lint": str(lint_path),
                "model_registry": str(reg_path),
                "snapshot_bundle_manifest": str(bundle_manifest),
            },
            "bundle_ok": bool(lint.ok and freeze_ok),
            "freeze_ok": bool(freeze_ok),
            "freeze_error": freeze_err,
            "lint_ok": bool(lint.ok),
        },
    )

    return SnapshotOutputResult(
        bundle_manifest=bundle_manifest,
        freeze_ok=freeze_ok,
        freeze_error=freeze_err,
        lint_ok=bool(lint.ok),
        generated_at_utc=generated_at_utc,
    )


__all__ = ["SnapshotOutputResult", "finalize_query_snapshot_outputs"]
