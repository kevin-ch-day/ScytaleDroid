from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace

from scytaledroid.DynamicAnalysis.ml.query_mode_snapshot_outputs import (
    finalize_query_snapshot_outputs,
)


def test_finalize_query_snapshot_outputs_records_freeze_failure_and_lint(tmp_path: Path) -> None:
    snapshot_dir = tmp_path / "snapshot"
    snapshot_dir.mkdir()
    manifest_path = snapshot_dir / "selection_manifest.json"
    manifest_path.write_text("{}", encoding="utf-8")
    bundle_manifest = snapshot_dir / "snapshot_bundle_manifest.json"
    writes: dict[str, object] = {}

    def _write_tables(_snapshot_dir: Path, **kwargs) -> None:
        writes["tables"] = kwargs
        tables_dir = snapshot_dir / "tables"
        tables_dir.mkdir(exist_ok=True)

    def _write_freeze_manifest(**_kwargs) -> None:
        raise RuntimeError("freeze manifest write failed")

    def _lint_operational_snapshot(_snapshot_dir: Path) -> SimpleNamespace:
        return SimpleNamespace(ok=False, issues=["missing freeze manifest"])

    def _write_bundle_manifest(_snapshot_dir: Path) -> Path:
        bundle_manifest.write_text("{}", encoding="utf-8")
        return bundle_manifest

    summary_payload: dict[str, object] = {}

    def _write_snapshot_summary(_snapshot_dir: Path, payload: dict[str, object]) -> None:
        summary_payload.update(payload)
        (snapshot_dir / "snapshot_summary.json").write_text(
            json.dumps(payload, indent=2, sort_keys=True),
            encoding="utf-8",
        )

    result = finalize_query_snapshot_outputs(
        snapshot_dir=snapshot_dir,
        sid="snap-1",
        selection=SimpleNamespace(selector_type="query", included=["r1", "r2"]),
        groups_seen=2,
        groups_trained=1,
        groups_skipped_no_baseline=0,
        groups_union_fallback=1,
        groups_skipped_baseline_gate_fail=0,
        groups_baseline_thin=0,
        runs_scored=1,
        runs_skipped=1,
        manifest_path=manifest_path,
        model_registry_rows=[],
        write_tables=_write_tables,
        write_snapshot_freeze_manifest=_write_freeze_manifest,
        lint_operational_snapshot=_lint_operational_snapshot,
        write_snapshot_bundle_manifest=_write_bundle_manifest,
        write_snapshot_summary=_write_snapshot_summary,
        output_dir=str(tmp_path / "output"),
        per_run_rows=[],
        per_group_mode_rows=[],
        persistence_rows=[],
        stability_rows=[],
        coverage_rows=[],
        risk_rows=[],
        dynamic_math_audit_rows=[],
        overlap_rows=[],
        transport_rows=[],
        transport_group_mode_rows=[],
    )

    assert "tables" in writes
    assert result.freeze_ok is False
    assert result.freeze_error == "freeze manifest write failed"
    assert result.lint_ok is False
    assert (snapshot_dir / "freeze_manifest_error.txt").read_text(encoding="utf-8").strip() == "freeze manifest write failed"
    assert summary_payload["bundle_ok"] is False
    assert summary_payload["freeze_ok"] is False
    assert summary_payload["lint_ok"] is False
    assert summary_payload["runs_selected"] == 2
    assert summary_payload["runs_skipped"] == 1


