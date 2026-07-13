from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace

from scytaledroid.DynamicAnalysis.ml.query_mode_snapshot_outputs import (
    finalize_query_snapshot_outputs,
)


def test_snapshot_finalizer_uses_selected_evidence_root(tmp_path: Path) -> None:
    snapshot_dir = tmp_path / "snapshot"
    snapshot_dir.mkdir()
    manifest_path = snapshot_dir / "selection_manifest.json"
    manifest_path.write_text("{}\n", encoding="utf-8")
    evidence_root = tmp_path / "data" / "evidence" / "dynamic"
    captured: dict[str, Path] = {}
    summaries: list[dict] = []

    def _write_tables(*_args, **_kwargs) -> None:
        (snapshot_dir / "tables").mkdir()

    def _write_freeze_manifest(*, snapshot_dir: Path, evidence_root: Path, overwrite: bool) -> None:
        captured["snapshot_dir"] = snapshot_dir
        captured["evidence_root"] = evidence_root
        captured["overwrite"] = overwrite
        (snapshot_dir / "freeze_manifest.json").write_text("{}\n", encoding="utf-8")

    def _write_bundle_manifest(snapshot_dir: Path) -> Path:
        path = snapshot_dir / "snapshot_bundle_manifest.json"
        path.write_text("{}\n", encoding="utf-8")
        return path

    def _write_summary(_snapshot_dir: Path, payload: dict) -> None:
        summaries.append(payload)

    result = finalize_query_snapshot_outputs(
        snapshot_dir=snapshot_dir,
        sid="query-123",
        selection=SimpleNamespace(selector_type="query", included=[]),
        groups_seen=0,
        groups_trained=0,
        groups_skipped_no_baseline=0,
        groups_union_fallback=0,
        groups_skipped_baseline_gate_fail=0,
        groups_baseline_thin=0,
        runs_scored=0,
        runs_skipped=0,
        manifest_path=manifest_path,
        model_registry_rows=[],
        write_tables=_write_tables,
        write_snapshot_freeze_manifest=_write_freeze_manifest,
        lint_operational_snapshot=lambda _snapshot_dir: SimpleNamespace(ok=True, issues=[]),
        write_snapshot_bundle_manifest=_write_bundle_manifest,
        write_snapshot_summary=_write_summary,
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
        evidence_root=evidence_root,
    )

    assert result.freeze_ok is True
    assert captured["evidence_root"] == evidence_root
    assert captured["snapshot_dir"] == snapshot_dir
    assert captured["overwrite"] is True
    assert summaries and summaries[0]["freeze_ok"] is True
    assert summaries[0]["method_basis"]["runtime_evidence"]["feature_unit"] == "fixed-width PCAP time window"
    registry = json.loads((snapshot_dir / "model_registry.json").read_text(encoding="utf-8"))
    assert registry["method_basis"]["models"]["isolation_forest"]["role"] == "primary_runtime_anomaly_score"
