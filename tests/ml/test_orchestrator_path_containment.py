from __future__ import annotations

from pathlib import Path

import pytest
from scytaledroid.DynamicAnalysis.ml import evidence_pack_ml_orchestrator as orchestrator


@pytest.mark.parametrize(
    "run_id",
    ["../escape", "/tmp/escape", "nested/run", ".", "", " run-1", None],
)
def test_frozen_run_id_validation_rejects_unsafe_values(run_id: object) -> None:
    with pytest.raises(RuntimeError, match="run_id"):
        orchestrator._validate_frozen_run_id(run_id)


def test_frozen_run_dir_resolves_valid_id_below_evidence_root(tmp_path: Path) -> None:
    evidence_root = tmp_path / "evidence"

    result = orchestrator._resolve_frozen_run_dir(evidence_root, "run-1")

    assert result == evidence_root / "run-1"


def test_frozen_run_dir_rejects_symlink_escape(tmp_path: Path) -> None:
    evidence_root = tmp_path / "evidence"
    outside = tmp_path / "outside"
    evidence_root.mkdir()
    outside.mkdir()
    (evidence_root / "linked-run").symlink_to(outside, target_is_directory=True)

    with pytest.raises(RuntimeError, match="escapes evidence root"):
        orchestrator._resolve_frozen_run_dir(evidence_root, "linked-run")


def test_complete_outputs_require_regular_files(tmp_path: Path) -> None:
    output = tmp_path / "analysis" / "ml" / "v1"
    for name in (
        "model_manifest.json",
        "ml_summary.json",
        "anomaly_scores_iforest.csv",
        "anomaly_scores_ocsvm.csv",
    ):
        (output / name).mkdir(parents=True)

    assert orchestrator._run_has_complete_v1_outputs(tmp_path) is False
