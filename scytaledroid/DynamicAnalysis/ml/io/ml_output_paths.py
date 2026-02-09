"""Helpers for resolving ML output paths."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class MLOutputPaths:
    run_dir: Path
    schema_label: str

    @property
    def output_dir(self) -> Path:
        # Phase E and Phase F operational snapshots both treat `analysis/ml/<schema>` as
        # the canonical location. Older `analysis/ml_provisional/...` layouts are legacy
        # and intentionally not supported by new code paths.
        return self.run_dir / "analysis" / "ml" / self.schema_label

    @property
    def summary_path(self) -> Path:
        return self.output_dir / "ml_summary.json"

    @property
    def model_manifest_path(self) -> Path:
        return self.output_dir / "model_manifest.json"

    @property
    def iforest_scores_path(self) -> Path:
        return self.output_dir / "anomaly_scores_iforest.csv"

    @property
    def ocsvm_scores_path(self) -> Path:
        return self.output_dir / "anomaly_scores_ocsvm.csv"
