"""Phase E v1 pipeline wiring (scaffold)."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from ... import ml_parameters_profile as config
from ...evidence_pack_ml_preflight import (
    compute_ml_preflight,
    load_run_inputs,
    write_ml_preflight,
)
from ...io import MLOutputPaths
from ..core import Pipeline, PipelineContext


@dataclass
class _MetadataStage:
    name: str
    updates: dict[str, Any]

    def run(self, context: PipelineContext) -> PipelineContext:
        # Avoid clobbering nested dictionaries (this is a scaffold, but keep it correct).
        for k, v in self.updates.items():
            if k == "phase_e" and isinstance(v, dict):
                context.metadata.setdefault("phase_e", {}).update(v)
            else:
                context.metadata[k] = v
        return context


@dataclass
class PhaseEConfig:
    """Configuration for Phase E pipeline wiring."""

    schema_label: str = config.ML_SCHEMA_LABEL


@dataclass
class PhaseEPreflightStage:
    name: str = "preflight"
    config: PhaseEConfig = field(default_factory=PhaseEConfig)

    def run(self, context: PipelineContext) -> PipelineContext:
        run_dir = Path(context.run_dir)
        inputs = load_run_inputs(run_dir)
        if inputs is None:
            context.metadata.setdefault("phase_e", {})["preflight"] = "missing_manifest"
            return context
        result = compute_ml_preflight(inputs)
        context.artifacts["run_inputs"] = inputs
        context.artifacts["preflight"] = result

        paths = MLOutputPaths(
            run_dir=run_dir,
            schema_label=self.config.schema_label,
        )
        paths.output_dir.mkdir(parents=True, exist_ok=True)
        # Do not overwrite v1 artifacts (immutability posture for Paper #2).
        pf_path = paths.output_dir / "ml_preflight.json"
        if not pf_path.exists():
            write_ml_preflight(pf_path, result)
        context.metadata.setdefault("phase_e", {})["preflight"] = "ok" if result.frozen_inputs_ok else "failed"
        return context


def build_phase_e_v1_pipeline(config: PhaseEConfig | None = None) -> Pipeline:
    """Return a scaffolded Phase E pipeline with explicit stage boundaries."""
    cfg = config or PhaseEConfig()
    stages = [
        PhaseEPreflightStage(config=cfg),
        _MetadataStage(name="features", updates={"phase_e": {"features": "pending"}}),
        _MetadataStage(name="training", updates={"phase_e": {"training": "pending"}}),
        _MetadataStage(name="scoring", updates={"phase_e": {"scoring": "pending"}}),
    ]
    return Pipeline(stages)


__all__ = ["PhaseEConfig", "PhaseEPreflightStage", "build_phase_e_v1_pipeline"]
