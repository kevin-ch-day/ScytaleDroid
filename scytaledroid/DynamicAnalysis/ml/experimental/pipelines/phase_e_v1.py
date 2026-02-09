"""Phase E v1 pipeline wiring (scaffold)."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from ..core import Pipeline, PipelineContext
from ..io import MLOutputPaths
from ..evidence_pack_ml_preflight import (
    compute_ml_preflight,
    load_run_inputs,
    write_ml_preflight,
)
from .. import ml_parameters_paper2 as config


@dataclass
class _MetadataStage:
    name: str
    updates: dict[str, Any]

    def run(self, context: PipelineContext) -> PipelineContext:
        context.metadata.update(self.updates)
        return context


@dataclass
class PhaseEConfig:
    """Configuration for Phase E pipeline wiring."""

    frozen: bool = True
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
            frozen=self.config.frozen,
        )
        paths.output_dir.mkdir(parents=True, exist_ok=True)
        write_ml_preflight(paths.output_dir / "ml_preflight.json", result)
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
