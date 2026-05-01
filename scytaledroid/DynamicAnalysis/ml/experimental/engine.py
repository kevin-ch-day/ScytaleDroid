"""Machine learning engine for DynamicAnalysis."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from .core import Pipeline, PipelineContext, PipelineStage
from .core.data_points import DataPointSet


@dataclass
class MLRunResult:
    """Result container for ML engine runs."""

    run_id: str
    artifacts: dict[str, Any] = field(default_factory=dict)
    metrics: dict[str, Any] = field(default_factory=dict)


class MLEngine:
    """Entry point for composable ML runs."""

    def __init__(self, *, stages: list[PipelineStage] | None = None) -> None:
        self._pipeline = Pipeline(stages or [])

    def run(
        self,
        *,
        run_id: str,
        run_dir: str,
        output_dir: str,
        data_points: DataPointSet | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> MLRunResult:
        context = PipelineContext(
            run_id=run_id,
            run_dir=run_dir,
            output_dir=output_dir,
            metadata=metadata or {},
            artifacts={"data_points": data_points} if data_points else {},
        )
        context = self._pipeline.run(context)
        return MLRunResult(
            run_id=context.run_id,
            artifacts=context.artifacts,
            metrics=context.metadata,
        )


__all__ = ["MLEngine", "MLRunResult"]
