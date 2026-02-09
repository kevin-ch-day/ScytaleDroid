"""Pipeline primitives for DynamicAnalysis ML workflows."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Protocol


@dataclass
class PipelineContext:
    """Shared context passed between pipeline stages."""

    run_id: str
    run_dir: str
    output_dir: str
    metadata: dict[str, Any] = field(default_factory=dict)
    artifacts: dict[str, Any] = field(default_factory=dict)


class PipelineStage(Protocol):
    """Interface for a pipeline stage."""

    name: str

    def run(self, context: PipelineContext) -> PipelineContext:
        """Execute the stage and return the updated context."""


@dataclass
class Pipeline:
    """Simple pipeline runner for ML workflows."""

    stages: list[PipelineStage]

    def run(self, context: PipelineContext) -> PipelineContext:
        for stage in self.stages:
            context = stage.run(context)
        return context
