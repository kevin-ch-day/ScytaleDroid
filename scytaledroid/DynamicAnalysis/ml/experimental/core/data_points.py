"""Core ML data point definitions for DynamicAnalysis."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass(frozen=True)
class DataPoint:
    """Single feature record for ML workflows."""

    name: str
    value: float
    unit: str | None = None
    tags: dict[str, str] = field(default_factory=dict)


@dataclass
class DataPointSet:
    """Collection of data points plus shared metadata."""

    points: list[DataPoint]
    metadata: dict[str, Any] = field(default_factory=dict)

    def by_name(self, name: str) -> list[DataPoint]:
        return [point for point in self.points if point.name == name]

    def to_dict(self) -> dict[str, Any]:
        return {
            "metadata": dict(self.metadata),
            "points": [
                {
                    "name": point.name,
                    "value": float(point.value),
                    "unit": point.unit,
                    "tags": dict(point.tags),
                }
                for point in self.points
            ],
        }
