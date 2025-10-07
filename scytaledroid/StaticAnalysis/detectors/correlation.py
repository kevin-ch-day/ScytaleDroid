"""Correlation engine scaffolding for synthesised findings."""

from __future__ import annotations

from ..core.context import DetectorContext
from ..core.findings import Badge, DetectorResult
from .base import BaseDetector, register_detector
from .section_utils import placeholder_result


@register_detector
class CorrelationDetector(BaseDetector):
    """Placeholder correlation engine emitting no findings yet."""

    detector_id = "correlation_engine"
    name = "Correlation engine"
    default_profiles = ("quick", "full")
    section_key = "correlation_findings"

    def run(self, context: DetectorContext) -> DetectorResult:
        return placeholder_result(
            detector_id=self.detector_id,
            section_key=self.section_key,
            summary="Correlation rules placeholder",
            status=Badge.SKIPPED,
        )


__all__ = ["CorrelationDetector"]
