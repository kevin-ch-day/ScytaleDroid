"""Obfuscation and anti-analysis detector scaffolding."""

from __future__ import annotations

from ..core.context import DetectorContext
from ..core.findings import Badge, DetectorResult
from .base import BaseDetector, register_detector
from .section_utils import placeholder_result


@register_detector
class ObfuscationDetector(BaseDetector):
    """Summarises obfuscation / anti-analysis traits (placeholder)."""

    detector_id = "obfuscation_signals"
    name = "Obfuscation / Anti-analysis detector"
    default_profiles = ("full",)
    section_key = "obfuscation"

    def run(self, context: DetectorContext) -> DetectorResult:
        return placeholder_result(
            detector_id=self.detector_id,
            section_key=self.section_key,
            summary="Obfuscation analysis placeholder",
            status=Badge.SKIPPED,
        )


__all__ = ["ObfuscationDetector"]
