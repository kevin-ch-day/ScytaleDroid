"""Dynamic code loading and reflection detector scaffolding."""

from __future__ import annotations

from ..core.context import DetectorContext
from ..core.findings import Badge, DetectorResult
from .base import BaseDetector, register_detector
from .section_utils import placeholder_result


@register_detector
class DynamicLoadingDetector(BaseDetector):
    """Summarises dynamic loading patterns (placeholder)."""

    detector_id = "dynamic_loading"
    name = "Dynamic / Reflection detector"
    default_profiles = ("quick", "full")
    section_key = "dynamic_loading"

    def run(self, context: DetectorContext) -> DetectorResult:
        return placeholder_result(
            detector_id=self.detector_id,
            section_key=self.section_key,
            summary="Dynamic loading analysis placeholder",
            status=Badge.SKIPPED,
        )


__all__ = ["DynamicLoadingDetector"]
