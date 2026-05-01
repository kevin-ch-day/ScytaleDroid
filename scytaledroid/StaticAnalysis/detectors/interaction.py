"""Clipboard / overlay / accessibility detector scaffolding."""

from __future__ import annotations

from ..core.context import DetectorContext
from ..core.findings import Badge, DetectorResult
from .base import BaseDetector, register_detector
from .section_utils import placeholder_result


@register_detector
class UserInteractionRisksDetector(BaseDetector):
    """Summarises clipboard/overlay/accessibility usage (placeholder)."""

    detector_id = "interaction_risks"
    name = "Clipboard/Overlay/Accessibility detector"
    default_profiles = ("quick", "full")
    section_key = "interaction_risks"

    def run(self, context: DetectorContext) -> DetectorResult:
        return placeholder_result(
            detector_id=self.detector_id,
            section_key=self.section_key,
            summary="User interaction risks analysis placeholder",
            status=Badge.SKIPPED,
        )


__all__ = ["UserInteractionRisksDetector"]