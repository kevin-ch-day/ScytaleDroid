"""Third-party SDK detector scaffolding."""

from __future__ import annotations

from ..core.context import DetectorContext
from ..core.findings import Badge, DetectorResult
from .base import BaseDetector, register_detector
from .section_utils import placeholder_result


@register_detector
class SdkInventoryDetector(BaseDetector):
    """Summarises embedded SDKs and trackers (placeholder)."""

    detector_id = "sdk_inventory"
    name = "SDK / Tracker detector"
    default_profiles = ("full",)
    section_key = "sdk_inventory"

    def run(self, context: DetectorContext) -> DetectorResult:
        return placeholder_result(
            detector_id=self.detector_id,
            section_key=self.section_key,
            summary="SDK inventory placeholder",
            status=Badge.SKIPPED,
        )


__all__ = ["SdkInventoryDetector"]