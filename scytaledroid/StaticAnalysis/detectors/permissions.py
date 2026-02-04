"""Permissions profile detector."""

from __future__ import annotations

from time import perf_counter

from ..core.context import DetectorContext
from ..core.findings import Badge, DetectorResult
from ..core.pipeline import make_detector_result
from ..modules.permissions import build_permission_analysis
from .base import BaseDetector, register_detector


@register_detector
class PermissionsProfileDetector(BaseDetector):
    """Summarises declared manifest permissions and notable risk clusters."""

    detector_id = "permissions_profile"
    name = "Permissions profile detector"
    default_profiles = ("quick", "full")
    section_key = "permissions"

    def run(self, context: DetectorContext) -> DetectorResult:
        started = perf_counter()
        analysis = build_permission_analysis(context)
        return make_detector_result(
            detector_id=self.detector_id,
            section_key=self.section_key,
            status=Badge.INFO,
            started_at=started,
            metrics=analysis.metrics,
            evidence=analysis.evidence,
            notes=analysis.notes if analysis.notes else None,
        )


__all__ = ["PermissionsProfileDetector"]