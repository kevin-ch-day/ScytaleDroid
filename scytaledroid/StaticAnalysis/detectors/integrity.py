"""Integrity & identity detector scaffolding."""

from __future__ import annotations

from ..core.context import DetectorContext
from ..core.findings import Badge, DetectorResult
from .base import BaseDetector, register_detector
from .section_utils import placeholder_result


@register_detector
class IntegrityIdentityDetector(BaseDetector):
    """Summarises APK integrity metadata (placeholder implementation)."""

    detector_id = "integrity_identity"
    name = "Integrity & Identity detector"
    default_profiles = ("quick", "full")
    section_key = "integrity"

    def run(self, context: DetectorContext) -> DetectorResult:
        return placeholder_result(
            detector_id=self.detector_id,
            section_key=self.section_key,
            summary="Integrity analysis placeholder",
            status=Badge.SKIPPED,
        )


__all__ = ["IntegrityIdentityDetector"]
