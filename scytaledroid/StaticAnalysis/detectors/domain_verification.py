"""Domain verification detector scaffolding."""

from __future__ import annotations

from ..core.context import DetectorContext
from ..core.findings import Badge, DetectorResult
from .base import BaseDetector, register_detector
from .section_utils import placeholder_result


@register_detector
class DomainVerificationDetector(BaseDetector):
    """Summarises manifest domain verification data (placeholder)."""

    detector_id = "domain_verification"
    name = "Domain verification detector"
    default_profiles = ("quick", "full")
    section_key = "domain_verification"

    def run(self, context: DetectorContext) -> DetectorResult:
        return placeholder_result(
            detector_id=self.detector_id,
            section_key=self.section_key,
            summary="Domain verification analysis placeholder",
            status=Badge.SKIPPED,
        )


__all__ = ["DomainVerificationDetector"]