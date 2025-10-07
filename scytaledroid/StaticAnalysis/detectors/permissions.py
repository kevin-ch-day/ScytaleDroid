"""Permissions profile detector scaffolding."""

from __future__ import annotations

from ..core.context import DetectorContext
from ..core.findings import Badge, DetectorResult
from .base import BaseDetector, register_detector
from .section_utils import placeholder_result


@register_detector
class PermissionsProfileDetector(BaseDetector):
    """Summarises dangerous and custom permissions (placeholder)."""

    detector_id = "permissions_profile"
    name = "Permissions profile detector"
    default_profiles = ("quick", "full")
    section_key = "permissions"

    def run(self, context: DetectorContext) -> DetectorResult:
        return placeholder_result(
            detector_id=self.detector_id,
            section_key=self.section_key,
            summary="Permissions analysis placeholder",
            status=Badge.SKIPPED,
        )


__all__ = ["PermissionsProfileDetector"]
