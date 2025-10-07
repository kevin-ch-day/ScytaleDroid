"""Content provider ACL detector scaffolding."""

from __future__ import annotations

from ..core.context import DetectorContext
from ..core.findings import Badge, DetectorResult
from .base import BaseDetector, register_detector
from .section_utils import placeholder_result


@register_detector
class ProviderAclDetector(BaseDetector):
    """Analyses exported content providers (placeholder)."""

    detector_id = "provider_acl"
    name = "Provider ACL detector"
    default_profiles = ("quick", "full")
    section_key = "provider_acl"

    def run(self, context: DetectorContext) -> DetectorResult:
        return placeholder_result(
            detector_id=self.detector_id,
            section_key=self.section_key,
            summary="Provider ACL analysis placeholder",
            status=Badge.SKIPPED,
        )


__all__ = ["ProviderAclDetector"]
