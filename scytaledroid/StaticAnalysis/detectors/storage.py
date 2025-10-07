"""Storage & backup detector scaffolding."""

from __future__ import annotations

from ..core.context import DetectorContext
from ..core.findings import Badge, DetectorResult
from .base import BaseDetector, register_detector
from .section_utils import placeholder_result


@register_detector
class StorageBackupDetector(BaseDetector):
    """Highlights plaintext storage and backup posture (placeholder)."""

    detector_id = "storage_backup"
    name = "Storage & Backup detector"
    default_profiles = ("quick", "full")
    section_key = "storage_backup"

    def run(self, context: DetectorContext) -> DetectorResult:
        return placeholder_result(
            detector_id=self.detector_id,
            section_key=self.section_key,
            summary="Storage analysis placeholder",
            status=Badge.SKIPPED,
        )


__all__ = ["StorageBackupDetector"]
