"""File I/O sink detector scaffolding."""

from __future__ import annotations

from ..core.context import DetectorContext
from ..core.findings import Badge, DetectorResult
from .base import BaseDetector, register_detector
from .section_utils import placeholder_result


@register_detector
class FileIoSinksDetector(BaseDetector):
    """Summarises file I/O sinks (placeholder)."""

    detector_id = "file_io_sinks"
    name = "File I/O sinks detector"
    default_profiles = ("quick", "full")
    section_key = "file_io_sinks"

    def run(self, context: DetectorContext) -> DetectorResult:
        return placeholder_result(
            detector_id=self.detector_id,
            section_key=self.section_key,
            summary="File I/O analysis placeholder",
            status=Badge.SKIPPED,
        )


__all__ = ["FileIoSinksDetector"]