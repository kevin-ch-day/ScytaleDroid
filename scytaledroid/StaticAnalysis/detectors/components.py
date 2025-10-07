"""IPC component exposure detector scaffolding."""

from __future__ import annotations

from ..core.context import DetectorContext
from ..core.findings import Badge, DetectorResult
from .base import BaseDetector, register_detector
from .section_utils import placeholder_result


@register_detector
class IpcExposureDetector(BaseDetector):
    """Summarises exported IPC components (placeholder)."""

    detector_id = "ipc_components"
    name = "IPC Components detector"
    default_profiles = ("quick", "full")
    section_key = "ipc_components"

    def run(self, context: DetectorContext) -> DetectorResult:
        return placeholder_result(
            detector_id=self.detector_id,
            section_key=self.section_key,
            summary="IPC exposure analysis placeholder",
            status=Badge.SKIPPED,
        )


__all__ = ["IpcExposureDetector"]
