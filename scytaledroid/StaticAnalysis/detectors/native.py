"""Native/JNI hardening detector scaffolding."""

from __future__ import annotations

from ..core.context import DetectorContext
from ..core.findings import Badge, DetectorResult
from .base import BaseDetector, register_detector
from .section_utils import placeholder_result


@register_detector
class NativeHardeningDetector(BaseDetector):
    """Summarises native library posture (placeholder)."""

    detector_id = "native_hardening"
    name = "Native / JNI detector"
    default_profiles = ("full",)
    section_key = "native_jni"

    def run(self, context: DetectorContext) -> DetectorResult:
        return placeholder_result(
            detector_id=self.detector_id,
            section_key=self.section_key,
            summary="Native analysis placeholder",
            status=Badge.SKIPPED,
        )


__all__ = ["NativeHardeningDetector"]
