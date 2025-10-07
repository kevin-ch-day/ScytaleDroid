"""WebView usage detector scaffolding."""

from __future__ import annotations

from ..core.context import DetectorContext
from ..core.findings import Badge, DetectorResult
from .base import BaseDetector, register_detector
from .section_utils import placeholder_result


@register_detector
class WebViewDetector(BaseDetector):
    """Summarises WebView configuration (placeholder)."""

    detector_id = "webview_hygiene"
    name = "WebView hygiene detector"
    default_profiles = ("quick", "full")
    section_key = "webview"

    def run(self, context: DetectorContext) -> DetectorResult:
        return placeholder_result(
            detector_id=self.detector_id,
            section_key=self.section_key,
            summary="WebView analysis placeholder",
            status=Badge.SKIPPED,
        )


__all__ = ["WebViewDetector"]
