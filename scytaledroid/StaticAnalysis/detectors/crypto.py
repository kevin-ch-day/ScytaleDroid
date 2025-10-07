"""Cryptography hygiene detector scaffolding."""

from __future__ import annotations

from ..core.context import DetectorContext
from ..core.findings import Badge, DetectorResult
from .base import BaseDetector, register_detector
from .section_utils import placeholder_result


@register_detector
class CryptoHygieneDetector(BaseDetector):
    """Summarises cipher/digest usage (placeholder)."""

    detector_id = "crypto_hygiene"
    name = "Crypto hygiene detector"
    default_profiles = ("quick", "full")
    section_key = "crypto_hygiene"

    def run(self, context: DetectorContext) -> DetectorResult:
        return placeholder_result(
            detector_id=self.detector_id,
            section_key=self.section_key,
            summary="Cryptography analysis placeholder",
            status=Badge.SKIPPED,
        )


__all__ = ["CryptoHygieneDetector"]
