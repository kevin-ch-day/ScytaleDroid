"""Manifest-oriented detectors."""

from __future__ import annotations

from typing import Dict, Tuple

from ..core.context import DetectorContext
from ..core.findings import (
    DetectorResult,
    EvidencePointer,
    Finding,
    MasvsCategory,
    SeverityLevel,
)
from .base import BaseDetector, register_detector


_FLAG_CONFIG: Dict[str, Tuple[MasvsCategory, SeverityLevel, str, str]] = {
    "uses_cleartext_traffic": (
        MasvsCategory.NETWORK,
        SeverityLevel.P2,
        "Application manifest allows cleartext network traffic.",
        "/manifest/application/@android:usesCleartextTraffic",
    ),
    "debuggable": (
        MasvsCategory.PLATFORM,
        SeverityLevel.P2,
        "Debuggable flag enabled in application manifest.",
        "/manifest/application/@android:debuggable",
    ),
    "allow_backup": (
        MasvsCategory.STORAGE,
        SeverityLevel.P2,
        "Application data included in OS backup by default.",
        "/manifest/application/@android:allowBackup",
    ),
}


@register_detector
class ManifestBaselineDetector(BaseDetector):
    """Generates informational findings for manifest boolean flags."""

    detector_id = "manifest_baseline"
    name = "Manifest baseline detector"
    default_profiles = ("quick", "full")

    def run(self, context: DetectorContext) -> DetectorResult:
        findings: list[Finding] = []
        flags = context.manifest_flags

        for attribute, (masvs, severity, summary, xpath) in _FLAG_CONFIG.items():
            value = getattr(flags, attribute, None)
            if value is not True:
                continue
            finding = Finding(
                finding_id=f"manifest_flag_{attribute}",
                title=f"Manifest flag {attribute.replace('_', ' ')} enabled",
                summary=summary,
                detector_id=self.detector_id,
                severity=severity,
                masvs_category=masvs,
                evidence=EvidencePointer(
                    manifest_xpath=xpath,
                    description=f"android:{attribute} is true",
                ),
                tags=("manifest", "baseline"),
                supporting_data={"value": value},
            )
            findings.append(finding)

        metrics = {"flags_evaluated": len(_FLAG_CONFIG), "findings": len(findings)}
        return DetectorResult(
            detector_id=self.detector_id,
            findings=tuple(findings),
            metrics=metrics,
        )


__all__ = ["ManifestBaselineDetector"]
