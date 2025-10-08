"""Correlation detector wiring to combine helper modules."""

from __future__ import annotations

from time import perf_counter
from typing import Dict

from ...core.context import DetectorContext
from ...core.findings import Badge, DetectorResult, EvidencePointer
from ...core.pipeline import make_detector_result
from ..base import BaseDetector, register_detector
from .diffing import build_diff_bundle, diff_findings
from .network import current_network_snapshot
from .scoring import risk_finding, risk_score
from .splits import split_findings_and_metrics
from .utils import report_pointer


@register_detector
class CorrelationDetector(BaseDetector):
    """Correlation engine emitting drift, split, and risk findings."""

    detector_id = "correlation_engine"
    name = "Correlation engine"
    default_profiles = ("quick", "full")
    section_key = "correlation_findings"

    def run(self, context: DetectorContext) -> DetectorResult:
        started = perf_counter()
        bundle = build_diff_bundle(context)
        historical_findings = diff_findings(bundle)
        current_snapshot = current_network_snapshot(context)
        split_findings, split_metrics = split_findings_and_metrics(
            context, current_snapshot
        )
        combined_findings = historical_findings + tuple(split_findings)
        risk_profile = risk_score(
            context,
            combined_findings,
            bundle.network_diff,
            current_snapshot,
            split_metrics,
        )
        risk = risk_finding(risk_profile)

        findings = combined_findings + (risk,)

        badge = Badge.OK
        if any(f.status is Badge.FAIL for f in findings):
            badge = Badge.FAIL
        elif any(f.status is Badge.WARN for f in findings):
            badge = Badge.WARN
        elif any(f.status is Badge.INFO for f in findings):
            badge = Badge.INFO

        evidence: list[EvidencePointer] = []
        if bundle.previous is not None:
            evidence.append(
                EvidencePointer(
                    location=report_pointer(bundle.previous.path),
                    description="Baseline report",
                    extra={"sha256": bundle.previous.report.hashes.get("sha256")},
                )
            )

        metrics: Dict[str, object] = {
            "risk_profile": risk_profile,
            "diff": {
                "exported": bundle.new_exported,
                "permissions": bundle.new_permissions,
                "flags": bundle.flipped_flags,
                "network": {
                    "http_added": bundle.network_diff.http_added,
                    "https_added": bundle.network_diff.https_added,
                    "cleartext_flip": bundle.network_diff.cleartext_flip,
                    "cleartext_domains_added": bundle.network_diff.cleartext_domains_added,
                    "pinning_removed": bundle.network_diff.pinning_removed,
                },
            },
        }

        if split_metrics:
            metrics["split_composition"] = split_metrics

        return make_detector_result(
            detector_id=self.detector_id,
            section_key=self.section_key,
            status=badge,
            started_at=started,
            findings=findings,
            metrics=metrics,
            evidence=tuple(evidence),
        )


__all__ = ["CorrelationDetector"]
