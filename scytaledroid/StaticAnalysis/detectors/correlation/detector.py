"""Correlation detector wiring to combine helper modules."""

from __future__ import annotations

from time import perf_counter
from dataclasses import replace

from ...core.context import DetectorContext
from ...core.findings import Badge, DetectorResult, EvidencePointer, Finding
from ...core.results_builder import make_detector_result
from ..base import BaseDetector, register_detector
from .diffing import build_diff_bundle, diff_findings
from .network import current_network_snapshot
from .scoring import risk_finding, risk_score
from .splits import split_findings_and_metrics
from .utils import report_pointer


def _normalise_risk_finding(finding: Finding) -> Finding:
    """
    The correlation "risk profile" is a synthesis signal, not a policy gate.
    It must never force the correlation detector into FAIL "by construction".
    """
    if finding.status is not Badge.FAIL:
        return finding
    # Rebuild with WARN and a tag for downstream interpretation.
    return Finding(
        finding_id=finding.finding_id,
        title=finding.title,
        severity_gate=finding.severity_gate,
        category_masvs=finding.category_masvs,
        status=Badge.WARN,
        because=finding.because,
        evidence=tuple(finding.evidence),
        remediate=finding.remediate,
        metrics=dict(finding.metrics),
        tags=tuple(list(finding.tags) + ["risk_profile_downgraded"]),
    )


@register_detector
class CorrelationDetector(BaseDetector):
    """Correlation engine emitting drift, split, and risk findings."""

    detector_id = "correlation_engine"
    name = "Correlation engine"
    default_profiles = ("quick", "full")
    section_key = "correlation_findings"

    def run(self, context: DetectorContext) -> DetectorResult:
        started = perf_counter()
        reason_codes: list[str] = []
        rule_failures: list[str] = []
        try:
            bundle = build_diff_bundle(context)
            if bundle.previous is None:
                reason_codes.append("insufficient_evidence:baseline_missing")

            historical_findings = diff_findings(bundle)
            current_snapshot = current_network_snapshot(context)
            split_findings, split_metrics = split_findings_and_metrics(context, current_snapshot)
            combined_findings = historical_findings + tuple(split_findings)
            risk_profile = risk_score(
                context,
                combined_findings,
                bundle.network_diff,
                current_snapshot,
                split_metrics,
            )
            risk = _normalise_risk_finding(risk_finding(risk_profile))
        except Exception as exc:
            # Never present correlation exceptions as FAIL. They are tool errors.
            return make_detector_result(
                detector_id=self.detector_id,
                section_key=self.section_key,
                status=Badge.ERROR,
                started_at=started,
                findings=tuple(),
                metrics={"error": f"{exc.__class__.__name__}: {exc}", "reason_codes": ["error:exception"]},
                evidence=tuple(),
                notes=(f"correlation exception: {exc}",),
            )

        # Explicit, computed correlation rules (v1). FAIL only if a rule is violated.
        # Cleartext newly enabled is a concrete regression vs baseline (if baseline exists).
        if bundle.previous is not None:
            flip = bundle.network_diff.cleartext_flip
            if flip and flip[0] is False and flip[1] is True:
                rule_failures.append("corr_cleartext_enabled")

        findings = combined_findings + (risk,)

        if rule_failures:
            badge = Badge.FAIL
        elif any(f.status is Badge.WARN for f in findings) or reason_codes:
            badge = Badge.WARN
        elif any(f.status is Badge.INFO for f in findings):
            badge = Badge.INFO
        else:
            badge = Badge.OK

        evidence: list[EvidencePointer] = []
        if bundle.previous is not None:
            evidence.append(
                EvidencePointer(
                    location=report_pointer(bundle.previous.path),
                    description="Baseline report",
                    extra={"sha256": bundle.previous.report.hashes.get("sha256")},
                )
            )

        metrics: dict[str, object] = {
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

        if reason_codes:
            metrics["reason_codes"] = list(reason_codes)
        if rule_failures:
            metrics["rule_failures"] = list(rule_failures)
        # Policy gate flag: only explicit correlation rule failures count as "policy fail".
        metrics["policy_gate"] = bool(rule_failures)

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
