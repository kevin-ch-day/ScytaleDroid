"""Data assembly helpers for static run persistence."""

from __future__ import annotations

from collections.abc import Mapping, Sequence

from scytaledroid.StaticAnalysis._androguard import APK

from ...core.findings import Badge, Finding
from .utils import safe_int, truncate


def severity_band_from_badge(badge: Badge) -> str:
    if badge is Badge.FAIL:
        return "FAIL"
    if badge is Badge.WARN:
        return "WARN"
    return "INFO"


def score_from_finding(finding: Finding) -> int:
    metrics = finding.metrics
    if isinstance(metrics, Mapping):
        value = metrics.get("score")
        try:
            return safe_int(value, default=0)
        except (TypeError, ValueError):
            pass
    try:
        from scytaledroid.StaticAnalysis.detectors.correlation.scoring import finding_weight

        return safe_int(finding_weight(finding), default=0)
    except Exception:
        return 0


def correlation_rows_from_result(
    result: object,
    *,
    static_run_id: int,
    package_name: str,
) -> list[dict[str, object]]:
    findings = getattr(result, "findings", None)
    if not isinstance(findings, Sequence):
        return []
    rows: list[dict[str, object]] = []
    for finding in findings:
        if not isinstance(finding, Finding):
            continue
        band = severity_band_from_badge(finding.status)
        score = score_from_finding(finding)
        rationale = finding.because or finding.title
        evidence_path = None
        evidence_preview = None
        if finding.evidence:
            pointer = finding.evidence[0]
            evidence_path = getattr(pointer, "location", None)
            evidence_preview = getattr(pointer, "description", None)
        if not evidence_preview:
            evidence_preview = rationale
        rows.append(
            {
                "static_run_id": static_run_id,
                "package_name": package_name,
                "correlation_key": finding.finding_id,
                "severity_band": band,
                "score": score,
                "rationale": truncate(rationale, 512),
                "evidence_path": truncate(evidence_path, 1024),
                "evidence_preview": truncate(evidence_preview, 1024),
            }
        )
    return rows


def extract_target_sdk(apk: APK) -> int | None:
    try:
        value = apk.get_target_sdk_version()
    except Exception:
        return None
    try:
        return int(value) if value is not None else None
    except (TypeError, ValueError):
        return None


__all__ = [
    "severity_band_from_badge",
    "score_from_finding",
    "correlation_rows_from_result",
    "extract_target_sdk",
]
