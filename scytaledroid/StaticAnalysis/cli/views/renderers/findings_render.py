"""Baseline findings rendering helpers."""

from __future__ import annotations

from collections import Counter
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from textwrap import fill

from scytaledroid.StaticAnalysis.modules.string_analysis import BUCKET_LABELS
from scytaledroid.Utils.System import output_prefs

_WIDTH = 78
_SEVERITY_TOKENS = {"High": "H", "Medium": "M", "Low": "L", "Info": "I"}


def _wrap_lines(text: str, *, indent: int = 2, subsequent_indent: int | None = None) -> list[str]:
    if not text:
        return []
    subsequent = subsequent_indent if subsequent_indent is not None else indent
    return fill(
        text,
        width=_WIDTH,
        initial_indent=" " * indent,
        subsequent_indent=" " * subsequent,
        break_long_words=False,
        break_on_hyphens=False,
    ).splitlines()


@dataclass(frozen=True)
class BaselineFinding:
    """Structured baseline finding entry for display and JSON."""

    finding_id: str
    severity: str
    title: str
    pointer: str
    fix: str
    evidence: Mapping[str, str]


_SEVERITY_NORMALISER = {
    "critical": "High",
    "high": "High",
    "p0": "High",
    "medium": "Medium",
    "med": "Medium",
    "p1": "Medium",
    "low": "Low",
    "p2": "Low",
    "info": "Info",
    "information": "Info",
    "note": "Info",
    "p3": "Low",
    "p4": "Info",
}


def _normalise_baseline_severity(value: object) -> str:
    token = str(value).strip().lower()
    if not token:
        return "Info"
    return _SEVERITY_NORMALISER.get(token, token.title())


def baseline_findings(
    report,
    exports: Mapping[str, int],
    string_payload: Mapping[str, object],
    *,
    nsc: Mapping[str, object] | None = None,
) -> tuple[list[BaselineFinding], Counter[str]]:
    findings: list[BaselineFinding] = []
    totals = Counter({"High": 0, "Medium": 0, "Low": 0, "Info": 0})

    baseline = getattr(report, "baseline_findings", None)
    if not baseline:
        return findings, totals

    severity_lookup = {}
    for finding in getattr(report, "baseline_findings_summary", []) or []:
        severity_lookup[str(getattr(finding, "finding_id", ""))] = getattr(
            finding, "severity", None
        )

    for finding in baseline:
        severity = getattr(finding, "severity", None)
        finding_id = getattr(finding, "finding_id", None)
        effective_severity = severity_lookup.get(str(finding_id)) or _normalise_baseline_severity(severity)
        totals[effective_severity] += 1
        evidence = getattr(finding, "evidence", None)
        evidence_map = dict(evidence) if isinstance(evidence, Mapping) else {}
        findings.append(
            BaselineFinding(
                finding_id=str(finding_id),
                severity=effective_severity,
                title=str(getattr(finding, "title", "")),
                pointer=str(getattr(finding, "pointer", "")),
                fix=str(getattr(finding, "fix", "")),
                evidence=evidence_map,
            )
        )

    # Add synthetic findings based on string buckets or exports if present.
    if output_prefs.is_compact_mode():
        return findings, totals

    if string_payload:
        counts = string_payload.get("counts") if isinstance(string_payload, Mapping) else {}
        if isinstance(counts, Mapping):
            for key, value in counts.items():
                if not value:
                    continue
                label = BUCKET_LABELS.get(key)
                if not label:
                    continue
                totals["Info"] += 0

    return findings, totals


def finding_lines(
    findings: Sequence[BaselineFinding],
    totals: Counter[str] | None = None,
) -> list[str]:
    lines = ["Findings (baseline)"]
    if not findings:
        lines.append("  (none)")
        return lines

    seen: set[tuple[str, str, str]] = set()
    for finding in findings:
        pointer = finding.pointer
        dedupe_key = (finding.finding_id, finding.severity, pointer)
        if dedupe_key in seen:
            continue
        seen.add(dedupe_key)
        token = _SEVERITY_TOKENS.get(finding.severity, "I")
        lines.append(f"  {token} {finding.finding_id}  {finding.title}")
        pointer_lines = _wrap_lines(finding.pointer, indent=4, subsequent_indent=6)
        lines.extend(pointer_lines)
        fix_lines = _wrap_lines(f"Fix: {finding.fix}", indent=4, subsequent_indent=6)
        lines.extend(fix_lines)
    return lines


def severity_summary_lines(totals: Counter[str]) -> list[str]:
    lines = ["", "Summary (severity)"]
    lines.append(
        "  High: {H}   Medium: {M}   Low: {L}   Info: {I}".format(
            H=totals.get("High", 0),
            M=totals.get("Medium", 0),
            L=totals.get("Low", 0),
            I=totals.get("Info", 0),
        )
    )
    return lines


__all__ = [
    "BaselineFinding",
    "baseline_findings",
    "finding_lines",
    "severity_summary_lines",
]
