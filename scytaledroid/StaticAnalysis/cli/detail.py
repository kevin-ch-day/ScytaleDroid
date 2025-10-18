"""Detailed per-app rendering helpers for static analysis CLI."""

from __future__ import annotations

from collections import defaultdict
from typing import Dict, Iterable, Mapping, Sequence, Set

from scytaledroid.Utils.DisplayUtils import status_messages, table_utils, prompt_utils

from ..core.findings import EvidencePointer, SeverityLevel
from .models import AppRunResult
from .sections import SECTION_DEFINITIONS

_SECTION_TITLE_LOOKUP = {definition.key: definition.title for definition in SECTION_DEFINITIONS}
_SEVERITY_LABELS: Mapping[SeverityLevel, tuple[str, str]] = {
    SeverityLevel.P0: ("High", "H"),
    SeverityLevel.P1: ("Med", "M"),
    SeverityLevel.P2: ("Low", "L"),
    SeverityLevel.NOTE: ("Info", "I"),
}
SEVERITY_TOKEN_ORDER = ("H", "M", "L", "I")


def render_app_table(results: Sequence[AppRunResult]) -> None:
    rows: list[list[str]] = []
    for idx, app_result in enumerate(results, start=1):
        totals = app_result.severity_totals()
        base_report = app_result.base_report()
        version = "—"
        target_sdk = "—"
        if base_report:
            version_name = base_report.manifest.version_name or "—"
            version_code = base_report.manifest.version_code
            version = f"{version_name} ({version_code})" if version_code else version_name
            target_sdk = base_report.manifest.target_sdk or "—"
        signer = app_result.signer or "—"
        rows.append(
            [
                str(idx),
                app_result.package_name,
                version,
                f"targetSdk={target_sdk}",
                signer,
                f"H {totals.get('H', 0)}",
                f"M {totals.get('M', 0)}",
                f"L {totals.get('L', 0)}",
                f"I {totals.get('I', 0)}",
            ]
        )
    headers = ["#", "Package", "Version", "Target", "Signer", "High", "Med", "Low", "Info"]
    print()
    table_utils.render_table(headers, rows)


def app_detail_loop(
    app_result: AppRunResult,
    evidence_lines: int,
    active_levels: Iterable[str],
    finding_limit: int,
    detail_renderer,
) -> None:
    active: Set[str] = set(active_levels)
    current_evidence = evidence_lines
    while True:
        detail_renderer(app_result, current_evidence, active, finding_limit)
        print("[f] Filter severity  [e] Evidence lines  [q] Back")
        command = input("Command: ").strip().lower()
        if command == "q":
            break
        if command == "f":
            active = prompt_severity_filter(active)
        elif command == "e":
            current_evidence = cycle_evidence_lines(current_evidence)
        else:
            print(status_messages.status("Unknown command.", level="warn"))


def render_app_detail(
    app_result: AppRunResult,
    evidence_lines: int,
    active_levels: Iterable[str],
    finding_limit: int,
) -> None:
    base_report = app_result.base_report()
    version = target_sdk = "—"
    if base_report:
        version_name = base_report.manifest.version_name or "—"
        version_code = base_report.manifest.version_code
        version = f"{version_name} ({version_code})" if version_code else version_name
        target_sdk = base_report.manifest.target_sdk or "—"
    totals = app_result.severity_totals()
    print()
    print(f"Package: {app_result.package_name}")
    print(
        f"High {totals.get('H',0)}   Med {totals.get('M',0)}   Low {totals.get('L',0)}   Info {totals.get('I',0)}"
    )
    print(f"Version: {version}   targetSdk={target_sdk}   Category: {app_result.category}")

    grouped = collect_findings(app_result, evidence_lines)
    for section_key in [definition.key for definition in SECTION_DEFINITIONS]:
        entries = grouped.get(section_key, [])
        filtered = [entry for entry in entries if entry["token"] in active_levels]
        if not filtered:
            continue
        title = _SECTION_TITLE_LOOKUP.get(section_key, section_key)
        print()
        print(f"[{title}]")
        for entry in filtered[: finding_limit]:
            print(f"  {entry['token']} {entry['id']}  {entry['title']}")
            if entry["evidence"]:
                print(f"      file: {entry['evidence'][0]}")
            if entry["snippet"]:
                print(f"      snippet: {entry['snippet']}")
            print(f"      rationale: {entry['rationale']}")
            if entry["fix"]:
                print(f"      fix: {entry['fix']}")


def collect_findings(app_result: AppRunResult, evidence_lines: int) -> Dict[str, list[Dict[str, str]]]:
    grouped: Dict[str, list[Dict[str, str]]] = defaultdict(list)
    for artifact in app_result.artifacts:
        for result in artifact.report.detector_results:
            section = result.section_key
            for finding in result.findings:
                token = severity_token(finding.severity_gate)
                evidence_text = format_evidence(finding.evidence, evidence_lines)
                snippet = finding.evidence[0].description if finding.evidence else ""
                grouped[section].append(
                    {
                        "token": token,
                        "id": finding.finding_id or finding.title,
                        "title": finding.title,
                        "evidence": evidence_text,
                        "snippet": snippet,
                        "rationale": finding.because,
                        "fix": finding.remediate or "",
                    }
                )
    return grouped


def format_evidence(evidence: Sequence[EvidencePointer], limit: int) -> list[str]:
    pointers: list[str] = []
    for pointer in evidence[: max(1, limit)]:
        text = pointer.location
        if pointer.description:
            text += f" — {pointer.description}"
        pointers.append(text)
    return pointers


def prompt_severity_filter(current: Iterable[str]) -> set[str]:
    current_set = set(current)
    print("Current filter: " + ", ".join(token for token in current_set))
    response = prompt_utils.prompt_text(
        "Filter severities (HM LI)",
        default="".join(current_set),
        required=False,
        hint="Provide combination of H/M/L/I. Empty = all.",
    )
    if not response.strip():
        return set(SEVERITY_TOKEN_ORDER)
    selected = {char.upper() for char in response if char.upper() in SEVERITY_TOKEN_ORDER}
    return selected or set(SEVERITY_TOKEN_ORDER)


def cycle_evidence_lines(current: int) -> int:
    from .prompts import EVIDENCE_STEPS

    try:
        index = EVIDENCE_STEPS.index(current)
    except ValueError:
        index = 0
    index = (index + 1) % len(EVIDENCE_STEPS)
    return EVIDENCE_STEPS[index]


def severity_token(level: SeverityLevel) -> str:
    return _SEVERITY_LABELS.get(level, ("Info", "I"))[1]


__all__ = [
    "render_app_table",
    "app_detail_loop",
    "render_app_detail",
    "collect_findings",
    "format_evidence",
    "prompt_severity_filter",
    "cycle_evidence_lines",
    "severity_token",
    "SEVERITY_TOKEN_ORDER",
]

