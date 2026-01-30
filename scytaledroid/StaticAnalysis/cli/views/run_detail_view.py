"""Detailed per-app rendering helpers for static analysis CLI."""

from __future__ import annotations

from collections import defaultdict
from typing import Dict, Iterable, Mapping, Sequence, Set

from scytaledroid.Utils.DisplayUtils import status_messages, table_utils, prompt_utils

from ...core.findings import EvidencePointer, SeverityLevel
from ..core.models import AppRunResult
from .view_sections import SECTION_DEFINITIONS

_SECTION_TITLE_LOOKUP = {definition.key: definition.title for definition in SECTION_DEFINITIONS}
_SEVERITY_LABELS: Mapping[SeverityLevel, tuple[str, str]] = {
    SeverityLevel.P0: ("High", "H"),
    SeverityLevel.P1: ("Med", "M"),
    SeverityLevel.P2: ("Low", "L"),
    SeverityLevel.NOTE: ("Info", "I"),
}
SEVERITY_TOKEN_ORDER = ("H", "M", "L", "I")


def render_app_table(results: Sequence[AppRunResult], *, diagnostic: bool = False) -> None:
    rows: list[list[str]] = []
    for idx, app_result in enumerate(results, start=1):
        totals = app_result.severity_totals()
        base_report = app_result.base_report()
        version = "—"
        target_sdk = "—"
        display_name = app_result.package_name
        suppressed_label = "suppressed (diagnostic)" if diagnostic else "—"
        if base_report:
            version_name = base_report.manifest.version_name or "—"
            version_code = base_report.manifest.version_code
            version = f"{version_name} ({version_code})" if version_code else version_name
            target_sdk = base_report.manifest.target_sdk or "—"
            if base_report.manifest.app_label:
                display_name = base_report.manifest.app_label
        else:
            if app_result.app_label:
                display_name = app_result.app_label
            if app_result.version_name:
                if app_result.version_code:
                    version = f"{app_result.version_name} ({app_result.version_code})"
                else:
                    version = app_result.version_name
            elif diagnostic:
                version = suppressed_label
            if app_result.target_sdk is not None:
                target_sdk = app_result.target_sdk
            elif diagnostic:
                target_sdk = suppressed_label
        signer = app_result.signer or "—"
        if diagnostic and signer == "—":
            signer = suppressed_label
        rows.append(
            [
                str(idx),
                display_name,
                version,
                f"targetSdk={target_sdk}",
                signer,
                str(totals.get('H', 0)),
                str(totals.get('M', 0)),
                str(totals.get('L', 0)),
                str(totals.get('I', 0)),
            ]
        )
    headers = ["#", "App", "Version", "Target", "Signer", "High", "Medium", "Low", "Information"]
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
        print("[f] Filter severity  [e] Evidence lines  [?] Help  [Enter/q] Back")
        command = input("Command: ").strip().lower()
        if command in {"", "q"}:
            break
        if command == "f":
            active = prompt_severity_filter(active)
        elif command == "e":
            current_evidence = cycle_evidence_lines(current_evidence)
        elif command == "?":
            _print_detail_help()
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
        f"High {totals.get('H',0)}   Medium {totals.get('M',0)}   Low {totals.get('L',0)}   Information {totals.get('I',0)}"
    )
    print(f"Version: {version}   targetSdk={target_sdk}   Profile: {app_result.category}")

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
    seen: set[tuple[str, str, str]] = set()
    for artifact in app_result.artifacts:
        for result in artifact.report.detector_results:
            section = result.section_key
            for finding in result.findings:
                pointer = finding.evidence[0].location if finding.evidence else finding.because or ""
                finding_id = finding.finding_id or finding.title or ""
                dedupe_key = (result.section_key or "", finding_id, pointer)
                if dedupe_key in seen:
                    continue
                seen.add(dedupe_key)
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
    from ..core.run_prompts import EVIDENCE_STEPS

    try:
        index = EVIDENCE_STEPS.index(current)
    except ValueError:
        index = 0
    index = (index + 1) % len(EVIDENCE_STEPS)
    return EVIDENCE_STEPS[index]


def severity_token(level: SeverityLevel) -> str:
    return _SEVERITY_LABELS.get(level, ("Info", "I"))[1]


def _print_detail_help() -> None:
    print("Commands:")
    print("  Enter/q  → Return to previous menu")
    print("  f        → Toggle severity filter (use HMLI tokens)")
    print("  e        → Cycle evidence preview lengths")
    print("  ?        → Show this help prompt")


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
