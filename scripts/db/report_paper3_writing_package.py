#!/usr/bin/env python3
"""Generate a repeatable integrated-study writing workspace from cutoff evidence reports."""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import sys
from collections import Counter
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

_REPO_ROOT = Path(__file__).resolve().parents[2]
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

from scytaledroid.Publication.submission_targets import IEEE_CARS_2026  # noqa: E402

REQUIRED_CUTOFF_FILES = (
    "summary.json",
    "paper_evidence_tiers.csv",
    "paper_evidence_tiers.json",
    "paper_freeze_manifest.csv",
    "paper_freeze_manifest.json",
    "paper_minimal_run_plan.csv",
)

OPTIONAL_CUTOFF_FILES = (
    "paper_freeze_decision_board.csv",
    "paper_freeze_decision_board.json",
)

BRIDGE_FILES = (
    "paper3_bridge_summary.md",
    "paper3_claims_matrix.csv",
    "paper3_recommended_tables.md",
    "paper3_methods_delta.md",
    "paper3_limitations_and_wording.md",
    "paper3_evidence_table.csv",
)

STUDY_DATASET_LABEL = "15-app consumer app dataset"
SAFE_CLAIM = "15/15 selected apps had paper-usable, build-backed evidence bundles at cutoff."
def _generation_label() -> str:
    return IEEE_CARS_2026.generation_label


def _generation_context() -> str:
    return "\n".join(
        (
            f"**Generation target:** {_generation_label()}  ",
            f"**Submission package ID:** {IEEE_CARS_2026.identifier}  ",
            f"**Venue:** {IEEE_CARS_2026.venue}  ",
            f"**Target format:** {IEEE_CARS_2026.target_format}",
        )
    )


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--cutoff-dir",
        required=True,
        help="Paper freeze output directory, for example output/paper/dynamic_paper_freeze_20260709T175429Z/.",
    )
    parser.add_argument(
        "--bridge-dir",
        default=None,
        help="Optional existing bridge directory to reuse for framing and claims.",
    )
    parser.add_argument(
        "--output-dir",
        default=None,
        help="Optional destination directory. Defaults to output/paper/IEEE-CARS-2026_draft_workspace_<timestamp>.",
    )
    parser.add_argument("--paper-one-pdf", default=None, help="Optional path to the Paper 1 PDF.")
    parser.add_argument("--paper-two-pdf", default=None, help="Optional path to the Paper 2 PDF.")
    parser.add_argument(
        "--manuscript-pdf",
        default=None,
        help="Optional path to the current IEEE-CARS-2026 manuscript PDF; it is hashed, never copied.",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Print the source manifest JSON to stdout after generating files.",
    )
    parser.add_argument(
        "--stdout-json",
        action="store_true",
        help="Alias for --json; kept for consistency with adjacent report scripts.",
    )
    return parser


def _default_output_dir() -> Path:
    stamp = datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")
    return _REPO_ROOT / "output" / "paper" / f"{IEEE_CARS_2026.identifier}_draft_workspace_{stamp}"


def _read_json(path: Path) -> dict[str, Any]:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise ValueError(f"{path} is not valid JSON: {exc}") from exc
    if not isinstance(payload, dict):
        raise ValueError(f"{path} must contain a JSON object")
    return payload


def _read_csv(path: Path) -> list[dict[str, str]]:
    with path.open(encoding="utf-8", newline="") as handle:
        return list(csv.DictReader(handle))


def _read_optional_text(path: Path | None) -> str:
    if not path or not path.exists():
        return ""
    return path.read_text(encoding="utf-8")


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _source_entry(path: Path, root: Path) -> dict[str, Any]:
    try:
        display = str(path.resolve().relative_to(root.resolve()))
    except ValueError:
        display = str(path.resolve())
    return {
        "path": display,
        "bytes": path.stat().st_size,
        "sha256": _sha256_file(path),
    }


def _write_text(path: Path, text: str) -> None:
    path.write_text(text.rstrip() + "\n", encoding="utf-8")


def _truthy(value: Any) -> bool:
    return str(value or "").strip().lower() in {"1", "true", "yes", "y"}


def _md_table(headers: list[str], rows: list[list[Any]]) -> str:
    out = ["| " + " | ".join(headers) + " |", "| " + " | ".join(["---"] * len(headers)) + " |"]
    for row in rows:
        out.append("| " + " | ".join(_md_cell(cell) for cell in row) + " |")
    return "\n".join(out)


def _md_cell(value: Any) -> str:
    text = str(value if value is not None else "").replace("\n", " ").strip()
    return text.replace("|", "\\|")


def _latex_escape(value: Any) -> str:
    text = str(value if value is not None else "")
    replacements = {
        "\\": r"\textbackslash{}",
        "&": r"\&",
        "%": r"\%",
        "$": r"\$",
        "#": r"\#",
        "_": r"\_",
        "{": r"\{",
        "}": r"\}",
        "~": r"\textasciitilde{}",
        "^": r"\textasciicircum{}",
    }
    return "".join(replacements.get(ch, ch) for ch in text)


def _extract_tier_summary(summary: dict[str, Any], tiers_json: dict[str, Any], tier_rows: list[dict[str, str]]) -> dict[str, Any]:
    evidence_summary = summary.get("evidence_tier_summary") if isinstance(summary.get("evidence_tier_summary"), dict) else {}
    tier_summary = tiers_json.get("summary") if isinstance(tiers_json.get("summary"), dict) else {}
    merged = {**tier_summary, **evidence_summary}
    tier_counts = merged.get("tier_counts") if isinstance(merged.get("tier_counts"), dict) else {}
    if not tier_counts and tier_rows:
        tier_counts = dict(Counter(row.get("evidence_tier", "") for row in tier_rows if row.get("evidence_tier")))
    paper_usable = merged.get("paper_usable")
    if paper_usable is None and tier_rows:
        paper_usable = sum(1 for row in tier_rows if _truthy(row.get("paper_usable")))
    apps_total = merged.get("apps_total") or summary.get("apps_total") or len(tier_rows)
    true_holes = merged.get("true_evidence_holes")
    if true_holes is None and tier_rows:
        true_holes = sum(1 for row in tier_rows if not _truthy(row.get("paper_usable")))
    return {
        "apps_total": _int_value(apps_total),
        "paper_usable": _int_value(paper_usable),
        "true_evidence_holes": _int_value(true_holes),
        "tier_counts": {str(key): _int_value(value) for key, value in tier_counts.items()},
        "drifted_but_paper_usable": _int_value(merged.get("drifted_but_paper_usable")),
        "prior_build_paper_usable": _int_value(merged.get("prior_build_paper_usable")),
    }


def _validate_cutoff_dir(cutoff_dir: Path) -> list[Path]:
    if not cutoff_dir.exists() or not cutoff_dir.is_dir():
        raise FileNotFoundError(f"cutoff directory does not exist: {cutoff_dir}")
    missing = [name for name in REQUIRED_CUTOFF_FILES if not (cutoff_dir / name).exists()]
    if missing:
        raise FileNotFoundError(
            "cutoff directory is missing required file(s): "
            + ", ".join(missing)
            + f" in {cutoff_dir}"
        )
    return [cutoff_dir / name for name in REQUIRED_CUTOFF_FILES + OPTIONAL_CUTOFF_FILES if (cutoff_dir / name).exists()]


def _load_bridge_inputs(bridge_dir: Path | None) -> tuple[list[Path], dict[str, str], list[dict[str, str]]]:
    if bridge_dir is None or not bridge_dir.exists():
        return [], {}, []
    files = [bridge_dir / name for name in BRIDGE_FILES if (bridge_dir / name).exists()]
    texts = {
        path.name: path.read_text(encoding="utf-8")
        for path in files
        if path.suffix.lower() == ".md"
    }
    claims = _read_csv(bridge_dir / "paper3_claims_matrix.csv") if (bridge_dir / "paper3_claims_matrix.csv").exists() else []
    return files, texts, claims


def _claim_groups(claims: list[dict[str, str]]) -> tuple[list[dict[str, str]], list[dict[str, str]], list[dict[str, str]]]:
    safe = [row for row in claims if row.get("claim_status") in {"reuse", "update", "new"}]
    caveat = [row for row in claims if row.get("claim_status") == "not_safe_without_rewording"]
    avoid = [row for row in claims if row.get("claim_status") == "not_safe"]
    if claims:
        return safe, caveat, avoid
    return (
        [
            {
                "claim_id": "CUTOFF",
                "claim_status": "new",
                "suggested_paper3_wording": SAFE_CLAIM,
                "evidence_source": "summary.json; paper_evidence_tiers.csv",
            }
        ],
        [
            {
                "claim_id": "QFG",
                "claim_status": "not_safe_without_rewording",
                "suggested_paper3_wording": "QFG captures are valid no-touch foreground observations, not strict idle baselines.",
                "required_caveat": "Report strict idle and QFG separately.",
            }
        ],
        [
            {
                "claim_id": "NO_CURRENT_ALL",
                "claim_status": "not_safe",
                "claim_text": "All 15 apps were current-build complete.",
                "suggested_paper3_wording": "All 15 apps had paper-usable, build-backed evidence at cutoff.",
            }
        ],
    )


def _tier_markdown_rows(tier_rows: list[dict[str, str]]) -> list[list[Any]]:
    rows: list[list[Any]] = []
    for row in tier_rows:
        rows.append(
            [
                row.get("app"),
                row.get("package_name"),
                row.get("evidence_tier"),
                row.get("selected_relation"),
                row.get("selected_version_code"),
                row.get("strict_idle_count"),
                row.get("quiescent_fg_count"),
                row.get("interactive_count"),
                row.get("paper_usable"),
            ]
        )
    return rows


def _status_counts(tier_rows: list[dict[str, str]]) -> list[list[Any]]:
    tier_counts = Counter(row.get("evidence_tier") or "UNKNOWN" for row in tier_rows)
    return [[tier, count] for tier, count in sorted(tier_counts.items())]


def _safe_claim_rows(safe: list[dict[str, str]], limit: int | None = None) -> list[list[Any]]:
    selected = safe[:limit] if limit else safe
    return [
        [
            row.get("claim_id"),
            row.get("claim_status"),
            row.get("suggested_paper3_wording") or row.get("claim_text"),
            row.get("evidence_source"),
        ]
        for row in selected
    ]


def _int_value(value: object, default: int = 0) -> int:
    try:
        return int(str(value or "").strip() or default)
    except (TypeError, ValueError):
        return default


def _is_truthy_csv(value: object) -> bool:
    return str(value or "").strip().lower() in {"1", "true", "yes", "y"}


def _run_plan_sort_key(row: dict[str, str]) -> tuple[int, int, int, str]:
    relation = str(row.get("paper_target_relation") or "").strip().lower()
    refresh_candidate = _is_truthy_csv(row.get("refresh_candidate"))
    missing = _int_value(row.get("missing_interactive_runs")) + _int_value(row.get("missing_baseline_runs"))
    app = str(row.get("app") or row.get("package_name") or "")
    return (
        0 if relation == "current" else 1,
        1 if refresh_candidate else 0,
        missing,
        app.lower(),
    )


def _last_run_recommendation_from_plan(plan_rows: list[dict[str, str]]) -> dict[str, Any]:
    actionable = [
        row
        for row in plan_rows
        if str(row.get("recommended_next_action") or "").strip().lower()
        not in {"", "none", "leave frozen", "defer", "future refresh only"}
    ]
    actionable.sort(key=_run_plan_sort_key)
    optional_candidates: list[dict[str, Any]] = []
    for row in actionable:
        optional_candidates.append(
            {
                "app": row.get("app") or row.get("package_name") or "",
                "package_name": row.get("package_name") or "",
                "recommended_next_action": row.get("recommended_next_action") or "",
                "paper_target_relation": row.get("paper_target_relation") or "",
                "missing_baseline_runs": _int_value(row.get("missing_baseline_runs")),
                "missing_interactive_runs": _int_value(row.get("missing_interactive_runs")),
                "refresh_candidate": _is_truthy_csv(row.get("refresh_candidate")),
            }
        )
    if not optional_candidates:
        return {
            "required": "none",
            "optional_final_polish": "none; collection paused; start writing",
            "otherwise": "start writing",
            "optional_candidates": [],
            "future_work_candidates": [],
        }
    return {
        "required": "none",
        "optional_final_polish": "none; collection paused; start writing",
        "otherwise": "start writing",
        "optional_candidates": [],
        "future_work_candidates": optional_candidates,
    }


def _build_tables_markdown(
    *,
    tier_rows: list[dict[str, str]],
    decision_rows: list[dict[str, str]],
    tier_summary: dict[str, Any],
) -> str:
    current = tier_summary["tier_counts"].get("STRICT_CURRENT_BUILD_COMPLETE", 0)
    mixed = tier_summary["tier_counts"].get("CURRENT_BUILD_MIXED_BASELINE", 0)
    prior = tier_summary["tier_counts"].get("PRIOR_BUILD_PAPER_EVIDENCE", 0)
    drift_rows = [
        [
            row.get("app"),
            row.get("selected_relation"),
            row.get("selected_version_code"),
            row.get("installed_version_code") or row.get("operational_installed_version_code"),
            row.get("caveat") or row.get("operational_drift_detail"),
        ]
        for row in tier_rows
        if row.get("selected_relation") != "current" or row.get("evidence_tier") == "PRIOR_BUILD_PAPER_EVIDENCE"
    ]
    class_rows = [
        [
            row.get("app"),
            row.get("strict_idle_count"),
            row.get("quiescent_fg_count"),
            row.get("interactive_count"),
            row.get("pcap_available_count"),
            row.get("caveat"),
        ]
        for row in tier_rows
    ]
    decision_table_rows = [
        [
            row.get("app"),
            row.get("relation"),
            row.get("strict_idle_count"),
            row.get("quiescent_fg_count"),
            row.get("interactive_count"),
            row.get("action"),
            row.get("reason"),
        ]
        for row in decision_rows
    ]
    return f"""# Integrated Static-Runtime Tables Markdown

## Table 1: Prior Work Lineage

{_md_table(
    ["Study line", "Scope", "Evidence type", "What this study reuses", "What this study changes"],
    [
        ["Published static predecessor", "Six social media apps", "Static manifest, permission, component, strings/resources, MASVS/CVSS", "Static-risk vocabulary and predecessor scope", "Regenerates current static evidence and does not claim exact reproduction"],
        ["Published runtime predecessor", "Twelve-app dynamic behavior study", "Idle/interactive captures, non-root physical device, package-filtered PCAP, RDI-style framing", "Dynamic observation method foundation", "Expands to cutoff evidence bundles and a 15-app dataset"],
        ["Current integrated study", STUDY_DATASET_LABEL, "Static + dynamic build/version-backed evidence", "Prior static/dynamic method lineage", "Uses cutoff tiers to handle app-update churn"],
    ],
)}

## Table 2: Evidence Tier Summary

{_md_table(
    ["Metric", "Count"],
    [
        ["Publication-usable apps", f"{tier_summary['paper_usable']}/{tier_summary['apps_total']}"],
        ["Strict current-build complete", current],
        ["Current-build mixed baseline", mixed],
        ["Prior-build paper evidence", prior],
        ["True evidence holes", tier_summary["true_evidence_holes"]],
    ],
)}

## Table 3: Cohort Evidence Summary

{_md_table(
    ["App", "Package", "Tier", "Relation", "Version", "Strict idle", "QFG", "Interactive", "Paper usable"],
    _tier_markdown_rows(tier_rows),
)}

## Table 4: Dynamic Evidence Classes

{_md_table(
    ["App", "Strict idle", "QFG", "Interactive", "PCAP available", "Caveat"],
    class_rows,
)}

## Table 5: Drift / Prior-Build Caveat Table

{_md_table(
    ["App", "Selected relation", "Selected version", "Installed version", "Caveat"],
    drift_rows,
)}

## Table 6: Decision Board / Last Run Context

{_md_table(
    ["App", "Relation", "Strict idle", "QFG", "Interactive", "Action", "Reason"],
    decision_table_rows,
)}

## Table 7: Limitations And Future Work

{_md_table(
    ["Limitation", "Paper wording"],
    [
        ["Current-build churn", "Live installed-build drift after cutoff is operational churn, not evidence loss."],
        ["Prior-build evidence", "Prior-build rows remain labeled with selected version and run provenance."],
        ["QFG baseline class", "QFG is valid no-touch foreground evidence, but it is not strict idle."],
        ["Quota", "Do not describe the paper as 105/105 quota complete."],
        ["Study lineage", "The current integrated study is a follow-on analysis, not an exact reproduction of the published predecessor papers."],
    ],
)}
"""


def _build_tables_latex(tier_rows: list[dict[str, str]], tier_summary: dict[str, Any]) -> str:
    rows = "\n".join(
        "    "
        + " & ".join(
            _latex_escape(value)
            for value in [
                row.get("app"),
                row.get("package_name"),
                row.get("evidence_tier"),
                row.get("selected_relation"),
                row.get("strict_idle_count"),
                row.get("quiescent_fg_count"),
                row.get("interactive_count"),
            ]
        )
        + r" \\"
        for row in tier_rows
    )
    return rf"""% Auto-generated integrated-study table drafts.
% Verify width and caption placement before journal submission.

\begin{{table*}}[t]
  \centering
  \caption{{Cutoff evidence tier summary.}}
  \begin{{tabular}}{{lr}}
    \hline
    Metric & Count \\
    \hline
    Publication-usable apps & {_latex_escape(f"{tier_summary['paper_usable']}/{tier_summary['apps_total']}")} \\
    Strict current-build complete & {_latex_escape(tier_summary['tier_counts'].get('STRICT_CURRENT_BUILD_COMPLETE', 0))} \\
    Current-build mixed baseline & {_latex_escape(tier_summary['tier_counts'].get('CURRENT_BUILD_MIXED_BASELINE', 0))} \\
    Prior-build paper evidence & {_latex_escape(tier_summary['tier_counts'].get('PRIOR_BUILD_PAPER_EVIDENCE', 0))} \\
    True evidence holes & {_latex_escape(tier_summary['true_evidence_holes'])} \\
    \hline
  \end{{tabular}}
\end{{table*}}

\begin{{table*}}[t]
  \centering
  \caption{{Selected 15-app evidence bundles at cutoff.}}
  \begin{{tabular}}{{llllrrr}}
    \hline
    App & Package & Tier & Relation & Strict idle & QFG & Interactive \\
    \hline
{rows}
    \hline
  \end{{tabular}}
\end{{table*}}
"""


def _methodology_text() -> str:
    return (
        "Dynamic collection was closed at a fixed cutoff because consumer Android applications "
        "updated during the study faster than a full all-current-build collection wave could be "
        "completed. Evidence was therefore assembled as app-level, build/version-backed bundles, "
        "preserving package name, version code/name, static run IDs, dynamic run IDs, APK hashes, "
        "PCAP availability, and QA provenance. Live installed-build drift after cutoff was treated "
        "as operational churn, not evidence loss. Current-build refreshes after cutoff are future "
        "work; paper claims use the selected build-backed evidence tier and explicitly label "
        "current-build, drifted-current, or retained prior-build provenance."
    )


def _baseline_class_text() -> str:
    return (
        "Strict idle baselines, quiescent foreground baselines, and interactive captures were "
        "reported as separate evidence classes. Quiescent foreground captures represent valid "
        "no-touch foreground observations in which the app continued app-driven network activity; "
        "they were not counted as strict idle."
    )


def _write_workspace_files(
    *,
    output_dir: Path,
    cutoff_dir: Path,
    bridge_dir: Path | None,
    summary: dict[str, Any],
    tier_summary: dict[str, Any],
    tier_rows: list[dict[str, str]],
    decision_rows: list[dict[str, str]],
    bridge_texts: dict[str, str],
    claims: list[dict[str, str]],
    last_run_recommendation: dict[str, Any],
    paper_one_pdf: Path | None,
    paper_two_pdf: Path | None,
    manuscript_pdf: Path | None,
) -> list[Path]:
    safe_claims, caveat_claims, avoid_claims = _claim_groups(claims)
    files: list[Path] = []
    current = tier_summary["tier_counts"].get("STRICT_CURRENT_BUILD_COMPLETE", 0)
    mixed = tier_summary["tier_counts"].get("CURRENT_BUILD_MIXED_BASELINE", 0)
    prior = tier_summary["tier_counts"].get("PRIOR_BUILD_PAPER_EVIDENCE", 0)
    source_line = f"Cutoff source: `{cutoff_dir}`"
    bridge_line = f"Bridge source: `{bridge_dir}`" if bridge_dir else "Bridge source: not provided"
    prior_refs = [
        f"Paper 1 PDF: `{paper_one_pdf}`" if paper_one_pdf else "Paper 1 PDF: not provided",
        f"Paper 2 PDF: `{paper_two_pdf}`" if paper_two_pdf else "Paper 2 PDF: not provided",
    ]
    manuscript_ref = (
        f"Current manuscript PDF: `{manuscript_pdf}`"
        if manuscript_pdf
        else "Current manuscript PDF: not registered in this workspace"
    )

    generation_context = _generation_context()
    drafts = {
        "paper3_submission_context.md": f"""# Paper #3 Submission Context

{generation_context}

This workspace is generated from the selected cutoff evidence. It is a drafting
workspace, not a submission package or a claim that the paper has been accepted.
Use the venue's current author instructions and template when preparing the final
manuscript.

{manuscript_ref}
""",
        "paper3_outline.md": f"""# Integrated Study Outline

{generation_context}

{source_line}

{bridge_line}

## Core Claim

{SAFE_CLAIM}

## Tier Split

- Strict current-build complete: {current}
- Current-build mixed baseline: {mixed}
- Prior-build paper evidence: {prior}
- Paper-usable apps: {tier_summary['paper_usable']}/{tier_summary['apps_total']}
- True evidence holes: {tier_summary['true_evidence_holes']}

## Sections

1. Introduction
2. Background and prior ScytaleDroid work
3. Methods and cutoff evidence model
4. Static analysis pipeline
5. Dynamic analysis pipeline
6. Results
7. Discussion
8. Limitations
9. Conclusion

## Last-Run Recommendation

No more runs are required for cutoff readiness. Collection is paused; use the cutoff bundle and start writing. Non-blocking run-plan rows are retained only as future-work provenance.
""",
        "paper3_working_outline.md": f"""# Integrated Study Working Outline

{generation_context}

{source_line}

{bridge_line}

## Core Claim

{SAFE_CLAIM}

## Tier Split

- Strict current-build complete: {current}
- Current-build mixed baseline: {mixed}
- Prior-build paper evidence: {prior}
- Paper-usable apps: {tier_summary['paper_usable']}/{tier_summary['apps_total']}
- True evidence holes: {tier_summary['true_evidence_holes']}

## Sections

1. Introduction
2. Background and prior ScytaleDroid work
3. Methods and cutoff evidence model
4. Static analysis pipeline
5. Dynamic analysis pipeline
6. Results
7. Discussion
8. Limitations
9. Conclusion

## Last-Run Recommendation

No more runs are required for cutoff readiness. Collection is paused; use the cutoff bundle and start writing. Non-blocking run-plan rows are retained only as future-work provenance.
""",
        "paper3_section_plan.md": f"""# Integrated Study Section Plan

{generation_context}

## Introduction

State the app-update churn problem and the cutoff solution. Use the core claim exactly: {SAFE_CLAIM}

## Background

- Published static predecessor: static-only six-app study.
- Published runtime predecessor: 12-app dynamic/RDI study.
- Current study: expanded 15-app consumer app cutoff analysis.

## Methodology

Use build/version-backed evidence bundles. Preserve package/version, static run IDs, dynamic run IDs, APK hashes, PCAP availability, and QA provenance.

## Results

Lead with evidence tiers, then static and dynamic summaries.

## Discussion And Limitations

Explain that current-build drift is operational churn and that prior-build rows must remain labeled.
""",
        "paper3_introduction_draft.md": f"""# Introduction Draft

{generation_context}

Consumer Android applications update frequently enough that an all-current-build collection target can become unstable during an active study. This study treats that churn as a measurement-design issue rather than as evidence loss. Dynamic collection is closed at a fixed cutoff and assembled into app-level evidence bundles tied to package name, version code/name, static run IDs, dynamic run IDs, APK hashes, PCAP availability, and QA provenance.

The safe headline for this draft is: {SAFE_CLAIM} The paper should not claim that all 15 apps were current-build complete or that the full 105-run quota was complete. Instead, it should describe the cutoff tier split: {current} strict current-build complete, {mixed} current-build mixed-baseline, and {prior} retained prior-build evidence apps.
""",
        "paper3_background_draft.md": f"""# Background Draft

{generation_context}

This integrated analysis is a follow-on study, not a strict reproduction of the published predecessor papers.

- The published static predecessor is the six-app snapshot for Facebook, Instagram, Facebook Msg, Snapchat, TikTok, and X.
- The published runtime predecessor establishes non-root physical-device capture, package-filtered PCAP analysis, traffic-shape features, and RDI-style interpretation.
- The current study expands the framing to a 15-app consumer app dataset and combines static and dynamic evidence through cutoff evidence tiers.

{prior_refs[0]}

{prior_refs[1]}
""",
        "paper3_methodology_draft.md": f"""# Methodology Draft

{generation_context}

{_methodology_text()}

{_baseline_class_text()}

The live current-build queue remains an operations tool that answers what should be refreshed next. The paper cutoff answers a separate research question: what valid, build-backed evidence existed at cutoff and can support the study claims.
""",
        "paper3_results_draft.md": f"""# Results Draft

{generation_context}

At cutoff, {tier_summary['paper_usable']}/{tier_summary['apps_total']} apps were paper-usable and {tier_summary['true_evidence_holes']} true evidence holes remained.

{_md_table(["Evidence tier", "App count"], _status_counts(tier_rows))}

The results section should present the cohort evidence table before detailed static and dynamic findings so readers can see which rows are current-build, mixed-baseline, or retained prior-build evidence.
""",
        "paper3_discussion_draft.md": f"""# Discussion Draft

{generation_context}

The cutoff model turns a moving operational target into an auditable research object. Apps that updated after their usable captures were collected are not treated as failed evidence; they are labeled by selected build and relation. This makes the paper finishable while preserving the provenance needed for later refresh work.

Prior-build evidence should be discussed as retained evidence with explicit package/version and run provenance, not as current-build evidence. QFG captures should be discussed as app-driven foreground activity, not as strict idle.
""",
        "paper3_limitations_draft.md": f"""# Limitations Draft

{generation_context}

- The current study does not exactly reproduce the published predecessor tables.
- The current study should not claim 15/15 current-build completion.
- The current study should not claim 105/105 quota completion.
- QFG captures are not strict idle captures.
- Prior-build evidence remains labeled as prior-build evidence.
- Static detector/resource parse caveats and dynamic signal caveats should be reported where relevant.
""",
        "paper3_conclusion_draft.md": f"""# Conclusion Draft

{generation_context}

This study demonstrates that an Android app behavior study can remain auditable even when live apps update faster than an all-current-build capture wave can complete. At cutoff, {SAFE_CLAIM} The contribution is not merely additional collection volume; it is the build/version-backed cutoff model that keeps evidence usable, labeled, and reproducible.
""",
        "paper3_claims_control.md": f"""# Claims Control

{generation_context}

## Safe Claims

{_md_table(["ID", "Status", "Recommended wording", "Evidence"], _safe_claim_rows(safe_claims))}

## Claims Needing Caveats

{_md_table(["ID", "Status", "Recommended wording", "Required caveat"], [
    [
        row.get("claim_id"),
        row.get("claim_status"),
        row.get("suggested_paper3_wording") or row.get("claim_text"),
        row.get("required_caveat"),
    ]
    for row in caveat_claims
])}

## Claims To Avoid

{_md_table(["ID", "Unsafe claim", "Use instead"], [
    [
        row.get("claim_id"),
        row.get("claim_text"),
        row.get("suggested_paper3_wording"),
    ]
    for row in avoid_claims
])}

## Exact Recommended Wording

{_methodology_text()}

{_baseline_class_text()}
""",
        "paper3_next_revision_items.md": f"""# Next Revision Items

{generation_context}

- Decide how much detail from the prior PDFs belongs in related work versus methods lineage.
- Decide whether to include APK storage/cold-store work as reproducibility infrastructure or leave it out of the paper.
- Confirm static detector/resource parse caveats before final results wording.
- Confirm dynamic unresolved signal rows before final provider/signal claims.
""",
        "paper3_open_questions.md": f"""# Open Questions

{generation_context}

- Decide how much detail from the prior PDFs belongs in related work versus methods lineage.
- Decide whether to include APK storage/cold-store work as reproducibility infrastructure or leave it out of the paper.
- Confirm static detector/resource parse caveats before final results wording.
- Confirm dynamic unresolved signal rows before final provider/signal claims.
""",
    }

    for name, text in drafts.items():
        path = output_dir / name
        _write_text(path, text)
        files.append(path)

    tables_md = _build_tables_markdown(
        tier_rows=tier_rows,
        decision_rows=decision_rows,
        tier_summary=tier_summary,
    )
    tables_md_path = output_dir / "paper3_tables_markdown.md"
    _write_text(tables_md_path, tables_md)
    files.append(tables_md_path)

    tables_tex_path = output_dir / "paper3_tables_latex.tex"
    _write_text(tables_tex_path, _build_tables_latex(tier_rows, tier_summary))
    files.append(tables_tex_path)

    if bridge_texts:
        bridge_notes = ["# Source Bridge Notes", ""]
        for name in sorted(bridge_texts):
            bridge_notes.extend([f"## {name}", "", bridge_texts[name].strip(), ""])
        path = output_dir / "paper3_bridge_notes_used.md"
        _write_text(path, "\n".join(bridge_notes))
        files.append(path)

    return files


def generate_package(
    *,
    cutoff_dir: Path,
    output_dir: Path | None = None,
    bridge_dir: Path | None = None,
    paper_one_pdf: Path | None = None,
    paper_two_pdf: Path | None = None,
    manuscript_pdf: Path | None = None,
) -> dict[str, Any]:
    cutoff_dir = cutoff_dir.expanduser()
    bridge_dir = bridge_dir.expanduser() if bridge_dir else None
    paper_one_pdf = paper_one_pdf.expanduser() if paper_one_pdf else None
    paper_two_pdf = paper_two_pdf.expanduser() if paper_two_pdf else None
    manuscript_pdf = manuscript_pdf.expanduser() if manuscript_pdf else None
    output_dir = (output_dir.expanduser() if output_dir else _default_output_dir())
    output_dir.mkdir(parents=True, exist_ok=True)

    cutoff_files = _validate_cutoff_dir(cutoff_dir)
    summary = _read_json(cutoff_dir / "summary.json")
    tiers_json = _read_json(cutoff_dir / "paper_evidence_tiers.json")
    tier_rows = _read_csv(cutoff_dir / "paper_evidence_tiers.csv")
    decision_rows = _read_csv(cutoff_dir / "paper_freeze_decision_board.csv") if (cutoff_dir / "paper_freeze_decision_board.csv").exists() else []
    run_plan_rows = _read_csv(cutoff_dir / "paper_minimal_run_plan.csv") if (cutoff_dir / "paper_minimal_run_plan.csv").exists() else []
    tier_summary = _extract_tier_summary(summary, tiers_json, tier_rows)
    last_run_recommendation = _last_run_recommendation_from_plan(run_plan_rows)

    bridge_files, bridge_texts, claims = _load_bridge_inputs(bridge_dir)
    pdf_files = [path for path in (paper_one_pdf, paper_two_pdf, manuscript_pdf) if path and path.exists()]

    generated_files = _write_workspace_files(
        output_dir=output_dir,
        cutoff_dir=cutoff_dir,
        bridge_dir=bridge_dir,
        summary=summary,
        tier_summary=tier_summary,
        tier_rows=tier_rows,
        decision_rows=decision_rows,
        bridge_texts=bridge_texts,
        claims=claims,
        last_run_recommendation=last_run_recommendation,
        paper_one_pdf=paper_one_pdf,
        paper_two_pdf=paper_two_pdf,
        manuscript_pdf=manuscript_pdf,
    )

    source_files = cutoff_files + bridge_files + pdf_files
    manifest_path = output_dir / "paper3_source_manifest.json"
    manifest = {
        "generated_at": datetime.now(UTC).isoformat(),
        "cutoff_dir": str(cutoff_dir),
        "bridge_dir": str(bridge_dir) if bridge_dir else None,
        "output_dir": str(output_dir),
        "paper_one_pdf": str(paper_one_pdf) if paper_one_pdf else None,
        "paper_two_pdf": str(paper_two_pdf) if paper_two_pdf else None,
        "manuscript_pdf": str(manuscript_pdf) if manuscript_pdf else None,
        "publication_target": {
            "submission_id": IEEE_CARS_2026.identifier,
            "paper_label": IEEE_CARS_2026.paper_label,
            "generation_label": _generation_label(),
            "venue": IEEE_CARS_2026.venue,
            "venue_short_label": IEEE_CARS_2026.venue_short_label,
            "target_format": IEEE_CARS_2026.target_format,
        },
        "official_cutoff_claim": SAFE_CLAIM,
        "writing_package_generator": "scripts/db/report_paper3_writing_package.py",
        "generated_from_current_source": True,
        "manual_bridge_artifacts_supplied": bool(bridge_dir),
        "paper_usable_count": tier_summary["paper_usable"],
        "apps_total": tier_summary["apps_total"],
        "true_evidence_holes": tier_summary["true_evidence_holes"],
        "tier_counts": tier_summary["tier_counts"],
        "warnings": [
            "Do not claim 15/15 current-build complete.",
            "Do not claim 105/105 quota complete.",
            "Do not equate QFG with strict idle.",
            "Do not equate prior-build evidence with current-build evidence.",
            "The current integrated study is a follow-on analysis, not an exact reproduction of the published predecessor papers.",
        ],
        "last_run_recommendation_source": "paper_minimal_run_plan.csv",
        "last_run_recommendation": last_run_recommendation,
        "source_files_used": [_source_entry(path, _REPO_ROOT) for path in source_files],
        "generated_files": [_source_entry(path, _REPO_ROOT) for path in generated_files],
        "mutation_scope": "reporting_workspace_only",
        "evidence_mutated": False,
        "db_rows_mutated": False,
        "quota_math_mutated": False,
        "tracker_countability_mutated": False,
    }
    manifest_path.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    generated_files.append(manifest_path)
    manifest["generated_files"] = [_source_entry(path, _REPO_ROOT) for path in generated_files]
    manifest_path.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return manifest


def main(argv: list[str] | None = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)
    try:
        manifest = generate_package(
            cutoff_dir=Path(args.cutoff_dir),
            bridge_dir=Path(args.bridge_dir) if args.bridge_dir else None,
            output_dir=Path(args.output_dir) if args.output_dir else None,
            paper_one_pdf=Path(args.paper_one_pdf) if args.paper_one_pdf else None,
            paper_two_pdf=Path(args.paper_two_pdf) if args.paper_two_pdf else None,
            manuscript_pdf=Path(args.manuscript_pdf) if args.manuscript_pdf else None,
        )
    except (FileNotFoundError, ValueError, OSError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    if args.json or args.stdout_json:
        print(json.dumps(manifest, indent=2, sort_keys=True))
    else:
        print(f"workspace: {manifest['output_dir']}")
        print(f"manifest: {Path(manifest['output_dir']) / 'paper3_source_manifest.json'}")
        print(f"paper usable: {manifest['paper_usable_count']}/{manifest['apps_total']}")
        print(f"true evidence holes: {manifest['true_evidence_holes']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
