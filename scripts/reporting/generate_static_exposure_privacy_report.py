#!/usr/bin/env python3
"""Generate a read-only Static Exposure & Privacy Assessment report."""

from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parents[2]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from scytaledroid.Reporting.models import ReportRequest  # noqa: E402
from scytaledroid.Reporting.services.report_scope_selector import (  # noqa: E402
    build_report_request,
    default_as_of_now,
    eligible_static_packages_for_basis,
    find_static_application_matches,
    resolve_application_category_scope,
    resolve_named_research_cohort_scope,
    resolve_static_social_media_2025_scope,
)
from scytaledroid.Reporting.study_profiles.static_exposure_privacy import (  # noqa: E402
    generate_static_exposure_privacy_report,
)

EVIDENCE_BASIS_ALIASES = {
    "exact_manifest": "exact_historical_freeze",
    "exact_historical_freeze": "exact_historical_freeze",
    "named_static_session": "named_static_session",
    "selected_manifest": "selected_publication_manifest",
    "selected_publication_manifest": "selected_publication_manifest",
    "latest_valid_as_of": "latest_valid_as_of",
    "fixed_recent_window": "fixed_recent_window",
}
SCOPE_TYPE_ALIASES = {
    "research_dataset": "research_cohort",
    "research_cohort": "research_cohort",
    "category": "application_category",
    "application_category": "application_category",
    "single_app": "single_app",
    "all_apps": "all_eligible_apps",
    "all_eligible_apps": "all_eligible_apps",
    "saved_custom_scope": "saved_custom_scope",
}


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--scope-type",
        required=True,
        metavar="{research_dataset,category,single_app,all_apps}",
        help="Report scope. Existing automation aliases are still accepted.",
    )
    parser.add_argument("--cohort-key", help="Research dataset key for --scope-type research_dataset.")
    parser.add_argument("--category", help="Application category for --scope-type category.")
    parser.add_argument("--package", help="Package name for --scope-type single_app.")
    parser.add_argument(
        "--saved-scope",
        choices=["static_social_media_2025"],
        help=argparse.SUPPRESS,
    )
    parser.add_argument(
        "--evidence-basis-type",
        required=True,
        metavar="{exact_manifest,named_static_session,selected_manifest,latest_valid_as_of,fixed_recent_window}",
        help="Evidence selector. Existing automation aliases are still accepted.",
    )
    parser.add_argument("--evidence-basis-key", required=True, help="Manifest path, static session stamp, or label for the evidence basis.")
    parser.add_argument("--as-of-utc", help="UTC timestamp for latest_valid_as_of. Defaults to now when needed.")
    parser.add_argument("--window-start-utc", help="UTC start timestamp for fixed_recent_window.")
    parser.add_argument("--window-end-utc", help="UTC end timestamp for fixed_recent_window.")
    parser.add_argument(
        "--report-mode",
        choices=["report_bundle", "exploratory", "archive"],
        default="report_bundle",
        help="Output mode shown to operators. Defaults to a standard report bundle.",
    )
    parser.add_argument(
        "--output-contract",
        choices=["exploratory", "publication_candidate", "frozen"],
        default=None,
        help=argparse.SUPPRESS,
    )
    parser.add_argument("--output-dir", help="Explicit output directory.")
    parser.add_argument("--operator-notes", default="")
    parser.add_argument("--include-tex", action="store_true", help="Also generate TeX table snippets and layout-fit artifacts.")
    return parser


def _output_contract_for_args(args: argparse.Namespace) -> str:
    """Map the operator-facing report mode onto the internal compatibility value."""

    if args.output_contract:
        return str(args.output_contract)
    if args.report_mode == "exploratory":
        return "exploratory"
    if args.report_mode == "archive":
        return "frozen"
    return "publication_candidate"


def _normalize_evidence_basis_type(value: str) -> str:
    normalized = EVIDENCE_BASIS_ALIASES.get(str(value or "").strip())
    if not normalized:
        allowed = ", ".join(["exact_manifest", "named_static_session", "selected_manifest", "latest_valid_as_of", "fixed_recent_window"])
        raise SystemExit(f"Unsupported --evidence-basis-type {value!r}. Use one of: {allowed}")
    return normalized


def _normalize_scope_type(value: str) -> str:
    normalized = SCOPE_TYPE_ALIASES.get(str(value or "").strip())
    if not normalized:
        allowed = ", ".join(["research_dataset", "category", "single_app", "all_apps"])
        raise SystemExit(f"Unsupported --scope-type {value!r}. Use one of: {allowed}")
    return normalized


def _parse_iso_utc(value: str) -> datetime:
    text = str(value or "").strip()
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    return datetime.fromisoformat(text)


def _default_recent_window(*, start_utc: str | None, end_utc: str | None, days: int = 30) -> tuple[str, str]:
    end_text = end_utc or default_as_of_now()
    if start_utc:
        return start_utc, end_text
    start = _parse_iso_utc(end_text) - timedelta(days=days)
    return start.isoformat(), end_text


def _resolve_single_app_query(query: str) -> tuple[str, str, list[str]]:
    requested = str(query or "").strip()
    if not requested:
        raise SystemExit("--package is required for single_app scope")
    matches = find_static_application_matches(requested, limit=5)
    exact = [
        row
        for row in matches
        if str(row.get("package_name") or "").strip().lower() == requested.lower()
        or str(row.get("display_name") or "").strip().lower() == requested.lower()
    ]
    selected: dict[str, Any] | None = None
    if len(exact) == 1:
        selected = exact[0]
    elif len(matches) == 1:
        selected = matches[0]
    elif matches and "." not in requested:
        options = ", ".join(
            f"{row.get('display_name') or row.get('package_name')} ({row.get('package_name')})"
            for row in matches[:5]
        )
        raise SystemExit(f"Ambiguous app name {requested!r}. Use one package name: {options}")

    if selected:
        package_name = str(selected.get("package_name") or "").strip().lower()
        label = str(selected.get("display_name") or package_name).strip()
        return package_name, label, [package_name]
    if "." not in requested:
        raise SystemExit(f"No app named {requested!r} was found. Use a display name or Android package name.")
    package_name = requested.lower()
    return package_name, package_name, [package_name]


def _build_request(args: argparse.Namespace) -> ReportRequest:
    evidence_basis_type = _normalize_evidence_basis_type(args.evidence_basis_type)
    requested_scope_type = _normalize_scope_type(args.scope_type)
    as_of_utc = args.as_of_utc or (default_as_of_now() if evidence_basis_type == "latest_valid_as_of" else None)
    window_start_utc = args.window_start_utc
    window_end_utc = args.window_end_utc or (default_as_of_now() if evidence_basis_type == "fixed_recent_window" else None)
    if evidence_basis_type == "fixed_recent_window":
        window_start_utc, window_end_utc = _default_recent_window(
            start_utc=window_start_utc,
            end_utc=window_end_utc,
            days=30,
        )
    if args.saved_scope:
        scope_key, scope_label, packages = resolve_static_social_media_2025_scope()
        scope_type = "saved_custom_scope"
    elif requested_scope_type == "research_cohort":
        if not args.cohort_key:
            raise SystemExit("--cohort-key is required for research_dataset scope")
        scope_key, scope_label, packages = resolve_named_research_cohort_scope(args.cohort_key)
        scope_type = "research_cohort"
    elif requested_scope_type == "application_category":
        if not args.category:
            raise SystemExit("--category is required for category scope")
        scope_key, scope_label, packages = resolve_application_category_scope(args.category)
        scope_type = "application_category"
    elif requested_scope_type == "single_app":
        if not args.package:
            raise SystemExit("--package is required for single_app scope")
        scope_key, scope_label, packages = _resolve_single_app_query(args.package)
        scope_type = "single_app"
    elif requested_scope_type == "all_eligible_apps":
        packages = eligible_static_packages_for_basis(
            evidence_basis_type=evidence_basis_type,
            evidence_basis_key=args.evidence_basis_key,
            as_of_utc=as_of_utc,
            window_start_utc=window_start_utc,
            window_end_utc=window_end_utc,
        )
        scope_key = "all_eligible_static_apps"
        scope_label = "All eligible static applications"
        scope_type = "all_eligible_apps"
    else:
        raise SystemExit("legacy saved scopes require --saved-scope")

    return build_report_request(
        study_profile_key="static_exposure_privacy",
        scope_type=scope_type,
        scope_key=scope_key,
        scope_label=scope_label,
        package_names=packages,
        evidence_basis_type=evidence_basis_type,
        evidence_basis_key=args.evidence_basis_key,
        output_contract=_output_contract_for_args(args),
        as_of_utc=as_of_utc,
        window_start_utc=window_start_utc,
        window_end_utc=window_end_utc,
        operator_notes=args.operator_notes,
        requested_formats=["csv", "json", "txt", "figures", "tex"] if args.include_tex else None,
    )


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    request = _build_request(args)
    try:
        result = generate_static_exposure_privacy_report(
            request,
            output_dir=Path(args.output_dir).resolve() if args.output_dir else None,
        )
    except (FileNotFoundError, ValueError) as exc:
        print(json.dumps({"status": "BLOCKED", "reason": str(exc)}, indent=2, sort_keys=True), file=sys.stderr)
        return 2
    print(json.dumps({"status": "OK", "output_dir": result["output_dir"], "row_counts": result["manifest"]["row_counts"]}, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
