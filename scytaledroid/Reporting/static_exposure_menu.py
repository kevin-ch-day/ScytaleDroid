"""Interactive launcher for the Static Exposure & Privacy Assessment report."""

from __future__ import annotations

from collections.abc import Callable
from datetime import UTC, datetime, timedelta

from scytaledroid.Database.db_core import db_queries as core_q
from scytaledroid.Utils.DisplayUtils import menu_utils, prompt_utils, status_messages, summary_cards, table_utils


def _recent_static_window(default_as_of_now_fn: Callable[[], str], *, days: int = 30) -> tuple[str, str]:
    """Return a UTC static evidence window ending at the current report time."""

    window_end = default_as_of_now_fn()
    end_dt = datetime.fromisoformat(window_end.replace("Z", "+00:00"))
    if end_dt.tzinfo is None:
        end_dt = end_dt.replace(tzinfo=UTC)
    end_dt = end_dt.astimezone(UTC)
    return (end_dt - timedelta(days=days)).replace(microsecond=0).isoformat(), end_dt.replace(microsecond=0).isoformat()


def _valid_static_history_days(value: str) -> bool:
    try:
        days = int(str(value).strip())
    except ValueError:
        return False
    return 1 <= days <= 30


def _prompt_static_history_days() -> int:
    value = prompt_utils.prompt_text(
        "History window days",
        default="30",
        required=True,
        validator=_valid_static_history_days,
        error_message="Enter a whole number from 1 to 30.",
    )
    return int(value)


def _choose_static_evidence_window(
    default_as_of_now_fn: Callable[[], str],
    *,
    scope_type: str,
) -> tuple[str, str, str | None, str | None, str | None] | None:
    """Return the static evidence window selected by the operator."""

    if scope_type == "single_app":
        options = [
            menu_utils.MenuOption("1", "Current app version", badge="RECOMMENDED"),
            menu_utils.MenuOption("2", "App history window"),
        ]
        menu_utils.print_section("Single-App Evidence")
        menu_utils.print_menu(options, show_exit=True, exit_label="Cancel", compact=True)
        choice = prompt_utils.menu_choice(menu_utils.selectable_keys(options, include_exit=True), default="1")
        if choice == "0":
            return None
        if choice == "1":
            as_of_utc = default_as_of_now_fn()
            return "latest_valid_as_of", "latest_valid_static_evidence", as_of_utc, None, None
        days = _prompt_static_history_days()
        window_start, window_end = _recent_static_window(default_as_of_now_fn, days=days)
        return "fixed_recent_window", f"single_app_history_{days}d", None, window_start, window_end

    options = [
        menu_utils.MenuOption("1", "Current app version evidence", badge="RECOMMENDED"),
        menu_utils.MenuOption("2", "App version history (last 30 days)"),
        menu_utils.MenuOption("3", "Latest valid static evidence now"),
    ]
    menu_utils.print_section("Evidence Window")
    menu_utils.print_menu(options, show_exit=True, exit_label="Cancel", compact=True)
    choice = prompt_utils.menu_choice(menu_utils.selectable_keys(options, include_exit=True), default="1")
    if choice == "0":
        return None
    if choice == "1":
        window_start, window_end = _recent_static_window(default_as_of_now_fn, days=30)
        return "fixed_recent_window", "current_static_evidence_30d", None, window_start, window_end
    if choice == "2":
        window_start, window_end = _recent_static_window(default_as_of_now_fn, days=30)
        return "fixed_recent_window", "app_version_history_30d", None, window_start, window_end
    as_of_utc = default_as_of_now_fn()
    return "latest_valid_as_of", "latest_valid_static_evidence", as_of_utc, None, None


def _describe_static_evidence_choice(request: object) -> str:
    """Return a concise operator-facing evidence description."""

    evidence_key = str(getattr(request, "evidence_basis_key", "") or "")
    evidence_type = str(getattr(request, "evidence_basis_type", "") or "")
    if evidence_key.startswith("single_app_history_"):
        days = evidence_key.removeprefix("single_app_history_").removesuffix("d")
        return f"Single-app history, last {days} days"
    if evidence_key == "app_version_history_30d":
        return "App version history, last 30 days"
    if evidence_key == "current_static_evidence_30d":
        return "Current app version evidence"
    if evidence_key == "latest_valid_static_evidence":
        return "Latest valid static evidence now"
    if evidence_type == "fixed_recent_window":
        return "Selected recent evidence window"
    if evidence_type == "latest_valid_as_of":
        return "Latest valid static evidence"
    return evidence_type.replace("_", " ").strip() or "Selected static evidence"


def _describe_static_evidence_window(request: object) -> str:
    """Return the selected report window without exposing backend keys."""

    window_start = str(getattr(request, "window_start_utc", "") or "")
    window_end = str(getattr(request, "window_end_utc", "") or "")
    as_of = str(getattr(request, "as_of_utc", "") or "")
    if window_start and window_end:
        return f"{_format_operator_date(window_start)} to {_format_operator_date(window_end)}"
    if as_of:
        return f"as of {_format_operator_date(as_of)}"
    return "selected static evidence"


def _format_operator_date(value: str) -> str:
    """Format an ISO timestamp as a short operator-facing date."""

    raw = str(value or "").strip()
    if not raw:
        return ""
    try:
        parsed = datetime.fromisoformat(raw.replace("Z", "+00:00"))
    except ValueError:
        return raw.split("T", 1)[0] or raw
    return f"{parsed.month}/{parsed.day}/{parsed.year}"


def _app_name_preview(package_names: list[str], *, limit: int = 8) -> str:
    """Return a concise display-name preview for the confirmation card."""

    packages = [str(package).strip().lower() for package in package_names if str(package).strip()]
    if not packages:
        return "none"
    label_map = _load_app_display_names(packages)
    labels = [label_map.get(package, package) for package in packages[:limit]]
    suffix = ", ..." if len(packages) > limit else ""
    return ", ".join(labels) + suffix


def _load_app_display_names(package_names: list[str]) -> dict[str, str]:
    normalized = sorted({str(package).strip().lower() for package in package_names if str(package).strip()})
    if not normalized:
        return {}
    placeholders = ", ".join(["%s"] * len(normalized))
    try:
        rows = core_q.run_sql(
            f"""
            SELECT LOWER(TRIM(package_name)) AS package_name,
                   COALESCE(NULLIF(display_name, ''), package_name) AS display_name
            FROM apps
            WHERE LOWER(TRIM(package_name)) IN ({placeholders})
            """,
            tuple(normalized),
            fetch="all_dict",
            query_name="reporting.static_exposure.app_preview_labels",
        ) or []
    except Exception:
        return {}
    out: dict[str, str] = {}
    for row in rows:
        package = str(row.get("package_name") or "").strip().lower()
        label = str(row.get("display_name") or package).strip()
        if package and label:
            out[package] = label
    return out


def _resolve_single_static_app_scope(
    query: str,
    matcher: Callable[[str], list[dict[str, object]]],
) -> tuple[str, str, list[str]] | None:
    """Resolve an operator-entered app label/package into a single package scope."""

    requested = str(query or "").strip()
    if not requested:
        return None
    matches = matcher(requested)
    exact_matches = [
        row
        for row in matches
        if str(row.get("package_name") or "").strip().lower() == requested.lower()
        or str(row.get("display_name") or "").strip().lower() == requested.lower()
    ]
    if len(exact_matches) == 1:
        selected = exact_matches[0]
        package_name = str(selected.get("package_name") or "").strip().lower()
        label = str(selected.get("display_name") or package_name).strip()
        return package_name, label, [package_name]
    if len(matches) == 1:
        selected = matches[0]
        package_name = str(selected.get("package_name") or "").strip().lower()
        label = str(selected.get("display_name") or package_name).strip()
        return package_name, label, [package_name]
    if matches:
        rows = [
            [
                str(idx),
                str(row.get("display_name") or row.get("package_name") or ""),
                str(row.get("package_name") or ""),
                str(row.get("app_category") or ""),
            ]
            for idx, row in enumerate(matches, start=1)
        ]
        table_utils.render_table(["#", "App", "Package", "Category"], rows, compact=True)
        selected_idx = prompt_utils.menu_choice([str(i) for i in range(1, len(matches) + 1)] + ["0"], default="1")
        if selected_idx == "0":
            return None
        selected = matches[int(selected_idx) - 1]
        package_name = str(selected.get("package_name") or "").strip().lower()
        label = str(selected.get("display_name") or package_name).strip()
        return package_name, label, [package_name]
    fallback = requested.lower()
    if "." not in fallback:
        print(status_messages.status("No matching app name found. Try the display name shown on the device, such as Facebook or Snapchat.", level="warn"))
        return None
    print(status_messages.status("No app-name match found; using the entered package identifier.", level="warn"))
    return fallback, fallback, [fallback]


def handle_generate_static_exposure_privacy_report() -> None:
    """Interactive launcher for the Static Exposure & Privacy Assessment."""

    from scytaledroid.Reporting.services.report_scope_selector import (
        build_report_request,
        default_as_of_now,
        eligible_static_packages_for_basis,
        find_static_application_matches,
        list_application_categories,
        list_named_research_cohorts,
        resolve_application_category_scope,
        resolve_named_research_cohort_scope,
    )
    from scytaledroid.Reporting.study_profiles.static_exposure_privacy import (
        generate_static_exposure_privacy_report,
    )

    print()
    menu_utils.print_header("Static Exposure & Privacy Assessment")
    scope_options = [
        ("1", "Research dataset"),
        ("2", "Application category"),
        ("3", "Single application"),
        ("4", "All eligible applications"),
    ]
    menu_utils.print_section("Report Scope")
    menu_utils.print_menu([menu_utils.MenuOption(k, v) for k, v in scope_options], show_exit=True, exit_label="Cancel", compact=True)
    scope_choice = prompt_utils.menu_choice([key for key, _ in scope_options] + ["0"], default="1")
    if scope_choice == "0":
        return
    exclusions: list[dict[str, object]] = []
    if scope_choice == "1":
        cohorts = list_named_research_cohorts()
        if cohorts:
            rows = [
                [str(idx), str(row.get("display_name") or row.get("cohort_key")), str(row.get("active_member_count") or 0)]
                for idx, row in enumerate(cohorts, start=1)
            ]
            table_utils.render_table(["#", "Cohort", "Apps"], rows, compact=True)
            selected = prompt_utils.menu_choice([str(i) for i in range(1, len(cohorts) + 1)] + ["0"], default="1")
            if selected == "0":
                return
            cohort_key = str(cohorts[int(selected) - 1].get("cohort_key") or "")
        else:
            cohort_key = prompt_utils.prompt_text("Research cohort key", required=True)
        scope_key, scope_label, packages = resolve_named_research_cohort_scope(cohort_key)
        scope_type = "research_cohort"
    elif scope_choice == "2":
        categories = list_application_categories()
        if categories:
            rows = [
                [str(idx), str(row.get("category_name") or "Uncategorized"), str(row.get("app_count") or 0)]
                for idx, row in enumerate(categories, start=1)
            ]
            table_utils.render_table(["#", "Category", "Apps"], rows, compact=True)
            selected = prompt_utils.menu_choice([str(i) for i in range(1, len(categories) + 1)] + ["0"], default="1")
            if selected == "0":
                return
            category_name = str(categories[int(selected) - 1].get("category_name") or "")
        else:
            category_name = prompt_utils.prompt_text("Application category", required=True)
        scope_key, scope_label, packages = resolve_application_category_scope(category_name)
        scope_type = "application_category"
    elif scope_choice == "3":
        query = prompt_utils.prompt_text(
            "App name",
            required=True,
            hint="Use the display name you know, such as Facebook, Snapchat, Gmail, or Telegram.",
        )
        selected_app = _resolve_single_static_app_scope(query, find_static_application_matches)
        if selected_app is None:
            return
        scope_key, scope_label, packages = selected_app
        scope_type = "single_app"
    else:
        scope_key = "all_eligible_static_apps"
        scope_label = "All eligible static applications"
        scope_type = "all_eligible_apps"

    print()
    selected_evidence_window = _choose_static_evidence_window(default_as_of_now, scope_type=scope_type)
    if selected_evidence_window is None:
        return
    evidence_basis_type, evidence_basis_key, as_of_utc, window_start_utc, window_end_utc = selected_evidence_window
    if scope_type == "all_eligible_apps":
        packages = eligible_static_packages_for_basis(
            evidence_basis_type=evidence_basis_type,
            evidence_basis_key=evidence_basis_key,
            as_of_utc=as_of_utc,
            window_start_utc=window_start_utc,
            window_end_utc=window_end_utc,
        )
        print(status_messages.status("Eligibility rule: completed + canonical + identity-valid static evidence under the selected evidence window.", level="info"))

    output_contract = "publication_candidate"

    request = build_report_request(
        study_profile_key="static_exposure_privacy",
        scope_type=scope_type,
        scope_key=scope_key,
        scope_label=scope_label,
        package_names=packages,
        evidence_basis_type=evidence_basis_type,
        evidence_basis_key=evidence_basis_key,
        output_contract=output_contract,
        as_of_utc=as_of_utc,
        window_start_utc=window_start_utc,
        window_end_utc=window_end_utc,
        scope_exclusions=exclusions,
    )
    print()
    app_preview = _app_name_preview(request.package_names)
    print(
        summary_cards.format_summary_card(
            "Confirm Report Request",
            [
                summary_cards.summary_item("Study", "Static Exposure & Privacy Assessment", value_style="accent"),
                summary_cards.summary_item("Scope", request.scope_label, value_style="accent"),
                summary_cards.summary_item("Applications", len(request.package_names), value_style="accent"),
                summary_cards.summary_item("Apps", app_preview, value_style="muted"),
                summary_cards.summary_item("Evidence", _describe_static_evidence_choice(request), value_style="accent"),
                summary_cards.summary_item("Window", _describe_static_evidence_window(request), value_style="muted"),
                summary_cards.summary_item("Output", "output/reports/static_exposure_privacy/<timestamp>", value_style="muted"),
            ],
            footer="Read-only report generation; source data and analysis records are not modified.",
        )
    )
    if not prompt_utils.prompt_yes_no("Generate report now?", default=False):
        return
    result = generate_static_exposure_privacy_report(request)
    print(status_messages.status(f"Wrote report: {result['output_dir']}", level="success"))
    prompt_utils.press_enter_to_continue()


__all__ = [
    "handle_generate_static_exposure_privacy_report",
]
