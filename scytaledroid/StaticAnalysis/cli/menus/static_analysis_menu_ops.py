"""Interactive static menu subflows: preset choice, optional batch sizing, and app search.

Kept separate from ``static_analysis_menu`` so the main loop file stays readable; behavior is unchanged.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from scytaledroid.Utils.DisplayUtils import menu_utils, prompt_utils, status_messages, table_utils

from ...core.detector_runner import PIPELINE_STAGES
from ..core.analysis_profiles import run_modules_for_profile
from ..flows.research_cohort import choose_research_cohort_scope as _choose_research_cohort_scope

if TYPE_CHECKING:
    from ..commands.models import Command
    from ..core.models import ScopeSelection


def distinct_package_count(groups: tuple) -> int:
    return len(
        {
            str(getattr(group, "package_name", "") or "").strip().lower()
            for group in groups
            if getattr(group, "package_name", None)
        }
    )


def latest_scope_for_all(groups: tuple) -> ScopeSelection:
    from ..core.models import ScopeSelection
    from ..flows.selection import select_latest_groups

    grouped: dict[str, list[object]] = {}
    order: list[str] = []
    for group in groups:
        package = str(getattr(group, "package_name", "") or "").strip().lower()
        if not package:
            continue
        if package not in grouped:
            grouped[package] = []
            order.append(package)
        grouped[package].append(group)

    selected = []
    for package in order:
        selected.extend(select_latest_groups(tuple(grouped[package])))
    return ScopeSelection("all", "All harvested apps", tuple(selected))


def choose_all_scope_variant(selection: ScopeSelection) -> ScopeSelection | None:
    from ..core.models import ScopeSelection

    total = len(selection.groups)
    print()
    menu_utils.print_section("Batch Size")
    print("1) All apps")
    print("2) Smoke batch (5)")
    print("3) Smoke batch (10)")
    print("4) Smoke batch (20)")
    print("5) Persistence test batch (10)")
    print("0) Back")
    choice = prompt_utils.get_choice(["1", "2", "3", "4", "5", "0"], default="1")
    if choice == "0":
        return None
    if choice == "1":
        return selection

    batch_sizes = {"2": 5, "3": 10, "4": 20, "5": 10}
    batch_size = min(batch_sizes[choice], total)
    scoped = tuple(selection.groups[:batch_size])
    return ScopeSelection(
        "all",
        (
            f"Persistence test ({batch_size} apps)"
            if choice == "5"
            else f"Smoke batch ({batch_size} apps)"
        ),
        scoped,
    )


def search_app_scope(groups: tuple) -> ScopeSelection | None:
    from ...core.repository import list_packages
    from ..core.models import ScopeSelection
    from ..flows.selection import select_latest_groups

    packages = list_packages(groups)
    if not packages:
        print(status_messages.status("No packages available for analysis.", level="warn"))
        prompt_utils.press_enter_to_continue()
        return None

    print()
    menu_utils.print_header(
        "Analyze One App",
        "Search harvested APKs on disk only (same library as the main menu).",
    )
    print("Search by package or app name.")
    print()
    print("Examples:")
    print("- signal")
    print("- instagram")
    print("- com.whatsapp")
    print("- twitter")
    print("- google")
    print()
    query = prompt_utils.prompt_text("Search", required=False).strip().lower()
    if not query:
        return None

    indexed_matches: list[tuple[int, tuple[str, str, int, str | None]]] = [
        (idx, item)
        for idx, item in enumerate(packages)
        if query in item[0].lower() or (item[3] and query in item[3].lower())
    ]
    if not indexed_matches:
        print(status_messages.status(f"No apps matched '{query}'.", level="warn"))
        prompt_utils.press_enter_to_continue()
        return None

    def _match_rank(item: tuple[str, str, int, str | None], original_index: int) -> tuple[int, int, int, int, int]:
        package_name, _version, _count, app_label = item
        package_lc = package_name.lower()
        label_lc = str(app_label or "").lower()

        if package_lc == query:
            rank = 0
        elif label_lc == query:
            rank = 1
        elif package_lc.startswith(query):
            rank = 2
        elif label_lc.startswith(query):
            rank = 3
        elif query in package_lc:
            rank = 4
        else:
            rank = 5

        return (
            rank,
            len(package_name),
            len(str(app_label or package_name)),
            0 if package_name.startswith("com.") else 1,
            original_index,
        )

    matches = [item for _idx, item in sorted(indexed_matches, key=lambda entry: _match_rank(entry[1], entry[0]))]

    print()
    menu_utils.print_section("Matches")
    limited = matches[:20]
    for idx, (package, _version, _count, app_label) in enumerate(limited, start=1):
        label = app_label or package
        print(f"{idx}) {label:<18} {package}")
    print("0) Back")
    choice = prompt_utils.get_choice(
        [str(i) for i in range(1, len(limited) + 1)] + ["0"],
        default="1",
    )
    if choice == "0":
        return None

    package_name, _version, _count, app_label = limited[int(choice) - 1]
    matching_groups = tuple(group for group in groups if group.package_name == package_name)
    scoped = select_latest_groups(matching_groups)
    label = f"{app_label} | {package_name}" if app_label else package_name
    return ScopeSelection("app", label, scoped)


def choose_exact_dynamic_worklist_target() -> tuple[ScopeSelection, object] | None:
    """Select and validate an exact APK target from the dynamic/static worklist."""

    from ..flows.exact_target import (
        ExactTargetResolutionError,
        assess_exact_target_readiness,
        resolve_exact_static_target,
        write_exact_target_receipt,
    )

    try:
        from scytaledroid.Database.db_core import db_queries as core_q
        from scytaledroid.Database.db_scripts.dynamic_static_alignment_report import sql_worklist
    except Exception as exc:
        print(status_messages.status(f"Dynamic/static worklist unavailable: {exc}", level="error"))
        prompt_utils.press_enter_to_continue()
        return None

    rows = core_q.run_sql(
        sql_worklist(25),
        (),
        fetch="all_dict",
        query_name="static_menu.exact_dynamic_worklist",
    ) or []
    if not rows:
        print(status_messages.status("No exact dynamic APK hashes currently need static analysis.", level="success"))
        prompt_utils.press_enter_to_continue()
        return None

    print()
    menu_utils.print_header(
        "Exact Dynamic APK Hash",
        "Select a dynamic/static worklist row. This path never falls back to newest package capture.",
    )
    try:
        from scytaledroid.StaticAnalysis.core.repository import group_artifacts

        receipt_groups = tuple(group_artifacts())
    except Exception:
        receipt_groups = ()
    readiness_rows = []
    for row in rows:
        try:
            readiness_rows.append(
                assess_exact_target_readiness(
                    apk_id=row.get("apk_id"),
                    base_apk_sha256=row.get("base_apk_sha256"),
                    package_name=row.get("package_name"),
                    dynamic_runs=row.get("dynamic_runs"),
                    groups=receipt_groups,
                )
            )
        except ExactTargetResolutionError:
            readiness_rows.append(None)
    table_rows: list[list[str]] = []
    for idx, row in enumerate(rows, start=1):
        readiness = readiness_rows[idx - 1]
        action = readiness.recommended_action if readiness is not None else "readiness_error"
        splits = (
            f"{readiness.split_files_available}/{readiness.split_files_expected}"
            if readiness is not None
            else "?"
        )
        table_rows.append(
            [
                str(idx),
                str(row.get("package_name") or ""),
                str(row.get("apk_id") or ""),
                str(row.get("base_apk_sha256") or "")[:16] + "...",
                str(row.get("dynamic_runs") or "0"),
                splits,
                action,
            ]
        )
    table_utils.render_table(
        ["#", "Package", "apk_id", "Base hash", "Dyn", "Splits", "Action"],
        table_rows,
        padding=1,
        compact=True,
    )
    print("0) Back")
    choice = prompt_utils.get_choice(
        [str(i) for i in range(1, len(rows) + 1)] + ["0"],
        default="1",
    )
    if choice == "0":
        return None

    row = rows[int(choice) - 1]
    readiness = readiness_rows[int(choice) - 1]
    if readiness is None:
        try:
            readiness = assess_exact_target_readiness(
                apk_id=row.get("apk_id"),
                base_apk_sha256=row.get("base_apk_sha256"),
                package_name=row.get("package_name"),
                dynamic_runs=row.get("dynamic_runs"),
                groups=receipt_groups,
            )
        except ExactTargetResolutionError as exc:
            print(status_messages.status(f"Exact target readiness failed: {exc}", level="error"))
            prompt_utils.press_enter_to_continue()
            return None

    print()
    menu_utils.print_section("Exact Target Readiness")
    print(f"  package            : {readiness.package_name}")
    print(f"  apk_id             : {readiness.apk_id or 'unknown'}")
    print(f"  expected hash      : {readiness.base_apk_sha256 or 'unknown'}")
    print(f"  repository row     : {'yes' if readiness.repository_row_exists else 'no'}")
    print(f"  receipt-backed set : {'yes' if readiness.receipt_backed_group_available else 'no'}")
    print(
        "  base bytes         : "
        f"{'available' if readiness.base_file_available else 'missing'} "
        f"(verified={'yes' if readiness.base_file_hash_verified else 'no'})"
    )
    print(
        "  split bytes        : "
        f"{readiness.split_files_available}/{readiness.split_files_expected} verified"
    )
    print(f"  recorded path      : {'available' if readiness.recorded_local_file_available else 'missing'}")
    print(f"  canonical store    : {'available' if readiness.canonical_store_file_available else 'missing'}")
    print(f"  recommended action : {readiness.recommended_action}")
    print(f"  reason             : {readiness.reason}")

    include_splits = "auto"
    if readiness.recommended_action not in {"exact_static_available", "base_only_available_explicit"}:
        print(
            status_messages.status(
                "This target is not currently analyzable from local bytes. "
                "Restore artifacts or reharvest explicitly before static analysis.",
                level="warn",
            )
        )
        prompt_utils.press_enter_to_continue()
        return None
    if readiness.recommended_action == "base_only_available_explicit":
        print("Only verified base APK bytes are available for this target.")
        if not prompt_utils.prompt_yes_no("Run exact base-only analysis?", default=False):
            return None
        include_splits = "base-only"

    try:
        target = resolve_exact_static_target(
            apk_id=row.get("apk_id"),
            base_apk_sha256=row.get("base_apk_sha256"),
            package_name=row.get("package_name"),
            include_splits=include_splits,
        )
    except ExactTargetResolutionError as exc:
        print(status_messages.status(f"Exact target preflight failed: {exc}", level="error"))
        prompt_utils.press_enter_to_continue()
        return None

    receipt_path = write_exact_target_receipt(
        target,
        source_worklist_bucket="dynamic_static_alignment",
    )
    print()
    menu_utils.print_section("Exact Target Preflight")
    print(f"  package           : {target.package_name}")
    print(f"  apk_id            : {target.apk_id or 'unknown'}")
    print(f"  expected hash     : {target.expected_base_sha256}")
    print(f"  actual hash       : {target.actual_base_sha256} (verified)")
    print(f"  split mode        : {target.split_mode}")
    print(f"  split members     : {target.split_count}")
    print(f"  artifacts verified: {len(target.artifacts)}")
    print(f"  receipt           : {receipt_path}")
    if not prompt_utils.prompt_yes_no("Run static analysis for this exact verified target?", default=True):
        return None
    return target.selection, target


def choose_research_cohort_scope(groups: tuple) -> ScopeSelection | None:
    return _choose_research_cohort_scope(groups)


def emit_selected_preset_summary(command: Command) -> None:
    """Summarize analyzer/pipeline sizing after a preset is chosen."""
    profile = str(command.profile or "full").lower()
    cid = str(getattr(command, "id", "") or "").upper()
    if cid == "T":
        preset_label = (command.title or "Persistence test").strip()
    else:
        preset_label = {"full": "Full analysis", "lightweight": "Fast analysis"}.get(
            profile,
            (command.title or profile).strip(),
        )
    print()
    summary = f"  Preset            : {preset_label}"
    if profile in {"full", "lightweight"}:
        mod_count = len(run_modules_for_profile(profile))
        summary += f" · {mod_count} modules · {len(PIPELINE_STAGES)} detector stages"
    else:
        summary += f" · up to {len(PIPELINE_STAGES)} detector stages"
    print(summary)


def choose_run_profile() -> Command | None:
    from ..commands import get_command
    from ..commands.models import Command

    print()
    menu_utils.print_section("Analysis Preset")
    print("1) Full analysis")
    print("2) Fast analysis")
    print("3) Persistence test")
    print("4) Custom detector profile")
    print("0) Back")
    choice = prompt_utils.get_choice(["1", "2", "3", "4", "0"], default="1", casefold=True)
    if choice == "0":
        return None
    if choice in {"1", "2"}:
        command = get_command(choice)
        if command is not None:
            emit_selected_preset_summary(command)
            return command
    if choice == "3":
        persisted = Command(
            id="T",
            title="Persistence test",
            description="Run a compact end-to-end persistence/finalization validation.",
            kind="scan",
            profile="full",
            section="workflow",
            auto_verify=True,
            prompt_reset=True,
            workers_override="2",
        )
        emit_selected_preset_summary(persisted)
        return persisted

    print()
    menu_utils.print_section("Custom detector profile")
    print("1) Metadata smoke")
    print("2) Permission audit")
    print("3) Strings and secrets")
    print("4) IPC and components")
    print("5) Network surface")
    print("6) Crypto hygiene")
    print("7) SDK inventory")
    print("0) Back")
    choice = prompt_utils.get_choice(["1", "2", "3", "4", "5", "6", "7", "0"], default="1")
    if choice == "0":
        return None
    focused_profiles = {
        "1": ("metadata", "Metadata smoke"),
        "2": ("permissions", "Permission audit"),
        "3": ("strings", "Strings and secrets"),
        "4": ("ipc", "IPC and components"),
        "5": ("nsc", "Network surface"),
        "6": ("crypto", "Crypto hygiene"),
        "7": ("sdk", "SDK inventory"),
    }
    profile, title = focused_profiles[choice]
    advanced_cmd = Command(
        id=choice,
        title=title,
        description=title,
        kind="scan",
        profile=profile,
        section="workflow",
        auto_verify=True,
    )
    emit_selected_preset_summary(advanced_cmd)
    return advanced_cmd


__all__ = [
    "choose_all_scope_variant",
    "choose_research_cohort_scope",
    "choose_run_profile",
    "distinct_package_count",
    "emit_selected_preset_summary",
    "latest_scope_for_all",
    "search_app_scope",
]
