"""Interactive menu for APK static analysis workflows."""

from __future__ import annotations

from collections import Counter
from pathlib import Path
from time import perf_counter
from typing import List, Mapping, Optional

from scytaledroid.Config import app_config
from scytaledroid.Utils.DisplayUtils import (
    menu_utils,
    prompt_utils,
    status_messages,
    table_utils,
)
from scytaledroid.Utils.LoggingUtils import logging_utils as log

from ..core import AnalysisConfig, StaticAnalysisError, StaticAnalysisReport, analyze_apk
from ..core.repository import ArtifactGroup, group_artifacts, list_categories, list_packages
from ..persistence import ReportStorageError, save_report
from .options import ScanDisplayOptions, resolve_display_options
from .progress import ScanProgress


def static_analysis_menu() -> None:
    """Render the static analysis menu loop."""

    while True:
        print()
        menu_utils.print_header("Static Analysis")
        options = {
            "1": "Run static analysis for all repository apps",
            "2": "Run static analysis for a category",
            "3": "Run static analysis for a specific app",
        }
        menu_utils.print_menu(options, is_main=False)
        choice = prompt_utils.get_choice(list(options.keys()) + ["0"], default="0")

        if choice == "0":
            break
        if choice == "1":
            _run_full_repository_scan()
        elif choice == "2":
            _run_category_scan()
        elif choice == "3":
            _run_package_scan()


def _run_full_repository_scan() -> None:
    base_dir = (Path(app_config.DATA_DIR) / "apks").resolve()
    groups: List[ArtifactGroup] = group_artifacts(base_dir)
    if not groups:
        _print_no_groups_warning()
        return

    options = resolve_display_options()
    _scan_groups(
        groups,
        base_dir=base_dir,
        heading="Full Repository Scan",
        description=f"{len(groups)} group(s), {sum(len(g.artifacts) for g in groups)} artifact(s)",
        options=options,
    )


def _run_package_scan() -> None:
    base_dir = (Path(app_config.DATA_DIR) / "apks").resolve()
    groups: List[ArtifactGroup] = group_artifacts(base_dir)
    if not groups:
        _print_no_groups_warning()
        return

    packages = list_packages(groups)
    if not packages:
        _print_no_groups_warning()
        return

    print()
    menu_utils.print_header("Package Scan", "Select an app")
    rows = []
    for idx, (package_name, count) in enumerate(packages, start=1):
        rows.append([str(idx), package_name, str(count)])
    table_utils.render_table(["#", "Package", "Groups"], rows)
    print()
    choice = prompt_utils.get_choice(
        [str(idx) for idx in range(1, len(packages) + 1)] + ["0"],
        prompt="Select package #: ",
        default="0",
    )
    if choice == "0":
        return

    package_name, _ = packages[int(choice) - 1]
    scoped_groups = [group for group in groups if group.package_name == package_name]
    if not scoped_groups:
        print(status_messages.status("No artifacts found for the selected package.", level="warn"))
        prompt_utils.press_enter_to_continue()
        return

    options = resolve_display_options()
    _scan_groups(
        scoped_groups,
        base_dir=base_dir,
        heading=f"App Scan — {package_name}",
        description=f"{len(scoped_groups)} group(s)",
        options=options,
    )


def _run_category_scan() -> None:
    base_dir = (Path(app_config.DATA_DIR) / "apks").resolve()
    groups: List[ArtifactGroup] = group_artifacts(base_dir)
    if not groups:
        _print_no_groups_warning()
        return

    categories = list_categories(groups)
    if not categories:
        print(status_messages.status("No category data available.", level="warn"))
        prompt_utils.press_enter_to_continue()
        return

    print()
    menu_utils.print_header("Category Scan", "Select a category")
    rows = []
    for idx, (category, count) in enumerate(categories, start=1):
        rows.append([str(idx), category, str(count)])
    table_utils.render_table(["#", "Category", "Groups"], rows)
    print()
    choice = prompt_utils.get_choice(
        [str(idx) for idx in range(1, len(categories) + 1)] + ["0"],
        prompt="Select category #: ",
        default="0",
    )
    if choice == "0":
        return

    category_name, _ = categories[int(choice) - 1]
    scoped_groups = [group for group in groups if group.category == category_name]
    if not scoped_groups:
        print(status_messages.status("No artifacts found for the selected category.", level="warn"))
        prompt_utils.press_enter_to_continue()
        return

    options = resolve_display_options()
    _scan_groups(
        scoped_groups,
        base_dir=base_dir,
        heading=f"Category Scan — {category_name}",
        description=f"{len(scoped_groups)} group(s)",
        options=options,
    )


def _generate_report(
    apk_path: Path,
    *,
    metadata: Optional[Mapping[str, object]] = None,
    storage_root: Optional[Path] = None,
    config: Optional[AnalysisConfig] = None,
) -> tuple[Optional[StaticAnalysisReport], Optional[Path], Optional[str], bool]:
    try:
        report = analyze_apk(
            apk_path,
            metadata=metadata,
            storage_root=storage_root,
            config=config,
        )
    except StaticAnalysisError as exc:
        return None, None, str(exc), True

    try:
        saved_path = save_report(report)
        return report, saved_path, None, False
    except ReportStorageError as exc:
        log.error(str(exc), category="static_analysis")
        return report, None, str(exc), False


def _scan_groups(
    groups: List[ArtifactGroup],
    *,
    base_dir: Path,
    heading: str,
    description: str,
    options: ScanDisplayOptions,
) -> None:
    print()
    menu_utils.print_header(heading, description)

    progress = ScanProgress(total_groups=len(groups), options=options)
    progress.announce_options()

    config = AnalysisConfig(profile=options.profile, verbosity=options.verbosity)
    successes = 0
    failures = 0
    severity_totals: Counter[str] = Counter()
    printed_logs: set[str] = set()

    scan_started = perf_counter()

    for index, group in enumerate(groups, start=1):
        progress.start_group(
            index=index,
            package_name=group.package_name,
            version=group.version_display,
            category=group.category,
            artifact_count=len(group.artifacts),
        )

        for artifact_index, artifact in enumerate(group.artifacts, start=1):
            label = artifact.artifact_label or artifact.display_path
            progress.artifact_started(
                artifact_index=artifact_index,
                artifact_total=len(group.artifacts),
                label=label,
            )

            artifact_started = perf_counter()
            report, saved_path, message, fatal = _generate_report(
                artifact.path,
                metadata=artifact.metadata,
                storage_root=base_dir,
                config=config,
            )
            artifact_duration = perf_counter() - artifact_started

            if fatal or report is None:
                failures += 1
                progress.artifact_failed(label, message or "analysis failed")
                continue

            successes += 1
            counter = progress.artifact_completed(
                label=label,
                saved_path=saved_path,
                findings=report.findings,
                duration_seconds=artifact_duration if options.show_timings else None,
                warning=message,
            )
            severity_totals.update(counter)

            if options.verbosity == "debug":
                metadata_map = getattr(report, "metadata", {})
                debug_log_path = None
                if isinstance(metadata_map, Mapping):
                    debug_log_path = metadata_map.get("androguard_log_path")
                if debug_log_path and debug_log_path not in printed_logs:
                    print(f"Raw tool log: {debug_log_path}")
                    printed_logs.add(debug_log_path)

    elapsed = perf_counter() - scan_started

    summary_lines = [
        ("Groups processed", len(groups)),
        ("Artifacts analysed", successes + failures),
        ("Successful reports", successes),
        ("Failures", failures),
    ]

    if severity_totals:
        ordered_labels = ["P0", "P1", "P2", "NOTE"]
        summary_lines.append(
            (
                "Findings",
                ", ".join(
                    f"{label}:{severity_totals[label]}"
                    for label in ordered_labels
                    if severity_totals.get(label, 0)
                )
                or "none recorded",
            )
        )

    summary_lines.append(("Elapsed", _format_duration(elapsed)))

    print()
    table_utils.render_key_value_pairs(summary_lines)
    print()
    prompt_utils.press_enter_to_continue("Scan complete. Press Enter to return...")


def _print_no_groups_warning() -> None:
    print(
        status_messages.status(
            "No harvested APK groups found. Run Device Analysis → 7 to pull artifacts.",
            level="warn",
        )
    )
    prompt_utils.press_enter_to_continue()


def _format_duration(seconds: float) -> str:
    if seconds < 0.001:
        return "<1 ms"
    if seconds < 1.0:
        return f"{seconds * 1000:.0f} ms"
    return f"{seconds:.2f} s"


__all__ = ["static_analysis_menu"]
