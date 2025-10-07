"""Interactive menu for APK static analysis workflows."""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import List, Mapping, Optional

from scytaledroid.Config import app_config
from scytaledroid.Utils.DisplayUtils import (
    menu_utils,
    prompt_utils,
    status_messages,
    table_utils,
    text_blocks,
)
from scytaledroid.Utils.LoggingUtils import logging_utils as log

from .analyzer import StaticAnalysisError, StaticAnalysisReport, analyze_apk
from . import reports


@dataclass(frozen=True)
class RepositoryApk:
    """APK discovered within the harvested repository."""

    path: Path
    display_path: str
    metadata: Mapping[str, object]


def static_analysis_menu() -> None:
    """Render the static analysis menu loop."""

    while True:
        print()
        menu_utils.print_header("Static Analysis")
        options = {
            "1": "Analyze APK from repository",
            "2": "Analyze APK from local path",
            "3": "Review saved reports",
        }
        menu_utils.print_menu(options, is_main=False)
        choice = prompt_utils.get_choice(list(options.keys()) + ["0"], default="0")

        if choice == "0":
            break
        if choice == "1":
            _handle_repository_analysis()
        elif choice == "2":
            _handle_manual_analysis()
        elif choice == "3":
            _review_saved_reports()


def _handle_repository_analysis() -> None:
    entry = _select_repository_apk()
    if not entry:
        return
    storage_root = (Path(app_config.DATA_DIR) / "apks").resolve()
    _run_analysis(entry.path, metadata=entry.metadata, storage_root=storage_root)


def _handle_manual_analysis() -> None:
    apk_path = _prompt_apk_path()
    if not apk_path:
        return
    _run_analysis(apk_path)


def _run_analysis(
    apk_path: Path,
    *,
    metadata: Optional[Mapping[str, object]] = None,
    storage_root: Optional[Path] = None,
) -> None:
    print()
    print(status_messages.status(f"Analyzing {apk_path.name}...", level="info"))

    try:
        report = analyze_apk(apk_path, metadata=metadata, storage_root=storage_root)
    except StaticAnalysisError as exc:
        print(status_messages.status(str(exc), level="error"))
        prompt_utils.press_enter_to_continue()
        return

    try:
        saved_path = reports.save_report(report)
    except reports.ReportStorageError as exc:
        log.error(str(exc), category="static_analysis")
        print(status_messages.status(str(exc), level="error"))
        saved_path = None

    _display_report(report, saved_path=saved_path)


def _select_repository_apk() -> Optional[RepositoryApk]:
    entries = _discover_repository_apks()
    if not entries:
        print(
            status_messages.status(
                "No harvested APKs found. Run Device Analysis → 7 to pull artifacts.",
                level="warn",
            )
        )
        prompt_utils.press_enter_to_continue()
        return None

    print()
    menu_utils.print_header("Repository APKs", "Select an artifact to analyse")
    rows = []
    for idx, entry in enumerate(entries, start=1):
        meta = entry.metadata
        label = str(meta.get("app_label") or meta.get("package_name") or entry.path.stem)
        version = str(meta.get("version_name") or meta.get("version_code") or "-")
        rows.append([str(idx), label, version, entry.display_path])
    table_utils.render_table(["#", "Package", "Version", "Path"], rows)
    print()
    choice = prompt_utils.get_choice(
        [str(idx) for idx in range(1, len(entries) + 1)] + ["0"],
        prompt="Select APK #: ",
        default="0",
    )
    if choice == "0":
        return None
    return entries[int(choice) - 1]


def _review_saved_reports() -> None:
    stored = reports.list_reports()
    if not stored:
        print(status_messages.status("No analysis reports found yet.", level="warn"))
        prompt_utils.press_enter_to_continue()
        return

    print()
    menu_utils.print_header("Saved Reports", "Most recent first")
    rows = []
    for idx, entry in enumerate(stored, start=1):
        report = entry.report
        manifest = report.manifest
        version = manifest.version_name or manifest.version_code or "-"
        sha256 = report.hashes.get("sha256") or "-"
        display_sha = sha256[:12] + ("…" if len(sha256) > 12 else "") if sha256 != "-" else "-"
        rows.append([str(idx), manifest.package_name or report.file_name, version, display_sha, report.generated_at])
    table_utils.render_table(["#", "Package", "Version", "SHA256", "Generated"], rows)
    print()
    menu_utils.print_hint("Enter the report number to view details.")
    choice = prompt_utils.get_choice(
        [str(idx) for idx in range(1, len(stored) + 1)] + ["0"],
        prompt="Select report #: ",
        default="0",
    )
    if choice == "0":
        return

    selected = stored[int(choice) - 1]
    _display_report(selected.report, saved_path=selected.path)


def _prompt_apk_path() -> Optional[Path]:
    while True:
        response = prompt_utils.prompt_text(
            "APK file path",
            hint="Provide an absolute or relative path to the APK you want to analyse.",
        )
        candidate = Path(response).expanduser()
        if not candidate.exists():
            print(status_messages.status("File not found.", level="error"))
            if not prompt_utils.prompt_yes_no("Try another path?", default=True):
                return None
            continue
        if candidate.is_dir():
            print(status_messages.status("Path points to a directory.", level="error"))
            if not prompt_utils.prompt_yes_no("Try another path?", default=True):
                return None
            continue
        if candidate.suffix.lower() != ".apk":
            if not prompt_utils.prompt_yes_no(
                "File does not end with .apk. Analyse anyway?", default=False
            ):
                if not prompt_utils.prompt_yes_no("Try another path?", default=True):
                    return None
                continue
        return candidate


def _display_report(report: StaticAnalysisReport, *, saved_path: Optional[Path]) -> None:
    print()
    subtitle = report.manifest.package_name or report.file_name
    menu_utils.print_header("Static Analysis Report", subtitle)

    metrics = [
        ("Declared permissions", len(report.permissions.declared)),
        ("Dangerous permissions", len(report.permissions.dangerous)),
        ("Custom permissions", len(report.permissions.custom)),
        ("Exported components", report.exported_components.total()),
        ("Declared features", len(report.features)),
    ]
    menu_utils.print_metrics(metrics)

    print()
    print(text_blocks.headline("File overview", width=70))
    overview_pairs = [
        ("File name", report.file_name),
        ("File size", _format_bytes(report.file_size)),
        ("SHA256", report.hashes.get("sha256") or "-"),
        ("SHA1", report.hashes.get("sha1") or "-"),
        ("MD5", report.hashes.get("md5") or "-"),
        ("Location", report.relative_path or report.file_path),
    ]
    table_utils.render_key_value_pairs(overview_pairs)

    manifest = report.manifest
    print()
    print(text_blocks.headline("Manifest summary", width=70))
    manifest_pairs = [
        ("Package", manifest.package_name or "Unknown"),
        ("Version", manifest.version_name or manifest.version_code or "Unknown"),
        ("Min SDK", manifest.min_sdk or "Unknown"),
        ("Target SDK", manifest.target_sdk or "Unknown"),
        ("Compile SDK", manifest.compile_sdk or "Unknown"),
        ("Main activity", manifest.main_activity or "None"),
        ("App label", manifest.app_label or "Unknown"),
    ]
    table_utils.render_key_value_pairs(manifest_pairs)

    flag_pairs = [
        ("Uses cleartext traffic", _format_flag(report.manifest_flags.uses_cleartext_traffic)),
        ("Debuggable", _format_flag(report.manifest_flags.debuggable)),
        ("Allow backup", _format_flag(report.manifest_flags.allow_backup)),
    ]
    print()
    table_utils.render_key_value_pairs(flag_pairs)

    print()
    print(text_blocks.headline("Components", width=70))
    component_rows = [
        [
            "Activities",
            len(report.components.activities),
            len(report.exported_components.activities),
        ],
        [
            "Services",
            len(report.components.services),
            len(report.exported_components.services),
        ],
        [
            "Broadcast receivers",
            len(report.components.receivers),
            len(report.exported_components.receivers),
        ],
        [
            "Content providers",
            len(report.components.providers),
            len(report.exported_components.providers),
        ],
    ]
    table_utils.render_table(["Component", "Declared", "Exported"], component_rows)

    _print_compact_list("Dangerous permissions", report.permissions.dangerous)
    _print_compact_list("Custom permissions", report.permissions.custom)
    _print_compact_list("Declared features", report.features)
    _print_compact_list("Linked libraries", report.libraries)
    _print_compact_list("Signatures", report.signatures, empty_message="Signature data unavailable.")

    metadata_pairs = _metadata_pairs(report)
    if metadata_pairs:
        print()
        print(text_blocks.headline("Harvest metadata", width=70))
        table_utils.render_key_value_pairs(metadata_pairs)

    if saved_path:
        try:
            display_path = saved_path.resolve().relative_to(Path.cwd())
        except ValueError:
            display_path = saved_path.resolve()
        print()
        print(status_messages.status(f"Report saved to {display_path}", level="success"))

    prompt_utils.press_enter_to_continue("Press Enter to return to the Static Analysis menu...")


def _print_compact_list(
    title: str,
    items: Mapping[str, object] | List[str] | tuple[str, ...],
    *,
    limit: int = 10,
    empty_message: str = "None detected.",
) -> None:
    values = list(items) if not isinstance(items, Mapping) else list(items.keys())
    print()
    print(text_blocks.headline(title, width=70))
    if not values:
        print(f"  • {empty_message}")
        return
    for entry in values[:limit]:
        print(f"  • {entry}")
    if len(values) > limit:
        remaining = len(values) - limit
        print(f"  • … {remaining} more not shown")


def _metadata_pairs(report: StaticAnalysisReport) -> List[tuple[str, object]]:
    metadata = report.metadata or {}
    if not metadata:
        return []
    fields = [
        ("package_name", "Harvest package"),
        ("app_label", "Harvest label"),
        ("device_serial", "Device serial"),
        ("session_stamp", "Harvest session"),
        ("captured_at", "Captured at"),
        ("local_path", "Repository path"),
        ("source_path", "Device path"),
        ("apk_id", "APK ID"),
        ("category", "Category"),
        ("artifact", "Artifact"),
    ]
    pairs: List[tuple[str, object]] = []
    for key, label in fields:
        if key in metadata and metadata[key] not in (None, ""):
            pairs.append((label, metadata[key]))
    return pairs


def _format_flag(value: Optional[bool]) -> str:
    if value is None:
        return "Unknown"
    return "Enabled" if value else "Disabled"


def _discover_repository_apks() -> List[RepositoryApk]:
    base_dir = (Path(app_config.DATA_DIR) / "apks").resolve()
    if not base_dir.exists():
        return []

    entries: List[RepositoryApk] = []
    for apk_path in sorted(base_dir.rglob("*.apk")):
        metadata = _load_metadata(apk_path)
        try:
            display = apk_path.resolve().relative_to(base_dir).as_posix()
        except ValueError:
            display = apk_path.name
        entries.append(RepositoryApk(path=apk_path, display_path=display, metadata=metadata))
    return entries


def _load_metadata(apk_path: Path) -> Mapping[str, object]:
    meta_path = apk_path.with_suffix(apk_path.suffix + ".meta.json")
    if not meta_path.exists():
        return {}
    try:
        with meta_path.open("r", encoding="utf-8") as handle:
            return json.load(handle)
    except (OSError, json.JSONDecodeError) as exc:
        log.warning(
            f"Failed to parse metadata for {apk_path.name}: {exc}",
            category="static_analysis",
        )
        return {}


def _format_bytes(size: int) -> str:
    units = ["B", "KiB", "MiB", "GiB", "TiB"]
    value = float(size)
    for unit in units:
        if value < 1024.0 or unit == units[-1]:
            if unit == "B":
                return f"{int(value)} {unit}"
            return f"{value:.1f} {unit}"
        value /= 1024.0
    return f"{size} B"


__all__ = ["static_analysis_menu"]
