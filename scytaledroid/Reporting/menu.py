"""Interactive workflows for generating and reviewing reports."""

from __future__ import annotations

from datetime import datetime
from pathlib import Path
from typing import Iterable, List, Optional

from scytaledroid.Config import app_config
from scytaledroid.DeviceAnalysis import adb_utils, device_manager
from scytaledroid.DeviceAnalysis.report import generate_device_report
from scytaledroid.Reporting.generator import export_static_analysis_markdown
from scytaledroid.StaticAnalysis.persistence import list_reports
from scytaledroid.Utils.DisplayUtils import menu_utils, prompt_utils, status_messages, table_utils
from scytaledroid.Utils.LoggingUtils import logging_utils as log


def reporting_menu() -> None:
    while True:
        print()
        menu_utils.print_header("Reporting")
        options = [
            menu_utils.MenuOption(
                "1",
                "Generate device summary report",
                description="Use the active device or select another connected target",
            ),
            menu_utils.MenuOption(
                "2",
                "Generate static analysis report",
                description="Convert a stored static analysis JSON artefact to markdown",
            ),
            menu_utils.MenuOption(
                "3",
                "View saved reports",
                description="Browse previously generated markdown reports",
            ),
        ]
        menu_utils.print_menu(options, is_main=False, default="1")
        choice = prompt_utils.get_choice([option.key for option in options] + ["0"], default="0")

        if choice == "0":
            break
        if choice == "1":
            _handle_device_report()
        elif choice == "2":
            _handle_static_report()
        elif choice == "3":
            _view_saved_reports()
        else:  # pragma: no cover - defensive path
            print(status_messages.status("Option not implemented yet.", level="warn"))
            prompt_utils.press_enter_to_continue()


def _handle_device_report() -> None:
    active_serial = device_manager.get_active_serial()
    if active_serial:
        label = device_manager.describe_active_device()
        if prompt_utils.prompt_yes_no(
            f"Generate report for active device {label}?", default=True
        ):
            generate_device_report(active_serial)
            return

    serial = _select_device_serial()
    if serial:
        log.info(f"Generating device report for {serial}", category="reporting")
        generate_device_report(serial)


def _select_device_serial() -> Optional[str]:
    devices, warnings = adb_utils.scan_devices()
    for message in warnings:
        print(status_messages.status(message, level="warn"))

    if not devices:
        print(status_messages.status("No Android devices detected.", level="warn"))
        prompt_utils.press_enter_to_continue()
        return None

    print()
    menu_utils.print_header("Device selection", "Choose a connected device")
    rows: List[List[str]] = []
    for index, device in enumerate(devices, start=1):
        serial = device.get("serial") or "?"
        model = device.get("model") or device.get("device") or "Unknown"
        state = device.get("state") or "unknown"
        rows.append([str(index), serial, model, state.upper()])
    table_utils.render_table(["#", "Serial", "Model", "State"], rows)

    print()
    choice = prompt_utils.get_choice(
        [str(index) for index in range(1, len(devices) + 1)] + ["0"],
        prompt="Select device #: ",
        default="0",
    )
    if choice == "0":
        return None

    return devices[int(choice) - 1].get("serial")


def _handle_static_report() -> None:
    stored = list_reports()
    if not stored:
        print(status_messages.status("No static analysis reports found.", level="warn"))
        prompt_utils.press_enter_to_continue()
        return

    print()
    menu_utils.print_header("Static analysis reports", "Select a report to export")

    rows: List[List[str]] = []
    for index, entry in enumerate(stored, start=1):
        manifest = entry.report.manifest
        package = manifest.package_name or entry.report.metadata.get("package_name") or "Unknown"
        version = (
            manifest.version_name
            or entry.report.metadata.get("version_name")
            or manifest.version_code
            or entry.report.metadata.get("version_code")
            or "Unknown"
        )
        generated = _format_timestamp(entry.report.generated_at)
        severity = _summarise_severity(entry.report.findings)
        rows.append([str(index), package, version, generated, severity])

    table_utils.render_table(["#", "Package", "Version", "Captured", "Findings"], rows)

    print()
    choice = prompt_utils.get_choice(
        [str(index) for index in range(1, len(stored) + 1)] + ["0"],
        prompt="Select report #: ",
        default="0",
    )
    if choice == "0":
        return

    selected = stored[int(choice) - 1]
    try:
        output_path = export_static_analysis_markdown(
            selected.report, source_path=selected.path
        )
    except OSError as exc:  # pragma: no cover - filesystem errors
        print(status_messages.status(f"Failed to write report: {exc}", level="fail"))
        prompt_utils.press_enter_to_continue()
        return

    resolved = _relative_path(output_path)
    print(status_messages.status(f"Markdown report saved to {resolved}", level="success"))
    log.info(f"Static analysis markdown exported to {output_path}", category="reporting")
    prompt_utils.press_enter_to_continue()


def _summarise_severity(findings: Iterable[object]) -> str:
    from scytaledroid.StaticAnalysis.core import Finding, SeverityLevel

    counts = {level: 0 for level in (SeverityLevel.P0, SeverityLevel.P1, SeverityLevel.P2)}
    total_notes = 0
    for entry in findings:
        if isinstance(entry, Finding):
            if entry.severity_gate in counts:
                counts[entry.severity_gate] += 1
            else:
                total_notes += 1

    parts = [f"{level.value}:{count}" for level, count in counts.items() if count]
    if total_notes:
        parts.append(f"NOTE:{total_notes}")
    return ", ".join(parts) if parts else "None"


def _view_saved_reports() -> None:
    base_dir = Path(app_config.OUTPUT_DIR) / "reports"
    if not base_dir.exists():
        print(status_messages.status("No reports have been generated yet.", level="warn"))
        prompt_utils.press_enter_to_continue()
        return

    files = sorted(base_dir.rglob("*.md"), key=lambda path: path.stat().st_mtime, reverse=True)
    if not files:
        print(status_messages.status("No markdown reports found in the output directory.", level="warn"))
        prompt_utils.press_enter_to_continue()
        return

    visible = files[:20]
    print()
    menu_utils.print_header("Saved reports", f"Showing {len(visible)} of {len(files)}")

    rows: List[List[str]] = []
    for index, path in enumerate(visible, start=1):
        report_type = _classify_report(path, base_dir)
        modified = datetime.fromtimestamp(path.stat().st_mtime).strftime("%Y-%m-%d %H:%M")
        rows.append([str(index), report_type, path.name, modified])

    table_utils.render_table(["#", "Type", "File", "Modified"], rows)
    if len(files) > len(visible):
        remaining = len(files) - len(visible)
        print(status_messages.status(f"+ {remaining} more report(s) available.", level="info"))

    print()
    choice = prompt_utils.get_choice(
        [str(index) for index in range(1, len(visible) + 1)] + ["0"],
        prompt="Preview report #: ",
        default="0",
    )
    if choice == "0":
        return

    selected = visible[int(choice) - 1]
    _preview_report_file(selected)


def _preview_report_file(path: Path) -> None:
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except OSError as exc:  # pragma: no cover - filesystem errors
        print(status_messages.status(f"Unable to read {path.name}: {exc}", level="fail"))
        prompt_utils.press_enter_to_continue()
        return

    print()
    menu_utils.print_header("Report preview", path.name)
    preview_limit = 40
    for line in lines[:preview_limit]:
        print(line)
    if len(lines) > preview_limit:
        print(f"... (+{len(lines) - preview_limit} more lines)")

    print()
    resolved = _relative_path(path)
    print(status_messages.status(f"Full report available at {resolved}", level="info"))
    prompt_utils.press_enter_to_continue()


def _classify_report(path: Path, base_dir: Path) -> str:
    try:
        relative = path.relative_to(base_dir)
    except ValueError:  # pragma: no cover - defensive
        return "Report"

    parts = list(relative.parts)
    if parts and parts[0] == "static_analysis":
        return "Static analysis"
    if path.name.startswith("device_report_"):
        return "Device"
    return "Report"


def _relative_path(path: Path) -> Path:
    resolved = path.resolve()
    try:
        return resolved.relative_to(Path.cwd())
    except ValueError:
        return resolved


def _format_timestamp(value: str) -> str:
    try:
        normalised = value.replace("Z", "+00:00")
        parsed = datetime.fromisoformat(normalised)
    except Exception:  # pragma: no cover - fallback path
        return value
    return parsed.strftime("%Y-%m-%d %H:%M UTC")
