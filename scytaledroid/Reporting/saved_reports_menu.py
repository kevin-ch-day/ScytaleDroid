"""Saved report browser and preview helpers."""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path

from scytaledroid.Config import app_config
from scytaledroid.Utils.DisplayUtils import menu_utils, prompt_utils, status_messages, table_utils


@dataclass(frozen=True)
class SavedReportEntry:
    """A generated report bundle or standalone markdown report."""

    path: Path
    report_type: str
    modified_ts: float
    is_bundle: bool

    @property
    def display_name(self) -> str:
        if self.is_bundle:
            return self.path.name
        return self.path.name


def view_saved_reports() -> None:
    """Browse and preview generated report bundles."""

    base_dir = Path(app_config.OUTPUT_DIR) / "reports"
    if not base_dir.exists():
        print(status_messages.status("No reports have been generated yet.", level="warn"))
        prompt_utils.press_enter_to_continue()
        return

    entries = find_saved_report_entries(base_dir)
    if not entries:
        print(status_messages.status("No saved report bundles found in the output directory.", level="warn"))
        prompt_utils.press_enter_to_continue()
        return

    visible = entries[:20]
    print()
    menu_utils.print_header("Saved Report Bundles", f"Showing {len(visible)} of {len(entries)}")

    rows: list[list[str]] = []
    for index, entry in enumerate(visible, start=1):
        modified = datetime.fromtimestamp(entry.modified_ts).strftime("%Y-%m-%d %H:%M")
        kind = "bundle" if entry.is_bundle else "file"
        rows.append([str(index), entry.report_type, kind, entry.display_name, modified])

    table_utils.render_table(["#", "Type", "Kind", "Name", "Modified"], rows)
    if len(entries) > len(visible):
        remaining = len(entries) - len(visible)
        print(status_messages.status(f"+ {remaining} more report(s) available.", level="info"))

    print()
    choice = prompt_utils.menu_choice(
        [str(index) for index in range(1, len(visible) + 1)] + ["0"],
        default="0",
    )
    if choice == "0":
        return

    preview_saved_report_entry(visible[int(choice) - 1])


def find_saved_report_entries(base_dir: Path) -> list[SavedReportEntry]:
    """Return generated report bundles first, then standalone markdown reports."""

    entries: dict[Path, SavedReportEntry] = {}
    for root in discover_report_bundle_roots(base_dir):
        entries[root] = SavedReportEntry(
            path=root,
            report_type=classify_report_bundle(root, base_dir),
            modified_ts=_report_modified_ts(root),
            is_bundle=True,
        )

    for path in base_dir.rglob("*.md"):
        if any(parent in entries for parent in path.parents):
            continue
        entries[path] = SavedReportEntry(
            path=path,
            report_type=classify_report(path, base_dir),
            modified_ts=path.stat().st_mtime,
            is_bundle=False,
        )

    return sorted(entries.values(), key=lambda entry: entry.modified_ts, reverse=True)


def discover_report_bundle_roots(base_dir: Path) -> list[Path]:
    """Find report bundle roots generated under ``output/reports``."""

    roots: set[Path] = set()
    for manifest in base_dir.rglob("manifest/report_manifest.json"):
        roots.add(manifest.parent.parent)
    for summary in base_dir.rglob("report/findings_summary.txt"):
        roots.add(summary.parent.parent)
    return sorted(roots)


def summarise_severity(findings: Iterable[object]) -> str:
    """Summarise static-analysis findings by severity level."""

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


def classify_report(path: Path, base_dir: Path) -> str:
    """Classify a report based on its location and name."""

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


def classify_report_bundle(path: Path, base_dir: Path) -> str:
    """Classify a report bundle based on its output location."""

    try:
        relative = path.relative_to(base_dir)
    except ValueError:  # pragma: no cover - defensive
        return "Report bundle"

    parts = list(relative.parts)
    if parts and parts[0] == "static_exposure_privacy":
        return "Static Exposure"
    if parts and parts[0] == "static_analysis":
        return "Static analysis"
    return "Report bundle"


def preview_saved_report_entry(entry: SavedReportEntry) -> None:
    """Display a short preview for a saved report entry."""

    if entry.is_bundle:
        preview_report_bundle(entry.path)
    else:
        preview_report_file(entry.path)


def preview_report_bundle(path: Path) -> None:
    """Display a concise preview of a generated report bundle."""

    print()
    menu_utils.print_header("Report Bundle Preview", path.name)
    summary = path / "report" / "findings_summary.txt"
    if summary.exists():
        _print_file_preview(summary, preview_limit=20)
    else:
        print(status_messages.status("No findings summary found for this bundle.", level="warn"))

    rows = [
        ["tables", _count_files(path / "tables")],
        ["figures", _count_files(path / "figures")],
        ["data", _count_files(path / "data")],
        ["manifest", _count_files(path / "manifest")],
        ["report", _count_files(path / "report")],
    ]
    table_utils.render_table(["Section", "Files"], rows, compact=True)
    print()
    print(status_messages.status(f"Full report bundle available at {_relative_path(path)}", level="info"))
    prompt_utils.press_enter_to_continue()


def preview_report_file(path: Path) -> None:
    """Display a short preview of a markdown report."""

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
    print(status_messages.status(f"Full report available at {_relative_path(path)}", level="info"))
    prompt_utils.press_enter_to_continue()


def _print_file_preview(path: Path, *, preview_limit: int) -> None:
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except OSError as exc:  # pragma: no cover - filesystem errors
        print(status_messages.status(f"Unable to read {path.name}: {exc}", level="fail"))
        return
    for line in lines[:preview_limit]:
        print(line)
    if len(lines) > preview_limit:
        print(f"... (+{len(lines) - preview_limit} more lines)")
    print()


def _count_files(path: Path) -> str:
    if not path.exists():
        return "0"
    return str(sum(1 for item in path.rglob("*") if item.is_file()))


def _report_modified_ts(path: Path) -> float:
    timestamps = [path.stat().st_mtime]
    for item in path.rglob("*"):
        try:
            timestamps.append(item.stat().st_mtime)
        except OSError:  # pragma: no cover - filesystem race
            continue
    return max(timestamps)


def _relative_path(path: Path) -> Path:
    resolved = path.resolve()
    try:
        return resolved.relative_to(Path.cwd())
    except ValueError:
        return resolved


__all__ = [
    "SavedReportEntry",
    "classify_report",
    "classify_report_bundle",
    "discover_report_bundle_roots",
    "find_saved_report_entries",
    "preview_report_bundle",
    "preview_report_file",
    "preview_saved_report_entry",
    "summarise_severity",
    "view_saved_reports",
]
