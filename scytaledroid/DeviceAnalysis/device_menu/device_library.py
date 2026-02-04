"""Helpers for browsing saved APK harvests for previously connected devices."""

from __future__ import annotations

import re
from collections import Counter, defaultdict
from collections.abc import Iterable
from dataclasses import dataclass
from pathlib import Path

from scytaledroid.Config import app_config
from scytaledroid.Utils.DisplayUtils import (
    error_panels,
    menu_utils,
    prompt_utils,
    status_messages,
    table_utils,
    text_blocks,
)


@dataclass
class _SessionSummary:
    stamp: str
    packages: set[str]
    artifacts: int
    package_counts: Counter[str]


@dataclass
class _DeviceLibrarySummary:
    serial: str
    sessions: list[_SessionSummary]
    total_packages: int
    total_artifacts: int
    base_path: Path
    package_counts: Counter[str]
    layout: str

    @property
    def session_count(self) -> int:
        return len(self.sessions)

    @property
    def latest_stamp(self) -> str | None:
        if not self.sessions:
            return None
        return max(session.stamp for session in self.sessions)


def browse_saved_apk_library() -> None:
    """Display harvested APKs saved on disk and allow drill-down per device."""

    base_dir = Path(app_config.DATA_DIR).resolve() / "device_apks"
    if not base_dir.exists():
        print()
        error_panels.print_info_panel(
            "Saved APKs",
            "No harvested artifacts directory found.",
            hint=f"Expected path: {base_dir}",
        )
        prompt_utils.press_enter_to_continue()
        return

    summaries = _scan_saved_apks(base_dir)
    if not summaries:
        print()
        error_panels.print_info_panel(
            "Saved APKs",
            "No APK files were found in the harvest directory.",
            hint="Run a pull to populate the library.",
        )
        prompt_utils.press_enter_to_continue()
        return

    if len(summaries) == 1:
        _show_device_library_detail(summaries[0])
        return

    while True:
        print()
        menu_utils.print_header("Saved APK Library")

        headers = ["#", "Device", "Sessions", "Packages", "Artifacts", "Last run"]
        rows: list[list[str]] = []
        for index, summary in enumerate(summaries, start=1):
            rows.append(
                [
                    str(index),
                    summary.serial,
                    str(summary.session_count),
                    str(summary.total_packages),
                    str(summary.total_artifacts),
                    summary.latest_stamp or "—",
                ]
            )
        table_utils.render_table(headers, rows)

        raw = prompt_utils.prompt_text(
            "Select a device number to inspect, or press Enter to return",
            required=False,
        ).strip()
        if not raw:
            break
        if not raw.isdigit():
            print(status_messages.status("Please choose a valid device index.", level="warn"))
            continue
        index = int(raw) - 1
        if not (0 <= index < len(summaries)):
            print(status_messages.status("Selection out of range.", level="warn"))
            continue

        _show_device_library_detail(summaries[index])

        print()
        if not prompt_utils.prompt_yes_no(
            "Inspect another saved device?", default=False
        ):
            break


def _scan_saved_apks(base_dir: Path) -> list[_DeviceLibrarySummary]:
    summaries: list[_DeviceLibrarySummary] = []
    date_dir_pattern = re.compile(r"^\d{8}$")
    for serial_dir in sorted(p for p in base_dir.iterdir() if p.is_dir()):
        child_dirs = [p for p in serial_dir.iterdir() if p.is_dir()]
        has_date_dirs = any(date_dir_pattern.match(p.name) for p in child_dirs)
        layout = "date_first" if has_date_dirs else "package_first"
        session_packages: dict[str, dict[str, object]] = defaultdict(
            lambda: {"packages": set(), "artifacts": 0, "package_counts": Counter()}
        )
        package_counts: Counter[str] = Counter()
        packages_seen: set[str] = set()
        total_artifacts = 0

        if layout == "date_first":
            for day_dir in child_dirs:
                if not day_dir.is_dir():
                    continue
                if not date_dir_pattern.match(day_dir.name):
                    continue
                for package_dir in day_dir.iterdir():
                    if not package_dir.is_dir():
                        continue
                    package_name = package_dir.name
                    apk_files = [path for path in package_dir.iterdir() if path.suffix.lower() == ".apk"]
                    if not apk_files:
                        continue

                    stats = session_packages[day_dir.name]
                    packages_set = stats["packages"]
                    if isinstance(packages_set, set):
                        packages_set.add(package_name)
                    stats["artifacts"] = int(stats["artifacts"]) + len(apk_files)
                    pkg_counter = stats["package_counts"]
                    if isinstance(pkg_counter, Counter):
                        pkg_counter[package_name] += len(apk_files)

                    package_counts[package_name] += len(apk_files)
                    packages_seen.add(package_name)
                    total_artifacts += len(apk_files)
        else:
            for package_dir in child_dirs:
                if not package_dir.is_dir():
                    continue
                package_name = package_dir.name
                for session_dir in package_dir.iterdir():
                    if not session_dir.is_dir():
                        continue
                    apk_files = [path for path in session_dir.iterdir() if path.suffix.lower() == ".apk"]
                    if not apk_files:
                        continue

                    stats = session_packages[session_dir.name]
                    packages_set = stats["packages"]
                    if isinstance(packages_set, set):
                        packages_set.add(package_name)
                    stats["artifacts"] = int(stats["artifacts"]) + len(apk_files)
                    pkg_counter = stats["package_counts"]
                    if isinstance(pkg_counter, Counter):
                        pkg_counter[package_name] += len(apk_files)

                    package_counts[package_name] += len(apk_files)
                    packages_seen.add(package_name)
                    total_artifacts += len(apk_files)

        if not session_packages:
            continue

        sessions: list[_SessionSummary] = []
        for stamp, stats in session_packages.items():
            packages_set = set(stats["packages"]) if isinstance(stats["packages"], set) else set()
            package_counter = (
                Counter(stats["package_counts"]) if isinstance(stats.get("package_counts"), Counter) else Counter()
            )
            sessions.append(
                _SessionSummary(
                    stamp=stamp,
                    packages=packages_set,
                    artifacts=int(stats["artifacts"]),
                    package_counts=package_counter,
                )
            )
        sessions.sort(key=lambda item: item.stamp, reverse=True)

        summaries.append(
            _DeviceLibrarySummary(
                serial=serial_dir.name,
                sessions=sessions,
                total_packages=len(packages_seen),
                total_artifacts=total_artifacts,
                base_path=serial_dir,
                package_counts=package_counts,
                layout=layout,
            )
        )

    return summaries


def _show_device_library_detail(summary: _DeviceLibrarySummary) -> None:
    print()
    menu_utils.print_header(
        f"Device {summary.serial}",
        subtitle=f"Stored sessions: {summary.session_count} · Packages: {summary.total_packages}",
    )

    headers = ["#", "Session", "Packages", "Artifacts"]
    rows: list[list[str]] = [
        [
            str(idx + 1),
            session.stamp,
            str(len(session.packages)),
            str(session.artifacts),
        ]
        for idx, session in enumerate(summary.sessions[:20])
    ]

    if rows:
        table_utils.render_table(headers, rows)
        _print_overflow_notice("session(s)", summary.sessions, rows)
    else:
        print(status_messages.status("No session directories with APK files found.", level="warn"))

    if summary.package_counts:
        print()
        print(text_blocks.headline("Top packages", width=70))
        top_packages = summary.package_counts.most_common(15)
        table_utils.render_table(
            ["Package", "Artifacts"],
            [[pkg, str(count)] for pkg, count in top_packages],
        )

    print()
    print()
    print(status_messages.status(f"Base directory: {summary.base_path}", level="info"))
    if summary.layout == "date_first":
        example_hint = summary.base_path / "<YYYYMMDD>" / "<package>"
    else:
        example_hint = summary.base_path / "<package>" / "<timestamp>"
    print(status_messages.status(f"APK location pattern: {example_hint}", level="info"))

    session_map = {str(idx + 1): session for idx, session in enumerate(summary.sessions)}
    if session_map:
        print()
        print(
            status_messages.status(
                "Enter a session number for package details, or press Enter to return.",
                level="info",
            )
        )
    while True:
        choice = prompt_utils.prompt_text(
            "Select session number for package details (Enter to return)",
            required=False,
        ).strip()
        if not choice:
            break
        session = session_map.get(choice)
        if not session:
            print(status_messages.status("Invalid session selection.", level="warn"))
            continue
        _show_session_packages(summary, session)


def _show_session_packages(summary: _DeviceLibrarySummary, session: _SessionSummary) -> None:
    print()
    menu_utils.print_header(
        f"Session {session.stamp}",
        subtitle=f"{len(session.packages)} package(s) · {session.artifacts} artifact(s)",
    )

    rows: list[list[str]] = []
    for package, count in session.package_counts.most_common():
        if summary.layout == "date_first":
            path = summary.base_path / session.stamp / package
        else:
            path = summary.base_path / package / session.stamp
        rows.append(
            [
                package,
                str(count),
                str(path),
            ]
        )

    if rows:
        table_utils.render_table(["Package", "Artifacts", "Path"], rows[:50])
        _print_overflow_notice("additional package(s)", rows, rows[:50])
    else:
        print(status_messages.status("No APK files recorded for this session.", level="warn"))

    prompt_utils.press_enter_to_continue()


def _print_overflow_notice(label: str, source: Iterable[object], shown: Iterable[object]) -> None:
    total = sum(1 for _ in source)
    displayed = sum(1 for _ in shown)
    remaining = total - displayed
    if remaining > 0:
        print(
            status_messages.status(
                f"… {remaining} {label} not shown.",
                level="info",
            )
        )


__all__ = ["browse_saved_apk_library"]
