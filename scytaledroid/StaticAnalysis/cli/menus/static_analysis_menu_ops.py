"""Interactive static menu subflows: preset choice, optional batch sizing, and app search.

Kept separate from ``static_analysis_menu`` so the main loop file stays readable; behavior is unchanged.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from scytaledroid.Utils.DisplayUtils import menu_utils, prompt_utils, status_messages

from ...core.detector_runner import PIPELINE_STAGES
from ..core.analysis_profiles import run_modules_for_profile

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
    print(f"  Preset            : {preset_label}")
    if profile in {"full", "lightweight"}:
        mod_count = len(run_modules_for_profile(profile))
        print(f"  Analyzer modules  : {mod_count}")
        print(f"  Detector stages   : {len(PIPELINE_STAGES)} ordered")
    else:
        print(f"  Detector stages   : {len(PIPELINE_STAGES)} ordered max (profile narrows coverage)")
    print(
        "  Note — profile / detector applicability rules may skip some stages "
        "(this is normal for focused presets)."
    )


def choose_run_profile() -> Command | None:
    from ..commands import get_command
    from ..commands.models import Command

    print()
    menu_utils.print_section("Analysis Preset")
    print("1) Full analysis")
    print("2) Fast analysis")
    print("3) Persistence test")
    print("4) Advanced profiles")
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
    menu_utils.print_section("Advanced Profiles")
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
    "choose_run_profile",
    "distinct_package_count",
    "emit_selected_preset_summary",
    "latest_scope_for_all",
    "search_app_scope",
]
