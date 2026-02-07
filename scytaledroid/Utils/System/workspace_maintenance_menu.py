"""Workspace maintenance & cleanup menu."""

from __future__ import annotations

from pathlib import Path

from scytaledroid.Config import app_config
from scytaledroid.Utils.DisplayUtils import (
    display_settings,
    menu_utils,
    prompt_utils,
    status_messages,
    table_utils,
    text_blocks,
)


def _dir_size_bytes(path: Path) -> int:
    total = 0
    if not path.exists():
        return 0
    for entry in path.rglob("*"):
        if entry.is_file():
            try:
                total += entry.stat().st_size
            except OSError:
                continue
    return total


def _humanize_bytes(value: int) -> str:
    units = ["B", "KB", "MB", "GB", "TB"]
    size = float(value)
    for unit in units:
        if size < 1024.0:
            return f"{size:.1f} {unit}"
        size /= 1024.0
    return f"{size:.1f} PB"

def _count_files(path: Path, *, pattern: str = "**/*") -> int:
    if not path.exists():
        return 0
    n = 0
    for entry in path.glob(pattern):
        if entry.is_file():
            n += 1
    return n


def _count_dirs(path: Path) -> int:
    if not path.exists():
        return 0
    try:
        return sum(1 for p in path.iterdir() if p.is_dir())
    except OSError:
        return 0


def _show_summary() -> None:
    data_dir = Path("data")
    apks_dir = data_dir / "device_apks"
    logs_dir = Path("logs")
    output_dir = Path(app_config.OUTPUT_DIR)
    cache_dirs = [data_dir / "static_analysis" / "cache", output_dir / "cache"]
    apk_files = list(apks_dir.rglob("*.apk")) if apks_dir.exists() else []

    apks_size = _dir_size_bytes(apks_dir)
    logs_size = _dir_size_bytes(logs_dir)
    cache_size = sum(_dir_size_bytes(p) for p in cache_dirs)

    print()
    print(text_blocks.headline("Workspace usage summary", width=display_settings.default_width(80)))

    rows: list[list[str]] = []
    rows.append(["APK storage", str(apks_dir)])
    rows.append(["APK files", f"{len(apk_files)}"])
    rows.append(["APK size", _humanize_bytes(apks_size)])
    rows.append(["Logs dir", str(logs_dir)])
    rows.append(["Logs size", _humanize_bytes(logs_size)])

    # Evidence packs and batch artifacts are the main growth areas during Paper #2.
    rows.append(["Output dir", str(output_dir)])
    rows.append(["Output size", _humanize_bytes(_dir_size_bytes(output_dir))])
    dyn_evidence = output_dir / "evidence" / "dynamic"
    static_runs = output_dir / "evidence" / "static_runs"
    batches_dir = output_dir / "batches"
    rows.append(["Dynamic evidence packs", f"{_count_dirs(dyn_evidence)} run(s)"])
    rows.append(["Dynamic evidence size", _humanize_bytes(_dir_size_bytes(dyn_evidence))])
    rows.append(["Static runs (evidence)", f"{_count_dirs(static_runs)} run(s)"])
    rows.append(["Static evidence size", _humanize_bytes(_dir_size_bytes(static_runs))])
    rows.append(["Batch JSON outputs", f"{_count_files(batches_dir, pattern='**/*.json')}"])
    rows.append(["Batch output size", _humanize_bytes(_dir_size_bytes(batches_dir))])

    # Inventory snapshots should be bounded by retention (Phase A).
    state_dir = Path(app_config.DATA_DIR) / "state"
    inv_dir: Path | None = None
    try:
        serial_dirs = sorted([p for p in state_dir.iterdir() if p.is_dir()])
        if serial_dirs:
            inv_dir = serial_dirs[0] / "inventory"
    except OSError:
        inv_dir = None
    if inv_dir and inv_dir.exists():
        inv_files = len(list(inv_dir.glob("inventory_*.json")))
        rows.append(["Inventory snapshots (fs)", f"{inv_files} (policy N=5)"])
        rows.append(["Inventory dir", str(inv_dir)])

    for p in cache_dirs:
        rows.append([f"Cache {p}", _humanize_bytes(_dir_size_bytes(p))])
    rows.append(["Caches total", _humanize_bytes(cache_size)])

    table_kwargs = display_settings.apply_table_defaults({"compact": True, "accent_first_column": True})
    table_utils.render_table(["Item", "Value"], rows, **table_kwargs)

    print()
    print(text_blocks.headline("Cleanup hints", width=display_settings.default_width(80)))
    hints: list[str] = []
    dyn_size = _dir_size_bytes(dyn_evidence)
    if dyn_size > 5 * 1024 * 1024 * 1024:
        hints.append("Dynamic evidence is large: consider deleting INVALID runs (Workspace -> Dynamic evidence packs).")
    if cache_size > 1024 * 1024 * 1024:
        hints.append("Caches exceed 1GB: clear output cache if disk space is tight.")
    if inv_dir and inv_dir.exists():
        inv_files = len(list(inv_dir.glob("inventory_*.json")))
        if inv_files > 5:
            hints.append("Inventory snapshots exceed expected retention: verify retention is running on sync.")
    if not hints:
        hints.append("No cleanup actions suggested.")
    for line in hints:
        print(status_messages.status(line, level="info"))
    prompt_utils.press_enter_to_continue()


def workspace_menu() -> None:
    """Render the workspace maintenance menu."""

    while True:
        print()
        menu_utils.print_header("Workspace maintenance & cleanup")
        items = [
            menu_utils.MenuOption("1", "Show workspace usage"),
            menu_utils.MenuOption("2", "Dynamic evidence packs"),
        ]
        spec_kwargs = display_settings.apply_menu_defaults(
            {"items": items, "exit_label": "Back", "show_exit": True}
        )
        menu_utils.render_menu(menu_utils.MenuSpec(**spec_kwargs))
        choice = prompt_utils.get_choice([opt.key for opt in items] + ["0"], default="1")

        if choice == "0":
            break
        if choice == "1":
            _show_summary()
        elif choice == "2":
            from scytaledroid.DynamicAnalysis.tools.evidence_packs_menu import evidence_packs_menu

            evidence_packs_menu()
        else:
            print(status_messages.status("Option not available yet.", level="warn"))
            prompt_utils.press_enter_to_continue()


__all__ = ["workspace_menu"]
