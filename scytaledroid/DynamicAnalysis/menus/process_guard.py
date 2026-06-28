"""Process-staleness helpers for the Dynamic Analysis menu."""

from __future__ import annotations

import hashlib
from pathlib import Path

from scytaledroid.Utils.DisplayUtils import status_messages


def _sha256_file(path: Path) -> str:
    try:
        data = path.read_bytes()
    except Exception:
        return ""
    return hashlib.sha256(data).hexdigest()


def dynamic_menu_code_paths(menu_file: Path) -> dict[str, Path]:
    dynamic_root = menu_file.resolve().parents[1]
    return {
        "dynamic_menu.py": menu_file.resolve(),
        "guided_run.py": (dynamic_root / "controllers" / "guided_run.py").resolve(),
        "manual.py": (dynamic_root / "scenarios" / "manual.py").resolve(),
        "manual_templates.py": (dynamic_root / "scenarios" / "manual_templates.py").resolve(),
        "paper_eligibility.py": (dynamic_root / "paper_eligibility.py").resolve(),
    }


def build_dynamic_menu_code_signature(menu_file: Path) -> dict[str, str]:
    return {
        name: _sha256_file(path)
        for name, path in dynamic_menu_code_paths(menu_file).items()
    }


def warn_if_dynamic_menu_code_changed(*, menu_file: Path, start_signature: dict[str, str]) -> None:
    current = build_dynamic_menu_code_signature(menu_file)
    changed = [
        name
        for name, sig in current.items()
        if sig and sig != start_signature.get(name, sig)
    ]
    if not changed:
        return
    changed_list = ", ".join(changed[:5]) + (" ..." if len(changed) > 5 else "")
    status_messages.print_status(
        f"Code changed on disk since this Dynamic Analysis menu started ({changed_list}).",
        level="warn",
    )
    status_messages.print_status(
        "Exit ScytaleDroid completely (Main Menu -> 0) and restart to apply the new templates/logic.",
        level="warn",
    )
