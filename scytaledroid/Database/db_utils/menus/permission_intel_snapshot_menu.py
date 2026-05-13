"""Database Tools → Permission Intel & snapshot governance."""

from __future__ import annotations

from scytaledroid.Utils.DisplayUtils import menu_utils, prompt_utils

from ..menu_actions import show_governance_snapshot_status
from ..permission_intel_readiness import prompt_permission_intel_readiness


def permission_intel_and_snapshot_menu() -> None:
    """Shared Permission Intel DSN: snapshot row counts vs full readiness / connectivity."""

    while True:
        print()
        menu_utils.print_header("Permission Intel & snapshot governance")
        menu_utils.print_hint(
            "Uses SCYTALEDROID_PERMISSION_INTEL_DB_* (or full URL). Distinct from analyst core DB above."
        )
        menu_utils.print_section("Actions")
        print("  1) Governance snapshot status (header / row counts on Intel catalog)")
        print("  2) Permission Intel readiness (env, connectivity, governance checks)")
        print("  0) Back")
        choice = prompt_utils.get_choice(["0", "1", "2"], default="0")
        if choice == "0":
            return
        if choice == "1":
            show_governance_snapshot_status()
        elif choice == "2":
            prompt_permission_intel_readiness()


__all__ = ["permission_intel_and_snapshot_menu"]
