"""Database Tools → Database health & integrity (read-only core catalog probes)."""

from __future__ import annotations

from scytaledroid.Utils.DisplayUtils import menu_utils, prompt_utils

from . import health_checks


def database_health_and_integrity_menu() -> None:
    """Roll-up for DB-wide summary, latest-session depth checks, and evidence linkage."""

    while True:
        print()
        menu_utils.print_header("Database health & integrity")
        menu_utils.print_hint(
            "Read-only. Core catalog (static runs, summaries, orphans, audit snapshots)."
        )
        menu_utils.print_section("Actions")
        print("  1) DB health summary (run status, orphans, handoff invariants, Permission Intel snapshot)")
        print("  2) Latest session depth checks (ingestion, linkage, scoring, contract integrity)")
        print("  3) Evidence snapshot linkage (permission_audit_snapshots paths / hashes)")
        print("  0) Back")
        choice = prompt_utils.get_choice(["0", "1", "2", "3"], default="0")
        if choice == "0":
            return
        if choice == "1":
            health_checks.run_health_summary()
        elif choice == "2":
            health_checks.run_health_checks()
        elif choice == "3":
            health_checks.run_evidence_integrity_check()


__all__ = ["database_health_and_integrity_menu"]
