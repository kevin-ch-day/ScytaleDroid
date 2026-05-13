"""Database Tools → Catalog hygiene (read-only report + explicit override flows)."""

from __future__ import annotations

from scytaledroid.Utils.DisplayUtils import menu_utils, prompt_utils, status_messages

from .repo_db_script_runner import run_scripts_db_py


def catalog_hygiene_menu() -> None:
    """Operator entry for app display-name hygiene (report + CSV apply helpers)."""

    while True:
        print()
        menu_utils.print_header("Catalog hygiene")
        menu_utils.print_hint(
            "Curated catalog fixes for apps.display_name. "
            "Does not copy device_inventory.app_label automatically."
        )
        menu_utils.print_section("Read-only")
        print("  1) App display-name hygiene report (inventory + optional focus bucket)")
        menu_utils.print_section("Overrides (CSV-backed)")
        print("  2) Preview apply (default dry-run)")
        print("  3) Apply after review (writes DB)")
        print()
        choice = prompt_utils.get_choice(["0", "1", "2", "3"], default="0")
        if choice == "0":
            return
        if choice == "1":
            want = prompt_utils.prompt_yes_no(
                "Include Play Store / Unclassified / Data focus detail?", default=False
            )
            extra = ["--focus-play-store-unclassified"] if want else []
            run_scripts_db_py("report_app_label_hygiene.py", extra)
        elif choice == "2":
            run_scripts_db_py("apply_app_display_name_overrides.py")
        elif choice == "3":
            if not prompt_utils.prompt_yes_no(
                "Apply curated CSV display names to apps (writes DB; skips existing labels)?",
                default=False,
            ):
                print(status_messages.status("Aborted.", level="info"))
                continue
            if not prompt_utils.prompt_yes_no(
                "Final confirmation: proceed with DB writes now?", default=False
            ):
                print(status_messages.status("Aborted.", level="info"))
                continue
            run_scripts_db_py("apply_app_display_name_overrides.py", ["--apply"])
