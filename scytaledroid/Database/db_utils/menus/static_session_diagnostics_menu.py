"""Database Tools → Static session diagnostics (read-only DB scripts)."""

from __future__ import annotations

from scytaledroid.Utils.DisplayUtils import menu_utils, prompt_utils, status_messages

from .repo_db_script_runner import run_scripts_db_py


def run_static_session_canonical_audit(
    session_stamp: str,
    *,
    no_sql: bool = False,
    strict_masvs_views: bool = False,
) -> int:
    """In-process ``audit_static_session`` (canonical counts + views + legacy mirror)."""

    stamp = str(session_stamp or "").strip()
    if not stamp:
        print(status_messages.status("session_stamp is empty.", level="error"))
        return 1
    try:
        from scytaledroid.Database.db_utils.static_session_operator_audit import (
            audit_static_session_operator,
        )
    except ImportError as exc:
        print(status_messages.status(f"audit import failed: {exc}", level="error"))
        return 1
    return audit_static_session_operator(
        stamp,
        print_sql_appendix=not no_sql,
        strict_masvs_views=strict_masvs_views,
    )


def run_session_static_health(session_stamp: str) -> int:
    stamp = str(session_stamp or "").strip()
    if not stamp:
        print(status_messages.status("session_stamp is empty.", level="error"))
        return 1
    return run_scripts_db_py("session_static_health.py", ["--session", stamp])


def run_grain_integrity_report(session_stamp: str) -> int:
    stamp = str(session_stamp or "").strip()
    if not stamp:
        print(status_messages.status("session_stamp is empty.", level="error"))
        return 1
    return run_scripts_db_py(
        "report_static_session_grain_integrity.py",
        ["--session-stamp", stamp],
    )


def run_artifact_registry_integrity_report() -> int:
    return run_scripts_db_py("report_artifact_registry_integrity.py")


def run_verify_static_session_id_rollout() -> int:
    return run_scripts_db_py("verify_static_session_id_rollout.py")


def static_session_diagnostics_menu() -> None:
    """Operator entry for read-only static session / registry probes."""

    while True:
        print()
        menu_utils.print_header("Static session diagnostics")
        menu_utils.print_hint(
            "Read-only scripts under scripts/db/ (except item 5: in-process audit). Require analyst DB (SCYTALEDROID_DB_*)."
        )
        menu_utils.print_section("Session-scoped")
        print("  1) Session static health (DB + optional persistence audit JSON)")
        print("  2) Grain / integrity report (--session-stamp)")
        print()
        menu_utils.print_section("Catalog-wide")
        print("  3) Artifact registry integrity (v_artifact_registry_integrity)")
        print("  4) Static session_id rollout verification (scalar counts)")
        print("  5) Canonical session audit (DB counts + views; in-process)")
        print()
        choice = prompt_utils.get_choice(["0", "1", "2", "3", "4", "5"], default="0")
        if choice == "0":
            return
        if choice == "1":
            stamp = prompt_utils.prompt_text(
                "session_stamp (e.g. 20260510-all-full)",
                default="",
                required=True,
            ).strip()
            run_session_static_health(stamp)
        elif choice == "2":
            stamp = prompt_utils.prompt_text(
                "session_stamp for grain report",
                default="",
                required=True,
            ).strip()
            want = prompt_utils.prompt_yes_no(
                "Include --count-archive-json (extra I/O)?", default=False
            )
            labels = prompt_utils.prompt_yes_no(
                "Add --with-display-labels (CSV + apps.display_name column)?", default=False
            )
            extra = ["--session-stamp", stamp]
            if want:
                extra.append("--count-archive-json")
            if labels:
                extra.append("--with-display-labels")
            run_scripts_db_py("report_static_session_grain_integrity.py", extra)
        elif choice == "3":
            run_artifact_registry_integrity_report()
        elif choice == "4":
            run_verify_static_session_id_rollout()
        elif choice == "5":
            stamp = prompt_utils.prompt_text(
                "session_stamp for canonical audit",
                default="",
                required=True,
            ).strip()
            want_sql = prompt_utils.prompt_yes_no(
                "Include copyable SQL appendix (long)?", default=False
            )
            strict_m = prompt_utils.prompt_yes_no(
                "Strict MASVS views (exit 3 if views missing)?", default=False
            )
            code = run_static_session_canonical_audit(
                stamp,
                no_sql=not want_sql,
                strict_masvs_views=strict_m,
            )
            if code != 0:
                print(status_messages.status(f"Canonical session audit exited {code}.", level="warn"))


def post_run_db_checks_submenu(*, session_stamp: str | None, persist_enabled: bool) -> None:
    """Post-run diagnostics: read-only DB probes for the current session when available."""

    stamp = str(session_stamp or "").strip()
    while True:
        print()
        menu_utils.print_header("DB-backed session checks (read-only)")
        if not persist_enabled:
            menu_utils.print_hint("DB persistence was skipped for this run; probes may be less meaningful.")
        if stamp:
            menu_utils.print_hint(f"session_stamp: {stamp}")
        else:
            menu_utils.print_hint("No session_stamp on this run; enter stamp manually when prompted.")
        print("  1) Session static health (session_static_health.py)")
        print("  2) Grain / integrity report (report_static_session_grain_integrity.py)")
        print("  3) Artifact registry integrity (whole DB)")
        print("  4) Static session_id rollout verification (scalar counts)")
        print("  5) Canonical session audit (DB counts + views; in-process)")
        print("  0) Back")
        choice = prompt_utils.get_choice(["0", "1", "2", "3", "4", "5"], default="0")
        if choice == "0":
            return
        if choice == "1":
            use = stamp or prompt_utils.prompt_text(
                "session_stamp",
                default="",
                required=True,
            ).strip()
            run_session_static_health(use)
        elif choice == "2":
            use = stamp or prompt_utils.prompt_text(
                "session_stamp",
                default="",
                required=True,
            ).strip()
            want = prompt_utils.prompt_yes_no(
                "Include --count-archive-json (extra I/O)?", default=False
            )
            labels = prompt_utils.prompt_yes_no(
                "Add --with-display-labels (CSV + apps.display_name column)?", default=False
            )
            extra = ["--session-stamp", use]
            if want:
                extra.append("--count-archive-json")
            if labels:
                extra.append("--with-display-labels")
            run_scripts_db_py("report_static_session_grain_integrity.py", extra)
        elif choice == "3":
            run_artifact_registry_integrity_report()
        elif choice == "4":
            run_verify_static_session_id_rollout()
        elif choice == "5":
            use = stamp or prompt_utils.prompt_text(
                "session_stamp",
                default="",
                required=True,
            ).strip()
            want_sql = prompt_utils.prompt_yes_no(
                "Include copyable SQL appendix (long)?", default=False
            )
            strict_m = prompt_utils.prompt_yes_no(
                "Strict MASVS views (exit 3 if views missing)?", default=False
            )
            code = run_static_session_canonical_audit(
                use,
                no_sql=not want_sql,
                strict_masvs_views=strict_m,
            )
            if code != 0:
                print(status_messages.status(f"Canonical session audit exited {code}.", level="warn"))


__all__ = [
    "post_run_db_checks_submenu",
    "run_artifact_registry_integrity_report",
    "run_grain_integrity_report",
    "run_session_static_health",
    "run_static_session_canonical_audit",
    "run_verify_static_session_id_rollout",
    "static_session_diagnostics_menu",
]
