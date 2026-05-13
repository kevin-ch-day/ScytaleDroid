"""Database Tools → Static & registry diagnostics (read-only scripts + in-process probes)."""

from __future__ import annotations

from scytaledroid.Database.db_core import run_sql
from scytaledroid.Database.db_utils.static_run_governance_checks import (
    fetch_static_run_governance_counts,
)
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


def run_artifact_registry_cleanup_candidates_report() -> int:
    """Read-only cleanup bucket report (whole DB). Use CLI for ``--run-type`` / ``--path-sample``."""

    return run_scripts_db_py("report_artifact_registry_cleanup_candidates.py")


def run_verify_static_session_id_rollout(*, extra: list[str] | None = None) -> int:
    """Subprocess ``verify_static_session_id_rollout.py`` (pass ``['--explain']`` for stderr legend)."""

    return run_scripts_db_py("verify_static_session_id_rollout.py", extra or [])


def _print_governance_posture_invariants() -> None:
    menu_utils.print_section("Static run class / handoff invariants (in-process)")
    try:
        g = fetch_static_run_governance_counts(run_sql)
    except Exception as exc:
        print(status_messages.status(f"Governance posture counts failed: {exc}", level="error"))
        return
    menu_utils.print_metrics(
        [
            ("failed_canonical_runs", str(g.failed_canonical_runs)),
            ("failed_missing_run_class", str(g.failed_missing_run_class)),
            (
                "completed_session_invariant_violations",
                str(g.completed_session_invariant_violations),
            ),
        ]
    )
    if g.non_zero_check_count() > 0:
        print(
            status_messages.status(
                "One or more checks non-zero. Repair static_analysis_runs / handoff alignment; "
                "use item 2 for CI-style exit codes, or scripts/db/check_static_run_governance_posture.py.",
                level="warn",
            )
        )


def _artifact_cleanup_candidates_extras_from_prompts() -> list[str] | None:
    rt = prompt_utils.prompt_text(
        "Cleanup candidates: optional --run-type (static / dynamic, blank=all)",
        default="",
        required=False,
    ).strip().lower()
    extra_cc: list[str] = []
    if rt in {"static", "dynamic"}:
        extra_cc.extend(["--run-type", rt])
    ps_raw = prompt_utils.prompt_text(
        "Cleanup candidates: --path-sample N (0 = skip file probes)",
        default="0",
        required=False,
    ).strip()
    if ps_raw.isdigit():
        nps = int(ps_raw)
        if nps > 0:
            extra_cc.extend(["--path-sample", str(min(nps, 5000))])
    return extra_cc if extra_cc else None


def _session_stamp_or_prompt(default_stamp: str | None, *, primary_label: str) -> str:
    s = str(default_stamp or "").strip()
    if s:
        return s
    return prompt_utils.prompt_text(primary_label, default="", required=True).strip()


def _run_grain_integrity_with_prompts(default_stamp: str | None) -> None:
    use = _session_stamp_or_prompt(default_stamp, primary_label="session_stamp for grain report")
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


def _run_canonical_audit_with_prompts(default_stamp: str | None) -> None:
    use = _session_stamp_or_prompt(
        default_stamp, primary_label="session_stamp for canonical audit"
    )
    want_sql = prompt_utils.prompt_yes_no(
        "Include copyable SQL appendix (long)?", default=False
    )
    strict_m = prompt_utils.prompt_yes_no(
        "Strict MASVS views (exit 3 if views missing)?", default=False
    )
    code = run_static_session_canonical_audit(
        use, no_sql=not want_sql, strict_masvs_views=strict_m
    )
    if code != 0:
        print(status_messages.status(f"Canonical session audit exited {code}.", level="warn"))


_STATIC_REGISTRY_KEYS = ["0", "1", "2", "3", "4", "5", "6", "7", "8"]


def _dispatch_static_registry_choice(choice: str, *, default_session_stamp: str | None) -> None:
    if choice == "1":
        _print_governance_posture_invariants()
    elif choice == "2":
        code = run_scripts_db_py("check_static_run_governance_posture.py")
        if code != 0:
            print(status_messages.status(f"Script exited {code}.", level="warn"))
    elif choice == "3":
        run_artifact_registry_integrity_report()
    elif choice == "4":
        extra_cc = _artifact_cleanup_candidates_extras_from_prompts()
        run_scripts_db_py(
            "report_artifact_registry_cleanup_candidates.py",
            extra_cc if extra_cc else None,
        )
    elif choice == "5":
        want_explain = prompt_utils.prompt_yes_no(
            "Include --explain (stderr legend for artifact_static_numeric_dangling)?",
            default=True,
        )
        run_verify_static_session_id_rollout(
            extra=["--explain"] if want_explain else [],
        )
    elif choice == "6":
        use = _session_stamp_or_prompt(
            default_session_stamp,
            primary_label="session_stamp (e.g. 20260510-all-full)",
        )
        run_session_static_health(use)
    elif choice == "7":
        _run_grain_integrity_with_prompts(default_session_stamp)
    elif choice == "8":
        _run_canonical_audit_with_prompts(default_session_stamp)


def static_session_diagnostics_menu() -> None:
    """Ledger / catalog governance plus session-scoped read-only probes."""

    while True:
        print()
        menu_utils.print_header("Static & registry diagnostics")
        menu_utils.print_hint(
            "Read-only. Analyst core DB (SCYTALEDROID_DB_*). "
            "Subprocess scripts under scripts/db/ except items 1 and 8 (in-process)."
        )
        menu_utils.print_section("Ledger & catalog")
        print("  1) Run-class / handoff invariants (in-process counts)")
        print("  2) Same checks via subprocess (exit 0/1/2; CI / gates)")
        print("  3) Artifact registry integrity (v_artifact_registry_integrity)")
        print("  4) Artifact registry cleanup candidates (optional --run-type / --path-sample)")
        print("  5) Static session_id rollout verification (scalar counts; --explain optional)")
        print()
        menu_utils.print_section("Session-scoped (session_stamp)")
        print("  6) Session static health (DB + optional persistence audit JSON)")
        print("  7) Grain / integrity report (--session-stamp)")
        print("  8) Canonical session audit (DB counts + views; in-process)")
        print()
        choice = prompt_utils.get_choice(_STATIC_REGISTRY_KEYS, default="0")
        if choice == "0":
            return
        _dispatch_static_registry_choice(choice, default_session_stamp=None)


def post_run_db_checks_submenu(*, session_stamp: str | None, persist_enabled: bool) -> None:
    """Post-run diagnostics: same static/registry hub with optional default session_stamp."""

    stamp = str(session_stamp or "").strip()
    while True:
        print()
        menu_utils.print_header("DB-backed session checks (read-only)")
        if not persist_enabled:
            menu_utils.print_hint("DB persistence was skipped for this run; probes may be less meaningful.")
        if stamp:
            menu_utils.print_hint(f"session_stamp default for items 6–8: {stamp}")
        else:
            menu_utils.print_hint("No session_stamp on this run; enter stamp manually when prompted.")
        menu_utils.print_section("Ledger & catalog")
        print("  1) Run-class / handoff invariants (in-process)")
        print("  2) Same checks via subprocess (CI exits)")
        print("  3) Artifact registry integrity")
        print("  4) Artifact registry cleanup candidates")
        print("  5) Static session_id rollout verify")
        print()
        menu_utils.print_section("Session-scoped")
        print("  6) Session static health")
        print("  7) Grain / integrity report")
        print("  8) Canonical session audit (in-process)")
        print("  0) Back")
        choice = prompt_utils.get_choice(_STATIC_REGISTRY_KEYS, default="0")
        if choice == "0":
            return
        _dispatch_static_registry_choice(choice, default_session_stamp=stamp or None)


__all__ = [
    "post_run_db_checks_submenu",
    "run_artifact_registry_cleanup_candidates_report",
    "run_artifact_registry_integrity_report",
    "run_grain_integrity_report",
    "run_session_static_health",
    "run_static_session_canonical_audit",
    "run_verify_static_session_id_rollout",
    "static_session_diagnostics_menu",
]
