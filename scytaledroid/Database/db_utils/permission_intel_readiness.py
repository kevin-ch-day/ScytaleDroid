"""Permission Intel readiness for ScytaleDroid (``android_permission_intel`` via SCYTALEDROID_* env)."""

from __future__ import annotations

from dataclasses import dataclass

from scytaledroid.Database.db_core import permission_intel as intel_db
from scytaledroid.StaticAnalysis.cli.execution.pipeline import governance_ready
from scytaledroid.Utils.DisplayUtils import menu_utils, prompt_utils, status_messages


_EXPECTED_INTEL_CATALOG = "android_permission_intel"


@dataclass(frozen=True)
class PermissionIntelReadiness:
    configured: bool
    resolved_database: str | None
    catalog_name_matches_expected: bool
    connect_ok: bool
    missing_tables: tuple[str, ...]
    governance_ok: bool
    governance_detail: str | None
    dictionary_select_ok: bool


def assess_permission_intel_readiness() -> PermissionIntelReadiness:
    """Connectivity + required tables + dictionary read + governance gate (no writes probed)."""

    if not intel_db.is_permission_intel_configured():
        return PermissionIntelReadiness(
            configured=False,
            resolved_database=None,
            catalog_name_matches_expected=False,
            connect_ok=False,
            missing_tables=(),
            governance_ok=False,
            governance_detail="not_configured",
            dictionary_select_ok=False,
        )

    resolved_db: str | None = None
    catalog_ok = False
    try:
        desc = intel_db.describe_target()
        resolved_db = str(desc.get("database") or "").strip() or None
        catalog_ok = (resolved_db or "").lower() == _EXPECTED_INTEL_CATALOG
    except Exception:
        resolved_db = None
        catalog_ok = False

    missing: list[str] = []
    connect_ok = True
    for table in intel_db.MANAGED_TABLES:
        try:
            if not intel_db.intel_table_exists(table):
                missing.append(table)
        except Exception:
            missing.append(table)
            connect_ok = False

    dict_ok = False
    if connect_ok and not missing:
        dict_ok = bool(intel_db.probe_dictionary_read_access())
        if not dict_ok:
            connect_ok = False

    gov_ok, gov_detail = governance_ready()
    return PermissionIntelReadiness(
        configured=True,
        resolved_database=resolved_db,
        catalog_name_matches_expected=catalog_ok,
        connect_ok=connect_ok,
        missing_tables=tuple(missing),
        governance_ok=bool(gov_ok),
        governance_detail=gov_detail,
        dictionary_select_ok=dict_ok,
    )


def render_permission_intel_readiness(*, paper_grade_requested: bool) -> str:
    """
    Print status lines. Returns a short label: OK | EXPERIMENTAL | ERROR.

    * paper_grade_requested=True mirrors static analysis when canonical paper-grade is expected:
      missing Intel or governance yields ERROR-level messaging.
    """

    print()
    menu_utils.print_header("Permission Intel readiness (SCYTALEDROID_PERMISSION_INTEL_DB_*)")
    print(
        status_messages.status(
            "ScytaleDroid Permission Intel → SCYTALEDROID_PERMISSION_INTEL_DB_* "
            "(expected catalog: android_permission_intel). Erebus uses its own DB via EREBUS_* — not this catalog.",
            level="info",
        )
    )

    state = assess_permission_intel_readiness()
    if not state.configured:
        print(status_messages.status("Configuration: NOT SET (no resolved Intel DSN)", level="warn"))
        print(
            "  Set SCYTALEDROID_PERMISSION_INTEL_DB_URL or "
            "SCYTALEDROID_PERMISSION_INTEL_DB_HOST/PORT/NAME/USER/PASSWD."
        )
        if paper_grade_requested:
            print(status_messages.status("Status: ERROR (paper-grade context requires Permission Intel)", level="error"))
            return "ERROR"
        print(
            status_messages.status(
                "Status: EXPERIMENTAL (Intel absent; OK when SCYTALEDROID_CANONICAL_GRADE=0 / no paper-grade)",
                level="warn",
            )
        )
        return "EXPERIMENTAL"

    try:
        desc = intel_db.describe_target()
    except Exception as exc:
        print(status_messages.status(f"describe_target failed: {exc}", level="error"))
        return "ERROR"

    menu_utils.print_metrics(
        [
            ("host", str(desc.get("host") or "—")),
            ("port", str(desc.get("port") or "—")),
            ("database", str(desc.get("database") or "—")),
            ("user", str(desc.get("user") or "—")),
            ("source", str(desc.get("source") or "—")),
            (
                "expected catalog",
                _EXPECTED_INTEL_CATALOG,
            ),
            (
                "catalog name OK",
                "yes" if state.catalog_name_matches_expected else "no",
            ),
        ]
    )

    if not state.catalog_name_matches_expected:
        print(
            status_messages.status(
                f"Resolved database name is not {_EXPECTED_INTEL_CATALOG!r} "
                f"(got {state.resolved_database!r}). Point SCYTALEDROID_PERMISSION_INTEL_DB_* at the Intel catalog.",
                level="error",
            )
        )
        if paper_grade_requested:
            print(
                status_messages.status(
                    "Status: ERROR (paper-grade requires Permission Intel on android_permission_intel)",
                    level="error",
                )
            )
            return "ERROR"
        print(
            status_messages.status(
                "Status: EXPERIMENTAL (resolved database name is not android_permission_intel; "
                "fix SCYTALEDROID_PERMISSION_INTEL_DB_* before relying on dictionary/governance)",
                level="warn",
            )
        )
        return "EXPERIMENTAL"

    if not state.connect_ok:
        print(status_messages.status("Connection / introspection: FAILED", level="error"))
        return "ERROR"

    if state.missing_tables:
        print(
            status_messages.status(
                f"Missing required tables/views: {', '.join(state.missing_tables)}",
                level="error",
            )
        )
        return "ERROR"

    print(
        status_messages.status(
            "Dictionary read probe: OK" if state.dictionary_select_ok else "Dictionary read probe: FAILED",
            level="info" if state.dictionary_select_ok else "error",
        )
    )

    print(
        status_messages.status(
            "Write capability: not auto-probed (avoid side effects). "
            "Confirm INSERT/UPDATE GRANTs on Permission Intel observation/queue tables with your DBA.",
            level="info",
        )
    )

    gov_label = state.governance_detail or "ok"
    print(f"  governance_ready: {state.governance_ok} ({gov_label})")

    if paper_grade_requested:
        if not state.governance_ok:
            print(
                status_messages.status(
                    "Status: ERROR (paper-grade requested; governance / Intel gate not satisfied)",
                    level="error",
                )
            )
            return "ERROR"
        print(status_messages.status("Status: OK (Permission Intel configured and paper-grade gate satisfied)", level="info"))
        return "OK"

    if not state.governance_ok:
        print(
            status_messages.status(
                "Status: EXPERIMENTAL (Intel reachable but governance incomplete for paper-grade)",
                level="warn",
            )
        )
        return "EXPERIMENTAL"

    print(status_messages.status("Status: OK (Permission Intel configured and reachable)", level="info"))
    return "OK"


def prompt_permission_intel_readiness() -> None:
    print()
    raw = prompt_utils.prompt_yes_no(
        "Treat this check as paper-grade / canonical grade context?",
        default=False,
    )
    render_permission_intel_readiness(paper_grade_requested=bool(raw))
    prompt_utils.press_enter_to_continue()


__all__ = [
    "PermissionIntelReadiness",
    "assess_permission_intel_readiness",
    "prompt_permission_intel_readiness",
    "render_permission_intel_readiness",
]
