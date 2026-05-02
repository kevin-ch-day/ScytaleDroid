"""MySQL web-view alignment helpers and report path sampling."""

from __future__ import annotations

from collections.abc import Mapping

from ...core.models import AppRunResult


def _approximate_findings_ready(
    *,
    persistence_enabled: bool,
    persist_attempted: bool,
    persisted_ok_app: bool,
    persisted_findings: int | None,
) -> int | None:
    """Best-effort stand-in for MySQL ``findings_ready`` (1 if row count > 0, else 0).

    Returns ``None`` when this run did not produce a reliable DB-side signal from the CLI.
    """
    if not persistence_enabled or not persist_attempted:
        return None
    if not persisted_ok_app:
        return None
    if not isinstance(persisted_findings, int):
        return None
    return 1 if persisted_findings > 0 else 0


def _web_session_health_projection_for_app(
    app: AppRunResult,
    *,
    persistence_enabled: bool,
    persist_attempted: bool,
    persisted: bool,
    persisted_ok_app: bool,
    rt_pf: object,
    ps_pf: object,
    cap_pf: object,
) -> dict[str, object]:
    """Map MySQL ``v_web_*`` column names to CLI-computable values where possible."""
    findings_ready = _approximate_findings_ready(
        persistence_enabled=persistence_enabled,
        persist_attempted=persist_attempted,
        persisted_ok_app=persisted_ok_app,
        persisted_findings=ps_pf if isinstance(ps_pf, int) else None,
    )
    mysql_only = {
        "permissions_ready": None,
        "strings_ready": None,
        "audit_ready": None,
        "link_ready": None,
        "session_usability": None,
        "is_usable_complete": None,
    }
    cap_json: object | None
    if isinstance(cap_pf, int) and cap_pf > 0:
        cap_json = getattr(app, "persistence_findings_capped_by_detector", None)
    else:
        cap_json = None
    return {
        "approximate_mysql_columns": {
            "findings_ready": findings_ready,
            "findings_runtime_total": rt_pf if isinstance(rt_pf, int) else None,
            "findings_persisted_rowcount_approx": ps_pf if isinstance(ps_pf, int) else None,
            "findings_capped_total": cap_pf if isinstance(cap_pf, int) else None,
            "findings_capped_by_detector_json": cap_json if isinstance(cap_json, Mapping) else None,
        },
        "mysql_only_requires_db_refresh": mysql_only,
    }


def collect_report_paths_for_app(app_result: AppRunResult, limit: int = 24) -> list[str]:
    paths: list[str] = []
    for art in getattr(app_result, "artifacts", []) or []:
        p = getattr(art, "saved_path", None)
        if p and str(p).strip():
            paths.append(str(p))
        if len(paths) >= max(8, limit):
            break
    return paths[:limit]
