"""Post-run static session summary (persistence audit + optional DB enrichment)."""

from __future__ import annotations

import json
from collections import Counter
from pathlib import Path
from typing import Any

from scytaledroid.Config import app_config
from scytaledroid.Database.db_scripts.static_run_audit import collect_static_run_counts
from scytaledroid.Utils.DisplayUtils import menu_utils, prompt_utils, status_messages, table_utils


def resolve_persistence_audit_path(session_stamp: str, *, output_dir: str | None = None) -> Path | None:
    stamp = (session_stamp or "").strip()
    if not stamp:
        return None
    base = Path(output_dir or app_config.OUTPUT_DIR) / "audit" / "persistence"
    for name in (f"{stamp}_persistence_audit.json", f"{stamp}_missing_run_ids.json"):
        p = base / name
        if p.is_file():
            return p
    return None


def load_persistence_audit_payload(session_stamp: str, *, output_dir: str | None = None) -> dict[str, Any] | None:
    path = resolve_persistence_audit_path(session_stamp, output_dir=output_dir)
    if path is None:
        return None
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return None


def _audit_row_stats(rows: list[dict[str, Any]]) -> dict[str, Any]:
    by_stage = Counter(str(r.get("stage") or "unknown") for r in rows)
    with_exc = [r for r in rows if r.get("exception_class") or r.get("exception_message")]
    with_warn = [r for r in rows if r.get("persistence_warnings")]
    completed_like = [
        r
        for r in rows
        if str(r.get("stage") or "") == "completed"
        and not r.get("exception_class")
        and not r.get("exception_message")
    ]
    return {
        "row_count": len(rows),
        "persistence_error_rows": len(with_exc),
        "persistence_warning_rows": len(with_warn),
        "completed_audit_rows": len(completed_like),
        "stages": dict(by_stage),
    }


def render_post_run_session_summary(
    session_stamp: str,
    *,
    output_dir: str | None = None,
    skip_db: bool = False,
    interactive: bool = True,
    skip_permission_insights: bool = False,
) -> None:
    """Print operator summary: persistence JSON + optional canonical DB checks."""

    stamp = (session_stamp or "").strip()
    if not stamp:
        print(status_messages.status("session_stamp is required.", level="error"))
        return

    print()
    menu_utils.print_header("Post-run session summary", stamp)

    payload = load_persistence_audit_payload(stamp, output_dir=output_dir)
    path = resolve_persistence_audit_path(stamp, output_dir=output_dir)
    if path:
        print(status_messages.status(f"Persistence audit: {path}", level="info"))
    if not payload:
        print(status_messages.status("No persistence audit JSON found for this session.", level="warn"))
    else:
        rows_raw = payload.get("rows")
        rows = [dict(r) for r in rows_raw] if isinstance(rows_raw, list) else []
        stats = _audit_row_stats(rows)
        outcome = payload.get("outcome") if isinstance(payload.get("outcome"), dict) else {}
        menu_utils.print_section("Persistence artifact")
        menu_utils.print_metrics(
            [
                ("total_apps (artifact)", str(payload.get("total_apps") or stats["row_count"])),
                ("rows in audit", str(stats["row_count"])),
                ("rows completed (no exception)", str(stats["completed_audit_rows"])),
                ("rows with persistence exception", str(stats["persistence_error_rows"])),
                ("rows with persistence warnings", str(stats["persistence_warning_rows"])),
                ("canonical_failed", str(outcome.get("canonical_failed"))),
                ("persistence_failed", str(outcome.get("persistence_failed"))),
            ]
        )
        if stats["stages"]:
            print()
            menu_utils.print_section("Persistence stages (row counts)")
            for k, v in sorted(stats["stages"].items(), key=lambda kv: (-kv[1], kv[0])):
                print(f"  {k}: {v}")

        err_rows = [
            r
            for r in rows
            if r.get("exception_class") or r.get("exception_message") or r.get("errno")
        ]
        err_rows.sort(key=lambda r: str(r.get("package_name") or ""))
        if err_rows:
            print()
            menu_utils.print_section("Apps with persistence errors (from audit JSON)")
            table_utils.render_table(
                ["package", "static_run_id", "stage", "exception", "message (trimmed)"],
                [
                    [
                        str(r.get("package_name") or "—")[:48],
                        str(r.get("static_run_id") or "—"),
                        str(r.get("stage") or "—")[:28],
                        str(r.get("exception_class") or "—")[:20],
                        (str(r.get("exception_message") or "")[:72] + "…")
                        if len(str(r.get("exception_message") or "")) > 72
                        else str(r.get("exception_message") or "—"),
                    ]
                    for r in err_rows[:25]
                ],
            )
            if len(err_rows) > 25:
                print(status_messages.status(f"… plus {len(err_rows) - 25} more", level="info"))

        warn_rows = [r for r in rows if r.get("persistence_warnings")]
        if warn_rows:
            print()
            menu_utils.print_section("Apps with persistence warnings (non-fatal; from audit JSON)")
            for r in warn_rows[:15]:
                pkg = str(r.get("package_name") or "—")
                sid = str(r.get("static_run_id") or "—")
                codes = ", ".join(
                    str(w.get("warning_code") or "?")
                    for w in (r.get("persistence_warnings") or [])
                    if isinstance(w, dict)
                )
                print(f"  {pkg[:52]:<52} static_run_id={sid}  {codes}")
            if len(warn_rows) > 15:
                print(status_messages.status(f"… plus {len(warn_rows) - 15} more", level="info"))

    if skip_db:
        if interactive:
            prompt_utils.press_enter_to_continue()
        return

    menu_utils.print_section("Database enrichment")
    try:
        audit = collect_static_run_counts(session_stamp=stamp)
    except Exception as exc:
        print(status_messages.status(f"DB audit skipped: {exc}", level="warn"))
        if interactive:
            prompt_utils.press_enter_to_continue()
        return

    if not audit:
        print(status_messages.status("No static_analysis_runs match this session_stamp.", level="warn"))
        if interactive:
            prompt_utils.press_enter_to_continue()
        return

    gv = audit.group_verification
    menu_utils.print_metrics(
        [
            ("group_scope", str(audit.is_group_scope)),
            ("static_analysis_runs (table)", str(audit.counts.get("static_analysis_runs", ("?",))[0])),
            ("legacy findings rows", str(audit.counts.get("findings", ("?",))[0])),
            ("canonical findings rows", str(audit.counts.get("static_analysis_findings", ("?",))[0])),
            ("static_findings_summary", str(audit.counts.get("static_findings_summary", ("?",))[0])),
            ("static_string_summary", str(audit.counts.get("static_string_summary", ("?",))[0])),
            ("static_permission_matrix", str(audit.counts.get("static_permission_matrix", ("?",))[0])),
            ("permission_audit_apps", str(audit.counts.get("permission_audit_apps", ("?",))[0])),
        ]
    )
    print()
    menu_utils.print_hint(
        "Permission provenance (manifest vs splits, dictionary match) lives in each report JSON under "
        "detector_metrics.permissions_profile when the detector ran; matrix/audit counts below are canonical DB surfaces."
    )

    if gv:
        print()
        menu_utils.print_section("Group session verification")
        menu_utils.print_metrics(
            [
                ("completed_runs", str(gv.completed_total)),
                ("failed_terminal", str(gv.failed_total)),
                ("started_runs", str(gv.started_total)),
                ("overall", gv.overall),
            ]
        )
        for note in gv.notes:
            print(status_messages.status(note, level="info"))

    _print_top_failed_packages(stamp)

    if not skip_db and not skip_permission_insights:
        try:
            from scytaledroid.StaticAnalysis.cli.audit.permission_session_insights import (
                render_permission_session_insights,
            )

            print()
            render_permission_session_insights(stamp, output_dir=output_dir)
        except Exception as exc:
            print(status_messages.status(f"Permission session insights skipped: {exc}", level="warn"))

    if interactive:
        prompt_utils.press_enter_to_continue()


def _print_top_failed_packages(session_stamp: str) -> None:
    try:
        from scytaledroid.Database.db_core import db_queries as core_q
    except Exception:
        return

    try:
        rows = core_q.run_sql(
            """
            SELECT a.package_name,
                   sar.status,
                   COALESCE(sar.abort_reason, '') AS abort_reason,
                   COALESCE(spf.exception_message, '') AS persist_msg
            FROM static_analysis_runs sar
            JOIN app_versions av ON av.id = sar.app_version_id
            JOIN apps a ON a.id = av.app_id
            LEFT JOIN static_persistence_failures spf ON spf.static_run_id = sar.id
            WHERE sar.session_stamp = %s
              AND UPPER(COALESCE(sar.status, '')) = 'FAILED'
            ORDER BY sar.id ASC
            LIMIT 10
            """,
            (session_stamp,),
            fetch="all",
        ) or []
    except Exception as exc:
        print(status_messages.status(f"Failed-list query skipped: {exc}", level="warn"))
        return

    if not rows:
        return
    print()
    menu_utils.print_section("Top failed packages (DB, up to 10)")
    table_utils.render_table(
        ["package", "abort_reason", "persistence failure (trimmed)"],
        [
            [
                str(r[0])[:40],
                str(r[2] or "—")[:24],
                (str(r[3] or "—")[:64] + "…") if len(str(r[3] or "")) > 64 else str(r[3] or "—"),
            ]
            for r in rows
        ],
    )


def prompt_post_run_session_summary() -> None:
    print()
    menu_utils.print_section("Post-run session summary")
    stamp = prompt_utils.prompt_text("session_stamp", required=True).strip()
    render_post_run_session_summary(stamp)


__all__ = [
    "load_persistence_audit_payload",
    "render_post_run_session_summary",
    "resolve_persistence_audit_path",
    "prompt_post_run_session_summary",
]
