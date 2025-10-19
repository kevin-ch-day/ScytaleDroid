"""Result rendering helpers for static analysis CLI."""

from __future__ import annotations

from scytaledroid.Utils.DisplayUtils import prompt_utils, status_messages, table_utils

from ...engine.strings import analyse_strings
from ..db_persist import persist_run_summary
from ..detail import (
    SEVERITY_TOKEN_ORDER,
    app_detail_loop,
    render_app_detail,
)
from ..masvs_summary import fetch_db_masvs_summary
from ..models import RunOutcome, RunParameters
from ..renderer import render_app_result, write_baseline_json
from .scan_flow import format_duration
from scytaledroid.Database.db_core import db_queries as core_q


def render_run_results(outcome: RunOutcome, params: RunParameters) -> None:
    """Pretty-print run results and optionally drill into per-app details."""

    print(f"Duration: {format_duration(outcome.duration_seconds)}")
    print()

    for index, app_result in enumerate(outcome.results, start=1):
        base_report = app_result.base_report()
        if base_report is None:
            warning = f"No report generated for {app_result.package_name}."
            print(status_messages.status(warning, level="warn"))
            continue

        string_data = analyse_strings(
            base_report.file_path,
            mode=params.strings_mode,
            min_entropy=params.string_min_entropy,
            max_samples=params.string_max_samples,
            cleartext_only=params.string_cleartext_only,
        )

        try:
            persist_run_summary(base_report, string_data, app_result.package_name)
        except Exception as exc:
            warning = (
                f"Failed to persist run summary for {app_result.package_name}: {exc}"
            )
            print(status_messages.status(warning, level="warn"))

        total_duration = sum(artifact.duration_seconds for artifact in app_result.artifacts)
        lines, payload, _ = render_app_result(
            base_report,
            signer=app_result.signer,
            split_count=len(app_result.artifacts),
            string_data=string_data,
            duration_seconds=total_duration,
        )

        for line in lines:
            print(line)

        try:
            saved_path = write_baseline_json(
                payload,
                package=app_result.package_name,
                profile=params.profile,
                scope=params.scope,
            )
            print(f"  Saved baseline JSON → {saved_path.name}")
        except Exception as exc:
            warning = (
                f"Failed to write baseline JSON for {app_result.package_name}: {exc}"
            )
            print(status_messages.status(warning, level="warn"))

        if index < len(outcome.results):
            print()

    session_stamp = params.session_stamp
    if outcome.results:
        printed_db_table = False
        if session_stamp:
            printed_db_table = _render_db_severity_table(session_stamp)
        if not printed_db_table:
            from ..detail import render_app_table  # local import to avoid cycle

            render_app_table(outcome.results)
        if session_stamp and not params.dry_run:
            _render_persistence_footer(session_stamp)
        _interactive_detail_loop(outcome, params)

    if outcome.warnings:
        for message in sorted(set(outcome.warnings)):
            print(status_messages.status(message, level="warn"))
    if outcome.failures:
        for message in sorted(set(outcome.failures)):
            print(status_messages.status(message, level="error"))

    _render_db_masvs_summary()


def _interactive_detail_loop(outcome: RunOutcome, params: RunParameters) -> None:
    while True:
        resp = prompt_utils.prompt_text(
            "View details for app # (Enter to skip)", default="", required=False
        ).strip()
        if not resp:
            break
        if not resp.isdigit():
            print(status_messages.status("Invalid selection.", level="warn"))
            continue
        idx = int(resp)
        if idx < 1 or idx > len(outcome.results):
            print(status_messages.status("Selection out of range.", level="warn"))
            continue
        selected = outcome.results[idx - 1]
        app_detail_loop(
            selected,
            params.evidence_lines,
            set(SEVERITY_TOKEN_ORDER),
            params.finding_limit,
            render_app_detail,
        )


def _render_db_masvs_summary() -> None:
    try:
        summary = fetch_db_masvs_summary()
        if not summary:
            return
        run_id, rows = summary
        print()
        print(f"DB MASVS Summary (run_id={run_id})")
        print("Area       High  Med   Low   Info  Status  Worst CVSS")
        for area in ("NETWORK", "PLATFORM", "PRIVACY", "STORAGE"):
            entry = next((row for row in rows if row["area"] == area), None)
            if entry is None:
                print(f"{area.title():<9}  0     0     0     0     PASS   —")
            else:
                status = "PASS" if entry["sev_ge_med"] == 0 else "FAIL"
                print(
                    f"{area.title():<9}  0     {entry['sev_ge_med']:<5}{entry['low']:<5}{entry['info']:<6}"
                    f"{status:<6} {entry['worst']}"
                )
    except Exception:
        pass


__all__ = ["render_run_results"]


def _render_db_severity_table(session_stamp: str) -> bool:
    try:
        rows = core_q.run_sql(
            """
            SELECT s.package_name, COALESCE(r.target_sdk, '—') AS target_sdk,
                   s.high, s.med, s.low, s.info
            FROM static_findings_summary s
            LEFT JOIN runs r
              ON r.package = s.package_name
             AND r.session_stamp = s.session_stamp
            WHERE s.session_stamp = %s
            ORDER BY s.package_name
            """,
            (session_stamp,),
            fetch="all",
            dictionary=True,
        ) or []
    except Exception:
        return False

    if not rows:
        return False

    table_rows = []
    for idx, row in enumerate(rows, start=1):
        table_rows.append(
            [
                str(idx),
                row.get("package_name", "—"),
                str(row.get("target_sdk", "—")),
                str(int(row.get("high") or 0)),
                str(int(row.get("med") or 0)),
                str(int(row.get("low") or 0)),
                str(int(row.get("info") or 0)),
            ]
        )

    print()
    table_utils.render_table(
        ["#", "Package", "targetSdk", "High", "Med", "Low", "Info"],
        table_rows,
    )
    return True


def _render_persistence_footer(session_stamp: str) -> None:
    try:
        run_rows = core_q.run_sql(
            "SELECT run_id FROM runs WHERE session_stamp = %s",
            (session_stamp,),
            fetch="all",
        ) or []
    except Exception:
        return

    run_ids = [int(row[0]) for row in run_rows if row and row[0] is not None]

    def _count(sql: str, params: tuple[object, ...]) -> int:
        try:
            row = core_q.run_sql(sql, params, fetch="one")
        except Exception:
            return 0
        if not row:
            return 0
        value = row[0] if not isinstance(row, dict) else next(iter(row.values()), 0)
        try:
            return int(value or 0)
        except (TypeError, ValueError):
            return 0

    findings_summary = _count(
        "SELECT COUNT(*) FROM static_findings_summary WHERE session_stamp = %s",
        (session_stamp,),
    )
    findings_detail = _count(
        """
        SELECT COUNT(*)
        FROM static_findings f
        JOIN static_findings_summary s ON s.id = f.summary_id
        WHERE s.session_stamp = %s
        """,
        (session_stamp,),
    )
    strings_summary = _count(
        "SELECT COUNT(*) FROM static_string_summary WHERE session_stamp = %s",
        (session_stamp,),
    )
    string_samples = _count(
        """
        SELECT COUNT(*)
        FROM static_string_samples x
        JOIN static_findings_summary s ON s.id = x.summary_id
        WHERE s.session_stamp = %s
        """,
        (session_stamp,),
    )
    fileproviders = _count(
        "SELECT COUNT(*) FROM static_fileproviders WHERE session_stamp = %s",
        (session_stamp,),
    )
    provider_acl = _count(
        "SELECT COUNT(*) FROM static_provider_acl WHERE session_stamp = %s",
        (session_stamp,),
    )

    buckets = metrics = findings = contributors = 0
    if run_ids:
        placeholders = ",".join(["%s"] * len(run_ids))
        params = tuple(run_ids)
        buckets = _count(
            f"SELECT COUNT(*) FROM buckets WHERE run_id IN ({placeholders})",
            params,
        )
        metrics = _count(
            f"SELECT COUNT(*) FROM metrics WHERE run_id IN ({placeholders})",
            params,
        )
        findings = _count(
            f"SELECT COUNT(*) FROM findings WHERE run_id IN ({placeholders})",
            params,
        )
        contributors = _count(
            f"SELECT COUNT(*) FROM contributors WHERE run_id IN ({placeholders})",
            params,
        )

    print()
    print("Persisted")
    print("==========")
    lines = [
        ("runs", str(len(run_ids))),
        ("static_findings_summary", f"{findings_summary} ({findings_detail})"),
        ("static_string_summary", f"{strings_summary} ({string_samples})"),
        ("static_fileproviders", str(fileproviders)),
        ("static_provider_acl", str(provider_acl)),
        ("buckets", str(buckets)),
        ("metrics", str(metrics)),
        ("findings", str(findings)),
        ("contributors", str(contributors)),
    ]
    width = max(len(name) for name, _ in lines) if lines else 0
    for name, detail in lines:
        print(f"  {name.ljust(width)} : {detail}")
