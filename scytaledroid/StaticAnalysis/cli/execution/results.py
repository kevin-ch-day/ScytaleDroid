"""Result rendering helpers for static analysis CLI."""

from __future__ import annotations

from scytaledroid.Utils.DisplayUtils import prompt_utils, status_messages

from ...engine.strings import analyse_strings
from ..db_persist import persist_run_summary
from ..detail import (
    SEVERITY_TOKEN_ORDER,
    app_detail_loop,
    render_app_detail,
    render_app_table,
)
from ..masvs_summary import fetch_db_masvs_summary
from ..models import RunOutcome, RunParameters
from ..renderer import render_app_result, write_baseline_json
from .scan_flow import format_duration


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
        except Exception:
            pass

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
        except Exception:
            pass

        if index < len(outcome.results):
            print()

    if outcome.results:
        render_app_table(outcome.results)
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
