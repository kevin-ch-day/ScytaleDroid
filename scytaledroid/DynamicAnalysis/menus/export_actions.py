"""Export-oriented menu actions for Dynamic Analysis."""

from __future__ import annotations

from pathlib import Path

from scytaledroid.Utils.DisplayUtils import menu_utils, status_messages


def count_csv_rows(path: Path) -> int | None:
    try:
        with path.open("r", encoding="utf-8") as handle:
            count = sum(1 for _ in handle)
        return max(0, count - 1)
    except Exception:
        return None


def export_pcap_features_csv(*, resolve_dataset_freeze_read_path_fn) -> None:
    from scytaledroid.DynamicAnalysis.pcap.aggregate import export_pcap_features_csv as export_fn

    print()
    menu_utils.print_header("PCAP Features Export")
    freeze_path = resolve_dataset_freeze_read_path_fn()
    try:
        output_path = export_fn(freeze_path=freeze_path, require_freeze=True)
    except RuntimeError as exc:
        print(status_messages.status(str(exc), level="error"))
        return
    if output_path is None:
        print(status_messages.status("No pcap_features.json files found.", level="warn"))
        return
    count = count_csv_rows(output_path)
    msg = f"Exported CSV: {output_path} [frozen-archive]"
    if count is not None:
        msg += f" ({count} row(s))"
    print(status_messages.status(msg, level="success"))


def export_dynamic_run_summary_csv(*, resolve_dataset_freeze_read_path_fn) -> None:
    from scytaledroid.DynamicAnalysis.pcap.aggregate import export_dynamic_run_summary_csv as export_fn

    print()
    menu_utils.print_header("Run Summary Export")
    freeze_path = resolve_dataset_freeze_read_path_fn()
    try:
        output_path = export_fn(freeze_path=freeze_path, require_freeze=True)
    except RuntimeError as exc:
        print(status_messages.status(str(exc), level="error"))
        return
    if output_path is None:
        print(status_messages.status("No dynamic run summaries found.", level="warn"))
        return
    count = count_csv_rows(output_path)
    msg = f"Exported CSV: {output_path} [frozen-archive]"
    if count is not None:
        msg += f" ({count} row(s))"
    print(status_messages.status(msg, level="success"))


def export_protocol_ledger_csv(*, resolve_dataset_freeze_read_path_fn) -> None:
    from scytaledroid.DynamicAnalysis.pcap.aggregate import export_protocol_ledger_csv as export_fn

    print()
    menu_utils.print_header("Protocol Ledger Export")
    freeze_path = resolve_dataset_freeze_read_path_fn()
    try:
        output_path = export_fn(freeze_path=freeze_path, require_freeze=True)
    except RuntimeError as exc:
        print(status_messages.status(str(exc), level="error"))
        return
    if output_path is None:
        print(status_messages.status("No protocol ledger rows found.", level="warn"))
        return
    count = count_csv_rows(output_path)
    msg = f"Exported CSV: {output_path} [frozen-archive]"
    if count is not None:
        msg += f" ({count} row(s))"
    print(status_messages.status(msg, level="success"))


def run_cohort_security_audit_export(*, include_hidden_patterns: bool = False) -> None:
    """Export cohort PCAP security-surface audit CSVs from live evidence packs."""
    from scytaledroid.DynamicAnalysis.utils.path_utils import dynamic_evidence_root

    print()
    menu_utils.print_header("Cohort Security Audit Export")
    try:
        from scripts.db import report_dynamic_pcap_payload_audit as payload_audit
    except Exception as exc:  # noqa: BLE001
        print(status_messages.status(f"Payload audit export unavailable: {exc}", level="error"))
        return
    try:
        summary = payload_audit.generate_report()
    except Exception as exc:  # noqa: BLE001
        print(status_messages.status(f"Security audit export failed: {exc}", level="error"))
        return
    output_files = summary.get("output_files") if isinstance(summary.get("output_files"), dict) else {}
    runs_scanned = summary.get("runs_scanned")
    print(
        status_messages.status(
            f"Scanned {runs_scanned} evidence pack(s) under {dynamic_evidence_root()}",
            level="info",
        )
    )
    for label, path in sorted(output_files.items()):
        count = count_csv_rows(Path(str(path))) if path else None
        suffix = f" ({count} rows)" if count is not None else ""
        print(status_messages.status(f"{label}: {path}{suffix}", level="success"))
    rollup_path = output_files.get("app_payload_rollup_csv")
    if rollup_path:
        try:
            import csv

            denied = 0
            surface = 0
            with Path(str(rollup_path)).open(encoding="utf-8") as handle:
                for row in csv.DictReader(handle):
                    denied += int(row.get("cleartext_mismatch_denied_observed_runs") or 0)
                    surface += int(row.get("cleartext_surface_runs") or 0)
            print(
                status_messages.status(
                    f"Cohort cleartext surface runs: {surface}; static-denied-but-observed: {denied}",
                    level="info",
                )
            )
        except Exception:
            pass
    print(
        status_messages.status(
            "Tip: backfill security_surface on older packs with "
            "PYTHONPATH=. python scripts/db/backfill_dynamic_security_surface.py --apply",
            level="info",
        )
    )
    if include_hidden_patterns:
        try:
            from scripts.db import report_dynamic_hidden_patterns as hidden

            hidden_summary = hidden.generate_report()
            print(
                status_messages.status(
                    f"Hidden patterns: {hidden_summary.get('candidate_count')} candidates",
                    level="success",
                )
            )
        except Exception as exc:  # noqa: BLE001
            print(status_messages.status(f"Hidden patterns export failed: {exc}", level="warn"))
    try:
        from scytaledroid.DynamicAnalysis.pcap.security_cohort import generate_cohort_security_report

        cohort_payload = generate_cohort_security_report()
        review = (cohort_payload.get("output_files") or {}).get("cohort_security_review_md")
        print(
            status_messages.status(
                f"Cohort security: {cohort_payload.get('cleartext_surface_runs')} cleartext-surface, "
                f"{cohort_payload.get('xmpp_cleartext_runs')} XMPP, "
                f"{cohort_payload.get('mismatch_denied_observed')} denied-but-observed"
                + (f" · review={review}" if review else ""),
                level="info",
            )
        )
    except Exception as exc:  # noqa: BLE001
        print(status_messages.status(f"Cohort security analysis failed: {exc}", level="warn"))
