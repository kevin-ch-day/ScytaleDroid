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

