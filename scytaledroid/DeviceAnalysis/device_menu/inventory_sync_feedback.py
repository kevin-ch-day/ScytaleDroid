"""CLI feedback lines after an inventory sync (Device Analysis menu paths)."""

from __future__ import annotations

from scytaledroid.DeviceAnalysis.inventory import cli_labels as inventory_cli_labels
from scytaledroid.Utils.DisplayUtils import status_messages


def inventory_run_duration_label(seconds: float | None) -> str:
    if seconds is None or float(seconds) < 1.0:
        return ""
    total = int(round(float(seconds)))
    minutes, secs = divmod(total, 60)
    hours, minutes = divmod(minutes, 60)
    if hours:
        return f"{hours}h {minutes:02d}m"
    if minutes:
        return f"{minutes}m {secs:02d}s"
    return f"{secs}s"


def print_inventory_run_feedback(result, *, scoped_label: str | None = None) -> None:
    if result is None or not hasattr(result, "stats"):
        return
    sid = result.snapshot_id if getattr(result, "snapshot_id", None) is not None else "—"
    dur_tag = inventory_run_duration_label(getattr(result, "elapsed_seconds", None))
    timing = f" · {dur_tag}" if dur_tag else ""
    if scoped_label:
        body = (
            f"{inventory_cli_labels.FEEDBACK_ACTION} ({scoped_label}) · "
            f"{result.stats.total_packages} pkgs · snap {sid}{timing}"
        )
    else:
        body = (
            f"{inventory_cli_labels.FEEDBACK_ACTION} · "
            f"{result.stats.total_packages} pkgs · snap {sid}{timing}"
        )
    print(status_messages.status(body, level="success"))


__all__ = ["inventory_run_duration_label", "print_inventory_run_feedback"]
