"""Network signal quality evaluation helpers."""

from __future__ import annotations


def evaluate_network_signal_quality(
    *,
    netstats_rows: int,
    netstats_missing_rows: int,
    sum_bytes_in: int | None,
    sum_bytes_out: int | None,
    pcap_present: bool = False,
    pcap_bytes: int | None = None,
) -> str:
    total_bytes = (sum_bytes_in or 0) + (sum_bytes_out or 0)
    if netstats_rows > 0:
        if total_bytes == 0:
            return "netstats_zero_bytes"
        return "netstats_ok"
    if netstats_missing_rows > 0:
        return "netstats_missing"
    if pcap_present or (pcap_bytes or 0) > 0:
        return "pcap_only"
    return "no_network_signal"


__all__ = ["evaluate_network_signal_quality"]
