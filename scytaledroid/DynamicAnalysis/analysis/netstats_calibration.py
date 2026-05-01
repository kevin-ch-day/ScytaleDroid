"""Netstats calibration utilities against PCAP bins."""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass


@dataclass(frozen=True)
class CalibrationResult:
    status: str
    alignment_score: float
    reasons: list[str]


def calibrate_netstats(
    *,
    pcap_bins: Iterable[int],
    netstats_bins: Iterable[int],
    tolerance_ratio: float = 0.3,
) -> CalibrationResult:
    pcap_list = list(pcap_bins)
    netstats_list = list(netstats_bins)
    if not pcap_list or not netstats_list:
        return CalibrationResult(status="invalid", alignment_score=0.0, reasons=["missing_bins"])
    total_pcap = sum(pcap_list)
    total_net = sum(netstats_list)
    if total_pcap == 0 or total_net == 0:
        return CalibrationResult(status="invalid", alignment_score=0.0, reasons=["zero_totals"])
    ratio = abs(total_pcap - total_net) / max(total_pcap, total_net)
    alignment = max(0.0, 1.0 - ratio)
    if ratio > tolerance_ratio:
        return CalibrationResult(status="invalid", alignment_score=alignment, reasons=["ratio_mismatch"])
    return CalibrationResult(status="valid", alignment_score=alignment, reasons=[])


__all__ = ["calibrate_netstats", "CalibrationResult"]
