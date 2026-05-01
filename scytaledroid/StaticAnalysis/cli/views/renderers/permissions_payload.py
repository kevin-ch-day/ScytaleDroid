"""Permission payload helpers for static analysis rendering."""

from __future__ import annotations

from collections.abc import Mapping

from scytaledroid.StaticAnalysis.core import StaticAnalysisReport


def permission_payload(report: StaticAnalysisReport) -> Mapping[str, object]:
    declared = sorted(set(report.permissions.declared))
    dangerous = sorted(set(report.permissions.dangerous))
    custom = sorted(set(report.permissions.custom))
    signature = sorted(set(declared) - set(dangerous) - set(custom))
    counts = {
        "dangerous": len(dangerous),
        "custom": len(custom),
        "signature": len(signature),
    }
    return {
        "declared": declared,
        "dangerous": dangerous,
        "custom": custom,
        "signature": signature,
        "counts": counts,
    }