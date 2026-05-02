"""Parse/skip rollup helpers shared with scan report aggregation."""

from __future__ import annotations

from collections.abc import Iterable, Mapping

from ...core.models import AppRunResult


def merge_skipped_detectors(skip_rows: Iterable[Mapping[str, object]]) -> list[dict[str, object]]:
    """Deduplicate skipped-detector rows while preserving detector/section/reason."""
    merged: list[dict[str, object]] = []
    seen: set[tuple[str, str, str]] = set()
    for row in skip_rows:
        if not isinstance(row, Mapping):
            continue
        det = str(row.get("detector") or "").strip()
        sec = str(row.get("section") or "").strip()
        reason = str(row.get("reason") or "").strip()
        key = (det, sec, reason)
        if key in seen:
            continue
        seen.add(key)
        merged.append(
            {
                "detector": det or "?",
                "section": sec,
                "reason": reason or "unspecified",
            }
        )
    return merged


def rollup_parse_fallback_signals(app_result: AppRunResult) -> dict[str, int]:
    resource_fallback_art = 0
    bounds_warn_art = 0
    label_or_resource_parse_signals = 0
    for artifact in getattr(app_result, "artifacts", []) or []:
        report = getattr(artifact, "report", None)
        meta = getattr(report, "metadata", None)
        if not isinstance(meta, Mapping):
            continue
        lf = str(meta.get("label_fallback") or "").strip().lower()
        lbl_signal = lf in {"aapt2", "aapt2-localized"} or bool(meta.get("parse_error_resources"))

        fb = meta.get("resource_fallback")
        if isinstance(fb, Mapping) and bool(fb.get("fallback_used")):
            resource_fallback_art += 1
        rbw = meta.get("resource_bounds_warnings")
        if isinstance(rbw, list) and rbw:
            bounds_warn_art += 1

        if lbl_signal:
            label_or_resource_parse_signals += 1

    parse_fallback_events = resource_fallback_art + bounds_warn_art + label_or_resource_parse_signals
    return {
        "resource_fallback_used_artifacts": resource_fallback_art,
        "resource_bounds_warning_artifacts": bounds_warn_art,
        "label_parse_signal_artifacts": label_or_resource_parse_signals,
        "parse_fallback_events_est": parse_fallback_events,
    }
