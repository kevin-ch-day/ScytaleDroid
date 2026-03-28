"""Shared string-analysis payload helpers for static CLI execution flows."""

from __future__ import annotations

from collections.abc import Callable, Mapping

from scytaledroid.Utils.LoggingUtils import logging_engine

from ...engine.strings import analyse_strings as _default_analyse_strings
from ..core.models import RunParameters


def empty_string_analysis_payload(*, warning: str | None = None) -> Mapping[str, object]:
    warnings = [warning] if warning else []
    return {
        "counts": {},
        "samples": {},
        "selected_samples": {},
        "selection_params": {},
        "extra_counts": {},
        "regex_skipped": 0,
        "noise_counts": {},
        "aggregates": {},
        "structured": {},
        "warnings": warnings,
        "resource_strings_skipped": False,
        "options": {},
    }


def analyse_string_payload(
    apk_path: str,
    *,
    params: RunParameters,
    package_name: str,
    warning_sink: list[str] | None = None,
    analyse_fn: Callable[..., Mapping[str, object]] = _default_analyse_strings,
) -> Mapping[str, object]:
    try:
        return analyse_fn(
            apk_path,
            mode=params.strings_mode,
            min_entropy=params.string_min_entropy,
            max_samples=params.string_max_samples,
            cleartext_only=params.string_cleartext_only,
            include_https_risk=params.string_include_https_risk,
        )
    except Exception as exc:
        message = f"String analysis failed during finalization for {package_name}: {exc}"
        if warning_sink is not None:
            warning_sink.append(message)
        logging_engine.get_error_logger().exception(
            "String analysis failed during result finalization",
            extra=logging_engine.ensure_trace(
                {
                    "event": "static.strings.finalization_failed",
                    "package": package_name,
                    "apk_path": apk_path,
                    "session_stamp": params.session_stamp,
                    "error_class": exc.__class__.__name__,
                }
            ),
        )
        return empty_string_analysis_payload(
            warning=f"{exc.__class__.__name__}: {exc}"
        )


__all__ = ["analyse_string_payload", "empty_string_analysis_payload"]
