"""Per-app execution signal summaries (reasons for non-complete status)."""

from __future__ import annotations

from collections.abc import Mapping, Sequence

from ...core.models import AppRunResult


def string_summary_signals(
    base_string_data: Mapping[str, object] | None,
    *,
    discovered_artifacts: int,
) -> dict[str, object]:
    """Describe post-run analyse_string_payload rollup (base APK only when splits exist)."""
    scope = "base_apk_only"
    warning: str | None = None
    if discovered_artifacts > 1:
        warning = (
            "split_specific_strings_not_in_post_summary: post-run analyse_string_payload uses "
            "the base APK path only"
        )

    warnings_list: Sequence[object] = ()
    ok = True
    if isinstance(base_string_data, Mapping):
        raw_w = base_string_data.get("warnings")
        if isinstance(raw_w, list):
            warnings_list = tuple(raw_w)
            if raw_w:
                ok = False
    string_summary_status = "ok" if ok and not warnings_list else "warnings"

    out: dict[str, object] = {
        "string_summary_scope": scope,
        "string_summary_status": string_summary_status,
        "discovered_artifacts_for_note": discovered_artifacts,
    }
    if warning:
        out["string_summary_warning"] = warning
    if warnings_list:
        out["string_summary_messages"] = [str(item) for item in warnings_list if item][:20]
    return out


def summarize_execution_signals_for_app(
    app: AppRunResult,
    *,
    persistence_enabled: bool,
    persist_attempted: bool,
) -> dict[str, object]:
    """Structured reasons why an app is not *strict complete* (mirrors ``compute_app_final_status``)."""

    from ..scan_report import _summarize_app_pipeline

    disc = int(getattr(app, "discovered_artifacts", 0) or 0)
    success_n = len(getattr(app, "artifacts", []) or ())
    failed_n = int(getattr(app, "failed_artifacts", 0) or 0)
    summary = _summarize_app_pipeline(app)

    errs = int(summary.get("error_count", 0) or 0)
    fails = int(summary.get("fail_count", 0) or 0)
    warns = int(summary.get("warn_count", 0) or 0)
    parse_use = int(summary.get("parse_fallback_events_est", 0) or 0)

    str_sig = string_summary_signals(
        getattr(app, "base_string_data", None),
        discovered_artifacts=disc,
    )
    str_status = str(str_sig.get("string_summary_status") or "ok")

    persisted_db_issue = False
    if persistence_enabled and persist_attempted:
        persisted_db_issue = bool(
            getattr(app, "persistence_failure_stage", None) or getattr(app, "persistence_exception_class", None)
        )

    drivers: list[str] = []
    if failed_n > 0:
        drivers.append(f"artifact_scan_failures={failed_n}")
    if disc > 0 and success_n < disc:
        drivers.append(f"artifacts_ok_below_expected ({success_n}/{disc})")
    if errs > 0:
        drivers.append(f"detector_errors={errs}")
    if fails > 0:
        drivers.append(f"detector_failures={fails}")
    if warns > 0:
        drivers.append(f"detector_warnings={warns}")
    if parse_use > 0:
        drivers.append(f"parse_fallback_events≈{parse_use}")
    if str_status != "ok":
        drivers.append(f"string_summary_status={str_status}")
    if persisted_db_issue:
        drivers.append("db_persistence_issue")

    return {
        "drivers": drivers,
        "counts": {
            "detector_warnings": warns,
            "detector_failures": fails,
            "detector_errors": errs,
            "parse_fallback_events_est": parse_use,
            "artifacts_discovered": disc,
            "artifacts_report_ok": success_n,
            "artifacts_failed_scan": failed_n,
            "string_summary_status": str_status,
            "persistence_db_issue": persisted_db_issue,
        },
    }
