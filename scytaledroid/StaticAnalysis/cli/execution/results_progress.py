"""Operator-facing persistence progress helpers for static runs."""

from __future__ import annotations

from collections.abc import Mapping, Sequence

from scytaledroid.Utils.LoggingUtils import logging_engine

from ..core.models import AppRunResult, RunParameters
from .operator_display_label import resolve_operator_app_label


def _persistence_progress_display_label(
    app_result: AppRunResult,
    *,
    v3_overrides: Mapping[str, str],
    fresh_display_names: Mapping[str, str],
) -> str | None:
    """Match per-app scan heartbeat / compact summary label chain (same ``resolve_operator_app_label``)."""

    base_out = app_result.base_artifact_outcome()
    meta: Mapping[str, object] = {}
    if base_out and isinstance(base_out.metadata, Mapping):
        meta = base_out.metadata
    return resolve_operator_app_label(
        app_result.package_name,
        meta,
        v3_overrides,
        fresh_display_names,
    )


def _emit_static_persistence_event(
    *,
    event: str,
    message: str,
    params: RunParameters,
    extra: Mapping[str, object] | None = None,
) -> None:
    payload = {
        "event": event,
        "session_stamp": params.session_stamp,
        "run_id": params.session_stamp,
        "execution_id": getattr(params, "execution_id", None),
        "scope_label": params.scope_label,
        "scope": params.scope,
        "profile": params.profile_label,
    }
    if extra:
        payload.update({key: value for key, value in extra.items() if value is not None})
    logging_engine.get_static_logger().info(
        message,
        extra=logging_engine.ensure_trace(payload),
    )


def _format_persistence_progress_text(
    *,
    index: int,
    total_results: int,
    package_name: str,
    app_label: str | None,
    elapsed_text: str,
    eta_text: str,
    persistence_error_count: int,
    include_phase_banner: bool = True,
) -> str:
    current = app_label or package_name
    lines: list[str] = []
    if include_phase_banner:
        lines.extend(
            [
                "DB persistence phase (scan finished; writing DB/evidence rows per package)",
                "-" * 60,
            ]
        )
    lines.append(f"Writing now: {current}")
    if package_name and package_name.strip() != current.strip():
        lines.append(f"Package: {package_name}")
    eta_raw = str(eta_text or "").strip()
    if eta_raw in {"", "--"}:
        eta_disp = "not available yet"
    else:
        eta_disp = f"~{eta_raw}" if not eta_raw.startswith("~") else eta_raw
    pct = ""
    if total_results > 0:
        pct = f" ({int(round((index / total_results) * 100))}%)"
    lines.extend(
        [
            f"Package write progress: {index} / {total_results}{pct}",
            f"Elapsed: {elapsed_text}",
            f"ETA: {eta_disp} (from recent write rate; stabilizes mid-run)",
            f"Persistence errors: {persistence_error_count}"
            + (
                " (none - DB write phase healthy so far)"
                if persistence_error_count == 0
                else " (see prior lines / persistence audit)"
            ),
        ]
    )
    return "\n".join(lines)


def _render_compact_persistence_summary(
    *,
    params: RunParameters,
    total_results: int,
    normalized_findings_total: int,
    string_samples_persisted_total: int,
    baseline_written_count: int,
    plan_written_count: int,
    report_reference_count: int,
    persistence_errors: Sequence[str],
    canonical_failures: Sequence[str],
    compat_export_errors: Sequence[str],
    run_status: str,
) -> None:
    print()
    print("Persistence summary")
    print("-------------------")
    print(f"Session : {params.session_stamp or params.session_label or 'unspecified'}")
    print(f"Apps    : {total_results}")
    print(f"Findings: {normalized_findings_total}")
    print(f"Strings : {string_samples_persisted_total}")
    print(
        "Artifacts: "
        f"baseline={baseline_written_count} "
        f"plan={plan_written_count} "
        f"report={report_reference_count}"
    )
    persist_err_ct = len(list(dict.fromkeys(str(x) for x in persistence_errors)))
    canon_err_ct = len(list(dict.fromkeys(str(x) for x in canonical_failures if x)))
    compat_err_ct = len(list(dict.fromkeys(str(x) for x in compat_export_errors if x)))
    print(

            "Status  : "
            f"{run_status} | persistence_errors={persist_err_ct} | "
            f"canonical_failures={canon_err_ct} | compat_export_errors={compat_err_ct}"

    )
    print("Details : Database tools / Web view for full diagnostics")
