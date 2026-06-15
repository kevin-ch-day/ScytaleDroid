"""Output helpers for scan execution."""

from __future__ import annotations

from collections.abc import Mapping, Sequence

from scytaledroid.Utils.DisplayUtils import colors, status_messages

from ...core.detector_runner import PIPELINE_STAGES
from ..core.models import RunParameters
from ..core.run_context import StaticRunContext
from .cohort_scan_notes import suppress_per_app_cohort_echoes
from .scan_progress_display import _format_elapsed

# One combined split-heavy brief per execute_scan (reset from scan_flow).
_SPLIT_HEAVY_BRIEF_EMITTED: bool = False


def reset_split_heavy_session_notice() -> None:
    """Reset the once-per-run split-heavy operator notice (call from execute_scan start)."""

    global _SPLIT_HEAVY_BRIEF_EMITTED
    _SPLIT_HEAVY_BRIEF_EMITTED = False


def is_compact_card_mode(params: RunParameters) -> bool:
    """Compact cards are used for multi-app scopes in non-verbose mode."""
    return bool(params.scope in {"all", "profile"} and not params.verbose_output)


def _is_validation_scope(params: RunParameters) -> bool:
    label = str(getattr(params, "scope_label", "") or "").strip().lower()
    return label.startswith("smoke batch") or label.startswith("persistence test")


def show_copy_markers(params: RunParameters) -> bool:
    """Optional extra copy/paste markers for compact runs.

    Default is off because compact mode already emits one app-completion line,
    and the extra marker line doubles output volume during large batch scans.
    """

    import os

    value = os.getenv("SCYTALEDROID_STATIC_SHOW_COPY_MARKERS")
    if value is None:
        return False
    return value.strip().lower() in {"1", "true", "yes", "on"}


def _slow_detector_parts(slowest: object, *, limit: int) -> list[str]:
    parts: list[str] = []
    seen: set[str] = set()
    if not isinstance(slowest, Sequence):
        return parts
    for entry in slowest:
        if not isinstance(entry, Mapping):
            continue
        det = str(entry.get("detector") or entry.get("section") or "").strip()
        dur = entry.get("duration_sec")
        if not det or det in seen or not isinstance(dur, (int, float)):
            continue
        seen.add(det)
        parts.append(f"{det} {dur:.2f}s")
        if len(parts) >= max(1, limit):
            break
    return parts


def _max_slow_detector_duration(slowest: object) -> float:
    max_duration = 0.0
    if not isinstance(slowest, Sequence):
        return max_duration
    for entry in slowest:
        if not isinstance(entry, Mapping):
            continue
        dur = entry.get("duration_sec")
        if isinstance(dur, (int, float)):
            max_duration = max(max_duration, float(dur))
    return max_duration


def _error_detector_parts(payload: object, *, limit: int) -> list[str]:
    parts: list[str] = []
    seen: set[str] = set()
    if not isinstance(payload, Sequence):
        return parts
    for entry in payload:
        if not isinstance(entry, Mapping):
            continue
        det = str(entry.get("detector") or entry.get("section") or "").strip()
        if not det or det in seen:
            continue
        seen.add(det)
        reason = None
        for key in ("reason", "error", "message", "exception", "detail"):
            candidate = entry.get(key)
            if isinstance(candidate, str) and candidate.strip():
                reason = candidate.strip()
                break
        if reason:
            reason = " ".join(reason.split())
            if len(reason) > 90:
                reason = reason[:87].rstrip() + "..."
            parts.append(f"{det}: {reason}")
        else:
            parts.append(f"{det}: <no reason>")
        if len(parts) >= max(1, int(limit)):
            break
    return parts


def _policy_finding_gate_counts(app_summary: Mapping[str, object] | None) -> tuple[int, int]:
    """Return (policy_gate_failures, finding_gate_failures) with legacy ``fail_count`` fallback."""

    if not isinstance(app_summary, Mapping):
        return 0, 0
    pol = int(app_summary.get("policy_fail_count", 0) or 0)
    fnd = int(app_summary.get("finding_fail_count", 0) or 0)
    legacy = int(app_summary.get("fail_count", 0) or 0)
    if pol == 0 and fnd == 0 and legacy > 0:
        return legacy, 0
    return pol, fnd


def format_compact_completion_line(
    *,
    app_index: int,
    app_total: int,
    app_title: str | None,
    package_name: str | None,
    artifact_count: int,
    elapsed_seconds: float,
    app_summary: Mapping[str, object] | None,
) -> str:
    label = (app_title or package_name or "").strip() or str(package_name or "<unknown>")
    warn = int(app_summary.get("warn_count", 0) or 0) if isinstance(app_summary, Mapping) else 0
    pol, fnd = _policy_finding_gate_counts(app_summary)
    severity_counts = app_summary.get("severity_counts") if isinstance(app_summary, Mapping) else None
    if isinstance(severity_counts, Mapping):
        high = int(app_summary.get("high_count", severity_counts.get("P1", 0)) or 0)
        med = int(app_summary.get("medium_count", severity_counts.get("P2", 0)) or 0)
    else:
        high = int(app_summary.get("high_count", 0) or 0) if isinstance(app_summary, Mapping) else 0
        med = int(app_summary.get("medium_count", 0) or 0) if isinstance(app_summary, Mapping) else 0
    err = int(app_summary.get("error_count", 0) or 0) if isinstance(app_summary, Mapping) else 0
    parts = [
        f"[{app_index}/{app_total}] {label}",
        f"{artifact_count} APK{'s' if artifact_count != 1 else ''}",
        _format_elapsed(elapsed_seconds or 0.0),
        f"detector_warnings={warn}",
        f"policy_gate_failures={pol}",
        f"finding_gate_failures={fnd}",
        f"gate_failures_total={pol + fnd}",
        f"execution_errors={err}",
        f"high={high}",
        f"medium={med}",
    ]
    return " | ".join(parts)


def format_recent_completion_line(
    *,
    app_index: int,
    app_title: str | None,
    package_name: str | None,
    elapsed_seconds: float,
    app_summary: Mapping[str, object] | None,
) -> str:
    label = (app_title or package_name or "").strip() or str(package_name or "<unknown>")
    warn = int(app_summary.get("warn_count", 0) or 0) if isinstance(app_summary, Mapping) else 0
    pol, fnd = _policy_finding_gate_counts(app_summary)
    severity_counts = app_summary.get("severity_counts") if isinstance(app_summary, Mapping) else None
    high = med = 0
    if isinstance(severity_counts, Mapping):
        high = int(app_summary.get("high_count", severity_counts.get("P1", 0)) or 0)
        med = int(app_summary.get("medium_count", severity_counts.get("P2", 0)) or 0)
    else:
        high = int(app_summary.get("high_count", 0) or 0) if isinstance(app_summary, Mapping) else 0
        med = int(app_summary.get("medium_count", 0) or 0) if isinstance(app_summary, Mapping) else 0
    return (
        f"#{app_index} {label} {_format_elapsed(elapsed_seconds or 0.0)} "
        f"warnings={warn} policy_gates={pol} finding_gates={fnd} gates_total={pol + fnd} high={high} medium={med}"
    )


def render_app_start(
    *,
    title: str | None,
    package_name: str,
    profile_label: str,
    run_ctx: StaticRunContext,
    card_mode: bool = False,
) -> None:
    if run_ctx.quiet and run_ctx.batch:
        return
    if not (title or package_name):
        return
    if card_mode:
        return
    print()
    display = title or package_name
    if title and package_name and title != package_name:
        display = f"{title} ({package_name})"
    print(f"Scanning App: {display}")
    print(
        f"Detector pipeline: {len(PIPELINE_STAGES)} ordered stages "
        f"· analyzer profile={profile_label}"
    )


def render_resource_warnings(lines: Sequence[str], *, run_ctx: StaticRunContext) -> None:
    if not lines:
        return
    if run_ctx.quiet and run_ctx.batch:
        return
    print()
    for line in lines:
        print(status_messages.status(line, level="warn"))
    print()


def render_app_completion(
    *,
    artifact_count: int,
    elapsed_seconds: float,
    report_metadata: Mapping[str, object] | None,
    params: RunParameters,
    run_ctx: StaticRunContext,
    app_index: int | None = None,
    app_total: int | None = None,
    app_title: str | None = None,
    package_name: str | None = None,
    app_summary: Mapping[str, object] | None = None,
) -> str:
    if run_ctx.quiet and run_ctx.batch:
        return _format_elapsed(elapsed_seconds or 0.0)
    elapsed = _format_elapsed(elapsed_seconds or 0.0)
    summary: Mapping[str, object] | None = None
    if isinstance(app_summary, Mapping):
        summary = app_summary
    elif isinstance(report_metadata, Mapping):
        candidate = report_metadata.get("pipeline_summary")
        if isinstance(candidate, Mapping):
            summary = candidate
    if not isinstance(summary, Mapping):
        return elapsed
    total = summary.get("detector_total")
    executed = summary.get("detector_executed")
    skipped = summary.get("detector_skipped")
    duration = summary.get("total_duration_sec")
    status_counts = summary.get("status_counts") if isinstance(summary.get("status_counts"), Mapping) else {}
    policy_fail_count = int(summary.get("policy_fail_count", 0) or 0)
    finding_fail_count = int(summary.get("finding_fail_count", 0) or 0)
    warn_count = int(status_counts.get("WARN", 0) or 0)
    ok_count = int(status_counts.get("OK", 0) or 0)
    info_count = int(status_counts.get("INFO", 0) or 0)
    error_count = int(summary.get("error_count", 0) or 0)
    skipped_count = int(skipped or 0)
    fail_count = finding_fail_count + policy_fail_count
    card_mode = is_compact_card_mode(params)

    if card_mode:
        palette = colors.get_palette()
        large_batch_mode = bool((app_total or 0) >= 50 or (_is_validation_scope(params) and (app_total or 0) >= 10))
        # Multi-app profile/all runs (2+) use the same dense card as large cohorts to avoid
        # repeating pipeline/skipped-placeholder/string-rollup blocks per app.
        compact_completion = bool(large_batch_mode or (app_total or 0) >= 2)
        very_large_batch_mode = bool((app_total or 0) >= 100)
        label = (app_title or package_name or "").strip() or str(package_name or "<unknown>")
        pkg = str(package_name or "").strip()
        header_line = ""
        if app_index is not None and app_total is not None:
            if pkg and label and label != pkg:
                header_line = f"[{app_index}/{app_total}] {label}  ({pkg})"
            elif pkg:
                header_line = f"[{app_index}/{app_total}] {pkg}"
            else:
                header_line = f"[{app_index}/{app_total}] {label}"
        else:
            if pkg and label and label != pkg:
                header_line = f"{label}  ({pkg})"
            elif pkg:
                header_line = pkg
            else:
                header_line = label
        p0 = int((summary.get("severity_counts") or {}).get("P0", 0) if isinstance(summary.get("severity_counts"), Mapping) else 0)
        p1 = int((summary.get("severity_counts") or {}).get("P1", 0) if isinstance(summary.get("severity_counts"), Mapping) else 0)
        p2 = int((summary.get("severity_counts") or {}).get("P2", 0) if isinstance(summary.get("severity_counts"), Mapping) else 0)
        # Legacy detector outputs map to C/H/M in compact cards.
        c_count, h_count, m_count = p0, p1, p2
        l_count = int((summary.get("severity_counts") or {}).get("P3", 0) if isinstance(summary.get("severity_counts"), Mapping) else 0)
        i_count = int((summary.get("severity_counts") or {}).get("P4", 0) if isinstance(summary.get("severity_counts"), Mapping) else 0)
        note = int((summary.get("severity_counts") or {}).get("NOTE", 0) if isinstance(summary.get("severity_counts"), Mapping) else 0)
        if params.verbose_output:
            findings_text = (
                "Findings (severity buckets): "
                f"critical/P0={c_count} high/P1={h_count} medium/P2={m_count} "
                f"low/P3={l_count} informational/P4={i_count} notes={note}"
            )
        else:
            findings_text = (
                f"Findings: C:{c_count} H:{h_count} M:{m_count} "
                f"L:{l_count} I:{i_count} Note:{note}"
            )
        detail_needed = bool(
            error_count > 0
            or fail_count >= 3
            or c_count > 0
            or (elapsed_seconds or 0.0) >= 90.0
            or artifact_count > 20
        )

        def _emit_large_artifact_split_notice() -> None:
            global _SPLIT_HEAVY_BRIEF_EMITTED
            if artifact_count < 15 or _SPLIT_HEAVY_BRIEF_EMITTED:
                return
            _SPLIT_HEAVY_BRIEF_EMITTED = True
            friendly = (label or pkg or "app").strip()
            print()
            print(
                status_messages.status(
                    f"Split-heavy app: {friendly} — {artifact_count} APK artifacts",
                    level="warn",
                )
            )
            if params.verbose_output:
                print(
                    status_messages.status(
                        "Impact: detectors scan base and split APK rows when split scan is on; "
                        "post-run string payloads are merged across scanned APK artifacts.",
                        level="info",
                        show_icon=False,
                        show_prefix=False,
                    )
                )
            else:
                print(
                    status_messages.status(
                        "Split scan: each APK artifact is scanned; post-run string payloads are merged per app.",
                        level="info",
                        show_icon=False,
                        show_prefix=False,
                    )
                )

        if very_large_batch_mode:
            _emit_large_artifact_split_notice()
            return elapsed
        if compact_completion:
            artifact_label = f"{artifact_count} APK{'s' if artifact_count != 1 else ''}"
            header_only = header_line
            if pkg and label and label != pkg:
                if app_index is not None and app_total is not None:
                    header_only = f"[{app_index}/{app_total}] {label}"
                else:
                    header_only = label
            print(colors.apply(header_only, palette.banner_primary, bold=True))
            _emit_large_artifact_split_notice()
            if pkg and label != pkg:
                print(
                    status_messages.status(
                        f"Package: {pkg}",
                        level="info",
                        show_icon=False,
                        show_prefix=False,
                    )
                )
            compact_parts = [
                artifact_label,
                elapsed,
                f"detector_warnings={warn_count}",
                f"policy_gate_failures={policy_fail_count}",
                f"finding_gate_failures={finding_fail_count}",
                f"gate_failures_total={fail_count}",
                f"execution_errors={error_count}",
            ]
            if h_count or m_count:
                compact_parts.append(f"high={h_count}")
                compact_parts.append(f"medium={m_count}")
            final_row = summary.get("final_app_status") if isinstance(summary.get("final_app_status"), str) else ""
            if final_row.strip():
                compact_parts.append(f"status={final_row.strip()}")
            print(" | ".join(compact_parts))
            print()
        if not compact_completion:
            print(colors.apply(header_line, palette.banner_primary, bold=True))
            _emit_large_artifact_split_notice()
            # Avoid redundant "Package:" line when the header already includes it.
            show_pkg = bool(pkg)
            if show_pkg and pkg:
                if f"({pkg})" in header_line or header_line.strip().endswith(f"] {pkg}"):
                    show_pkg = False
            if show_pkg and pkg:
                print(
                    status_messages.status(
                        f"Package: {pkg}",
                        level="info",
                        show_icon=False,
                        show_prefix=False,
                    )
                )

            print(
                status_messages.status(
                    f"Artifacts: {artifact_count}   Time: {elapsed}",
                    level="info",
                    show_icon=False,
                    show_prefix=False,
                )
            )
            print(
                status_messages.status(
                    (
                        f"Pipeline stages: ok={ok_count} detector_warnings={warn_count} "
                        f"policy_gate_failures={policy_fail_count} "
                        f"finding_gate_failures={finding_fail_count} "
                        f"gate_failures_total={fail_count} execution_errors={error_count} "
                        f"detector_stages_skipped={skipped_count}"
                    ),
                    level="info",
                    show_icon=False,
                    show_prefix=False,
                )
            )
            final_token = summary.get("final_app_status") if isinstance(summary.get("final_app_status"), str) else ""
            if final_token.strip():
                print(
                    status_messages.status(
                        f"Final app status: {final_token.strip()}",
                        level="info",
                        show_icon=False,
                        show_prefix=False,
                    )
                )
            skips_preview = summary.get("skipped_detectors")
            if suppress_per_app_cohort_echoes(params, app_total):
                skips_preview = None
            if isinstance(skips_preview, Sequence) and not isinstance(skips_preview, (str, bytes)):
                preview_lines = []
                for entry in skips_preview:
                    if not isinstance(entry, Mapping) or len(preview_lines) >= 4:
                        break
                    det = str(entry.get("detector") or entry.get("section") or "?").strip()
                    rs = str(entry.get("reason") or "").strip()
                    preview_lines.append(f"{det}: {rs}" if rs else det)
                if preview_lines:
                    print(
                        status_messages.status(
                            "Skipped detectors: " + " | ".join(preview_lines),
                            level="info",
                            show_icon=False,
                            show_prefix=False,
                        )
                    )
            if artifact_count > 1 and not suppress_per_app_cohort_echoes(params, app_total):
                print(
                    status_messages.status(
                        "String rollup note: this app has multiple APK artifacts; post-run string summary coverage is tracked in run_health.json.",
                        level="info",
                        show_icon=False,
                        show_prefix=False,
                    )
                )
            print(
                status_messages.status(
                    findings_text,
                    level="info",
                    show_icon=False,
                    show_prefix=False,
                )
            )

        slow_parts = _slow_detector_parts(summary.get("slowest_detectors"), limit=2)
        max_slow = _max_slow_detector_duration(summary.get("slowest_detectors"))
        show_slow_details = bool(
            slow_parts
            and (
                not compact_completion
                or params.verbose_output
                or max_slow >= 10.0
            )
        )
        if show_slow_details:
            print(colors.apply("Slow: ", palette.hint, bold=True) + "; ".join(slow_parts))

        if error_count > 0 or (not compact_completion and fail_count > 0) or (p0 > 0 and not compact_completion) or (compact_completion and detail_needed):
            failing: list[str] = []
            error_parts = _error_detector_parts(summary.get("error_detectors"), limit=3)
            for key in ("finding_fail_detectors", "policy_fail_detectors"):
                payload = summary.get(key)
                if not isinstance(payload, Sequence):
                    continue
                for entry in payload:
                    if not isinstance(entry, Mapping):
                        continue
                    det = str(entry.get("detector") or entry.get("section") or "").strip()
                    if det and det not in failing:
                        failing.append(det)
            if error_parts:
                print(
                    status_messages.status(
                        "Execution errors: " + ", ".join(error_parts),
                        level="warn",
                        show_icon=False,
                        show_prefix=False,
                    )
                )
            if failing and (not compact_completion or params.verbose_output):
                print(
                    status_messages.status(
                        "Policy/finding gate failures: " + ", ".join(failing[:4]),
                        level="warn",
                        show_icon=False,
                        show_prefix=False,
                    )
                )
        # Keep regular cards visually separated; compact multi-app cards stay dense.
        if not compact_completion:
            print()
        return elapsed

    status_line = "Pipeline stages"
    if executed is not None and total is not None:
        status_line += f": {executed}/{total} executed"
    status_line += f" · ok={ok_count} warn={warn_count} pol_gates={policy_fail_count} fnd_gates={finding_fail_count}"
    if error_count:
        status_line += f" err={error_count}"
    if info_count:
        status_line += f" info={info_count}"
    if skipped_count:
        status_line += f" skipped={skipped_count}"
    if duration is not None:
        status_line += f" · {duration:.1f}s"
    print(status_line)

    policy_failures = summary.get("policy_fail_detectors")
    if policy_fail_count and isinstance(policy_failures, Sequence) and policy_failures:
        def _policy_label(section: str) -> str:
            lookup = {
                "integrity": "Integrity identity",
                "manifest_hygiene": "Manifest baseline",
                "permissions": "Permissions profile",
                "ipc_components": "IPC components",
                "provider_acl": "Provider ACL",
                "network_surface": "Network surface",
                "react_native": "React Native",
                "domain_verification": "Domain verification",
                "secrets": "Secrets",
                "storage_backup": "Storage backup",
                "dfir_hints": "DFIR hints",
                "webview": "WebView",
                "crypto_hygiene": "Crypto hygiene",
                "dynamic_loading": "Dynamic loading",
                "file_io_sinks": "File I/O sinks",
                "interaction_risks": "Interaction risks",
                "sdk_inventory": "SDK inventory",
                "native_jni": "Native hardening",
                "obfuscation": "Obfuscation",
                "correlation_findings": "Correlation findings",
            }
            return lookup.get(section, section.replace("_", " ").title())

        print("Policy gates")
        for entry in policy_failures:
            if not isinstance(entry, Mapping):
                continue
            section = str(entry.get("section") or "unknown")
            detector = str(entry.get("detector") or "unknown")
            label = _policy_label(section)
            print(f"  FAIL: {label} ({section}/{detector})")

    error_detectors = summary.get("error_detectors")
    if params.verbose_output and isinstance(error_detectors, Sequence) and error_detectors:
        for entry in error_detectors:
            if not isinstance(entry, Mapping):
                continue
            det = entry.get("detector") or "unknown"
            reason = entry.get("reason") or "unspecified"
            print(status_messages.status(f"Detector error: {det} - {reason}", level="warn"))

    severity_counts = summary.get("severity_counts") if isinstance(summary.get("severity_counts"), Mapping) else {}
    if severity_counts:
        p0 = int(severity_counts.get("P0", 0) or 0)
        p1 = int(severity_counts.get("P1", 0) or 0)
        p2 = int(severity_counts.get("P2", 0) or 0)
        note = int(severity_counts.get("NOTE", 0) or 0)
        print(
            "Findings (severity buckets): "
            f"critical/P0={p0} high/P1={p1} medium/P2={p2} notes={note}"
        )

    slow_parts = _slow_detector_parts(summary.get("slowest_detectors"), limit=3)
    if slow_parts:
        print("Slowest: " + "; ".join(slow_parts))
    return elapsed


__all__ = [
    "format_compact_completion_line",
    "is_compact_card_mode",
    "reset_split_heavy_session_notice",
    "show_copy_markers",
    "render_app_completion",
    "render_app_start",
    "render_resource_warnings",
]
