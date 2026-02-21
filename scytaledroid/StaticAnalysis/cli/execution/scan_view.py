"""Output helpers for scan execution."""

from __future__ import annotations

from collections.abc import Mapping, Sequence

from scytaledroid.Utils.DisplayUtils import colors, status_messages

from ...core.detector_runner import PIPELINE_STAGES
from ..core.models import RunParameters
from ..core.run_context import StaticRunContext
from .scan_progress_display import _format_elapsed


def is_compact_card_mode(params: RunParameters) -> bool:
    """Compact cards are used for multi-app scopes in non-verbose mode."""
    return bool(params.scope in {"all", "profile"} and not params.verbose_output)


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
    print(f"Checks: {len(PIPELINE_STAGES)} stages · Profile: {profile_label}")


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
        large_batch_mode = bool((app_total or 0) >= 50)
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
        findings_text = (
            f"Findings: C:{c_count} H:{h_count} M:{m_count} "
            f"L:{l_count} I:{i_count} Note:{note}"
        )
        if large_batch_mode:
            compact_parts = [
                colors.apply(header_line, palette.banner_primary, bold=True),
                f"art={artifact_count}",
                f"time={elapsed}",
                f"ok={ok_count}",
                f"warn={warn_count}",
                f"fail={fail_count}",
                f"err={error_count}",
                f"H={h_count}",
                f"M={m_count}",
            ]
            print("  ".join(compact_parts))
        else:
            print(colors.apply(header_line, palette.banner_primary, bold=True))
            if pkg:
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
                        f"Checks: ok={ok_count} warn={warn_count} "
                        f"policy_fail={policy_fail_count} finding_fail={finding_fail_count} "
                        f"error={error_count} skipped={skipped_count}"
                    ),
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
        if slow_parts and (not large_batch_mode or fail_count > 0 or error_count > 0):
            print(colors.apply("Slow: ", palette.hint, bold=True) + "; ".join(slow_parts))

        outlier = artifact_count > 20
        if outlier:
            print("⚠ OUTLIER ARTIFACT COUNT")
            print(
                f"Artifacts: {artifact_count} (expected <= 20)   Time: {elapsed}   "
                "High split artifact cardinality; inspect selection manifest (press D for selection details)."
            )

        if error_count > 0 or fail_count > 0 or (p0 > 0 and not large_batch_mode):
            failing: list[str] = []
            error_only: list[str] = []
            payload = summary.get("error_detectors")
            if isinstance(payload, Sequence):
                for entry in payload:
                    if not isinstance(entry, Mapping):
                        continue
                    det = str(entry.get("detector") or entry.get("section") or "").strip()
                    if det and det not in error_only:
                        error_only.append(det)
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
            if error_only:
                print(
                    status_messages.status(
                        "Execution errors: " + ", ".join(error_only[:4]),
                        level="warn",
                        show_icon=False,
                        show_prefix=False,
                    )
                )
            if failing:
                print(
                    status_messages.status(
                        "Policy/finding fails: " + ", ".join(failing[:4]),
                        level="warn",
                        show_icon=False,
                        show_prefix=False,
                    )
                )
        # Keep regular cards visually separated; large batch mode stays dense.
        if not large_batch_mode:
            print()
        return elapsed

    status_line = "Checks complete"
    if executed is not None and total is not None:
        status_line += f": {executed}/{total} executed"
    status_line += f" · ok={ok_count} warn={warn_count} policy_fail={policy_fail_count}"
    if finding_fail_count:
        status_line += f" fail={finding_fail_count}"
    if error_count:
        status_line += f" error={error_count}"
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
            print(status_messages.status(f"Detector error: {det} — {reason}", level="warn"))

    severity_counts = summary.get("severity_counts") if isinstance(summary.get("severity_counts"), Mapping) else {}
    if severity_counts:
        p0 = int(severity_counts.get("P0", 0) or 0)
        p1 = int(severity_counts.get("P1", 0) or 0)
        p2 = int(severity_counts.get("P2", 0) or 0)
        note = int(severity_counts.get("NOTE", 0) or 0)
        print(f"Findings: P0={p0} P1={p1} P2={p2} Note={note}")

    slow_parts = _slow_detector_parts(summary.get("slowest_detectors"), limit=3)
    if slow_parts:
        print("Slowest: " + "; ".join(slow_parts))
    return elapsed


__all__ = [
    "is_compact_card_mode",
    "render_app_completion",
    "render_app_start",
    "render_resource_warnings",
]
