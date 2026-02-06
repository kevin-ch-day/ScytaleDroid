"""Output helpers for scan execution."""

from __future__ import annotations

from collections.abc import Mapping, Sequence

from scytaledroid.Utils.System import output_prefs

from scytaledroid.Utils.DisplayUtils import status_messages

from ...core.detector_runner import PIPELINE_STAGES
from ..core.models import RunParameters
from .scan_progress_display import _format_elapsed


def render_app_start(
    *,
    title: str | None,
    package_name: str,
    profile_label: str,
) -> None:
    prefs = output_prefs.get()
    if prefs.quiet and prefs.batch:
        return
    if not (title or package_name):
        return
    print()
    display = title or package_name
    if title and package_name and title != package_name:
        display = f"{title} ({package_name})"
    print(f"Scanning App: {display}")
    print(f"Checks: {len(PIPELINE_STAGES)} stages · Profile: {profile_label}")


def render_resource_warnings(lines: Sequence[str]) -> None:
    if not lines:
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
) -> str:
    prefs = output_prefs.get()
    if prefs.quiet and prefs.batch:
        return _format_elapsed(elapsed_seconds or 0.0)
    elapsed = _format_elapsed(elapsed_seconds or 0.0)
    if not isinstance(report_metadata, Mapping):
        return elapsed
    summary = report_metadata.get("pipeline_summary")
    if not isinstance(summary, Mapping):
        return elapsed
    total = summary.get("detector_total")
    executed = summary.get("detector_executed")
    skipped = summary.get("detector_skipped")
    duration = summary.get("total_duration_sec")
    status_counts = summary.get("status_counts") if isinstance(summary.get("status_counts"), Mapping) else {}
    fail_count = int(status_counts.get("FAIL", 0) or 0)
    warn_count = int(status_counts.get("WARN", 0) or 0)
    ok_count = int(status_counts.get("OK", 0) or 0)
    info_count = int(status_counts.get("INFO", 0) or 0)
    error_count = int(summary.get("error_count", 0) or 0)
    skipped_count = int(skipped or 0)
    status_line = "Checks complete"
    if executed is not None and total is not None:
        status_line += f": {executed}/{total} executed"
    status_line += f" · ok={ok_count} warn={warn_count} policy_fail={fail_count}"
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
    if fail_count and isinstance(policy_failures, Sequence) and policy_failures:
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

    severity = summary.get("severity_counts") if isinstance(summary.get("severity_counts"), Mapping) else {}
    if severity:
        p0 = int(severity.get("P0", 0) or 0)
        p1 = int(severity.get("P1", 0) or 0)
        p2 = int(severity.get("P2", 0) or 0)
        note = int(severity.get("NOTE", 0) or 0)
        print(f"Findings: P0={p0} P1={p1} P2={p2} Note={note}")

    slowest = summary.get("slowest_detectors")
    if isinstance(slowest, Sequence) and slowest:
        slow_parts = []
        for entry in slowest[:3]:
            if not isinstance(entry, Mapping):
                continue
            det = entry.get("detector") or entry.get("section")
            dur = entry.get("duration_sec")
            if det and isinstance(dur, (int, float)):
                slow_parts.append(f"{det} {dur:.2f}s")
        if slow_parts:
            print("Slowest: " + "; ".join(slow_parts))
    return elapsed


__all__ = [
    "render_app_completion",
    "render_app_start",
    "render_resource_warnings",
]
