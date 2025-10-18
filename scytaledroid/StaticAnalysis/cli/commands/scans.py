"""Scan-oriented command definitions."""

from __future__ import annotations

from .models import Command

SCAN_COMMANDS: tuple[Command, ...] = (
    Command(
        id="1",
        title="Full static analysis (all detectors; writes to DB)",
        description="Run all detectors and persist summaries",
        kind="scan",
        profile="full",
    ),
    Command(
        id="2",
        title="Baseline static analysis (paper-aligned; writes to DB)",
        description="Faster path; key detectors only",
        kind="scan",
        profile="lightweight",
    ),
    Command(
        id="3",
        title="App Metadata (hashes, manifest flags)",
        description="No DB writes; summary only",
        kind="scan",
        profile="metadata",
    ),
    Command(
        id="4",
        title="Permission Analysis (writes to DB)",
        description="Persist detected permissions and audit",
        kind="scan",
        profile="permissions",
    ),
    Command(
        id="5",
        title="String analysis (DEX + resources; writes to DB)",
        description="Persist string summary and samples",
        kind="scan",
        profile="strings",
    ),
    Command(
        id="6",
        title="Split-APK composition (base + splits)",
        description="Analyze split grouping and consistency",
        kind="scan",
        profile="split",
    ),
    Command(
        id="7",
        title="WebView posture (read-only)",
        description="Check JS/mixed-content/JS bridge flags",
        kind="scan",
        profile="webview",
    ),
    Command(
        id="8",
        title="Network Security Config (read-only)",
        description="Parse NSC cleartext/pins/user certs",
        kind="scan",
        profile="nsc",
    ),
    Command(
        id="9",
        title="IPC & PendingIntent safety (read-only)",
        description="Exported receivers/permissions; PI flags",
        kind="scan",
        profile="ipc",
    ),
    Command(
        id="10",
        title="Crypto/TLS quick scan (read-only)",
        description="Weak hashes/TLS refs in strings",
        kind="scan",
        profile="crypto",
    ),
    Command(
        id="11",
        title="SDK fingerprints (read-only)",
        description="Known analytics/ads SDK presence",
        kind="scan",
        profile="sdk",
    ),
)

__all__ = ["SCAN_COMMANDS"]

