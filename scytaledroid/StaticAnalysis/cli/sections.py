"""Section rendering utilities for static-analysis CLI."""

from __future__ import annotations

from typing import List

SECTION_TITLES: tuple[str, ...] = (
    "Integrity & Identity",
    "Manifest Hygiene",
    "Permissions",
    "Network Surface & TLS",
    "Secrets & Credentials",
    "Storage & Backup",
    "WebView",
    "Cryptography",
    "Provider ACL",
    "SDK / Tracker Inventory",
    "Native / JNI",
    "Obfuscation / Anti-Analysis",
    "Findings (P0/P1)",
    "Summary",
)


def render_stub_sections() -> List[str]:
    """Return placeholder lines for every analysis section."""

    lines: List[str] = []
    for title in SECTION_TITLES:
        lines.append(title)
        lines.append("-" * len(title))
        lines.append("Status: [skipped]")
        lines.append("")
    if lines:
        lines.pop()  # drop trailing blank line
    return lines


__all__ = ["SECTION_TITLES", "render_stub_sections"]
