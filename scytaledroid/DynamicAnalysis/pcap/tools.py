"""Host tool discovery for PCAP post-analysis.

Dataset-tier runs require a complete host toolchain for reproducibility.
This module centralizes tool discovery so callers don't re-implement checks.
"""

from __future__ import annotations

import shutil
import subprocess


def find_tool(name: str) -> str | None:
    return shutil.which(name)


def tool_version_line(tool: str) -> str | None:
    path = find_tool(tool)
    if not path:
        return None
    try:
        completed = subprocess.run(
            [path, "--version"],
            check=False,
            capture_output=True,
            text=True,
        )
    except Exception:
        return None
    out = (completed.stdout or "").splitlines()
    if not out:
        return None
    return out[0].strip() or None


def collect_host_tools() -> dict[str, object]:
    """Return a small audit payload for the current host toolchain."""
    tools = {}
    for name in ("capinfos", "tshark"):
        tools[name] = {
            "path": find_tool(name),
            "version": tool_version_line(name),
        }
    return tools


def missing_required_tools(*, tier: str | None) -> list[str]:
    """Return missing tool names for the requested tier."""
    if not tier or str(tier).lower() != "dataset":
        return []
    required = ("capinfos", "tshark")
    missing = []
    for tool in required:
        if not find_tool(tool):
            missing.append(tool)
    return missing


__all__ = ["collect_host_tools", "find_tool", "missing_required_tools", "tool_version_line"]
