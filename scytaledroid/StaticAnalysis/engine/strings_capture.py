"""Capture and summarise parser warnings for string analysis."""

from __future__ import annotations

import os
import re
import sys
import tempfile


def _extract_bounds_warnings(text: str) -> list[str]:
    """Extract resource parsing warnings emitted by third-party parsers."""

    if not text:
        return []
    lines: list[str] = []
    for raw in text.replace("\r", "\n").split("\n"):
        candidate = raw.strip()
        if not candidate:
            continue
        lowered = candidate.lower()
        if "out of bound" in lowered or "complex entry" in lowered:
            lines.append(candidate)
    return lines


def _summarize_bounds_warnings(lines: list[str]) -> dict[str, object]:
    counts: list[int] = []
    for line in lines:
        match = re.search(r"Count:\s*(\d+)", line)
        if match:
            try:
                counts.append(int(match.group(1)))
            except ValueError:
                continue
    normalized = [line.strip().lower() for line in lines if isinstance(line, str) and line.strip()]
    only_complex_entry = bool(normalized) and all("complex entry" in line for line in normalized)
    single_warning = len(normalized) == 1
    max_count = max(counts) if counts else None
    if only_complex_entry and single_warning and max_count is not None and max_count <= 1024:
        severity = "minor"
        render_level = "info"
        warning_kind = "complex_entry_minor"
    elif only_complex_entry:
        severity = "warn"
        render_level = "warn"
        warning_kind = "complex_entry"
    else:
        severity = "warn"
        render_level = "warn"
        warning_kind = "mixed_or_large"
    return {
        "count_values": counts,
        "lines": lines,
        "severity": severity,
        "render_level": render_level,
        "warning_kind": warning_kind,
    }


def _classify_resource_parse_state(
    lines: list[str],
    *,
    resource_string_count: int | None = None,
    parse_error_resources: bool = False,
    resource_fallback_used: bool = False,
) -> dict[str, object]:
    """Classify whether resource parser warnings indicate a materially partial parse."""

    summary = _summarize_bounds_warnings(lines)
    severity = str(summary.get("severity") or "none")
    if not lines:
        return {
            "parse_state": "none",
            "parse_partial": False,
            "reparse_candidate": False,
        }
    if severity == "minor":
        return {
            "parse_state": "minor",
            "parse_partial": False,
            "reparse_candidate": False,
        }
    parse_partial = True
    reparse_candidate = bool(
        parse_error_resources
        or not resource_fallback_used
        or resource_string_count is None
        or resource_string_count <= 16
    )
    return {
        "parse_state": "partial",
        "parse_partial": parse_partial,
        "reparse_candidate": reparse_candidate,
    }


def _run_with_fd_capture(callable_obj):
    stdout_fd = os.dup(1)
    stderr_fd = os.dup(2)
    temp = tempfile.TemporaryFile(mode="w+b")
    try:
        sys.stdout.flush()
        sys.stderr.flush()
        os.dup2(temp.fileno(), 1)
        os.dup2(temp.fileno(), 2)
        result = callable_obj()
        sys.stdout.flush()
        sys.stderr.flush()
    finally:
        os.dup2(stdout_fd, 1)
        os.dup2(stderr_fd, 2)
        os.close(stdout_fd)
        os.close(stderr_fd)
    temp.seek(0)
    raw = temp.read()
    temp.close()
    return result, raw.decode("utf-8", errors="replace")


__all__ = [
    "_classify_resource_parse_state",
    "_extract_bounds_warnings",
    "_run_with_fd_capture",
    "_summarize_bounds_warnings",
]
