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
    return {
        "count_values": counts,
        "lines": lines,
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
    "_extract_bounds_warnings",
    "_run_with_fd_capture",
    "_summarize_bounds_warnings",
]
