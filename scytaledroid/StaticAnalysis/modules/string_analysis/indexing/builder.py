"""High level orchestration for building string indexes."""

from __future__ import annotations

import io
import os
import re
import sys
import tempfile
from contextlib import redirect_stderr, redirect_stdout

from scytaledroid.StaticAnalysis._androguard import APK
from scytaledroid.Utils.LoggingUtils import logging_utils as log

from .models import IndexedString, StringIndex
from .sources import collect_file_strings


def _extract_bounds_warnings(text: str) -> list[str]:
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


def _parse_bounds_counts(lines: list[str]) -> list[int]:
    counts: list[int] = []
    for line in lines:
        match = re.search(r"Count:\s*(\d+)", line)
        if match:
            try:
                counts.append(int(match.group(1)))
            except ValueError:
                continue
    return counts


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


def build_string_index(apk: APK, *, include_resources: bool = True) -> StringIndex:
    """Extract strings from *apk* and return a searchable index."""

    buffer = io.StringIO()
    with redirect_stdout(buffer), redirect_stderr(buffer):
        collected, fd_output = _run_with_fd_capture(lambda: collect_file_strings(apk))
    captured = buffer.getvalue() + fd_output
    warnings = _extract_bounds_warnings(captured)
    if warnings:
        counts = _parse_bounds_counts(warnings)
        apk_path = getattr(apk, "filename", None)
        log.warning(
            "Resource table parsing emitted bounds warnings",
            category="static_analysis",
            extra={
                "event": "strings.resource_bounds_warning",
                "apk_path": apk_path,
                "warning_lines": warnings,
                "count_values": counts,
            },
        )

    if not include_resources:
        filtered = tuple(entry for entry in collected if entry.origin_type not in {"res"})
    else:
        filtered = collected

    return StringIndex(strings=filtered)


__all__ = ["build_string_index"]
