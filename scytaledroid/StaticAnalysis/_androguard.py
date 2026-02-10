"""Compatibility helpers for importing androguard primitives."""

from __future__ import annotations

import io
import os
import sys
import tempfile
from collections.abc import Mapping, Sequence
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path

from androguard.core.apk import APK, FileNotPresent


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


def open_apk_safely(apk_path: str | Path) -> tuple[APK, list[str]]:
    """Open APK while capturing resource parser warnings."""
    buffer = io.StringIO()
    with redirect_stdout(buffer), redirect_stderr(buffer):
        apk, fd_output = _run_with_fd_capture(lambda: APK(str(apk_path)))
    captured = buffer.getvalue() + fd_output
    warnings = _extract_bounds_warnings(captured)
    return apk, warnings


def merge_bounds_warnings(
    metadata: Mapping[str, object],
    warnings: Sequence[str],
) -> None:
    """Append bounds warnings into report metadata (best effort)."""
    if not warnings or not isinstance(metadata, dict):
        return
    existing = metadata.get("resource_bounds_warnings")
    if isinstance(existing, list):
        target = existing
    else:
        target = []
        metadata["resource_bounds_warnings"] = target
    for line in warnings:
        if isinstance(line, str) and line not in target:
            target.append(line)


__all__ = ["APK", "FileNotPresent", "open_apk_safely", "merge_bounds_warnings"]
