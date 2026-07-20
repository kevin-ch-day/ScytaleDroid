"""High level orchestration for building string indexes."""

from __future__ import annotations

import io
import os
import re
import sys
import tempfile
from collections.abc import Mapping
from contextlib import redirect_stderr, redirect_stdout

from scytaledroid.StaticAnalysis._androguard import APK
from scytaledroid.Utils.LoggingUtils import logging_utils as log

from .models import StringIndex
from .sources import (
    collect_aapt2_resource_strings,
    collect_file_strings,
    collect_resource_table_strings,
)

_BOUNDS_WARNING_SEEN: set[str] = set()


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


def build_string_index(
    apk: APK,
    *,
    include_resources: bool = True,
    is_split_member: bool = False,
    split_member_policy: str = "full",
    log_context: Mapping[str, object] | None = None,
) -> StringIndex:
    """Extract strings from *apk* and return a searchable index."""

    indexing_mode = "split_lightweight" if is_split_member and split_member_policy == "lightweight" else "full"
    include_resource_table = include_resources and indexing_mode == "full"

    def _collect() -> tuple:
        file_entries = collect_file_strings(apk, mode=indexing_mode)
        if not include_resource_table:
            return file_entries
        return file_entries + collect_resource_table_strings(apk)

    buffer = io.StringIO()
    with redirect_stdout(buffer), redirect_stderr(buffer):
        collected, fd_output = _run_with_fd_capture(_collect)
    captured = buffer.getvalue() + fd_output
    warnings = tuple(dict.fromkeys(_extract_bounds_warnings(captured)))
    added_fallback_entries = tuple()
    if include_resource_table and warnings:
        fallback_entries = collect_aapt2_resource_strings(apk)
        if fallback_entries:
            existing_values = {entry.value for entry in collected}
            added_fallback_entries = tuple(
                entry for entry in fallback_entries if entry.value not in existing_values
            )
            collected = collected + added_fallback_entries
    if warnings:
        apk_path = getattr(apk, "filename", None)
        dedupe_key = apk_path or f"apk:{id(apk)}"
        if dedupe_key not in _BOUNDS_WARNING_SEEN:
            _BOUNDS_WARNING_SEEN.add(dedupe_key)
            counts = _parse_bounds_counts(list(warnings))
            event_extra: dict[str, object] = {
                "event": "strings.resource_bounds_warning",
                "apk_path": apk_path,
                "warning_lines": list(warnings),
                "count_values": counts,
            }
            if log_context:
                event_extra.update(
                    {
                        str(key): value
                        for key, value in log_context.items()
                        if value is not None
                    }
                )
            log.warning(
                "Resource table parsing emitted bounds warnings",
                category="static_analysis",
                extra=event_extra,
            )

    if not include_resource_table:
        filtered = tuple(
            entry for entry in collected if entry.origin_type != "resource"
        )
    else:
        filtered = collected

    return StringIndex(
        strings=filtered,
        resource_bounds_warnings=warnings,
        aapt2_resource_fallback_count=len(added_fallback_entries),
    )


__all__ = ["build_string_index"]
