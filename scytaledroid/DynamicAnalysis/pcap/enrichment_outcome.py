"""Structured PCAP enrichment outcome states."""

from __future__ import annotations

from typing import Literal, TypedDict

EnrichmentStatus = Literal[
    "completed",
    "completed_no_observations",
    "skipped_tool_unavailable",
    "skipped_not_applicable",
    "failed_input_invalid",
    "failed_tool_execution",
    "failed_parser",
    "failed_internal",
]

COMPLETED: EnrichmentStatus = "completed"
COMPLETED_NO_OBSERVATIONS: EnrichmentStatus = "completed_no_observations"
SKIPPED_TOOL_UNAVAILABLE: EnrichmentStatus = "skipped_tool_unavailable"
SKIPPED_NOT_APPLICABLE: EnrichmentStatus = "skipped_not_applicable"
FAILED_INPUT_INVALID: EnrichmentStatus = "failed_input_invalid"
FAILED_TOOL_EXECUTION: EnrichmentStatus = "failed_tool_execution"
FAILED_PARSER: EnrichmentStatus = "failed_parser"
FAILED_INTERNAL: EnrichmentStatus = "failed_internal"


class EnrichmentOutcome(TypedDict, total=False):
    status: EnrichmentStatus
    reason_code: str
    message: str
    tool_name: str
    tool_version: str | None
    tool_path: str | None
    usable: bool
    observation_count: int
    source: str | None
    legacy_status: str
    reason: str | None


def legacy_status(status: EnrichmentStatus) -> str:
    if status in {COMPLETED, COMPLETED_NO_OBSERVATIONS}:
        return "ok"
    if status in {SKIPPED_TOOL_UNAVAILABLE, SKIPPED_NOT_APPLICABLE}:
        return "skipped"
    return "failed"


def make_outcome(
    status: EnrichmentStatus,
    reason_code: str,
    message: str,
    *,
    usable: bool,
    observation_count: int = 0,
    tool_name: str = "tshark",
    tool_path: str | None = None,
    tool_version: str | None = None,
    source: str | None = None,
) -> EnrichmentOutcome:
    return {
        "status": status,
        "reason_code": reason_code,
        "message": message,
        "tool_name": tool_name,
        "tool_version": tool_version,
        "tool_path": tool_path,
        "usable": usable,
        "observation_count": max(0, int(observation_count)),
        "source": source,
        "legacy_status": legacy_status(status),
        "reason": reason_code,
    }
