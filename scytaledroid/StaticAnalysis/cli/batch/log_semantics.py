"""Batch log semantics for static analysis.

Goal: make batch logs interpretable and paper-safe.

We separate "run failure" from "risk findings":
- Stage WARN/FINDING/POLICY_FAIL are *signals* (detectors ran) not execution failure.
- Stage ERROR indicates a detector crashed and is a tooling/system failure signal.

Five-level stage taxonomy (v1):
- OK: no output in batch
- WARN: detector warning (risk signal)
- FINDING: detector FAIL but not a policy gate (risk signal)
- POLICY_FAIL: detector FAIL with policy_gate=True (paper-grade blocker)
- ERROR: detector crash/exception
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum


class BatchStageLevel(str, Enum):
    OK = "OK"
    WARN = "WARN"
    FINDING = "FINDING"
    POLICY_FAIL = "POLICY_FAIL"
    ERROR = "ERROR"

    @classmethod
    def from_detector_result(cls, result: object) -> "BatchStageLevel":
        status = str(getattr(result, "status", "") or "").upper()
        if status == "WARN":
            return cls.WARN
        if status == "ERROR":
            return cls.ERROR
        if status == "FAIL":
            if _policy_gate_flag(result):
                return cls.POLICY_FAIL
            return cls.FINDING
        return cls.OK


class BatchWarnKind(str, Enum):
    """Refines WARN so batch logs remain interpretable.

    WARN kinds are *not* run failures.
    """

    RISK = "RISK"  # detector warning implies risk/signal in the app
    EVIDENCE = "EVIDENCE"  # detector could not compute due to missing/insufficient evidence
    TOOLING = "TOOLING"  # detector degraded due to missing tools/dependencies

    @classmethod
    def from_detector_result(cls, result: object) -> "BatchWarnKind":
        codes = _reason_codes(result)
        joined = " ".join(codes).lower()
        if any(code.lower().startswith("insufficient_evidence:") for code in codes) or "baseline_missing" in joined:
            return cls.EVIDENCE
        if (
            "missing_tools" in joined
            or "tool_missing" in joined
            or "dependency_missing" in joined
            or "capinfos" in joined
            or "tshark" in joined
        ):
            return cls.TOOLING
        return cls.RISK


@dataclass(frozen=True, slots=True)
class StageSummaryLine:
    level: BatchStageLevel
    section: str
    artifact_sets: frozenset[str]
    warn_kind: BatchWarnKind | None = None
    note: str | None = None

    def format(self) -> str:
        sets = _format_artifact_sets(set(self.artifact_sets))
        prefix = self.level.value
        if self.level == BatchStageLevel.WARN and self.warn_kind is not None:
            prefix = f"WARN[{self.warn_kind.value}]"
        line = f"{prefix:<11} {self.section} ({sets})"
        if self.note:
            line += f" note={self.note}"
        return line


def summarize_stage_levels(
    app_result: object,
    *,
    artifact_set_resolver,
) -> list[StageSummaryLine]:
    """Summarize detector stage outcomes for batch logs.

    `artifact_set_resolver(artifact) -> str` returns "base" or a split token.
    """
    stage_sets: dict[tuple[BatchStageLevel, BatchWarnKind | None, str, str | None], set[str]] = {}

    for artifact in getattr(app_result, "artifacts", []) or []:
        artifact_set = "base"
        try:
            token = artifact_set_resolver(artifact)
            artifact_set = token or "base"
        except Exception:
            artifact_set = "base"

        for result in getattr(getattr(artifact, "report", None), "detector_results", []) or []:
            section = str(getattr(result, "section_key", "") or "").strip() or "unknown"
            level = BatchStageLevel.from_detector_result(result)
            if level == BatchStageLevel.OK:
                continue
            warn_kind = None
            note = None
            if level == BatchStageLevel.WARN:
                warn_kind = BatchWarnKind.from_detector_result(result)
                codes = _reason_codes(result)
                if codes:
                    note = _truncate_note(codes[0])
            stage_sets.setdefault((level, warn_kind, section, note), set()).add(artifact_set)

    # Collapse policy: WARN repeats across splits are noise if base already WARNs.
    collapsed: dict[tuple[BatchStageLevel, BatchWarnKind | None, str, str | None], set[str]] = {}
    for (level, warn_kind, section, note), sets in stage_sets.items():
        if level == BatchStageLevel.WARN and "base" in sets:
            collapsed[(level, warn_kind, section, note)] = {"base"}
        else:
            collapsed[(level, warn_kind, section, note)] = sets

    # Stable order: section order comes from view definitions if available.
    section_order = _section_order_map()

    def _key(
        item: tuple[tuple[BatchStageLevel, BatchWarnKind | None, str, str | None], set[str]]
    ) -> tuple[int, int, int, str]:
        (level, warn_kind, section, _), _sets = item
        # Put WARN first, then FINDING, then POLICY_FAIL, then ERROR.
        level_rank = {
            BatchStageLevel.WARN: 0,
            BatchStageLevel.FINDING: 1,
            BatchStageLevel.POLICY_FAIL: 2,
            BatchStageLevel.ERROR: 3,
        }.get(level, 9)
        warn_rank = {
            BatchWarnKind.RISK: 0,
            BatchWarnKind.EVIDENCE: 1,
            BatchWarnKind.TOOLING: 2,
            None: 9,
        }.get(warn_kind, 9)
        return (section_order.get(section, 9999), level_rank, warn_rank, section)

    lines: list[StageSummaryLine] = []
    for (level, warn_kind, section, note), sets in sorted(collapsed.items(), key=_key):
        if not sets:
            continue
        lines.append(
            StageSummaryLine(
                level=level,
                section=section,
                artifact_sets=frozenset(sets),
                warn_kind=warn_kind,
                note=note,
            )
        )
    return lines


def _policy_gate_flag(result: object) -> bool:
    try:
        metrics = getattr(result, "metrics", None)
        if isinstance(metrics, dict):
            return bool(metrics.get("policy_gate", False))
        return bool(getattr(metrics, "policy_gate", False))
    except Exception:
        return False


def _reason_codes(result: object) -> list[str]:
    try:
        metrics = getattr(result, "metrics", None)
        if isinstance(metrics, dict):
            value = metrics.get("reason_codes")
        else:
            value = getattr(metrics, "reason_codes", None)
        if isinstance(value, list):
            return [str(item) for item in value if str(item).strip()]
        if isinstance(value, tuple):
            return [str(item) for item in value if str(item).strip()]
        return []
    except Exception:
        return []


def _truncate_note(value: str) -> str:
    text = (value or "").strip()
    if len(text) <= 60:
        return text
    return text[:57] + "..."


def _section_order_map() -> dict[str, int]:
    try:
        from scytaledroid.StaticAnalysis.cli.views.view_sections import SECTION_DEFINITIONS

        return {definition.key: idx for idx, definition in enumerate(SECTION_DEFINITIONS)}
    except Exception:
        return {}


def _format_artifact_sets(artifact_sets: set[str]) -> str:
    ordered = sorted(artifact_sets, key=lambda s: (0 if s == "base" else 1, s))
    if len(ordered) <= 4:
        return ", ".join(ordered)
    head = ordered[:3]
    tail = len(ordered) - len(head)
    return ", ".join([*head, f"+{tail}"])
