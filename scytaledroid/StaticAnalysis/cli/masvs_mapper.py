from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, Iterable, List, Mapping, Tuple

__all__ = [
    "ControlEvidence",
    "RULE_TO_CONTROL",
    "STATUS_PRECEDENCE",
    "summarise_controls",
    "rule_to_control",
    "rule_to_area",
]

RULE_TO_CONTROL: Dict[str, Tuple[str, str]] = {
    "BASE-IPC-COMP-NO-ACL": ("PLATFORM-IPC-1", "FAIL"),
    "BASE-IPC-PROVIDER-NO-ACL": ("PLATFORM-IPC-1", "FAIL"),
    "BASE-IPC-EXPORTED-WITH-PERM": ("PLATFORM-IPC-1", "PASS"),
    "BASE-CLR-001": ("NETWORK-1", "FAIL"),
    "BASE-STO-LEGACY": ("STORAGE-2", "FAIL"),
    "STR-SECRET-AWS-HC": ("STORAGE-2", "INCONCLUSIVE"),
}

STATUS_PRECEDENCE = {"FAIL": 3, "INCONCLUSIVE": 2, "PASS": 1}


@dataclass(slots=True)
class ControlEvidence:
    control_id: str
    status: str
    evidence: List[Mapping[str, object]] = field(default_factory=list)
    rubric: Mapping[str, object] = field(default_factory=dict)

    def merge(self, other: "ControlEvidence") -> "ControlEvidence":
        if STATUS_PRECEDENCE[other.status] > STATUS_PRECEDENCE[self.status]:
            self.status = other.status
        if other.evidence:
            self.evidence.extend(other.evidence)
        if other.rubric:
            self.rubric = other.rubric
        return self

    def payload(self) -> Mapping[str, object]:
        return {
            "status": self.status,
            "evidence": self.evidence,
            "rubric": self.rubric,
        }


def summarise_controls(entries: Iterable[Tuple[str, Mapping[str, object]]]) -> Dict[str, ControlEvidence]:
    summary: Dict[str, ControlEvidence] = {}
    for rule_id, evidence in entries:
        mapping = RULE_TO_CONTROL.get(rule_id)
        if not mapping:
            continue
        control_id, status = mapping
        payload = ControlEvidence(
            control_id=control_id,
            status=status,
            evidence=[evidence],
            rubric={"rule_id": rule_id, "source": "detector"},
        )
        existing = summary.get(control_id)
        if existing is None:
            summary[control_id] = payload
        else:
            existing.merge(payload)
    return summary


def rule_to_control(rule_id: str) -> Tuple[str, str] | None:
    return RULE_TO_CONTROL.get(rule_id)


def rule_to_area(rule_id: str) -> str | None:
    mapping = RULE_TO_CONTROL.get(rule_id)
    if not mapping:
        return None
    control_id, _status = mapping
    parts = [segment for segment in control_id.split("-") if segment]
    if not parts:
        return None
    return parts[0].upper()
