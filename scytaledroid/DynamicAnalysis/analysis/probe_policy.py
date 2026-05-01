"""Probe manifest and adaptive policy helpers."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime


@dataclass(frozen=True)
class ProbeAction:
    action: str
    duration_s: int
    reason: str
    triggered_at: datetime


def select_adaptive_probes(
    *,
    uncertainty_score: float,
    heartbeat_vs_sync_threshold: float = 0.2,
    novel_mode_detected: bool = False,
    now: datetime,
) -> list[ProbeAction]:
    probes: list[ProbeAction] = []
    if uncertainty_score > heartbeat_vs_sync_threshold:
        probes.append(
            ProbeAction(
                action="extended_idle",
                duration_s=45,
                reason="ambiguity_heartbeat_background_sync",
                triggered_at=now,
            )
        )
    if novel_mode_detected:
        probes.append(
            ProbeAction(
                action="repeat_last_probe",
                duration_s=30,
                reason="novel_mode_repeat",
                triggered_at=now,
            )
        )
    return probes


__all__ = ["ProbeAction", "select_adaptive_probes"]
