"""Cross-source agreement scoring and arbitration."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class AgreementInputs:
    lag_seconds: float
    magnitude_ratio: float
    cpu_pct: float | None = None
    mem_kb: float | None = None
    pcap_present: bool = False
    netstats_present: bool = False


@dataclass(frozen=True)
class AgreementDecision:
    score: float
    netstats_status: str
    pcap_status: str
    decision: str
    reasons: list[str]


def score_agreement(inputs: AgreementInputs, *, lag_tolerance: float = 1.0, ratio_tolerance: float = 0.5) -> float:
    lag_score = 1.0 if abs(inputs.lag_seconds) <= lag_tolerance else 0.0
    ratio_score = 1.0 if inputs.magnitude_ratio >= (1 - ratio_tolerance) else 0.0
    cpu_score = 1.0
    if inputs.cpu_pct is not None and inputs.cpu_pct < 0.5 and inputs.magnitude_ratio > 1.5:
        cpu_score = 0.5
    return round((lag_score * 0.4) + (ratio_score * 0.4) + (cpu_score * 0.2), 3)


def arbitrate(inputs: AgreementInputs) -> AgreementDecision:
    reasons: list[str] = []
    score = score_agreement(inputs)
    netstats_status = "valid" if inputs.netstats_present else "missing"
    pcap_status = "valid" if inputs.pcap_present else "missing"
    decision = "proceed"
    if netstats_status == "missing" and pcap_status == "valid":
        decision = "pcap_only"
        reasons.append("netstats_missing_use_pcap")
    if pcap_status == "missing" and netstats_status == "valid":
        decision = "netstats_only"
        reasons.append("pcap_missing_use_netstats")
    if netstats_status == "missing" and pcap_status == "missing":
        decision = "no_network_signal"
        reasons.append("both_missing")
    if score < 0.5 and decision == "proceed":
        decision = "low_agreement"
        reasons.append("low_agreement_score")
    return AgreementDecision(
        score=score,
        netstats_status=netstats_status,
        pcap_status=pcap_status,
        decision=decision,
        reasons=reasons,
    )


__all__ = ["AgreementInputs", "AgreementDecision", "score_agreement", "arbitrate"]
