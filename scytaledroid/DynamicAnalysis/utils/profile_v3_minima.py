"""Profile v3 (Paper #3) effective minima helpers.

We want one canonical source of "what are the minima" so that:
- capture status dashboard
- strict manifest builder
- post-run checks
all report and enforce the same values.

Policy:
- min_windows is global (MIN_WINDOWS_PER_RUN)
- min_pcap_bytes is phase-specific for Profile v3 (idle vs scripted)

Optional env overrides exist to support operational experiments without code changes.
For paper runs, provenance receipts already hash the underlying constants file(s),
so changing env overrides should be treated as a deliberate decision.
"""

from __future__ import annotations

import os

from scytaledroid.DynamicAnalysis.ml import ml_parameters_profile as profile_config
from scytaledroid.DynamicAnalysis.pcap.dataset_tracker import MIN_WINDOWS_PER_RUN


def _env_int(name: str) -> int | None:
    raw = str(os.environ.get(name) or "").strip()
    if not raw:
        return None
    try:
        return int(raw)
    except Exception:
        return None


def effective_min_windows_per_run() -> int:
    return int(MIN_WINDOWS_PER_RUN)


def effective_min_pcap_bytes_idle() -> int:
    # Optional override for operations.
    override = _env_int("SCYTALEDROID_V3_MIN_PCAP_BYTES_IDLE")
    if override is not None:
        return int(override)
    return int(getattr(profile_config, "MIN_PCAP_BYTES_V3_IDLE", 0))


def effective_min_pcap_bytes_scripted() -> int:
    override = _env_int("SCYTALEDROID_V3_MIN_PCAP_BYTES_SCRIPTED")
    if override is not None:
        return int(override)
    return int(getattr(profile_config, "MIN_PCAP_BYTES_V3_SCRIPTED", getattr(profile_config, "MIN_PCAP_BYTES", 50_000)))


def effective_min_pcap_bytes_for_phase(*, phase: str) -> int:
    ph = str(phase or "").strip().lower()
    if ph == "idle":
        return effective_min_pcap_bytes_idle()
    return effective_min_pcap_bytes_scripted()


__all__ = [
    "effective_min_windows_per_run",
    "effective_min_pcap_bytes_idle",
    "effective_min_pcap_bytes_scripted",
    "effective_min_pcap_bytes_for_phase",
]

