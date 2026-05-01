"""Shared run-profile normalization helpers.

This module centralizes interpretation of `run_profile` strings across tools.
Profile exporters must not implement local heuristics that can drift.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class RunProfileResolved:
    raw_operator: str
    raw_dataset: str
    normalized: str


class RunProfileConflictError(RuntimeError):
    pass


def normalize_run_profile(value: object) -> str:
    s = str(value or "").strip().lower()
    if not s:
        return ""
    # Normalize common aliases/spelling variants.
    s = s.replace("interactive", "interaction")
    if s == "baseline":
        return "baseline_idle"
    if s == "idle":
        return "baseline_idle"
    if s == "interaction":
        return "interaction_scripted"
    return s


def resolve_run_profile_from_manifest(manifest: dict, *, strict_conflict: bool = True) -> RunProfileResolved:
    op = manifest.get("operator") if isinstance(manifest.get("operator"), dict) else {}
    ds = manifest.get("dataset") if isinstance(manifest.get("dataset"), dict) else {}
    raw_op = str(op.get("run_profile") or "").strip()
    raw_ds = str(ds.get("run_profile") or "").strip()
    op_norm = normalize_run_profile(raw_op)
    ds_norm = normalize_run_profile(raw_ds)
    if strict_conflict and op_norm and ds_norm and op_norm != ds_norm:
        raise RunProfileConflictError(f"operator={op_norm} dataset={ds_norm}")
    return RunProfileResolved(raw_operator=raw_op, raw_dataset=raw_ds, normalized=(op_norm or ds_norm))


def phase_from_normalized_profile(norm: str) -> str:
    rp = str(norm or "").strip().lower()
    if not rp:
        return ""
    if rp.startswith("baseline"):
        return "idle"
    if rp.startswith("interaction"):
        return "interactive"
    return ""


__all__ = [
    "RunProfileResolved",
    "RunProfileConflictError",
    "normalize_run_profile",
    "resolve_run_profile_from_manifest",
    "phase_from_normalized_profile",
]

