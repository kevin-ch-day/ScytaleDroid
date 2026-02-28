"""Profile v3 post-run validator (Phase 2 churn reduction).

This module performs the same per-run checks that strict v3 manifest build will
eventually enforce, but immediately after a dynamic run completes.

It is intentionally filesystem-driven:
- run_manifest.json is authoritative
- derived ML artifacts under analysis/ml/v1/ must exist for paper-grade runs

The orchestrator can call this after sealing the manifest to emit a single
copy/paste-friendly line and optionally write a derived check artifact.
"""

from __future__ import annotations

import csv
import json
from dataclasses import dataclass
from pathlib import Path

from scytaledroid.DynamicAnalysis.ml import ml_parameters_profile as profile_config
from scytaledroid.DynamicAnalysis.pcap.dataset_tracker import MIN_WINDOWS_PER_RUN
from scytaledroid.DynamicAnalysis.run_profile_norm import (
    normalize_run_profile,
    phase_from_normalized_profile,
    resolve_run_profile_from_manifest,
)


@dataclass(frozen=True)
class V3PostRunCheck:
    ok: bool
    run_id: str
    package: str
    run_profile: str
    phase: str
    version_code: str
    windows: int | None
    pcap_bytes: int | None
    min_windows_required: int
    min_pcap_bytes_required: int
    has_window_scores: bool
    has_baseline_threshold: bool
    reasons: list[str]

    def to_dict(self) -> dict[str, object]:
        return {
            "ok": bool(self.ok),
            "run_id": self.run_id,
            "package": self.package,
            "run_profile": self.run_profile,
            "phase": self.phase,
            "version_code": self.version_code,
            "windows": self.windows,
            "pcap_bytes": self.pcap_bytes,
            "min_windows_required": int(self.min_windows_required),
            "min_pcap_bytes_required": int(self.min_pcap_bytes_required),
            "has_window_scores": bool(self.has_window_scores),
            "has_baseline_threshold": bool(self.has_baseline_threshold),
            "reasons": list(self.reasons),
        }


def _rjson(path: Path) -> dict:
    payload = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(payload, dict):
        raise ValueError(f"expected object: {path}")
    return payload


def _run_identity(manifest: dict) -> dict:
    tgt = manifest.get("target") if isinstance(manifest.get("target"), dict) else {}
    ident = tgt.get("run_identity") if isinstance(tgt.get("run_identity"), dict) else {}
    return ident


def _run_package(manifest: dict) -> str:
    tgt = manifest.get("target") if isinstance(manifest.get("target"), dict) else {}
    pkg = str(tgt.get("package_name") or tgt.get("package") or "").strip()
    return pkg


def _pcap_size_bytes(manifest: dict) -> int | None:
    artifacts = manifest.get("artifacts")
    if not isinstance(artifacts, list):
        return None
    for art in artifacts:
        if not isinstance(art, dict):
            continue
        if str(art.get("type") or "") != "pcapdroid_capture":
            continue
        size = art.get("size_bytes")
        try:
            return int(size) if size is not None else None
        except Exception:
            return None
    return None


def _window_scores_path(run_dir: Path) -> Path:
    return run_dir / "analysis" / "ml" / "v1" / "window_scores.csv"


def _threshold_path(run_dir: Path) -> Path:
    return run_dir / "analysis" / "ml" / "v1" / "baseline_threshold.json"


def _count_windows(window_scores_csv: Path) -> int | None:
    if not window_scores_csv.exists():
        return None
    try:
        with window_scores_csv.open("r", encoding="utf-8", newline="") as f:
            r = csv.DictReader(f)
            n = 0
            for _ in r:
                n += 1
        return int(n)
    except Exception:
        return None


def validate_run_dir_for_profile_v3(run_dir: Path) -> V3PostRunCheck:
    """Validate a single evidence-pack run directory for v3 strict minima/artifacts."""

    manifest_path = run_dir / "run_manifest.json"
    man = _rjson(manifest_path)
    run_id = str(man.get("dynamic_run_id") or run_dir.name).strip()
    pkg = _run_package(man).strip()
    try:
        rp = resolve_run_profile_from_manifest(man, strict_conflict=True).normalized
    except Exception:
        rp = ""
    rp = normalize_run_profile(rp)
    phase = phase_from_normalized_profile(rp)
    ident = _run_identity(man)
    version_code = str(ident.get("version_code") or ident.get("observed_version_code") or "").strip()

    min_windows = int(MIN_WINDOWS_PER_RUN)
    min_pcap_idle = int(getattr(profile_config, "MIN_PCAP_BYTES_V3_IDLE", 0))
    min_pcap_scripted = int(
        getattr(profile_config, "MIN_PCAP_BYTES_V3_SCRIPTED", getattr(profile_config, "MIN_PCAP_BYTES", 50_000))
    )
    # Apply phase-specific minima. Idle can be small/zero; scripted must demonstrate meaningful traffic.
    min_pcap_bytes = int(min_pcap_idle) if str(phase or "").strip().lower() == "idle" else int(min_pcap_scripted)

    scores_path = _window_scores_path(run_dir)
    thr_path = _threshold_path(run_dir)
    has_scores = scores_path.exists()
    has_thr = thr_path.exists()
    windows = _count_windows(scores_path)
    pcap_bytes = _pcap_size_bytes(man)

    reasons: list[str] = []
    if not pkg:
        reasons.append("missing_package_name")
    if not version_code:
        reasons.append("missing_version_code")
    if not has_scores:
        reasons.append("missing_window_scores_csv")
    if not has_thr:
        reasons.append("missing_baseline_threshold_json")
    if windows is None:
        reasons.append("window_count_unavailable")
    elif int(windows) < int(min_windows):
        reasons.append("insufficient_windows")
    if pcap_bytes is None:
        reasons.append("pcap_size_unavailable")
    elif int(pcap_bytes) < int(min_pcap_bytes):
        reasons.append("insufficient_pcap_bytes")

    ok = len(reasons) == 0
    return V3PostRunCheck(
        ok=ok,
        run_id=run_id,
        package=pkg,
        run_profile=rp,
        phase=phase,
        version_code=version_code,
        windows=windows,
        pcap_bytes=pcap_bytes,
        min_windows_required=min_windows,
        min_pcap_bytes_required=min_pcap_bytes,
        has_window_scores=has_scores,
        has_baseline_threshold=has_thr,
        reasons=reasons,
    )


__all__ = ["V3PostRunCheck", "validate_run_dir_for_profile_v3"]
