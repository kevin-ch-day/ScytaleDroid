"""Native/JNI hardening detector."""

from __future__ import annotations

import math
import time

from ..core.context import DetectorContext
from ..core.findings import (
    Badge,
    DetectorResult,
    EvidencePointer,
    Finding,
    MasvsCategory,
    SeverityLevel,
)
from .base import BaseDetector, register_detector

_SUSPICIOUS_TOKENS = (
    "frida",
    "xposed",
    "magisk",
    "substrate",
    "root",
    "su",
    "debug",
    "emulator",
    "ptrace",
    "gadget",
)


@register_detector
class NativeHardeningDetector(BaseDetector):
    """Summarises native library posture."""

    detector_id = "native_hardening"
    name = "Native / JNI detector"
    default_profiles = ("full",)
    section_key = "native_jni"

    def run(self, context: DetectorContext) -> DetectorResult:
        started = time.time()
        libs = _collect_native_libraries(context.apk)
        if not libs:
            return DetectorResult(
                detector_id=self.detector_id,
                section_key=self.section_key,
                status=Badge.INFO,
                duration_sec=time.time() - started,
                metrics={"native_libs": 0},
                evidence=tuple(),
                notes=("No native libraries detected.",),
                findings=tuple(),
            )

        suspicious_hits = _scan_suspicious_tokens(libs)
        for entry in libs:
            entry.pop("blob", None)
        entropy_samples = sorted(libs, key=lambda item: item["entropy"], reverse=True)[:5]

        evidence: list[EvidencePointer] = []
        for entry in entropy_samples:
            evidence.append(
                EvidencePointer(
                    location=entry["path"],
                    hash_short=entry.get("hash_short"),
                    description=f"entropy={entry['entropy']}",
                )
            )

        findings: list[Finding] = []
        status = Badge.OK
        if suspicious_hits:
            status = Badge.WARN
            findings.append(
                Finding(
                    finding_id="native_anti_analysis_signals",
                    title="Native anti-analysis indicators",
                    severity_gate=SeverityLevel.P2,
                    category_masvs=MasvsCategory.RESILIENCE,
                    status=Badge.WARN,
                    because="Native libraries contain strings associated with anti-debug/root checks.",
                    evidence=tuple(evidence[:5]),
                    remediate="Review native protections and validate behavior in a controlled run.",
                    metrics={"suspicious_hits": len(suspicious_hits)},
                    tags=("native", "anti-analysis"),
                )
            )

        metrics = {
            "native_libs": len(libs),
            "jni_density": _calc_jni_density(libs),
            "suspicious_hits": len(suspicious_hits),
            "entropy_top": entropy_samples,
        }

        return DetectorResult(
            detector_id=self.detector_id,
            section_key=self.section_key,
            status=status,
            duration_sec=time.time() - started,
            metrics=metrics,
            evidence=tuple(evidence),
            notes=tuple(),
            findings=tuple(findings),
        )


def _collect_native_libraries(apk) -> list[dict[str, object]]:
    libs: list[dict[str, object]] = []
    try:
        files = apk.get_files() or []
    except Exception:
        files = []
    for name in sorted(files):
        if not name.lower().endswith(".so"):
            continue
        try:
            blob = apk.get_file(name)
        except Exception:
            continue
        if not blob:
            continue
        libs.append(
            {
                "path": name,
                "size_bytes": len(blob),
                "entropy": round(_shannon_entropy(blob), 3),
                "hash_short": _short_hash(blob),
                "blob": blob,
            }
        )
    return libs


def _scan_suspicious_tokens(libs: list[dict[str, object]]) -> list[dict[str, object]]:
    hits: list[dict[str, object]] = []
    for lib in libs:
        blob = lib.get("blob")
        if not isinstance(blob, (bytes, bytearray)):
            continue
        text = blob.decode("utf-8", errors="ignore").lower()
        for token in _SUSPICIOUS_TOKENS:
            if token in text:
                hits.append({"path": lib["path"], "token": token})
    return hits


def _short_hash(blob: bytes) -> str:
    return f"{sum(blob) % 65536:04x}"


def _calc_jni_density(libs: list[dict[str, object]]) -> float:
    total_size = sum(int(entry.get("size_bytes") or 0) for entry in libs)
    return round(total_size / max(len(libs), 1), 2)


def _shannon_entropy(blob: bytes) -> float:
    if not blob:
        return 0.0
    counts = [0] * 256
    for byte in blob:
        counts[byte] += 1
    entropy = 0.0
    length = len(blob)
    for count in counts:
        if count == 0:
            continue
        p = count / length
        entropy -= p * math.log2(p)
    return entropy


__all__ = ["NativeHardeningDetector"]