"""Native/JNI hardening detector."""

from __future__ import annotations

import math
import time
from collections.abc import Sequence

from ..core.context import DetectorContext
from ..core.findings import (
    Badge,
    DetectorResult,
    EvidencePointer,
    Finding,
    MasvsCategory,
    SeverityLevel,
)
from ..modules.string_analysis.origins import canonical_origin_type
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
_ENTROPY_SAMPLE_BYTES = 131072
_HASH_SAMPLE_BYTES = 8192


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

        suspicious_hits = _scan_suspicious_tokens(
            libs,
            string_index=getattr(context, "string_index", None),
        )
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
            "entropy_sampling_bytes": _ENTROPY_SAMPLE_BYTES,
            "suspicious_scan_source": "string_index"
            if getattr(context, "string_index", None) is not None
            else "binary_fallback",
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
        sample = _sample_blob(blob, max_bytes=_ENTROPY_SAMPLE_BYTES)
        libs.append(
            {
                "path": name,
                "size_bytes": len(blob),
                "entropy": round(_shannon_entropy(sample), 3),
                "hash_short": _short_hash(sample),
                "scan_sample": sample,
            }
        )
    return libs


def _sample_blob(blob: bytes, *, max_bytes: int) -> bytes:
    if len(blob) <= max_bytes:
        return blob
    segment = max(max_bytes // 3, 1)
    middle = max_bytes - (segment * 2)
    middle = max(middle, 1)
    mid_start = max((len(blob) // 2) - (middle // 2), 0)
    return b"".join(
        (
            blob[:segment],
            blob[mid_start : mid_start + middle],
            blob[-segment:],
        )
    )


def _scan_suspicious_tokens(
    libs: list[dict[str, object]],
    *,
    string_index=None,
) -> list[dict[str, object]]:
    if string_index is not None and not string_index.is_empty():
        hits = _scan_suspicious_tokens_from_index(libs, string_index.strings)
        if hits:
            return hits
    return _scan_suspicious_tokens_from_samples(libs)


def _scan_suspicious_tokens_from_index(
    libs: list[dict[str, object]],
    entries: Sequence[object],
) -> list[dict[str, object]]:
    lib_paths = {str(lib.get("path") or "") for lib in libs}
    if not lib_paths:
        return []

    hits: list[dict[str, object]] = []
    seen: set[tuple[str, str]] = set()
    for entry in entries:
        origin = str(getattr(entry, "origin", "") or "")
        if origin not in lib_paths:
            continue
        if canonical_origin_type(getattr(entry, "origin_type", None)) != "native":
            continue
        lowered = str(getattr(entry, "value", "") or "").lower()
        if not lowered:
            continue
        for token in _SUSPICIOUS_TOKENS:
            if token not in lowered:
                continue
            key = (origin, token)
            if key in seen:
                continue
            seen.add(key)
            hits.append({"path": origin, "token": token})
    return hits


def _scan_suspicious_tokens_from_samples(libs: list[dict[str, object]]) -> list[dict[str, object]]:
    hits: list[dict[str, object]] = []
    seen: set[tuple[str, str]] = set()
    for lib in libs:
        blob = lib.get("scan_sample")
        if not isinstance(blob, (bytes, bytearray)):
            continue
        text = blob.decode("utf-8", errors="ignore").lower()
        for token in _SUSPICIOUS_TOKENS:
            if token not in text:
                continue
            key = (str(lib.get("path") or ""), token)
            if key in seen:
                continue
            seen.add(key)
            hits.append({"path": lib.get("path"), "token": token})
    return hits


def _short_hash(blob: bytes) -> str:
    sample = blob[:_HASH_SAMPLE_BYTES]
    return f"{sum(sample) % 65536:04x}"


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
