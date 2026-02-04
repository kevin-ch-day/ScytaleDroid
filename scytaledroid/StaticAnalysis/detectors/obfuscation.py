"""Obfuscation and packing signal detector."""

from __future__ import annotations

import re
import struct
import time
from collections.abc import Iterable

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

_CLASS_DESC_PATTERN = re.compile(r"L[a-zA-Z0-9_/\\$]{3,};")
_CLASS_NAME_PATTERN = re.compile(r"(?:[a-zA-Z0-9_]{1,}/){1,}[a-zA-Z0-9_]{1,}")
_DYNAMIC_LOAD_TOKENS = (
    "DexClassLoader",
    "PathClassLoader",
    "BaseDexClassLoader",
    "InMemoryDexClassLoader",
    "System.loadLibrary",
    "Runtime.getRuntime().load",
    "Runtime.getRuntime().loadLibrary",
)


@register_detector
class ObfuscationDetector(BaseDetector):
    """Summarises obfuscation / anti-analysis traits."""

    detector_id = "obfuscation_signals"
    name = "Obfuscation / Anti-analysis detector"
    default_profiles = ("full",)
    section_key = "obfuscation"

    def run(self, context: DetectorContext) -> DetectorResult:
        started = time.time()
        dex_metrics = _collect_dex_metrics(context.apk)
        class_stats = _collect_class_name_stats(context.string_index)
        dynamic_hits = _count_dynamic_load_hits(context.string_index)

        obfuscation_score = _score_obfuscation(dex_metrics, class_stats, dynamic_hits)
        obfuscation_hint = obfuscation_score >= 0.6

        metrics = {
            "dex_count": len(dex_metrics),
            "dex_metrics": dex_metrics,
            "class_name_samples": class_stats.get("samples", []),
            "class_short_ratio": class_stats.get("short_ratio", 0.0),
            "class_total": class_stats.get("total", 0),
            "dynamic_load_hits": dynamic_hits,
            "obfuscation_score": round(obfuscation_score, 3),
        }

        evidence: list[EvidencePointer] = []
        for entry in class_stats.get("samples", []):
            evidence.append(
                EvidencePointer(
                    location=str(entry.get("origin") or "dex"),
                    description=f"class-like string: {entry.get('value')}",
                )
            )

        findings: list[Finding] = []
        status = Badge.OK
        if obfuscation_hint:
            status = Badge.WARN
            findings.append(
                Finding(
                    finding_id="obfuscation_hints",
                    title="Obfuscation indicators detected",
                    severity_gate=SeverityLevel.P2,
                    category_masvs=MasvsCategory.RESILIENCE,
                    status=Badge.WARN,
                    because=(
                        "DEX/class naming patterns and dynamic-loading hints suggest "
                        "obfuscation or packing."
                    ),
                    evidence=tuple(evidence[:5]),
                    remediate="Use deobfuscation-aware tooling and verify behavior with dynamic analysis.",
                    metrics={
                        "obfuscation_score": obfuscation_score,
                        "dynamic_load_hits": dynamic_hits,
                    },
                    tags=("obfuscation", "anti-analysis"),
                )
            )

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


def _collect_dex_metrics(apk) -> list[dict[str, object]]:
    metrics: list[dict[str, object]] = []
    try:
        files = apk.get_files() or []
    except Exception:
        files = []
    for name in sorted(files):
        if not name.lower().endswith(".dex"):
            continue
        try:
            blob = apk.get_file(name)
        except Exception:
            continue
        if not blob or len(blob) < 0x70:
            continue
        header = blob[:0x70]
        string_ids = _read_u32(header, 0x38)
        method_ids = _read_u32(header, 0x58)
        class_defs = _read_u32(header, 0x60)
        metrics.append(
            {
                "dex": name,
                "size_bytes": len(blob),
                "string_ids": string_ids,
                "method_ids": method_ids,
                "class_defs": class_defs,
            }
        )
    return metrics


def _read_u32(blob: bytes, offset: int) -> int:
    try:
        return struct.unpack_from("<I", blob, offset)[0]
    except struct.error:
        return 0


def _collect_class_name_stats(index) -> dict[str, object]:
    if index is None or index.is_empty():
        return {"total": 0, "short_ratio": 0.0, "samples": []}
    candidates: list[tuple[str, str]] = []
    for entry in index.strings:
        if entry.origin_type not in {"dex", "code"}:
            continue
        value = entry.value
        if _CLASS_DESC_PATTERN.search(value) or _CLASS_NAME_PATTERN.fullmatch(value):
            candidates.append((value, entry.origin))

    total_segments = 0
    short_segments = 0
    samples: list[dict[str, object]] = []
    for value, origin in candidates[:200]:
        cleaned = value.strip("L;")
        parts = re.split(r"[./]", cleaned)
        parts = [p for p in parts if p]
        total_segments += len(parts)
        short_segments += sum(1 for part in parts if len(part) <= 2)
        if len(samples) < 5:
            samples.append({"value": value, "origin": origin})

    ratio = (short_segments / total_segments) if total_segments else 0.0
    return {"total": len(candidates), "short_ratio": round(ratio, 3), "samples": samples}


def _count_dynamic_load_hits(index) -> int:
    if index is None or index.is_empty():
        return 0
    hits = 0
    for entry in index.strings:
        if entry.origin_type not in {"dex", "code"}:
            continue
        if any(token in entry.value for token in _DYNAMIC_LOAD_TOKENS):
            hits += 1
    return hits


def _score_obfuscation(
    dex_metrics: Iterable[dict[str, object]],
    class_stats: dict[str, object],
    dynamic_hits: int,
) -> float:
    dex_count = len(list(dex_metrics))
    short_ratio = float(class_stats.get("short_ratio") or 0.0)
    class_total = int(class_stats.get("total") or 0)
    score = 0.0
    if dex_count >= 3:
        score += 0.2
    if class_total >= 100 and short_ratio >= 0.45:
        score += 0.5
    if dynamic_hits:
        score += 0.2
    return min(score, 1.0)


__all__ = ["ObfuscationDetector"]