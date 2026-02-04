"""React Native footprint detection and bundle metadata."""

from __future__ import annotations

from collections.abc import Iterable, Sequence
from time import perf_counter

from ..core.context import DetectorContext
from ..core.findings import (
    Badge,
    DetectorResult,
    EvidencePointer,
    Finding,
    MasvsCategory,
    SeverityLevel,
)
from ..core.pipeline import make_detector_result
from .base import BaseDetector, register_detector

_RN_LIB_MARKERS = (
    "libhermes.so",
    "libreactnativejni.so",
    "libfabric.so",
    "libreactnative.so",
    "libjsi.so",
)
_RN_PACKAGE_MARKERS = (
    "com.facebook.react",
    "com.facebook.hermes",
    "com.facebook.jni",
)


def _iter_rn_assets(files: Iterable[str]) -> list[str]:
    hits: list[str] = []
    for name in files:
        lowered = name.lower()
        if lowered.startswith("assets/") and (
            lowered.endswith(".hbc")
            or lowered.endswith(".bundle")
            or lowered.endswith(".bundle.js")
            or "index.android.bundle" in lowered
        ):
            hits.append(name)
    return sorted(hits)


def _iter_rn_libs(files: Iterable[str]) -> list[str]:
    hits: list[str] = []
    for name in files:
        lowered = name.lower()
        if not lowered.startswith("lib/"):
            continue
        if any(marker in lowered for marker in _RN_LIB_MARKERS):
            hits.append(name)
    return sorted(hits)


def _iter_rn_namespaces(libraries: Sequence[str]) -> list[str]:
    hits: list[str] = []
    for item in libraries:
        lowered = item.lower()
        if any(marker in lowered for marker in _RN_PACKAGE_MARKERS):
            hits.append(item)
    return sorted(dict.fromkeys(hits))


@register_detector
class ReactNativeDetector(BaseDetector):
    detector_id = "react_native"
    name = "React Native footprint"
    section_key = "react_native"
    default_profiles = ("full",)

    def run(self, context: DetectorContext) -> DetectorResult:
        started = perf_counter()

        try:
            files = sorted(context.apk.get_files() or [])
        except Exception:
            files = []

        assets = _iter_rn_assets(files)
        libs = _iter_rn_libs(files)
        namespaces = _iter_rn_namespaces(context.libraries or ())

        rn_detected = bool(assets or libs or namespaces)
        hermes_present = any("hermes" in item.lower() for item in libs) or any(
            item.lower().endswith(".hbc") for item in assets
        )
        fabric_present = any("fabric" in item.lower() for item in libs)

        metrics = {
            "rn_detected": rn_detected,
            "bundles": len(assets),
            "native_libs": len(libs),
            "namespaces": len(namespaces),
            "hermes": hermes_present,
            "fabric": fabric_present,
        }

        evidence: list[EvidencePointer] = []
        base_location = context.apk_path.resolve().as_posix()
        for name in assets[:4]:
            evidence.append(
                EvidencePointer(
                    location=f"{base_location}!{name}",
                    description="React Native bundle asset",
                    extra={"asset": name},
                )
            )
        for name in libs[:4]:
            evidence.append(
                EvidencePointer(
                    location=f"{base_location}!{name}",
                    description="React Native native library",
                    extra={"library": name},
                )
            )

        findings: list[Finding] = []
        if rn_detected:
            findings.append(
                Finding(
                    finding_id="RN_FOOTPRINT",
                    title="React Native footprint detected",
                    severity_gate=SeverityLevel.NOTE,
                    category_masvs=MasvsCategory.OTHER,
                    status=Badge.INFO,
                    because=(
                        "React Native bundle/native components detected; "
                        "enable RN-specific analysis for JS/Hermes coverage."
                    ),
                    evidence=tuple(evidence[:2]),
                    tags=("react_native", "bundle"),
                )
            )

        status = Badge.INFO if rn_detected else Badge.OK
        notes = []
        if rn_detected and assets:
            notes.append("Hermes/JS bundles detected under assets.")

        return make_detector_result(
            detector_id=self.detector_id,
            section_key=self.section_key,
            status=status,
            started_at=started,
            findings=tuple(findings),
            metrics=metrics,
            evidence=tuple(evidence),
            notes=tuple(notes),
        )


__all__ = ["ReactNativeDetector"]