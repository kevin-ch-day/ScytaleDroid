"""Digital forensics triage hints derived from static artefacts."""

from __future__ import annotations

import re
from collections.abc import Mapping
from pathlib import Path
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
from ..modules.string_analysis.extractor import StringIndex
from .base import BaseDetector, register_detector

_PREF_PATTERN = re.compile(r"shared_prefs/([\w\-\.]+\.xml)", re.IGNORECASE)
_DB_PATTERN = re.compile(r"databases/([\w\-\.]+\.db)", re.IGNORECASE)
_FILE_PATTERN = re.compile(r"files/([\w\-\.]+\.(?:log|json|txt))", re.IGNORECASE)

_PERMISSION_HINTS: Mapping[str, tuple[str, str]] = {
    "android.permission.READ_SMS": ("sms.db", "databases"),
    "android.permission.READ_CONTACTS": ("contacts2.db", "databases"),
    "android.permission.READ_CALL_LOG": ("calllog.db", "databases"),
    "android.permission.ACCESS_FINE_LOCATION": ("location_history.xml", "shared_prefs"),
    "android.permission.RECORD_AUDIO": ("media_uploads", "files"),
}


def _string_hints(
    index: StringIndex, package: str, apk_path: Path
) -> tuple[list[dict[str, object]], list[EvidencePointer]]:
    hints: list[dict[str, object]] = []
    evidence: list[EvidencePointer] = []
    seen_targets: set[str] = set()

    for entry in index.strings:
        value = entry.value
        if len(value) > 160:
            continue
        target_path = None
        hint_type = None
        for pattern, label in (
            (_PREF_PATTERN, "shared_prefs"),
            (_DB_PATTERN, "database"),
            (_FILE_PATTERN, "file"),
        ):
            match = pattern.search(value)
            if match:
                hint_type = label
                target_path = match.group(1)
                break
        if target_path is None or hint_type is None:
            continue

        if hint_type == "shared_prefs":
            absolute = f"/data/data/{package}/shared_prefs/{target_path}"
        elif hint_type == "database":
            absolute = f"/data/data/{package}/databases/{target_path}"
        else:
            absolute = f"/data/data/{package}/files/{target_path}"

        if absolute in seen_targets:
            continue
        seen_targets.add(absolute)

        hints.append({
            "path": absolute,
            "origin": entry.origin,
            "origin_type": entry.origin_type,
            "hint_type": hint_type,
        })
        evidence.append(
            EvidencePointer(
                location=f"{apk_path.resolve().as_posix()}!string[{entry.origin}]",
                description=f"{hint_type}:{target_path}",
                extra={"origin_type": entry.origin_type},
            )
        )
        if len(hints) >= 6:
            break

    return hints, evidence


def _permission_hints(context: DetectorContext) -> list[dict[str, object]]:
    package = context.manifest_summary.package_name or context.apk_path.stem
    hints: list[dict[str, object]] = []
    for permission, (filename, location) in _PERMISSION_HINTS.items():
        if permission not in context.permissions.declared:
            continue
        path = f"/data/data/{package}/{location}/{filename}"
        hints.append({"permission": permission, "path": path, "location": location})
    return hints


@register_detector
class DfirHintsDetector(BaseDetector):
    """Predicts useful collection points for DFIR follow-up."""

    detector_id = "dfir_hints"
    name = "DFIR hints detector"
    default_profiles = ("quick", "full")
    section_key = "dfir_hints"

    def run(self, context: DetectorContext) -> DetectorResult:
        started = perf_counter()
        package = context.manifest_summary.package_name or context.apk_path.stem
        index = context.string_index

        path_hints: list[dict[str, object]] = []
        evidence: list[EvidencePointer] = []
        if index is not None and not index.is_empty():
            path_hints, evidence = _string_hints(index, package, context.apk_path)

        permission_hints = _permission_hints(context)

        findings: list[Finding] = []
        if path_hints:
            findings.append(
                Finding(
                    finding_id="dfir_static_paths",
                    title="Static artefacts hint at stored evidence",
                    severity_gate=SeverityLevel.NOTE,
                    category_masvs=MasvsCategory.OTHER,
                    status=Badge.INFO,
                    because=f"Identified {len(path_hints)} candidate preference/database/log paths.",
                    evidence=tuple(evidence[:4]),
                    metrics={"paths": path_hints},
                    remediate="Prioritise pulling these files during triage to capture tokens and activity logs.",
                )
            )

        if permission_hints:
            findings.append(
                Finding(
                    finding_id="dfir_permission_hypothesis",
                    title="Permissions imply sensitive runtime stores",
                    severity_gate=SeverityLevel.NOTE,
                    category_masvs=MasvsCategory.PRIVACY,
                    status=Badge.INFO,
                    because="Dangerous permissions map to likely on-device data locations.",
                    metrics={"predicted_locations": permission_hints},
                    remediate="Plan minimal adb pulls to validate the presence of these artefacts after dynamic testing.",
                )
            )

        metrics = {
            "path_hint_count": len(path_hints),
            "permission_hint_count": len(permission_hints),
        }

        badge = Badge.OK
        if findings:
            badge = Badge.INFO

        return make_detector_result(
            detector_id=self.detector_id,
            section_key=self.section_key,
            status=badge,
            started_at=started,
            findings=tuple(findings),
            metrics=metrics,
            evidence=tuple(evidence[:4]),
        )


__all__ = ["DfirHintsDetector"]