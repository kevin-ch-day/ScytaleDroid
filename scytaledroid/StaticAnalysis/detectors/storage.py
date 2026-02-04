"""Storage and backup posture detector."""

from __future__ import annotations

import re
from collections.abc import Mapping, Sequence
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

_SENSITIVE_KEY = re.compile(r"(token|secret|auth|session|cookie|credential)", re.IGNORECASE)


def _detect_sensitive_keys(context: DetectorContext) -> Sequence[EvidencePointer]:
    index = context.string_index
    if index is None or index.is_empty():
        return tuple()

    pointers: list[EvidencePointer] = []
    seen: set[str] = set()

    for entry in index.strings:
        if len(entry.value) > 80:
            continue
        if entry.sha256 in seen:
            continue
        if not _SENSITIVE_KEY.search(entry.value):
            continue
        if not any(token in entry.value.lower() for token in ("pref", "key", "token", "secret")):
            continue
        seen.add(entry.sha256)
        pointers.append(
            EvidencePointer(
                location=f"{context.apk_path.resolve().as_posix()}!string[{entry.origin}]",
                hash_short=f"#h:{entry.sha256[:8]}",
                description=f"Potential sensitive key '{entry.value[:40]}'",
                extra={"origin_type": entry.origin_type},
            )
        )
        if len(pointers) >= 5:
            break

    return tuple(pointers)


def _build_findings(context: DetectorContext, key_evidence: Sequence[EvidencePointer]) -> Sequence[Finding]:
    findings: list[Finding] = []
    flags = context.manifest_flags

    if flags.allow_backup:
        findings.append(
            Finding(
                finding_id="storage_allow_backup",
                title="Application allows Android backup",
                severity_gate=SeverityLevel.P1,
                category_masvs=MasvsCategory.STORAGE,
                status=Badge.WARN,
                because="android:allowBackup is true; user data may leak via adb backup.",
                remediate="Disable backups or provide custom BackupAgent filtering secrets.",
            )
        )

    if flags.request_legacy_external_storage:
        findings.append(
            Finding(
                finding_id="storage_legacy_external",
                title="Legacy external storage requested",
                severity_gate=SeverityLevel.P1,
                category_masvs=MasvsCategory.STORAGE,
                status=Badge.WARN,
                because="requestLegacyExternalStorage=true keeps scoped storage disabled.",
                remediate="Adopt scoped storage or justify legacy flag for backwards compatibility.",
            )
        )

    if key_evidence:
        findings.append(
            Finding(
                finding_id="storage_sensitive_keys",
                title="Potential sensitive preference keys",
                severity_gate=SeverityLevel.P2,
                category_masvs=MasvsCategory.STORAGE,
                status=Badge.INFO,
                because="Keys referencing tokens/secrets detected in resources or code.",
                evidence=tuple(key_evidence),
                remediate="Ensure sensitive tokens are encrypted or stored within Android Keystore-backed preferences.",
            )
        )

    return tuple(findings)


def _build_metrics(
    context: DetectorContext,
    key_evidence: Sequence[EvidencePointer],
) -> Mapping[str, object]:
    flags = context.manifest_flags
    return {
        "allow_backup": flags.allow_backup,
        "legacy_external_storage": flags.request_legacy_external_storage,
        "full_backup_content": flags.full_backup_content,
        "sensitive_keys": len(key_evidence),
    }


@register_detector
class StorageBackupDetector(BaseDetector):
    """Highlights plaintext storage and backup posture."""

    detector_id = "storage_backup"
    name = "Storage & Backup detector"
    default_profiles = ("quick", "full")
    section_key = "storage_backup"

    def run(self, context: DetectorContext) -> DetectorResult:
        started = perf_counter()
        key_evidence = _detect_sensitive_keys(context)
        findings = _build_findings(context, key_evidence)
        metrics = _build_metrics(context, key_evidence)

        badge = Badge.OK
        if any(f.status is Badge.FAIL for f in findings):
            badge = Badge.FAIL
        elif any(f.status is Badge.WARN for f in findings):
            badge = Badge.WARN
        elif findings:
            badge = Badge.INFO

        return make_detector_result(
            detector_id=self.detector_id,
            section_key=self.section_key,
            status=badge,
            started_at=started,
            findings=findings,
            metrics=metrics,
            evidence=key_evidence,
        )


__all__ = ["StorageBackupDetector"]