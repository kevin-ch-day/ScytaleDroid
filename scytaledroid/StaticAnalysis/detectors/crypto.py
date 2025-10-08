"""Cryptography hygiene detector."""

from __future__ import annotations

import re
from dataclasses import dataclass
from time import perf_counter
from typing import Dict, Sequence

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
from ..modules.string_analysis.extractor import IndexedString
from .base import BaseDetector, register_detector


@dataclass(frozen=True)
class CryptoPattern:
    name: str
    regex: re.Pattern[str]
    severity: SeverityLevel
    badge: Badge
    title: str
    remediation: str
    category: MasvsCategory = MasvsCategory.CRYPTO
    because: str = ""


_CRYPTO_PATTERNS: tuple[CryptoPattern, ...] = (
    CryptoPattern(
        name="aes_ecb",
        regex=re.compile(r"AES/ECB", re.IGNORECASE),
        severity=SeverityLevel.P0,
        badge=Badge.FAIL,
        title="AES in ECB mode",
        remediation="Use AES-GCM or AES-CBC with random IVs instead of ECB.",
        because="AES/ECB leaks structure of plaintext blocks.",
    ),
    CryptoPattern(
        name="des_usage",
        regex=re.compile(r"DES/(ECB|CBC)?", re.IGNORECASE),
        severity=SeverityLevel.P0,
        badge=Badge.FAIL,
        title="DES cipher usage",
        remediation="Replace DES with AES-256 or modern primitives.",
        because="DES is cryptographically broken and should not protect secrets.",
    ),
    CryptoPattern(
        name="md5_digest",
        regex=re.compile(r"MD5", re.IGNORECASE),
        severity=SeverityLevel.P1,
        badge=Badge.WARN,
        title="MD5 message digest",
        remediation="Use SHA-256 or better message digests.",
        because="MD5 is collision-prone and unsuitable for integrity.",
    ),
    CryptoPattern(
        name="sha1_digest",
        regex=re.compile(r"SHA-1", re.IGNORECASE),
        severity=SeverityLevel.P1,
        badge=Badge.WARN,
        title="SHA-1 message digest",
        remediation="Use SHA-256 or SHA-3 families for hashing.",
        because="SHA-1 collisions are practical; avoid for security decisions.",
    ),
    CryptoPattern(
        name="sha1prng",
        regex=re.compile(r"SHA1PRNG", re.IGNORECASE),
        severity=SeverityLevel.P2,
        badge=Badge.INFO,
        title="SecureRandom SHA1PRNG",
        remediation="Use default SecureRandom without explicit provider or use ChaCha20.",
        because="SHA1PRNG has predictability issues on some Android versions.",
    ),
)


def _scan_pattern(
    pattern: CryptoPattern, index_entries: Sequence[IndexedString]
) -> list[IndexedString]:
    matches: list[IndexedString] = []
    seen: set[str] = set()
    for entry in index_entries:
        if entry.sha256 in seen:
            continue
        if pattern.regex.search(entry.value):
            seen.add(entry.sha256)
            matches.append(entry)
    return matches


def _build_finding(
    pattern: CryptoPattern,
    matches: Sequence[IndexedString],
    *,
    apk_path,
) -> Finding:
    evidence = [
        EvidencePointer(
            location=f"{apk_path.resolve().as_posix()}!string[{entry.origin}]",
            hash_short=f"#h:{entry.sha256[:8]}",
            description=f"{pattern.name} → {entry.origin}",
            extra={"origin_type": entry.origin_type},
        )
        for entry in matches[:2]
    ]

    because = pattern.because
    if len(matches) > 2:
        because += f" ({len(matches)} occurrences)"

    return Finding(
        finding_id=f"crypto_{pattern.name}",
        title=pattern.title,
        severity_gate=pattern.severity,
        category_masvs=pattern.category,
        status=pattern.badge,
        because=because,
        evidence=tuple(evidence),
        remediate=pattern.remediation,
        metrics={"match_count": len(matches)},
        tags=("crypto", pattern.name),
    )


@register_detector
class CryptoHygieneDetector(BaseDetector):
    """Summarises cipher/digest usage."""

    detector_id = "crypto_hygiene"
    name = "Crypto hygiene detector"
    default_profiles = ("quick", "full")
    section_key = "crypto_hygiene"

    def run(self, context: DetectorContext) -> DetectorResult:
        started = perf_counter()
        index = context.string_index
        if index is None or index.is_empty():
            return make_detector_result(
                detector_id=self.detector_id,
                section_key=self.section_key,
                status=Badge.SKIPPED,
                started_at=started,
                findings=tuple(),
                metrics={"skip_reason": "string index unavailable"},
                evidence=tuple(),
            )

        findings: list[Finding] = []
        metrics: Dict[str, object] = {}

        for pattern in _CRYPTO_PATTERNS:
            matches = _scan_pattern(pattern, index.strings)
            if not matches:
                continue
            findings.append(
                _build_finding(pattern, matches, apk_path=context.apk_path)
            )
            metrics[pattern.name] = len(matches)

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
            findings=tuple(findings),
            metrics=metrics,
            evidence=tuple(
                pointer
                for finding in findings
                for pointer in finding.evidence
            )[:4],
        )


__all__ = ["CryptoHygieneDetector"]
