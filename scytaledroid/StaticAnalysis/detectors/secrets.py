"""Secrets & credentials detector leveraging string-index patterns."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from time import perf_counter
from typing import Dict, Iterable, List, Mapping, MutableMapping, Sequence

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
from ..modules.string_analysis.patterns import DEFAULT_PATTERNS, StringPattern
from .base import BaseDetector, register_detector


_TEST_HINTS = (
    "test",
    "dummy",
    "sample",
    "example",
    "fake",
    "demo",
    "staging",
    "sandbox",
    "placeholder",
    "replace",
    "your",
)


@dataclass(frozen=True)
class _SecretMatch:
    """Internal representation of a pattern hit."""

    pattern: StringPattern
    string_entry: IndexedString
    value_fragment: str
    is_test_like: bool


def _detect_matches(strings: Sequence[IndexedString]) -> Sequence[_SecretMatch]:
    hits: List[_SecretMatch] = []
    for entry in strings:
        value = entry.value
        if not value:
            continue
        for pattern in DEFAULT_PATTERNS:
            if not pattern.pattern.search(value):
                continue
            # Collect distinct fragments for this pattern within the string.
            for match in pattern.pattern.finditer(value):
                fragment = match.group(0)
                if not _is_valid_for_pattern(pattern.name, fragment):
                    continue
                is_test = _is_test_like(fragment, entry)
                hits.append(
                    _SecretMatch(
                        pattern=pattern,
                        string_entry=entry,
                        value_fragment=fragment,
                        is_test_like=is_test,
                    )
                )
    return tuple(hits)


def _is_test_like(fragment: str, entry: IndexedString) -> bool:
    lowered = fragment.lower()
    if any(token in lowered for token in _TEST_HINTS):
        return True
    if fragment.startswith("sk_test_"):
        return True
    if lowered.startswith("sq0dev-") or lowered.startswith("sq0csp-"):
        return True
    # Placeholder style strings that include the origin can be treated as test data.
    composite = f"{entry.origin}:{entry.value}".lower()
    if "example.com" in composite or "localhost" in composite:
        return True
    return False


def _is_valid_for_pattern(pattern_name: str, fragment: str) -> bool:
    if pattern_name == "aws_secret_key":
        upper = sum(1 for char in fragment if char.isupper())
        lower = sum(1 for char in fragment if char.islower())
        digits = sum(1 for char in fragment if char.isdigit())
        if upper < 4 or lower < 4 or digits < 4:
            return False
    if pattern_name == "generic_bearer":
        if len(fragment.split()) <= 1:
            return False
    if pattern_name == "google_oauth_client":
        # Avoid matching guidance strings such as {client-id}.apps.googleusercontent.com
        if "{" in fragment or "}" in fragment:
            return False
    return True


def _group_matches(matches: Iterable[_SecretMatch]) -> Mapping[str, Sequence[_SecretMatch]]:
    grouped: MutableMapping[str, List[_SecretMatch]] = {}
    dedupe: MutableMapping[tuple[str, str], bool] = {}
    for match in matches:
        key = (match.pattern.name, match.string_entry.sha256)
        if key in dedupe:
            continue
        dedupe[key] = True
        grouped.setdefault(match.pattern.name, []).append(match)
    return {name: tuple(entries) for name, entries in grouped.items()}


def _build_metrics(grouped: Mapping[str, Sequence[_SecretMatch]]) -> Dict[str, object]:
    secret_types: Dict[str, Dict[str, int]] = {}
    for pattern_name, entries in sorted(grouped.items()):
        real = [entry for entry in entries if not entry.is_test_like]
        filtered = len(entries) - len(real)
        secret_types[pattern_name] = {
            "found": len(real),
            "filtered": filtered,
        }

    matched_strings = sum(len(entries) for entries in grouped.values())
    real_strings = sum(
        len([entry for entry in entries if not entry.is_test_like])
        for entries in grouped.values()
    )

    return {
        "secret_types": secret_types,
        "matched_strings": matched_strings,
        "real_strings": real_strings,
        "filtered_strings": matched_strings - real_strings,
    }


def _string_pointer(
    entry: IndexedString,
    *,
    apk_path: Path,
    pattern: StringPattern | None,
) -> EvidencePointer:
    base_location = apk_path.resolve().as_posix()
    extra: Dict[str, object] = {
        "origin": entry.origin,
        "origin_type": entry.origin_type,
    }
    if pattern is not None:
        extra["pattern"] = pattern.name
    return EvidencePointer(
        location=f"{base_location}!string[{entry.origin}]",
        hash_short=f"#h:{entry.sha256[:8]}",
        description=f"{entry.origin} #h:{entry.sha256[:12]}",
        extra=extra,
    )


def _collect_result_evidence(
    grouped: Mapping[str, Sequence[_SecretMatch]],
    *,
    apk_path: Path,
    limit: int = 2,
) -> Sequence[EvidencePointer]:
    pointers: List[EvidencePointer] = []
    for _, entries in sorted(grouped.items()):
        for match in entries:
            if match.is_test_like:
                continue
            pointers.append(
                _string_pointer(
                    match.string_entry,
                    apk_path=apk_path,
                    pattern=match.pattern,
                )
            )
            if len(pointers) >= limit:
                return tuple(pointers)
    return tuple(pointers)


def _build_findings(
    grouped: Mapping[str, Sequence[_SecretMatch]],
    *,
    apk_path: Path,
) -> Sequence[Finding]:
    findings: List[Finding] = []

    for pattern_name, entries in sorted(grouped.items()):
        real_entries = [entry for entry in entries if not entry.is_test_like]
        if not real_entries:
            continue
        pattern = real_entries[0].pattern
        sample = real_entries[0].string_entry
        count = len(real_entries)
        summary = (
            f"Detected {count} potential secret{'' if count == 1 else 's'} matching "
            f"{pattern.description.lower()}."
        )

        supporting_hashes = [entry.string_entry.sha256 for entry in real_entries[:10]]
        filtered = len(entries) - count
        pointer = _string_pointer(sample, apk_path=apk_path, pattern=pattern)

        metrics_payload = {
            "hashes": supporting_hashes,
            "filtered": filtered,
            "origin_types": sorted({entry.string_entry.origin_type for entry in real_entries}),
        }

        findings.append(
            Finding(
                finding_id=f"secret_{pattern_name}",
                title=f"{pattern.description}",
                severity_gate=SeverityLevel.P1,
                category_masvs=MasvsCategory.PRIVACY,
                status=Badge.WARN,
                because=summary,
                evidence=(pointer,),
                remediate="Rotate the credential and remove hardcoded secrets from the artifact.",
                metrics=metrics_payload,
                tags=("secret", pattern_name),
            )
        )

    return tuple(findings)


@register_detector
class SecretsDetector(BaseDetector):
    """Detector that surfaces potential hardcoded credentials."""

    detector_id = "secrets_credentials"
    name = "Secrets & Credentials detector"
    default_profiles = ("quick", "full")
    section_key = "secrets"

    def run(self, context: DetectorContext) -> DetectorResult:
        started = perf_counter()
        index = context.string_index
        if index is None or index.is_empty():
            metrics = {
                "matched_strings": 0,
                "real_strings": 0,
                "filtered_strings": 0,
                "status": "ok",
            }
            return make_detector_result(
                detector_id=self.detector_id,
                section_key=self.section_key,
                status=Badge.OK,
                started_at=started,
                findings=tuple(),
                metrics={key: value for key, value in metrics.items() if key != "status"},
                evidence=tuple(),
            )

        matches = _detect_matches(index.strings)
        grouped = _group_matches(matches)
        metrics = _build_metrics(grouped)
        findings = _build_findings(grouped, apk_path=context.apk_path)
        evidence = _collect_result_evidence(grouped, apk_path=context.apk_path)

        # Downgrade severity when nothing real remains.
        if not findings and metrics["filtered_strings"]:
            metrics["status"] = "filtered"
        elif findings:
            metrics["status"] = "warn"
        else:
            metrics["status"] = "ok"

        status_key = str(metrics.get("status", "ok")).lower()
        badge = {
            "warn": Badge.WARN,
            "ok": Badge.OK,
            "filtered": Badge.INFO,
        }.get(status_key, Badge.INFO)

        metrics_payload = dict(metrics)
        metrics_payload.pop("status", None)

        return make_detector_result(
            detector_id=self.detector_id,
            section_key=self.section_key,
            status=badge,
            started_at=started,
            findings=findings,
            metrics=metrics_payload,
            evidence=evidence,
        )


__all__ = ["SecretsDetector"]
