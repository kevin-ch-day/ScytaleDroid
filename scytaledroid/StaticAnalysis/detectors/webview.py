"""WebView hardening detector."""

from __future__ import annotations

import re
from collections.abc import Sequence
from dataclasses import dataclass
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
from ..core.results_builder import make_detector_result
from ..modules.string_analysis.extractor import IndexedString
from .base import BaseDetector, register_detector


@dataclass(frozen=True)
class WebViewPattern:
    name: str
    regex: re.Pattern[str]
    severity: SeverityLevel
    badge: Badge
    title: str
    because: str
    remediation: str


_WEBVIEW_PATTERNS: tuple[WebViewPattern, ...] = (
    WebViewPattern(
        name="add_javascript_interface",
        regex=re.compile(r"addJavascriptInterface", re.IGNORECASE),
        severity=SeverityLevel.P1,
        badge=Badge.WARN,
        title="JavaScript interface exposed",
        because="addJavascriptInterface allows Java objects to be callable from JS.",
        remediation="Annotate interfaces with @JavascriptInterface and restrict to trusted content.",
    ),
    WebViewPattern(
        name="universal_file_access",
        regex=re.compile(r"setAllowUniversalAccessFromFileURLs", re.IGNORECASE),
        severity=SeverityLevel.P0,
        badge=Badge.FAIL,
        title="Universal file access enabled",
        because="Universal access from file URLs exposes local file APIs to injected scripts.",
        remediation="Avoid enabling universal file access; serve content over https.",
    ),
    WebViewPattern(
        name="javascript_enabled",
        regex=re.compile(r"setJavaScriptEnabled", re.IGNORECASE),
        severity=SeverityLevel.P2,
        badge=Badge.INFO,
        title="JavaScript explicitly enabled",
        because="WebView JavaScript execution increases XSS risk; review content sources.",
        remediation="Only enable JavaScript for trusted content and disable for other views.",
    ),
    WebViewPattern(
        name="mixed_content",
        regex=re.compile(r"setMixedContentMode", re.IGNORECASE),
        severity=SeverityLevel.P1,
        badge=Badge.WARN,
        title="Mixed content mode modified",
        because="setMixedContentMode may allow HTTP content inside HTTPS WebView.",
        remediation="Keep mixed content mode to NEVER_ALLOW for production builds.",
    ),
)


def _collect_matches(index_entries: Sequence[IndexedString], pattern: WebViewPattern) -> list[IndexedString]:
    hits: list[IndexedString] = []
    seen: set[str] = set()
    for entry in index_entries:
        if entry.sha256 in seen:
            continue
        if pattern.regex.search(entry.value):
            seen.add(entry.sha256)
            hits.append(entry)
    return hits


def _build_finding(
    pattern: WebViewPattern,
    matches: Sequence[IndexedString],
    *,
    apk_path,
) -> Finding:
    evidence = [
        EvidencePointer(
            location=f"{apk_path.resolve().as_posix()}!string[{entry.origin}]",
            hash_short=f"#h:{entry.sha256[:8]}",
            description=f"{pattern.name} in {entry.origin}",
            extra={"origin_type": entry.origin_type},
        )
        for entry in matches[:2]
    ]

    because = pattern.because
    if len(matches) > 1:
        because += f" ({len(matches)} occurrences)"

    return Finding(
        finding_id=f"webview_{pattern.name}",
        title=pattern.title,
        severity_gate=pattern.severity,
        category_masvs=MasvsCategory.NETWORK,
        status=pattern.badge,
        because=because,
        evidence=tuple(evidence),
        remediate=pattern.remediation,
        metrics={"matches": len(matches)},
        tags=("webview", pattern.name),
    )


@register_detector
class WebViewDetector(BaseDetector):
    """Summarises WebView configuration."""

    detector_id = "webview_hygiene"
    name = "WebView hygiene detector"
    default_profiles = ("quick", "full")
    section_key = "webview"

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
        metrics: dict[str, object] = {}

        for pattern in _WEBVIEW_PATTERNS:
            matches = _collect_matches(index.strings, pattern)
            if not matches:
                continue
            findings.append(_build_finding(pattern, matches, apk_path=context.apk_path))
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


__all__ = ["WebViewDetector"]