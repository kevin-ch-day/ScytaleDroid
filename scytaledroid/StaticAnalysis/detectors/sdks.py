"""Offline SDK / tracker overlap inventory built from static strings and local receipts."""

from __future__ import annotations

import json
import re
from collections import Counter, defaultdict
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass
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
from ..core.results_builder import make_detector_result
from ..modules.string_analysis import IndexedString, StringIndex
from ..modules.string_analysis.network import extract_endpoints
from .base import BaseDetector, register_detector

_REPO_ROOT = Path(__file__).resolve().parents[3]
_TRACKER_RECEIPT_DIR = _REPO_ROOT / "data" / "state" / "external_sdk_tracker_intel"
_TRACKER_RECEIPT_GLOB = "external_sdk_tracker_intel_refresh_*.json"
_COMMON_TWO_PART_SUFFIXES = {
    "co.uk",
    "org.uk",
    "gov.uk",
    "ac.uk",
    "com.au",
    "net.au",
    "org.au",
    "edu.au",
    "co.jp",
    "com.br",
}
_NAMESPACE_PATTERN = re.compile(
    r"\b[a-zA-Z_][a-zA-Z0-9_$]*(?:\.[a-zA-Z0-9_$]+){2,}\b"
)


@dataclass(frozen=True)
class TrackerIntelRow:
    tracker_name: str
    code_tokens: tuple[str, ...]
    domain_tokens: tuple[str, ...]
    categories: tuple[str, ...]


def _latest_tracker_receipt_path() -> Path | None:
    candidates = sorted(_TRACKER_RECEIPT_DIR.glob(_TRACKER_RECEIPT_GLOB))
    if not candidates:
        return None
    return candidates[-1]


def _approx_root_domain(host: str) -> str:
    text = str(host or "").strip().lower().strip(".")
    if "." not in text:
        return text
    parts = [part for part in text.split(".") if part]
    if len(parts) < 2:
        return text
    tail = ".".join(parts[-2:])
    if len(parts) >= 3 and tail in _COMMON_TWO_PART_SUFFIXES:
        return ".".join(parts[-3:])
    return tail


def _normalize_code_token(value: object) -> str | None:
    text = str(value or "").strip().lower()
    if not text:
        return None
    text = text.replace("/", ".").strip()
    while ".." in text:
        text = text.replace("..", ".")
    text = text.strip(".")
    if not text or "." not in text:
        return None
    if not re.fullmatch(r"[a-z0-9_$]+(?:\.[a-z0-9_$]+)+", text):
        return None
    return text


def _extract_code_tokens(raw_value: object) -> tuple[str, ...]:
    tokens: list[str] = []
    seen: set[str] = set()
    for raw in str(raw_value or "").split("|"):
        normalized = _normalize_code_token(raw)
        if not normalized or normalized in seen:
            continue
        seen.add(normalized)
        tokens.append(normalized)
    return tuple(tokens)


def _extract_domain_tokens(raw_value: object) -> tuple[str, ...]:
    tokens: list[str] = []
    seen: set[str] = set()
    for raw in str(raw_value or "").split("|"):
        text = raw.strip()
        if not text:
            continue
        text = text.replace("\\.", ".").replace("\\-", "-").replace("\\_", "_")
        text = text.replace(".*.", "").replace(".*", "")
        text = text.lstrip(".^").rstrip("$").replace("\\", "").strip(". ")
        if not text or "." not in text:
            continue
        if not re.fullmatch(r"[a-z0-9._-]+", text.lower()):
            continue
        root = _approx_root_domain(text)
        if not root or root in seen:
            continue
        seen.add(root)
        tokens.append(root)
    return tuple(tokens)


def _extract_categories(raw_value: object) -> tuple[str, ...]:
    if isinstance(raw_value, list):
        items = raw_value
    elif isinstance(raw_value, str) and raw_value.strip():
        try:
            parsed = json.loads(raw_value)
        except json.JSONDecodeError:
            parsed = []
        items = parsed if isinstance(parsed, list) else []
    else:
        items = []
    out: list[str] = []
    seen: set[str] = set()
    for item in items:
        text = str(item or "").strip()
        if not text:
            continue
        key = text.casefold()
        if key in seen:
            continue
        seen.add(key)
        out.append(text)
    return tuple(out)


def _load_tracker_rows(receipt_path: Path) -> tuple[tuple[TrackerIntelRow, ...], dict[str, object]]:
    payload = json.loads(receipt_path.read_text(encoding="utf-8"))
    rows = payload.get("rows")
    if not isinstance(rows, list):
        rows = []
    summary = payload.get("summary")
    summary_map = dict(summary) if isinstance(summary, Mapping) else {}
    parsed_rows: list[TrackerIntelRow] = []
    for row in rows:
        if not isinstance(row, Mapping):
            continue
        tracker_name = str(
            row.get("tracker_name")
            or row.get("name")
            or row.get("tracker_id_external")
            or "unknown_tracker"
        ).strip()
        code_tokens = _extract_code_tokens(row.get("code_signature"))
        domain_tokens = _extract_domain_tokens(row.get("network_signature"))
        categories = _extract_categories(row.get("categories") or row.get("categories_json"))
        if not code_tokens and not domain_tokens:
            continue
        parsed_rows.append(
            TrackerIntelRow(
                tracker_name=tracker_name,
                code_tokens=code_tokens,
                domain_tokens=domain_tokens,
                categories=categories,
            )
        )
    return tuple(parsed_rows), summary_map


def _collect_namespace_hits(index: StringIndex | None) -> dict[str, list[IndexedString]]:
    if index is None or index.is_empty():
        return {}
    hits: dict[str, list[IndexedString]] = defaultdict(list)
    for entry in index.strings:
        value = str(entry.value or "")
        if "." not in value or len(value) > 240:
            continue
        for match in _NAMESPACE_PATTERN.finditer(value):
            token = _normalize_code_token(match.group(0))
            if not token:
                continue
            bucket = hits[token]
            if len(bucket) < 3:
                bucket.append(entry)
    return hits


def _matches_code_token(observed: str, tracker_token: str) -> bool:
    return observed == tracker_token or observed.startswith(f"{tracker_token}.")


def _evidence_from_entry(entry: IndexedString, *, description: str, extra: Mapping[str, object]) -> EvidencePointer:
    return EvidencePointer(
        location=entry.pointer,
        hash_short=entry.sha_short,
        description=description,
        extra=dict(extra),
    )


@register_detector
class SdkInventoryDetector(BaseDetector):
    """Summarise contextual tracker/SDK overlap from static evidence."""

    detector_id = "sdk_inventory"
    name = "SDK / Tracker detector"
    default_profiles = ("full",)
    section_key = "sdk_inventory"

    def run(self, context: DetectorContext) -> DetectorResult:
        started = perf_counter()
        receipt_path = _latest_tracker_receipt_path()
        notes: list[str] = [
            "Tracker overlap uses the latest local Exodus receipt as contextual reference data; matches are not proof of runtime execution."
        ]
        findings: list[Finding] = []
        evidence: list[EvidencePointer] = []
        subitems: list[dict[str, object]] = []

        namespace_hits = _collect_namespace_hits(context.string_index)
        namespace_total = len(namespace_hits)
        endpoints = extract_endpoints(context.string_index) if context.string_index is not None else ()
        endpoint_roots: dict[str, list[object]] = defaultdict(list)
        for endpoint in endpoints:
            root = _approx_root_domain(endpoint.host)
            if root and len(endpoint_roots[root]) < 3:
                endpoint_roots[root].append(endpoint)

        metrics: dict[str, object] = {
            "External tracker intel": {
                "receipt_available": bool(receipt_path),
                "receipt_path": receipt_path.as_posix() if receipt_path else None,
            },
            "Observed signals": {
                "namespace_candidates": namespace_total,
                "http_endpoint_candidates": len(endpoints),
                "root_domains_observed": len(endpoint_roots),
                "declared_libraries": len(tuple(context.libraries or ())),
            },
        }

        if receipt_path is None:
            notes.append(
                "No local tracker-intel receipt found under data/state/external_sdk_tracker_intel; overlap analysis was skipped."
            )
            return make_detector_result(
                detector_id=self.detector_id,
                section_key=self.section_key,
                status=Badge.INFO,
                started_at=started,
                findings=tuple(),
                metrics=metrics,
                evidence=tuple(),
                notes=tuple(notes),
            )

        tracker_rows, tracker_summary = _load_tracker_rows(receipt_path)
        metrics["External tracker intel"] = {
            **metrics["External tracker intel"],
            "snapshot_date": tracker_summary.get("snapshot_date"),
            "tracker_rows": len(tracker_rows),
            "rows_with_code_signature": int(tracker_summary.get("rows_with_code_signature") or 0),
            "rows_with_network_signature": int(tracker_summary.get("rows_with_network_signature") or 0),
        }

        matched_code_trackers: list[TrackerIntelRow] = []
        matched_network_trackers: list[TrackerIntelRow] = []
        category_counter: Counter[str] = Counter()
        matched_tracker_names: set[str] = set()

        for tracker in tracker_rows:
            code_match = False
            domain_match = False
            matched_namespaces: list[str] = []
            matched_roots: list[str] = []

            for tracker_token in tracker.code_tokens:
                for observed, entries in namespace_hits.items():
                    if not _matches_code_token(observed, tracker_token):
                        continue
                    matched_namespaces.append(observed)
                    if entries:
                        evidence.append(
                            _evidence_from_entry(
                                entries[0],
                                description="Namespace-like string overlapping tracker code signature",
                                extra={"tracker": tracker.tracker_name, "namespace": observed},
                            )
                        )
                    code_match = True
                    if len(matched_namespaces) >= 3:
                        break
                if len(matched_namespaces) >= 3:
                    break

            for domain_token in tracker.domain_tokens:
                endpoint_matches = endpoint_roots.get(domain_token) or []
                if not endpoint_matches:
                    continue
                matched_roots.append(domain_token)
                endpoint = endpoint_matches[0]
                evidence.append(
                    _evidence_from_entry(
                        endpoint.string_entry,
                        description="Endpoint root-domain overlapping tracker network signature",
                        extra={"tracker": tracker.tracker_name, "root_domain": domain_token},
                    )
                )
                domain_match = True
                if len(matched_roots) >= 3:
                    break

            if not code_match and not domain_match:
                continue

            matched_tracker_names.add(tracker.tracker_name)
            category_counter.update(tracker.categories)
            if code_match:
                matched_code_trackers.append(tracker)
            if domain_match:
                matched_network_trackers.append(tracker)
            subitems.append(
                {
                    "tracker": tracker.tracker_name,
                    "categories": ", ".join(tracker.categories) or None,
                    "code_overlap": ", ".join(sorted(dict.fromkeys(matched_namespaces))) or None,
                    "network_overlap": ", ".join(sorted(dict.fromkeys(matched_roots))) or None,
                }
            )

        if matched_code_trackers:
            findings.append(
                Finding(
                    finding_id="sdk_inventory_tracker_namespace_overlap",
                    title="Static namespace overlap with tracker/SDK reference intel",
                    severity_gate=SeverityLevel.NOTE,
                    category_masvs=MasvsCategory.PRIVACY,
                    status=Badge.INFO,
                    because=(
                        f"{len(matched_code_trackers)} tracker reference entries overlapped namespace-like "
                        "strings inside the APK. This is contextual evidence only and should be verified against code paths."
                    ),
                    evidence=tuple(evidence[:2]),
                    tags=("sdk_inventory", "tracker_intel", "namespace_overlap"),
                )
            )
        if matched_network_trackers:
            start_index = 2 if matched_code_trackers else 0
            findings.append(
                Finding(
                    finding_id="sdk_inventory_tracker_network_overlap",
                    title="Endpoint overlap with tracker network reference intel",
                    severity_gate=SeverityLevel.NOTE,
                    category_masvs=MasvsCategory.NETWORK,
                    status=Badge.INFO,
                    because=(
                        f"{len(matched_network_trackers)} tracker reference entries overlapped root domains "
                        "from extracted HTTP(S) strings. This indicates contextual network similarity, not confirmed tracking behavior."
                    ),
                    evidence=tuple(evidence[start_index : start_index + 2]),
                    tags=("sdk_inventory", "tracker_intel", "network_overlap"),
                )
            )

        if context.string_index is None:
            notes.append("String index was unavailable for this artifact, so overlap coverage is reduced.")
        elif not namespace_hits and not endpoints:
            notes.append("No namespace-like strings or HTTP(S) endpoints were available for overlap matching.")
        if matched_tracker_names:
            notes.append(
                f"Matched tracker references: {', '.join(sorted(matched_tracker_names)[:6])}"
                + (" ..." if len(matched_tracker_names) > 6 else "")
            )

        metrics["Overlap counts"] = {
            "matched_tracker_rows": len(matched_tracker_names),
            "code_signature_matches": len(matched_code_trackers),
            "network_signature_matches": len(matched_network_trackers),
        }
        metrics["Matched trackers"] = sorted(matched_tracker_names)[:12]
        metrics["Top categories"] = [
            {"category": category, "match_count": count}
            for category, count in category_counter.most_common(6)
        ]

        status = Badge.INFO if matched_tracker_names or context.string_index is None else Badge.OK
        return make_detector_result(
            detector_id=self.detector_id,
            section_key=self.section_key,
            status=status,
            started_at=started,
            findings=tuple(findings),
            metrics=metrics,
            evidence=tuple(evidence[:8]),
            notes=tuple(notes),
            subitems=tuple(subitems[:12]),
        )


__all__ = ["SdkInventoryDetector"]
