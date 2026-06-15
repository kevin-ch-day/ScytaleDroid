"""Shared string-analysis payload helpers for static CLI execution flows."""

from __future__ import annotations

from collections import Counter, defaultdict
from collections.abc import Callable, Mapping, Sequence

from scytaledroid.Utils.LoggingUtils import logging_engine

from ...engine.strings import analyse_strings as _default_analyse_strings
from ...modules.string_analysis import BUCKET_ORDER, StringHit, build_bucket_overview
from ...modules.string_analysis.selection import select_samples
from ..core.models import RunParameters

_SAMPLE_FIELDS = (
    "value",
    "value_masked",
    "src",
    "tag",
    "sha256",
    "finding_type",
    "provider",
    "risk_tag",
    "confidence",
    "scheme",
    "root_domain",
    "resource_name",
    "source_type",
    "sample_hash",
    "xref_context",
    "api_context",
    "posture",
    "ownership_class",
    "pair_group",
    "verification_status",
    "dynamic_corroboration",
)


def empty_string_analysis_payload(*, warning: str | None = None) -> Mapping[str, object]:
    warnings = [warning] if warning else []
    return {
        "counts": {},
        "samples": {},
        "selected_samples": {},
        "selection_params": {},
        "extra_counts": {},
        "regex_skipped": 0,
        "noise_counts": {},
        "aggregates": {},
        "structured": {},
        "warnings": warnings,
        "resource_strings_skipped": False,
        "options": {},
        "aggregation_scope": "empty",
    }


def _with_aggregation_scope(
    payload: Mapping[str, object],
    *,
    scope: str,
) -> Mapping[str, object]:
    copied = dict(payload)
    copied.setdefault("aggregation_scope", scope)
    return copied


def _int_mapping(value: object) -> dict[str, int]:
    if not isinstance(value, Mapping):
        return {}
    out: dict[str, int] = {}
    for key, raw in value.items():
        try:
            out[str(key)] = int(raw)
        except (TypeError, ValueError):
            continue
    return out


def _warnings_list(value: object) -> list[str]:
    if not isinstance(value, Sequence) or isinstance(value, (str, bytes, bytearray)):
        return []
    seen: set[str] = set()
    out: list[str] = []
    for item in value:
        text = str(item or "").strip()
        if not text or text in seen:
            continue
        seen.add(text)
        out.append(text)
    return out


def _sample_key(entry: Mapping[str, object]) -> tuple[object, ...]:
    return tuple(entry.get(field) for field in _SAMPLE_FIELDS)


def _normalize_sample(entry: Mapping[str, object]) -> dict[str, object]:
    return {field: entry.get(field) for field in _SAMPLE_FIELDS if entry.get(field) is not None}


def _sample_groups(payloads: Sequence[Mapping[str, object]]) -> dict[str, list[dict[str, object]]]:
    merged: dict[str, list[dict[str, object]]] = {}
    seen_per_bucket: dict[str, set[tuple[object, ...]]] = defaultdict(set)
    for payload in payloads:
        raw_samples = payload.get("samples")
        if not isinstance(raw_samples, Mapping):
            continue
        for bucket, entries in raw_samples.items():
            bucket_name = str(bucket)
            if not isinstance(entries, Sequence) or isinstance(entries, (str, bytes, bytearray)):
                continue
            bucket_out = merged.setdefault(bucket_name, [])
            seen = seen_per_bucket[bucket_name]
            for entry in entries:
                if not isinstance(entry, Mapping):
                    continue
                key = _sample_key(entry)
                if key in seen:
                    continue
                seen.add(key)
                bucket_out.append(_normalize_sample(entry))
    for bucket_name, entries in merged.items():
        entries.sort(
            key=lambda item: (
                str(item.get("value") or ""),
                str(item.get("src") or ""),
                str(item.get("tag") or ""),
            )
        )
    return merged


def _string_hits_from_samples(
    sample_groups: Mapping[str, Sequence[Mapping[str, object]]],
) -> dict[str, list[StringHit]]:
    hits_by_bucket: dict[str, list[StringHit]] = {}
    for bucket, entries in sample_groups.items():
        bucket_hits: list[StringHit] = []
        for entry in entries:
            if not isinstance(entry, Mapping):
                continue
            value = str(entry.get("value") or "")
            src = str(entry.get("src") or "")
            bucket_hits.append(
                StringHit(
                    bucket=str(bucket),
                    value=value,
                    src=src,
                    tag=str(entry.get("tag")) if entry.get("tag") is not None else None,
                    sha256=str(entry.get("sha256")) if entry.get("sha256") is not None else None,
                    masked=str(entry.get("value_masked")) if entry.get("value_masked") is not None else None,
                    finding_type=(
                        str(entry.get("finding_type"))
                        if entry.get("finding_type") is not None
                        else None
                    ),
                    provider=str(entry.get("provider")) if entry.get("provider") is not None else None,
                    risk_tag=str(entry.get("risk_tag")) if entry.get("risk_tag") is not None else None,
                    confidence=(
                        str(entry.get("confidence")) if entry.get("confidence") is not None else None
                    ),
                    scheme=str(entry.get("scheme")) if entry.get("scheme") is not None else None,
                    root_domain=(
                        str(entry.get("root_domain")) if entry.get("root_domain") is not None else None
                    ),
                    resource_name=(
                        str(entry.get("resource_name"))
                        if entry.get("resource_name") is not None
                        else None
                    ),
                    source_type=(
                        str(entry.get("source_type"))
                        if entry.get("source_type") is not None
                        else None
                    ),
                    sample_hash=(
                        str(entry.get("sample_hash")) if entry.get("sample_hash") is not None else None
                    ),
                    xref_context=(
                        str(entry.get("xref_context"))
                        if entry.get("xref_context") is not None
                        else None
                    ),
                    api_context=(
                        str(entry.get("api_context"))
                        if entry.get("api_context") is not None
                        else None
                    ),
                    posture=(
                        str(entry.get("posture"))
                        if entry.get("posture") is not None
                        else None
                    ),
                    ownership_class=(
                        str(entry.get("ownership_class"))
                        if entry.get("ownership_class") is not None
                        else None
                    ),
                    pair_group=(
                        str(entry.get("pair_group"))
                        if entry.get("pair_group") is not None
                        else None
                    ),
                    verification_status=(
                        str(entry.get("verification_status"))
                        if entry.get("verification_status") is not None
                        else None
                    ),
                    dynamic_corroboration=(
                        str(entry.get("dynamic_corroboration"))
                        if entry.get("dynamic_corroboration") is not None
                        else None
                    ),
                )
            )
        if bucket_hits:
            hits_by_bucket[str(bucket)] = bucket_hits
    return hits_by_bucket


def _merge_aggregate_rows(
    payloads: Sequence[Mapping[str, object]],
    key: str,
    *,
    identity_fields: Sequence[str],
) -> list[dict[str, object]]:
    merged: list[dict[str, object]] = []
    seen: set[tuple[object, ...]] = set()
    for payload in payloads:
        aggregates = payload.get("aggregates")
        if not isinstance(aggregates, Mapping):
            continue
        rows = aggregates.get(key)
        if not isinstance(rows, Sequence) or isinstance(rows, (str, bytes, bytearray)):
            continue
        for row in rows:
            if not isinstance(row, Mapping):
                continue
            identity = tuple(row.get(field) for field in identity_fields)
            if identity in seen:
                continue
            seen.add(identity)
            merged.append(dict(row))
    return merged


def _merge_endpoint_roots(payloads: Sequence[Mapping[str, object]]) -> list[dict[str, object]]:
    rows_by_root: dict[str, dict[str, object]] = {}
    for payload in payloads:
        aggregates = payload.get("aggregates")
        if not isinstance(aggregates, Mapping):
            continue
        rows = aggregates.get("endpoint_roots")
        if not isinstance(rows, Sequence) or isinstance(rows, (str, bytes, bytearray)):
            continue
        for row in rows:
            if not isinstance(row, Mapping):
                continue
            root = str(row.get("root_domain") or "").strip()
            if not root:
                continue
            target = rows_by_root.setdefault(
                root,
                {
                    "root_domain": root,
                    "total": 0,
                    "schemes": {},
                    "source_types": [],
                },
            )
            try:
                target["total"] = int(target.get("total", 0) or 0) + int(row.get("total", 0) or 0)
            except (TypeError, ValueError):
                pass
            scheme_counts = row.get("schemes")
            if isinstance(scheme_counts, Mapping):
                target_schemes = dict(target.get("schemes") or {})
                for scheme, count in scheme_counts.items():
                    try:
                        target_schemes[str(scheme)] = int(target_schemes.get(str(scheme), 0) or 0) + int(count)
                    except (TypeError, ValueError):
                        continue
                target["schemes"] = dict(sorted(target_schemes.items()))
            source_types = row.get("source_types")
            if isinstance(source_types, Sequence) and not isinstance(source_types, (str, bytes, bytearray)):
                merged_types = set(target.get("source_types") or [])
                merged_types.update(str(item) for item in source_types if str(item or "").strip())
                target["source_types"] = sorted(merged_types)
    return sorted(
        rows_by_root.values(),
        key=lambda row: (-int(row.get("total", 0) or 0), str(row.get("root_domain") or "")),
    )


def _merge_analytics_ids(payloads: Sequence[Mapping[str, object]]) -> dict[str, list[dict[str, object]]]:
    merged: dict[str, dict[str, set[str]]] = defaultdict(lambda: defaultdict(set))
    for payload in payloads:
        aggregates = payload.get("aggregates")
        if not isinstance(aggregates, Mapping):
            continue
        analytics = aggregates.get("analytics_ids")
        if not isinstance(analytics, Mapping):
            continue
        for vendor, entries in analytics.items():
            if not isinstance(entries, Sequence) or isinstance(entries, (str, bytes, bytearray)):
                continue
            vendor_key = str(vendor)
            for entry in entries:
                if not isinstance(entry, Mapping):
                    continue
                src = str(entry.get("src") or "").strip()
                ids = entry.get("ids")
                if not src or not isinstance(ids, Sequence) or isinstance(ids, (str, bytes, bytearray)):
                    continue
                merged[vendor_key][src].update(
                    str(item) for item in ids if str(item or "").strip()
                )
    out: dict[str, list[dict[str, object]]] = {}
    for vendor, by_src in merged.items():
        entries: list[dict[str, object]] = []
        for src, ids in sorted(by_src.items()):
            sorted_ids = sorted(ids)
            entries.append({"src": src, "ids": sorted_ids, "count": len(sorted_ids)})
        entries.sort(key=lambda item: (-int(item.get("count", 0) or 0), str(item.get("src") or "")))
        out[vendor] = entries
    return out


def _merge_aggregates(payloads: Sequence[Mapping[str, object]]) -> Mapping[str, object]:
    endpoint_totals: Counter[str] = Counter()
    for payload in payloads:
        aggregates = payload.get("aggregates")
        if not isinstance(aggregates, Mapping):
            continue
        endpoint_totals.update(_int_mapping(aggregates.get("endpoint_totals")))
    return {
        "endpoint_totals": dict(endpoint_totals),
        "endpoint_roots": _merge_endpoint_roots(payloads),
        "endpoint_cleartext": _merge_aggregate_rows(
            payloads,
            "endpoint_cleartext",
            identity_fields=("value", "src", "root_domain", "scheme"),
        ),
        "api_keys_high": _merge_aggregate_rows(
            payloads,
            "api_keys_high",
            identity_fields=("provider", "masked", "src", "token_type"),
        ),
        "cloud_refs": _merge_aggregate_rows(
            payloads,
            "cloud_refs",
            identity_fields=("provider", "service", "resource", "region", "src"),
        ),
        "analytics_ids": _merge_analytics_ids(payloads),
        "entropy_high_samples": _merge_aggregate_rows(
            payloads,
            "entropy_high_samples",
            identity_fields=("masked", "src"),
        ),
        "pair_matches": _merge_aggregate_rows(
            payloads,
            "pair_matches",
            identity_fields=("pair_group", "pair_type", "provider"),
        ),
        "actionable_strings": _merge_aggregate_rows(
            payloads,
            "actionable_strings",
            identity_fields=("bucket", "value_masked", "src", "pair_group"),
        ),
        "exploratory_strings": _merge_aggregate_rows(
            payloads,
            "exploratory_strings",
            identity_fields=("bucket", "value_masked", "src", "pair_group"),
        ),
    }


def analyse_string_payload(
    apk_path: str,
    *,
    params: RunParameters,
    package_name: str,
    warning_sink: list[str] | None = None,
    analyse_fn: Callable[..., Mapping[str, object]] = _default_analyse_strings,
) -> Mapping[str, object]:
    try:
        payload = analyse_fn(
            apk_path,
            mode=params.strings_mode,
            min_entropy=params.string_min_entropy,
            max_samples=params.string_max_samples,
            cleartext_only=params.string_cleartext_only,
            include_https_risk=params.string_include_https_risk,
            artifact_context={"package_name": package_name},
        )
        if isinstance(payload, Mapping):
            return _with_aggregation_scope(payload, scope="single_artifact")
        return empty_string_analysis_payload()
    except Exception as exc:
        message = f"String analysis failed during finalization for {package_name}: {exc}"
        if warning_sink is not None:
            warning_sink.append(message)
        logging_engine.get_error_logger().exception(
            "String analysis failed during result finalization",
            extra=logging_engine.ensure_trace(
                {
                    "event": "static.strings.finalization_failed",
                    "package": package_name,
                    "apk_path": apk_path,
                    "session_stamp": params.session_stamp,
                    "error_class": exc.__class__.__name__,
                }
            ),
        )
        return empty_string_analysis_payload(
            warning=f"{exc.__class__.__name__}: {exc}"
        )


def merge_string_analysis_payloads(
    payloads: Sequence[Mapping[str, object] | None],
    *,
    params: RunParameters,
) -> Mapping[str, object]:
    valid_payloads = [payload for payload in payloads if isinstance(payload, Mapping)]
    if not valid_payloads:
        return empty_string_analysis_payload(warning="no_string_payloads_available")
    if len(valid_payloads) == 1:
        return valid_payloads[0]

    counts: Counter[str] = Counter()
    extra_counts: Counter[str] = Counter()
    noise_counts: Counter[str] = Counter()
    warnings: list[str] = []
    resource_strings_skipped = False
    regex_skipped = 0
    options: Mapping[str, object] = {}
    selection_params: Mapping[str, object] = {}

    for payload in valid_payloads:
        counts.update(_int_mapping(payload.get("counts")))
        extra_counts.update(_int_mapping(payload.get("extra_counts")))
        noise_counts.update(_int_mapping(payload.get("noise_counts")))
        regex_skipped += int(payload.get("regex_skipped", 0) or 0)
        warnings.extend(_warnings_list(payload.get("warnings")))
        resource_strings_skipped = resource_strings_skipped or bool(payload.get("resource_strings_skipped"))
        if not options and isinstance(payload.get("options"), Mapping):
            options = dict(payload.get("options") or {})
        if not selection_params and isinstance(payload.get("selection_params"), Mapping):
            selection_params = dict(payload.get("selection_params") or {})

    counts.setdefault("trailing_punct_trimmed", int(extra_counts.get("trailing_punct_trimmed", 0) or 0))
    merged_samples = _sample_groups(valid_payloads)
    sample_hits = _string_hits_from_samples(merged_samples)
    max_selected = max(1, int(params.string_max_samples or 1))
    selected_samples, recomputed_selection_params = select_samples(
        merged_samples,
        max_samples=max_selected,
        min_entropy=float(params.string_min_entropy),
    )

    merged_options = dict(options)
    merged_options.update(
        {
            "max_samples": params.string_max_samples,
            "cleartext_only": params.string_cleartext_only,
            "min_entropy": params.string_min_entropy,
            "mode": params.strings_mode,
            "https_in_risk": params.string_include_https_risk,
        }
    )

    return {
        "counts": dict(counts),
        "samples": merged_samples,
        "selected_samples": selected_samples,
        "selection_params": dict(selection_params) if selection_params else recomputed_selection_params,
        "extra_counts": dict(extra_counts),
        "regex_skipped": regex_skipped,
        "noise_counts": dict(noise_counts),
        "aggregates": _merge_aggregates(valid_payloads),
        "structured": build_bucket_overview(sample_hits, dict(counts)),
        "warnings": _warnings_list(warnings),
        "resource_strings_skipped": resource_strings_skipped,
        "options": merged_options,
        "aggregation_scope": "artifact_merged",
        "artifact_payload_count": len(valid_payloads),
        "artifact_bucket_coverage": {
            bucket: len(merged_samples.get(bucket, ()))
            for bucket in BUCKET_ORDER
            if merged_samples.get(bucket)
        },
    }


__all__ = [
    "analyse_string_payload",
    "empty_string_analysis_payload",
    "merge_string_analysis_payloads",
]
