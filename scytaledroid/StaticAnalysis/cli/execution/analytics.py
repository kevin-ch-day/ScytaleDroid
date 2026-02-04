"""Analytics helpers for static analysis results."""

from __future__ import annotations

import statistics
from collections import Counter, defaultdict
from collections.abc import Mapping, Sequence

from scytaledroid.Database.db_core import db_queries as core_q
from scytaledroid.StaticAnalysis.modules.permissions.permission_console_rendering import (
    _classify_permissions as _perm_classify,
)
from scytaledroid.StaticAnalysis.modules.permissions.permission_console_rendering import (
    render_permission_matrix,
)
from scytaledroid.StaticAnalysis.modules.permissions.permission_protection_lookup import (
    _fetch_protections as _perm_fetch_protections,
)
from scytaledroid.StaticAnalysis.risk.permission import (
    permission_points_0_20,
    permission_risk_grade,
    permission_risk_score_detail,
)
from scytaledroid.Utils.DisplayUtils import colors, table_utils

from ...core import StaticAnalysisReport
from ..core.models import RunOutcome
from .results_formatters import _format_masvs_cell, _percentile


def _derive_highlight_stats(outcome: RunOutcome) -> dict[str, int]:
    stats = {"providers": 0, "nsc_guard": 0, "secrets_suppressed": 0}
    for app_result in outcome.results:
        base_report = app_result.base_report()
        if base_report is None:
            continue
        try:
            providers = getattr(base_report.exported_components, "providers", ())
            stats["providers"] += len(providers)
        except Exception:
            pass

        metadata = base_report.metadata if isinstance(base_report.metadata, Mapping) else {}
        nsc_payload: Mapping[str, object] | None = None
        if isinstance(metadata, Mapping):
            candidate = metadata.get("network_security_config")
            if isinstance(candidate, Mapping):
                nsc_payload = candidate
            else:
                repro = metadata.get("repro_bundle")
                if isinstance(repro, Mapping):
                    repro_candidate = repro.get("network_security_config")
                    if isinstance(repro_candidate, Mapping):
                        nsc_payload = repro_candidate

        base_flag = base_report.manifest_flags.uses_cleartext_traffic
        if isinstance(nsc_payload, Mapping):
            base_cleartext = nsc_payload.get("base_cleartext")
            domain_policies = nsc_payload.get("domain_policies")
            has_domains = bool(domain_policies)
            if base_cleartext is False or (base_flag is False and not has_domains):
                stats["nsc_guard"] += 1
        elif base_flag is False:
            stats["nsc_guard"] += 1

        for result in getattr(base_report, "detector_results", ()):  # type: ignore[attr-defined]
            if getattr(result, "detector_id", "") == "secrets_credentials":
                metrics = getattr(result, "metrics", {})
                if isinstance(metrics, Mapping):
                    secret_types = metrics.get("secret_types")
                    if isinstance(secret_types, Mapping):
                        for data in secret_types.values():
                            if isinstance(data, Mapping):
                                stats["secrets_suppressed"] += int(data.get("validator_dropped") or 0)
                break
    return stats


def _build_permission_profile(report, app_result) -> dict[str, object | None]:
    try:
        declared = list(report.permissions.declared or ())
    except Exception:
        declared = []
    declared_pairs = [(name, "uses-permission") for name in declared]
    try:
        target_sdk = int(report.manifest.target_sdk) if report.manifest.target_sdk else None
    except Exception:
        target_sdk = None
    shorts_only = [
        name.split(".")[-1].upper() for name in declared if isinstance(name, str) and name.startswith("android.")
    ]
    try:
        protection_map = _perm_fetch_protections(shorts_only, target_sdk)
    except Exception:
        protection_map = {}
    try:
        risk_counts, groups, oem_counts, fw_ds, oem_names = _perm_classify(declared_pairs, protection_map)
    except Exception:
        risk_counts, groups, oem_counts, fw_ds, oem_names = ({}, {}, {}, set(), set())

    detector_metrics = getattr(report, "detector_metrics", None)
    permissions_metrics: Mapping[str, object] | None = None
    if isinstance(detector_metrics, Mapping):
        permissions_metrics = detector_metrics.get("permissions_profile")

    profiles_section = {}
    if isinstance(permissions_metrics, Mapping):
        raw_profiles = permissions_metrics.get("permission_profiles")
        if isinstance(raw_profiles, Mapping):
            profiles_section = raw_profiles

    flagged_normals_set: set[str] = set()
    weak_guard_count = 0
    if profiles_section:
        for perm_name, data in profiles_section.items():
            if not isinstance(data, Mapping):
                continue
            if data.get("is_flagged_normal"):
                flagged_normals_set.add(str(perm_name))
            guard_strength = str(data.get("guard_strength") or "").lower()
            if guard_strength in {"weak", "unknown"} and data.get("is_runtime_dangerous"):
                weak_guard_count += 1
    elif isinstance(permissions_metrics, Mapping):
        flagged_list = permissions_metrics.get("flagged_normal_permissions")
        if isinstance(flagged_list, (list, tuple, set)):
            flagged_normals_set.update(str(item) for item in flagged_list)

    flagged_normals = len(flagged_normals_set)

    flags = getattr(report, "manifest_flags", None)
    allow_backup = bool(getattr(flags, "allow_backup", False)) if flags else False
    legacy_storage = bool(getattr(flags, "request_legacy_external_storage", False)) if flags else False

    d = int(risk_counts.get("dangerous", 0))
    s = int(risk_counts.get("signature", 0))
    v = int(oem_counts.get("ADS", 0))

    try:
        detail = permission_risk_score_detail(
            dangerous=d,
            signature=s,
            vendor=v,
            groups=groups,
            target_sdk=target_sdk,
            allow_backup=allow_backup,
            legacy_external_storage=legacy_storage,
            flagged_normals=flagged_normals,
            weak_guards=weak_guard_count,
        )
    except Exception:
        detail = {
            "score_3dp": 0.0,
            "score_capped": 0.0,
            "score_raw": 0.0,
        }
    score = float(detail.get("score_3dp") or detail.get("score_capped") or detail.get("score_raw") or 0.0)
    score = round(score, 3)
    try:
        grade = permission_risk_grade(score)
    except Exception:
        grade = "N/A"

    manifest = getattr(report, "manifest", None)
    package_name = getattr(manifest, "package_name", None) or app_result.package_name
    app_label = getattr(manifest, "app_label", None) if manifest else None
    label = app_label or package_name

    return {
        "package": package_name,
        "label": label,
        "risk": score,
        "grade": grade,
        "D": d,
        "S": s,
        "V": v,
        "O": v,
        "groups": groups,
        "fw_ds": set(fw_ds),
        "vendor_names": set(oem_names),
        "risk_counts": risk_counts,
        "score_detail": detail,
        "flagged_normals": flagged_normals,
        "weak_guard_count": weak_guard_count,
        "flagged_permissions": sorted(flagged_normals_set),
    }


def _collect_masvs_profile(report) -> dict[str, object]:
    severity_map = {"P0": "High", "P1": "Medium", "P2": "Low", "NOTE": "Info"}
    counts: dict[str, dict[str, int]] = {
        area: {"High": 0, "Medium": 0, "Low": 0, "Info": 0} for area in ("NETWORK", "PLATFORM", "PRIVACY", "STORAGE")
    }
    highlights: dict[str, Counter[str]] = {area: Counter() for area in counts}
    has_values = False
    for result in getattr(report, "detector_results", []) or []:
        for finding in getattr(result, "findings", []) or []:
            area_obj = getattr(finding, "category_masvs", None)
            area_value = None
            if hasattr(area_obj, "value"):
                area_value = area_obj.value
            elif area_obj is not None:
                area_value = str(area_obj)
            if not area_value:
                continue
            area_key = str(area_value).upper()
            if area_key not in counts:
                continue
            sev_gate = getattr(getattr(finding, "severity_gate", None), "value", None)
            severity_label = severity_map.get(str(sev_gate), None)
            if severity_label is None:
                continue
            counts[area_key][severity_label] += 1
            if severity_label in {"High", "Medium"}:
                descriptor = finding.title or finding.finding_id or result.detector_id or "Unknown"
                highlights[area_key][descriptor] += 1
            has_values = True
    if not has_values:
        return {}
    return {
        "counts": counts,
        "highlights": {area: counter for area, counter in highlights.items() if counter},
    }


def _code_http_counts(string_data: Mapping[str, object]) -> tuple[int, int]:
    try:
        samples = string_data.get("samples", {}) if isinstance(string_data, Mapping) else {}
        http_samples = (samples.get("http_cleartext") or []) + (samples.get("endpoints") or [])
        code_hosts: set[str] = set()
        asset_hosts: set[str] = set()
        options = string_data.get("options") if isinstance(string_data, Mapping) else {}
        include_https = False
        if isinstance(options, Mapping):
            include_https = bool(options.get("https_in_risk"))
        for sample in http_samples:
            st = str(sample.get("source_type") or "").lower()
            scheme = str(sample.get("scheme") or "").lower()
            root = str(sample.get("root_domain") or "")
            if scheme not in {"http"} and not (include_https and scheme == "https"):
                continue
            if st in {"code", "dex", "native"}:
                if root:
                    code_hosts.add(root)
            else:
                if root:
                    asset_hosts.add(root)
        return len(code_hosts), len(asset_hosts)
    except Exception:
        return (0, 0)


def _build_static_risk_row(
    report,
    string_data: Mapping[str, object],
    permission_profile: dict | None,
    app_result,
) -> dict[str, object | None]:
    try:
        total_exports = report.exported_components.total()
    except Exception:
        total_exports = 0
    flags = getattr(report, "manifest_flags", None)
    uses_cleartext = bool(getattr(flags, "uses_cleartext_traffic", False)) if flags else False
    legacy_storage = bool(getattr(flags, "request_legacy_external_storage", False)) if flags else False

    code_http_hosts, _asset_http_hosts = _code_http_counts(string_data)
    has_code_http = code_http_hosts > 0
    try:
        declared = list(report.permissions.declared or ())
    except Exception:
        declared = []

    net_points = 12.0 if (uses_cleartext and has_code_http) else (4.0 if has_code_http else 0.0)
    sto_points = 8.0 if legacy_storage else 0.0
    comp_points = float(min(12, total_exports * 1.5))

    aggregates = string_data.get("aggregates", {}) if isinstance(string_data, Mapping) else {}
    validated = len(aggregates.get("api_keys_high") or [])
    counts_section = string_data.get("counts", {}) if isinstance(string_data, Mapping) else {}
    entropy_hits = int(counts_section.get("high_entropy", 0) or 0) if isinstance(counts_section, Mapping) else 0
    secrets_points = float(min(20, validated * 2)) + (3.0 if entropy_hits >= 10 else (1.5 if entropy_hits else 0.0))
    webssl_points = 0.0
    corr_points = 0.0
    if has_code_http and "android.permission.INTERNET" in declared:
        corr_points += 1.0
    if any(str(name).endswith("READ_CONTACTS") for name in declared) and aggregates.get("endpoint_roots"):
        corr_points += 1.0
    corr_points = min(3.0, corr_points)

    risk_score = float(permission_profile.get("risk", 0.0)) if permission_profile else 0.0
    try:
        perm_points = permission_points_0_20(risk_score) * 0.75
    except Exception:
        perm_points = risk_score * 2
    perm_points = min(15.0, perm_points)
    grade = permission_profile.get("grade") if permission_profile else "N/A"

    total_score = perm_points + net_points + sto_points + comp_points + secrets_points + webssl_points + corr_points
    package = getattr(report.manifest, "package_name", None) or app_result.package_name
    label = permission_profile.get("label") if permission_profile else package

    return {
        "package": package,
        "label": label,
        "permission": round(perm_points, 2),
        "network": round(net_points, 2),
        "storage": round(sto_points, 2),
        "components": round(comp_points, 2),
        "secrets": round(secrets_points, 2),
        "webssl": round(webssl_points, 2),
        "correlation": round(corr_points, 2),
        "total": round(total_score, 2),
        "grade": grade,
    }


def _collect_component_stats(report: StaticAnalysisReport) -> dict[str, object]:
    manifest = getattr(report, "manifest", None)
    app_label = manifest.app_label if manifest and manifest.app_label else manifest.package_name if manifest else "unknown"
    exports = getattr(report, "exported_components", None)
    activities = len(getattr(exports, "activities", []) or []) if exports else 0
    services = len(getattr(exports, "services", []) or []) if exports else 0
    receivers = len(getattr(exports, "receivers", []) or []) if exports else 0
    providers = len(getattr(exports, "providers", []) or []) if exports else 0
    return {
        "package": getattr(manifest, "package_name", None) if manifest else None,
        "label": app_label,
        "activities": activities,
        "services": services,
        "receivers": receivers,
        "providers": providers,
    }


def _collect_secret_stats(string_payload: Mapping[str, object], report: StaticAnalysisReport) -> dict[str, object]:
    counts = string_payload.get("counts", {}) if isinstance(string_payload, Mapping) else {}
    api_keys = int(counts.get("api_keys", 0) or 0)
    high_entropy = int(counts.get("high_entropy", 0) or 0)
    samples = string_payload.get("samples", {}) if isinstance(string_payload, Mapping) else {}
    risk_counter: Counter[str] = Counter()
    for bucket in ("api_keys", "high_entropy"):
        entries = samples.get(bucket) if isinstance(samples, Mapping) else None
        if not isinstance(entries, Sequence) or isinstance(entries, (str, bytes)):
            continue
        for entry in entries:
            if not isinstance(entry, Mapping):
                continue
            tag = entry.get("risk_tag") or entry.get("provider") or entry.get("tag")
            if tag:
                risk_counter[str(tag)] += 1
    manifest = getattr(report, "manifest", None)
    app_label = manifest.app_label if manifest and manifest.app_label else manifest.package_name if manifest else "unknown"
    return {
        "package": getattr(manifest, "package_name", None) if manifest else None,
        "label": app_label,
        "api_keys": api_keys,
        "high_entropy": high_entropy,
        "risk_tags": risk_counter,
    }


def _collect_finding_signatures(report: StaticAnalysisReport) -> dict[str, object]:
    counter: Counter[tuple[str, str]] = Counter()
    severity_map = {"P0": "High", "P1": "Medium"}
    for result in getattr(report, "detector_results", []) or []:
        for finding in getattr(result, "findings", []) or []:
            sev = getattr(getattr(finding, "severity_gate", None), "value", None)
            label = severity_map.get(str(sev))
            if not label:
                continue
            descriptor = finding.title or finding.finding_id or result.detector_id or "Unknown"
            counter[(label, descriptor)] += 1
    manifest = getattr(report, "manifest", None)
    app_label = manifest.app_label if manifest and manifest.app_label else manifest.package_name if manifest else "unknown"
    return {
        "package": getattr(manifest, "package_name", None) if manifest else None,
        "label": app_label,
        "counter": counter,
    }


def _compute_trend_delta(
    package_name: str,
    session_stamp: str | None,
    finding_totals: Counter[str],
) -> dict[str, object | None]:
    if not session_stamp:
        return None
    try:
        row = core_q.run_sql(
            """
            SELECT session_stamp, high, med, low, info
            FROM static_findings_summary
            WHERE package_name = %s AND session_stamp < %s
            ORDER BY session_stamp DESC
            LIMIT 1
            """,
            (package_name, session_stamp),
            fetch="one",
            dictionary=True,
        )
    except Exception:
        return None
    if not row:
        return None
    try:
        deltas = {
            "delta_high": int(finding_totals.get("High", 0)) - int(row.get("high") or 0),
            "delta_medium": int(finding_totals.get("Medium", 0)) - int(row.get("med") or 0),
            "delta_low": int(finding_totals.get("Low", 0)) - int(row.get("low") or 0),
        }
    except Exception:
        return None
    return {
        "package": package_name,
        "previous_session": row.get("session_stamp"),
        **deltas,
    }


def _bulk_trend_deltas(
    session_stamp: str | None,
    finding_totals_map: Mapping[str, Counter[str]],
) -> list[dict[str, object]]:
    if not session_stamp or not finding_totals_map:
        return []
    packages = [pkg for pkg in finding_totals_map.keys() if pkg]
    if not packages:
        return []
    placeholders = ",".join(["%s"] * len(packages))
    try:
        rows = core_q.run_sql(
            f"""
            SELECT t.package_name, t.session_stamp, t.high, t.med, t.low
            FROM static_findings_summary t
            JOIN (
                SELECT package_name, MAX(session_stamp) AS session_stamp
                FROM static_findings_summary
                WHERE package_name IN ({placeholders})
                  AND session_stamp < %s
                GROUP BY package_name
            ) latest
              ON latest.package_name = t.package_name
             AND latest.session_stamp = t.session_stamp
            """,
            tuple(packages) + (session_stamp,),
            fetch="all",
            dictionary=True,
        )
    except Exception:
        return []
    if not rows:
        return []
    deltas: list[dict[str, object]] = []
    for row in rows or []:
        package = row.get("package_name") if isinstance(row, dict) else None
        if not package:
            continue
        totals = finding_totals_map.get(str(package))
        if not totals:
            continue
        try:
            deltas.append(
                {
                    "package": str(package),
                    "previous_session": row.get("session_stamp"),
                    "delta_high": int(totals.get("High", 0)) - int(row.get("high") or 0),
                    "delta_medium": int(totals.get("Medium", 0)) - int(row.get("med") or 0),
                    "delta_low": int(totals.get("Low", 0)) - int(row.get("low") or 0),
                }
            )
        except Exception:
            continue
    return deltas


def _render_masvs_matrix_local(
    matrix: Mapping[str, Mapping[str, object]],
    *,
    limit: int = 15,
) -> bool:
    if not matrix:
        return False
    areas = ("NETWORK", "PLATFORM", "PRIVACY", "STORAGE")

    prepared: list[tuple[str, Mapping[str, object] | object]] = []
    for _, entry in matrix.items():
        label = str((entry.get("label") if isinstance(entry, Mapping) else "") or "")
        package = str((entry.get("package") if isinstance(entry, Mapping) else "") or "")
        display = label or package or "—"
        prepared.append((display, entry))

    ordered = sorted(prepared, key=lambda item: item[0].lower())[:limit]
    if not ordered:
        return False

    print("\nMASVS Matrix — Current run snapshot")
    headers = ["App", "Network", "Platform", "Privacy", "Storage", "Totals"]
    table_payload: list[list[str]] = []
    for display, entry in ordered:
        counts = entry.get("counts") if isinstance(entry, Mapping) else {}
        if not isinstance(counts, Mapping):
            counts = {}
        row = [display]
        total_high = total_medium = total_low = total_info = 0
        for area in areas:
            area_counts = counts.get(area, {"High": 0, "Medium": 0, "Low": 0, "Info": 0}) if isinstance(counts, Mapping) else {}
            if not isinstance(area_counts, Mapping):
                area_counts = {"High": 0, "Medium": 0, "Low": 0, "Info": 0}
            row.append(_format_masvs_cell(area_counts))
            total_high += int(area_counts.get("High", 0))
            total_medium += int(area_counts.get("Medium", 0))
            total_low += int(area_counts.get("Low", 0))
            total_info += int(area_counts.get("Info", 0))
        totals_text = f"H{total_high} M{total_medium} L{total_low} I{total_info}"
        if colors.colors_enabled():
            if total_high:
                totals_text = colors.apply(totals_text, colors.style("error"), bold=True)
            elif total_medium:
                totals_text = colors.apply(totals_text, colors.style("warning"), bold=True)
        row.append(totals_text)
        table_payload.append(row)
    table_utils.render_table(headers, table_payload)
    return True


def _render_static_risk_table(rows: Sequence[dict[str, object]], *, limit: int = 15) -> bool:
    if not rows:
        return False
    ordered = sorted(
        rows,
        key=lambda item: str(item.get("label") or item.get("package") or "").lower(),
    )[:limit]
    if not ordered:
        return False
    print("\nStatic Risk Scores — Composite buckets")
    headers = [
        "App",
        "Grade",
        "Total",
        "Perm",
        "Network",
        "Storage",
        "Components",
        "Secrets",
        "Web/SSL",
        "Corr",
    ]
    table_rows: list[list[str]] = []
    for entry in ordered:
        label = str(entry.get("label") or entry.get("package") or "—")
        table_rows.append(
            [
                label,
                str(entry.get("grade") or "N/A"),
                f"{float(entry.get('total', 0.0)):.1f}",
                f"{float(entry.get('permission', 0.0)):.1f}",
                f"{float(entry.get('network', 0.0)):.1f}",
                f"{float(entry.get('storage', 0.0)):.1f}",
                f"{float(entry.get('components', 0.0)):.1f}",
                f"{float(entry.get('secrets', 0.0)):.1f}",
                f"{float(entry.get('webssl', 0.0)):.1f}",
                f"{float(entry.get('correlation', 0.0)):.1f}",
            ]
        )
    table_utils.render_table(headers, table_rows)
    return True


def _render_post_run_views(
    permission_profiles: Sequence[dict[str, object]],
    masvs_matrix: Mapping[str, Mapping[str, object]],
    static_risk_rows: Sequence[dict[str, object]],
    *,
    scope_label: str,
) -> None:
    rendered_any = False
    if permission_profiles:
        limit = min(15, len(permission_profiles))
        try:
            render_permission_matrix(permission_profiles, scope_label=scope_label, show=limit)
            rendered_any = True
        except Exception:
            pass
    if masvs_matrix:
        if _render_masvs_matrix_local(masvs_matrix, limit=15):
            rendered_any = True
    if static_risk_rows:
        if _render_static_risk_table(static_risk_rows, limit=15):
            rendered_any = True
    if rendered_any:
        print()


def _render_cross_app_insights(
    permission_profiles: Sequence[dict[str, object]],
    component_profiles: Sequence[dict[str, object]],
    masvs_matrix: Mapping[str, Mapping[str, object]],
    secret_profiles: Sequence[dict[str, object]],
    finding_profiles: Sequence[dict[str, object]],
    trend_deltas: Sequence[dict[str, object]],
    *,
    scope_label: str,
) -> None:
    app_count = len(permission_profiles)
    if app_count < 2:
        return

    print("\nAggregate Insights")
    print("-------------------")

    dangerous_counts = [profile.get("D", 0) for profile in permission_profiles if profile.get("D") is not None]
    signature_counts = [profile.get("S", 0) for profile in permission_profiles if profile.get("S") is not None]
    if dangerous_counts or signature_counts:
        med_d = statistics.median(dangerous_counts) if dangerous_counts else 0
        p90_d = _percentile(dangerous_counts, 0.9) if dangerous_counts else 0
        med_s = statistics.median(signature_counts) if signature_counts else 0
        print(
            "• Permissions: "
            f"median dangerous={med_d:.1f}, 90th percentile dangerous={p90_d:.1f}, median signature={med_s:.1f}"
        )

    if component_profiles:
        component_totals = [
            stats["activities"] + stats["services"] + stats["receivers"] + stats["providers"]
            for stats in component_profiles
        ]
        top_components = sorted(
            component_profiles,
            key=lambda item: item["activities"] + item["services"] + item["receivers"] + item["providers"],
            reverse=True,
        )[:5]
        if component_totals:
            med_components = statistics.median(component_totals)
            formatted = ", ".join(
                f"{item['label']} ({item['activities']}/{item['services']}/{item['receivers']}/{item['providers']})"
                for item in top_components
            )
            print(f"• Exported components: median total={med_components:.1f}; top apps: {formatted}")

    if masvs_matrix:
        area_failures: dict[str, int] = defaultdict(int)
        area_top_rules: dict[str, Counter[str]] = defaultdict(Counter)
        for entry in masvs_matrix.values():
            counts = entry.get("counts", {}) if isinstance(entry, Mapping) else {}
            highlights = entry.get("highlights", {}) if isinstance(entry, Mapping) else {}
            for area, stats in counts.items() if isinstance(counts, Mapping) else []:
                high = int(stats.get("High", 0))
                medium = int(stats.get("Medium", 0))
                if high or medium:
                    area_failures[area] += 1
            for area, counter in highlights.items() if isinstance(highlights, Mapping) else []:
                if isinstance(counter, Counter):
                    area_top_rules[area].update(counter)
        if area_failures:
            summary = ", ".join(f"{area.title()} fails={count}" for area, count in sorted(area_failures.items()))
            print(f"• MASVS coverage: {summary}")
            for area, counter in area_top_rules.items():
                most_common = counter.most_common(2)
                if most_common:
                    formatted = ", ".join(f"{name}×{occ}" for name, occ in most_common)
                    print(f"    - {area.title()} top findings: {formatted}")

    if secret_profiles:
        total_api = sum(profile.get("api_keys", 0) for profile in secret_profiles)
        total_entropy = sum(profile.get("high_entropy", 0) for profile in secret_profiles)
        tag_counter: Counter[str] = Counter()
        for profile in secret_profiles:
            tag_counter.update(profile.get("risk_tags", Counter()))
        top_tags = ", ".join(f"{tag}×{count}" for tag, count in tag_counter.most_common(5)) if tag_counter else "none"
        print(
            f"• Secrets: total API keys={total_api}, high-entropy samples={total_entropy}, top tags: {top_tags}"
        )

    if finding_profiles:
        combined = Counter()
        for profile in finding_profiles:
            combined.update(profile.get("counter", Counter()))
        if combined:
            top_findings = ", ".join(
                f"{sev} {name}×{count}" for (sev, name), count in combined.most_common(5)
            )
            print(f"• Recurring findings: {top_findings}")

    if trend_deltas:
        changes = [
            delta
            for delta in trend_deltas
            if any(delta.get(key) for key in ("delta_high", "delta_medium", "delta_low"))
        ]
        if changes:
            summary = []
            for delta in changes[:5]:
                parts = []
                for label, key in (("H", "delta_high"), ("M", "delta_medium"), ("L", "delta_low")):
                    value = delta.get(key)
                    if value:
                        parts.append(f"{label}{value:+d}")
                if parts:
                    summary.append(f"{delta['package']} ({', '.join(parts)})")
            if summary:
                print("• Trend vs previous session: " + ", ".join(summary))

    print(f"• Scope reviewed: {scope_label or 'n/a'} across {app_count} apps")


__all__ = [
    "_build_permission_profile",
    "_build_static_risk_row",
    "_bulk_trend_deltas",
    "_collect_component_stats",
    "_collect_finding_signatures",
    "_collect_masvs_profile",
    "_collect_secret_stats",
    "_compute_trend_delta",
    "_derive_highlight_stats",
    "_render_cross_app_insights",
    "_render_post_run_views",
]