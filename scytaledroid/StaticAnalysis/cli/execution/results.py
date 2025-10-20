"""Result rendering helpers for static analysis CLI."""

from __future__ import annotations

from pathlib import Path

from collections import Counter, defaultdict
import math
import statistics
from typing import Mapping, MutableMapping, Sequence, Optional, Dict

from scytaledroid.Utils.DisplayUtils import (
    prompt_utils,
    severity,
    status_messages,
    summary_cards,
    table_utils,
    colors,
)

from ...core import StaticAnalysisReport
from ...engine.strings import analyse_strings
from ..db_persist import persist_run_summary
from ..detail import (
    SEVERITY_TOKEN_ORDER,
    app_detail_loop,
    render_app_detail,
)
from ..masvs_summary import fetch_db_masvs_summary
from ..models import RunOutcome, RunParameters
from ..renderer import render_app_result, write_baseline_json
from ...persistence.ingest import ingest_baseline_payload
from .scan_flow import format_duration
from scytaledroid.Database.db_core import db_queries as core_q
from scytaledroid.StaticAnalysis.modules.permissions.simple import (
    render_permission_matrix,
    _classify_permissions as _perm_classify,
    _fetch_protections as _perm_fetch_protections,
)
from scytaledroid.StaticAnalysis.modules.permissions.analysis.scoring import (
    permission_risk_score_detail,
    permission_risk_grade,
    permission_points_0_20,
)



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


def _format_highlight_tokens(
    stats: Mapping[str, int], totals: Mapping[str, int], app_count: int
) -> list[str]:
    tokens: list[str] = []
    providers = stats.get("providers", 0)
    if providers:
        tokens.append(
            f"{providers} exported provider{'s' if providers != 1 else ''} lacking strong guards"
        )
    guard = stats.get("nsc_guard", 0)
    if guard:
        tokens.append(
            f"NSC blocks cleartext in {guard}/{app_count} app{'s' if guard != 1 else ''}"
        )
    suppressed = stats.get("secrets_suppressed", 0)
    if suppressed:
        tokens.append(
            f"{suppressed} secret hit{'s' if suppressed != 1 else ''} auto-suppressed"
        )
    if not tokens:
        high = totals.get("high", 0) + totals.get("critical", 0)
        if high:
            tokens.append(
                f"{high} high-severity finding{'s' if high != 1 else ''} require review"
            )
        else:
            tokens.append("No high-severity findings detected")
    return tokens


def render_run_results(outcome: RunOutcome, params: RunParameters) -> None:
    """Pretty-print run results and optionally drill into per-app details."""

    aggregated: Counter[str] = Counter()
    artifact_count = 0
    permission_profiles: list[dict[str, object]] = []
    masvs_matrix: dict[str, dict[str, object]] = {}
    static_risk_rows: list[dict[str, object]] = []
    component_profiles: list[dict[str, object]] = []
    secret_profiles: list[dict[str, object]] = []
    finding_profiles: list[dict[str, object]] = []
    trend_deltas: list[dict[str, object]] = []
    for app_result in outcome.results:
        aggregated.update(app_result.severity_totals())
        artifact_count += len(app_result.artifacts)

    totals = severity.normalise_counts(aggregated)
    highlight_stats = _derive_highlight_stats(outcome)
    total_findings = sum(totals.values())
    overview_items = [
        summary_cards.summary_item("Duration", format_duration(outcome.duration_seconds), value_style="emphasis"),
        summary_cards.summary_item("Applications", len(outcome.results)),
        summary_cards.summary_item("Artifacts", artifact_count),
        summary_cards.summary_item("Findings", total_findings, value_style="severity_high" if totals.get("high") or totals.get("critical") else "emphasis"),
    ]
    overview_items.extend(severity.severity_summary_items(totals))
    subtitle_parts = [params.profile_label]
    if params.scope_label:
        subtitle_parts.append(f"Scope: {params.scope_label}")
    if params.session_stamp:
        subtitle_parts.append(f"Session: {params.session_stamp}")
    subtitle = " • ".join(subtitle_parts)
    print(
        summary_cards.format_summary_card(
            "Static analysis summary",
            overview_items,
            subtitle=subtitle,
            footer="Use the prompts below to drill into per-app findings.",
            width=90,
        )
    )
    highlight_tokens = _format_highlight_tokens(
        highlight_stats,
        totals,
        len(outcome.results),
    )
    if highlight_tokens:
        print(status_messages.highlight("; ".join(highlight_tokens), show_icon=True))
    print()

    persistence_errors: list[str] = []
    persist_enabled = not params.dry_run

    for index, app_result in enumerate(outcome.results, start=1):
        base_report = app_result.base_report()
        if base_report is None:
            warning = f"No report generated for {app_result.package_name}."
            print(status_messages.status(warning, level="warn"))
            continue

        string_data = analyse_strings(
            base_report.file_path,
            mode=params.strings_mode,
            min_entropy=params.string_min_entropy,
            max_samples=params.string_max_samples,
            cleartext_only=params.string_cleartext_only,
        )
        permission_profile = _build_permission_profile(base_report, app_result)
        if permission_profile:
            permission_profiles.append(permission_profile)
        component_profiles.append(_collect_component_stats(base_report))
        risk_row = _build_static_risk_row(base_report, string_data, permission_profile, app_result)
        if risk_row:
            static_risk_rows.append(risk_row)
        secret_profiles.append(_collect_secret_stats(string_data, base_report))
        masvs_profile = _collect_masvs_profile(base_report)
        if masvs_profile:
            manifest = base_report.manifest
            app_label = manifest.app_label if manifest and manifest.app_label else app_result.package_name
            masvs_profile["label"] = app_label
            masvs_profile["package"] = manifest.package_name if manifest and manifest.package_name else app_result.package_name
            masvs_matrix[app_result.package_name] = masvs_profile
        finding_profiles.append(_collect_finding_signatures(base_report))

        total_duration = sum(artifact.duration_seconds for artifact in app_result.artifacts)
        lines, payload, finding_totals = render_app_result(
            base_report,
            signer=app_result.signer,
            split_count=len(app_result.artifacts),
            string_data=string_data,
            duration_seconds=total_duration,
        )
        trend_delta = _compute_trend_delta(app_result.package_name, params.session_stamp, finding_totals)
        if trend_delta:
            trend_deltas.append(trend_delta)

        if persist_enabled:
            try:
                outcome_status = persist_run_summary(
                    base_report,
                    string_data,
                    app_result.package_name,
                    session_stamp=params.session_stamp,
                    scope_label=params.scope_label,
                    finding_totals=finding_totals,
                    baseline_payload=payload,
                    dry_run=params.dry_run,
                )
                if outcome_status and not outcome_status.success:
                    persistence_errors.extend(outcome_status.errors)
            except Exception as exc:
                warning = (
                    f"Failed to persist run summary for {app_result.package_name}: {exc}"
                )
                print(status_messages.status(warning, level="warn"))
                persistence_errors.append(str(exc))

            try:
                ingest_payload = _build_ingest_payload(payload, base_report, params)
                if not ingest_baseline_payload(ingest_payload):
                    warning = (
                        f"Failed to record canonical snapshot for {app_result.package_name}."
                    )
                    print(status_messages.status(warning, level="warn"))
                    persistence_errors.append(warning)
            except Exception as exc:
                warning = (
                    f"Failed to ingest baseline snapshot for {app_result.package_name}: {exc}"
                )
                print(status_messages.status(warning, level="warn"))
                persistence_errors.append(str(exc))

        report_reference = None
        base_artifact = app_result.base_artifact_outcome()
        if base_artifact and base_artifact.saved_path:
            try:
                report_reference = f"report://{Path(base_artifact.saved_path).name}"
            except Exception:
                report_reference = None

        for line in lines:
            print(line)

        if persist_enabled:
            try:
                saved_path = write_baseline_json(
                    payload,
                    package=app_result.package_name,
                    profile=params.profile,
                    scope=params.scope,
                )
                print(f"  Saved baseline JSON → {saved_path.name}")
            except Exception as exc:
                warning = (
                    f"Failed to write baseline JSON for {app_result.package_name}: {exc}"
                )
                print(status_messages.status(warning, level="warn"))

        if report_reference:
            print(f"  Report reference    → {report_reference}")

        if index < len(outcome.results):
            print()

    session_stamp = params.session_stamp
    if outcome.results:
        printed_db_table = False
        if session_stamp and persist_enabled:
            printed_db_table = _render_db_severity_table(session_stamp)
        if not printed_db_table:
            from ..detail import render_app_table  # local import to avoid cycle

            render_app_table(outcome.results)
        if session_stamp and persist_enabled:
            _render_persistence_footer(session_stamp, had_errors=bool(persistence_errors))
            if persistence_errors:
                print(status_messages.status("Persistence issues detected:", level="error"))
                for message in persistence_errors:
                    print(f"  - {message}")

        _render_post_run_views(
            permission_profiles,
            masvs_matrix,
            static_risk_rows,
            scope_label=params.scope_label,
        )
        if len(outcome.results) > 1:
            _render_cross_app_insights(
                permission_profiles,
                component_profiles,
                masvs_matrix,
                secret_profiles,
                finding_profiles,
                trend_deltas,
                scope_label=params.scope_label,
            )
        if len(outcome.results) <= 5:
            _interactive_detail_loop(outcome, params)

    if outcome.warnings:
        for message in sorted(set(outcome.warnings)):
            print(status_messages.status(message, level="warn"))
    if outcome.failures:
        for message in sorted(set(outcome.failures)):
            print(status_messages.status(message, level="error"))

    if persist_enabled:
        _render_db_masvs_summary()


def _build_ingest_payload(
    payload: Mapping[str, object],
    report: StaticAnalysisReport,
    params: RunParameters,
) -> Mapping[str, object]:
    app_section = payload.get("app")
    app_copy: MutableMapping[str, object]
    if isinstance(app_section, Mapping):
        app_copy = dict(app_section)
    else:
        app_copy = {}

    baseline_section = payload.get("baseline")
    baseline_copy: MutableMapping[str, object] = {}
    findings_list: list[Mapping[str, object]] = []
    if isinstance(baseline_section, Mapping):
        baseline_copy.update(baseline_section)
        findings_raw = baseline_section.get("findings")
        if isinstance(findings_raw, Sequence) and not isinstance(
            findings_raw, (str, bytes)
        ):
            findings_list = [
                dict(entry)
                for entry in findings_raw
                if isinstance(entry, Mapping)
            ]

    app_copy.setdefault("package", report.manifest.package_name or app_copy.get("package"))
    if report.manifest.version_name and not app_copy.get("version_name"):
        app_copy["version_name"] = report.manifest.version_name
    if report.manifest.version_code and not app_copy.get("version_code"):
        app_copy["version_code"] = report.manifest.version_code
    if report.manifest.min_sdk and not app_copy.get("min_sdk"):
        app_copy["min_sdk"] = report.manifest.min_sdk
    if report.manifest.target_sdk and not app_copy.get("target_sdk"):
        app_copy["target_sdk"] = report.manifest.target_sdk

    metadata_map: MutableMapping[str, object] = {}
    if isinstance(report.metadata, Mapping):
        metadata_map.update(report.metadata)
    if params.session_stamp and not metadata_map.get("session_stamp"):
        metadata_map["session_stamp"] = params.session_stamp
    if params.scope_label and not metadata_map.get("run_scope_label"):
        metadata_map["run_scope_label"] = params.scope_label
    if params.scope and not metadata_map.get("run_scope"):
        metadata_map["run_scope"] = params.scope

    ingest_payload: MutableMapping[str, object] = {}
    ingest_payload["generated_at"] = payload.get("generated_at")
    ingest_payload["app"] = app_copy
    ingest_payload["baseline"] = baseline_copy
    ingest_payload["findings"] = findings_list
    ingest_payload["hashes"] = dict(report.hashes)
    ingest_payload["analysis_version"] = report.analysis_version
    ingest_payload["scan_profile"] = params.profile
    ingest_payload["detector_metrics"] = dict(report.detector_metrics)
    ingest_payload["metadata"] = metadata_map
    analytics_section = payload.get("analytics")
    if isinstance(analytics_section, Mapping):
        ingest_payload["analytics"] = dict(analytics_section)

    return ingest_payload


def _interactive_detail_loop(outcome: RunOutcome, params: RunParameters) -> None:
    while True:
        resp = prompt_utils.prompt_text(
            "View details for app # (Enter to skip)", default="", required=False
        ).strip()
        if not resp:
            break
        if not resp.isdigit():
            print(status_messages.status("Invalid selection.", level="warn"))
            continue
        idx = int(resp)
        if idx < 1 or idx > len(outcome.results):
            print(status_messages.status("Selection out of range.", level="warn"))
            continue
        selected = outcome.results[idx - 1]
        app_detail_loop(
            selected,
            params.evidence_lines,
            set(SEVERITY_TOKEN_ORDER),
            params.finding_limit,
            render_app_detail,
        )


def _render_db_masvs_summary() -> None:
    try:
        summary = fetch_db_masvs_summary()
        if not summary:
            return
        run_id, rows = summary
        print()
        print(f"DB MASVS Summary (run_id={run_id})")
        print("Area       High  Med   Low   Info  Status  Worst CVSS")
        for area in ("NETWORK", "PLATFORM", "PRIVACY", "STORAGE"):
            entry = next((row for row in rows if row["area"] == area), None)
            if entry is None:
                print(f"{area.title():<9}  0     0     0     0     PASS   —")
            else:
                high = entry.get("high", 0)
                medium = entry.get("medium", 0)
                if high:
                    status = "FAIL"
                elif medium:
                    status = "WARN"
                else:
                    status = "PASS"
                print(
                    f"{area.title():<9}  {high:<5} {medium:<5} {entry['low']:<5} {entry['info']:<6}"
                    f"{status:<6} {entry['worst']}"
                )
    except Exception:
        pass


def _build_permission_profile(report, app_result) -> Optional[dict[str, object]]:
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
        risk_counts, groups, vendor_counts, fw_ds, vendor_names = _perm_classify(declared_pairs, protection_map)
    except Exception:
        risk_counts, groups, vendor_counts, fw_ds, vendor_names = ({}, {}, {}, set(), set())

    flags = getattr(report, "manifest_flags", None)
    allow_backup = bool(getattr(flags, "allow_backup", False)) if flags else False
    legacy_storage = bool(getattr(flags, "request_legacy_external_storage", False)) if flags else False

    d = int(risk_counts.get("dangerous", 0))
    s = int(risk_counts.get("signature", 0))
    v = int(vendor_counts.get("ADS", 0))

    try:
        detail = permission_risk_score_detail(
            dangerous=d,
            signature=s,
            vendor=v,
            groups=groups,
            target_sdk=target_sdk,
            allow_backup=allow_backup,
            legacy_external_storage=legacy_storage,
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
        "groups": groups,
        "fw_ds": set(fw_ds),
        "vendor_names": set(vendor_names),
        "risk_counts": risk_counts,
        "score_detail": detail,
    }


def _collect_masvs_profile(report) -> dict[str, object]:
    severity_map = {"P0": "High", "P1": "Medium", "P2": "Low", "NOTE": "Info"}
    counts: Dict[str, Dict[str, int]] = {area: {"High": 0, "Medium": 0, "Low": 0, "Info": 0} for area in ("NETWORK", "PLATFORM", "PRIVACY", "STORAGE")}
    highlights: Dict[str, Counter[str]] = {area: Counter() for area in counts}
    has_values = False
    for result in getattr(report, "detector_results", []) or []:
        for finding in getattr(result, "findings", []) or []:
            area_obj = getattr(finding, "category_masvs", None)
            area_value = None
            if hasattr(area_obj, "value"):
                area_value = getattr(area_obj, "value")
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
        for sample in http_samples:
            st = str(sample.get("source_type") or "").lower()
            scheme = str(sample.get("scheme") or "").lower()
            root = str(sample.get("root_domain") or "")
            if scheme != "http":
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


def _build_static_risk_row(report, string_data: Mapping[str, object], permission_profile: Optional[dict], app_result) -> Optional[dict[str, object]]:
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
        if not isinstance(entries, Sequence):
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


def _compute_trend_delta(package_name: str, session_stamp: str | None, finding_totals: Counter[str]) -> Optional[dict[str, object]]:
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


def _format_masvs_cell(area_counts: Mapping[str, int]) -> str:
    high = int(area_counts.get("High", 0))
    medium = int(area_counts.get("Medium", 0))
    low = int(area_counts.get("Low", 0))
    info = int(area_counts.get("Info", 0))
    if high > 0:
        status = "FAIL"
        palette = colors.style("error")
    elif medium > 0:
        status = "WARN"
        palette = colors.style("warning")
    else:
        status = "PASS"
        palette = colors.style("success")
    summary = f"{status} H{high}/M{medium}"
    if colors.colors_enabled():
        return colors.apply(summary, palette, bold=True)
    return summary


def _render_masvs_matrix_local(
    matrix: Mapping[str, Mapping[str, object]],
    *,
    limit: int = 15,
) -> bool:
    if not matrix:
        return False
    areas = ("NETWORK", "PLATFORM", "PRIVACY", "STORAGE")

    def _score(entry: Mapping[str, object]) -> tuple[int, int, int]:
        counts = entry.get("counts") if isinstance(entry, Mapping) else {}
        if not isinstance(counts, Mapping):
            counts = {}
        total_high = sum((counts.get(area, {}) or {}).get("High", 0) for area in areas)
        total_medium = sum((counts.get(area, {}) or {}).get("Medium", 0) for area in areas)
        total_low = sum((counts.get(area, {}) or {}).get("Low", 0) for area in areas)
        return (total_high, total_medium, total_low)

    ordered = sorted(
        matrix.items(),
        key=lambda item: _score(item[1]),
        reverse=True,
    )[:limit]
    if not ordered:
        return False

    print("\nMASVS Matrix — Current run snapshot")
    headers = ["App", "Network", "Platform", "Privacy", "Storage", "Totals"]
    table_payload: list[list[str]] = []
    for _, entry in ordered:
        counts = entry.get("counts") if isinstance(entry, Mapping) else {}
        if not isinstance(counts, Mapping):
            counts = {}
        label = str(entry.get("label") or entry.get("package") or "—")
        row = [label]
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
    table_utils.render_table(headers, table_payload, accent_first_column=False)
    return True


def _render_static_risk_table(rows: Sequence[dict[str, object]], *, limit: int = 15) -> bool:
    if not rows:
        return False
    ordered = sorted(rows, key=lambda item: item.get("total", 0.0), reverse=True)[:limit]
    if not ordered:
        return False
    print("\nStatic Risk Scores — Composite buckets")
    headers = [
        "Grade",
        "Total",
        "App",
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
                str(entry.get("grade") or "N/A"),
                f"{float(entry.get('total', 0.0)):.1f}",
                label,
                f"{float(entry.get('permission', 0.0)):.1f}",
                f"{float(entry.get('network', 0.0)):.1f}",
                f"{float(entry.get('storage', 0.0)):.1f}",
                f"{float(entry.get('components', 0.0)):.1f}",
                f"{float(entry.get('secrets', 0.0)):.1f}",
                f"{float(entry.get('webssl', 0.0)):.1f}",
                f"{float(entry.get('correlation', 0.0)):.1f}",
            ]
        )
    table_utils.render_table(headers, table_rows, accent_first_column=False)
    return True


def _percentile(values: Sequence[float], pct: float) -> float:
    if not values:
        return 0.0
    ordered = sorted(values)
    if len(ordered) == 1:
        return float(ordered[0])
    k = (len(ordered) - 1) * pct
    f = math.floor(k)
    c = math.ceil(k)
    if f == c:
        return float(ordered[int(k)])
    d0 = ordered[f] * (c - k)
    d1 = ordered[c] * (k - f)
    return float(d0 + d1)


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
        print(f"• Permissions: median dangerous={med_d:.1f}, 90th percentile dangerous={p90_d:.1f}, median signature={med_s:.1f}")

    if component_profiles:
        component_totals = [stats["activities"] + stats["services"] + stats["receivers"] + stats["providers"] for stats in component_profiles]
        top_components = sorted(component_profiles, key=lambda item: item["activities"] + item["services"] + item["receivers"] + item["providers"], reverse=True)[:5]
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
        print(f"• Secrets: total API keys={total_api}, high-entropy samples={total_entropy}, top tags: {top_tags}")

    if finding_profiles:
        combined = Counter()
        for profile in finding_profiles:
            combined.update(profile.get("counter", Counter()))
        if combined:
            top_findings = ", ".join(f"{sev} {name}×{count}" for (sev, name), count in combined.most_common(5))
            print(f"• Recurring findings: {top_findings}")

    if trend_deltas:
        changes = [delta for delta in trend_deltas if any(delta.get(key) for key in ("delta_high", "delta_medium", "delta_low"))]
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


def _render_db_severity_table(session_stamp: str) -> bool:
    try:
        rows = core_q.run_sql(
            """
            SELECT s.package_name, COALESCE(r.target_sdk, '—') AS target_sdk,
                   s.high, s.med, s.low, s.info
            FROM static_findings_summary s
            LEFT JOIN runs r
              ON r.package = s.package_name
             AND r.session_stamp = s.session_stamp
            WHERE s.session_stamp = %s
            ORDER BY s.package_name
            """,
            (session_stamp,),
            fetch="all",
            dictionary=True,
        ) or []
    except Exception:
        return False

    if not rows:
        return False

    table_rows = []
    for idx, row in enumerate(rows, start=1):
        table_rows.append(
            [
                str(idx),
                row.get("package_name", "—"),
                str(row.get("target_sdk", "—")),
                str(int(row.get("high") or 0)),
                str(int(row.get("med") or 0)),
                str(int(row.get("low") or 0)),
                str(int(row.get("info") or 0)),
            ]
        )

    print()
    table_utils.render_table(
        ["#", "Package", "targetSdk", "High", "Medium", "Low", "Information"],
        table_rows,
    )
    return True


def _render_persistence_footer(session_stamp: str, *, had_errors: bool = False) -> None:
    try:
        run_rows = core_q.run_sql(
            "SELECT run_id FROM runs WHERE session_stamp = %s",
            (session_stamp,),
            fetch="all",
        ) or []
    except Exception:
        return

    run_ids = [int(row[0]) for row in run_rows if row and row[0] is not None]

    def _count(sql: str, params: tuple[object, ...]) -> int:
        try:
            row = core_q.run_sql(sql, params, fetch="one")
        except Exception:
            return 0
        if not row:
            return 0
        value = row[0] if not isinstance(row, dict) else next(iter(row.values()), 0)
        try:
            return int(value or 0)
        except (TypeError, ValueError):
            return 0

    def _count_total(sql: str) -> int:
        try:
            row = core_q.run_sql(sql, fetch="one")
        except Exception:
            return 0
        if not row:
            return 0
        value = row[0] if not isinstance(row, dict) else next(iter(row.values()), 0)
        try:
            return int(value or 0)
        except (TypeError, ValueError):
            return 0

    findings_summary = _count(
        "SELECT COUNT(*) FROM static_findings_summary WHERE session_stamp = %s",
        (session_stamp,),
    )
    findings_summary_total = _count_total("SELECT COUNT(*) FROM static_findings_summary")
    findings_detail = _count(
        """
        SELECT COUNT(*)
        FROM static_findings f
        JOIN static_findings_summary s ON s.id = f.summary_id
        WHERE s.session_stamp = %s
        """,
        (session_stamp,),
    )
    findings_detail_total = _count_total("SELECT COUNT(*) FROM static_findings")
    strings_summary = _count(
        "SELECT COUNT(*) FROM static_string_summary WHERE session_stamp = %s",
        (session_stamp,),
    )
    strings_summary_total = _count_total("SELECT COUNT(*) FROM static_string_summary")
    string_samples = _count(
        """
        SELECT COUNT(*)
        FROM static_string_samples x
        JOIN static_findings_summary s ON s.id = x.summary_id
        WHERE s.session_stamp = %s
        """,
        (session_stamp,),
    )
    string_samples_total = _count_total("SELECT COUNT(*) FROM static_string_samples")
    fileproviders = _count(
        "SELECT COUNT(*) FROM static_fileproviders WHERE session_stamp = %s",
        (session_stamp,),
    )
    fileproviders_total = _count_total("SELECT COUNT(*) FROM static_fileproviders")
    provider_acl = _count(
        "SELECT COUNT(*) FROM static_provider_acl WHERE session_stamp = %s",
        (session_stamp,),
    )
    provider_acl_total = _count_total("SELECT COUNT(*) FROM static_provider_acl")

    buckets = metrics = findings = contributors = 0
    if run_ids:
        placeholders = ",".join(["%s"] * len(run_ids))
        params = tuple(run_ids)
        buckets = _count(
            f"SELECT COUNT(*) FROM buckets WHERE run_id IN ({placeholders})",
            params,
        )
        metrics = _count(
            f"SELECT COUNT(*) FROM metrics WHERE run_id IN ({placeholders})",
            params,
        )
        findings = _count(
            f"SELECT COUNT(*) FROM findings WHERE run_id IN ({placeholders})",
            params,
        )
        contributors = _count(
            f"SELECT COUNT(*) FROM contributors WHERE run_id IN ({placeholders})",
            params,
        )

    runs_total = _count_total("SELECT COUNT(*) FROM runs")
    buckets_total = _count_total("SELECT COUNT(*) FROM buckets")
    metrics_total = _count_total("SELECT COUNT(*) FROM metrics")
    findings_total = _count_total("SELECT COUNT(*) FROM findings")
    contributors_total = _count_total("SELECT COUNT(*) FROM contributors")

    print()
    print("Persisted")
    print("==========")
    lines = [
        ("runs", f"{len(run_ids)} (total={runs_total})"),
        ("static_findings_summary", f"{findings_summary} (total={findings_summary_total})"),
        ("static_findings", f"{findings_detail} (total={findings_detail_total})"),
        ("static_string_summary", f"{strings_summary} (total={strings_summary_total})"),
        ("static_string_samples", f"{string_samples} (total={string_samples_total})"),
        ("static_fileproviders", f"{fileproviders} (total={fileproviders_total})"),
        ("static_provider_acl", f"{provider_acl} (total={provider_acl_total})"),
        ("buckets", f"{buckets} (total={buckets_total})"),
        ("metrics", f"{metrics} (total={metrics_total})"),
        ("findings", f"{findings} (total={findings_total})"),
        ("contributors", f"{contributors} (total={contributors_total})"),
    ]
    width = max(len(name) for name, _ in lines) if lines else 0
    for name, detail in lines:
        print(f"  {name.ljust(width)} : {detail}")
    if had_errors:
        print(f"  {'status'.ljust(width)} : ERROR (see logs)")


__all__ = ["render_run_results"]
