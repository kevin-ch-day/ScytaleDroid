"""High-level run persistence helpers (buckets, metrics, findings, contributors)."""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from functools import lru_cache
from pathlib import Path
from typing import Any, Dict, Iterable, List, Mapping, MutableMapping, Optional, Sequence, Tuple

try:
    import yaml
except Exception:  # pragma: no cover - optional dependency
    yaml = None

from scytaledroid.Persistence import db_writer as _dw
from scytaledroid.Utils.LoggingUtils import logging_utils as log
from scytaledroid.StaticAnalysis.modules.permissions.simple import (
    _classify_permissions as _classify,
    _fetch_protections as _prot_map,
)
from scytaledroid.StaticAnalysis.modules.permissions.analysis.scoring import (
    permission_risk_score_detail as _perm_detail,
    permission_points_0_20 as _perm_pts,
)
from scytaledroid.Database.db_func.static_analysis import (
    static_findings as _sf,
    string_analysis as _sa,
)
from scytaledroid.Database.db_core import db_queries as core_q
from .cvss_v4 import apply_profiles, score_vector
from .evidence import normalize_evidence
from .masvs_mapper import summarise_controls, rule_to_area
from .rule_mapping import derive_rule_id


_CVSS_BASE_ORDER = ("AV", "AC", "AT", "PR", "UI", "VC", "VI", "VA", "SC", "SI", "SA")


def _first_non_empty_str(*values: object) -> Optional[str]:
    for value in values:
        if isinstance(value, str):
            candidate = value.strip()
        elif value is None:
            candidate = ""
        else:
            candidate = str(value).strip()
        if candidate:
            return candidate
    return None


def _extract_from_sources(
    sources: Sequence[Mapping[str, Any]],
    paths: Sequence[Sequence[str]],
) -> Optional[str]:
    for source in sources:
        if not isinstance(source, Mapping):
            continue
        for path in paths:
            current: Any = source
            for key in path:
                if not isinstance(current, Mapping):
                    break
                current = current.get(key)
            else:
                candidate = _first_non_empty_str(current)
                if candidate:
                    return candidate
    return None


def _extract_run_profiles(
    report: Any,
    baseline_payload: Mapping[str, object],
) -> tuple[str, str]:
    metadata = getattr(report, "metadata", None)
    metadata_map: Mapping[str, Any] = metadata if isinstance(metadata, Mapping) else {}
    baseline_map: Mapping[str, Any] = baseline_payload if isinstance(baseline_payload, Mapping) else {}
    baseline_section_raw = (
        baseline_map.get("baseline") if isinstance(baseline_map.get("baseline"), Mapping) else {}
    )
    baseline_section: Mapping[str, Any] = (
        baseline_section_raw if isinstance(baseline_section_raw, Mapping) else {}
    )

    sources: Sequence[Mapping[str, Any]] = (
        metadata_map,
        baseline_map,
        baseline_section,
    )

    threat_candidate = _extract_from_sources(
        sources,
        (
            ("threat_profile",),
            ("threatProfile",),
            ("threat_profile_code",),
            ("profiles", "threat", "profile"),
            ("profiles", "threat", "code"),
            ("threat", "profile"),
            ("threat", "code"),
            ("risk", "threat_profile"),
            ("risk", "threat", "profile"),
        ),
    )
    env_candidate = _extract_from_sources(
        sources,
        (
            ("env_profile",),
            ("environment_profile",),
            ("envProfile",),
            ("environmentProfile",),
            ("profiles", "env", "profile"),
            ("profiles", "environment", "profile"),
            ("env", "profile"),
            ("environment", "profile"),
        ),
    )

    threat_profile = threat_candidate or "Unknown"
    env_profile = env_candidate or "consumer"
    return threat_profile, env_profile


def _extract_rule_hint(finding: Any) -> Optional[str]:
    for attr in ("rule_id_hint", "rule_id", "rule"):
        value = getattr(finding, attr, None)
        if isinstance(value, str) and value.strip():
            return value.strip()
    extra = getattr(finding, "extra", None)
    if isinstance(extra, Mapping):
        candidate = extra.get("rule_id")
        if isinstance(candidate, str) and candidate.strip():
            return candidate.strip()
    return None


def _normalise_masvs_value(value: object) -> Optional[str]:
    if value is None:
        return None
    if isinstance(value, Mapping):
        value = value.get("value")
    if hasattr(value, "value"):
        try:
            value = getattr(value, "value")
        except Exception:  # pragma: no cover - defensive
            return None
    text = str(value or "").strip()
    if not text:
        return None
    text = text.replace("MASVS-", "")
    parts = [segment for segment in text.replace("_", "-").split("-") if segment]
    if not parts:
        return None
    return parts[0].upper()


def _derive_masvs_tag(finding: Any, rule_id: Optional[str]) -> Optional[str]:
    for attr in ("category_masvs", "masvs", "category", "masvs_category"):
        candidate = _normalise_masvs_value(getattr(finding, attr, None))
        if candidate:
            return candidate
    if rule_id:
        area = rule_to_area(rule_id)
        if area:
            return area
    return None


_FALLBACK_RULE_CVSS: Dict[str, Dict[str, object]] = {
    "BASE-IPC-COMP-NO-ACL": {
        "vector": "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:L/VI:L/VA:L/SC:N/SI:N/SA:N",
        "score": 8.0,
        "rationale": "Exported component without permission allows external apps to trigger privileged code paths.",
    },
    "BASE-IPC-EXPORTED-WITH-PERM": {
        "vector": "CVSS:4.0/AV:A/AC:L/AT:N/PR:L/UI:N/VC:N/VI:N/VA:N/SC:N/SI:N/SA:N",
        "score": 2.5,
        "rationale": "Exported component guarded by a permission; residual risk depends on permission strength and grant path.",
    },
    "BASE-CLR-001": {
        "vector": "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:R/VC:L/VI:N/VA:N/SC:N/SI:N/SA:N",
        "score": 4.5,
        "rationale": "Cleartext allowed; exploitation often needs user navigation in WebView contexts.",
    },
    "BASE-STO-LEGACY": {
        "vector": "CVSS:4.0/AV:L/AC:L/AT:N/PR:N/UI:N/VC:N/VI:L/VA:N/SC:N/SI:N/SA:N",
        "score": 3.9,
        "rationale": "Legacy external storage broadens read/write surface for other apps.",
    },
}


@lru_cache(maxsize=1)
def _load_cvss_v4_config() -> Optional[Dict[str, Any]]:
    path = Path("config/cvss_v4_map.yaml")
    if not path.exists() or yaml is None:
        return None
    try:
        data = yaml.safe_load(path.read_text("utf-8"))
    except Exception:
        return None
    if not isinstance(data, dict):
        return None
    defaults = data.get("defaults") or {}
    rule_entries = {}
    for entry in data.get("rules", []):
        if not isinstance(entry, dict):
            continue
        rid = entry.get("detector_id")
        if not rid:
            continue
        rule_entries[str(rid)] = entry
    return {"defaults": defaults, "rules": rule_entries}


def _build_cvss_vector(metrics: Mapping[str, str]) -> Optional[str]:
    entries = []
    for key in _CVSS_BASE_ORDER:
        value = metrics.get(key)
        if value:
            entries.append(f"{key}:{value}")
    if not entries:
        return None
    return "CVSS:4.0/" + "/".join(entries)


def _compute_cvss_base(rule_id: Optional[str]) -> Tuple[Optional[str], Optional[float], Dict[str, Any]]:
    if not rule_id:
        return None, None, {}
    config = _load_cvss_v4_config()
    defaults = (config or {}).get("defaults", {})
    base_defaults = defaults.get("base") or {}
    rule_cfg = (config or {}).get("rules", {}).get(rule_id)

    if not rule_cfg and rule_id in _FALLBACK_RULE_CVSS:
        spec = _FALLBACK_RULE_CVSS[rule_id]
        meta = {"base": {"rationale": spec.get("rationale"), "rule_id": rule_id, "source": "fallback"}}
        vector = spec.get("vector")
        score = spec.get("score")
        return vector, float(score) if isinstance(score, (int, float)) else None, meta

    if not rule_cfg:
        return None, None, {}

    base_metrics = dict(base_defaults)
    base_metrics.update(rule_cfg.get("base") or {})
    vector = _build_cvss_vector(base_metrics)
    score = None
    fallback = _FALLBACK_RULE_CVSS.get(rule_id)
    if fallback and isinstance(fallback.get("score"), (int, float)):
        score = float(fallback["score"])
    if vector and score is None:
        score = score_vector(vector)
    meta: Dict[str, Any] = {
        "base": {
            "metrics": base_metrics,
            "rationale": rule_cfg.get("rationale") or (fallback and fallback.get("rationale")),
            "rule_id": rule_id,
            "source": "cvss_v4_map",
        }
    }
    supplemental = rule_cfg.get("supplemental")
    if supplemental:
        meta["supplemental"] = supplemental
    return vector, score, meta



def _truncate(value: Optional[str], limit: int) -> Optional[str]:
    if value is None:
        return None
    value = str(value)
    if len(value) <= limit:
        return value
    return value[: limit - 3] + "..."


def _coerce_mapping(obj: Any) -> Dict[str, Any]:
    if obj is None:
        return {}
    if isinstance(obj, dict):
        return {k: v for k, v in obj.items()}
    data: Dict[str, Any] = {}
    for attr in dir(obj):
        if attr.startswith("_"):
            continue
        try:
            value = getattr(obj, attr)
        except Exception:  # pragma: no cover - defensive
            continue
        if callable(value):
            continue
        data[attr] = value
    return data



def _persist_findings(run_id: int, rows: Sequence[Dict[str, Any]]) -> bool:
    try:
        core_q.run_sql("DELETE FROM findings WHERE run_id=%s", (run_id,))
    except Exception:
        pass
    try:
        for row in rows:
            core_q.run_sql(
                """
                INSERT INTO findings (
                    run_id, severity, masvs, cvss, kind, evidence, module_id,
                    cvss_v40_b_score, cvss_v40_bt_score, cvss_v40_be_score, cvss_v40_bte_score,
                    cvss_v40_b_vector, cvss_v40_bt_vector, cvss_v40_be_vector, cvss_v40_bte_vector,
                    cvss_v40_meta, analyst_tag, evidence_path, evidence_offset, evidence_preview, rule_id
                ) VALUES (
                    %s,%s,%s,%s,%s,%s,%s,
                    %s,%s,%s,%s,
                    %s,%s,%s,%s,
                    %s,%s,%s,%s,%s,%s
                )
                """,
                (
                    run_id,
                    row.get("severity"),
                    row.get("masvs"),
                    _truncate(row.get("cvss"), 128),
                    row.get("kind"),
                    _truncate(row.get("evidence"), 512),
                    row.get("module_id"),
                    row.get("cvss_v40_b_score"),
                    row.get("cvss_v40_bt_score"),
                    row.get("cvss_v40_be_score"),
                    row.get("cvss_v40_bte_score"),
                    row.get("cvss_v40_b_vector"),
                    row.get("cvss_v40_bt_vector"),
                    row.get("cvss_v40_be_vector"),
                    row.get("cvss_v40_bte_vector"),
                    row.get("cvss_v40_meta"),
                    None,
                    _truncate(row.get("evidence_path"), 512),
                    _truncate(row.get("evidence_offset"), 64),
                    _truncate(row.get("evidence_preview"), 256),
                    row.get("rule_id"),
                ),
            )
        return True
    except Exception:
        return False


def _persist_masvs_controls(run_id: int, package: str, coverage: Mapping[str, Any]) -> None:
    try:
        core_q.run_sql("DELETE FROM masvs_control_coverage WHERE run_id=%s", (run_id,))
    except Exception:
        pass
    for control_id, entry in coverage.items():
        try:
            payload_attr = getattr(entry, "payload", None)
            if callable(payload_attr):
                payload_map = payload_attr()
            elif isinstance(entry, Mapping):
                payload_map = entry
            else:
                continue
            evidence = json.dumps(payload_map.get("evidence") or [], ensure_ascii=False)
            rubric = json.dumps(payload_map.get("rubric") or {}, ensure_ascii=False)
            core_q.run_sql(
                """
                INSERT INTO masvs_control_coverage (run_id, package, control_id, status, evidence, rubric)
                VALUES (%s,%s,%s,%s,%s,%s)
                ON DUPLICATE KEY UPDATE status=VALUES(status), evidence=VALUES(evidence), rubric=VALUES(rubric)
                """,
                (run_id, package, control_id, payload_map.get("status"), evidence, rubric),
            )
        except Exception:
            continue


def _persist_storage_surface_data(report, session_stamp: str, scope_label: str) -> None:
    try:
        from scytaledroid.StaticAnalysis.modules.storage_surface import (
            AppModuleContext,
            StorageSurfaceModule,
        )
    except Exception:
        return

    apk_path = getattr(report, "file_path", None)
    package_name = getattr(report.manifest, "package_name", None) or report.metadata.get("package")
    if not apk_path or not package_name:
        return

    metadata = dict(report.metadata or {})
    context = AppModuleContext(
        report=report,
        package_name=str(package_name),
        apk_path=Path(apk_path),
        metadata=metadata,
        session_stamp=session_stamp,
        scope_label=scope_label,
    )

    module = StorageSurfaceModule()
    try:
        module_result = module.run(context)
        module.persist(module_result)
    except Exception:
        return



@dataclass(slots=True)
class PersistenceOutcome:
    run_id: int | None = None
    errors: list[str] = field(default_factory=list)

    @property
    def success(self) -> bool:
        return not self.errors

    def add_error(self, message: str) -> None:
        self.errors.append(message)


def persist_run_summary(
    base_report,
    string_data: Mapping[str, object],
    run_package: str,
    *,
    session_stamp: str | None,
    scope_label: str,
    finding_totals: Mapping[str, int],
    baseline_payload: Mapping[str, object],
    dry_run: bool = False,
) -> PersistenceOutcome:
    outcome = PersistenceOutcome()
    br = base_report
    if dry_run:
        log.info(
            f"Dry-run enabled; persistence for {run_package} will be simulated",
            category="static_analysis",
        )

    if not session_stamp:
        try:
            meta = getattr(br, "metadata", {}) or {}
            value = meta.get("session_stamp")
            if isinstance(value, str) and value.strip():
                session_stamp = value.strip()
        except Exception:
            pass

    if not session_stamp:
        message = f"Missing session stamp for {run_package}; static persistence will be skipped."
        log.warning(message, category="static_analysis")
        outcome.add_error(message)
        return outcome

    target_sdk = None
    try:
        target_sdk = int(br.manifest.target_sdk) if br.manifest.target_sdk else None
    except Exception:
        target_sdk = None

    threat_profile_value, env_profile_value = _extract_run_profiles(br, baseline_payload)
    run_id: Optional[int] = None
    if not dry_run:
        run_id = _dw.create_run(
            package=br.manifest.package_name or run_package,
            version_code=int(br.manifest.version_code) if br.manifest.version_code else None,
            version_name=br.manifest.version_name,
            target_sdk=target_sdk,
            session_stamp=session_stamp,
            threat_profile=threat_profile_value,
            env_profile=env_profile_value,
        )
        if not run_id:
            message = f"Failed to create run record for {run_package}"
            log.warning(message, category="static_analysis")
            outcome.add_error(message)
            return outcome
        outcome.run_id = int(run_id)

    threat_profile = threat_profile_value
    env_profile = env_profile_value
    if run_id is not None:
        run_profile_row: Optional[Mapping[str, Any]] = None
        try:
            row = core_q.run_sql(
                "SELECT threat_profile, env_profile FROM runs WHERE run_id=%s",
                (run_id,),
                fetch="one",
                dictionary=True,
            )
            if isinstance(row, Mapping):
                run_profile_row = row
        except Exception:
            run_profile_row = None

        if run_profile_row:
            threat_profile = _first_non_empty_str(run_profile_row.get("threat_profile"), threat_profile) or "Unknown"
            env_profile = _first_non_empty_str(run_profile_row.get("env_profile"), env_profile) or "consumer"

    declared = list(br.permissions.declared or ())
    shorts_only = [n.split(".")[-1].upper() for n in declared if n.startswith("android.")]
    pmap = _prot_map(shorts_only)
    rc, groups, vc, _fw_ds, _vn = _classify([(n, "uses-permission") for n in declared], pmap)
    d = rc.get("dangerous", 0)
    s = rc.get("signature", 0)
    v = vc.get("ADS", 0)
    flags = br.manifest_flags
    d_detail = _perm_detail(
        dangerous=d,
        signature=s,
        vendor=v,
        groups=groups,
        target_sdk=target_sdk,
        allow_backup=flags.allow_backup,
        legacy_external_storage=flags.request_legacy_external_storage,
    )
    perm_points = _perm_pts(float(d_detail.get("score_3dp", 0.0)))

    # Compute code-path and asset HTTP hosts for metrics
    def _code_asset_http_counts() -> tuple[int, int]:
        try:
            samples = string_data.get("samples", {}) if isinstance(string_data, dict) else {}
            http_samples = (samples.get("http_cleartext") or []) + (samples.get("endpoints") or [])
            code_hosts: set[str] = set()
            asset_hosts: set[str] = set()
            for s in http_samples:
                st = str(s.get("source_type") or "").lower()
                scheme = str(s.get("scheme") or "").lower()
                root = str(s.get("root_domain") or "")
                if scheme != "http":
                    continue
                if st in {"code", "dex", "native"}:
                    code_hosts.add(root or "")
                else:
                    asset_hosts.add(root or "")
            return (len({h for h in code_hosts if h}), len({h for h in asset_hosts if h}))
        except Exception:
            return (0, 0)

    code_http_hosts, asset_http_hosts = _code_asset_http_counts()
    has_code_http = code_http_hosts > 0
    uses_ct = bool(flags.uses_cleartext_traffic)
    net_points = 20.0 if (uses_ct and has_code_http) else (5.0 if has_code_http else 0.0)

    sto_points = 10.0 if bool(flags.request_legacy_external_storage) else 0.0
    exp_total = br.exported_components.total()
    comp_points = float(min(15, exp_total))
    agg = string_data.get("aggregates", {}) if isinstance(string_data, dict) else {}
    validated = len(agg.get("api_keys_high", []) or [])
    entropy = int(string_data.get("counts", {}).get("high_entropy", 0)) if isinstance(string_data, dict) else 0
    secrets_points = float(min(25, validated)) + float(min(5, 5 if entropy else 0))
    webssl_points = 0.0
    corr_points = 0.0
    if has_code_http and ("android.permission.INTERNET" in declared):
        corr_points += 1.0
    if any(p.endswith("READ_CONTACTS") for p in declared) and agg.get("endpoint_roots"):
        corr_points += 1.0
    corr_points = min(5.0, corr_points)

    buckets_payload = {
        "permissions": (perm_points, 20.0),
        "network": (net_points, 20.0),
        "storage": (sto_points, 10.0),
        "components": (comp_points, 15.0),
        "secrets": (secrets_points, 25.0),
        "webssl": (webssl_points, 10.0),
        "correlations": (corr_points, 5.0),
    }
    if run_id is not None and not _dw.write_buckets(int(run_id), buckets_payload):
        message = f"Failed to persist scoring buckets for run_id={run_id}"
        log.warning(message, category="static_analysis")
        outcome.add_error(message)

    severity_map = {"P0": "High", "P1": "Medium", "P2": "Low", "NOTE": "Info"}
    cvss_v4_config = _load_cvss_v4_config()
    # threat_profile and env_profile determined above

    finding_rows: List[Dict[str, Any]] = []
    control_entries: List[Tuple[str, Mapping[str, Any]]] = []
    total_findings = 0
    rule_assigned = 0
    base_vector_count = 0
    bte_vector_count = 0
    preview_assigned = 0
    path_assigned = 0

    try:
        for result in (br.detector_results or ()):  # type: ignore[attr-defined]
            detector_id = str(getattr(result, "detector_id", getattr(result, "section_key", None)) or "unknown")
            module_id_val = getattr(result, "module_id", None)
            module_id = str(module_id_val) if module_id_val not in (None, "") else None
            for f in result.findings:
                total_findings += 1
                sev = severity_map.get(f.severity_gate.value, "Info")
                evidence = normalize_evidence(
                    f.evidence,
                    detail_hint=getattr(f, "detail", None)
                    or getattr(f, "headline", None)
                    or getattr(f, "summary", None)
                    or getattr(f, "because", None),
                    path_hint=getattr(f, "path", None),
                    offset_hint=getattr(f, "offset", None),
                )
                evidence_payload = json.dumps(evidence.as_payload(), ensure_ascii=False)
                evidence_path = evidence.path
                evidence_offset = evidence.offset
                evidence_preview = evidence.detail
                if evidence_preview:
                    preview_assigned += 1
                if evidence_path:
                    path_assigned += 1
                rule_id = derive_rule_id(
                    detector_id,
                    module_id,
                    evidence_path,
                    evidence_preview,
                    rule_id_hint=_extract_rule_hint(f),
                )
                if rule_id:
                    rule_assigned += 1
                masvs_area = _derive_masvs_tag(f, rule_id)
                base_vector, base_score, base_meta = _compute_cvss_base(rule_id)
                if base_vector:
                    base_vector_count += 1
                (
                    bt_vector,
                    bt_score,
                    be_vector,
                    be_score,
                    bte_vector,
                    bte_score,
                    profile_meta,
                ) = apply_profiles(base_vector, threat_profile, env_profile)
                if bte_vector:
                    bte_vector_count += 1
                meta_combined: Dict[str, Any] = {}
                if base_meta:
                    meta_combined.update(base_meta)
                if profile_meta:
                    meta_combined.update(profile_meta)
                finding_rows.append(
                    {
                        "severity": sev,
                        "masvs": masvs_area,
                        "cvss": base_vector,
                        "kind": detector_id,
                        "module_id": module_id,
                        "evidence": evidence_payload,
                        "evidence_path": evidence_path,
                        "evidence_offset": evidence_offset,
                        "evidence_preview": evidence_preview,
                        "rule_id": rule_id,
                        "cvss_v40_b_vector": base_vector,
                        "cvss_v40_b_score": base_score,
                        "cvss_v40_bt_vector": bt_vector,
                        "cvss_v40_bt_score": bt_score,
                        "cvss_v40_be_vector": be_vector,
                        "cvss_v40_be_score": be_score,
                        "cvss_v40_bte_vector": bte_vector,
                        "cvss_v40_bte_score": bte_score,
                        "cvss_v40_meta": json.dumps(meta_combined, ensure_ascii=False) if meta_combined else None,
                    }
                )

                if rule_id:
                    control_entries.append(
                        (
                            rule_id,
                            {
                                "kind": detector_id,
                                "path": evidence_path,
                                "note": evidence_preview or rule_id or detector_id,
                                "rule": rule_id,
                            },
                        )
                    )
    except Exception as exc:
        message = f"Failed to collate findings for {run_package}: {exc}"
        log.warning(message, category="static_analysis")
        outcome.add_error(message)

    control_summary = summarise_controls(control_entries)

    if finding_rows:
        if run_id is None:
            sample = finding_rows[0] if finding_rows else {}
            sample_view = {
                key: sample.get(key)
                for key in ("rule_id", "evidence_path", "evidence_preview", "severity")
            }
            log.info(
                (
                    f"Dry-run persistence payload for {run_package}: "
                    f"findings={total_findings} "
                    f"sample={json.dumps(sample_view, ensure_ascii=False)}"
                ),
                category="static_analysis",
            )
        elif not _persist_findings(int(run_id), finding_rows):
            message = f"Failed to persist findings for run_id={run_id}"
            log.warning(message, category="static_analysis")
            outcome.add_error(message)
        else:
            _persist_masvs_controls(
                int(run_id),
                br.manifest.package_name or run_package,
                control_summary,
            )
            _persist_storage_surface_data(br, session_stamp, scope_label)

    metrics_payload = {
        "network.code_http_hosts": (float(code_http_hosts), None),
        "network.asset_http_hosts": (float(asset_http_hosts), None),
        "exports.total": (float(exp_total), None),
    }
    metrics_payload["findings.total"] = (float(total_findings), None)
    rule_cov_pct = (float(rule_assigned) / float(total_findings) * 100.0) if total_findings else 0.0
    base_cov_pct = (float(base_vector_count) / float(total_findings) * 100.0) if total_findings else 0.0
    bte_cov_pct = (float(bte_vector_count) / float(total_findings) * 100.0) if total_findings else 0.0
    preview_cov_pct = (float(preview_assigned) / float(total_findings) * 100.0) if total_findings else 0.0
    path_cov_pct = (float(path_assigned) / float(total_findings) * 100.0) if total_findings else 0.0
    metrics_payload["findings.ruleid_coverage_pct"] = (rule_cov_pct, None)
    metrics_payload["findings.preview_coverage_pct"] = (preview_cov_pct, None)
    metrics_payload["findings.path_coverage_pct"] = (path_cov_pct, None)
    metrics_payload["cvss.base_vector_coverage_pct"] = (base_cov_pct, None)
    metrics_payload["cvss.bte_vector_coverage_pct"] = (bte_cov_pct, None)

    if run_id is not None and not _dw.write_metrics(int(run_id), metrics_payload):
        message = f"Failed to persist metrics for run_id={run_id}"
        log.warning(message, category="static_analysis")
        outcome.add_error(message)

    summary_run_id = run_id if run_id is not None else "dry-run"
    log.info(
        (
            f"Persistence summary for {run_package} (run_id={summary_run_id}): "
            f"findings={total_findings} "
            f"rule_id={rule_cov_pct:.1f}% "
            f"preview={preview_cov_pct:.1f}% "
            f"path={path_cov_pct:.1f}% "
            f"bte={bte_cov_pct:.1f}%"
        ),
        category="static_analysis",
    )

    contributors = []
    try:
        sig_components = d_detail.get("signal_components", {})
        breadth = float(d_detail.get("breadth", {}).get("applied", 0.0) or 0.0)
        modernization = float(d_detail.get("modernization_credit", 0.0) or 0.0)

        def _points(value: float) -> float:
            return round(float(value) * 2.0, 2)

        if sig_components:
            dangerous_pts = _points(sig_components.get("dangerous", 0.0))
            signature_pts = _points(sig_components.get("signature", 0.0))
            vendor_pts = _points(sig_components.get("vendor", 0.0))
            if dangerous_pts:
                contributors.append(("permissions_dangerous", dangerous_pts, f"Dangerous permissions footprint (+{dangerous_pts})", 0))
            if signature_pts:
                contributors.append(("permissions_signature", signature_pts, f"Signature-level capabilities (+{signature_pts})", 0))
            if vendor_pts:
                contributors.append(("permissions_vendor", vendor_pts, f"Vendor/ads permissions (+{vendor_pts})", 0))
        breadth_pts = _points(breadth)
        if breadth_pts:
            contributors.append(("permissions_breadth", breadth_pts, f"Capability breadth bonus (+{breadth_pts})", 0))
        modernization_pts = _points(modernization)
        if modernization_pts:
            contributors.append(("permissions_modernization", -modernization_pts, f"Modernization credit (targetSdk/flags) (−{modernization_pts})", 0))
        if net_points:
            if uses_ct and has_code_http:
                reason = "usesCleartextTraffic with code-path HTTP endpoints"
            elif has_code_http:
                reason = "HTTP endpoints observed in code paths"
            else:
                reason = "Network hygiene signal"
            contributors.append(("network", net_points, f"{reason} (+{net_points})", 0))
        if comp_points:
            contributors.append(("components", comp_points, f"Exported components without guards (+{comp_points})", 0))
        if sto_points:
            contributors.append(("storage", sto_points, f"Legacy storage flag/requestLegacyExternalStorage (+{sto_points})", 0))
        if secrets_points:
            contributors.append(("secrets", secrets_points, f"Validated secrets & entropy findings (+{secrets_points})", 0))
        if webssl_points:
            contributors.append(("webssl", webssl_points, f"WebView/SSL configuration signals (+{webssl_points})", 0))
        if corr_points:
            contributors.append(("correlations", corr_points, f"Composite risk correlations (+{corr_points})", 0))
    except Exception as exc:
        message = f"Failed to derive contributor weights for {run_package}: {exc}"
        log.warning(message, category="static_analysis")
        outcome.add_error(message)
        contributors = []

    if contributors:
        contrib_sorted = sorted(contributors, key=lambda row: abs(row[1]), reverse=True)
        contrib_ranked = [
            (name, round(points, 2), explanation, idx + 1)
            for idx, (name, points, explanation, _rank) in enumerate(contrib_sorted)
            if points or "modernization" in name
        ]
        if run_id is not None and contrib_ranked and not _dw.write_contributors(int(run_id), contrib_ranked):
            message = f"Failed to persist contributor breakdown for run_id={run_id}"
            log.warning(message, category="static_analysis")
            outcome.add_error(message)

    if run_id is not None:
        baseline_section = baseline_payload.get("baseline") if isinstance(baseline_payload, Mapping) else {}
        string_payload = baseline_section.get("string_analysis") if isinstance(baseline_section, Mapping) else {}
        static_errors = _persist_static_tables(
            package_name=br.manifest.package_name or run_package,
            session_stamp=session_stamp,
            scope_label=scope_label,
            finding_totals=finding_totals,
            baseline_section=baseline_section if isinstance(baseline_section, Mapping) else {},
            string_payload=string_payload if isinstance(string_payload, Mapping) else {},
        )
        for err in static_errors:
            outcome.add_error(err)

    return outcome


def _persist_static_tables(
    *,
    package_name: str,
    session_stamp: str,
    scope_label: str,
    finding_totals: Mapping[str, int],
    baseline_section: Mapping[str, object],
    string_payload: Mapping[str, object],
) -> list[str]:
    errors: list[str] = []

    severity_counts = _coerce_severity_counts(finding_totals)
    details = {
        "manifest_flags": baseline_section.get("manifest_flags"),
        "exports": baseline_section.get("exports"),
        "permissions": baseline_section.get("permissions"),
        "nsc": baseline_section.get("nsc"),
        "string_counts": (string_payload.get("counts") if isinstance(string_payload.get("counts"), Mapping) else {}),
    }

    try:
        if not _sf.ensure_tables():
            raise RuntimeError("static_findings tables unavailable")
        summary_id = _sf.upsert_summary(
            package_name=package_name,
            session_stamp=session_stamp,
            scope_label=scope_label,
            severity_counts=severity_counts,
            details=details,
        )
        if summary_id is None:
            raise RuntimeError("upsert_summary returned None")
        findings = baseline_section.get("findings")
        if isinstance(findings, Sequence) and findings:
            _sf.replace_findings(summary_id, tuple(findings))
    except Exception as exc:
        message = f"Failed to persist static findings summary for {package_name}: {exc}"
        log.warning(message, category="static_analysis")
        errors.append(message)

    try:
        if not _sa.ensure_tables():
            raise RuntimeError("static_string tables unavailable")
        counts = _normalise_string_counts(string_payload.get("counts"))
        summary_record = _sa.StringSummaryRecord(
            package_name=package_name,
            session_stamp=session_stamp,
            scope_label=scope_label,
            counts=counts,
        )
        summary_id = _sa.upsert_summary(summary_record)
        if summary_id is None:
            raise RuntimeError("upsert_summary returned None")
        samples_payload = string_payload.get("samples")
        samples = samples_payload if isinstance(samples_payload, Mapping) else {}
        _sa.replace_top_samples(summary_id, samples, top_n=3)
    except Exception as exc:
        message = f"Failed to persist string analysis summary for {package_name}: {exc}"
        log.warning(message, category="static_analysis")
        errors.append(message)

    return errors


def _coerce_severity_counts(totals: Mapping[str, int]) -> Mapping[str, int]:
    def _value(*keys: str) -> int:
        for key in keys:
            value = totals.get(key)
            if value is not None:
                try:
                    return int(value)
                except (TypeError, ValueError):
                    continue
        return 0

    return {
        "High": _value("High", "H"),
        "Medium": _value("Medium", "Med", "M"),
        "Low": _value("Low", "L"),
        "Info": _value("Info", "Information", "I"),
    }


def _normalise_string_counts(raw: object) -> Mapping[str, int]:
    source = raw if isinstance(raw, Mapping) else {}
    keys = (
        "endpoints",
        "http_cleartext",
        "api_keys",
        "analytics_ids",
        "cloud_refs",
        "ipc",
        "uris",
        "flags",
        "certs",
        "high_entropy",
    )
    return {key: int(source.get(key, 0) or 0) for key in keys}


__all__ = ["persist_run_summary", "PersistenceOutcome"]
