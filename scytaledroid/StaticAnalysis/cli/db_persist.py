"""High-level run persistence helpers (buckets, metrics, findings, contributors)."""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from functools import lru_cache
from pathlib import Path
import re
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


_CVSS_BASE_ORDER = ("AV", "AC", "AT", "PR", "UI", "VC", "VI", "VA", "SC", "SI", "SA")

_RULE_REGEXES: tuple[tuple[re.Pattern[str], str], ...] = (
    (re.compile(r"usesCleartextTraffic\s*=\s*true", re.IGNORECASE), "BASE-CLR-001"),
    (re.compile(r"\bcleartext\b", re.IGNORECASE), "BASE-CLR-001"),
    (re.compile(r"requestLegacyExternalStorage\s*=\s*true", re.IGNORECASE), "BASE-STO-LEGACY"),
    (
        re.compile(r"\b(Activity|Service|Receiver|Activity Alias|Provider)\b.*exported.*relies on.*\bpermission", re.IGNORECASE),
        "BASE-IPC-EXPORTED-WITH-PERM",
    ),
    (re.compile(r"\bexported\b.*\brelies on\b.*\bpermission", re.IGNORECASE), "BASE-IPC-EXPORTED-WITH-PERM"),
    (re.compile(r"ContentProvider.*(without|no)\s+permission", re.IGNORECASE), "BASE-IPC-PROVIDER-NO-ACL"),
    (
        re.compile(
            r"\b(Activity|Service|Receiver|Activity Alias|Provider)\b.*exported.*(does not d|does not decla|without)\s+permission",
            re.IGNORECASE,
        ),
        "BASE-IPC-COMP-NO-ACL",
    ),
)

_RULE_FORCE_PHRASES: tuple[tuple[str, str], ...] = (
    ("exported receiver relies on permission", "BASE-IPC-EXPORTED-WITH-PERM"),
    ("exported service relies on permission", "BASE-IPC-EXPORTED-WITH-PERM"),
    ("exported activity relies on permission", "BASE-IPC-EXPORTED-WITH-PERM"),
    ("exported provider relies on permission", "BASE-IPC-EXPORTED-WITH-PERM"),
    ("is exported but does not", "BASE-IPC-COMP-NO-ACL"),
)

_RULE_TO_MASVS: Dict[str, Tuple[str, str]] = {
    "BASE-IPC-COMP-NO-ACL": ("PLATFORM-IPC-1", "FAIL"),
    "BASE-IPC-PROVIDER-NO-ACL": ("PLATFORM-IPC-1", "FAIL"),
    "BASE-IPC-EXPORTED-WITH-PERM": ("PLATFORM-IPC-1", "PASS"),
    "BASE-CLR-001": ("NETWORK-1", "FAIL"),
    "BASE-STO-LEGACY": ("STORAGE-2", "FAIL"),
    "STR-SECRET-AWS-HC": ("STORAGE-2", "INCONCLUSIVE"),
}

_STATUS_RANK = {"FAIL": 3, "INCONCLUSIVE": 2, "PASS": 1}

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


def _resolve_threat_code(threat_profile: Optional[str]) -> str:
    profile = (threat_profile or "Unknown").strip()
    return {
        "Unknown": "U",
        "Unreported": "U",
        "ProofOfConcept": "P",
        "PoC": "P",
        "Active": "A",
        "Attacked": "A",
        "Weaponized": "W",
    }.get(profile, "U")


def _resolve_env_metrics(env_profile: Optional[str]) -> Dict[str, str]:
    profile = (env_profile or "consumer").strip().lower()
    mapping = {
        "consumer": {"CR": "M", "IR": "M", "AR": "M"},
        "enterprise": {"CR": "H", "IR": "H", "AR": "H"},
    }
    return mapping.get(profile, mapping["consumer"])


def _append_metric(vector: Optional[str], key: str, value: str) -> Optional[str]:
    if not vector:
        return None
    parts = [segment for segment in vector.split("/") if not segment.startswith(f"{key}:")]
    parts.append(f"{key}:{value}")
    return "/".join(parts)


def _apply_cvss_profiles(
    base_vector: Optional[str],
    base_score: Optional[float],
    threat_profile: Optional[str],
    env_profile: Optional[str],
) -> Tuple[Optional[str], Optional[float], Optional[str], Optional[float], Optional[str], Optional[float], Dict[str, Any]]:
    if not base_vector:
        return None, None, None, None, None, None, {}
    threat_code = _resolve_threat_code(threat_profile)
    env_metrics = _resolve_env_metrics(env_profile)

    bt_vector = _append_metric(base_vector, "E", threat_code)
    be_vector = base_vector
    for key, value in env_metrics.items():
        be_vector = _append_metric(be_vector, key, value)
    bte_vector = bt_vector
    for key, value in env_metrics.items():
        bte_vector = _append_metric(bte_vector, key, value)

    meta = {
        "threat": {"profile": threat_profile or "Unknown", "E": threat_code},
        "env": {"profile": env_profile or "consumer", **env_metrics},
    }

    # Until a full CVSS 4.0 calculator is integrated, reuse the base score for derived variants.
    return (
        bt_vector,
        base_score,
        be_vector,
        base_score,
        bte_vector,
        base_score,
        meta,
    )


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


def _extract_evidence_details(
    evidence: Any, fallback: Optional[str]
) -> Tuple[Optional[str], Optional[str], Optional[str], str]:
    entries: List[Dict[str, Any]] = []
    if isinstance(evidence, (list, tuple)):
        iter_evidence: Iterable[Any] = evidence
    elif evidence:
        iter_evidence = [evidence]
    else:
        iter_evidence = []

    chosen_path: Optional[str] = None
    chosen_offset: Optional[str] = None
    chosen_preview: Optional[str] = None

    for item in iter_evidence:
        data = _coerce_mapping(item)
        cleaned: Dict[str, Any] = {}
        for key in ("path", "file", "location", "resource"):
            value = data.get(key)
            if chosen_path is None and isinstance(value, str) and value.strip():
                chosen_path = value.strip()
        for key in ("offset", "line", "column", "index"):
            value = data.get(key)
            if chosen_offset is None and value not in (None, ""):
                chosen_offset = str(value)
        for key in ("detail", "message", "preview", "summary", "because"):
            value = data.get(key)
            if chosen_preview is None and isinstance(value, str) and value.strip():
                chosen_preview = value.strip()
        for key, value in data.items():
            if isinstance(value, (str, int, float, bool)) and key not in cleaned:
                cleaned[key] = value
        if cleaned:
            entries.append(cleaned)

    if chosen_preview is None and isinstance(fallback, str):
        chosen_preview = fallback.strip()

    payload = {
        "path": chosen_path,
        "offset": chosen_offset,
        "detail": chosen_preview,
        "entries": entries,
    }
    payload_str = json.dumps(payload, ensure_ascii=False) if payload else ""
    return chosen_path, chosen_offset, chosen_preview, payload_str


def _derive_rule_id(
    detector_id: Optional[str],
    module_id: Optional[str],
    evidence_path: Optional[str],
    evidence_preview: Optional[str],
) -> Optional[str]:
    tokens = " ".join(filter(None, [detector_id, module_id, evidence_path, evidence_preview])).strip()
    if not tokens:
        return None
    for pattern, rid in _RULE_REGEXES:
        if pattern.search(tokens):
            return rid
    lower_tokens = tokens.lower()
    for phrase, rid in _RULE_FORCE_PHRASES:
        if phrase in lower_tokens:
            return rid
    return None


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
                    _truncate(row.get("legacy_cvss"), 128),
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


def _persist_masvs_controls(run_id: int, package: str, coverage: Dict[str, Dict[str, Any]]) -> None:
    try:
        core_q.run_sql("DELETE FROM masvs_control_coverage WHERE run_id=%s", (run_id,))
    except Exception:
        pass
    for control_id, payload in coverage.items():
        try:
            evidence = json.dumps(payload.get("evidence") or [], ensure_ascii=False)
            rubric = json.dumps(payload.get("rubric") or {}, ensure_ascii=False)
            core_q.run_sql(
                """
                INSERT INTO masvs_control_coverage (run_id, package, control_id, status, evidence, rubric)
                VALUES (%s,%s,%s,%s,%s,%s)
                ON DUPLICATE KEY UPDATE status=VALUES(status), evidence=VALUES(evidence), rubric=VALUES(rubric)
                """,
                (run_id, package, control_id, payload.get("status"), evidence, rubric),
            )
        except Exception:
            continue



@lru_cache(maxsize=1)
def _load_cvss_map() -> Mapping[str, Mapping[str, Optional[str]]]:
    path = Path("config/masvs_map.json")
    if not path.exists():
        return {}
    try:
        data = json.loads(path.read_text("utf-8"))
    except Exception:
        return {}
    mapping = {}
    for finding_id, payload in data.items():
        if not isinstance(payload, dict):
            continue
        codes = payload.get("masvs") or []
        area = None
        if isinstance(codes, list) and codes:
            code = str(codes[0])
            parts = code.split("-")
            if len(parts) >= 2:
                area = parts[1].upper()
        mapping[str(finding_id)] = {
            "masvs": area,
            "cvss": payload.get("cvss_v4"),
        }
    return mapping


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
    if dry_run:
        log.info("Dry-run enabled; skipping persistence for %s", run_package, category="static_analysis")
        return outcome

    if not session_stamp:
        message = f"Missing session stamp for {run_package}; static persistence will be skipped."
        log.warning(message, category="static_analysis")
        outcome.add_error(message)
        return outcome

    br = base_report
    target_sdk = None
    try:
        target_sdk = int(br.manifest.target_sdk) if br.manifest.target_sdk else None
    except Exception:
        target_sdk = None
    if not session_stamp:
        try:
            meta = getattr(br, "metadata", {}) or {}
            value = meta.get("session_stamp")
            if isinstance(value, str) and value.strip():
                session_stamp = value.strip()
        except Exception:
            pass

    run_id = _dw.create_run(
        package=br.manifest.package_name or run_package,
        version_code=int(br.manifest.version_code) if br.manifest.version_code else None,
        version_name=br.manifest.version_name,
        target_sdk=target_sdk,
        session_stamp=session_stamp,
    )
    if not run_id:
        message = f"Failed to create run record for {run_package}"
        log.warning(message, category="static_analysis")
        outcome.add_error(message)
        return outcome

    outcome.run_id = int(run_id)

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
    if not _dw.write_buckets(int(run_id), buckets_payload):
        message = f"Failed to persist scoring buckets for run_id={run_id}"
        log.warning(message, category="static_analysis")
        outcome.add_error(message)

    severity_map = {"P0": "High", "P1": "Medium", "P2": "Low", "NOTE": "Info"}
    cvss_map = _load_cvss_map()
    cvss_v4_config = _load_cvss_v4_config()
    run_profile = core_q.run_sql(
        "SELECT threat_profile, env_profile FROM runs WHERE run_id=%s",
        (run_id,),
        fetch="one",
        dictionary=True,
    )
    threat_profile = (run_profile or {}).get("threat_profile") or "Unknown"
    env_profile = (run_profile or {}).get("env_profile") or "consumer"

    finding_rows: List[Dict[str, Any]] = []
    control_coverage: Dict[str, Dict[str, Any]] = {}
    total_findings = 0
    rule_assigned = 0
    base_vector_count = 0
    bte_vector_count = 0

    try:
        for result in (br.detector_results or ()):  # type: ignore[attr-defined]
            detector_id = str(getattr(result, "detector_id", getattr(result, "section_key", None)) or "unknown")
            module_id_val = getattr(result, "module_id", None)
            module_id = str(module_id_val) if module_id_val not in (None, "") else None
            for f in result.findings:
                total_findings += 1
                sev = severity_map.get(f.severity_gate.value, "Info")
                mapping = cvss_map.get(f.finding_id)
                masvs_area = (mapping.get("masvs") if mapping else None) or f.category_masvs.value
                cvss = mapping.get("cvss") if mapping else ""
                evidence_path, evidence_offset, evidence_preview, evidence_payload = _extract_evidence_details(
                    f.evidence, f.because
                )
                rule_id = _derive_rule_id(detector_id, module_id, evidence_path, evidence_preview)
                if rule_id:
                    rule_assigned += 1
                base_vector, base_score, base_meta = _compute_cvss_base(rule_id)
                if base_vector:
                    base_vector_count += 1
                bt_vector, bt_score, be_vector, be_score, bte_vector, bte_score, profile_meta = _apply_cvss_profiles(
                    base_vector, base_score, threat_profile, env_profile
                )
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
                        "legacy_cvss": cvss or (base_vector or ""),
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

                coverage = _RULE_TO_MASVS.get(rule_id)
                if coverage:
                    ctrl_id, status = coverage
                    evidence_note = evidence_preview or rule_id or detector_id
                    payload = {
                        "status": status,
                        "evidence": [
                            {
                                "kind": detector_id,
                                "path": evidence_path,
                                "note": evidence_note,
                                "rule": rule_id,
                            }
                        ],
                        "rubric": {"rule_id": rule_id, "source": "detector"},
                    }
                    existing = control_coverage.get(ctrl_id)
                    if existing is None or _STATUS_RANK[status] > _STATUS_RANK[existing["status"]]:
                        control_coverage[ctrl_id] = payload
                    elif _STATUS_RANK[status] == _STATUS_RANK[existing["status"]]:
                        existing.setdefault("evidence", []).extend(payload["evidence"])
    except Exception as exc:
        message = f"Failed to collate findings for {run_package}: {exc}"
        log.warning(message, category="static_analysis")
        outcome.add_error(message)

    if finding_rows:
        if not _persist_findings(int(run_id), finding_rows):
            message = f"Failed to persist findings for run_id={run_id}"
            log.warning(message, category="static_analysis")
            outcome.add_error(message)
        else:
            _persist_masvs_controls(int(run_id), br.manifest.package_name or run_package, control_coverage)

    metrics_payload = {
        "network.code_http_hosts": (float(code_http_hosts), None),
        "network.asset_http_hosts": (float(asset_http_hosts), None),
        "exports.total": (float(exp_total), None),
    }
    metrics_payload["findings.total"] = (float(total_findings), None)
    rule_cov_pct = (float(rule_assigned) / float(total_findings) * 100.0) if total_findings else 0.0
    base_cov_pct = (float(base_vector_count) / float(total_findings) * 100.0) if total_findings else 0.0
    bte_cov_pct = (float(bte_vector_count) / float(total_findings) * 100.0) if total_findings else 0.0
    metrics_payload["findings.ruleid_coverage_pct"] = (rule_cov_pct, None)
    metrics_payload["cvss.base_vector_coverage_pct"] = (base_cov_pct, None)
    metrics_payload["cvss.bte_vector_coverage_pct"] = (bte_cov_pct, None)

    if not _dw.write_metrics(int(run_id), metrics_payload):
        message = f"Failed to persist metrics for run_id={run_id}"
        log.warning(message, category="static_analysis")
        outcome.add_error(message)

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
        if contrib_ranked and not _dw.write_contributors(int(run_id), contrib_ranked):
            message = f"Failed to persist contributor breakdown for run_id={run_id}"
            log.warning(message, category="static_analysis")
            outcome.add_error(message)

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
