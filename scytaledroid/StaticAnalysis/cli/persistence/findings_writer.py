"""Utilities for persisting dynamic findings and MASVS control coverage."""

from __future__ import annotations

import json
from functools import lru_cache
from pathlib import Path
from typing import Any, Dict, Mapping, Optional, Sequence, Tuple

try:  # pragma: no cover - optional dependency
    import yaml
except Exception:  # pragma: no cover - optional dependency
    yaml = None

from scytaledroid.Database.db_core import db_queries as core_q
from scytaledroid.Utils.LoggingUtils import logging_utils as log

from ..cvss_v4 import score_vector

_CVSS_BASE_ORDER = ("AV", "AC", "AT", "PR", "UI", "VC", "VI", "VA", "SC", "SI", "SA")
_LOGGED_MISSING_CONFIG = False


def extract_rule_hint(finding: Any) -> Optional[str]:
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


def derive_masvs_tag(finding: Any, rule_id: Optional[str], *, lookup_rule_area) -> Optional[str]:
    for attr in ("category_masvs", "masvs", "category", "masvs_category"):
        candidate = _normalise_masvs_value(getattr(finding, attr, None))
        if candidate:
            return candidate
    if rule_id:
        area = lookup_rule_area(rule_id)
        if area:
            return area
    return None


@lru_cache(maxsize=1)
def _load_cvss_v4_config() -> Optional[Dict[str, Any]]:
    global _LOGGED_MISSING_CONFIG
    path = Path("config/cvss_v4_map.yaml")
    if not path.exists() or yaml is None:
        if not _LOGGED_MISSING_CONFIG:
            log.info(
                "cvss_v4_map.yaml unavailable; falling back to baked-in defaults",
                category="static_analysis",
            )
            _LOGGED_MISSING_CONFIG = True
        return None
    try:
        data = yaml.safe_load(path.read_text("utf-8"))
    except Exception:  # pragma: no cover - defensive
        if not _LOGGED_MISSING_CONFIG:
            log.info(
                "Failed to read cvss_v4_map.yaml; using fallback scores",
                category="static_analysis",
            )
            _LOGGED_MISSING_CONFIG = True
        return None
    if not isinstance(data, dict):
        if not _LOGGED_MISSING_CONFIG:
            log.info(
                "cvss_v4_map.yaml malformed; using fallback scores",
                category="static_analysis",
            )
            _LOGGED_MISSING_CONFIG = True
        return None
    defaults = data.get("defaults") or {}
    rule_entries: Dict[str, Any] = {}
    for entry in data.get("rules", []):
        if not isinstance(entry, dict):
            continue
        rid = entry.get("detector_id")
        if not rid:
            continue
        rule_entries[str(rid)] = entry
    return {"defaults": defaults, "rules": rule_entries}


def build_cvss_vector(metrics: Mapping[str, str]) -> Optional[str]:
    entries = []
    for key in _CVSS_BASE_ORDER:
        value = metrics.get(key)
        if value:
            entries.append(f"{key}:{value}")
    if not entries:
        return None
    return "CVSS:4.0/" + "/".join(entries)


_FALLBACK_RULE_CVSS: Dict[str, Dict[str, object]] = {
    "BASE-IPC-COMP-NO-ACL": {
        "vector": "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:L/VI:L/VA:L/SC:N/SI:N/SA:N",
        "score": 8.0,
        "rationale": "Exported component without permission allows external apps to trigger privileged code paths.",
    },
    "BASE-002": {
        "vector": "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:L/VI:L/VA:L/SC:N/SI:N/SA:N",
        "score": 8.0,
        "rationale": "Unprotected content provider exposes IPC surface to arbitrary callers.",
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
    "diff_exported_activities": {
        "vector": "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:L/VI:L/VA:L/SC:N/SI:N/SA:N",
        "score": 8.0,
        "rationale": "New exported activities introduced relative to baseline increase attack surface.",
    },
    "diff_exported_services": {
        "vector": "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:L/VI:L/VA:L/SC:N/SI:N/SA:N",
        "score": 8.0,
        "rationale": "New exported services introduced relative to baseline increase attack surface.",
    },
    "diff_exported_receivers": {
        "vector": "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:L/VI:L/VA:L/SC:N/SI:N/SA:N",
        "score": 8.0,
        "rationale": "New exported broadcast receivers introduced relative to baseline increase attack surface.",
    },
    "diff_exported_providers": {
        "vector": "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:L/VI:L/VA:L/SC:N/SI:N/SA:N",
        "score": 8.0,
        "rationale": "New exported content providers introduced relative to baseline increase attack surface.",
    },
    "diff_new_permissions": {
        "vector": "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:L/VI:N/VA:N/SC:N/SI:N/SA:N",
        "score": 5.0,
        "rationale": "New dangerous permissions were added relative to baseline; impact depends on downstream use of granted capabilities.",
    },
    "diff_cleartext_enabled": {
        "vector": "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:R/VC:L/VI:N/VA:N/SC:N/SI:N/SA:N",
        "score": 4.5,
        "rationale": "Cleartext traffic newly enabled relative to baseline enables downgrade of network protections.",
    },
    "diff_flag_usesCleartextTraffic": {
        "vector": "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:R/VC:L/VI:N/VA:N/SC:N/SI:N/SA:N",
        "score": 4.5,
        "rationale": "Manifest flag toggled to permit cleartext network traffic compared to baseline.",
    },
    "diff_flag_requestLegacyExternalStorage": {
        "vector": "CVSS:4.0/AV:L/AC:L/AT:N/PR:N/UI:N/VC:N/VI:L/VA:N/SC:N/SI:N/SA:N",
        "score": 3.9,
        "rationale": "Manifest flag toggled to request legacy external storage relative to baseline.",
    },
}


def compute_cvss_base(rule_id: Optional[str]) -> Tuple[Optional[str], Optional[float], Dict[str, Any]]:
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
        return vector, float(spec.get("score", 0.0) or 0.0), meta

    if not rule_cfg:
        return None, None, {}

    base_metrics = dict(base_defaults)
    base_metrics.update(rule_cfg.get("base") or {})
    vector = build_cvss_vector(base_metrics)
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


def persist_findings(run_id: int, rows: Sequence[Dict[str, Any]], *, static_run_id: int | None = None) -> bool:
    """Persist normalized findings for a static run.

    Both run_id and static_run_id are written where supported so newer schemas
    can key by static_analysis_runs.id while legacy consumers can still use
    the generic run_id.
    """
    try:
        core_q.run_sql(
            "DELETE FROM findings WHERE run_id=%s OR static_run_id=%s",
            (run_id, static_run_id if static_run_id is not None else run_id),
        )
    except Exception as exc:  # pragma: no cover - defensive
        log.warning(f"Failed to prune findings for run_id={run_id}: {exc}", category="static_analysis")
    try:
        for row in rows:
            core_q.run_sql(
                """
                INSERT INTO findings (
                    run_id, static_run_id, severity, masvs, cvss, kind, evidence, module_id,
                    cvss_v40_b_score, cvss_v40_bt_score, cvss_v40_be_score, cvss_v40_bte_score,
                    cvss_v40_b_vector, cvss_v40_bt_vector, cvss_v40_be_vector, cvss_v40_bte_vector,
                    cvss_v40_meta, analyst_tag, evidence_path, evidence_offset, evidence_preview, rule_id
                ) VALUES (
                    %s,%s,%s,%s,%s,%s,%s,%s,
                    %s,%s,%s,%s,
                    %s,%s,%s,%s,
                    %s,%s,%s,%s,%s,%s,%s
                )
                """,
                (
                    run_id,
                    static_run_id if static_run_id is not None else run_id,
                    row.get("severity"),
                    row.get("masvs"),
                    row.get("cvss"),
                    row.get("kind"),
                    row.get("evidence"),
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
                    row.get("evidence_path"),
                    row.get("evidence_offset"),
                    row.get("evidence_preview"),
                    row.get("rule_id"),
                ),
            )
        return True
    except Exception as exc:  # pragma: no cover - defensive
        log.error(
            f"Failed to persist findings for run_id={run_id} static_run_id={static_run_id}: {exc}",
            category="static_analysis",
        )
        return False


def persist_masvs_controls(run_id: int, package: str, coverage: Mapping[str, Any]) -> None:
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
                payload_map = dict(entry)
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


__all__ = [
    "compute_cvss_base",
    "derive_masvs_tag",
    "extract_rule_hint",
    "persist_findings",
    "persist_masvs_controls",
    "build_cvss_vector",
]
