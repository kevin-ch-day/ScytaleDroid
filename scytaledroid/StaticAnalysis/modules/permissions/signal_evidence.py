from __future__ import annotations

import json
from pathlib import Path

from .signal_config import SIGNAL_OBSERVATION_CONFIG, match_permissions


def persist_signal_observations(
    *,
    core_q,
    log,
    evidence_base: Path | None,
    app,
    app_static_run_id: int | None,
) -> None:
    if app_static_run_id is None:
        return

    signal_write_failed = False
    for signal_key, meta in SIGNAL_OBSERVATION_CONFIG.items():
        if not app.signals.get(signal_key, False):
            continue
        rule = dict(meta)
        perms = rule.get("trigger_permissions") or []
        primary = rule.get("primary_permission")
        severity = rule.get("severity_band") or "INFO"
        score = int(rule.get("score") or 0)
        rationale = rule.get("rationale") or ""
        evidence_path = None
        trigger_permissions: tuple[str, ...] = ()
        if evidence_base and app.package:
            candidates = tuple(meta.get("permissions") or perms or ())
            trigger_permissions = match_permissions(app.declared_permissions, candidates)
            artifact_token = f"run_{app_static_run_id}"
            try:
                row = core_q.run_sql(
                    "SELECT sha256 FROM static_analysis_runs WHERE id=%s",
                    (app_static_run_id,),
                    fetch="one",
                )
                if row and row[0]:
                    artifact_token = str(row[0])
            except Exception:
                pass
            signal_dir = (
                evidence_base / str(app_static_run_id) / app.package / artifact_token
            )
            try:
                signal_dir.mkdir(parents=True, exist_ok=True)
            except Exception:
                log.warning(
                    f"Failed to create signal evidence folder for {app.package}",
                    category="db",
                )
                signal_dir = None
            if signal_dir:
                signal_file = signal_dir / f"signal_{signal_key}.json"
                try:
                    signal_payload = {
                        "static_run_id": app_static_run_id,
                        "package_name": app.package,
                        "signal_key": signal_key,
                        "severity_band": severity,
                        "score": score,
                        "trigger_permissions": list(trigger_permissions or ()),
                        "rationale": rationale,
                    }
                    signal_file.write_text(
                        json.dumps(signal_payload, ensure_ascii=True, indent=2, default=str),
                        encoding="utf-8",
                    )
                    evidence_path = str(
                        Path("evidence")
                        / "static_runs"
                        / str(app_static_run_id)
                        / app.package
                        / artifact_token
                        / signal_file.name
                    )
                except Exception:
                    log.warning(
                        f"Failed to write signal evidence for {app.package} ({signal_key})",
                        category="db",
                    )

        payload = {
            "static_run_id": app_static_run_id,
            "package_name": app.package,
            "signal_key": signal_key,
            "severity_band": severity,
            "score": score,
            "trigger_permissions_json": json.dumps(trigger_permissions or perms, default=str),
            "primary_permission": primary,
            "rationale": rationale,
            "evidence_path": evidence_path,
        }
        columns = ", ".join(payload.keys())
        placeholders = ", ".join([f"%({key})s" for key in payload])
        updates = ", ".join(
            f"{key}=VALUES({key})"
            for key in payload.keys()
            if key not in {"static_run_id", "package_name", "signal_key"}
        )
        sql = (
            "INSERT INTO permission_signal_observations ("
            + columns
            + ") VALUES ("
            + placeholders
            + ")"
            + (" ON DUPLICATE KEY UPDATE " + updates if updates else "")
        )
        try:
            core_q.run_sql(sql, payload)
        except Exception:
            if not signal_write_failed:
                log.warning(
                    "Failed to persist permission signal observations.",
                    category="db",
                )
            signal_write_failed = True
