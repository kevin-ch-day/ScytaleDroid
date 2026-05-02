"""Audit persisted permission-risk scores for a session/snapshot."""

from __future__ import annotations

import argparse
import json
import os
from collections import defaultdict
from pathlib import Path
from statistics import mean
from typing import Any

import pymysql
from scytaledroid.StaticAnalysis.modules.permissions.analysis.tokens import (
    classify_flagged_normal,
    is_scored_flagged_normal,
)
from scytaledroid.StaticAnalysis.risk.permission import (
    permission_risk_grade,
    permission_risk_score_detail,
)


def _connect() -> pymysql.connections.Connection:
    return pymysql.connect(
        host=os.environ["SCYTALEDROID_DB_HOST"],
        user=os.environ["SCYTALEDROID_DB_USER"],
        password=os.environ.get("SCYTALEDROID_DB_PASSWD", ""),
        database=os.environ["SCYTALEDROID_DB_NAME"],
        charset="utf8mb4",
        cursorclass=pymysql.cursors.DictCursor,
    )


def _snapshot_id_for_session(cur: pymysql.cursors.DictCursor, session_label: str) -> int | None:
    cur.execute(
        """
        SELECT snapshot_id
        FROM permission_audit_snapshots
        WHERE snapshot_key = %s
        ORDER BY created_at DESC
        LIMIT 1
        """,
        (f"perm-audit:app:{session_label}",),
    )
    row = cur.fetchone()
    return int(row["snapshot_id"]) if row and row.get("snapshot_id") is not None else None


def _load_audit_rows(cur: pymysql.cursors.DictCursor, snapshot_id: int) -> list[dict[str, Any]]:
    cur.execute(
        """
        SELECT
          package_name,
          app_label,
          score_capped,
          grade,
          dangerous_count,
          signature_count,
          vendor_count,
          combos_total,
          surprises_total,
          legacy_total,
          vendor_modifier,
          modernization_credit,
          details
        FROM permission_audit_apps
        WHERE snapshot_id = %s
        ORDER BY score_capped DESC, package_name
        """,
        (snapshot_id,),
    )
    return list(cur.fetchall() or [])


def _load_risk_rows(cur: pymysql.cursors.DictCursor, session_label: str) -> list[dict[str, Any]]:
    cur.execute(
        """
        SELECT package_name, app_label, risk_score, risk_grade, dangerous, signature, vendor
        FROM risk_scores
        WHERE session_stamp = %s
        ORDER BY risk_score DESC, package_name
        """,
        (session_label,),
    )
    return list(cur.fetchall() or [])


def _load_report_profiles_by_package(session_label: str) -> dict[str, dict[str, Any]]:
    report_dir = Path("data/static_analysis/reports/archive") / session_label
    if not report_dir.is_dir():
        return {}
    by_package: dict[str, dict[str, Any]] = {}
    for path in sorted(report_dir.glob("*.json")):
        try:
            payload = json.loads(path.read_text(encoding="utf-8"))
        except Exception:
            continue
        manifest = payload.get("manifest") if isinstance(payload, dict) else {}
        detector_metrics = payload.get("detector_metrics") if isinstance(payload, dict) else {}
        permissions_profile = (
            detector_metrics.get("permissions_profile")
            if isinstance(detector_metrics, dict)
            else {}
        )
        permission_profiles = (
            permissions_profile.get("permission_profiles")
            if isinstance(permissions_profile, dict)
            else {}
        )
        package_name = manifest.get("package_name") if isinstance(manifest, dict) else None
        if not package_name or not isinstance(permission_profiles, dict):
            continue
        by_package[str(package_name)] = {
            "permission_profiles": permission_profiles,
            "manifest": manifest if isinstance(manifest, dict) else {},
            "manifest_flags": payload.get("manifest_flags")
            if isinstance(payload.get("manifest_flags"), dict)
            else {},
        }
    return by_package


def _reclassify_permission_profiles(
    permission_profiles: dict[str, Any],
) -> dict[str, Any]:
    noisy: set[str] = set()
    noteworthy: set[str] = set()
    special: set[str] = set()
    scored: set[str] = set()
    weak_guard_count = 0
    for permission_name, profile in permission_profiles.items():
        if not isinstance(profile, dict):
            continue
        guard_strength = str(profile.get("guard_strength") or "").strip().lower()
        is_runtime_dangerous = bool(profile.get("is_runtime_dangerous"))
        if is_runtime_dangerous and guard_strength in {"weak", "unknown"}:
            weak_guard_count += 1
        flagged_class = classify_flagged_normal(
            str(permission_name),
            tokens=tuple(str(token) for token in (profile.get("tokens") or ()) if token),
            severity=int(profile.get("severity") or 0),
            is_runtime_dangerous=is_runtime_dangerous,
            is_signature=bool(profile.get("is_signature")),
            is_privileged=bool(profile.get("is_privileged")),
            is_special_access=bool(profile.get("is_special_access")),
            is_custom=bool(profile.get("is_custom")),
        )
        if flagged_class == "noisy_normal":
            noisy.add(str(permission_name))
        elif flagged_class == "noteworthy_normal":
            noteworthy.add(str(permission_name))
        elif flagged_class == "special_risk_normal":
            special.add(str(permission_name))
        if is_scored_flagged_normal(flagged_class):
            scored.add(str(permission_name))
    return {
        "noisy_normal_permissions": sorted(noisy),
        "noteworthy_normal_permissions": sorted(noteworthy),
        "special_risk_normal_permissions": sorted(special),
        "scored_flagged_permissions": sorted(scored),
        "noisy_normal_count": len(noisy),
        "noteworthy_normal_count": len(noteworthy),
        "special_risk_normal_count": len(special),
        "flagged_normal_count": len(scored),
        "weak_guard_count": weak_guard_count,
    }


def _replay_session_scores(
    rows: list[dict[str, Any]],
    report_profiles_by_package: dict[str, dict[str, Any]],
) -> dict[str, Any]:
    grade_distribution: dict[str, int] = defaultdict(int)
    change_summary = {
        "apps_total": 0,
        "score_changed": 0,
        "score_lowered": 0,
        "score_raised": 0,
        "grade_changed": 0,
        "grade_improved": 0,
        "grade_worsened": 0,
    }
    split_class_totals: dict[str, int] = defaultdict(int)
    largest_deltas: list[dict[str, Any]] = []

    grade_rank = {"A": 0, "B": 1, "C": 2, "D": 3, "F": 4}

    for row in rows:
        package_name = str(row.get("package_name") or "")
        details = json.loads(row["details"]) if row.get("details") else {}
        score_detail = details.get("score_detail", {}) if isinstance(details, dict) else {}
        groups = details.get("groups") if isinstance(details, dict) and isinstance(details.get("groups"), dict) else {}
        sdk = details.get("sdk") if isinstance(details, dict) and isinstance(details.get("sdk"), dict) else {}

        report_payload = report_profiles_by_package.get(package_name) or {}
        permission_profiles = (
            report_payload.get("permission_profiles")
            if isinstance(report_payload.get("permission_profiles"), dict)
            else {}
        )
        manifest_flags = (
            report_payload.get("manifest_flags")
            if isinstance(report_payload.get("manifest_flags"), dict)
            else {}
        )
        split = _reclassify_permission_profiles(permission_profiles)
        for key in (
            "noisy_normal_count",
            "noteworthy_normal_count",
            "special_risk_normal_count",
        ):
            split_class_totals[key] += int(split.get(key) or 0)

        allow_backup = manifest_flags.get("allow_backup")
        legacy_external_storage = manifest_flags.get("request_legacy_external_storage")
        target_sdk = sdk.get("target")
        try:
            target_sdk = int(target_sdk) if target_sdk is not None else None
        except Exception:
            target_sdk = None

        recomputed = permission_risk_score_detail(
            dangerous=int(row.get("dangerous_count") or 0),
            signature=int(row.get("signature_count") or 0),
            vendor=int(row.get("vendor_count") or 0),
            groups=groups,
            target_sdk=target_sdk,
            allow_backup=allow_backup,
            legacy_external_storage=legacy_external_storage,
            flagged_normals=int(split.get("flagged_normal_count") or 0),
            noteworthy_normals=int(split.get("noteworthy_normal_count") or 0),
            special_risk_normals=int(split.get("special_risk_normal_count") or 0),
            weak_guards=int(split.get("weak_guard_count") or 0),
        )
        old_score = float(row.get("score_capped") or 0.0)
        new_score = float(recomputed.get("score_3dp") or recomputed.get("score_capped") or 0.0)
        old_grade = str(row.get("grade") or "?")
        new_grade = permission_risk_grade(new_score)
        delta = round(new_score - old_score, 3)

        grade_distribution[new_grade] += 1
        change_summary["apps_total"] += 1
        if delta != 0:
            change_summary["score_changed"] += 1
            if delta < 0:
                change_summary["score_lowered"] += 1
            else:
                change_summary["score_raised"] += 1
        if new_grade != old_grade:
            change_summary["grade_changed"] += 1
            if grade_rank.get(new_grade, 99) < grade_rank.get(old_grade, 99):
                change_summary["grade_improved"] += 1
            elif grade_rank.get(new_grade, -1) > grade_rank.get(old_grade, -1):
                change_summary["grade_worsened"] += 1

        largest_deltas.append(
            {
                "package_name": package_name,
                "old_score": round(old_score, 3),
                "new_score": round(new_score, 3),
                "delta": delta,
                "old_grade": old_grade,
                "new_grade": new_grade,
                "flagged_normal_old": int(score_detail.get("flagged_normal_count", 0) or 0),
                "flagged_normal_new": int(split.get("flagged_normal_count") or 0),
                "noisy_normal_count": int(split.get("noisy_normal_count") or 0),
                "noteworthy_normal_count": int(split.get("noteworthy_normal_count") or 0),
                "special_risk_normal_count": int(split.get("special_risk_normal_count") or 0),
            }
        )

    largest_deltas.sort(key=lambda row: abs(float(row.get("delta") or 0.0)), reverse=True)
    return {
        "grade_distribution": dict(sorted(grade_distribution.items())),
        "change_summary": change_summary,
        "split_class_totals": dict(sorted(split_class_totals.items())),
        "largest_deltas": largest_deltas[:20],
    }


def _summarize_audit_rows(rows: list[dict[str, Any]]) -> dict[str, Any]:
    by_grade: dict[str, dict[str, list[float]]] = {}
    cap_counts = {
        "flagged_normal_cap": 0,
        "breadth_cap": 0,
        "vendor_cap": 0,
        "weak_guard_cap": 0,
    }
    negative_score_rows = 0
    flagged_category_counts: dict[str, int] = defaultdict(int)
    flagged_category_examples: dict[str, str] = {}
    top_examples: list[dict[str, Any]] = []

    for row in rows:
        if float(row.get("score_capped") or 0.0) < 0:
            negative_score_rows += 1
        details = json.loads(row["details"]) if row.get("details") else {}
        score_detail = details.get("score_detail", {}) if isinstance(details, dict) else {}
        grade = str(row.get("grade") or "?")
        entry = by_grade.setdefault(
            grade,
            defaultdict(list),  # type: ignore[arg-type]
        )
        entry["scores"].append(float(row.get("score_capped") or 0.0))
        entry["dangerous"].append(float(score_detail.get("dangerous_count", 0) or 0))
        entry["signature"].append(float(score_detail.get("signature_count", 0) or 0))
        entry["vendor"].append(float(score_detail.get("vendor_count", 0) or 0))
        entry["flagged"].append(float(score_detail.get("flagged_normal_count", 0) or 0))
        entry["weak"].append(float(score_detail.get("weak_guard_count", 0) or 0))
        entry["breadth"].append(float((score_detail.get("breadth") or {}).get("applied", 0.0) or 0.0))
        entry["modernization"].append(float(score_detail.get("modernization_credit", 0.0) or 0.0))

        penalties = score_detail.get("penalty_components") or {}
        penalty_weights = score_detail.get("penalty_weights") or {}
        breadth = score_detail.get("breadth") or {}
        if float(penalties.get("flagged_normal", 0.0) or 0.0) >= float(
            penalty_weights.get("flagged_normal_cap", 999.0) or 999.0
        ):
            cap_counts["flagged_normal_cap"] += 1
        if float(breadth.get("applied", 0.0) or 0.0) >= float(breadth.get("cap", 999.0) or 999.0):
            cap_counts["breadth_cap"] += 1
        if bool(score_detail.get("vendor_cap_applied")):
            cap_counts["vendor_cap"] += 1
        if float(penalties.get("weak_guard", 0.0) or 0.0) >= float(
            penalty_weights.get("weak_guard_cap", 999.0) or 999.0
        ) and float(penalty_weights.get("weak_guard_cap", 0.0) or 0.0) > 0:
            cap_counts["weak_guard_cap"] += 1

        for permission_name in score_detail.get("flagged_permissions", []) or []:
            category = _categorize_flagged_permission(str(permission_name))
            flagged_category_counts[category] += 1
            flagged_category_examples.setdefault(category, str(permission_name))

        if len(top_examples) < 15:
            top_examples.append(
                {
                    "package_name": row.get("package_name"),
                    "score_capped": float(row.get("score_capped") or 0.0),
                    "grade": grade,
                    "dangerous_count": score_detail.get("dangerous_count"),
                    "signature_count": score_detail.get("signature_count"),
                    "vendor_count": score_detail.get("vendor_count"),
                    "flagged_normal_count": score_detail.get("flagged_normal_count"),
                    "weak_guard_count": score_detail.get("weak_guard_count"),
                    "signal_score_subtotal": score_detail.get("signal_score_subtotal"),
                    "signal_components": score_detail.get("signal_components"),
                    "penalty_components": score_detail.get("penalty_components"),
                    "breadth": score_detail.get("breadth"),
                    "modernization_credit": score_detail.get("modernization_credit"),
                }
            )

    grade_summary = {
        grade: {metric: round(mean(values), 3) for metric, values in metrics.items()}
        for grade, metrics in by_grade.items()
    }
    return {
        "apps_total": len(rows),
        "negative_score_rows": negative_score_rows,
        "grade_summary": grade_summary,
        "cap_counts": cap_counts,
        "flagged_permission_categories": dict(sorted(flagged_category_counts.items())),
        "flagged_permission_examples": dict(sorted(flagged_category_examples.items())),
        "top_examples": top_examples,
    }


def _summarize_risk_rows(rows: list[dict[str, Any]]) -> dict[str, Any]:
    by_grade: dict[str, list[float]] = defaultdict(list)
    for row in rows:
        by_grade[str(row.get("risk_grade") or "?")].append(float(row.get("risk_score") or 0.0))
    return {
        "apps_total": len(rows),
        "grade_distribution": {
            grade: {
                "count": len(scores),
                "avg_score": round(mean(scores), 3),
                "min_score": round(min(scores), 3),
                "max_score": round(max(scores), 3),
            }
            for grade, scores in sorted(by_grade.items())
        },
    }


def _categorize_flagged_permission(permission_name: str) -> str:
    token = permission_name.strip().lower()
    if not token:
        return "unknown"
    if token.startswith("android.permission."):
        special_suffixes = (
            "system_alert_window",
            "schedule_exact_alarm",
            "capture_video_output",
            "capture_secure_video_output",
            "query_all_packages",
            "request_install_packages",
            "package_usage_stats",
        )
        if any(token.endswith(suffix) for suffix in special_suffixes):
            return "android_special"
        return "android_framework_normal"
    if (
        token.startswith("com.google.android.c2dm.permission.")
        or token.startswith("com.google.android.gms.permission.")
        or "finsky" in token
        or token.endswith(".billing")
    ):
        return "google_push_billing_ads"
    if "launcher" in token or "badge" in token or "shortcut" in token:
        return "launcher_badge_shortcut"
    if (
        ".dynamic_receiver_not_exported_permission" in token
        or ".provider.access" in token
        or ".access_secrets" in token
        or ".permission." in token
    ):
        return "app_defined_or_internal"
    if token.startswith("com.facebook.") or token.startswith("com.whatsapp."):
        return "vendor_internal"
    return "other_custom"


def main() -> int:
    parser = argparse.ArgumentParser(description="Audit persisted permission risk scores for a static session.")
    parser.add_argument("session_label", help="Static session label, for example 20260429-all-full")
    args = parser.parse_args()

    with _connect() as conn:
        with conn.cursor() as cur:
            snapshot_id = _snapshot_id_for_session(cur, args.session_label)
            risk_rows = _load_risk_rows(cur, args.session_label)
            audit_rows = _load_audit_rows(cur, snapshot_id) if snapshot_id is not None else []

    payload = {
        "session_label": args.session_label,
        "snapshot_id": snapshot_id,
        "risk_scores": _summarize_risk_rows(risk_rows),
        "permission_audit": _summarize_audit_rows(audit_rows) if audit_rows else None,
    }
    if audit_rows:
        payload["replayed_scores"] = _replay_session_scores(
            audit_rows,
            _load_report_profiles_by_package(args.session_label),
        )
    print(json.dumps(payload, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
