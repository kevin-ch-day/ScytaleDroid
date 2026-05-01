from __future__ import annotations

from scytaledroid.Database.tools.risk_score_audit import (
    _reclassify_permission_profiles,
    _replay_session_scores,
)


def test_reclassify_permission_profiles_splits_flagged_normals() -> None:
    profiles = {
        "android.permission.RECEIVE_BOOT_COMPLETED": {
            "tokens": ["normal"],
            "severity": 1,
            "is_runtime_dangerous": False,
            "is_signature": False,
            "is_privileged": False,
            "is_special_access": False,
            "is_custom": False,
            "guard_strength": "unknown",
        },
        "android.permission.SYSTEM_ALERT_WINDOW": {
            "tokens": ["appop"],
            "severity": 45,
            "is_runtime_dangerous": False,
            "is_signature": False,
            "is_privileged": False,
            "is_special_access": True,
            "is_custom": False,
            "guard_strength": "unknown",
        },
        "com.example.provider.ACCESS": {
            "tokens": ["normal"],
            "severity": 0,
            "is_runtime_dangerous": False,
            "is_signature": False,
            "is_privileged": False,
            "is_special_access": False,
            "is_custom": True,
            "guard_strength": "unknown",
        },
    }

    split = _reclassify_permission_profiles(profiles)

    assert split["noisy_normal_count"] == 1
    assert split["noteworthy_normal_count"] == 1
    assert split["special_risk_normal_count"] == 1
    assert split["flagged_normal_count"] == 2


def test_replay_session_scores_reports_grade_improvement() -> None:
    rows = [
        {
            "package_name": "com.example.app",
            "score_capped": 8.5,
            "grade": "F",
            "dangerous_count": 4,
            "signature_count": 0,
            "vendor_count": 0,
            "details": (
                '{"groups":{"CAM":1,"CNT":1},'
                '"sdk":{"target":35},'
                '"score_detail":{"flagged_normal_count":12}}'
            ),
        }
    ]
    report_profiles = {
        "com.example.app": {
            "permission_profiles": {
                "com.example.provider.ACCESS": {
                    "tokens": ["normal"],
                    "severity": 0,
                    "is_runtime_dangerous": False,
                    "is_signature": False,
                    "is_privileged": False,
                    "is_special_access": False,
                    "is_custom": True,
                    "guard_strength": "unknown",
                }
            },
            "manifest_flags": {
                "allow_backup": False,
                "request_legacy_external_storage": False,
            },
        }
    }

    replayed = _replay_session_scores(rows, report_profiles)

    assert replayed["change_summary"]["apps_total"] == 1
    assert replayed["change_summary"]["score_lowered"] == 1
    assert replayed["change_summary"]["grade_improved"] == 1
