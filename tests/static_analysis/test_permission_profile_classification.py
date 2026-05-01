from __future__ import annotations

from scytaledroid.StaticAnalysis.modules.permissions.analysis.profiles import build_profiles


def test_build_profiles_marks_custom_internal_permissions_as_noisy_normals() -> None:
    profiles = build_profiles(
        ["com.facebook.katana.provider.ACCESS"],
        {"com.facebook.katana.provider.ACCESS": ("normal",)},
        [],
    )

    profile = profiles["com.facebook.katana.provider.ACCESS"]
    assert profile.flagged_normal_class == "noisy_normal"
    assert profile.is_scored_flagged_normal is False


def test_build_profiles_marks_framework_special_access_as_special_risk() -> None:
    profiles = build_profiles(
        ["android.permission.SYSTEM_ALERT_WINDOW"],
        {"android.permission.SYSTEM_ALERT_WINDOW": ("appop",)},
        [],
    )

    profile = profiles["android.permission.SYSTEM_ALERT_WINDOW"]
    assert profile.flagged_normal_class == "special_risk_normal"
    assert profile.is_scored_flagged_normal is True


def test_build_profiles_marks_boot_completed_as_noteworthy_normal() -> None:
    profiles = build_profiles(
        ["android.permission.RECEIVE_BOOT_COMPLETED"],
        {"android.permission.RECEIVE_BOOT_COMPLETED": ("normal",)},
        [],
    )

    profile = profiles["android.permission.RECEIVE_BOOT_COMPLETED"]
    assert profile.flagged_normal_class == "noteworthy_normal"
    assert profile.is_scored_flagged_normal is True
