from __future__ import annotations

from collections import Counter
from datetime import UTC, datetime

from scytaledroid.StaticAnalysis.modules.permissions import catalog
from scytaledroid.StaticAnalysis.modules.permissions import permission_matrix_view as matrix_view
from scytaledroid.StaticAnalysis.modules.permissions.analysis.profiles import (
    PermissionProfile,
    build_profiles,
)
from scytaledroid.StaticAnalysis.modules.permissions.analysis.tokens import (
    classify_flagged_normal,
    score_tokens,
    tokens_from_db,
)
from scytaledroid.StaticAnalysis.modules.permissions.profile import _build_metrics

# =============================================================================
# Former tests/static_analysis/test_permission_profile_classification.py
# =============================================================================


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


def test_group_hits_include_health_and_background_pairs() -> None:
    from scytaledroid.StaticAnalysis.modules.permissions.analysis.signals import (
        compute_group_strengths,
    )

    groups, fw = compute_group_strengths(
        [
            ("android.permission.health.READ_HEART_RATE", "uses-permission"),
            ("android.permission.BACKGROUND_CAMERA", "uses-permission"),
            ("android.permission.RECORD_BACKGROUND_AUDIO", "uses-permission"),
            ("android.permission.READ_HEALTH_DATA_IN_BACKGROUND", "uses-permission"),
        ],
        {
            "BACKGROUND_CAMERA": "dangerous|instant",
            "RECORD_BACKGROUND_AUDIO": "dangerous",
        },
    )
    assert groups["SENS"] >= 1
    assert groups["CAM"] >= 1
    assert groups["MIC"] >= 1
    assert "HEALTH_CONNECT_DATA" in fw
    assert "BACKGROUND_CAMERA" in fw


def test_format_summary_and_notes_include_health_and_background() -> None:
    from scytaledroid.StaticAnalysis.modules.permissions.analysis.summarize import (
        build_notes,
        format_summary,
    )

    summary = format_summary(
        total=4,
        dangerous=2,
        signature=1,
        custom=0,
        health=2,
        background=1,
    )
    assert "health 2" in summary
    assert "background 1" in summary
    notes = build_notes(
        total=4,
        dangerous=2,
        signature=1,
        privileged=0,
        special_access=0,
        health=2,
        background=1,
        catalog_matched=3,
    )
    assert any("health-data" in note for note in notes)
    assert any("background-sensitive" in note for note in notes)
    assert any("Permission Intel catalog classified 3/4" in note for note in notes)


def test_reporting_classifies_permission_intel_authority() -> None:
    from scytaledroid.StaticAnalysis.reporting import view as reporting_view

    label, reason = reporting_view._classify_permission(  # noqa: SLF001
        "android.permission.CAMERA",
        {"catalog_source": "permission_intel_v1", "authority_class": "AOSP_PUBLIC"},
    )
    assert label == "AOSP"
    assert reason is None
    hidden, _reason = reporting_view._classify_permission(  # noqa: SLF001
        "android.permission.READ_FRAME_BUFFER",
        {"catalog_source": "permission_intel_v1", "authority_class": "AOSP_HIDDEN"},
    )
    assert hidden == "AOSP-Hidden"
    legacy, ghost = reporting_view._classify_permission(  # noqa: SLF001
        "android.permission.WRITE_EXTERNAL_STORAGE",
        {},
    )
    assert legacy == "AOSP-Legacy"
    assert ghost is not None


def test_compute_signal_flags_marks_health_and_background_capture() -> None:
    from scytaledroid.StaticAnalysis.modules.permissions.audit import compute_signal_flags

    signals = compute_signal_flags(
        groups={"SENS": 1, "CAM": 1, "MIC": 1, "LOC": 0},
        permissions=(
            "android.permission.health.READ_HEART_RATE",
            "android.permission.BACKGROUND_CAMERA",
            "android.permission.RECORD_BACKGROUND_AUDIO",
        ),
        vendor_present=False,
    )
    assert signals.health_data is True
    assert signals.background_camera is True
    assert signals.background_audio is True
    assert signals.sensors is True


def test_tokens_from_db_keeps_compound_protection_expressions() -> None:
    assert tokens_from_db("dangerous|instant") == ("dangerous", "instant")
    assert tokens_from_db("signature|privileged") == ("privileged", "signature")
    assert tokens_from_db("internal|privileged") == ("internal", "privileged")
    assert tokens_from_db("normal") == ("normal",)
    assert tokens_from_db(None) is None
    assert tokens_from_db("") is None


def test_internal_protection_is_not_flagged_normal_and_scores_above_normal() -> None:
    tokens = ("internal",)
    assert score_tokens(tokens, is_custom=False) == 75
    assert (
        classify_flagged_normal(
            "android.permission.READ_FRAME_BUFFER",
            tokens=tokens,
            severity=75,
            is_runtime_dangerous=False,
            is_signature=False,
            is_privileged=False,
            is_special_access=False,
            is_custom=False,
        )
        is None
    )


def test_score_permission_uses_catalog_context_and_caps_severity() -> None:
    from scytaledroid.StaticAnalysis.modules.permissions.analysis.tokens import score_permission

    camera = score_permission(
        ("dangerous",),
        name="android.permission.CAMERA",
        permission_group="android.permission-group.UNDEFINED",
        background_permission="android.permission.BACKGROUND_CAMERA",
    )
    assert camera == 73
    health = score_permission(
        ("dangerous",),
        name="android.permission.health.READ_HEART_RATE",
        permission_group="android.permission-group.HEALTH",
    )
    assert health == 70
    background = score_permission(
        ("dangerous",),
        name="android.permission.ACCESS_BACKGROUND_LOCATION",
    )
    assert background == 77
    stacked = score_permission(
        ("signature", "appop", "development", "privileged", "installer", "role"),
        name="android.permission.PACKAGE_USAGE_STATS",
        authority_class="AOSP_HIDDEN",
        feature_dependency="android.hardware.foo",
    )
    assert stacked == 160
    process_control = score_permission(
        ("signature", "privileged"),
        name="android.permission.START_ACTIVITIES_FROM_BACKGROUND",
    )
    assert process_control == 126
    health_unprotected = score_permission(
        (),
        name="android.permission.health.READ_HEART_RATE",
    )
    assert health_unprotected == 70


def test_metrics_overlay_catalog_group_and_background() -> None:
    profile = PermissionProfile(
        name="android.permission.ACCESS_FINE_LOCATION",
        protection_label="dangerous",
        protection_tokens=("dangerous",),
        permission_group=None,
        description=None,
        is_runtime_dangerous=True,
        is_signature=False,
        is_privileged=False,
        is_special_access=False,
        severity=60,
        flagged_normal_class=None,
        is_scored_flagged_normal=False,
    )

    class _Catalog:
        def describe(self, name: str):
            return catalog.PermissionDescriptor(
                name=name,
                protection=("dangerous",),
                source="permission_intel_v1",
                permission_group="LOCATION",
                background_permission="android.permission.ACCESS_BACKGROUND_LOCATION",
                authority_class="AOSP_PUBLIC",
                feature_dependency="android.hardware.location.gps",
            )

    metrics = _build_metrics(
        total=1,
        dangerous=["android.permission.ACCESS_FINE_LOCATION"],
        signature=[],
        privileged=[],
        custom=[],
        level_counts=Counter({"dangerous": 1}),
        token_histogram={"dangerous": 1},
        group_summary={},
        special_permissions=[],
        profiles={"android.permission.ACCESS_FINE_LOCATION": profile},
        summary="1 declared",
        catalog_snapshot={},
        protection_levels={},
        declared_map={},
        permission_catalog=_Catalog(),
    )
    payload = metrics["permission_profiles"]["android.permission.ACCESS_FINE_LOCATION"]
    assert payload["group"] == "LOCATION"
    assert payload["background_permission"] == "android.permission.ACCESS_BACKGROUND_LOCATION"
    assert payload["authority_class"] == "AOSP_PUBLIC"
    assert payload["feature_dependency"] == "android.hardware.location.gps"
    assert metrics["permission_groups"]["LOCATION"] == [
        "android.permission.ACCESS_FINE_LOCATION"
    ]
    assert metrics["top_permissions"][0]["group"] == "LOCATION"
    assert metrics["catalog_matched_total"] == 1
    assert metrics["background_sensitive_total"] == 1
    assert metrics["authority_class_counts"] == {"AOSP_PUBLIC": 1}


def test_build_profiles_uses_full_name_compound_db_protection() -> None:
    profiles = build_profiles(
        ["android.permission.CAMERA"],
        {},
        [],
        db_protections={"android.permission.CAMERA": "dangerous|instant"},
    )
    profile = profiles["android.permission.CAMERA"]
    assert profile.is_runtime_dangerous is True
    assert profile.protection_tokens == ("dangerous", "instant")
    assert profile.protection_label == "dangerous|instant"


# =============================================================================
# Former tests/static_analysis/test_permission_matrix_rendering.py
# =============================================================================


def _profile(
    label: str,
    *,
    risk: float,
    fw_ds: set[str] | None = None,
    vendor_names: set[str] | None = None,
) -> dict[str, object]:
    package = label.lower().replace(" ", ".")
    return {
        "display_name": label,
        "label": label,
        "package": package,
        "risk": risk,
        "fw_ds": fw_ds or {"CAMERA"},
        "vendor_names": vendor_names or set(),
    }


def test_permission_matrix_uses_snapshot_and_stable_order_when_show_covers_all(
    monkeypatch,
    capsys,
):
    monkeypatch.setattr(matrix_view, "get_terminal_width", lambda: 240)
    monkeypatch.setattr(matrix_view.colors, "colors_enabled", lambda: False)

    profiles = [
        _profile("WhatsApp", risk=8.0),
        _profile("Facebook", risk=3.0),
        _profile("Instagram", risk=5.0),
    ]

    matrix_view.render_permission_matrix(
        profiles,
        scope_label="Research Dataset Alpha",
        show=10,
        snapshot_at=datetime(2026, 3, 28, 15, 4, tzinfo=UTC),
    )

    out = capsys.readouterr().out
    assert "Snapshot: 2026-03-28" in out
    assert "View: Apps 1–3/3" in out
    header_line = next(line for line in out.splitlines() if line.startswith("Permission"))
    facebook_index = header_line.index("Facebook")
    instagram_index = header_line.index("Instagram")
    whatsapp_index = header_line.index("WhatsApp")
    assert facebook_index < instagram_index < whatsapp_index


def test_permission_matrix_uses_top_risk_language_when_truncated(monkeypatch, capsys):
    monkeypatch.setattr(matrix_view, "get_terminal_width", lambda: 240)
    monkeypatch.setattr(matrix_view.colors, "colors_enabled", lambda: False)

    profiles = [
        _profile("Alpha", risk=1.0),
        _profile("Zulu", risk=9.0),
        _profile("Bravo", risk=7.0),
        _profile("Charlie", risk=3.0),
    ]

    matrix_view.render_permission_matrix(
        profiles,
        scope_label="Scope",
        show=2,
        snapshot_at="2026-03-28 9:04 AM",
    )

    out = capsys.readouterr().out
    assert "View: Top 1–2/4 by permission risk" in out
    header_line = next(line for line in out.splitlines() if line.startswith("Permission"))
    assert "Zulu" in header_line
    assert "Bravo" in header_line
    assert "Alpha" not in header_line


def test_permission_matrix_compacts_headers_and_prints_app_key(monkeypatch, capsys):
    monkeypatch.setattr(matrix_view, "get_terminal_width", lambda: 80)
    monkeypatch.setattr(matrix_view.colors, "colors_enabled", lambda: False)

    profiles = [
        _profile("Alpha One", risk=5.0),
        _profile("Beta Two", risk=4.0),
        _profile("Gamma Three", risk=3.0),
        _profile("Delta Four", risk=2.0),
        _profile("Epsilon Five", risk=1.0),
        _profile("Zeta Six", risk=0.5),
        _profile("Eta Seven", risk=0.4),
        _profile("Theta Eight", risk=0.3),
        _profile("Iota Nine", risk=0.2),
    ]

    matrix_view.render_permission_matrix(
        profiles,
        scope_label="Scope",
        show=9,
        snapshot_at="2026-03-28 9:04 AM",
    )

    out = capsys.readouterr().out
    header_line = next(line for line in out.splitlines() if line.startswith("Permission"))
    assert "AO" in header_line
    assert "BT" in header_line
    assert "App key:" in out
    assert "AO=Alpha One" in out
    assert "BT=Beta Two" in out


def test_unresolved_android_framework_shorts_skips_catalog_hits() -> None:
    from scytaledroid.StaticAnalysis.modules.permissions.profile import (
        _unresolved_android_framework_shorts,
    )

    declared = (
        "android.permission.INTERNET",
        "android.permission.CAMERA",
        "com.example.CUSTOM",
    )
    db_map = {"android.permission.INTERNET": "normal"}
    assert _unresolved_android_framework_shorts(declared, db_map) == ["CAMERA"]
    assert (
        _unresolved_android_framework_shorts(
            declared,
            {
                "android.permission.INTERNET": "normal",
                "android.permission.CAMERA": "dangerous",
            },
        )
        == []
    )
