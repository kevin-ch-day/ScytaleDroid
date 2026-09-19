from __future__ import annotations

import importlib
from pathlib import Path

import pytest
from scytaledroid.StaticAnalysis.risk import permission as mod


def test_permission_risk_loader_honors_toml_weights(monkeypatch, tmp_path) -> None:
    config_path = tmp_path / "permission_risk.toml"
    config_path.write_text(
        """
[base]
dangerous_weight = 0.11
signature_weight = 0.33
vendor_weight = 0.01

[bonuses]
breadth_step = 0.05
breadth_cap = 0.40

[penalties]
flagged_normal_weight = 0.07
flagged_normal_cap = 0.30
noteworthy_normal_weight = 0.05
noteworthy_normal_cap = 0.20
special_risk_normal_weight = 0.11
special_risk_normal_cap = 0.40
weak_guard_weight = 0.06
weak_guard_cap = 0.20

[normalize]
max_score = 10.0
        """.strip(),
        encoding="utf-8",
    )
    monkeypatch.setenv("SCY_PERMISSION_RISK_TOML", str(config_path))
    monkeypatch.setattr(mod, "_LOADED_WEIGHTS", None)

    detail = mod.permission_risk_score_detail(
        dangerous=10,
        signature=2,
        vendor=1,
        groups={"location": 1, "contacts": 1, "camera": 1},
        noteworthy_normals=2,
        special_risk_normals=1,
        weak_guards=3,
    )

    assert detail["weights_applied"]["dangerous"] == 0.11
    assert detail["weights_applied"]["signature"] == 0.33
    assert detail["weights_applied"]["vendor"] == 0.01
    assert detail["breadth"]["applied"] == pytest.approx(mod.saturating_response(3, 0.05, 0.40))
    assert detail["penalty_weights"]["flagged_normal_weight"] == 0.07
    assert detail["penalty_weights"]["noteworthy_normal_weight"] == 0.05
    assert detail["penalty_weights"]["special_risk_normal_weight"] == 0.11
    assert detail["penalty_weights"]["weak_guard_weight"] == 0.06


def test_permission_risk_current_calibration_reduces_broad_permission_pressure(monkeypatch) -> None:
    monkeypatch.delenv("SCY_PERMISSION_RISK_TOML", raising=False)
    monkeypatch.setattr(mod, "_LOADED_WEIGHTS", None)

    detail = mod.permission_risk_score_detail(
        dangerous=21,
        signature=0,
        vendor=2,
        groups={
            "location": 1,
            "contacts": 1,
            "camera": 1,
            "microphone": 1,
            "bluetooth": 1,
            "nearby_devices": 1,
            "notifications": 1,
            "storage_legacy": 1,
            "sms_mms": 1,
        },
        target_sdk=36,
        allow_backup=False,
        legacy_external_storage=False,
        noteworthy_normals=1,
        special_risk_normals=1,
        weak_guards=4,
    )

    assert detail["score_3dp"] < 8.0
    assert detail["modernization_credit"] >= 0.5


def test_permission_intel_signals_raise_score_without_breaking_cap(monkeypatch) -> None:
    monkeypatch.delenv("SCY_PERMISSION_RISK_TOML", raising=False)
    monkeypatch.setattr(mod, "_LOADED_WEIGHTS", None)

    baseline = mod.permission_risk_score_detail(dangerous=2, signature=0, vendor=0)
    enriched = mod.permission_risk_score_detail(
        dangerous=2,
        signature=0,
        vendor=0,
        background_sensitive=3,
        health_sensitive=4,
        privileged_declared=2,
    )
    assert enriched["score_3dp"] > baseline["score_3dp"]
    assert enriched["background_sensitive_component"] == pytest.approx(
        mod.saturating_response(3, 0.18, 0.54)
    )
    assert enriched["health_sensitive_component"] == pytest.approx(
        mod.saturating_response(4, 0.12, 0.60)
    )
    assert enriched["privileged_declared_component"] == pytest.approx(
        mod.saturating_response(2, 0.10, 0.40)
    )
    assert enriched["score_3dp"] <= 10.0
    assert enriched["weights_applied"]["response_curve"] == "saturating_exp"


def test_collect_catalog_score_signals_from_profiles() -> None:
    signals = mod.collect_catalog_score_signals(
        {
            "android.permission.CAMERA": {
                "background_permission": "android.permission.BACKGROUND_CAMERA",
                "is_privileged": False,
            },
            "android.permission.health.READ_HEART_RATE": {"group": "HEALTH"},
            "android.permission.WRITE_SECURE_SETTINGS": {"is_privileged": True},
            "android.permission.ACCESS_BACKGROUND_LOCATION": {"group": "UNDEFINED"},
        }
    )
    assert signals["background_sensitive"] == 2
    assert signals["health_sensitive"] == 1
    assert signals["privileged_declared"] == 1


def test_repo_permission_risk_config_is_valid_and_active(monkeypatch) -> None:
    config_path = Path(__file__).resolve().parents[2] / "config" / "permission_risk.toml"
    monkeypatch.setenv("SCY_PERMISSION_RISK_TOML", str(config_path))
    monkeypatch.setattr(mod, "_LOADED_WEIGHTS", None)

    params = mod.get_scoring_params()

    assert params.dangerous_weight == 0.22
    assert params.signature_weight == 0.55
    assert params.vendor_weight == 0.02
    assert params.breadth_step == 0.08
    assert params.breadth_cap == 0.80
    assert params.flagged_normal_weight == 0.10
    assert params.flagged_normal_cap == 0.60
    assert params.noteworthy_normal_weight == 0.06
    assert params.noteworthy_normal_cap == 0.24
    assert params.special_risk_normal_weight == 0.16
    assert params.special_risk_normal_cap == 0.60
    assert params.weak_guard_weight == 0.08
    assert params.weak_guard_cap == 0.50
    assert params.background_sensitive_weight == 0.18
    assert params.background_sensitive_cap == 0.54
    assert params.health_sensitive_weight == 0.12
    assert params.health_sensitive_cap == 0.60
    assert params.privileged_declared_weight == 0.10
    assert params.privileged_declared_cap == 0.40
    assert params.dangerous_cap == 6.50
    assert params.signature_cap == 2.80
    assert params.vendor_cap == 1.00
    assert params.background_capture_scale == 0.35
    assert params.health_background_scale == 0.22


def test_permission_risk_weight_cache_tracks_env_path(monkeypatch, tmp_path):
    cfg1 = tmp_path / "risk1.toml"
    cfg1.write_text("""
[penalties]
noteworthy_normal_weight = 0.06
""".strip())

    cfg2 = tmp_path / "risk2.toml"
    cfg2.write_text("""
[penalties]
noteworthy_normal_weight = 0.08
""".strip())

    importlib.reload(mod)

    monkeypatch.setenv("SCY_PERMISSION_RISK_TOML", str(cfg1))
    p1 = mod.get_scoring_params()
    assert p1.noteworthy_normal_weight == 0.06

    monkeypatch.setenv("SCY_PERMISSION_RISK_TOML", str(cfg2))
    p2 = mod.get_scoring_params()
    assert p2.noteworthy_normal_weight == 0.08


def test_saturating_response_is_concave_and_bounded() -> None:
    values = [mod.saturating_response(n, 0.22, 6.5) for n in range(0, 12)]
    deltas = [values[index + 1] - values[index] for index in range(len(values) - 1)]
    assert values[0] == 0.0
    assert values[-1] < 6.5
    assert deltas[0] == pytest.approx(0.2163, abs=1e-3)
    assert all(
        deltas[index] + 1e-12 >= deltas[index + 1]
        for index in range(len(deltas) - 1)
    )
    assert mod.saturating_marginal(0, 0.22, 6.5) == pytest.approx(0.22)
    assert mod.saturating_marginal(8, 0.22, 6.5) < mod.saturating_marginal(1, 0.22, 6.5)


def test_independent_risk_combine_matches_cvss_iss() -> None:
    from scytaledroid.StaticAnalysis.modules.permissions.analysis.curves import (
        independent_risk_combine,
    )

    lone = independent_risk_combine([60], scale=180)
    assert lone == pytest.approx(60.0)
    stacked = independent_risk_combine([60, 20], scale=180)
    assert stacked == pytest.approx(180 * (1 - (1 - 60 / 180) * (1 - 20 / 180)))
    assert stacked < 80
    saturated = independent_risk_combine([180, 40], scale=180)
    assert saturated == pytest.approx(180.0)


def test_background_capture_interaction_uses_group_and_count(monkeypatch) -> None:
    monkeypatch.delenv("SCY_PERMISSION_RISK_TOML", raising=False)
    monkeypatch.setattr(mod, "_LOADED_WEIGHTS", None)
    isolated = mod.permission_risk_score_detail(
        dangerous=1,
        signature=0,
        vendor=0,
        background_sensitive=2,
    )
    combined = mod.permission_risk_score_detail(
        dangerous=1,
        signature=0,
        vendor=0,
        background_sensitive=2,
        groups={"CAM": 1, "LOC": 1, "MIC": 1},
    )
    assert isolated["background_capture_combo"] == 0.0
    assert combined["background_capture_combo"] > isolated["background_capture_combo"]
    assert combined["score_3dp"] > isolated["score_3dp"]


def test_group_multipliers_raise_location_breadth_over_notifications(monkeypatch) -> None:
    monkeypatch.delenv("SCY_PERMISSION_RISK_TOML", raising=False)
    monkeypatch.setattr(mod, "_LOADED_WEIGHTS", None)
    location = mod.permission_risk_score_detail(
        dangerous=0,
        signature=0,
        vendor=0,
        groups={"location": 1, "camera": 1, "microphone": 1},
    )
    notices = mod.permission_risk_score_detail(
        dangerous=0,
        signature=0,
        vendor=0,
        groups={"notifications": 1, "bluetooth": 1, "nearby_devices": 1},
    )
    assert location["breadth"]["weighted_groups"] > notices["breadth"]["weighted_groups"]
    assert location["breadth"]["applied"] > notices["breadth"]["applied"]
    assert location["marginals"]["dangerous"] == pytest.approx(0.22)


def test_collect_catalog_score_signals_ignores_process_background_names() -> None:
    signals = mod.collect_catalog_score_signals(
        {
            "android.permission.START_ACTIVITIES_FROM_BACKGROUND": {},
            "android.permission.KILL_BACKGROUND_PROCESSES": {},
            "android.permission.ACCESS_BACKGROUND_LOCATION": {},
            "android.permission.health.READ_HEART_RATE": {},
        }
    )
    assert signals["background_sensitive"] == 1
    assert signals["health_sensitive"] == 1
