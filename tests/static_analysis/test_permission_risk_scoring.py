from __future__ import annotations

import pytest
from pathlib import Path

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
    assert detail["breadth"]["applied"] == pytest.approx(0.15)
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
