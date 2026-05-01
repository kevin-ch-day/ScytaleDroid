from __future__ import annotations

from scytaledroid.DynamicAnalysis.ml.operational_risk import build_static_inputs_from_plan


def test_build_static_inputs_prefers_static_features_snapshot() -> None:
    plan = {
        "static_features": {
            "exported_components_total": 21,
            "dangerous_permission_count": 9,
            "uses_cleartext_traffic": True,
            "sdk_indicator_score": 0.75,
        },
        "exported_components": {"total": 1},
        "permissions": {"dangerous": ["android.permission.CAMERA"]},
        "risk_flags": {"uses_cleartext_traffic": False},
        "sdk_indicators": {"score": 0.1},
    }
    out = build_static_inputs_from_plan(plan)
    assert out is not None
    assert out.exported_components_total == 21
    assert out.dangerous_permission_count == 9
    assert out.uses_cleartext_traffic == 1
    assert abs(out.sdk_indicator_score - 0.75) < 1e-9

