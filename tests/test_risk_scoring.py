"""Unit tests for the composite static-analysis risk scorer."""

from __future__ import annotations

from scytaledroid.StaticAnalysis.core.models import (
    ManifestFlags,
    PermissionSummary,
    StaticAnalysisReport,
)
from scytaledroid.StaticAnalysis.risk import RiskConfig, compute_risk_assessment


def _report(
    *,
    uses_cleartext: bool = False,
    declared_permissions: tuple[str, ...] = tuple(),
) -> StaticAnalysisReport:
    return StaticAnalysisReport(
        file_path="/tmp/app.apk",
        relative_path=None,
        file_name="app.apk",
        file_size=1024,
        hashes={"sha256": "deadbeef"},
        manifest_flags=ManifestFlags(uses_cleartext_traffic=uses_cleartext),
        permissions=PermissionSummary(declared=declared_permissions),
    )


def test_risk_assessment_returns_low_without_signals() -> None:
    assessment = compute_risk_assessment(
        permissions=tuple(),
        secrets=tuple(),
        network={"http_count": 0},
        report=_report(),
    )

    assert assessment.score == 0
    assert assessment.band == "Low"
    assert assessment.factors == tuple()


def test_risk_assessment_accumulates_secret_weights() -> None:
    assessment = compute_risk_assessment(
        permissions=tuple(),
        secrets=(
            {"severity": "P0"},
            {"severity": "P1"},
        ),
        network={"http_count": 1},
        report=_report(uses_cleartext=True, declared_permissions=("android.permission.INTERNET",)),
    )

    assert assessment.score == 90  # 45 (P0) + 25 (P1) + 20 (cleartext)
    assert assessment.band == "High"
    assert assessment.factors[0].key == "secrets"
    assert any(factor.key == "cleartext" for factor in assessment.factors)


def test_secret_scores_are_capped_by_config() -> None:
    secrets = tuple({"severity": "P0"} for _ in range(4))
    assessment = compute_risk_assessment(
        permissions=tuple(),
        secrets=secrets,
        network={"http_count": 0},
        report=_report(),
    )

    assert assessment.score == 75  # default secret cap
    assert assessment.factors[0].score == 75


def test_cleartext_factor_requires_manifest_signal() -> None:
    assessment = compute_risk_assessment(
        permissions=tuple(),
        secrets=tuple(),
        network={"http_count": 3},
        report=_report(uses_cleartext=False, declared_permissions=("android.permission.INTERNET",)),
    )

    assert assessment.score == 0
    assert all(factor.key != "cleartext" for factor in assessment.factors)

    assessment = compute_risk_assessment(
        permissions=tuple(),
        secrets=tuple(),
        network={"http_count": 3},
        report=_report(uses_cleartext=True, declared_permissions=("android.permission.INTERNET",)),
    )

    assert any(factor.key == "cleartext" for factor in assessment.factors)


def test_permission_factor_scales_and_caps() -> None:
    high_risk_permissions = tuple({"risk": "High"} for _ in range(10))
    assessment = compute_risk_assessment(
        permissions=high_risk_permissions,
        secrets=tuple(),
        network={"http_count": 0},
        report=_report(),
    )

    assert any(factor.key == "permissions" for factor in assessment.factors)
    permissions_factor = next(f for f in assessment.factors if f.key == "permissions")
    assert permissions_factor.score == RiskConfig().permission_cap


def test_custom_band_thresholds_are_respected() -> None:
    config = RiskConfig(high_band_threshold=80, medium_band_threshold=20)
    assessment = compute_risk_assessment(
        permissions=tuple(),
        secrets=({"severity": "P1"},),
        network={"http_count": 0},
        report=_report(),
        config=config,
    )

    assert assessment.score == 25
    assert assessment.band == "Medium"
