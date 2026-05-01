import importlib

from scytaledroid.StaticAnalysis.risk import permission as permission_risk


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

    importlib.reload(permission_risk)

    monkeypatch.setenv("SCY_PERMISSION_RISK_TOML", str(cfg1))
    p1 = permission_risk.get_scoring_params()
    assert p1.noteworthy_normal_weight == 0.06

    monkeypatch.setenv("SCY_PERMISSION_RISK_TOML", str(cfg2))
    p2 = permission_risk.get_scoring_params()
    assert p2.noteworthy_normal_weight == 0.08
