from __future__ import annotations

from scytaledroid.DynamicAnalysis.controllers import guided_run


def _patch_common_ready(monkeypatch, tmp_path):
    monkeypatch.setattr(guided_run.app_config, "DATA_DIR", str(tmp_path))
    monkeypatch.setattr(guided_run, "missing_required_tools", lambda tier=None: [])
    monkeypatch.setattr(guided_run, "_read_capture_interface", lambda _serial: "wlan0")
    monkeypatch.setattr(guided_run, "_read_vpn_state", lambda _serial: "not_vpn")
    monkeypatch.setattr(guided_run, "_read_battery_level", lambda _serial: 100)
    monkeypatch.setattr(guided_run, "_read_storage_free_gb", lambda _serial: 50.0)
    monkeypatch.setattr(guided_run, "_read_clock_drift_seconds", lambda _serial: 1.0)
    monkeypatch.setattr(
        guided_run,
        "_read_observed_version_code_details",
        lambda _serial, _package: {
            "version_code": "123",
            "command": "cmd package dump",
            "pattern": "versionCode",
            "matched_line": "versionCode=123",
        },
    )


def test_scientific_checks_warn_when_plan_signer_unknown(monkeypatch, tmp_path, capsys):
    _patch_common_ready(monkeypatch, tmp_path)
    monkeypatch.setattr(
        guided_run,
        "_load_plan_identity",
        lambda _path: {"version_code": "123", "signer_set_hash": "UNKNOWN"},
    )
    monkeypatch.setattr(guided_run, "_read_observed_signer_set_hash", lambda _serial, _package: "a" * 64)

    ok = guided_run._pre_run_scientific_checks(
        device_serial="device",
        package_name="com.example.app",
        plan_path="plan.json",
        observer_ids=["pcapdroid_capture"],
    )

    out = capsys.readouterr().out
    assert ok is True
    assert "WARN" in out
    assert "Plan signer identity unavailable" in out
    assert "Status: READY" in out


def test_scientific_checks_block_hard_failure_without_warnings(monkeypatch, tmp_path, capsys):
    _patch_common_ready(monkeypatch, tmp_path)
    monkeypatch.setattr(
        guided_run,
        "_load_plan_identity",
        lambda _path: {"version_code": "123", "signer_set_hash": "b" * 64},
    )
    monkeypatch.setattr(guided_run, "_read_observed_signer_set_hash", lambda _serial, _package: "a" * 64)

    ok = guided_run._pre_run_scientific_checks(
        device_serial="device",
        package_name="com.example.app",
        plan_path="plan.json",
        observer_ids=["pcapdroid_capture"],
    )

    out = capsys.readouterr().out
    assert ok is False
    assert "Signer identity drift detected" in out
    assert "Pre-run scientific checks failed" in out
    assert "Status: READY" not in out
