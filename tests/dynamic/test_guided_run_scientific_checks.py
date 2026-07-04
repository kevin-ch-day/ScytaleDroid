from __future__ import annotations

from scytaledroid.DynamicAnalysis.controllers import guided_run, guided_run_checks


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
    monkeypatch.setattr(
        guided_run_checks.menu_utils,
        "print_table",
        lambda _headers, rows, **_kwargs: [
            print(" ".join(str(cell) for cell in row)) for row in rows
        ],
    )


def test_scientific_checks_warn_when_plan_signer_unknown(monkeypatch, tmp_path, capsys):
    _patch_common_ready(monkeypatch, tmp_path)
    monkeypatch.setattr(
        guided_run,
        "_load_plan_identity",
        lambda _path: {"version_code": "123", "signer_set_hash": "UNKNOWN"},
    )
    monkeypatch.setattr(
        guided_run, "_read_observed_signer_set_hash", lambda _serial, _package: "a" * 64
    )

    ok = guided_run._pre_run_scientific_checks(
        device_serial="device",
        package_name="com.example.app",
        plan_path="plan.json",
        observer_ids=["pcapdroid_capture"],
    )

    out = capsys.readouterr().out
    assert ok is True
    assert "Plan signer identity unavailable" not in out
    assert "plan signer unavailable; drift check skipped" in out
    assert "INFO" in out
    assert "Status: READY" in out


def test_scientific_checks_explains_run_signature_is_not_comparable_signer(
    monkeypatch, tmp_path, capsys
):
    _patch_common_ready(monkeypatch, tmp_path)
    monkeypatch.setattr(
        guided_run,
        "_load_plan_identity",
        lambda _path: {"version_code": "123", "signer_set_hash": "", "run_signature": "c" * 64},
    )
    monkeypatch.setattr(
        guided_run, "_read_observed_signer_set_hash", lambda _serial, _package: "a" * 64
    )

    ok = guided_run._pre_run_scientific_checks(
        device_serial="device",
        package_name="com.example.app",
        plan_path="plan.json",
        observer_ids=["pcapdroid_capture"],
    )

    out = capsys.readouterr().out
    assert ok is True
    assert "plan signer unavailable in comparable format; drift check skipped" in out
    assert "Status: READY" in out


def test_scientific_checks_block_hard_failure_without_warnings(monkeypatch, tmp_path, capsys):
    _patch_common_ready(monkeypatch, tmp_path)
    monkeypatch.setattr(
        guided_run,
        "_load_plan_identity",
        lambda _path: {"version_code": "123", "signer_set_hash": "b" * 64},
    )
    monkeypatch.setattr(
        guided_run, "_read_observed_signer_set_hash", lambda _serial, _package: "a" * 64
    )

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


def test_print_paper_mode_constants_uses_training_wording(capsys):
    guided_run._print_paper_mode_constants()

    out = capsys.readouterr().out
    assert "Training: baseline-only" in out
    assert "Baseline-only=YES" not in out
