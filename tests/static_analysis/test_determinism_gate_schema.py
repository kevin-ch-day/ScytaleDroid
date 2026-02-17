from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path


def _load_gate_module():
    root = Path(__file__).resolve().parents[2]
    script_path = root / "scripts" / "static_analysis" / "determinism_gate.py"
    spec = importlib.util.spec_from_file_location("sd_static_determinism_gate", script_path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def test_static_determinism_rules_file_exists_and_loads():
    gate = _load_gate_module()
    rules_path = Path("docs/contracts/determinism_static_rules.json")
    assert rules_path.exists()
    rules = gate._load_rules(rules_path)
    assert rules.compare_type == "static_analysis"
    assert "static_analysis_findings" in rules.table_coverage_lock


def test_static_determinism_diff_items_are_structured():
    gate = _load_gate_module()
    rules = gate.GateRules(
        schema_version="v1",
        compare_type="static_analysis",
        allowed_diff_fields=(),
        table_coverage_lock=("static_analysis_runs",),
    )
    diffs = gate._collect_diffs(
        {"identity": {"package": "a"}, "counts": [1, 2]},
        {"identity": {"package": "b"}, "counts": [1, 2, 3]},
        rules=rules,
    )
    assert diffs
    for item in diffs:
        assert set(item.keys()) == {"path", "left", "right", "allowed"}


def test_static_determinism_result_payload_schema():
    gate = _load_gate_module()
    rules = gate.GateRules(
        schema_version="v1",
        compare_type="static_analysis",
        allowed_diff_fields=(),
        table_coverage_lock=("static_analysis_runs",),
    )
    payload = gate._build_result_payload(
        apk_path=Path("/tmp/example.apk"),
        profile="full",
        rules=rules,
        rules_path="docs/contracts/determinism_static_rules.json",
        left_meta={"run_id": 1},
        right_meta={"run_id": 2},
        payload_a={"identity": {"package_name": "com.example"}, "analytics": {"findings_total": 3}},
        payload_b={"identity": {"package_name": "com.example"}, "analytics": {"findings_total": 5}},
    )
    assert payload["compare_type"] == "static_analysis"
    assert payload["result"]["pass"] is False
    assert payload["result"]["pass_raw"] is False
    assert payload["result"]["diff_counts"]["disallowed"] >= 1
    assert isinstance(payload["diffs"], list)
    assert payload["rules"]["schema_version"] == "v1"


def test_static_determinism_validation_issue_sets_fail_reason():
    gate = _load_gate_module()
    rules = gate.GateRules(
        schema_version="v1",
        compare_type="static_analysis",
        allowed_diff_fields=(),
        table_coverage_lock=("static_analysis_runs",),
    )
    payload = gate._build_result_payload(
        apk_path=Path("/tmp/example.apk"),
        profile="full",
        rules=rules,
        rules_path="docs/contracts/determinism_static_rules.json",
        left_meta={"run_id": 1},
        right_meta={"run_id": 2},
        payload_a={
            "analytics": {
                "permission_risk_vnext": {
                    "validation": {
                        "missing_key_fields": [],
                        "duplicate_keys": [],
                        "non_canonical_permission_names": ["Android.Permission.CAMERA"],
                    }
                }
            }
        },
        payload_b={
            "analytics": {
                "permission_risk_vnext": {
                    "validation": {
                        "missing_key_fields": [],
                        "duplicate_keys": [],
                        "non_canonical_permission_names": [],
                    }
                }
            }
        },
    )
    assert payload["result"]["pass"] is False
    assert payload["result"]["fail_reason"] == "validation_error"
    assert payload["result"]["validation_issues"] == ["left.permission_risk_vnext.non_canonical_permission_names"]


def test_static_determinism_waiver_sets_waived_pass():
    gate = _load_gate_module()
    rules = gate.GateRules(
        schema_version="v1",
        compare_type="static_analysis",
        allowed_diff_fields=(),
        table_coverage_lock=("static_analysis_runs",),
    )
    payload = gate._build_result_payload(
        apk_path=Path("/tmp/example.apk"),
        profile="full",
        rules=rules,
        rules_path="docs/contracts/determinism_static_rules.json",
        left_meta={"run_id": 1},
        right_meta={"run_id": 2},
        payload_a={"analytics": {"findings_total": 1}},
        payload_b={"analytics": {"findings_total": 2}},
        waiver={
            "reason": "approved drift",
            "scope": "static_analysis",
            "approver": "pm",
            "expires_utc": "2099-01-01T00:00:00Z",
        },
    )
    assert payload["result"]["pass_raw"] is False
    assert payload["result"]["waived"] is True
    assert payload["result"]["pass"] is True


def test_static_determinism_load_waiver_requires_fields(tmp_path: Path):
    gate = _load_gate_module()
    waiver = tmp_path / "waiver.json"
    waiver.write_text(json.dumps({"reason": "x"}), encoding="utf-8")
    try:
        gate._load_waiver(waiver)
        assert False, "expected missing-field failure"
    except RuntimeError as exc:
        assert "missing required fields" in str(exc)
