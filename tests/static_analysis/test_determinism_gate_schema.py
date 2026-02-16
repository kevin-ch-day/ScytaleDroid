from __future__ import annotations

import importlib.util
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


def test_static_determinism_diff_items_are_structured():
    gate = _load_gate_module()
    diffs = gate._collect_diffs(
        {"identity": {"package": "a"}, "counts": [1, 2]},
        {"identity": {"package": "b"}, "counts": [1, 2, 3]},
    )
    assert diffs
    for item in diffs:
        assert set(item.keys()) == {"path", "left", "right", "allowed"}


def test_static_determinism_result_payload_schema():
    gate = _load_gate_module()
    payload = gate._build_result_payload(
        apk_path=Path("/tmp/example.apk"),
        profile="full",
        left_meta={"run_id": 1},
        right_meta={"run_id": 2},
        payload_a={"identity": {"package_name": "com.example"}, "analytics": {"findings_total": 3}},
        payload_b={"identity": {"package_name": "com.example"}, "analytics": {"findings_total": 5}},
    )
    assert payload["compare_type"] == "static_analysis"
    assert payload["result"]["pass"] is False
    assert payload["result"]["diff_counts"]["disallowed"] >= 1
    assert isinstance(payload["diffs"], list)
