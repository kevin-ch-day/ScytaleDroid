from __future__ import annotations

from pathlib import Path


_STUBS = {
    Path("docs/paper2/README.md"): "docs/legacy/paper2/README.md",
    Path("docs/paper2/operator_runbook.md"): "docs/legacy/paper2/operator_runbook.md",
    Path("docs/paper2/phase_e_plan.md"): "docs/legacy/paper2/phase_e_plan.md",
    Path("docs/paper2/phase_e_intelligence_map.md"): "docs/legacy/paper2/phase_e_intelligence_map.md",
    Path("docs/contracts/paper2_capture_policy_v1.md"): "docs/contracts/freeze_capture_policy_v1.md",
}


def test_legacy_doc_stubs_exist_and_point_to_new_paths() -> None:
    for stub_path, target in _STUBS.items():
        assert stub_path.exists(), f"missing stub: {stub_path}"
        payload = stub_path.read_text(encoding="utf-8")
        assert target in payload, f"{stub_path} does not reference expected target: {target}"

