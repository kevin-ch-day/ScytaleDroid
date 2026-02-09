from __future__ import annotations

import json
from pathlib import Path

from scytaledroid.DynamicAnalysis.ml.selectors.models import RunRef, SelectionResult, write_selection_manifest


def _dummy_runref(tmp_path: Path, run_id: str) -> RunRef:
    evidence = tmp_path / run_id
    evidence.mkdir(parents=True, exist_ok=True)
    mf = evidence / "run_manifest.json"
    mf.write_text("{}", encoding="utf-8")
    return RunRef(
        run_id=run_id,
        evidence_dir=evidence,
        manifest_path=mf,
        manifest_sha256="0" * 64,
        package_name="com.example",
        base_apk_sha256="a" * 64,
        mode="baseline",
        mode_source="test",
        run_profile="baseline_idle",
        started_at_utc=None,
        ended_at_utc=None,
    )


def test_selection_manifest_config_fingerprint_differs_by_selector(tmp_path: Path) -> None:
    # Query vs freeze should fingerprint different config modules once operational F2 is enabled.
    r = _dummy_runref(tmp_path, "r1")

    sel_query = SelectionResult(
        selector_type="query",
        query_params={"tier": "dataset"},
        grouping_key="base_apk_sha256",
        pool_versions=False,
        included=[r],
        excluded={},
    )
    sel_freeze = SelectionResult(
        selector_type="freeze",
        query_params={"freeze_manifest_path": "x"},
        grouping_key="base_apk_sha256",
        pool_versions=False,
        included=[r],
        excluded={},
    )

    out_q = tmp_path / "sel_query.json"
    out_f = tmp_path / "sel_freeze.json"
    write_selection_manifest(out_q, result=sel_query)
    write_selection_manifest(out_f, result=sel_freeze)
    q = json.loads(out_q.read_text(encoding="utf-8"))
    f = json.loads(out_f.read_text(encoding="utf-8"))
    assert q["config_fingerprint_sha256"] != f["config_fingerprint_sha256"]

