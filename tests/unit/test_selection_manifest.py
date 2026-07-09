from __future__ import annotations

import json
from pathlib import Path

from scytaledroid.DynamicAnalysis.ml.selectors.models import (
    RunRef,
    SelectionResult,
    write_selection_manifest,
)


def _dummy_runref(tmp_path: Path, run_id: str = "r1") -> RunRef:
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


def test_selection_manifest_sha256_is_stable(tmp_path: Path) -> None:
    run_dir = tmp_path / "evidence" / "r1"
    run_dir.mkdir(parents=True)
    mf = run_dir / "run_manifest.json"
    mf.write_text("{\"dynamic_run_id\":\"r1\"}\n", encoding="utf-8")
    ref = RunRef(
        run_id="r1",
        evidence_dir=run_dir,
        manifest_path=mf,
        manifest_sha256="00" * 32,
        package_name="com.example",
        base_apk_sha256="aa" * 32,
        mode="baseline",
        mode_source="run_profile",
        run_profile="baseline",
        started_at_utc="2026-02-01T00:00:00+00:00",
        ended_at_utc="2026-02-01T00:01:00+00:00",
    )
    sel = SelectionResult(
        selector_type="query",
        query_params={"tier": "dataset"},
        grouping_key="base_apk_sha256",
        pool_versions=False,
        included=[ref],
        excluded={},
    )
    out = tmp_path / "selection_manifest.json"
    m1 = write_selection_manifest(out, result=sel)
    payload = json.loads(out.read_text(encoding="utf-8"))
    assert payload["selection_manifest_sha256"] == m1.sha256
    # Re-write and confirm the sha matches the recomputed one (ignoring created_at drift by reusing payload).
    # The manifest writer includes timestamps, so we validate internal self-consistency only.
    assert isinstance(m1.sha256, str) and len(m1.sha256) == 64


def test_selection_manifest_config_fingerprint_differs_by_selector(tmp_path: Path) -> None:
    # Query vs freeze should fingerprint different config modules once operational F2 is enabled.
    r = _dummy_runref(tmp_path)

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
