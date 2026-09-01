from __future__ import annotations

import json
from pathlib import Path

from scytaledroid.DynamicAnalysis.ml.selectors.freeze_selector import FreezeSelector
from scytaledroid.DynamicAnalysis.ml.selectors.models import QueryParams
from scytaledroid.DynamicAnalysis.ml.selectors.query_selector import QuerySelector


def test_freeze_selector_excludes_run_id_outside_evidence_root(tmp_path: Path) -> None:
    evidence_root = tmp_path / "evidence"
    evidence_root.mkdir()
    freeze_path = tmp_path / "freeze.json"
    unsafe_id = "../outside-run"
    freeze_path.write_text(
        json.dumps(
            {
                "apps": {
                    "com.example.app": {
                        "baseline_run_ids": [unsafe_id],
                        "interactive_run_ids": [unsafe_id, unsafe_id],
                    }
                },
                "included_run_ids": [unsafe_id],
                "included_run_checksums": {unsafe_id: {}},
            }
        ),
        encoding="utf-8",
    )

    result = FreezeSelector(
        evidence_root=evidence_root,
        freeze_manifest_path=freeze_path,
    ).select()

    assert result.included == []
    assert result.excluded[unsafe_id]["reason"] == "unsafe_run_id"


def test_query_selector_excludes_unsafe_db_run_id(
    tmp_path: Path,
    monkeypatch,
) -> None:
    monkeypatch.setattr(
        QuerySelector,
        "_candidate_run_ids",
        lambda _self: ["../outside-run"],
    )
    selector = QuerySelector(
        evidence_root=tmp_path / "evidence",
        params=QueryParams(),
        allow_db_index=True,
    )

    result = selector.select()

    assert result.included == []
    assert result.excluded["../outside-run"]["reason"] == "unsafe_run_id"
