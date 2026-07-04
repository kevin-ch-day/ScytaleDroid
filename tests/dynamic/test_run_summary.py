from __future__ import annotations

import json
from datetime import UTC, datetime

from scytaledroid.DynamicAnalysis.run_summary import print_run_summary
from scytaledroid.Utils.DisplayUtils import colors
from tests.dynamic._run_summary_support import blocked_result


def test_run_summary_smoke_blocked_plan_validation(tmp_path, capsys) -> None:
    notes_dir = tmp_path / "notes"
    notes_dir.mkdir(parents=True, exist_ok=True)
    payload = {
        "timestamp": datetime.now(UTC).isoformat(),
        "event_type": "plan.validation",
        "details": {
            "validation_result": "FAIL",
            "reasons": ["missing required fields: run_signature"],
            "warnings": [],
            "summary": {
                "reason_count": 1,
                "warning_count": 0,
                "mismatch_count": 0,
                "db_row_found": True,
                "has_static_link": True,
            },
        },
    }
    (notes_dir / "run_events.jsonl").write_text(json.dumps(payload) + "\n", encoding="utf-8")

    print_run_summary(blocked_result(tmp_path), "Profile v3")

    out = colors.strip(capsys.readouterr().out)
    assert "Session blocked by plan validation." in out
    assert "missing required fields: run_signature" in out
