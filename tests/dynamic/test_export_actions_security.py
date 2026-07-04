from __future__ import annotations

from pathlib import Path

from scripts.db import report_dynamic_hidden_patterns as hidden_mod
from scripts.db import report_dynamic_pcap_payload_audit as payload_mod
from scytaledroid.DynamicAnalysis.menus import export_actions


def test_cohort_security_audit_export_can_include_hidden_patterns(
    monkeypatch, tmp_path: Path, capsys
) -> None:
    payload_calls: list[bool] = []
    hidden_calls: list[bool] = []

    def _payload_report() -> dict:
        payload_calls.append(True)
        return {
            "runs_scanned": 1,
            "output_files": {"pcap_payload_runs_csv": str(tmp_path / "pcap_payload_runs.csv")},
        }

    def _hidden_report() -> dict:
        hidden_calls.append(True)
        return {"candidate_count": 3}

    (tmp_path / "pcap_payload_runs.csv").write_text("run_id\nrun-1\n", encoding="utf-8")

    monkeypatch.setattr(payload_mod, "generate_report", _payload_report)
    monkeypatch.setattr(hidden_mod, "generate_report", _hidden_report)

    export_actions.run_cohort_security_audit_export(include_hidden_patterns=True)

    out = capsys.readouterr().out
    assert payload_calls == [True]
    assert hidden_calls == [True]
    assert "Hidden patterns: 3 candidates" in out
