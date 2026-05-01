from __future__ import annotations

from collections import Counter

from scytaledroid.StaticAnalysis.cli.persistence import run_summary


def test_persist_static_analysis_findings_writes_masvs_area_and_control_id(monkeypatch):
    recorded: dict[str, object] = {}

    monkeypatch.setattr(run_summary.core_q, "run_sql", lambda *_a, **_k: None)

    def _capture(sql, params, **_kwargs):
        recorded["sql"] = sql
        recorded["params"] = params

    monkeypatch.setattr(run_summary.core_q, "run_sql_many", _capture)

    run_summary._persist_static_analysis_findings(
        static_run_id=99,
        rows=[
            {
                "finding_id": "f-1",
                "status": "OPEN",
                "severity": "High",
                "category": "PLATFORM",
                "title": "Exported activity without permission",
                "tags": "{}",
                "evidence": "{}",
                "fix": "Lock it down",
                "rule_id": "BASE-IPC-COMP-NO-ACL",
                "cvss_score": "8.0",
                "masvs_area": "PLATFORM",
                "masvs_control_id": "PLATFORM-IPC-1",
                "masvs_control": "PLATFORM",
                "detector": "ipc_components",
                "module": "manifest",
                "evidence_refs": "{}",
            }
        ],
    )

    sql = str(recorded["sql"])
    params = recorded["params"]
    assert "masvs_area" in sql
    assert "masvs_control_id" in sql
    assert params == [
        (
            99,
            "f-1",
            "OPEN",
            "High",
            "PLATFORM",
            "Exported activity without permission",
            "{}",
            "{}",
            "Lock it down",
            "BASE-IPC-COMP-NO-ACL",
            "8.0",
            "PLATFORM",
            "PLATFORM-IPC-1",
            "PLATFORM",
            "ipc_components",
            "manifest",
            "{}",
        )
    ]


def test_build_findings_context_derives_control_summary_from_canonical_rows():
    accumulator = run_summary._FindingPreparationAccumulator(
        canonical_finding_rows=[
            {
                "finding_id": "f-1",
                "severity": "Medium",
                "category": "PLATFORM",
                "title": "Exported activity without permission",
                "rule_id": "BASE-IPC-COMP-NO-ACL",
                "masvs_control_id": "PLATFORM-IPC-1",
            },
            {
                "finding_id": "f-2",
                "severity": "Medium",
                "category": "NETWORK",
                "title": "Cleartext traffic enabled",
                "rule_id": "BASE-CLR-001",
                "masvs_control_id": "NETWORK-1",
            },
            {
                "finding_id": "f-3",
                "severity": "Info",
                "category": "OTHER",
                "title": "Unmapped correlation finding",
                "rule_id": None,
                "masvs_control_id": None,
            },
        ],
        finding_rows=[
            {"masvs": "PLATFORM"},
            {"masvs": "NETWORK"},
            {"masvs": None},
        ],
        severity_counter=Counter({"Medium": 2, "Info": 1}),
    )

    context = run_summary._build_findings_persistence_context(
        accumulator=accumulator,
        baseline_counts=Counter(),
    )

    assert context.control_entry_count == 2
    assert set(context.control_summary.keys()) == {"PLATFORM-IPC-1", "NETWORK-1"}
    assert context.control_summary["PLATFORM-IPC-1"].rubric["source"] == "detector"
    assert context.missing_masvs == 1
