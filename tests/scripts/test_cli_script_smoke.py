"""CLI script smoke tests: ``--help``, importlib-loaded audit modules, policy strings.

Merged from ``test_session_static_health_legacy_display``,
``test_static_schema_audit_operator_vocab``, ``test_verify_evidence_manifest_script``.
"""

from __future__ import annotations

import importlib.util
import os
import subprocess
import sys
from pathlib import Path

from scripts.db import session_static_health as ssh


# --- session_static_health: legacy mirror line policy (unchanged assertions) ---


def test_legacy_findings_skip_when_runs_missing() -> None:
    line = ssh._legacy_findings_status_line(
        runs_present=False,
        findings_present=True,
        count_ok=True,
        count=0,
        err_detail=None,
    )
    assert "SKIP" in line
    assert "table absent" in line.lower()


def test_legacy_findings_skip_when_findings_missing() -> None:
    line = ssh._legacy_findings_status_line(
        runs_present=True,
        findings_present=False,
        count_ok=True,
        count=0,
        err_detail=None,
    )
    assert "SKIP" in line


def test_legacy_findings_info_when_zero_rows() -> None:
    line = ssh._legacy_findings_status_line(
        runs_present=True,
        findings_present=True,
        count_ok=True,
        count=0,
        err_detail=None,
    )
    assert "INFO" in line
    assert "0" in line


def test_legacy_findings_warn_on_query_error() -> None:
    line = ssh._legacy_findings_status_line(
        runs_present=True,
        findings_present=True,
        count_ok=False,
        count=None,
        err_detail="ERROR: 1146",
    )
    assert "WARN" in line


# --- static_schema_audit: operator vocabulary (importlib) ---


def _load_static_schema_audit_module():
    root = Path(__file__).resolve().parents[2]
    path = root / "scripts" / "db" / "static_schema_audit.py"
    spec = importlib.util.spec_from_file_location("static_schema_audit", path)
    assert spec and spec.loader
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def test_legacy_table_names_matches_legacy_five_plus_correlations() -> None:
    m = _load_static_schema_audit_module()
    assert m.LEGACY_TABLE_NAMES == frozenset(
        {"runs", "findings", "metrics", "buckets", "contributors", "correlations"}
    )


def test_operator_vocab_mapping() -> None:
    m = _load_static_schema_audit_module()
    f = m._operator_vocab_for_classification
    assert f("canonical_keep") == "CANONICAL"
    assert f("derived_keep") == "DERIVED"
    assert f("bridge_compat") == "OPTIONAL (bridge compat)"
    assert f("legacy_freeze") == "LEGACY MIRROR"
    assert f("") == "—"


# --- verify_evidence_manifest.py: subprocess --help ---


def test_verify_evidence_manifest_help_exits_zero() -> None:
    repo = Path(__file__).resolve().parents[2]
    env = os.environ.copy()
    env["PYTHONPATH"] = str(repo)
    proc = subprocess.run(
        [sys.executable, str(repo / "scripts" / "db" / "verify_evidence_manifest.py"), "--help"],
        cwd=str(repo),
        env=env,
        text=True,
        capture_output=True,
        timeout=15,
        check=False,
    )
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert "--session" in (proc.stdout or "").lower() or "--session" in (proc.stderr or "").lower()


def test_report_pcap_observer_audit_help_exits_zero() -> None:
    repo = Path(__file__).resolve().parents[2]
    env = os.environ.copy()
    env["PYTHONPATH"] = str(repo)
    proc = subprocess.run(
        [sys.executable, str(repo / "scripts" / "db" / "report_pcap_observer_audit.py"), "--help"],
        cwd=str(repo),
        env=env,
        text=True,
        capture_output=True,
        timeout=15,
        check=False,
    )
    assert proc.returncode == 0, proc.stdout + proc.stderr
    out = ((proc.stdout or "") + (proc.stderr or "")).lower()
    assert "pcap observer audit" in out
