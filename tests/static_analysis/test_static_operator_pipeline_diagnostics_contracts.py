from __future__ import annotations

from scripts.operator import diagnose_static_pipeline as diag
from scytaledroid.StaticAnalysis.cli.execution import scan_flow

# =============================================================================
# Former tests/static_analysis/test_diagnose_static_pipeline_script.py
# =============================================================================


def test_resolve_db_url_from_split_env(monkeypatch) -> None:
    monkeypatch.delenv("SCYTALEDROID_DB_URL", raising=False)
    monkeypatch.setenv("SCYTALEDROID_DB_NAME", "scytaledroid_db_dev")
    monkeypatch.setenv("SCYTALEDROID_DB_USER", "operator")
    monkeypatch.setenv("SCYTALEDROID_DB_PASSWD", "secret")
    monkeypatch.setenv("SCYTALEDROID_DB_HOST", "localhost")
    monkeypatch.setenv("SCYTALEDROID_DB_PORT", "3306")
    monkeypatch.setenv("SCYTALEDROID_DB_SCHEME", "mysql+pymysql")

    assert (
        diag._resolve_db_url()
        == "mysql://operator:secret@localhost:3306/scytaledroid_db_dev"
    )


def test_normalize_db_scheme_strips_driver_suffix() -> None:
    assert diag._normalize_db_scheme("mysql+pymysql") == "mysql"
    assert diag._normalize_db_scheme("mariadb+mysqldb") == "mariadb"


# =============================================================================
# Former tests/static_analysis/test_diagnostic_progress.py
# =============================================================================


def test_diagnostic_verbose_suppresses_checkpoint_lines(capsys):
    progress = scan_flow._PipelineProgress(
        total=10,
        show_splits=False,
        show_artifacts=True,
        show_checkpoints=False,
    )

    progress.finish(5, "Example • base")
    captured = capsys.readouterr()
    assert captured.out == ""
