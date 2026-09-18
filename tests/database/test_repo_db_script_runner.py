from __future__ import annotations

from scytaledroid.Database.db_utils.menus.repo_db_script_runner import run_scripts_db_py


def test_run_scripts_db_py_rejects_path_escape(capsys) -> None:
    code = run_scripts_db_py("../not_a_db_script.py")
    captured = capsys.readouterr()
    assert code == 1
    assert "Missing script" in captured.out
