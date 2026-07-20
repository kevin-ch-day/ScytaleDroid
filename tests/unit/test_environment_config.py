from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

from scytaledroid.Config.environment import load_dotenv


def test_load_dotenv_preserves_process_values_and_parses_quoted_values(monkeypatch, tmp_path: Path) -> None:
    env_file = tmp_path / ".env"
    env_file.write_text(
        "# comment\nSCYTALEDROID_DATA_DIR='/srv/data'\nEXISTING=from-file\nINVALID\n",
        encoding="utf-8",
    )
    monkeypatch.setenv("EXISTING", "from-process")

    try:
        assert load_dotenv(env_path=env_file, allow_in_tests=True) is True
        assert os.environ["SCYTALEDROID_DATA_DIR"] == "/srv/data"
        assert os.environ["EXISTING"] == "from-process"
    finally:
        os.environ.pop("SCYTALEDROID_DATA_DIR", None)


def test_load_dotenv_respects_opt_out(monkeypatch, tmp_path: Path) -> None:
    env_file = tmp_path / ".env"
    env_file.write_text("SCYTALEDROID_OUTPUT_DIR=/srv/output\n", encoding="utf-8")
    monkeypatch.setenv("SCYTALEDROID_NO_DOTENV", "1")

    assert load_dotenv(env_path=env_file, allow_in_tests=True) is False


def test_load_dotenv_skips_invalid_variable_names(monkeypatch, tmp_path: Path) -> None:
    env_file = tmp_path / ".env"
    env_file.write_text(
        "export SCYTALEDROID_OUTPUT_DIR=/ignored\nINVALID-KEY=value\nVALID_VALUE=kept\n",
        encoding="utf-8",
    )
    monkeypatch.delenv("SCYTALEDROID_OUTPUT_DIR", raising=False)
    monkeypatch.delenv("VALID_VALUE", raising=False)

    assert load_dotenv(env_path=env_file, allow_in_tests=True) is True
    assert os.environ["VALID_VALUE"] == "kept"
    assert "SCYTALEDROID_OUTPUT_DIR" not in os.environ


def test_app_config_reads_workspace_paths_from_declared_env_file(tmp_path: Path) -> None:
    env_file = tmp_path / "migration.env"
    env_file.write_text(
        "\n".join(
            (
                "SCYTALEDROID_DATA_DIR=/srv/scytaledroid/data",
                "SCYTALEDROID_OUTPUT_DIR=/srv/scytaledroid/output",
                "SCYTALEDROID_LOGS_DIR=/srv/scytaledroid/logs",
            )
        )
        + "\n",
        encoding="utf-8",
    )
    environment = os.environ.copy()
    environment.pop("PYTEST_CURRENT_TEST", None)
    environment.pop("SCYTALEDROID_NO_DOTENV", None)
    environment["SCYTALEDROID_ENV_FILE"] = str(env_file)
    environment["PYTHONPATH"] = str(Path(__file__).resolve().parents[2])

    completed = subprocess.run(
        [
            sys.executable,
            "-c",
            (
                "from scytaledroid.Config import app_config; "
                "print('|'.join((app_config.DATA_DIR, app_config.OUTPUT_DIR, "
                "app_config.LOGS_DIR, app_config.DYNAMIC_EVIDENCE_ROOT)))"
            ),
        ],
        capture_output=True,
        check=False,
        env=environment,
        text=True,
    )

    assert completed.returncode == 0, completed.stderr
    assert completed.stdout.strip() == (
        "/srv/scytaledroid/data|/srv/scytaledroid/output|/srv/scytaledroid/logs|"
        "/srv/scytaledroid/data/evidence/dynamic"
    )
