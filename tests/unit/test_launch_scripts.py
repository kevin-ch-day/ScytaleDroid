"""Regression coverage for repository launcher behavior."""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]


def test_launch_scripts_have_valid_bash_syntax() -> None:
    for script in ("run.sh", "run_mariadb.sh", "setup.sh"):
        result = subprocess.run(
            ["bash", "-n", str(REPO_ROOT / script)],
            capture_output=True,
            text=True,
            check=False,
        )
        assert result.returncode == 0, result.stderr


def test_setup_allows_headless_or_android_provisioned_modes() -> None:
    source = (REPO_ROOT / "setup.sh").read_text(encoding="utf-8")

    assert 'ANDROID_SETUP_MODE="${SCYTALEDROID_SETUP_ANDROID:-auto}"' in source
    assert 'SCYTALEDROID_SETUP_ANDROID=1' in source
    assert "WORKSPACE_DIRS" in source
    assert "app_config.DYNAMIC_EVIDENCE_ROOT" in source
    assert "Could not resolve configured workspace directories" in source
    assert 'PYTHONPATH="$ROOT_DIR${PYTHONPATH:+:$PYTHONPATH}"' in source


def test_run_script_explains_required_setup_for_normal_launches() -> None:
    source = (REPO_ROOT / "run.sh").read_text(encoding="utf-8")

    assert 'SETUP_MARKER="$ROOT_DIR/.setup/requirements.sha256"' in source
    assert "ScytaleDroid has not been set up on this host." in source
    assert "--new-system-check" in source
    assert '[[ ! -x "$ROOT_DIR/.venv/bin/python" ]] || [[ ! -s "$SETUP_MARKER" ]]' in source


def test_mariadb_launcher_does_not_source_environment_files() -> None:
    source = (REPO_ROOT / "run_mariadb.sh").read_text(encoding="utf-8")

    assert 'source "$ENV_FILE"' not in source
    assert "Treat .env as data, not executable shell." in source


def test_mariadb_launcher_treats_environment_file_as_data(tmp_path: Path) -> None:
    sentinel = tmp_path / "executed"
    env_file = tmp_path / "migration.env"
    env_file.write_text(
        f"UNSAFE=$(touch {sentinel})\nSCYTALEDROID_DB_NAME=ignored\n",
        encoding="utf-8",
    )

    result = subprocess.run(
        [str(REPO_ROOT / "run_mariadb.sh"), "mysql://user:pass@localhost:3306/test", "--help"],
        capture_output=True,
        env={"PATH": "/usr/bin:/bin", "SCYTALEDROID_ENV_FILE": str(env_file)},
        text=True,
        check=False,
        timeout=20,
    )

    assert result.returncode == 0, result.stderr
    assert not sentinel.exists()


def test_run_script_is_cwd_independent_and_exposes_new_system_check(tmp_path: Path) -> None:
    result = subprocess.run(
        [str(REPO_ROOT / "run.sh"), "--help"],
        cwd=tmp_path,
        capture_output=True,
        text=True,
        check=False,
        timeout=20,
    )

    assert result.returncode == 0, result.stderr
    assert "--new-system-check" in result.stdout


def test_main_help_does_not_require_optional_database_driver() -> None:
    """Keep fresh-host launcher help usable before runtime dependencies install."""

    result = subprocess.run(
        [sys.executable, "-S", str(REPO_ROOT / "main.py"), "--help"],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
        check=False,
        timeout=20,
    )

    assert result.returncode == 0, result.stderr
    assert "--new-system-check" in result.stdout


def test_subcommand_help_does_not_import_runtime_dependencies() -> None:
    for command in ("device", "static"):
        result = subprocess.run(
            [sys.executable, "-S", str(REPO_ROOT / "main.py"), command, "--help"],
            cwd=REPO_ROOT,
            capture_output=True,
            text=True,
            check=False,
            timeout=20,
        )

        assert result.returncode == 0, result.stderr
        assert "usage:" in result.stdout
