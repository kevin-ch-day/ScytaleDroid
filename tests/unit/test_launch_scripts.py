"""Regression coverage for repository launcher behavior."""

from __future__ import annotations

import subprocess
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]


def test_launch_scripts_have_valid_bash_syntax() -> None:
    for script in ("run.sh", "setup.sh"):
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


def test_run_script_explains_required_setup_for_normal_launches() -> None:
    source = (REPO_ROOT / "run.sh").read_text(encoding="utf-8")

    assert 'SETUP_MARKER="$ROOT_DIR/.setup/requirements.sha256"' in source
    assert "ScytaleDroid has not been set up on this host." in source
    assert "--new-system-check" in source


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
