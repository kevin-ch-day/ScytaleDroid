"""Safety contract for the governed MariaDB backup helper."""

from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
SCRIPT = REPO_ROOT / "scripts" / "db" / "backup_production_databases.sh"


def test_backup_helper_is_credential_safe_and_read_only() -> None:
    source = SCRIPT.read_text(encoding="utf-8")

    assert "set -Eeuo pipefail" in source
    assert "chmod 600 -- \"$option_file\"" in source
    assert "trap cleanup EXIT" in source
    assert "trap 'cleanup; exit 130' INT TERM" in source
    assert 'rm -f -- "$option_file"' in source
    assert "OPTION_FILES+=(\"$option_file\")" in source
    assert 'core_option="$(make_option_file' not in source
    assert "--defaults-file=\"$option_file\"" in source
    assert "--defaults-extra-file" not in source  # ~/.my.cnf must not override .env credentials
    assert "password=" in source
    assert "export " not in source
    assert "-pPASSWORD" not in source
    assert "CREATE USER" not in source
    assert "ALTER USER" not in source
    assert "GRANT " not in source
    assert "DROP DATABASE" not in source


def test_backup_helper_enforces_governed_destination_and_verification() -> None:
    source = SCRIPT.read_text(encoding="utf-8")

    assert 'readonly APPROVED_ROOT="${MERCURY_MOUNT}/mercury_backups"' in source
    assert '[[ "$resolved_destination" == "$resolved_root"/* ]]' in source
    assert '[[ ! -e "$DESTINATION" ]] || die "refusing to overwrite existing backup directory' in source
    assert "findmnt -no UUID" in source
    assert "--single-transaction --quick --routines --triggers --events" in source
    assert '--database="$database"' in source
    assert "sha256sum --check SHA256SUMS" in source
    assert "manifest.txt" in source
    assert "restore_commands.txt" in source
    assert "verification.txt" in source


def _resolved_mercury_settings(tmp_path: Path, *, env_lines: str, environ: dict[str, str]) -> list[str]:
    import os
    import subprocess

    script_copy = tmp_path / "scripts" / "db" / SCRIPT.name
    script_copy.parent.mkdir(parents=True)
    # Drop the final `main "$@"` call so only the setting resolution runs.
    body = SCRIPT.read_text(encoding="utf-8").replace('\nmain "$@"\n', "\n")
    script_copy.write_text(body + '\nprintf "%s\\n%s\\n%s\\n" "$MERCURY_MOUNT" "$MERCURY_UUID" "$APPROVED_ROOT"\n')
    (tmp_path / ".env").write_text(env_lines, encoding="utf-8")
    env = {k: v for k, v in os.environ.items() if not k.startswith("SCYTALEDROID_MERCURY_")}
    env.update(environ)
    # The EXIT trap's cleanup returns non-zero when no option files were created,
    # so judge the run by its printed settings rather than the exit status.
    out = subprocess.run(["bash", str(script_copy)], env=env, capture_output=True, text=True, check=False)
    assert "ERROR" not in out.stderr
    return out.stdout.splitlines()


def test_backup_helper_mount_defaults_to_v2(tmp_path: Path) -> None:
    mount, uuid, root = _resolved_mercury_settings(tmp_path, env_lines="# SCYTALEDROID_MERCURY_MOUNTPOINT=/x\n", environ={})

    assert mount == "/mnt/MERCURY_DATA_V2"
    assert uuid == ""
    assert root == "/mnt/MERCURY_DATA_V2/mercury_backups"


def test_backup_helper_mount_reads_dotenv_setting(tmp_path: Path) -> None:
    mount, uuid, root = _resolved_mercury_settings(
        tmp_path,
        env_lines='SCYTALEDROID_MERCURY_MOUNTPOINT="/mnt/MERCURY_DATA/"\nSCYTALEDROID_MERCURY_UUID=abc\n',
        environ={},
    )

    assert mount == "/mnt/MERCURY_DATA"
    assert uuid == "abc"
    assert root == "/mnt/MERCURY_DATA/mercury_backups"


def test_backup_helper_mount_environment_overrides_dotenv(tmp_path: Path) -> None:
    mount, _uuid, _root = _resolved_mercury_settings(
        tmp_path,
        env_lines="SCYTALEDROID_MERCURY_MOUNTPOINT=/mnt/MERCURY_DATA\n",
        environ={"SCYTALEDROID_MERCURY_MOUNTPOINT": "/srv/mercury"},
    )

    assert mount == "/srv/mercury"


def test_backup_helper_requires_uuid_setting() -> None:
    source = SCRIPT.read_text(encoding="utf-8")

    assert "DEFAULT_MERCURY_UUID" not in source
    assert '[[ -n "$MERCURY_UUID" ]] || die' in source


def test_backup_helper_checks_active_mount_before_uuid() -> None:
    source = SCRIPT.read_text(encoding="utf-8")

    assert 'mountpoint -q -- "$MERCURY_MOUNT"' in source
    assert "source \"$ENV_FILE\"" not in source and ". \"$ENV_FILE\"" not in source
