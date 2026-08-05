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
    assert "--defaults-extra-file=\"$option_file\"" in source
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
