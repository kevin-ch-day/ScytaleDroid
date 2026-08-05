"""Safety contracts for the privileged new-system DB provisioning helper."""

import subprocess
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
PROVISION_SCRIPT = REPO_ROOT / "scripts" / "db" / "provision_new_system_databases.sh"


def test_provision_helper_stops_on_failures_and_redacts_credential_material() -> None:
    source = PROVISION_SCRIPT.read_text(encoding="utf-8")

    assert "return 0 2>/dev/null || true" not in source
    assert "trap 'cleanup; exit 130' INT TERM" in source
    assert 'python3 - "$ENV_FILE" 3<<<"$DB_PASSWORD"' in source
    assert "export SCYTALE_GENERATED_DB_PASSWORD" not in source
    assert "IDENTIFIED BY PASSWORD )'[^']*'" in source
    assert "<redacted>" in source
    assert "Rerunning this script rotates the scytaledroid_operator password." in source
    assert 'rm -f -- "$CLIENT_FILE"' in source
    assert "tempfile.mkstemp" in source
    assert "os.fchmod(fd, 0o600)" in source
    assert "os.replace(temporary_path, path)" in source


def test_provision_helper_requires_explicit_write_confirmation() -> None:
    source = PROVISION_SCRIPT.read_text(encoding="utf-8")

    assert 'CONFIRMATION="PROVISION LOCAL SCYTALEDROID OPERATOR"' in source
    assert '"${1:-}" == "--execute"' in source
    assert '"${3:-}" == "$CONFIRMATION"' in source
    assert "BLOCKED use --check, or exact --execute and confirmation" in source
    assert source.index("BLOCKED use --check") < source.index('mkdir -p "$LOG_DIR"')


def test_provision_helper_help_is_side_effect_free() -> None:
    result = subprocess.run(
        [str(PROVISION_SCRIPT), "--help"],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
        check=False,
        timeout=20,
    )

    assert result.returncode == 0, result.stderr
    assert "--check" in result.stdout
    assert "--execute" in result.stdout
    assert "PROVISION LOCAL SCYTALEDROID OPERATOR" in result.stdout


def test_provision_helper_is_portable_but_refuses_root_and_foreign_env_files() -> None:
    source = PROVISION_SCRIPT.read_text(encoding="utf-8")

    assert 'OPERATOR_NAME="$(id -un)"' in source
    assert "Run this script as the normal repository operator, not as root" in source
    assert '[[ ! -O "$ENV_FILE" ]]' in source
    assert "Run this script as systemadmin" not in source


def test_provision_helper_has_read_only_preflight_mode() -> None:
    source = PROVISION_SCRIPT.read_text(encoding="utf-8")

    assert '"${1:-}" == "--check"' in source
    assert 'MODE="check"' in source
    assert 'if [[ "$MODE" == "check" ]]; then' in source
    assert "READY FOR EXPLICIT EXECUTE; no account or configuration was changed." in source
    assert source.index('if [[ "$MODE" == "check" ]]; then') < source.index('section "4. GENERATE LOCAL OPERATOR CREDENTIAL"')
