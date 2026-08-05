"""Safety contracts for the privileged new-system DB provisioning helper."""

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
