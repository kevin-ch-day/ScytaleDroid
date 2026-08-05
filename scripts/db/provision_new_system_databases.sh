#!/usr/bin/env bash

# Provision and verify the local ScytaleDroid database operator.
#
# This script:
#   - runs as a child process and does not close the parent terminal
#   - generates a password using a SQL-safe character set
#   - does not print or log the generated password
#   - creates or updates scytaledroid_operator@127.0.0.1
#   - grants access only to the two required databases
#   - updates the canonical .env PASSWD fields
#   - tests both database connections
#   - runs the ScytaleDroid database checks

set +e
umask 077

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd -- "${SCRIPT_DIR}/../.." && pwd)"
ENV_FILE="${REPO_ROOT}/.env"

TIMESTAMP="$(date -u +%Y%m%dT%H%M%SZ)"
LOG_DIR="${REPO_ROOT}/migration-checks"
LOG_FILE="${LOG_DIR}/scytaledroid-db-provision-${TIMESTAMP}.log"

PASS_COUNT=0
WARN_COUNT=0
FAIL_COUNT=0

DB_USER="scytaledroid_operator"
DB_HOST="127.0.0.1"
DB_PORT="3306"
CORE_DB="scytaledroid_core_prod"
PERMISSION_DB="android_permission_intel"

DB_PASSWORD=""
CLIENT_FILE=""

mkdir -p "$LOG_DIR"

cleanup()
{
    if [[ -n "$CLIENT_FILE" && -f "$CLIENT_FILE" ]]; then
        rm -f -- "$CLIENT_FILE"
    fi

    unset DB_PASSWORD
}

trap cleanup EXIT
trap 'cleanup; exit 130' INT TERM

section()
{
    printf '\n%s\n' \
        "==============================================================================" \
        "$1" \
        "=============================================================================="
}

pass()
{
    printf '[PASS] %s\n' "$1"
    PASS_COUNT=$((PASS_COUNT + 1))
}

warn()
{
    printf '[WARN] %s\n' "$1"
    WARN_COUNT=$((WARN_COUNT + 1))
}

fail()
{
    printf '[FAIL] %s\n' "$1"
    FAIL_COUNT=$((FAIL_COUNT + 1))
}

pause_before_return()
{
    printf '\nLog file: %s\n' "$LOG_FILE"
    printf 'The parent terminal remains open.\n'
    read -r -p "Press Enter to return to the command prompt..." _
    printf '\n'
}

# Log ordinary output, but never enable shell tracing.
exec > >(tee -a "$LOG_FILE") 2>&1

section "SCYTALEDROID DATABASE PROVISIONING"

printf 'Repository : %s\n' "$REPO_ROOT"
printf 'User       : %s\n' "$(id -un)"
printf 'Started    : %s UTC\n' "$(date -u '+%Y-%m-%d %H:%M:%S')"
printf '%s\n' \
    'WARNING: Rerunning this script rotates the scytaledroid_operator password.' \
    '         Do not rerun after a successful provisioning unless credential rotation is intended.'

section "1. PREREQUISITES"

if [[ "$(id -un)" != "systemadmin" ]]; then
    fail "Run this script as systemadmin on the new Asus desktop"
    pause_before_return
    exit 1
fi

if [[ ! -f "$ENV_FILE" ]]; then
    fail "Missing environment file: $ENV_FILE"
    pause_before_return
    exit 1
fi

if ! command -v mariadb >/dev/null 2>&1; then
    fail "MariaDB client is not installed"
    pause_before_return
    exit 1
fi

if ! command -v openssl >/dev/null 2>&1; then
    fail "OpenSSL is not installed"
    pause_before_return
    exit 1
fi

if ! command -v python3 >/dev/null 2>&1; then
    fail "Python 3 is not installed"
    pause_before_return
    exit 1
fi

pass "Required local commands are available"
pass ".env exists"

section "2. SUDO VALIDATION"

printf '%s\n' \
    "Enter the Linux password for systemadmin." \
    "This is not the MariaDB operator password."

sudo -k

if sudo -v; then
    pass "sudo authentication succeeded"
else
    fail "sudo authentication failed; no database changes were made"
    pause_before_return
    exit 1
fi

section "3. DATABASE SERVICE AND CATALOGS"

if systemctl is-active --quiet mariadb; then
    pass "MariaDB service is active"
else
    fail "MariaDB service is not active"
    systemctl --no-pager --full status mariadb 2>&1 | tail -n 25
    pause_before_return
    exit 1
fi

if ! sudo mariadb -e 'SELECT 1;' >/dev/null 2>&1; then
    fail "Local MariaDB administrator access failed"
    pause_before_return
    exit 1
fi

pass "Local MariaDB administrator access succeeded"

MISSING_DATABASE=0

for database in "$CORE_DB" "$PERMISSION_DB"; do
    database_count="$(
        sudo mariadb --batch --skip-column-names -e "
            SELECT COUNT(*)
            FROM information_schema.SCHEMATA
            WHERE SCHEMA_NAME = '${database}';
        " 2>/dev/null
    )"

    if [[ "$database_count" == "1" ]]; then
        table_count="$(
            sudo mariadb --batch --skip-column-names -e "
                SELECT COUNT(*)
                FROM information_schema.TABLES
                WHERE TABLE_SCHEMA = '${database}';
            " 2>/dev/null
        )"

        pass "Database exists: $database"
        printf '       Table count: %s\n' "${table_count:-unknown}"

        if [[ "${table_count:-0}" == "0" ]]; then
            warn "$database exists but contains no tables"
        fi
    else
        fail "Required database is missing: $database"
        MISSING_DATABASE=1
    fi
done

if [[ "$MISSING_DATABASE" -ne 0 ]]; then
    printf '\nNo account or .env changes were made.\n'
    pause_before_return
    exit 1
fi

section "4. GENERATE LOCAL OPERATOR CREDENTIAL"

# Generate a high-entropy password using only characters that are safe for:
#   - MariaDB single-quoted SQL strings
#   - .env values
#   - MariaDB option files
#
# Deliberately excludes single quote, double quote, backslash, whitespace,
# dollar sign, backtick, semicolon, hash, and shell metacharacters.

while [[ ${#DB_PASSWORD} -lt 36 ]]; do
    DB_PASSWORD="$(
        openssl rand -base64 96 2>/dev/null |
            tr -dc 'A-Za-z0-9_@%+=:,.-' |
            head -c 36
    )"
done

if [[ ${#DB_PASSWORD} -ne 36 ]]; then
    fail "Could not generate a database password"
    pause_before_return
    exit 1
fi

pass "Generated a 36-character local operator password"
printf '       The password will not be displayed or written to the log.\n'

section "5. CREATE ACCOUNT AND GRANTS"

if sudo mariadb <<SQL
CREATE USER IF NOT EXISTS
    '${DB_USER}'@'${DB_HOST}'
    IDENTIFIED BY '${DB_PASSWORD}';

ALTER USER
    '${DB_USER}'@'${DB_HOST}'
    IDENTIFIED BY '${DB_PASSWORD}';

GRANT ALL PRIVILEGES ON \`${CORE_DB}\`.*
    TO '${DB_USER}'@'${DB_HOST}';

GRANT ALL PRIVILEGES ON \`${PERMISSION_DB}\`.*
    TO '${DB_USER}'@'${DB_HOST}';

FLUSH PRIVILEGES;
SQL
then
    pass "MariaDB account and grants were applied"
else
    fail "MariaDB account provisioning failed"
    pause_before_return
    exit 1
fi

printf '\nConfigured grants:\n'

if grants="$(sudo mariadb -e "SHOW GRANTS FOR '${DB_USER}'@'${DB_HOST}';" 2>&1)"; then
    printf '%s\n' "$grants" | sed -E "s/(IDENTIFIED BY PASSWORD )'[^']*'/\\1'<redacted>'/"
else
    fail "Could not display grants"
fi

section "6. UPDATE CANONICAL .ENV FIELDS"

python3 - "$ENV_FILE" 3<<<"$DB_PASSWORD" <<'PY'
import os
import sys
from pathlib import Path

path = Path(sys.argv[1])
password = os.fdopen(3, encoding="utf-8").read().rstrip("\n")

canonical = {
    "SCYTALEDROID_DB_PASSWD": password,
    "SCYTALEDROID_PERMISSION_INTEL_DB_PASSWD": password,
}

blocked_urls = {
    "SCYTALEDROID_DB_URL",
    "SCYTALEDROID_PERMISSION_INTEL_DB_URL",
}

deprecated = {
    "SCYTALEDROID_DB_PASS",
}

original = path.read_text(encoding="utf-8")
lines = original.splitlines()
seen = set()
updated = []

for line in lines:
    stripped = line.strip()

    if not stripped or stripped.startswith("#") or "=" not in line:
        updated.append(line)
        continue

    key = line.split("=", 1)[0].strip()

    if key in canonical:
        updated.append(f"{key}={canonical[key]}")
        seen.add(key)
    elif key in blocked_urls:
        updated.append(f"{key}=")
    elif key in deprecated:
        updated.append(f"# {line}")
    else:
        updated.append(line)

for key, value in canonical.items():
    if key not in seen:
        updated.append(f"{key}={value}")

path.write_text("\n".join(updated) + "\n", encoding="utf-8")
PY

PYTHON_RC=$?

if [[ "$PYTHON_RC" -eq 0 ]]; then
    chmod 600 "$ENV_FILE"
    pass "Canonical .env password fields were updated"
    pass ".env permissions were set to 600"
else
    fail "Could not update .env"
    pause_before_return
    exit 1
fi

printf '\nSafe environment-state inspection:\n'

python3 - "$ENV_FILE" <<'PY'
import sys
from pathlib import Path

path = Path(sys.argv[1])

wanted = [
    "SCYTALEDROID_DB_PASSWD",
    "SCYTALEDROID_PERMISSION_INTEL_DB_PASSWD",
    "SCYTALEDROID_DB_URL",
    "SCYTALEDROID_PERMISSION_INTEL_DB_URL",
    "SCYTALEDROID_DB_PASS",
]

values = {}

for raw in path.read_text(encoding="utf-8", errors="replace").splitlines():
    stripped = raw.strip()

    if not stripped or stripped.startswith("#") or "=" not in stripped:
        continue

    key, value = stripped.split("=", 1)

    if key in wanted:
        values[key] = value

for key in wanted:
    if key not in values:
        state = "ABSENT"
    elif values[key] == "":
        state = "BLANK"
    else:
        state = "SET"

    print(f"{key}: {state}")

print("Secret values are deliberately omitted.")
PY

section "7. NONINTERACTIVE TCP LOGIN TESTS"

CLIENT_FILE="$(mktemp "${TMPDIR:-/tmp}/scytaledroid-mariadb-client.XXXXXX")"
chmod 600 "$CLIENT_FILE"

cat > "$CLIENT_FILE" <<EOF
[client]
protocol=tcp
host=${DB_HOST}
port=${DB_PORT}
user=${DB_USER}
password=${DB_PASSWORD}
EOF

if mariadb \
    --defaults-extra-file="$CLIENT_FILE" \
    "$CORE_DB" \
    -e 'SELECT CURRENT_USER(), DATABASE();'
then
    pass "TCP login to $CORE_DB succeeded"
    CORE_LOGIN_RC=0
else
    fail "TCP login to $CORE_DB failed"
    CORE_LOGIN_RC=1
fi

if mariadb \
    --defaults-extra-file="$CLIENT_FILE" \
    "$PERMISSION_DB" \
    -e 'SELECT CURRENT_USER(), DATABASE();'
then
    pass "TCP login to $PERMISSION_DB succeeded"
    PERMISSION_LOGIN_RC=0
else
    fail "TCP login to $PERMISSION_DB failed"
    PERMISSION_LOGIN_RC=1
fi

rm -f -- "$CLIENT_FILE"
CLIENT_FILE=""

section "8. APPLICATION CHECKS"

cd "$REPO_ROOT" || {
    fail "Could not enter repository root"
    pause_before_return
    exit 1
}

if [[ "$CORE_LOGIN_RC" -eq 0 && "$PERMISSION_LOGIN_RC" -eq 0 ]]; then
    printf '\nRunning new-system database check:\n\n'

    ./run.sh --new-system-check --require-database
    RUN_CHECK_RC=$?

    if [[ "$RUN_CHECK_RC" -eq 0 ]]; then
        pass "New-system database check succeeded"
    else
        fail "New-system database check failed with status $RUN_CHECK_RC"
    fi

    printf '\nRunning Permission Intel validation:\n\n'

    PYTHONPATH=. .venv/bin/python scripts/db/check_permission_intel.py
    PERMISSION_CHECK_RC=$?

    if [[ "$PERMISSION_CHECK_RC" -eq 0 ]]; then
        pass "Permission Intel validation succeeded"
    else
        fail "Permission Intel validation failed with status $PERMISSION_CHECK_RC"
    fi
else
    warn "Application checks were skipped because direct database login failed"
    RUN_CHECK_RC=99
    PERMISSION_CHECK_RC=99
fi

section "FINAL SUMMARY"

printf 'Passed   : %d\n' "$PASS_COUNT"
printf 'Warnings : %d\n' "$WARN_COUNT"
printf 'Failures : %d\n' "$FAIL_COUNT"

printf '\nResult:\n'

if [[ "${CORE_LOGIN_RC:-1}" -ne 0 || "${PERMISSION_LOGIN_RC:-1}" -ne 0 ]]; then
    printf '%s\n' \
        "- Database provisioning or direct TCP authentication did not complete." \
        "- Review the failures above before changing ScytaleDroid code."
elif [[ "${PERMISSION_CHECK_RC:-99}" -ne 0 ]]; then
    printf '%s\n' \
        "- Database authentication now works." \
        "- Permission Intel validation still failed." \
        "- Restore or provision its required schema and governance snapshots."
elif [[ "$FAIL_COUNT" -eq 0 ]]; then
    printf '%s\n' \
        "- Both databases, credentials, and application checks passed."
else
    printf '%s\n' \
        "- Authentication works, but another migration check still requires attention."
fi

printf '\nThe generated password remains only in MariaDB and the protected .env file.\n'

pause_before_return
