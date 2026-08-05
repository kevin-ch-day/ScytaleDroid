#!/usr/bin/env bash

# Create a non-secret, logical backup baseline for the two ScytaleDroid
# production catalogs.  This script is intentionally read-only with respect to
# MariaDB: it only issues metadata SELECTs and mariadb-dump commands.

set -Eeuo pipefail
umask 077

readonly REPO_ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)"
readonly ENV_FILE="${REPO_ROOT}/.env"
readonly MERCURY_MOUNT="/mnt/MERCURY_DATA_V2"
readonly MERCURY_UUID="715f29a9-2671-477b-8c8d-515d190addb9"
readonly APPROVED_ROOT="${MERCURY_MOUNT}/mercury_backups"
readonly CORE_DB="scytaledroid_core_prod"
readonly INTEL_DB="android_permission_intel"

OPTION_FILES=()
DESTINATION=""
CREATED_OPTION_FILE=""

cleanup() {
    local option_file
    for option_file in "${OPTION_FILES[@]:-}"; do
        [[ -n "$option_file" ]] && rm -f -- "$option_file"
    done
}

trap cleanup EXIT
trap 'cleanup; exit 130' INT TERM

die() {
    printf '[backup] ERROR: %s\n' "$*" >&2
    exit 1
}

require_command() {
    command -v "$1" >/dev/null 2>&1 || die "required command is unavailable: $1"
}

# Read a literal dotenv value without sourcing .env or placing it in an
# environment variable.  The project setup contract uses uncomplicated KEY=VALUE
# lines for these six connection fields.
env_value() {
    local key="$1"
    local value
    value="$(awk -v wanted="$key" '
        index($0, wanted "=") == 1 {
            value = substr($0, length(wanted) + 2)
            sub(/\r$/, "", value)
            if ((value ~ /^".*"$/) || (value ~ /^'\''.*'\''$/)) {
                value = substr(value, 2, length(value) - 2)
            }
            print value
            exit
        }
    ' "$ENV_FILE")"
    [[ -n "$value" ]] || die "missing or empty ${key} in .env"
    printf '%s' "$value"
}

assert_mercury_mount() {
    local mounted_uuid
    mounted_uuid="$(findmnt -no UUID --target "$MERCURY_MOUNT" 2>/dev/null || true)"
    [[ "$mounted_uuid" == "$MERCURY_UUID" ]] || die "Mercury is not mounted at ${MERCURY_MOUNT} with expected UUID"
}

assert_destination_is_approved() {
    local resolved_root resolved_destination
    resolved_root="$(realpath -m -- "$APPROVED_ROOT")"
    resolved_destination="$(realpath -m -- "$DESTINATION")"
    [[ "$resolved_root" == "$APPROVED_ROOT" ]] || die "approved backup root resolved unexpectedly"
    [[ "$resolved_destination" == "$resolved_root"/* ]] || die "refusing destination outside approved Mercury backup root"
}

make_option_file() {
    local prefix="$1"
    local option_file host port user password
    host="$(env_value "${prefix}_HOST")"
    port="$(env_value "${prefix}_PORT")"
    user="$(env_value "${prefix}_USER")"
    password="$(env_value "${prefix}_PASSWD")"
    option_file="$(mktemp "${DESTINATION}/.mariadb.XXXXXX.cnf")"
    chmod 600 -- "$option_file"
    OPTION_FILES+=("$option_file")
    {
        printf '[client]\n'
        printf 'host=%s\nport=%s\nuser=%s\npassword=%s\nprotocol=tcp\n' "$host" "$port" "$user" "$password"
    } >"$option_file"
    unset password
    CREATED_OPTION_FILE="$option_file"
}

db_scalar() {
    local option_file="$1" database="$2" sql="$3"
    mariadb --defaults-extra-file="$option_file" --database="$database" --batch --skip-column-names --raw -e "$sql"
}

dump_catalog() {
    local database="$1" option_file="$2" dump_file="$3" schema_file="$4"
    mariadb-dump --defaults-extra-file="$option_file" \
        --databases "$database" --single-transaction --quick --routines --triggers --events \
        --hex-blob --add-drop-database --skip-dump-date | gzip -9 >"$dump_file"
    mariadb-dump --defaults-extra-file="$option_file" \
        --databases "$database" --no-data --routines --triggers --events \
        --add-drop-database --skip-dump-date | gzip -9 >"$schema_file"
}

verify_dump() {
    local database="$1" dump_file="$2" expected_table="$3"
    gzip -t -- "$dump_file"
    [[ -s "$dump_file" ]] || die "empty dump produced for ${database}"
    zgrep -Eq 'MariaDB dump|MySQL dump' "$dump_file" || die "dump header is not plausible for ${database}"
    zgrep -Fq "CREATE DATABASE" "$dump_file" || die "dump lacks CREATE DATABASE for ${database}"
    zgrep -Fq "\`${expected_table}\`" "$dump_file" || die "dump lacks expected table ${expected_table}"
    ! zgrep -Eq '^ERROR [0-9]+' "$dump_file" || die "dump contains apparent MariaDB client error output for ${database}"
}

main() {
    local stamp day free_kib required_kib core_option intel_option core_dump intel_dump core_schema intel_schema
    local core_tables intel_tables core_version intel_governance server_version client_version start finish
    local engine_rows fedora_version git_branch git_commit git_dirty

    for command_name in awk date df findmnt git gzip mariadb mariadb-dump realpath sha256sum stat zgrep; do
        require_command "$command_name"
    done
    [[ -f "$ENV_FILE" ]] || die "missing .env at ${ENV_FILE}"
    assert_mercury_mount

    stamp="$(date -u +%Y%m%dT%H%M%SZ)"
    day="$(date -u +%F)"
    DESTINATION="${APPROVED_ROOT}/${day}/scytaledroid_new_system_baseline_${stamp}"
    assert_destination_is_approved
    [[ ! -e "$DESTINATION" ]] || die "refusing to overwrite existing backup directory: ${DESTINATION}"
    mkdir -p -- "$(dirname -- "$DESTINATION")"
    chmod 700 -- "$(dirname -- "$DESTINATION")"
    free_kib="$(df --output=avail -k "$MERCURY_MOUNT" | tail -n 1 | tr -d '[:space:]')"
    required_kib=$((1024 * 1024)) # conservative 1 GiB free-space floor
    (( free_kib >= required_kib )) || die "insufficient free space on Mercury (need at least 1 GiB)"
    mkdir -- "$DESTINATION"
    chmod 700 -- "$DESTINATION"
    start="$(date -u +%FT%TZ)"

    make_option_file SCYTALEDROID_DB
    core_option="$CREATED_OPTION_FILE"
    make_option_file SCYTALEDROID_PERMISSION_INTEL_DB
    intel_option="$CREATED_OPTION_FILE"
    core_tables="$(db_scalar "$core_option" "$CORE_DB" "SELECT COUNT(*) FROM information_schema.TABLES WHERE TABLE_SCHEMA='${CORE_DB}' AND TABLE_TYPE='BASE TABLE';")"
    intel_tables="$(db_scalar "$intel_option" "$INTEL_DB" "SELECT COUNT(*) FROM information_schema.TABLES WHERE TABLE_SCHEMA='${INTEL_DB}' AND TABLE_TYPE='BASE TABLE';")"
    engine_rows="$(db_scalar "$core_option" "$CORE_DB" "SELECT CONCAT(TABLE_SCHEMA, ':', COALESCE(ENGINE,'NULL'), ':', COUNT(*)) FROM information_schema.TABLES WHERE TABLE_SCHEMA IN ('${CORE_DB}','${INTEL_DB}') AND TABLE_TYPE='BASE TABLE' GROUP BY TABLE_SCHEMA, ENGINE ORDER BY TABLE_SCHEMA, ENGINE;")"
    [[ "$engine_rows" != *":InnoDB:"* ]] && die "transactional InnoDB engine check failed"
    if printf '%s\n' "$engine_rows" | grep -Ev ':(InnoDB):' >/dev/null; then
        die "non-InnoDB tables detected; refusing snapshot backup without an explicit strategy"
    fi
    core_version="$(db_scalar "$core_option" "$CORE_DB" "SELECT COALESCE((SELECT schema_version_after FROM schema_migrations WHERE status='applied' AND schema_version_after IS NOT NULL AND TRIM(schema_version_after) <> '' ORDER BY migration_entry_id DESC LIMIT 1), (SELECT version FROM schema_version ORDER BY applied_at_utc DESC LIMIT 1), 'unknown');")"
    intel_governance="$(db_scalar "$intel_option" "$INTEL_DB" "SELECT CONCAT(COUNT(*), ' snapshots / ', (SELECT COUNT(*) FROM permission_governance_snapshot_rows), ' rows') FROM permission_governance_snapshots;")"
    server_version="$(db_scalar "$core_option" "$CORE_DB" 'SELECT VERSION();')"
    client_version="$(mariadb-dump --version)"

    core_dump="${DESTINATION}/${CORE_DB}.sql.gz"
    intel_dump="${DESTINATION}/${INTEL_DB}.sql.gz"
    core_schema="${DESTINATION}/${CORE_DB}.schema.sql.gz"
    intel_schema="${DESTINATION}/${INTEL_DB}.schema.sql.gz"
    dump_catalog "$CORE_DB" "$core_option" "$core_dump" "$core_schema"
    dump_catalog "$INTEL_DB" "$intel_option" "$intel_dump" "$intel_schema"
    verify_dump "$CORE_DB" "$core_dump" static_analysis_runs
    verify_dump "$INTEL_DB" "$intel_dump" android_permission_dict_aosp
    gzip -t -- "$core_schema" "$intel_schema"
    (cd "$DESTINATION" && sha256sum "$(basename -- "$core_dump")" "$(basename -- "$intel_dump")" "$(basename -- "$core_schema")" "$(basename -- "$intel_schema")") >"${DESTINATION}/SHA256SUMS"
    (cd "$DESTINATION" && sha256sum --check SHA256SUMS)
    finish="$(date -u +%FT%TZ)"
    fedora_version="$(. /etc/os-release && printf '%s %s' "$NAME" "$VERSION_ID")"
    git_branch="$(git -C "$REPO_ROOT" branch --show-current)"
    git_commit="$(git -C "$REPO_ROOT" rev-parse HEAD)"
    git_dirty="$(git -C "$REPO_ROOT" diff --quiet && git -C "$REPO_ROOT" diff --cached --quiet && printf no || printf yes)"

    cat >"${DESTINATION}/restore_commands.txt" <<RESTORE
# Restore only into deliberately chosen, non-production targets.
# Create a new owner-only option file containing [client] host/port/user/password.
gzip -cd ${CORE_DB}.sql.gz | mariadb --defaults-extra-file=/path/to/owner-only-client.cnf
gzip -cd ${INTEL_DB}.sql.gz | mariadb --defaults-extra-file=/path/to/owner-only-client.cnf
RESTORE
    cat >"${DESTINATION}/verification.txt" <<VERIFY
sha256sum --check SHA256SUMS: PASS
gzip integrity: PASS
MariaDB dump headers, CREATE DATABASE statements, and critical table definitions: PASS
live base-table counts: ${CORE_DB}=${core_tables}; ${INTEL_DB}=${intel_tables}
engine check: ${engine_rows//$'\n'/; }
temporary credential option files: removed by EXIT/INT/TERM trap
VERIFY
    cat >"${DESTINATION}/manifest.txt" <<MANIFEST
ScytaleDroid governed production backup baseline
started_utc=${start}
finished_utc=${finish}
hardware_role=NEW SYSTEM — Asus desktop
operator_user=$(id -un)
fedora=${fedora_version}
mariadb_client=${client_version}
mariadb_server=${server_version}
git_branch=${git_branch}
git_commit=${git_commit}
working_tree_dirty=${git_dirty}
destination=${DESTINATION}
mercury_mount=${MERCURY_MOUNT}
mercury_uuid=${MERCURY_UUID}
databases=${CORE_DB},${INTEL_DB}
core_schema_version=${core_version}
permission_intel_governance=${intel_governance}
table_counts=${CORE_DB}:${core_tables};${INTEL_DB}:${intel_tables}
engine_summary=${engine_rows//$'\n'/; }
dump_files=$(basename -- "$core_dump"),$(basename -- "$intel_dump"),$(basename -- "$core_schema"),$(basename -- "$intel_schema")
dump_sizes_bytes=$(stat -c '%n:%s' "$core_dump" "$intel_dump" "$core_schema" "$intel_schema" | sed "s#${DESTINATION}/##" | tr '\n' ';')
checksums_file=SHA256SUMS
verification=PASS
restore_commands=restore_commands.txt
filesystem_limitation=historical evidence/static_runs remains unavailable; this is not a database backup failure
database_mutation=none
MANIFEST
    chmod 600 -- "${DESTINATION}"/*
    printf '[backup] PASS: governed baseline created at %s\n' "$DESTINATION"
}

main "$@"
