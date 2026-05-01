#!/usr/bin/env bash
# Helper to launch ScytaleDroid against MariaDB using SCYTALEDROID_DB_URL from .env or args.
#
# DB URL-from-parts logic mirrors scytaledroid.Database.db_core.db_config._compose_db_url_from_parts
# (stdlib only here so cold-start does not import the full package tree).
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

if [ "${1:-}" = "-h" ] || [ "${1:-}" = "--help" ]; then
  cat <<EOF
Usage: $(basename "$0") [MYSQL_URL] [run.sh arguments...]

Launches repo-root run.sh with a database URL set (remaining arguments pass through to ./run.sh). Resolve order:
  1. First argument MYSQL_URL (if given), else
  2. SCYTALEDROID_DB_URL from the environment (e.g. after sourcing .env), else
  3. Composed from SCYTALEDROID_DB_NAME and optional HOST/USER/PASSWD/PORT/SCHEME
     (same rules as Database/db_core/db_config composition).

Environment file: SCYTALEDROID_ENV_FILE (default: ${ROOT_DIR}/.env)

Examples:
  ./run_mariadb.sh                                         # compose URL from .env, then ./run.sh
  ./run_mariadb.sh 'mysql://user:pass@localhost:3306/db'   # explicit URL before run.sh defaults
EOF
  exit 0
fi

ENV_FILE="${SCYTALEDROID_ENV_FILE:-${ROOT_DIR}/.env}"

if [ -f "$ENV_FILE" ]; then
  # shellcheck disable=SC1090
  set -a
  source "$ENV_FILE"
  set +a
fi

if [ $# -ge 1 ]; then
  export SCYTALEDROID_DB_URL="$1"
  shift
fi

if [ -z "${SCYTALEDROID_DB_URL:-}" ]; then
  COMPOSED="$(
    python3 <<'PY'
import os
import sys
from urllib.parse import quote

PREFIX = "SCYTALEDROID_DB"


def raw(suffix: str) -> str | None:
    return os.environ.get(f"{PREFIX}_{suffix}")


def stripv(suffix: str) -> str:
    return (raw(suffix) or "").strip()


def reject_control(suffixes: tuple[str, ...]) -> None:
    for suf in suffixes:
        val = raw(suf)
        if val and any(c in val for c in ("\n", "\r", "\x00")):
            print(f"{PREFIX}_{suf} contains an invalid control character.", file=sys.stderr)
            sys.exit(1)


name = stripv("NAME")
if not name:
    sys.exit(0)

reject_control(("NAME", "USER", "PASSWD", "HOST"))

user = stripv("USER")
passwd = stripv("PASSWD")
port = stripv("PORT")
if port and not port.isdigit():
    print(f"{PREFIX}_PORT must be numeric.", file=sys.stderr)
    sys.exit(1)
if passwd and not user:
    print(f"{PREFIX}_USER is required when {PREFIX}_PASSWD is set.", file=sys.stderr)
    sys.exit(1)

host = stripv("HOST") or "localhost"
port = port or "3306"
scheme = (stripv("SCHEME") or "mysql").lower()
if scheme not in {"mysql", "mariadb"}:
    scheme = "mysql"

safe_user = quote(user, safe="") if user else ""
safe_passwd = quote(passwd, safe="") if passwd else ""
if passwd:
    auth = f"{safe_user}:{safe_passwd}" if safe_user else f":{safe_passwd}"
elif safe_user:
    auth = safe_user
else:
    auth = ""

if auth:
    print(f"{scheme}://{auth}@{host}:{port}/{name}")
else:
    print(f"{scheme}://{host}:{port}/{name}")
PY
  )"
  if [ -n "${COMPOSED}" ]; then
    export SCYTALEDROID_DB_URL="${COMPOSED}"
  fi
fi

if [ -z "${SCYTALEDROID_DB_URL:-}" ]; then
  echo "SCYTALEDROID_DB_URL not set. Provide it or SCYTALEDROID_DB_NAME (and HOST/USER/etc.) in .env, or pass the URL as the first argument."
  exit 1
fi

exec "${ROOT_DIR}/run.sh" "$@"
