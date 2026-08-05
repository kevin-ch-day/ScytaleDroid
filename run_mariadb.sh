#!/usr/bin/env bash
# Helper to launch ScytaleDroid against MariaDB using SCYTALEDROID_DB_URL from .env.
#
# DB URL-from-parts logic mirrors scytaledroid.Database.db_core.db_config._compose_db_url_from_parts
# (stdlib only here so cold-start does not import the full package tree).
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

if [ "${1:-}" = "-h" ] || [ "${1:-}" = "--help" ]; then
  cat <<EOF
Usage: $(basename "$0") [MYSQL_URL_WITHOUT_PASSWORD] [run.sh arguments...]

Launches repo-root run.sh with a database URL set (remaining arguments pass through to ./run.sh). Resolve order:
  1. First argument MYSQL_URL_WITHOUT_PASSWORD (if given), else
  2. SCYTALEDROID_DB_URL from the environment (e.g. after sourcing .env), else
  3. Composed from SCYTALEDROID_DB_NAME and optional HOST/USER/PASSWD/PORT/SCHEME
     (same rules as Database/db_core/db_config composition).

Environment file: SCYTALEDROID_ENV_FILE (default: ${ROOT_DIR}/.env)

Do not pass a password-bearing DSN on the command line: it can be exposed in
shell history and process listings. Put credentials in a private .env file
(mode 0600) and use split SCYTALEDROID_DB_* variables instead.

Examples:
  ./run_mariadb.sh                                         # compose URL from .env, then ./run.sh
  ./run_mariadb.sh 'mysql://scytaledroid_operator@localhost:3306/db'  # passwordless URL
EOF
  exit 0
fi

ENV_FILE="${SCYTALEDROID_ENV_FILE:-${ROOT_DIR}/.env}"

if [ -f "$ENV_FILE" ]; then
  # Treat .env as data, not executable shell. This matches the application
  # loader and prevents a transferred configuration file from running code.
  while IFS= read -r -d '' key && IFS= read -r -d '' value; do
    if [[ -z "${!key+x}" ]]; then
      export "$key=$value"
    fi
  done < <(
    python3 - "$ENV_FILE" <<'PY'
import re
import sys
from pathlib import Path

path = Path(sys.argv[1])
key_pattern = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")
try:
    lines = path.read_text(encoding="utf-8").splitlines()
except OSError as exc:
    print(f"Unable to read environment file: {exc}", file=sys.stderr)
    raise SystemExit(1)

for line in lines:
    stripped = line.strip()
    if not stripped or stripped.startswith("#") or "=" not in stripped:
        continue
    key, value = stripped.split("=", 1)
    key = key.strip()
    if not key_pattern.fullmatch(key):
        continue
    value = value.strip().strip('"').strip("'")
    sys.stdout.buffer.write(key.encode("utf-8") + b"\0" + value.encode("utf-8") + b"\0")
PY
  )
fi

if [ $# -ge 1 ]; then
  case "$1" in
    mysql://*|mariadb://*)
      if ! python3 - "$1" <<'PY'
from sys import argv
from urllib.parse import urlsplit

parsed = urlsplit(argv[1])
raise SystemExit(0 if parsed.password is None else 1)
PY
      then
        echo "Refusing a password-bearing MariaDB URL argument." >&2
        echo "Store credentials in a private .env file via SCYTALEDROID_DB_PASSWD instead." >&2
        exit 2
      fi
      export SCYTALEDROID_DB_URL="$1"
      shift
      ;;
  esac
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
  echo "SCYTALEDROID_DB_URL not set. Configure SCYTALEDROID_DB_NAME (and HOST/USER/PASSWD/etc.) in .env, or pass a passwordless URL as the first argument."
  exit 1
fi

exec "${ROOT_DIR}/run.sh" "$@"
