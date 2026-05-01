#!/usr/bin/env bash
# Helper to launch ScytaleDroid against MariaDB using SCYTALEDROID_DB_URL from .env or args.
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ENV_FILE="${SCYTALEDROID_ENV_FILE:-${ROOT_DIR}/.env}"

export SCYTALEDROID_RUNTIME_PRESET="${SCYTALEDROID_RUNTIME_PRESET:-physical}"

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
  echo "SCYTALEDROID_DB_URL not set. Provide it in .env or as the first argument."
  exit 1
fi

exec "${ROOT_DIR}/run.sh" "$@"
