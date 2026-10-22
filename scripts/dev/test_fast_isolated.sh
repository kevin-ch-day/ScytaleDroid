#!/usr/bin/env bash
# Extra pytest arguments add selectors/lanes inside the same offline sandbox.
set -euo pipefail
repo_root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd -P)"
command -v bwrap >/dev/null || { echo "error: bwrap is required" >&2; exit 2; }
test_venv="${SCYTALEDROID_TEST_VENV:-$repo_root/.venv}"
if [[ ! -x "$test_venv/bin/python" && -z "${SCYTALEDROID_TEST_VENV:-}" ]]; then
    common_dir="$(git -C "$repo_root" rev-parse --path-format=absolute --git-common-dir)"
    test_venv="$(dirname -- "$common_dir")/.venv"
fi
[[ -x "$test_venv/bin/python" ]] || {
    echo "error: .venv/bin/python missing; install dependencies or set SCYTALEDROID_TEST_VENV" >&2
    exit 2
}
# Root read-only, fresh HOME, no network or local MariaDB socket.
exec env -i PATH=/usr/bin:/bin HOME=/tmp/scytale-home TMPDIR=/tmp \
    PYTHONDONTWRITEBYTECODE=1 PYTHONPATH="$repo_root" \
    SCYTALEDROID_NO_DOTENV=1 SCYTALEDROID_DATA_DIR=/tmp/scytale-test-data \
    SCYTALEDROID_OUTPUT_DIR=/tmp/scytale-test-output SCYTALEDROID_LOGS_DIR=/tmp/scytale-test-logs \
    SCYTALEDROID_ENV=test SCYTALEDROID_API_AUTH_DISABLED=1 SCYTALEDROID_API_HOST=127.0.0.1 \
    RUFF_CACHE_DIR=/tmp/ruff-cache XDG_CACHE_HOME=/tmp/cache \
    bwrap --die-with-parent --unshare-net --ro-bind / / --tmpfs /tmp \
    --tmpfs /run --tmpfs /var/lib/mysql --proc /proc --dev /dev \
    --dir /tmp/scytale-home --chdir "$repo_root" \
    "$test_venv/bin/python" -B -m pytest -p no:cacheprovider \
    -m 'not integration and not db_live' \
    tests/api tests/database/test_web_db_scripts.py \
    tests/dynamic/test_pcap_features_transport.py -q "$@"
