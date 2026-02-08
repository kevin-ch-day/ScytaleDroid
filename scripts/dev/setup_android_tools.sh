#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"

# Keep this as a thin wrapper for compatibility.
# Prefer running ./setup.sh for full project setup.
source "${SCRIPT_DIR}/../lib/android_tools.sh"

setup_android_tools_main "$@"
