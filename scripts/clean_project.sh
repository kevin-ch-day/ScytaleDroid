#!/usr/bin/env bash
# clean_project.sh - Remove Python cache files and directories from ScytaleDroid

set -euo pipefail

PROJECT_ROOT="$(dirname "$(readlink -f "$0")")/.."

echo "[*] Cleaning Python cache files under: $PROJECT_ROOT"

# Remove all __pycache__ directories
find "$PROJECT_ROOT" -type d -name "__pycache__" -exec rm -rf {} +

# Remove all .pyc files (if any are left hanging)
find "$PROJECT_ROOT" -type f -name "*.pyc" -delete

echo "[✓] Project cleaned."
