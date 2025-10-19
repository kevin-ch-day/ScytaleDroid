#!/usr/bin/env bash
# Cleanup helper for ScytaleDroid development on Fedora/Linux
# Removes Python caches, pytest artefacts, and transient static-analysis outputs.

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DATA_DIR="${ROOT_DIR}/data"

usage() {
  cat <<USAGE
Usage: ${0##*/} [--yes]
  --yes    Perform cleanup without interactive confirmation.

The script removes Python bytecode caches, pytest caches, transient log files,
compiled artefacts, and static-analysis output directories. Protected catalog
data is not touched. Run from the repository root.
USAGE
}

CONFIRM=1
if [[ $# -gt 0 ]]; then
  case "$1" in
    --yes)
      CONFIRM=0
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "Unknown option: $1" >&2
      usage
      exit 1
      ;;
  esac
fi

if (( CONFIRM )); then
  read -rp "This will remove build artefacts and cached analysis output. Continue? [y/N] " reply
  if [[ ! $reply =~ ^[Yy]$ ]]; then
    echo "Cleanup cancelled."
    exit 0
  fi
fi

if [[ -d "$DATA_DIR" ]]; then
  echo "Removing contents of data/"
  find "$DATA_DIR" -mindepth 1 -maxdepth 1 -exec rm -rf {} +
else
  echo "Creating data/ directory"
  mkdir -p "$DATA_DIR"
fi

echo "Cleanup complete."
