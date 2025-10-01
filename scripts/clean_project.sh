#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

clean_bytecode() {
  find "$ROOT_DIR" -name '__pycache__' -type d -prune -exec rm -rf {} +
  find "$ROOT_DIR" -name '*.py[co]' -delete
  find "$ROOT_DIR" -name '*$py.class' -delete
}

clean_tooling_artifacts() {
  rm -rf "$ROOT_DIR/.mypy_cache" "$ROOT_DIR/.pytest_cache" "$ROOT_DIR/htmlcov"
  find "$ROOT_DIR" -name '.coverage*' -delete
}

clean_logs_and_output() {
  rm -rf "$ROOT_DIR/logs"/* 2>/dev/null || true
  rm -rf "$ROOT_DIR/output"/* 2>/dev/null || true
  rm -rf "$ROOT_DIR/data/state"/* 2>/dev/null || true
}

clean_harvest_artifacts() {
  rm -rf "$ROOT_DIR/data/apks/device_apks"/* 2>/dev/null || true
  rm -rf "$ROOT_DIR/data/watchlists"/* 2>/dev/null || true
}

clean_temp_files() {
  find "$ROOT_DIR" -name '*.tmp' -delete
  find "$ROOT_DIR" -name '*.bak' -delete
  find "$ROOT_DIR" -name '*~' -delete
}

print_usage() {
  cat <<USAGE
Usage: $(basename "$0") [--bytecode] [--tools] [--logs] [--harvest] [--temp] [--all]
  --bytecode   Remove Python bytecode and __pycache__ directories
  --tools      Remove tooling artifacts (pytest, coverage, mypy caches)
  --logs       Clear logs/, output/, data/state/
  --harvest    Remove harvested APK artifacts and saved watchlists
  --temp       Remove temporary files (*.tmp, *.bak, backup files)
  --all        Run all cleanup routines (default if no flags supplied)
USAGE
}

if [ "$#" -eq 0 ]; then
  clean_bytecode
  clean_tooling_artifacts
  clean_logs_and_output
  clean_harvest_artifacts
  clean_temp_files
else
  run_all=false
  for arg in "$@"; do
    case "$arg" in
      --bytecode) clean_bytecode ;;
      --tools) clean_tooling_artifacts ;;
      --logs) clean_logs_and_output ;;
      --harvest) clean_harvest_artifacts ;;
      --temp) clean_temp_files ;;
      --all)
        clean_bytecode
        clean_tooling_artifacts
        clean_logs_and_output
        clean_harvest_artifacts
        clean_temp_files
        ;;
      --help|-h)
        print_usage
        exit 0
        ;;
      *)
        echo "Unknown option: $arg" >&2
        print_usage
        exit 1
        ;;
    esac
  done
fi

printf 'Project cleanup complete.\n'
