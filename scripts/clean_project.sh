#!/usr/bin/env bash
# Comprehensive cleanup helper for ScytaleDroid development on Linux/macOS.
# This is the canonical cleanup entry point for the repository. It removes
# Python caches, pytest artefacts, build products, IDE workspace cruft,
# generated catalog caches, transient static-analysis outputs, and offers an
# option to purge local test suites. A menu-driven interface ensures the tool is
# run intentionally as clean_project.sh.

set -euo pipefail

SCRIPT_BASENAME="${0##*/}"
if [[ "$SCRIPT_BASENAME" != "clean_project.sh" ]]; then
  echo "This utility must be invoked as clean_project.sh" >&2
  exit 1
fi

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DATA_DIR="${ROOT_DIR}/data"
LOG_DIR="${ROOT_DIR}/logs"
OUTPUT_DIR="${ROOT_DIR}/output"
TESTS_DIR="${ROOT_DIR}/tests"

# The helper is menu driven and intentionally avoids CLI flags beyond this
# invocation guard so operators choose the desired cleanup mode interactively.

PRUNE_DIRS=(
  "$ROOT_DIR/.git"
  "$ROOT_DIR/.hg"
  "$ROOT_DIR/.svn"
  "$ROOT_DIR/.venv"
  "$ROOT_DIR/venv"
  "$ROOT_DIR/.env"
)

CLEAN_DIR_PATTERNS=(
  "__pycache__"
  ".pytest_cache"
  "pytest_cache"
  ".mypy_cache"
  ".ruff_cache"
  ".hypothesis"
  ".nox"
  ".tox"
  ".benchmarks"
  "htmlcov"
  "build"
  "dist"
  "*.egg-info"
  "pip-wheel-metadata"
  ".idea"
  ".vscode"
  "env"
)

# Keep Python bytecode caches explicit to address __pycache__/ and *.pyc cleanups.
CLEAN_FILE_PATTERNS=(
  "*.pyc"
  "*.pyo"
  "*.pyd"
  "*.py[cod]"
  ".coverage"
  ".coverage.*"
  "coverage.xml"
  "pytestdebug.log"
  ".DS_Store"
  "Thumbs.db"
  "*.log"
  "*.tmp"
  "*.bak"
)

PURGE_DIRS_ENSURE=(
  "$DATA_DIR"
  "$LOG_DIR"
  "$OUTPUT_DIR"
  "$OUTPUT_DIR/reports"
  "$OUTPUT_DIR/sql"
  "$ROOT_DIR/scytaledroid/Utils/AndroidPermCatalog/cache"
)

PURGE_DIRS_OPTIONAL=(
  "$DATA_DIR/state"
  "$DATA_DIR/watchlists"
  "$DATA_DIR/apks"
  "$DATA_DIR/static_analysis"
  "$DATA_DIR/static_analysis/reports"
  "$DATA_DIR/static_analysis/baseline"
  "$DATA_DIR/audit"
  "$ROOT_DIR/scripts/db"
)

safe_find() {
  local type="$1"
  local pattern="$2"
  local find_args=()

  if (( ${#PRUNE_DIRS[@]} )); then
    find_args+=("(")
    for i in "${!PRUNE_DIRS[@]}"; do
      if (( i > 0 )); then
        find_args+=("-o")
      fi
      find_args+=("-path" "${PRUNE_DIRS[i]}")
    done
    find_args+=(")" "-prune" "-o")
  fi

  find "$ROOT_DIR" "${find_args[@]}" -type "$type" -name "$pattern" -print0
}

remove_matches() {
  local type="$1"
  shift
  local pattern
  while (($#)); do
    pattern="$1"
    shift
    while IFS= read -r -d '' path; do
      local rel_path="${path#$ROOT_DIR/}"
      echo "Removing ${rel_path:-${path}}"
      rm -rf -- "$path"
    done < <(safe_find "$type" "$pattern")
  done
}

clear_directory_contents() {
  local dir="$1"
  shift
  local label="${dir#$ROOT_DIR/}"
  local -a preserve_names=(".gitignore" ".gitkeep")

  if (( $# )); then
    preserve_names+=("$@")
  fi

  if [[ -d "$dir" ]]; then
    echo "Clearing ${label:-.}/ directory (contents only)..."
    local -a find_args=()
    for pattern in "${preserve_names[@]}"; do
      find_args+=("!" "-name" "$pattern")
    done
    find "$dir" -mindepth 1 -maxdepth 1 "${find_args[@]}" -exec rm -rf -- {} +
  else
    echo "Creating ${label:-.}/ directory"
    mkdir -p "$dir"
  fi
}

perform_full_cleanup() {
  if (( ${#CLEAN_DIR_PATTERNS[@]} )); then
    echo "Removing cached and build directories..."
    remove_matches d "${CLEAN_DIR_PATTERNS[@]}"
  fi

  if (( ${#CLEAN_FILE_PATTERNS[@]} )); then
    echo "Removing cached files and logs..."
    remove_matches f "${CLEAN_FILE_PATTERNS[@]}"
  fi

  for target in "${PURGE_DIRS_ENSURE[@]}"; do
    clear_directory_contents "$target"
  done

  for target in "${PURGE_DIRS_OPTIONAL[@]}"; do
    case "$target" in
      "$ROOT_DIR/scripts/db")
        if [[ -d "$target" ]]; then
          clear_directory_contents "$target" "*.sql"
        else
          echo "scripts/db directory not present; skipping."
        fi
        ;;
      *)
        if [[ -d "$target" ]]; then
          clear_directory_contents "$target"
        fi
        ;;
    esac
  done

  echo "Full cleanup complete."
}

purge_tests_directory() {
  if [[ -d "$TESTS_DIR" ]]; then
    echo "Removing tests/ directory..."
    rm -rf -- "$TESTS_DIR"
    echo "tests/ directory removed."
  else
    echo "tests/ directory already absent."
  fi
}

confirm_action() {
  local message="$1"
  read -rp "$message [y/N] " reply
  [[ $reply =~ ^[Yy]$ ]]
}

run_menu() {
  while true; do
    cat <<MENU
Select cleanup task:
  1) Full cleanup (caches, logs, output, data)
  2) Remove tests/ directory
  3) Full cleanup + remove tests/ directory
  4) Exit
MENU
    read -rp "Enter choice [1-4]: " selection
    case "$selection" in
      1)
        if confirm_action "Run full cleanup?"; then
          perform_full_cleanup
        else
          echo "Skipped full cleanup."
        fi
        ;;
      2)
        if confirm_action "Remove the tests/ directory?"; then
          purge_tests_directory
        else
          echo "Skipped tests/ removal."
        fi
        ;;
      3)
        if confirm_action "Run full cleanup and remove tests/?"; then
          perform_full_cleanup
          purge_tests_directory
        else
          echo "Skipped combined cleanup."
        fi
        ;;
      4)
        echo "Exiting without changes."
        break
        ;;
      *)
        echo "Invalid selection. Please choose 1-4." >&2
        ;;
    esac
  done
}

run_menu

