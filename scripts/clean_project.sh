#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=lib/cleanup_tasks.sh
source "$SCRIPT_DIR/lib/cleanup_tasks.sh"

if [[ $# -gt 0 ]]; then
  printf 'This script does not accept command-line arguments. Please run as ./clean_project.sh\n' >&2
  exit 1
fi

show_menu() {
  if command -v clear >/dev/null 2>&1; then
    clear
  fi
  print_banner
  cat <<'MENU'
Project maintenance menu:

  1) Clean Python bytecode (__pycache__, *.pyc)
  2) Clean tooling artifacts (pytest, coverage, mypy)
  3) Clear logs and runtime output directories
  4) Remove harvested APK and watchlist artifacts
  5) Remove temporary and backup files
  6) Run full cleanup (all of the above)
  7) Scan project for cleanup candidates
  8) Show project overview (size and layout)
  9) Git status summary
 10) Git diff statistics
 11) Show recent commits
 12) Exit
MENU
}

handle_choice() {
  case "$1" in
    1) clean_bytecode ;;
    2) clean_tooling_artifacts ;;
    3) clean_logs_and_output ;;
    4) clean_harvest_artifacts ;;
    5) clean_temp_files ;;
    6) clean_all ;;
    7) scan_cleanup_targets ;;
    8) show_project_overview ;;
    9) show_git_status ;;
    10) show_git_diffstat ;;
    11) show_recent_commits ;;
    12) printf '\nExiting project maintenance utility.\n'; exit 0 ;;
    *) printf '\n[ERROR] Invalid selection. Please choose a valid option.\n' ;;
  esac
}

while true; do
  show_menu
  read -rp $'\nEnter your choice [1-12]: ' choice
  handle_choice "$choice"
  pause_prompt
done
