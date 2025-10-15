#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LIB_DIR="$SCRIPT_DIR/lib"
# shellcheck source=lib/common.sh
source "$LIB_DIR/common.sh"
# shellcheck source=lib/cleanup_tasks.sh
source "$LIB_DIR/cleanup_tasks.sh"

TASK_ORDER=(
  bytecode
  tooling
  logs
  harvest
  temp
  all
  scan
  overview
  status
  diffstat
  commits
)

declare -A TASK_FUNCS=(
  [bytecode]=clean_bytecode
  [tooling]=clean_tooling_artifacts
  [logs]=clean_logs_and_output
  [harvest]=clean_harvest_artifacts
  [temp]=clean_temp_files
  [all]=clean_all
  [scan]=scan_cleanup_targets
  [overview]=show_project_overview
  [status]=show_git_status
  [diffstat]=show_git_diffstat
  [commits]=show_recent_commits
)

declare -A TASK_TITLES=(
  [bytecode]="Python bytecode cleanup"
  [tooling]="Tooling artifact cleanup"
  [logs]="Logs and runtime output cleanup"
  [harvest]="Harvested APK cleanup"
  [temp]="Temporary file cleanup"
  [all]="Full project cleanup"
  [scan]="Scan for cleanup candidates"
  [overview]="Project overview"
  [status]="Git status summary"
  [diffstat]="Git diff statistics"
  [commits]="Recent commits overview"
)

declare -A TASK_DESCRIPTIONS=(
  [bytecode]="Remove Python bytecode and __pycache__ directories"
  [tooling]="Clear pytest, coverage, and mypy artifacts"
  [logs]="Empty logs/, output/, and data/state/ directories"
  [harvest]="Remove harvested APK and watchlist artifacts"
  [temp]="Delete temporary and backup files"
  [all]="Run every cleanup task"
  [scan]="List cleanup candidates without deleting"
  [overview]="Display project size and file counts"
  [status]="Show concise git status"
  [diffstat]="Display git diff statistics"
  [commits]="Show the latest git commits"
)

print_usage() {
  cat <<'USAGE'
Usage: ./clean_project.sh [task ...]

Run one or more cleanup tasks. If no task is provided the full cleanup
routine is executed. Use --list to show all tasks.

Available tasks:
USAGE
  scytale::render_task_table TASK_ORDER TASK_DESCRIPTIONS
  printf '\n'
}

list_tasks() {
  scytale::headline "ScytaleDroid maintenance tasks"
  scytale::note "Use ./clean_project.sh <task> ... to run specific entries"
  scytale::render_task_table TASK_ORDER TASK_DESCRIPTIONS
}

map_task_to_key() {
  local key="$1"
  if [[ -n "${TASK_FUNCS[$key]:-}" ]]; then
    echo "$key"
    return 0
  fi
  return 1
}

TASK_KEYS=()
while [[ $# -gt 0 ]]; do
  case "$1" in
    -h|--help)
      print_usage
      exit 0
      ;;
    --list)
      list_tasks
      exit 0
      ;;
    --)
      shift
      break
      ;;
    -*)
      printf 'Unknown option: %s\n\n' "$1" >&2
      print_usage >&2
      exit 1
      ;;
    *)
      if key=$(map_task_to_key "$1"); then
        TASK_KEYS+=("$key")
      else
        printf 'Unknown task: %s\n\n' "$1" >&2
        print_usage >&2
        exit 1
      fi
      ;;
  esac
  shift

done

if [[ ${#TASK_KEYS[@]} -eq 0 ]]; then
  TASK_KEYS=(all)
fi

scytale::headline "ScytaleDroid maintenance toolkit"

COMPLETED_TASKS=()
for key in "${TASK_KEYS[@]}"; do
  func="${TASK_FUNCS[$key]}"
  label="${TASK_TITLES[$key]}"
  scytale::run_task "$label" "$func"
  COMPLETED_TASKS+=("$label")

done

if [[ ${#COMPLETED_TASKS[@]} -gt 0 ]]; then
  scytale::section "Summary"
  scytale::list_with_icon COMPLETED_TASKS "$SCYTALE_SYMBOL_SUCCESS" "$SCYTALE_CLR_SUCCESS"
fi
