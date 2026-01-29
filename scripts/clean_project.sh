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
STATIC_ANALYSIS_DIR="${DATA_DIR}/static_analysis"
DYNAMIC_PLAN_DIR="${STATIC_ANALYSIS_DIR}/dynamic_plan"
SESSIONS_DIR="${DATA_DIR}/sessions"
DRY_RUN="${SCYTALE_CLEAN_DRY_RUN:-0}"
QUIET="${SCYTALE_CLEAN_QUIET:-0}"

# The helper is menu driven and intentionally avoids CLI flags beyond this
# invocation guard so operators choose the desired cleanup mode interactively.
shopt -s extglob

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
  "$DATA_DIR/sessions"
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
  local removed=0
  while (($#)); do
    pattern="$1"
    shift
    while IFS= read -r -d '' path; do
      local rel_path="${path#$ROOT_DIR/}"
      if [[ "$DRY_RUN" == "1" ]]; then
        if [[ "$QUIET" != "1" ]]; then
          echo "Would remove ${rel_path:-${path}}"
        fi
      else
        if [[ "$QUIET" != "1" ]]; then
          echo "Removing ${rel_path:-${path}}"
        fi
        rm -rf -- "$path"
      fi
      removed=$((removed + 1))
    done < <(safe_find "$type" "$pattern")
    if [[ "$QUIET" == "1" ]]; then
      if [[ "$DRY_RUN" == "1" ]]; then
        echo "Would remove ${removed} item(s) for pattern ${pattern}"
      else
        echo "Removed ${removed} item(s) for pattern ${pattern}"
      fi
    fi
    removed=0
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
    if [[ "$DRY_RUN" == "1" ]]; then
      echo "Would clear ${label:-.}/ directory (contents only)..."
      return
    fi
    echo "Clearing ${label:-.}/ directory (contents only)..."
    local -a find_args=()
    for pattern in "${preserve_names[@]}"; do
      find_args+=("!" "-name" "$pattern")
    done
    find "$dir" -mindepth 1 -maxdepth 1 "${find_args[@]}" -exec rm -rf -- {} +
  else
    if [[ "$DRY_RUN" == "1" ]]; then
      echo "Would create ${label:-.}/ directory"
    else
      echo "Creating ${label:-.}/ directory"
      mkdir -p "$dir"
    fi
  fi
}

perform_full_cleanup() {
  if [[ "$DRY_RUN" == "1" ]]; then
    echo "Dry run enabled (set SCYTALE_CLEAN_DRY_RUN=0 to apply)."
  fi
  if [[ "$QUIET" == "0" ]]; then
    echo "Tip: set SCYTALE_CLEAN_QUIET=1 to reduce per-item output."
  fi
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

dynamic_plan_stats() {
  if [[ -d "$DYNAMIC_PLAN_DIR" ]]; then
    local count
    local size
    count="$(find "$DYNAMIC_PLAN_DIR" -maxdepth 1 -type f -name "*.json" | wc -l | tr -d ' ')"
    size="$(du -sh "$DYNAMIC_PLAN_DIR" | awk '{print $1}')"
    echo "Dynamic plan files: ${count} | Size: ${size}"
  else
    echo "Dynamic plan directory not present: ${DYNAMIC_PLAN_DIR}"
  fi
}

prune_dynamic_plan_by_age() {
  local days="$1"
  if [[ ! -d "$DYNAMIC_PLAN_DIR" ]]; then
    echo "Dynamic plan directory not present; skipping."
    return 0
  fi

  local removed=0
  while IFS= read -r -d '' path; do
    local rel_path="${path#$ROOT_DIR/}"
    echo "Removing ${rel_path:-${path}}"
    rm -f -- "$path"
    removed=$((removed + 1))
  done < <(find "$DYNAMIC_PLAN_DIR" -maxdepth 1 -type f -name "*.json" -mtime +"$days" -print0)

  echo "Pruned ${removed} dynamic plan file(s) older than ${days} days."
}

prune_dynamic_plan_keep_latest() {
  if [[ ! -d "$DYNAMIC_PLAN_DIR" ]]; then
    echo "Dynamic plan directory not present; skipping."
    return 0
  fi

  declare -A latest_file
  declare -A latest_mtime
  local file
  for file in "$DYNAMIC_PLAN_DIR"/*.json; do
    [[ -e "$file" ]] || continue
    local base
    base="$(basename "$file")"
    local key="$base"
    key="${key%-sr+([0-9])-+([0-9])T+([0-9])Z.json}"
    key="${key%-+([0-9])T+([0-9])Z.json}"
    local mtime
    mtime="$(stat -c %Y "$file")"
    if [[ -z "${latest_mtime[$key]:-}" || "$mtime" -gt "${latest_mtime[$key]}" ]]; then
      latest_mtime["$key"]="$mtime"
      latest_file["$key"]="$file"
    fi
  done

  local removed=0
  for file in "$DYNAMIC_PLAN_DIR"/*.json; do
    [[ -e "$file" ]] || continue
    local base
    base="$(basename "$file")"
    local key="$base"
    key="${key%-sr+([0-9])-+([0-9])T+([0-9])Z.json}"
    key="${key%-+([0-9])T+([0-9])Z.json}"
    if [[ "${latest_file[$key]}" != "$file" ]]; then
      local rel_path="${file#$ROOT_DIR/}"
      echo "Removing ${rel_path:-${file}}"
      rm -f -- "$file"
      removed=$((removed + 1))
    fi
  done

  echo "Pruned ${removed} dynamic plan file(s); kept newest per package/profile."
}

session_dir_stats() {
  if [[ -d "$SESSIONS_DIR" ]]; then
    local count
    local size
    count="$(find "$SESSIONS_DIR" -mindepth 1 -maxdepth 1 -type d | wc -l | tr -d ' ')"
    size="$(du -sh "$SESSIONS_DIR" | awk '{print $1}')"
    echo "Session directories: ${count} | Size: ${size}"
  else
    echo "Sessions directory not present: ${SESSIONS_DIR}"
  fi
}

prune_sessions_by_age() {
  local days="$1"
  if [[ ! -d "$SESSIONS_DIR" ]]; then
    echo "Sessions directory not present; skipping."
    return 0
  fi

  local removed=0
  while IFS= read -r -d '' path; do
    local rel_path="${path#$ROOT_DIR/}"
    echo "Removing ${rel_path:-${path}}"
    rm -rf -- "$path"
    removed=$((removed + 1))
  done < <(find "$SESSIONS_DIR" -mindepth 1 -maxdepth 1 -type d -mtime +"$days" -print0)

  echo "Pruned ${removed} session directory(ies) older than ${days} days."
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
  echo "$message"
  read -rp "Proceed? [y/N] " reply
  [[ $reply =~ ^[Yy]$ ]]
}

repo_stats() {
  local ds sa ap out lg
  ds="0"
  sa="0"
  ap="0"
  out="0"
  lg="0"
  [[ -d "$SESSIONS_DIR" ]] && ds="$(du -sh "$SESSIONS_DIR" | awk '{print $1}')"
  [[ -d "$STATIC_ANALYSIS_DIR" ]] && sa="$(du -sh "$STATIC_ANALYSIS_DIR" | awk '{print $1}')"
  [[ -d "$DATA_DIR/apks" ]] && ap="$(du -sh "$DATA_DIR/apks" | awk '{print $1}')"
  [[ -d "$OUTPUT_DIR" ]] && out="$(du -sh "$OUTPUT_DIR" | awk '{print $1}')"
  [[ -d "$LOG_DIR" ]] && lg="$(du -sh "$LOG_DIR" | awk '{print $1}')"
  echo "Repo stats: sessions=${ds} static=${sa} apks=${ap} output=${out} logs=${lg}"
}

dir_exists() {
  [[ -d "$1" ]]
}

prompt_exit_if_empty() {
  local has_any="no"
  dir_exists "$SESSIONS_DIR" && has_any="yes"
  dir_exists "$STATIC_ANALYSIS_DIR" && has_any="yes"
  dir_exists "$DATA_DIR/apks" && has_any="yes"
  dir_exists "$OUTPUT_DIR" && has_any="yes"
  dir_exists "$LOG_DIR" && has_any="yes"
  if [[ "$has_any" == "no" ]]; then
    if confirm_action "Nothing left to clean. Exit?"; then
      exit 0
    fi
  fi
}

prune_static_analysis_by_age() {
  local days="$1"
  local targets=("$STATIC_ANALYSIS_DIR/baseline" "$STATIC_ANALYSIS_DIR/reports")
  local removed=0
  for dir in "${targets[@]}"; do
    [[ -d "$dir" ]] || continue
    while IFS= read -r -d '' path; do
      local rel_path="${path#$ROOT_DIR/}"
      if [[ "$DRY_RUN" == "1" ]]; then
        echo "Would remove ${rel_path:-${path}}"
      else
        echo "Removing ${rel_path:-${path}}"
        rm -rf -- "$path"
      fi
      removed=$((removed + 1))
    done < <(find "$dir" -maxdepth 1 -type f -name "*.json" -mtime +"$days" -print0)
  done
  echo "Pruned ${removed} static analysis file(s) older than ${days} days."
}

run_menu() {
  while true; do
    repo_stats
    if [[ "$DRY_RUN" == "1" || "$QUIET" == "1" ]]; then
      echo "Modes: dry_run=${DRY_RUN} quiet=${QUIET}"
    fi
    local has_dynamic_plans="no"
    local has_sessions="no"
    local has_static_reports="no"
    dir_exists "$DYNAMIC_PLAN_DIR" && has_dynamic_plans="yes"
    dir_exists "$SESSIONS_DIR" && has_sessions="yes"
    dir_exists "$STATIC_ANALYSIS_DIR" && has_static_reports="yes"
    cat <<MENU
Select cleanup task:
  1) Full cleanup (caches, logs, output, data)
  2) Prune dynamic plan files (${has_dynamic_plans})
  3) Prune session artifacts (${has_sessions})
  4) Prune static analysis (baseline/reports) (${has_static_reports})
  5) Remove tests/ directory
  6) Full cleanup + remove tests/ directory
  7) Exit
MENU
    read -rp "Enter choice [1-7]: " selection
    case "$selection" in
      1)
        if confirm_action "Run full cleanup?"; then
          perform_full_cleanup
          echo "Note: data/ was cleared; prune options will be unavailable until new runs generate artifacts."
          prompt_exit_if_empty
        else
          echo "Skipped full cleanup."
        fi
        ;;
      2)
        if [[ "$has_dynamic_plans" != "yes" ]]; then
          echo "Dynamic plan directory not present; run static analysis to regenerate."
          continue
        fi
        cat <<SUBMENU
Dynamic plan cleanup:
  1) Show current stats
  2) Keep newest per package/profile
  3) Prune files older than N days
  4) Back
SUBMENU
        read -rp "Enter choice [1-4]: " dp_selection
        case "$dp_selection" in
          1)
            dynamic_plan_stats
            ;;
          2)
            if confirm_action "Keep newest per package/profile and delete the rest?"; then
              prune_dynamic_plan_keep_latest
            else
              echo "Skipped dynamic plan prune."
            fi
            ;;
          3)
            read -rp "Prune files older than how many days? " days
            if [[ "$days" =~ ^[0-9]+$ ]]; then
              if confirm_action "Prune dynamic plan files older than ${days} days?"; then
                prune_dynamic_plan_by_age "$days"
              else
                echo "Skipped dynamic plan prune."
              fi
            else
              echo "Invalid day count."
            fi
            ;;
          4)
            echo "Returning to main menu."
            ;;
          *)
            echo "Invalid selection."
            ;;
        esac
        ;;
      3)
        if [[ "$has_sessions" != "yes" ]]; then
          echo "Sessions directory not present; run a scan to regenerate."
          continue
        fi
        cat <<SUBMENU
Session cleanup:
  1) Show current stats
  2) Prune session directories older than N days
  3) Back
SUBMENU
        read -rp "Enter choice [1-3]: " session_selection
        case "$session_selection" in
          1)
            session_dir_stats
            ;;
          2)
            read -rp "Prune sessions older than how many days? " days
            if [[ "$days" =~ ^[0-9]+$ ]]; then
              if confirm_action "Prune session folders older than ${days} days?"; then
                prune_sessions_by_age "$days"
              else
                echo "Skipped session prune."
              fi
            else
              echo "Invalid day count."
            fi
            ;;
          3)
            echo "Returning to main menu."
            ;;
          *)
            echo "Invalid selection."
            ;;
        esac
        ;;
      4)
        if [[ "$has_static_reports" != "yes" ]]; then
          echo "Static analysis directory not present; run a scan to regenerate."
          continue
        fi
        read -rp "Prune static analysis files older than how many days? " days
        if [[ "$days" =~ ^[0-9]+$ ]]; then
          if confirm_action "Prune static analysis files older than ${days} days?"; then
            prune_static_analysis_by_age "$days"
          else
            echo "Skipped static analysis prune."
          fi
        else
          echo "Invalid day count."
        fi
        ;;
      5)
        if confirm_action "Remove the tests/ directory?"; then
          purge_tests_directory
        else
          echo "Skipped tests/ removal."
        fi
        ;;
      6)
        if confirm_action "Run full cleanup and remove tests/?"; then
          perform_full_cleanup
          purge_tests_directory
        else
          echo "Skipped combined cleanup."
        fi
        ;;
      7)
        echo "Exiting without changes."
        break
        ;;
      *)
        echo "Invalid selection. Please choose 1-7." >&2
        ;;
    esac
  done
}

run_menu
