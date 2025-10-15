#!/usr/bin/env bash

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=lib/common.sh
source "$SCRIPT_DIR/common.sh"

ROOT_DIR="$SCYTALE_REPO_ROOT"

ensure_repo_available() {
  if [[ ! -d "$ROOT_DIR/.git" ]]; then
    scytale::warn "No git repository detected at $ROOT_DIR"
    return 1
  fi
  return 0
}

clean_bytecode() {
  scytale::info "Removing Python bytecode and __pycache__ directories..."
  find "$ROOT_DIR" -name '__pycache__' -type d -prune -print -exec rm -rf {} +
  find "$ROOT_DIR" -name '*.py[co]' -print -delete
  find "$ROOT_DIR" -name '*$py.class' -print -delete
}

clean_tooling_artifacts() {
  scytale::info "Removing tooling caches (pytest, coverage, mypy)..."
  rm -rf "$ROOT_DIR/.mypy_cache" "$ROOT_DIR/.pytest_cache" "$ROOT_DIR/htmlcov"
  find "$ROOT_DIR" -name '.coverage*' -print -delete
}

clean_logs_and_output() {
  scytale::info "Clearing logs/, output/, and data/state/..."
  rm -rf "$ROOT_DIR/logs"/* 2>/dev/null || true
  rm -rf "$ROOT_DIR/output"/* 2>/dev/null || true
  rm -rf "$ROOT_DIR/data/state"/* 2>/dev/null || true
}

clean_harvest_artifacts() {
  scytale::info "Removing harvested APKs and watchlists..."
  rm -rf "$ROOT_DIR/data/apks/device_apks"/* 2>/dev/null || true
  rm -rf "$ROOT_DIR/data/watchlists"/* 2>/dev/null || true
}

clean_temp_files() {
  scytale::info "Removing temporary files (*.tmp, *.bak, backup files)..."
  find "$ROOT_DIR" -name '*.tmp' -print -delete
  find "$ROOT_DIR" -name '*.bak' -print -delete
  find "$ROOT_DIR" -name '*~' -print -delete
}

clean_all() {
  scytale::info "Running full maintenance suite..."
  scytale::run_task "Python bytecode cleanup" clean_bytecode
  scytale::run_task "Tooling artifact cleanup" clean_tooling_artifacts
  scytale::run_task "Logs and runtime output cleanup" clean_logs_and_output
  scytale::run_task "Harvested APK cleanup" clean_harvest_artifacts
  scytale::run_task "Temporary file cleanup" clean_temp_files
}

scan_cleanup_targets() {
  scytale::info "Listing cleanup candidates (showing up to 20 results per category)..."
  scytale::subheading "__pycache__ directories"
  find "$ROOT_DIR" -name '__pycache__' -type d | head -n 20 | scytale::prefix_lines "    "

  scytale::subheading "Temporary files (*.tmp, *.bak, *~)"
  find "$ROOT_DIR" \( -name '*.tmp' -o -name '*.bak' -o -name '*~' \) | head -n 20 | scytale::prefix_lines "    "

  scytale::subheading "Coverage and testing artifacts"
  find "$ROOT_DIR" \( -name '.coverage*' -o -name '.pytest_cache' -o -name '.mypy_cache' \) | head -n 20 | scytale::prefix_lines "    "
}

show_project_overview() {
  scytale::info "Project overview for $ROOT_DIR"

  scytale::subheading "Key metrics"
  local total_size
  total_size=$(du -sh "$ROOT_DIR" 2>/dev/null | awk '{print $1}' || true)
  if [[ -n "$total_size" ]]; then
    printf '    %s %sTotal size:%s %s\n' \
      "$(scytale::fmt_color "$SCYTALE_CLR_ACCENT" "$SCYTALE_SYMBOL_BULLET")" \
      "$SCYTALE_FMT_BOLD" \
      "$SCYTALE_FMT_RESET" \
      "$total_size"
  fi

  local python_count shell_count
  python_count=$(find "$ROOT_DIR" -name '*.py' | wc -l)
  shell_count=$(find "$ROOT_DIR" -name '*.sh' | wc -l)
  printf '    %s %sPython files:%s %s\n' \
    "$(scytale::fmt_color "$SCYTALE_CLR_ACCENT" "$SCYTALE_SYMBOL_BULLET")" \
    "$SCYTALE_FMT_BOLD" \
    "$SCYTALE_FMT_RESET" \
    "$python_count"
  printf '    %s %sShell scripts:%s %s\n' \
    "$(scytale::fmt_color "$SCYTALE_CLR_ACCENT" "$SCYTALE_SYMBOL_BULLET")" \
    "$SCYTALE_FMT_BOLD" \
    "$SCYTALE_FMT_RESET" \
    "$shell_count"

  scytale::subheading "Top-level directories"
  find "$ROOT_DIR" -maxdepth 1 -type d ! -path "$ROOT_DIR" | sort | scytale::prefix_lines "    "
}

show_git_status() {
  if ! ensure_repo_available; then
    return
  fi
  scytale::info "Git status summary"
  git -C "$ROOT_DIR" status -sb
}

show_git_diffstat() {
  if ! ensure_repo_available; then
    return
  fi
  scytale::info "Diff statistics for working tree vs. HEAD"
  git -C "$ROOT_DIR" diff --stat
}

show_recent_commits() {
  if ! ensure_repo_available; then
    return
  fi
  scytale::info "Recent commits"
  git -C "$ROOT_DIR" log --oneline --graph -5
}
