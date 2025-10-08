#!/usr/bin/env bash

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/../.." && pwd)"

ensure_repo_available() {
  if [[ ! -d "$ROOT_DIR/.git" ]]; then
    printf '\n[WARN] No git repository detected at %s.\n' "$ROOT_DIR"
    return 1
  fi
  return 0
}

clean_bytecode() {
  printf '\n[INFO] Removing Python bytecode and __pycache__ directories...\n'
  find "$ROOT_DIR" -name '__pycache__' -type d -prune -print -exec rm -rf {} +
  find "$ROOT_DIR" -name '*.py[co]' -print -delete
  find "$ROOT_DIR" -name '*$py.class' -print -delete
}

clean_tooling_artifacts() {
  printf '\n[INFO] Removing tooling caches (pytest, coverage, mypy)...\n'
  rm -rf "$ROOT_DIR/.mypy_cache" "$ROOT_DIR/.pytest_cache" "$ROOT_DIR/htmlcov"
  find "$ROOT_DIR" -name '.coverage*' -print -delete
}

clean_logs_and_output() {
  printf '\n[INFO] Clearing logs/, output/, and data/state/...\n'
  rm -rf "$ROOT_DIR/logs"/* 2>/dev/null || true
  rm -rf "$ROOT_DIR/output"/* 2>/dev/null || true
  rm -rf "$ROOT_DIR/data/state"/* 2>/dev/null || true
}

clean_harvest_artifacts() {
  printf '\n[INFO] Removing harvested APKs and watchlists...\n'
  rm -rf "$ROOT_DIR/data/apks/device_apks"/* 2>/dev/null || true
  rm -rf "$ROOT_DIR/data/watchlists"/* 2>/dev/null || true
}

clean_temp_files() {
  printf '\n[INFO] Removing temporary files (*.tmp, *.bak, backup files)...\n'
  find "$ROOT_DIR" -name '*.tmp' -print -delete
  find "$ROOT_DIR" -name '*.bak' -print -delete
  find "$ROOT_DIR" -name '*~' -print -delete
}

clean_all() {
  clean_bytecode
  clean_tooling_artifacts
  clean_logs_and_output
  clean_harvest_artifacts
  clean_temp_files
}

scan_cleanup_targets() {
  printf '\n[SCAN] Listing current cleanup candidates (showing up to 20 results per category)...\n'
  printf '\n  • __pycache__ directories:\n'
  find "$ROOT_DIR" -name '__pycache__' -type d | head -n 20

  printf '\n  • Temporary files (*.tmp, *.bak, *~):\n'
  find "$ROOT_DIR" \( -name '*.tmp' -o -name '*.bak' -o -name '*~' \) | head -n 20

  printf '\n  • Coverage and testing artifacts:\n'
  find "$ROOT_DIR" \( -name '.coverage*' -o -name '.pytest_cache' -o -name '.mypy_cache' \) | head -n 20
}

show_project_overview() {
  printf '\n[INFO] Project overview for %s\n' "$ROOT_DIR"
  du -sh "$ROOT_DIR" 2>/dev/null | awk '{printf "  • Total size: %s\n", $1}' || true
  printf '  • Python files: %s\n' "$(find "$ROOT_DIR" -name '*.py' | wc -l)"
  printf '  • Shell scripts: %s\n' "$(find "$ROOT_DIR" -name '*.sh' | wc -l)"
  printf '\nTop-level directories:\n'
  find "$ROOT_DIR" -maxdepth 1 -type d ! -path "$ROOT_DIR" | sort
}

show_git_status() {
  if ! ensure_repo_available; then
    return
  fi
  printf '\n[GIT] Status summary:\n'
  git -C "$ROOT_DIR" status -sb
}

show_git_diffstat() {
  if ! ensure_repo_available; then
    return
  fi
  printf '\n[GIT] Diff statistics for working tree vs. HEAD:\n'
  git -C "$ROOT_DIR" diff --stat
}

show_recent_commits() {
  if ! ensure_repo_available; then
    return
  fi
  printf '\n[GIT] Recent commits:\n'
  git -C "$ROOT_DIR" log --oneline --graph -5
}

print_banner() {
  cat <<'BANNER'
   _____           _        _          ____            _           _   
  / ____|         | |      | |        |  _ \          | |         | |  
 | |     ___ _ __ | |_ __ _| |___   _ | |_) | ___  ___| |__   ___ | |_ 
 | |    / _ \ '_ \| __/ _` | / / | | ||  _ < / _ \/ __| '_ \ / _ \| __|
 | |___|  __/ | | | || (_| | <| |_| || |_) |  __/ (__| | | | (_) | |_ 
  \_____\___|_| |_|\__\__,_|_|\__, ||____/ \___|\___|_| |_|\___/ \__|
                                __/ |                                 
                               |___/                                  
BANNER
}

pause_prompt() {
  read -rp $'\nPress Enter to continue...' _
}
