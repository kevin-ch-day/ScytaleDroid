#!/usr/bin/env bash
# Common helpers shared by maintenance scripts.

# Resolve important paths once so that downstream scripts can reuse them.
_sc_common_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
: "${SCYTALE_SCRIPT_ROOT:="$(cd "$_sc_common_dir/.." && pwd)"}"
: "${SCYTALE_REPO_ROOT:="$(cd "${SCYTALE_SCRIPT_ROOT}/.." && pwd)"}"
unset _sc_common_dir

# --- Terminal formatting ----------------------------------------------------
_scytale_supports_color() {
  [[ -t 1 ]] || return 1
  command -v tput >/dev/null 2>&1 || return 1
  local colors
  colors=$(tput colors 2>/dev/null || echo 0)
  [[ "$colors" -ge 8 ]]
}

if _scytale_supports_color; then
  SCYTALE_FMT_RESET="$(tput sgr0)"
  SCYTALE_FMT_BOLD="$(tput bold)"
  SCYTALE_FMT_DIM="$(tput dim)"
  SCYTALE_FMT_UNDERLINE="$(tput smul)"
  SCYTALE_CLR_INFO="$(tput setaf 6)"
  SCYTALE_CLR_WARN="$(tput setaf 3)"
  SCYTALE_CLR_ERROR="$(tput setaf 1)"
  SCYTALE_CLR_SUCCESS="$(tput setaf 2)"
  SCYTALE_CLR_SECTION="$(tput setaf 5)"
  SCYTALE_CLR_ACCENT="$(tput setaf 4)"
  SCYTALE_CLR_MUTED="$(tput setaf 7)"
else
  SCYTALE_FMT_RESET=""
  SCYTALE_FMT_BOLD=""
  SCYTALE_FMT_DIM=""
  SCYTALE_FMT_UNDERLINE=""
  SCYTALE_CLR_INFO=""
  SCYTALE_CLR_WARN=""
  SCYTALE_CLR_ERROR=""
  SCYTALE_CLR_SUCCESS=""
  SCYTALE_CLR_SECTION=""
  SCYTALE_CLR_ACCENT=""
  SCYTALE_CLR_MUTED=""
fi
unset -f _scytale_supports_color

SCYTALE_SYMBOL_INFO="ℹ"
SCYTALE_SYMBOL_WARN="⚠"
SCYTALE_SYMBOL_ERROR="✖"
SCYTALE_SYMBOL_SUCCESS="✔"
SCYTALE_SYMBOL_SECTION="➤"
SCYTALE_SYMBOL_BULLET="•"

_scytale_colorize() {
  local color="$1"
  shift || true
  if [[ -z "$color" || -z "$*" ]]; then
    printf '%s' "$*"
  else
    printf '%s%s%s' "$color" "$*" "$SCYTALE_FMT_RESET"
  fi
}

scytale::fmt_color() {
  local color="$1"
  shift || true
  _scytale_colorize "$color" "$*"
}

scytale::fmt_bold() {
  printf '%s%s%s' "$SCYTALE_FMT_BOLD" "$*" "$SCYTALE_FMT_RESET"
}

scytale::fmt_dim() {
  printf '%s%s%s' "$SCYTALE_FMT_DIM" "$*" "$SCYTALE_FMT_RESET"
}

scytale::fmt_underline() {
  printf '%s%s%s' "$SCYTALE_FMT_UNDERLINE" "$*" "$SCYTALE_FMT_RESET"
}

scytale::term_width() {
  local fallback="${1:-80}"
  local width="${COLUMNS:-0}"
  if [[ -z "$width" || "$width" -le 0 ]]; then
    width=$(tput cols 2>/dev/null || printf '%s' "$fallback")
  fi
  if [[ "$width" -lt 40 ]]; then
    width=40
  elif [[ "$width" -gt 100 ]]; then
    width=100
  fi
  printf '%s' "$width"
}

scytale::hr() {
  local char="${1:-─}"
  local color="${2:-$SCYTALE_CLR_SECTION}"
  local width="${3:-$(scytale::term_width 60)}"
  local indent="${4:-2}"
  local padding=""
  if (( indent > 0 )); then
    printf -v padding '%*s' "$indent" ''
  fi
  local line
  printf -v line '%*s' "$width" ''
  line="${line// /$char}"
  printf '%s%s%s%s\n' "$padding" "$color" "$line" "$SCYTALE_FMT_RESET"
}

scytale::headline() {
  local title="$1"
  local width=$(scytale::term_width 60)
  scytale::hr '═' "$SCYTALE_CLR_SECTION" "$width" 0
  printf '%s %s%s%s\n' \
    "$(scytale::fmt_color "$SCYTALE_CLR_SECTION" "$SCYTALE_SYMBOL_SECTION")" \
    "$SCYTALE_FMT_BOLD" \
    "$title" \
    "$SCYTALE_FMT_RESET"
  scytale::hr '═' "$SCYTALE_CLR_SECTION" "$width" 0
}

scytale::log() {
  local level="$1"
  shift
  local color=""
  local icon=""
  case "$level" in
    INFO) color="$SCYTALE_CLR_INFO" ;;
    WARN) color="$SCYTALE_CLR_WARN" ;;
    ERROR) color="$SCYTALE_CLR_ERROR" ;;
    SUCCESS) color="$SCYTALE_CLR_SUCCESS" ;;
    NOTE) color="$SCYTALE_CLR_MUTED" ;;
  esac
  case "$level" in
    INFO) icon="$SCYTALE_SYMBOL_INFO" ;;
    WARN) icon="$SCYTALE_SYMBOL_WARN" ;;
    ERROR) icon="$SCYTALE_SYMBOL_ERROR" ;;
    SUCCESS) icon="$SCYTALE_SYMBOL_SUCCESS" ;;
    NOTE) icon="$SCYTALE_SYMBOL_INFO" ;;
    *) icon="$SCYTALE_SYMBOL_INFO" ;;
  esac
  local prefix
  case "$level" in
    WARN|ERROR|SUCCESS|NOTE)
      prefix="[$icon]"
      ;;
    *)
      prefix="[$level]"
      ;;
  esac
  if [[ -n "$color" ]]; then
    prefix="${SCYTALE_FMT_BOLD}$(_scytale_colorize "$color" "$prefix")"
  else
    prefix="${SCYTALE_FMT_BOLD}${prefix}${SCYTALE_FMT_RESET}"
  fi
  printf '%s %s%s\n' "$prefix" "$*" "$SCYTALE_FMT_RESET"
}

scytale::info() { scytale::log INFO "$@"; }
scytale::warn() { scytale::log WARN "$@" >&2; }
scytale::error() { scytale::log ERROR "$@" >&2; }
scytale::success() { scytale::log SUCCESS "$@"; }
scytale::note() { scytale::log NOTE "$@"; }

scytale::section() {
  local title="$1"
  printf '\n%s %s%s%s\n' \
    "$(scytale::fmt_color "$SCYTALE_CLR_SECTION" "$SCYTALE_SYMBOL_SECTION")" \
    "$SCYTALE_FMT_BOLD" \
    "$title" \
    "$SCYTALE_FMT_RESET"
  scytale::hr '─' "$SCYTALE_CLR_MUTED" "$(scytale::term_width 50)" 2
}

scytale::render_task_table() {
  local -n order_ref="$1"
  local -n desc_ref="$2"
  local width=0
  local task
  for task in "${order_ref[@]}"; do
    ((${#task} > width)) && width=${#task}
  done
  for task in "${order_ref[@]}"; do
    local padded
    printf -v padded '%-'"${width}"'s' "$task"
    printf '  %s %s%s%s  %s\n' \
      "$(scytale::fmt_color "$SCYTALE_CLR_ACCENT" "$SCYTALE_SYMBOL_SECTION")" \
      "${SCYTALE_CLR_ACCENT}${SCYTALE_FMT_BOLD}" \
      "$padded" \
      "$SCYTALE_FMT_RESET" \
      "$(scytale::fmt_dim "${desc_ref[$task]}")"
  done
}

scytale::run_task() {
  local label="$1"
  local func="$2"
  scytale::section "$label"
  if "$func"; then
    scytale::success "Completed: $label"
  else
    scytale::error "Task failed: $label"
    return 1
  fi
}

scytale::confirm() {
  local prompt="${1:-Proceed?}" response
  read -rp "$prompt [y/N] " response
  [[ "$response" =~ ^[Yy]([Ee][Ss])?$ ]]
}

scytale::ensure_directory() {
  local path="$1"
  if [[ ! -d "$path" ]]; then
    scytale::warn "Directory not found: $path"
    return 1
  fi
  return 0
}

scytale::subheading() {
  local title="$1"
  printf '\n  %s %s%s%s\n' \
    "$(scytale::fmt_color "$SCYTALE_CLR_ACCENT" "$SCYTALE_SYMBOL_SECTION")" \
    "$SCYTALE_FMT_BOLD" \
    "$title" \
    "$SCYTALE_FMT_RESET"
}

scytale::list_with_icon() {
  local -n items_ref="$1"
  local icon="${2:-$SCYTALE_SYMBOL_BULLET}"
  local color="${3:-$SCYTALE_CLR_INFO}"
  local item
  for item in "${items_ref[@]}"; do
    printf '  %s %s%s%s\n' \
      "$(scytale::fmt_color "$color" "$icon")" \
      "$SCYTALE_FMT_BOLD" \
      "$item" \
      "$SCYTALE_FMT_RESET"
  done
}

scytale::prefix_lines() {
  local prefix="${1:-    }"
  while IFS= read -r line || [[ -n "$line" ]]; do
    printf '%s%s\n' "$prefix" "$line"
  done
}
