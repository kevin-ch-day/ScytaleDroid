#!/usr/bin/env bash
# -----------------------------------------------------------------------------
# install_wireshark_cli.sh  (Fedora)
#
# Supported invocation ONLY:
#   sudo ./install_wireshark_cli.sh
#
# Installs and verifies Wireshark CLI tools:
#   - tshark
#   - capinfos
# Also reports on dumpcap (capture helper) permissions/capabilities.
#
# Exit codes:
#   0  success
#   1  bad usage / args provided
#   2  must run as root (sudo)
#   3  dnf missing / not Fedora-like
#   4  install failed
#   5  required binaries missing after install
# -----------------------------------------------------------------------------

set -euo pipefail

LOG_PREFIX="[WIRESHARK-CLI]"

log()  { echo "$LOG_PREFIX $*"; }
warn() { echo "$LOG_PREFIX WARN: $*"; }
err()  { echo "$LOG_PREFIX ERROR: $*" >&2; }

die() { err "$1"; exit "${2:-1}"; }

# ---- lock invocation: no args allowed ---------------------------------------
if [[ $# -ne 0 ]]; then
  echo "Usage: sudo ./install_wireshark_cli.sh" >&2
  exit 1
fi

# ---- must be root (via sudo) ------------------------------------------------
if [[ "${EUID}" -ne 0 ]]; then
  die "This script must be run with sudo: sudo ./install_wireshark_cli.sh" 2
fi

# ---- ensure dnf exists -------------------------------------------------------
if ! command -v dnf >/dev/null 2>&1; then
  die "dnf not found (this script is intended for Fedora/RHEL-like systems)" 3
fi

# ---- detect Fedora version (non-fatal if unknown) ----------------------------
FEDORA_VER=""
if [[ -r /etc/os-release ]]; then
  # shellcheck disable=SC1091
  . /etc/os-release
  if [[ "${ID:-}" == "fedora" ]]; then
    FEDORA_VER="${VERSION_ID:-}"
  fi
fi

if [[ -n "$FEDORA_VER" ]]; then
  log "Detected Fedora VERSION_ID=$FEDORA_VER"
else
  warn "Could not confirm Fedora from /etc/os-release. Continuing anyway."
fi

have_bin() { command -v "$1" >/dev/null 2>&1; }

# Prefer printing versions as the sudo user to avoid tshark's root warning
NONROOT_USER="${SUDO_USER:-}"

print_versions() {
  log "Versions:"
  if [[ -n "$NONROOT_USER" ]] && id "$NONROOT_USER" >/dev/null 2>&1; then
    runuser -u "$NONROOT_USER" -- tshark --version 2>/dev/null | head -n 1 || true
    runuser -u "$NONROOT_USER" -- capinfos --version 2>/dev/null | head -n 1 || true
  else
    # fallback (may print the root warning, but still OK)
    tshark --version | head -n 1 || true
    capinfos --version | head -n 1 || true
  fi
}

report_dumpcap() {
  if have_bin dumpcap; then
    local DUMP
    DUMP="$(command -v dumpcap)"
    log "dumpcap: $DUMP"

    if command -v getcap >/dev/null 2>&1; then
      local CAPS
      CAPS="$(getcap "$DUMP" 2>/dev/null || true)"
      if [[ -n "$CAPS" ]]; then
        log "dumpcap capabilities: $CAPS"
      else
        warn "dumpcap has no file capabilities (getcap empty)."
        warn "If you need non-root live capture, you may need to adjust permissions/caps per your policy."
      fi
    else
      warn "getcap not available; capability reporting skipped (install libcap tools if needed)"
    fi

    # mode/owner audit line
    ls -l "$DUMP" | sed "s/^/$LOG_PREFIX /"
  else
    warn "dumpcap not found (not fatal for offline PCAP analysis)"
  fi
}

log "Starting Wireshark CLI install/verify (tshark + capinfos)"

log "Installing wireshark-cli (CLI tools only)"
if ! dnf install -y wireshark-cli; then
  die "dnf install failed for wireshark-cli" 4
fi

# Verify required binaries
MISSING=0

if have_bin tshark; then
  log "OK: tshark found at $(command -v tshark)"
else
  err "tshark not found after install"
  MISSING=1
fi

if have_bin capinfos; then
  log "OK: capinfos found at $(command -v capinfos)"
else
  err "capinfos not found after install"
  MISSING=1
fi

if [[ "$MISSING" -ne 0 ]]; then
  die "Required binaries missing after install" 5
fi

print_versions
report_dumpcap

log "Install complete"
exit 0
