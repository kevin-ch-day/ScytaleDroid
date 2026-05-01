#!/usr/bin/env bash
set -euo pipefail

: "${ANDROID_HOME:="$HOME/Android/Sdk"}"
PREFERRED_BT="${PREFERRED_BT:-35.0.0}"
CMDLINE_ZIP_URL="${CMDLINE_ZIP_URL:-https://dl.google.com/android/repository/commandlinetools-linux-13114758_latest.zip}"
JAVA_PKG="${JAVA_PKG:-java-17-openjdk-headless}"

say(){ printf "\033[1;36m[i]\033[0m %s\n" "$*"; }
warn(){ printf "\033[1;33m[!]\033[0m %s\n" "$*"; }
err(){ printf "\033[1;31m[x]\033[0m %s\n" "$*" >&2; }

ANDROID_TOOLS_SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
ANDROID_TOOLS_ROOT="$(cd -- "${ANDROID_TOOLS_SCRIPT_DIR}/.." && pwd -P)"
ENV_CHECK="${ANDROID_TOOLS_ROOT}/env_check.py"

ensure_sdkmanager() {
  local sdkm
  for sdkm in \
    "$ANDROID_HOME/cmdline-tools/latest/bin/sdkmanager" \
    "$ANDROID_HOME/cmdline-tools/bin/sdkmanager" \
    "$ANDROID_HOME/tools/bin/sdkmanager"
  do
    [[ -x "$sdkm" ]] && { echo "$sdkm"; return 0; }
  done
  say "sdkmanager not found — downloading command-line tools…"
  local zip="$ANDROID_HOME/commandlinetools-linux_latest.zip"
  curl -L "$CMDLINE_ZIP_URL" -o "$zip"
  unzip -q "$zip" -d "$ANDROID_HOME"
  mkdir -p "$ANDROID_HOME/cmdline-tools/latest"
  shopt -s dotglob nullglob
  for item in "$ANDROID_HOME/cmdline-tools"/*; do
    [[ "$(basename "$item")" == "latest" ]] && continue
    cp -r "$item" "$ANDROID_HOME/cmdline-tools/latest/" 2>/dev/null || true
  done
  rm -f "$zip"
  local path_bin="$ANDROID_HOME/cmdline-tools/latest/bin"
  [[ -x "$path_bin/sdkmanager" ]] || { err "sdkmanager missing at $path_bin"; return 1; }
  echo "$path_bin/sdkmanager"
}

install_tools() {
  local sdkm="$1"
  export PATH="$(dirname "$sdkm"):$PATH"
  yes | "$sdkm" --licenses >/dev/null || true
  say "Installing platform-tools, build-tools;${PREFERRED_BT}, platforms;android-35…"
  if ! "$sdkm" "platform-tools" "build-tools;${PREFERRED_BT}" "platforms;android-35"; then
    warn "35.x not available — falling back to 34.x"
    "$sdkm" "platform-tools" "build-tools;34.0.0" "platforms;android-34"
  fi
}

persist_path() {
  local bt_ver
  bt_ver="$(ls -1 "$ANDROID_HOME/build-tools" | sort -V | tail -n1)"
  [[ -n "$bt_ver" ]] || { err "No build-tools installed under $ANDROID_HOME/build-tools"; return 1; }
  mkdir -p "$HOME/.bashrc.d"
  cat > "$HOME/.bashrc.d/android.sh" <<EOF
export ANDROID_HOME="\$HOME/Android/Sdk"
export PATH="\$ANDROID_HOME/platform-tools:\$ANDROID_HOME/build-tools/${bt_ver}:\$PATH"
EOF
  export ANDROID_HOME="$ANDROID_HOME"
  export PATH="$ANDROID_HOME/platform-tools:$ANDROID_HOME/build-tools/${bt_ver}:$PATH"
  say "PATH persisted to ~/.bashrc.d/android.sh (build-tools ${bt_ver})"
}

verify_bins() {
  say "Verifying…"
  which sdkmanager && sdkmanager --version || true
  which aapt2 && aapt2 version || warn "aapt2 not found"
  which apksigner && apksigner -version || warn "apksigner not found"
  if [[ -f "$ENV_CHECK" ]]; then
    python3 "$ENV_CHECK" || true
  fi
}

setup_android_tools_main() {
  if command -v dnf >/dev/null 2>&1; then
    sudo dnf install -y unzip curl "${JAVA_PKG}" >/dev/null 2>&1 || true
  fi
  if ! command -v curl >/dev/null 2>&1; then
    err "curl not found; please install curl and re-run."
    exit 1
  fi
  mkdir -p "$ANDROID_HOME"
  SDKM="$(ensure_sdkmanager)"
  install_tools "$SDKM"
  persist_path
  verify_bins
  say "Done. If binaries aren’t visible, run: source ~/.bashrc.d/android.sh"
}

__android_tools_loaded=1
