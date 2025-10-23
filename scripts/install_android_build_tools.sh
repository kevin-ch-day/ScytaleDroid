#!/usr/bin/env bash
set -euo pipefail

# --- configurable bits ---
SDK_VER="${SDK_VER:-35.0.0}"            # build-tools version you want installed
JAVA_PKG="${JAVA_PKG:-java-17-openjdk-headless}"
ANDROID_HOME="${ANDROID_HOME:-$HOME/Android/Sdk}"
TOOLS_ZIP="${1:-}" # optionally pass /path/to/commandlinetools-linux.zip

echo "[i] Preparing prerequisites..."
sudo dnf install -y "${JAVA_PKG}" unzip > /dev/null

mkdir -p "${ANDROID_HOME}/cmdline-tools" "${ANDROID_HOME}/build-tools" "${ANDROID_HOME}/platform-tools"

if [[ -n "${TOOLS_ZIP}" ]]; then
  echo "[i] Using supplied commandlinetools zip: ${TOOLS_ZIP}"
  WORKDIR="$(mktemp -d)"
  unzip -q "${TOOLS_ZIP}" -d "${WORKDIR}"
  # Place under cmdline-tools/latest as expected by sdkmanager
  mkdir -p "${ANDROID_HOME}/cmdline-tools/latest"
  cp -r "${WORKDIR}"/cmdline-tools/* "${ANDROID_HOME}/cmdline-tools/latest"/
  rm -rf "${WORKDIR}"
else
  echo "[!] Please download Google's 'commandlinetools-linux' zip from the Android developer site"
  echo "    and re-run: $0 /path/to/commandlinetools-linux.zip"
  exit 2
fi

export PATH="${ANDROID_HOME}/cmdline-tools/latest/bin:${PATH}"

echo "[i] Accepting licenses (may prompt)..."
yes | sdkmanager --licenses > /dev/null || true

echo "[i] Installing platform-tools, build-tools;${SDK_VER}, platforms;android-35 ..."
sdkmanager "platform-tools" "build-tools;${SDK_VER}" "platforms;android-35"

# Persist PATH for future shells
PROFILE_DIR="$HOME/.bashrc.d"
mkdir -p "$PROFILE_DIR"
cat > "$PROFILE_DIR/android.sh" <<EOF
export ANDROID_HOME="${ANDROID_HOME}"
export PATH="\$ANDROID_HOME/platform-tools:\$ANDROID_HOME/build-tools/${SDK_VER}:\$PATH"
EOF

echo "[i] Load PATH now: source $PROFILE_DIR/android.sh"
echo "[i] Verify:"
echo "     which aapt2 && aapt2 version"
echo "     which apksigner && apksigner -version"
