# ADB Contract (DeviceAnalysis)

This document defines the required, uniform behavior for all ADB usage in ScytaleDroid.
It is the single source of truth for serial selection, timeouts, error handling, and cache policy.

## 1) Serial selection (determinism)

**Execution paths (state-changing) must be deterministic.**

- DynamicAnalysis, inventory snapshot writes, harvest/APK pull, install/uninstall, and any DB write
  **must have an explicit serial** when multiple devices are attached.
- If multiple devices are attached and no serial is provided, execution **fails fast**.
- Menu/UI flows may prompt the user, but must end with an explicit serial choice.
- Non-interactive/headless runs must fail fast when serial is ambiguous.

## 2) Timeouts and retry policy

Default timeouts (seconds):

- Normal adb shell: **30s**
- Long operations (pull, heavy dumpsys, logcat collection): **120s**
- Device discovery: **10s**

Retry policy:

- **Default: none**.
- Retries are only allowed for explicitly classified transient failures (e.g., timeout, device-not-found),
  and must be opt-in at the call site.

## 3) Error taxonomy (normalized)

All ADB failures must map to the following error types:

- `AdbBinaryNotFoundError` – adb missing on PATH
- `AdbTimeoutError` – command exceeded timeout
- `AdbCommandError` – non-zero exit code
- `AdbDeviceSelectionError` – ambiguous device selection
- `AdbDeviceNotFoundError` – requested serial not present

These errors are raised by the ADB layer and consumed by higher-level modules.

## 4) Logging guarantees

Every ADB command must log (debug level or higher):

- serial
- command
- elapsed time
- exit code

Warnings must be emitted for any fallback behavior.

## 5) Binary resolution

- adb must be resolved from PATH by default.
- If adb is missing, setup must fail with a clear instruction.

## 6) Cache policy

Allowed caches (Phase 1):

- Package paths (keyed by serial + package)
- Device capability cache (per-serial)

Cache invalidation must occur on:

- device disconnect/reconnect
- device reboot / adb restart
- package version change / reinstall

**No-cache mode** must be available for troubleshooting.

## 7) Deprecations

`adb_utils.py` is deprecated and will be removed by **MILESTONE-DYNAMIC-C**.
All new code must use `adb_shell`, `adb_devices`, `adb_packages`, and `adb_status` directly.
