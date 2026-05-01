
# Re-export version metadata for callers that treat app_config as the canonical
# config surface.
from scytaledroid.Config import version as _version  # noqa: E402

APP_NAME = _version.APP_NAME
APP_VERSION = _version.APP_VERSION
APP_RELEASE = _version.APP_RELEASE
APP_DESCRIPTION = _version.APP_DESCRIPTION
APP_AUTHOR = _version.APP_AUTHOR
GITHUB_REPO = _version.GITHUB_REPO

# Paths
DATA_DIR   = "data"
OUTPUT_DIR = "output"
LOGS_DIR   = "logs"
STATIC_ANALYSIS_RETENTION_DAYS = 30
DYNAMIC_MIN_DURATION_S = 120
DYNAMIC_TARGET_DURATION_S = 180

# Dynamic dataset QA
# Default can be overridden at process start via SCYTALEDROID_MIN_PCAP_BYTES.
# Env is read at import time (entrypoint default) and must not be read mid-run.
import os  # noqa: E402
from scytaledroid.Utils.System.runtime_mode import resolve_runtime_mode  # noqa: E402

STATIC_HTML_MODE = str(os.getenv("SCYTALEDROID_STATIC_HTML_MODE", "latest")).strip().lower()
if STATIC_HTML_MODE not in {"latest", "archive", "both"}:
    STATIC_HTML_MODE = "latest"
STATIC_REPORT_JSON_MODE = str(
    os.getenv("SCYTALEDROID_STATIC_REPORT_JSON_MODE", "both")
).strip().lower()
if STATIC_REPORT_JSON_MODE not in {"latest", "archive", "both"}:
    STATIC_REPORT_JSON_MODE = "both"

RUNTIME_MODE = resolve_runtime_mode()
RUNTIME_PRESET = RUNTIME_MODE.preset
DEBUG_MODE = RUNTIME_MODE.debug_mode
SYS_TEST = RUNTIME_MODE.sys_test
EXECUTION_MODE = RUNTIME_MODE.execution_mode
SYS_ENV = RUNTIME_MODE.sys_env
SHOW_RUNTIME_IDENTITY = RUNTIME_MODE.show_runtime_identity

try:
    DYNAMIC_MIN_PCAP_BYTES = int(os.getenv("SCYTALEDROID_MIN_PCAP_BYTES", "100000"))
except Exception:
    DYNAMIC_MIN_PCAP_BYTES = 100000

# Dataset protocol (locked)
# Quotas are a methods-level contract and must not be overridden via environment variables
# in dataset-tier collection paths (prevents accidental scope creep).
DYNAMIC_DATASET_BASELINE_RUNS = 1
DYNAMIC_DATASET_INTERACTIVE_RUNS = 2
# Recommended baseline replicates for exploratory robustness (does not change
# paper cohort quota/freeze contract unless baseline quota is explicitly changed).
DYNAMIC_DATASET_BASELINE_RECOMMENDED_RUNS = 3

# Total quota slots (locked): baseline + interactive.
DYNAMIC_DATASET_RUNS_PER_APP = int(DYNAMIC_DATASET_BASELINE_RUNS) + int(DYNAMIC_DATASET_INTERACTIVE_RUNS)

# Device module paths
DEVICE_STATE_DIR = "state"
DEVICE_STATE_FILE = "active_device.json"

# UI preferences
DEFAULT_UI_TIMEZONES = {
    "Minneapolis, USA": "America/Chicago",
    "Las Vegas, USA": "America/Los_Angeles",
    "Dubai, UAE": "Asia/Dubai",
    "Paris, France": "Europe/Paris",
    "London, United Kingdom": "Etc/UTC",
}
UI_MAX_CLOCKS = 3
UI_TIMEZONES = {
    label: tz
    for label, tz in list(DEFAULT_UI_TIMEZONES.items())[:UI_MAX_CLOCKS]
}
UI_PRIMARY_CLOCK = "Minneapolis, USA"
UI_LOCAL_TIME_LABEL = UI_PRIMARY_CLOCK
UI_LOCAL_TIMEZONE = UI_TIMEZONES.get(UI_LOCAL_TIME_LABEL, "Etc/UTC")
UI_CLOCK_REFERENCE_MODE = "now"
UI_CLOCK_REFERENCE_LABEL = "Live (current time)"
UI_CLOCK_REFERENCE_TIMEZONE = UI_LOCAL_TIMEZONE
UI_CLOCK_REFERENCE_UTC = None

# Logging behaviour
ENABLE_CONSOLE_LOGS = False

# Static persistence reliability tuning (transaction-level retries/locks).
try:
    STATIC_PERSIST_TRANSIENT_RETRIES = int(os.getenv("SCYTALEDROID_STATIC_PERSIST_TRANSIENT_RETRIES", "4"))
except Exception:
    STATIC_PERSIST_TRANSIENT_RETRIES = 4
try:
    STATIC_PERSIST_LOCK_WAIT_RETRIES = int(os.getenv("SCYTALEDROID_STATIC_PERSIST_LOCK_WAIT_RETRIES", "2"))
except Exception:
    STATIC_PERSIST_LOCK_WAIT_RETRIES = 2
try:
    STATIC_PERSIST_LOCK_WAIT_TIMEOUT_S = int(os.getenv("SCYTALEDROID_STATIC_PERSIST_LOCK_WAIT_TIMEOUT_S", "15"))
except Exception:
    STATIC_PERSIST_LOCK_WAIT_TIMEOUT_S = 15
try:
    STATIC_PERSIST_RETRY_BACKOFF_BASE_S = float(os.getenv("SCYTALEDROID_STATIC_PERSIST_RETRY_BACKOFF_BASE_S", "0.35"))
except Exception:
    STATIC_PERSIST_RETRY_BACKOFF_BASE_S = 0.35
try:
    STATIC_PERSIST_RETRY_BACKOFF_MAX_S = float(os.getenv("SCYTALEDROID_STATIC_PERSIST_RETRY_BACKOFF_MAX_S", "3.0"))
except Exception:
    STATIC_PERSIST_RETRY_BACKOFF_MAX_S = 3.0

# Harvest behaviour
HARVEST_DEDUP_SHA256 = True
HARVEST_KEEP_LAST = 1
HARVEST_WRITE_DB = True
HARVEST_WRITE_META = True
HARVEST_META_FIELDS = (
    "package_name",
    "app_label",
    "installer",
    "version_name",
    "version_code",
    "file_name",
    "file_size",
    "source_path",
    "local_path",
    "sha256",
    "sha1",
    "md5",
    "captured_at",
    "session_stamp",
    "device_serial",
    "pull_mode",
    "is_split_member",
    "split_group_id",
    "apk_id",
    "occurrence_index",
    "category",
    "artifact",
    "artifact_kind",
    "canonical_store_path",
)

# Static analysis noise controls (baseline)
# Hard cap on persisted findings per detector to keep corpus outputs readable.
STATIC_FINDINGS_CAP_PER_DETECTOR = 20
# Optional detector-specific overrides (detector_id -> cap).
STATIC_FINDINGS_CAP_OVERRIDES: dict[str, int] = {
    "strings_runtime": 20,
    "secrets": 20,
    "sdk_inventory": 20,
    "correlation_engine": 20,
}

# Device analysis tuning
DEVICE_PROPERTY_KEYS = {
    "ro.product.brand": "brand",
    "ro.product.manufacturer": "manufacturer",
    "ro.product.model": "model",
    "ro.product.device": "device",
    "ro.product.name": "product",
    "ro.hardware": "hardware",
    "ro.build.version.release": "android_version",
    "ro.build.version.sdk": "sdk_level",
    "ro.build.display.id": "build_id",
    "ro.boot.qemu": "is_emulator_flag",
    "ro.hardware.chipname": "chipset",
    "ro.build.tags": "build_tags",
}
